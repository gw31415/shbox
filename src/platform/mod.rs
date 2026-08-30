//! Private process-launch seam.
//!
//! The production adapter (Milestone 5) wraps the pinned Arapuca revision
//! `c94802c4d8b6b880334c0d643b16b7326ec7f039` (package version 0.2.7). Tests
//! get a deterministic fake launcher with barriers and failure injection;
//! nothing here is a configurable backend, and no Arapuca type leaks into the
//! configuration or SSH surfaces. The dependency is pinned in `Cargo.toml` so
//! `Cargo.lock` records the exact revision from the first commit on.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::sandbox::SandboxId;

/// The private request passed from SandboxManager to a process adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchRequest {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) workspace: PathBuf,
}

/// A process handle owned by the runtime registry. The first adapter only
/// needs an idempotent termination operation; stdio/PTY behavior belongs to
/// the later SSH bridge milestone.
pub(crate) trait RunningProcess: fmt::Debug + Send + Sync {
    fn terminate(&self);
}

/// Private production/test seam. It is not a configurable backend surface.
pub(crate) trait ProcessLauncher: fmt::Debug + Send + Sync {
    fn launch(&self, request: LaunchRequest) -> Result<Arc<dyn RunningProcess>, LaunchError>;
}

/// Adapter-level launch failure, intentionally free of platform-specific
/// fields at the manager boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchError {
    message: String,
}

impl LaunchError {
    #[allow(dead_code)]
    pub(crate) fn new(message: impl Into<String>) -> LaunchError {
        LaunchError {
            message: message.into(),
        }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LaunchError {}

/// Deterministic fake adapter used by lifecycle tests. The barrier is
/// optional and is deliberately controlled by the test, not by user config.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeLauncher {
    state: Arc<std::sync::Mutex<FakeState>>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct FakeState {
    fail_next: bool,
    launches: usize,
    barrier: Option<Arc<std::sync::Barrier>>,
    last_process: Option<Arc<FakeProcess>>,
}

#[cfg(test)]
impl FakeLauncher {
    pub(crate) fn fail_next(&self) {
        self.state.lock().expect("fake launcher").fail_next = true;
    }

    pub(crate) fn set_barrier(&self, barrier: Arc<std::sync::Barrier>) {
        self.state.lock().expect("fake launcher").barrier = Some(barrier);
    }

    pub(crate) fn launch_count(&self) -> usize {
        self.state.lock().expect("fake launcher").launches
    }

    pub(crate) fn last_process(&self) -> Option<Arc<FakeProcess>> {
        self.state
            .lock()
            .expect("fake launcher")
            .last_process
            .clone()
    }
}

#[cfg(test)]
impl ProcessLauncher for FakeLauncher {
    fn launch(&self, _request: LaunchRequest) -> Result<Arc<dyn RunningProcess>, LaunchError> {
        let barrier = {
            let mut state = self.state.lock().expect("fake launcher");
            state.launches += 1;
            if state.fail_next {
                state.fail_next = false;
                return Err(LaunchError::new("injected fake launch failure"));
            }
            state.barrier.clone()
        };
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        let process = Arc::new(FakeProcess::default());
        self.state.lock().expect("fake launcher").last_process = Some(Arc::clone(&process));
        Ok(process)
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct FakeProcess {
    terminated: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl FakeProcess {
    #[allow(dead_code)]
    pub(crate) fn terminated(&self) -> bool {
        self.terminated.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(test)]
impl RunningProcess for FakeProcess {
    fn terminate(&self) {
        self.terminated
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    /// Compile-time probe of the pinned Arapuca public API. Building the
    /// production adapter on top of an unverified abstraction is the risk the
    /// plan calls out; this keeps the surface compiling from Milestone 1 on.
    #[test]
    fn pinned_arapuca_public_api_compiles() {
        let profile = arapuca::Profile::default();
        assert_eq!(profile.max_open_files, 0);
        assert_eq!(profile.seccomp_profile, arapuca::SeccompProfile::Strict);

        let task_id = "dev-0123456789abcdef0123456789abcdef";
        assert_eq!(
            arapuca::sanitize_task_id(task_id).expect("valid task id"),
            task_id
        );
        assert!(arapuca::sanitize_task_id("bad_task").is_err());

        fn implements_sandbox_trait<T: arapuca::platform::Sandbox>() {}
        #[cfg(target_os = "linux")]
        implements_sandbox_trait::<arapuca::platform::Linux>();
        #[cfg(target_os = "macos")]
        implements_sandbox_trait::<arapuca::platform::Darwin>();
    }
}
