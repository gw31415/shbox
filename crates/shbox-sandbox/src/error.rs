//! Sandbox error taxonomy.
//!
//! Failures distinguish *why* a sandbox could not run so callers can react
//! without string matching:
//!
//! * [`SandboxError::Unsupported`] — the running kernel/OS cannot provide a
//!   requested security primitive. Production callers must not silently
//!   retry without the primitive (fail-open is forbidden by design).
//! * [`SandboxError::InvalidPolicy`] — the requested configuration is
//!   contradictory or malformed, detected before any child exists.
//! * [`SandboxError::Setup`] — the per-child setup chain failed at a named
//!   stage; the child never executed the requested program.
//! * [`SandboxError::Io`] — an ordinary OS error on the parent side.

use std::fmt;

/// Everything that can go wrong creating or supervising a sandbox.
#[derive(Debug)]
pub enum SandboxError {
    /// A requested security primitive is unavailable on this system.
    Unsupported {
        /// Machine-readable primitive identifier, e.g. `"landlock"`,
        /// `"cgroup-v2"`, `"seccomp"`, `"user-namespace"`.
        feature: &'static str,
        /// Human-oriented explanation of what is missing.
        reason: String,
    },
    /// The policy is contradictory and was rejected before spawning.
    InvalidPolicy {
        /// The offending field or section, e.g. `"resources.cpu_max"`.
        field: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
    /// The child's pre-`exec` setup failed; user code never ran.
    Setup {
        /// The setup stage that failed.
        stage: ChildStage,
        /// Stage-specific detail where available.
        detail: u8,
        /// The `errno` reported by the failing syscall, when applicable.
        errno: Option<i32>,
    },
    /// Parent-side OS error.
    Io(std::io::Error),
    /// An invariant the crate cannot map to another variant was violated.
    Internal(String),
}

impl SandboxError {
    pub(crate) fn unsupported(feature: &'static str, reason: impl Into<String>) -> Self {
        SandboxError::Unsupported {
            feature,
            reason: reason.into(),
        }
    }

    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        SandboxError::InvalidPolicy {
            field,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxError::Unsupported { feature, reason } => {
                write!(f, "unsupported sandbox feature {feature}: {reason}")
            }
            SandboxError::InvalidPolicy { field, reason } => {
                write!(f, "invalid sandbox policy {field}: {reason}")
            }
            SandboxError::Setup {
                stage,
                detail,
                errno,
            } => {
                write!(
                    f,
                    "sandbox child setup failed at {stage:?} (detail {detail}"
                )?;
                if let Some(errno) = errno {
                    write!(f, ", errno {errno}")?;
                }
                f.write_str(")")
            }
            SandboxError::Io(error) => write!(f, "sandbox OS error: {error}"),
            SandboxError::Internal(message) => {
                write!(f, "sandbox internal invariant violated: {message}")
            }
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SandboxError::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SandboxError {
    fn from(error: std::io::Error) -> Self {
        SandboxError::Io(error)
    }
}

/// Named stages of the child-side setup chain. The ordering is significant:
/// each stage assumes the previous ones succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStage {
    /// `PR_SET_PDEATHSIG` installation or parent-identity check.
    ParentDeath,
    /// Session (`setsid`) setup.
    Session,
    /// Controlling-terminal acquisition (`TIOCSCTTY`).
    ControllingTerminal,
    /// `chdir` into the requested working directory.
    WorkingDirectory,
    /// User-namespace UID/GID mapping writes.
    UserNamespace,
    /// Mount-namespace propagation setup.
    MountPropagation,
    /// `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// Capability dropping (`capset`/bounding/ambient).
    Capabilities,
    /// Landlock ruleset enforcement.
    Landlock,
    /// PID-namespace init/supervisor bootstrap.
    Supervisor,
    /// seccomp filter installation.
    Seccomp,
    /// File-descriptor hygiene (`close_range` and friends).
    FdHygiene,
    /// `setrlimit` resource-limit installation (macOS backend).
    ResourceLimits,
    /// `execve` of the requested program.
    Exec,
}

impl ChildStage {
    /// Stable wire code for the stage, used by the child status record.
    pub fn code(self) -> u8 {
        match self {
            ChildStage::ParentDeath => 1,
            ChildStage::Session => 2,
            ChildStage::ControllingTerminal => 3,
            ChildStage::WorkingDirectory => 4,
            ChildStage::UserNamespace => 5,
            ChildStage::MountPropagation => 6,
            ChildStage::NoNewPrivs => 7,
            ChildStage::Capabilities => 8,
            ChildStage::Landlock => 9,
            ChildStage::Seccomp => 10,
            ChildStage::FdHygiene => 11,
            ChildStage::Exec => 12,
            ChildStage::Supervisor => 13,
            ChildStage::ResourceLimits => 14,
        }
    }

    /// Decode a wire code reported by the child.
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => ChildStage::ParentDeath,
            2 => ChildStage::Session,
            3 => ChildStage::ControllingTerminal,
            4 => ChildStage::WorkingDirectory,
            5 => ChildStage::UserNamespace,
            6 => ChildStage::MountPropagation,
            7 => ChildStage::NoNewPrivs,
            8 => ChildStage::Capabilities,
            9 => ChildStage::Landlock,
            10 => ChildStage::Seccomp,
            11 => ChildStage::FdHygiene,
            12 => ChildStage::Exec,
            13 => ChildStage::Supervisor,
            14 => ChildStage::ResourceLimits,
            _ => return None,
        })
    }
}

/// Normalized process exit: code, signal, and core-dump state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    code: Option<i32>,
    signal: Option<i32>,
    core_dumped: bool,
}

impl ExitStatus {
    pub(crate) fn from_code(code: i32) -> Self {
        ExitStatus {
            code: Some(code),
            signal: None,
            core_dumped: false,
        }
    }

    pub(crate) fn from_signal(signal: i32, core_dumped: bool) -> Self {
        ExitStatus {
            code: None,
            signal: Some(signal),
            core_dumped,
        }
    }

    /// Exit code, if the process exited normally.
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    /// Fatal signal number, if the process was killed by a signal.
    pub fn signal(&self) -> Option<i32> {
        self.signal
    }

    /// Whether the termination produced a core dump.
    pub fn core_dumped(&self) -> bool {
        self.core_dumped
    }

    /// Whether the process exited normally with code 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code {
            write!(f, "exit code {code}")
        } else if let Some(signal) = self.signal {
            write!(f, "killed by signal {signal}")?;
            if self.core_dumped {
                f.write_str(" (core dumped)")?;
            }
            Ok(())
        } else {
            f.write_str("unknown exit status")
        }
    }
}
