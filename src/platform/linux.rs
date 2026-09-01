//! Linux production launcher (nono confinement primitive).
//!
//! nono is a confinement primitive, not a process launcher: shbox owns the
//! PTY, the session, and the process lifecycle. This module converts the
//! backend-neutral [`crate::platform::policy::SandboxLaunchPolicy`] into
//! nono's prepared Landlock/seccomp policy in the parent, then applies it in
//! the post-fork child with `PreparedLandlockSandbox::apply_raw()`, which is
//! proven to perform no allocation, no path resolution, and no libc
//! coordination wrappers after `fork()`.

#![cfg(target_os = "linux")]

#[cfg(test)]
mod nono_api_probe {
    use nono::CapabilitySet;
    use nono::capability::{AccessMode, IpcMode, NetworkMode, SignalMode};
    use nono::sandbox::{RawSandboxStage, SeccompOpts, detect_abi, prepare_seccomp_with_abi};

    /// Compile-time spike for every nono API the Linux launcher relies on,
    /// pinned at `nono = "=0.74.0"`. Preparation only opens path descriptors
    /// and builds rules; it never restricts the calling task, so running this
    /// in the shared test process is safe. `apply_raw()` is deliberately not
    /// called here: Landlock restriction is irreversible for the process and
    /// would poison unrelated tests.
    #[test]
    fn pinned_nono_api_prepares_a_restricted_policy() {
        let workspace = tempfile::tempdir().expect("probe workspace");
        let caps = CapabilitySet::new()
            .allow_path("/usr", AccessMode::Read)
            .expect("usr read capability")
            .allow_path("/bin/sh", AccessMode::Read)
            .expect("shell read capability")
            .allow_path(workspace.path(), AccessMode::ReadWrite)
            .expect("workspace write capability")
            .set_network_mode(NetworkMode::Blocked)
            .set_signal_mode(SignalMode::Isolated)
            .set_ipc_mode(IpcMode::SharedMemoryOnly);

        let abi = detect_abi().expect("landlock ABI detection");
        let prepared = prepare_seccomp_with_abi(&caps, &abi, SeccompOpts::network_fallback())
            .expect("policy preparation");
        // The fallback mode is fixed-size data usable without formatting in a
        // post-fork child, mirroring the RawSandboxError contract.
        let _fallback = prepared.fallback();

        // RawSandboxStage is an exhaustive, fixed-size stage tag.
        let stage = RawSandboxStage::CreateRuleset;
        match stage {
            RawSandboxStage::CreateRuleset
            | RawSandboxStage::AddPathRule
            | RawSandboxStage::AddNetRule
            | RawSandboxStage::NoNewPrivs
            | RawSandboxStage::RestrictSelf
            | RawSandboxStage::InstallStaticFilter => {}
        }
    }

    /// The outbound network mapping must keep ordinary client sockets usable
    /// without port-specific grants.
    #[test]
    fn outbound_capability_set_prepares_without_network_handling() {
        let caps = CapabilitySet::new()
            .allow_path("/usr", AccessMode::Read)
            .expect("usr read capability")
            .set_network_mode(NetworkMode::AllowAll);
        let abi = detect_abi().expect("landlock ABI detection");
        let prepared = prepare_seccomp_with_abi(&caps, &abi, SeccompOpts::network_fallback())
            .expect("policy preparation");
        assert!(matches!(
            prepared.fallback(),
            nono::sandbox::SeccompNetFallback::None
        ));
    }
}
