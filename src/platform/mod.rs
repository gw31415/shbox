//! Private process-launch seam.
//!
//! The production adapter (Milestone 5) wraps the pinned Arapuca revision
//! `c94802c4d8b6b880334c0d643b16b7326ec7f039` (package version 0.2.7). Tests
//! get a deterministic fake launcher with barriers and failure injection;
//! nothing here is a configurable backend, and no Arapuca type leaks into the
//! configuration or SSH surfaces. The dependency is pinned in `Cargo.toml` so
//! `Cargo.lock` records the exact revision from the first commit on.

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
