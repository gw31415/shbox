//! XDG path resolution and safe creation of shbox-owned directories.
//!
//! Path lookup goes through the `xdg` crate; shbox never re-implements the
//! XDG fallback rules. The resolved locations are fixed for v0.1:
//!
//! ```text
//! $XDG_CONFIG_HOME/shbox/config.toml            optional
//! $XDG_DATA_HOME/shbox/registry.lock            sandbox data root lock
//! $XDG_DATA_HOME/shbox/sandboxes/<id>/          metadata + workspace
//! $XDG_STATE_HOME/shbox/host_key                Ed25519 host key
//! $XDG_STATE_HOME/shbox/lock                    daemon state root lock
//! ```
//!
//! Every directory shbox creates is validated after creation: it must be a
//! real directory (no symlink), owned by the daemon user, and neither group
//! nor world writable.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use xdg::BaseDirectories;

/// The `xdg` prefix for every lookup in this module.
const PREFIX: &str = "shbox";

/// Resolved, fixed locations of all shbox-managed state.
#[derive(Debug, Clone)]
pub struct Paths {
    config_dir: PathBuf,
    config_file: PathBuf,
    data_dir: PathBuf,
    sandboxes_root: PathBuf,
    registry_lock: PathBuf,
    state_dir: PathBuf,
    host_key: PathBuf,
    state_lock: PathBuf,
}

impl Paths {
    /// Resolve locations from the process environment via the `xdg` crate.
    ///
    /// `BaseDirectories::with_prefix("shbox")` already scopes each XDG home to
    /// the application (`$XDG_DATA_HOME` becomes `$XDG_DATA_HOME/shbox`), so
    /// the getters here return the shbox roots directly.
    pub fn resolve() -> Result<Paths, Error> {
        let base = BaseDirectories::with_prefix(PREFIX);
        let config_root = base
            .get_config_home()
            .ok_or_else(|| Error::xdg_unavailable("XDG_CONFIG_HOME (~/.config)"))?;
        let data_root = base
            .get_data_home()
            .ok_or_else(|| Error::xdg_unavailable("XDG_DATA_HOME (~/.local/share)"))?;
        let state_root = base
            .get_state_home()
            .ok_or_else(|| Error::xdg_unavailable("XDG_STATE_HOME (~/.local/state)"))?;
        Ok(Paths::from_roots(config_root, data_root, state_root))
    }

    /// Build locations from explicit shbox-scoped XDG roots (test seam).
    pub fn from_roots(config_dir: PathBuf, data_dir: PathBuf, state_dir: PathBuf) -> Paths {
        Paths {
            config_file: config_dir.join("config.toml"),
            sandboxes_root: data_dir.join("sandboxes"),
            registry_lock: data_dir.join("registry.lock"),
            host_key: state_dir.join("host_key"),
            state_lock: state_dir.join("lock"),
            config_dir,
            data_dir,
            state_dir,
        }
    }

    /// Create missing shbox directories and validate ownership and modes of
    /// every directory that already exists.
    pub fn ensure(&self) -> Result<(), Error> {
        ensure_dir(&self.config_dir)?;
        ensure_dir(&self.data_dir)?;
        ensure_dir(&self.sandboxes_root)?;
        ensure_dir(&self.state_dir)?;
        Ok(())
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    /// Sandbox data root: `$XDG_DATA_HOME/shbox`.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Directory holding per-sandbox metadata and workspace directories.
    /// Consumed by the Milestone 3 SandboxManager storage.
    #[allow(dead_code)]
    pub fn sandboxes_root(&self) -> &Path {
        &self.sandboxes_root
    }

    pub fn registry_lock(&self) -> &Path {
        &self.registry_lock
    }

    /// Daemon state root: `$XDG_STATE_HOME/shbox`.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn host_key(&self) -> &Path {
        &self.host_key
    }

    pub fn state_lock(&self) -> &Path {
        &self.state_lock
    }

    /// True when `path` is `root` or located inside `root`.
    pub fn contains(root: &Path, path: &Path) -> bool {
        let mut current = Some(path);
        while let Some(dir) = current {
            if dir == root {
                return true;
            }
            current = dir.parent();
        }
        false
    }
}

/// The daemon's effective uid.
pub fn euid() -> u32 {
    // SAFETY: geteuid is always signal-safe and cannot fail.
    unsafe { libc::geteuid() }
}

/// Create `path` and any missing ancestors with mode `0700`, then validate the
/// final directory: no symlink, owned by the daemon user, not group/world
/// writable. Existing directories are validated but never chmod'ed.
fn ensure_dir(path: &Path) -> Result<(), Error> {
    let mut missing: Vec<&Path> = Vec::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                missing.push(current);
                match current.parent() {
                    Some(parent) => current = parent,
                    None => {
                        return Err(Error::create(path, io::Error::other("no existing parent")));
                    }
                }
            }
            Err(err) => return Err(Error::create(path, err)),
        }
    }
    for dir in missing.iter().rev() {
        fs::create_dir(dir).map_err(|err| Error::create(path, err))?;
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, permissions).map_err(|err| Error::create(path, err))?;
    }
    validate_dir(path)
}

/// Validate that `path` is a directory shbox may safely own and use.
pub fn validate_dir(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|err| Error::stat(path, err))?;
    if !metadata.is_dir() {
        return Err(Error::unsafe_path(path, "not a directory"));
    }
    if metadata.uid() != euid() {
        return Err(Error::unsafe_path(path, "not owned by the daemon user"));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::unsafe_path(path, "group or world writable"));
    }
    Ok(())
}

/// The daemon user's home directory, resolved the same way the `xdg` crate
/// resolves it (the `HOME` environment variable).
pub fn home_dir() -> Result<PathBuf, Error> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::xdg_unavailable("HOME"))
}

/// Errors from XDG path resolution and managed-directory creation.
#[derive(Debug)]
pub struct Error {
    message: String,
    path: Option<PathBuf>,
    source: Option<io::Error>,
}

impl Error {
    fn xdg_unavailable(variable: &'static str) -> Error {
        Error {
            message: format!(
                "{variable} is not set; cannot resolve the shbox {PREFIX} directories"
            ),
            path: None,
            source: None,
        }
    }

    fn create(path: &Path, source: io::Error) -> Error {
        Error {
            message: "failed to create shbox directory".to_string(),
            path: Some(path.to_path_buf()),
            source: Some(source),
        }
    }

    fn stat(path: &Path, source: io::Error) -> Error {
        Error {
            message: "failed to inspect shbox path".to_string(),
            path: Some(path.to_path_buf()),
            source: Some(source),
        }
    }

    fn unsafe_path(path: &Path, reason: &str) -> Error {
        Error {
            message: format!("unsafe shbox path: {reason}"),
            path: Some(path.to_path_buf()),
            source: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(path) = &self.path {
            write!(f, ": {}", path.display())?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|err| err as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, Paths) {
        let home = TempDir::new().expect("tempdir");
        let paths = Paths::from_roots(
            home.path().join("config"),
            home.path().join("data"),
            home.path().join("state"),
        );
        (home, paths)
    }

    #[test]
    fn layout_matches_specification() {
        let (home, paths) = temp_paths();
        let config = home.path().join("config");
        let data = home.path().join("data");
        let state = home.path().join("state");
        assert_eq!(paths.config_dir(), config);
        assert_eq!(paths.data_dir(), data);
        assert_eq!(paths.state_dir(), state);
        assert_eq!(paths.config_file(), config.join("config.toml"));
        assert_eq!(paths.registry_lock(), data.join("registry.lock"));
        assert_eq!(paths.sandboxes_root(), data.join("sandboxes"));
        assert_eq!(paths.host_key(), state.join("host_key"));
        assert_eq!(paths.state_lock(), state.join("lock"));
    }

    #[test]
    fn ensure_creates_missing_directories_with_safe_modes() {
        let (_home, paths) = temp_paths();
        paths.ensure().expect("ensure");
        for dir in [
            paths.config_dir(),
            paths.data_dir(),
            paths.sandboxes_root(),
            paths.state_dir(),
        ] {
            let metadata = fs::symlink_metadata(dir).expect("dir exists");
            assert!(metadata.is_dir(), "{dir:?} is not a directory");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700, "{dir:?}");
            assert_eq!(metadata.uid(), euid());
        }
    }

    #[test]
    fn ensure_rejects_existing_group_writable_directory() {
        let (_home, paths) = temp_paths();
        fs::create_dir_all(paths.data_dir()).expect("create");
        fs::set_permissions(paths.data_dir(), fs::Permissions::from_mode(0o730)).expect("chmod");
        let err = paths.ensure().expect_err("group writable data dir");
        assert!(err.to_string().contains("group or world writable"), "{err}");
    }

    #[test]
    fn ensure_rejects_symlinked_directory() {
        let (home, paths) = temp_paths();
        let target = home.path().join("elsewhere");
        fs::create_dir_all(&target).expect("create target");
        fs::create_dir_all(paths.data_dir().parent().unwrap()).expect("create parent");
        std::os::unix::fs::symlink(&target, paths.data_dir()).expect("symlink");
        let err = paths.ensure().expect_err("symlinked data dir");
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn contains_matches_root_and_descendants_only() {
        let root = Path::new("/tmp/xdg/data/shbox");
        assert!(Paths::contains(root, root));
        assert!(Paths::contains(root, &root.join("sandboxes")));
        assert!(Paths::contains(
            root,
            &root.join("sandboxes").join("dev").join("workspace")
        ));
        assert!(!Paths::contains(
            root,
            Path::new("/tmp/xdg/data/shbox-other")
        ));
        assert!(!Paths::contains(root, Path::new("/tmp/xdg/data")));
        // Prefix strings that are not path components do not match.
        assert!(!Paths::contains(
            Path::new("/a/b"),
            &Path::new("/a/bc").join("x")
        ));
    }

    #[test]
    fn home_dir_uses_environment() {
        // Read-only probe: the daemon's own HOME must resolve in the test env.
        if std::env::var_os("HOME").is_some() {
            assert!(paths::home_dir().is_ok());
        }
    }
}
