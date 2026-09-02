//! Exclusive advisory daemon locks.
//!
//! A second daemon that shares either the sandbox data root or the state root
//! must fail to start, even with a different listen address. Ownership is
//! decided by holding the OS advisory lock (`flock(2)`), never by the mere
//! existence of the lock file. The data-root `registry.lock` is acquired
//! first, then the state-root `lock`; if the second acquisition fails, the
//! first is released before startup aborts.

use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::paths::{self, Paths};

/// Held advisory locks; dropping this value releases both.
#[derive(Debug)]
pub struct Locks {
    _registry: LockFile,
    _state: LockFile,
}

impl Locks {
    /// Acquire the registry lock and then the daemon state lock.
    ///
    /// Returns an error when either file is missing or unusable, or when
    /// another process already holds it. Partial acquisition is rolled back.
    pub fn acquire(paths: &Paths) -> Result<Locks, Error> {
        let registry = LockFile::acquire(paths.registry_lock())
            .map_err(|err| err.context("registry lock (sandbox data root)"))?;
        let state = match LockFile::acquire(paths.state_lock()) {
            Ok(state) => state,
            // Dropping `registry` releases the already-held lock before the
            // caller sees the failure.
            Err(err) => return Err(err.context("daemon lock (state root)")),
        };
        Ok(Locks {
            _registry: registry,
            _state: state,
        })
    }
}

/// A single held lock file.
#[derive(Debug)]
pub struct LockFile {
    path: PathBuf,
    file: fs::File,
}

impl LockFile {
    pub fn acquire(path: &Path) -> Result<LockFile, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    Error::new(path, "lock parent directory is missing", Some(err))
                } else if err.raw_os_error() == Some(libc::ELOOP) {
                    Error::new(path, "lock path is a symlink", Some(err))
                } else {
                    Error::new(path, "cannot open lock file", Some(err))
                }
            })?;
        validate_lock_file(path, &file)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(Error::new(
                    path,
                    "another daemon already holds this lock",
                    None,
                ));
            }
            return Err(Error::new(path, "cannot lock lock file", Some(err)));
        }
        Ok(LockFile {
            path: path.to_path_buf(),
            file,
        })
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        // SAFETY: the descriptor is valid for the lifetime of the held file.
        let result = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        if result != 0 {
            tracing::warn!(path = %self.path.display(), "failed to release advisory lock");
        }
    }
}

/// Validate the opened lock file before relying on it: a regular file, owned
/// by the daemon user, not group/world writable.
fn validate_lock_file(path: &Path, file: &fs::File) -> Result<(), Error> {
    let metadata = file
        .metadata()
        .map_err(|err| Error::new(path, "cannot stat lock file", Some(err)))?;
    if !metadata.is_file() {
        return Err(Error::new(path, "lock path is not a regular file", None));
    }
    if metadata.uid() != paths::euid() {
        return Err(Error::new(
            path,
            "lock file is not owned by the daemon user",
            None,
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::new(
            path,
            "lock file is group or world writable",
            None,
        ));
    }
    Ok(())
}

/// Errors from lock acquisition.
#[derive(Debug)]
pub struct Error {
    message: String,
    path: PathBuf,
    source: Option<io::Error>,
}

impl Error {
    fn new(path: &Path, message: &str, source: Option<io::Error>) -> Error {
        Error {
            message: message.to_string(),
            path: path.to_path_buf(),
            source,
        }
    }

    /// Add the logical role of the lock (registry vs state) to the message.
    pub fn context(mut self, role: &str) -> Error {
        self.message = format!("{} ({role})", self.message);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.message, self.path.display())?;
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
    use crate::paths::Paths;
    use tempfile::TempDir;

    fn paths_for(home: &TempDir, name: &str) -> Paths {
        let root = home.path().join(name);
        let paths = Paths::from_roots(root.join("config"), root.join("data"), root.join("state"));
        paths.ensure().expect("ensure dirs");
        paths
    }

    #[test]
    fn acquires_both_locks_and_creates_mode_0600_files() {
        let home = TempDir::new().expect("tempdir");
        let paths = paths_for(&home, "a");
        {
            let locks = Locks::acquire(&paths).expect("acquire");
            for lock_path in [paths.registry_lock(), paths.state_lock()] {
                let metadata = fs::metadata(lock_path).expect("lock file");
                assert!(metadata.is_file());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }
            drop(locks);
        }
        // Released locks can be acquired again.
        Locks::acquire(&paths).expect("reacquire after release");
    }

    #[test]
    fn second_daemon_on_same_roots_is_rejected() {
        let home = TempDir::new().expect("tempdir");
        let paths = paths_for(&home, "a");
        let _locks = Locks::acquire(&paths).expect("first acquire");
        let err = Locks::acquire(&paths).expect_err("second daemon, same roots");
        assert!(err.to_string().contains("another daemon"), "{err}");
    }

    #[test]
    fn shared_data_root_is_rejected_even_with_distinct_state_root() {
        let home = TempDir::new().expect("tempdir");
        let first = paths_for(&home, "a");
        let _locks = Locks::acquire(&first).expect("first acquire");

        // Same data root, different state root: registry lock collides.
        let second = Paths::from_roots(
            home.path().join("b/config"),
            first.data_dir().to_path_buf(),
            home.path().join("b/state"),
        );
        second.ensure().expect("ensure");
        let err = Locks::acquire(&second).expect_err("shared data root");
        assert!(err.to_string().contains("registry lock"), "{err}");
    }

    #[test]
    fn shared_state_root_is_rejected_and_registry_lock_is_released() {
        let home = TempDir::new().expect("tempdir");
        let first = paths_for(&home, "a");
        let _locks = Locks::acquire(&first).expect("first acquire");

        // Distinct data root, same state root: state lock collides after the
        // registry lock was taken; the transaction must roll back.
        let second = Paths::from_roots(
            home.path().join("b/config"),
            home.path().join("b/data"),
            first.state_dir().to_path_buf(),
        );
        second.ensure().expect("ensure");
        let err = Locks::acquire(&second).expect_err("shared state root");
        assert!(err.to_string().contains("daemon lock"), "{err}");

        // The first-acquired registry lock of the failed attempt was released:
        // a fresh daemon on that data root (with a free state root) can start.
        let third = paths_for(&home, "c");
        let _recovered = Locks::acquire(&third).expect("acquire after rollback");
    }

    #[test]
    fn symlinked_lock_file_is_rejected() {
        let home = TempDir::new().expect("tempdir");
        let paths = paths_for(&home, "a");
        let victim = home.path().join("victim.lock");
        fs::write(&victim, b"").expect("write victim");
        std::os::unix::fs::symlink(&victim, paths.registry_lock()).expect("symlink");
        let err = Locks::acquire(&paths).expect_err("symlinked lock");
        assert!(err.to_string().contains("symlink"), "{err}");
    }
}
