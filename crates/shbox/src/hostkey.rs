//! Ed25519 host key loading and atomic creation.
//!
//! The host key lives at the fixed path `$XDG_STATE_HOME/shbox/host_key`. It
//! is created once, atomically, with mode `0600`, and is never replaced: an
//! existing key that is corrupt, unsupported, wrongly owned, or loosely
//! permissioned is a startup error, not something shbox repairs by
//! regenerating.

use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use russh::keys::PrivateKey;
use russh::keys::ssh_key::{Algorithm, LineEnding};

use crate::paths::{self};

/// Upper bound for an unencrypted OpenSSH Ed25519 private key file.
const MAX_KEY_BYTES: usize = 64 * 1024;

/// The loaded daemon host key.
#[derive(Debug)]
pub struct HostKey {
    key: PrivateKey,
}

impl HostKey {
    /// Load the host key, creating it atomically when absent.
    pub fn load_or_create(path: &Path) -> Result<HostKey, Error> {
        match Self::load(path) {
            Ok(key) => Ok(key),
            Err(Error::Missing { path }) => Self::create(&path),
            Err(err) => Err(err),
        }
    }

    pub fn key(&self) -> &PrivateKey {
        &self.key
    }

    /// Load an existing key without creating one.
    fn load(path: &Path) -> Result<HostKey, Error> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => Error::Missing {
                    path: path.to_path_buf(),
                },
                _ => Error::io(path, "cannot open host key", err),
            })?;
        validate_file(path, &file)?;
        let mut pem = String::new();
        let mut limited = file.take(MAX_KEY_BYTES as u64 + 1);
        limited
            .read_to_string(&mut pem)
            .map_err(|err| Error::io(path, "cannot read host key", err))?;
        if pem.len() > MAX_KEY_BYTES {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                reason: "host key file is too large".into(),
            });
        }
        let key = PrivateKey::from_openssh(pem.as_str()).map_err(|_| Error::Invalid {
            path: path.to_path_buf(),
            reason: "not a valid OpenSSH private key".into(),
        })?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                reason: format!(
                    "host key algorithm is {:?}, Ed25519 is required",
                    key.algorithm()
                ),
            });
        }
        Ok(HostKey { key })
    }

    /// Create a new Ed25519 key atomically: write a temporary file, sync it,
    /// `link(2)` it into place (creating, never replacing), then sync the
    /// parent directory.
    fn create(path: &Path) -> Result<HostKey, Error> {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(|err| {
            Error::io(
                path,
                "cannot generate Ed25519 host key",
                io::Error::other(err),
            )
        })?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|err| Error::io(path, "cannot encode host key", io::Error::other(err)))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        for attempt in 0..8u32 {
            let temp = parent.join(format!(
                ".host_key.tmp.{}.{}",
                std::process::id(),
                attempt + rand::random_range(0u32..1_000_000u32)
            ));
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)
            {
                Ok(file) => file,
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(Error::io(path, "cannot create host key file", err)),
            };
            if let Err(err) = file.write_all(pem.as_bytes()) {
                let _ = fs::remove_file(&temp);
                return Err(Error::io(path, "cannot write host key", err));
            }
            if let Err(err) = file.sync_all() {
                let _ = fs::remove_file(&temp);
                return Err(Error::io(path, "cannot flush host key", err));
            }
            // `link` refuses to replace an existing key (EEXIST), so a racing
            // creator can never make shbox overwrite a key it did not write.
            if let Err(err) = fs::hard_link(&temp, path) {
                let _ = fs::remove_file(&temp);
                if err.kind() == io::ErrorKind::AlreadyExists {
                    // Someone else created the key first: use theirs.
                    return Self::load(path);
                }
                return Err(Error::io(path, "cannot publish host key", err));
            }
            if let Err(err) = fs::remove_file(&temp) {
                tracing::warn!(
                    path = %temp.display(),
                    error = %err,
                    "failed to remove host key temporary file"
                );
            }
            sync_dir(parent)
                .map_err(|err| Error::io(path, "cannot flush host key directory", err))?;
            return Self::load(path);
        }
        Err(Error::io(
            path,
            "cannot create host key",
            io::Error::other("no free temporary file name"),
        ))
    }
}

/// Flush the parent directory entry so the published key is durable.
fn sync_dir(dir: &Path) -> std::result::Result<(), io::Error> {
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    // SAFETY: the descriptor is a valid open file for the call's duration.
    let result = unsafe { libc::fsync(handle.as_raw_fd()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Validate the opened host key file: regular file, daemon-owned, no group or
/// world permissions.
fn validate_file(path: &Path, file: &fs::File) -> Result<(), Error> {
    let metadata = file
        .metadata()
        .map_err(|err| Error::io(path, "cannot stat host key", err))?;
    if !metadata.is_file() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "host key is not a regular file".into(),
        });
    }
    if metadata.uid() != paths::euid() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "host key is not owned by the daemon user".into(),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "host key is readable or writable by group or others".into(),
        });
    }
    Ok(())
}

/// Host key errors.
#[derive(Debug)]
pub enum Error {
    /// The key does not exist yet; creation is allowed.
    Missing { path: PathBuf },
    /// An existing key exists but must never be replaced.
    Invalid { path: PathBuf, reason: String },
    /// Environmental failure while creating or reading the key.
    Io {
        path: PathBuf,
        message: String,
        source: io::Error,
    },
}

impl Error {
    fn io(path: &Path, message: &str, source: io::Error) -> Error {
        Error::Io {
            path: path.to_path_buf(),
            message: message.to_string(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Missing { path } => write!(f, "host key is missing: {}", path.display()),
            Error::Invalid { path, reason } => {
                write!(
                    f,
                    "invalid host key at {} ({reason}); shbox never replaces an existing host key",
                    path.display()
                )
            }
            Error::Io {
                path,
                message,
                source,
            } => write!(f, "{message}: {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_key_path(home: &TempDir) -> PathBuf {
        let dir = home.path().join("state/shbox");
        fs::create_dir_all(&dir).expect("create state dir");
        dir.join("host_key")
    }

    /// Write a key fixture with private permissions, independent of the
    /// ambient umask.
    fn write_key_fixture(path: &PathBuf, content: impl AsRef<[u8]>) {
        fs::write(path, content).expect("write fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("fixture must be private");
    }

    #[test]
    fn creates_missing_key_with_mode_0600() {
        let home = TempDir::new().expect("tempdir");
        let path = temp_key_path(&home);
        let host_key = HostKey::load_or_create(&path).expect("create");
        assert_eq!(host_key.key().algorithm(), Algorithm::Ed25519);
        let metadata = fs::metadata(&path).expect("exists");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), paths::euid());
        // Reopening returns the same key, not a new one.
        let fingerprint = host_key
            .key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        drop(host_key);
        let again = HostKey::load_or_create(&path).expect("reload");
        assert_eq!(
            again
                .key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string(),
            fingerprint
        );
    }

    #[test]
    fn never_replaces_corrupt_existing_key() {
        let home = TempDir::new().expect("tempdir");
        let path = temp_key_path(&home);
        write_key_fixture(&path, b"not an openssh key");
        let err = HostKey::load_or_create(&path).expect_err("corrupt key");
        assert!(matches!(err, Error::Invalid { .. }), "{err}");
        assert_eq!(fs::read(&path).expect("unchanged"), b"not an openssh key");
    }

    #[test]
    fn rejects_existing_key_with_group_writable_mode() {
        let home = TempDir::new().expect("tempdir");
        let path = temp_key_path(&home);
        let created = HostKey::load_or_create(&path).expect("create");
        let pem = created
            .key()
            .to_openssh(LineEnding::LF)
            .expect("encode")
            .to_string();
        drop(created);
        fs::write(&path, pem).expect("rewrite");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        let err = HostKey::load_or_create(&path).expect_err("loose mode");
        assert!(err.to_string().contains("group or others"), "{err}");
    }

    #[test]
    fn rejects_symlinked_host_key() {
        let home = TempDir::new().expect("tempdir");
        let path = temp_key_path(&home);
        let target = home.path().join("elsewhere-key");
        fs::write(&target, b"").expect("write target");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        let err = HostKey::load_or_create(&path).expect_err("symlink");
        assert!(err.to_string().contains("cannot open"), "{err}");
    }

    #[test]
    fn concurrent_creation_keeps_exactly_one_key() {
        let home = TempDir::new().expect("tempdir");
        let path = temp_key_path(&home);
        let first = HostKey::load_or_create(&path).expect("first");
        let second = HostKey::load_or_create(&path).expect("second");
        assert_eq!(
            first
                .key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string(),
            second
                .key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string()
        );
        // No temporary files are left behind.
        let entries: Vec<_> = fs::read_dir(path.parent().unwrap())
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![path.file_name().unwrap().to_os_string()]);
    }
}
