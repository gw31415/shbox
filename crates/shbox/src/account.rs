//! Daemon OS account identity.
//!
//! shbox runs as a dedicated non-root service account. The account's passwd
//! entry supplies the login shell (the sandbox shell default and the host-mode
//! shell) and the home directory (the host-mode initial working directory).
//! SSH usernames are never mapped to OS accounts.

use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::paths;

/// The resolved daemon account.
#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    pub home: PathBuf,
    /// passwd login shell; empty entry means the account has no shell set.
    pub shell: String,
}

/// Read the passwd entry of the daemon's effective uid.
pub fn current_account() -> Result<Account, Error> {
    let uid = paths::euid();
    // SAFETY: getpwuid_r is called with valid, correctly sized buffers; the
    // returned pointers are copied into owned strings before use.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buffer = vec![0u8; 8192];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            &mut pwd,
            buffer.as_mut_ptr() as *mut c_char,
            buffer.len(),
            &mut result,
        );
        if rc != 0 {
            return Err(Error::Passwd {
                uid,
                message: io::Error::from_raw_os_error(rc).to_string(),
            });
        }
        if result.is_null() {
            return Err(Error::Passwd {
                uid,
                message: "no passwd entry for the daemon uid".to_string(),
            });
        }
        let entry = &*result;
        let name = CStr::from_ptr(entry.pw_name).to_string_lossy().into_owned();
        let home = CStr::from_ptr(entry.pw_dir).to_string_lossy().into_owned();
        let shell = CStr::from_ptr(entry.pw_shell)
            .to_string_lossy()
            .into_owned();
        if name.is_empty() || home.is_empty() {
            return Err(Error::Passwd {
                uid,
                message: "passwd entry has no name or home directory".to_string(),
            });
        }
        Ok(Account {
            name,
            home: PathBuf::from(home),
            shell,
        })
    }
}

impl Account {
    /// The host-mode login shell: the passwd shell, falling back to `/bin/sh`
    /// only when the passwd entry's shell field is empty.
    pub fn host_shell(&self) -> PathBuf {
        self.login_shell_path(&self.shell)
    }

    /// The sandbox shell for this daemon: the configured absolute path, or the
    /// account login shell with the same `/bin/sh` fallback rule.
    pub fn sandbox_shell(&self, config: &Config) -> Result<PathBuf, Error> {
        match config.sandbox_shell() {
            Some(configured) => Ok(configured.to_path_buf()),
            None => Ok(self.login_shell_path(&self.shell)),
        }
    }

    fn login_shell_path(&self, shell: &str) -> PathBuf {
        if shell.is_empty() {
            PathBuf::from("/bin/sh")
        } else {
            PathBuf::from(shell)
        }
    }
}

/// Validate that `path` can actually be executed by the daemon: a regular
/// file with the executable bit reachable for this user.
pub fn validate_executable(path: &Path) -> Result<(), Error> {
    let metadata = fs::metadata(path).map_err(|err| Error::Shell {
        path: path.to_path_buf(),
        message: format!("cannot stat shell: {err}"),
    })?;
    if !metadata.is_file() {
        return Err(Error::Shell {
            path: path.to_path_buf(),
            message: "shell is not a regular file".into(),
        });
    }
    let name = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error::Shell {
        path: path.to_path_buf(),
        message: "shell path contains NUL".into(),
    })?;
    // SAFETY: `name` is a valid NUL-terminated string and X_OK is a valid
    // access mode.
    let reachable = unsafe { libc::access(name.as_ptr(), libc::X_OK) } == 0;
    if !reachable {
        return Err(Error::Shell {
            path: path.to_path_buf(),
            message: "shell is not executable by the daemon user".into(),
        });
    }
    Ok(())
}

/// Account errors.
#[derive(Debug)]
pub enum Error {
    Passwd { uid: u32, message: String },
    Shell { path: PathBuf, message: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Passwd { uid, message } => {
                write!(f, "cannot resolve daemon account (uid {uid}): {message}")
            }
            Error::Shell { path, message } => {
                write!(f, "invalid shell {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::paths::Paths;
    use tempfile::TempDir;

    #[test]
    fn resolves_current_account() {
        let account = current_account().expect("passwd entry");
        assert!(!account.name.is_empty());
        assert!(!account.home.as_os_str().is_empty());
    }

    #[test]
    fn resolves_sandbox_shell_from_config_or_passwd() {
        let account = current_account().expect("passwd entry");
        let defaults = config::defaults();
        let resolved = account.sandbox_shell(&defaults).expect("default shell");
        if account.shell.is_empty() {
            assert_eq!(resolved, PathBuf::from("/bin/sh"));
        } else {
            assert_eq!(resolved, PathBuf::from(account.shell.clone()));
        }

        let (_home, paths) = temp_paths();
        // A ws-only build has no default listener, so pin one explicitly.
        #[cfg(feature = "tcp")]
        let text = "listen = [\"tcp://127.0.0.1:2222\"]\n[sandbox]\nshell = \"/bin/sh\"";
        #[cfg(not(feature = "tcp"))]
        let text = "listen = [\"ws://127.0.0.1:8080/ssh\"]\n[sandbox]\nshell = \"/bin/sh\"";
        let raw: config::RawConfig = toml::from_str(text).expect("toml");
        let config = config::build(raw, &paths).expect("config");
        assert_eq!(
            account.sandbox_shell(&config).expect("configured shell"),
            PathBuf::from("/bin/sh")
        );
    }

    #[test]
    fn rejects_non_executable_shell() {
        let home = TempDir::new().expect("tempdir");
        let not_a_file = home.path().join("directory");
        fs::create_dir(&not_a_file).expect("dir");
        assert!(matches!(
            validate_executable(&not_a_file),
            Err(Error::Shell { .. })
        ));
        let missing = home.path().join("missing");
        assert!(matches!(
            validate_executable(&missing),
            Err(Error::Shell { .. })
        ));
    }

    fn temp_paths() -> (TempDir, Paths) {
        let home = TempDir::new().expect("tempdir");
        let paths = Paths::from_roots(
            home.path().join("config"),
            home.path().join("data"),
            home.path().join("state"),
        );
        paths.ensure().expect("ensure");
        (home, paths)
    }

    #[test]
    fn login_shell_falls_back_only_for_empty_entry() {
        struct Case<'a> {
            entry: &'a str,
            expected: &'a str,
        }
        for case in [
            Case {
                entry: "",
                expected: "/bin/sh",
            },
            Case {
                entry: "/bin/zsh",
                expected: "/bin/zsh",
            },
        ] {
            let account = Account {
                name: "shbox".into(),
                home: PathBuf::from("/home/shbox"),
                shell: case.entry.into(),
            };
            assert_eq!(account.host_shell(), PathBuf::from(case.expected));
        }
    }
}
