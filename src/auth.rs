//! Key fingerprints and authorized-keys file validation.
//!
//! The stable principal identifier in shbox is the OpenSSH SHA-256 fingerprint
//! of the exact Ed25519 public key bytes:
//!
//! ```text
//! SHA256:<43 characters of unpadded standard base64>
//! ```
//!
//! Fingerprints printed by `ssh-keygen -lf` parse here unchanged. The module
//! also owns the bounded authorized-keys parser, connection principals, and
//! the file-level safety checks used by the SSH server.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::paths::{self};

/// Maximum size of the authorized_keys file.
pub const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024;

/// A validated OpenSSH SHA-256 fingerprint of an Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyFingerprint(String);

impl KeyFingerprint {
    /// Parse and validate the strict wire syntax.
    pub fn parse(raw: &str) -> Result<KeyFingerprint, FingerprintError> {
        let digest = raw
            .strip_prefix("SHA256:")
            .ok_or(FingerprintError::MissingPrefix)?;
        let bytes = decode_sha256_base64(digest)?;
        // The string form is the canonical unpadded encoding of exactly these
        // bytes, so re-encoding must reproduce the input byte for byte.
        debug_assert_eq!(bytes.len(), 32);
        Ok(KeyFingerprint(raw.to_string()))
    }

    /// Build from the OpenSSH fingerprint of a public key (Milestone 2).
    #[allow(dead_code)]
    pub fn from_ssh_key(public_key: &russh::keys::PublicKey) -> KeyFingerprint {
        KeyFingerprint(
            public_key
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string(),
        )
    }

    #[allow(dead_code)] // test assertions plus Milestone 2 consumers
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_value(byte: u8) -> Option<u8> {
    BASE64_ALPHABET
        .iter()
        .position(|&c| c == byte)
        .map(|index| index as u8)
}

/// Decode the 43-character unpadded base64 body of a SHA-256 fingerprint into
/// 32 digest bytes, rejecting non-canonical input (padding characters, wrong
/// length, invalid characters, or non-zero trailing bits).
fn decode_sha256_base64(digest: &str) -> Result<[u8; 32], FingerprintError> {
    let bytes = digest.as_bytes();
    if bytes.len() != 43 {
        return Err(FingerprintError::BadLength(bytes.len()));
    }
    let mut values = [0u8; 43];
    for (index, &byte) in bytes.iter().enumerate() {
        values[index] =
            base64_value(byte).ok_or(FingerprintError::InvalidCharacter(index, byte))?;
    }
    let mut out = [0u8; 32];
    for group in 0..10 {
        let v = &values[group * 4..group * 4 + 4];
        out[group * 3] = (v[0] << 2) | (v[1] >> 4);
        out[group * 3 + 1] = (v[1] << 4) | (v[2] >> 2);
        out[group * 3 + 2] = (v[2] << 6) | v[3];
    }
    // The final 3 characters encode the last 2 bytes plus 2 padding bits that
    // must be zero for the encoding to be canonical.
    let v = &values[40..43];
    if v[2] & 0b11 != 0 {
        return Err(FingerprintError::NonCanonical);
    }
    out[30] = (v[0] << 2) | (v[1] >> 4);
    out[31] = (v[1] << 4) | (v[2] >> 2);
    Ok(out)
}

/// Fingerprint syntax errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    MissingPrefix,
    BadLength(usize),
    InvalidCharacter(usize, u8),
    NonCanonical,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FingerprintError::MissingPrefix => write!(f, "fingerprint must start with \"SHA256:\""),
            FingerprintError::BadLength(length) => {
                write!(
                    f,
                    "fingerprint body must be 43 unpadded base64 characters, got {length}"
                )
            }
            FingerprintError::InvalidCharacter(index, byte) => {
                write!(
                    f,
                    "fingerprint contains invalid base64 character {byte:#04x} at offset {index}"
                )
            }
            FingerprintError::NonCanonical => {
                write!(f, "fingerprint base64 padding bits are not zero")
            }
        }
    }
}

impl std::error::Error for FingerprintError {}

/// Resolve the daemon user's `~/.ssh/authorized_keys`.
pub fn resolve_authorized_keys_path() -> Result<PathBuf, Error> {
    match paths::home_dir() {
        Ok(home) => Ok(home.join(".ssh").join("authorized_keys")),
        Err(err) => Err(Error::Home {
            message: err.to_string(),
        }),
    }
}

/// Validate file-level safety of a key source: if present, it must be a
/// regular file the daemon user owns, be group/world unwritable, fit the size
/// limit, and have safe directory ancestors.
pub fn validate_key_source_file(path: &Path, source_name: &'static str) -> Result<bool, Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                message: format!("cannot stat {source_name}"),
                source: err,
            });
        }
    };
    if !metadata.is_file() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} is not a regular file"),
        });
    }
    if metadata.file_type().is_symlink() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} must not be a symlink"),
        });
    }
    if metadata.len() > MAX_AUTHORIZED_KEYS_BYTES {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} exceeds the {MAX_AUTHORIZED_KEYS_BYTES} byte limit"),
        });
    }
    if metadata.uid() != paths::euid() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} is not owned by the daemon user"),
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} is group or world writable"),
        });
    }
    validate_key_source_parents(path, source_name)?;
    Ok(true)
}

/// Validate the containing directory chain before opening the key file. The
/// immediate parent must belong to the daemon account and must not be a
/// symlink; higher ancestors may be system-owned (macOS commonly exposes
/// `/var` this way), but none may be writable by group/other.
fn validate_key_source_parents(path: &Path, source_name: &'static str) -> Result<(), Error> {
    let mut current = path.parent();
    let mut immediate = true;
    while let Some(directory) = current {
        let link_metadata = fs::symlink_metadata(directory).map_err(|err| Error::Io {
            path: directory.to_path_buf(),
            message: format!("cannot stat {source_name} parent"),
            source: err,
        })?;
        if immediate && link_metadata.file_type().is_symlink() {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: format!("{source_name} parent must not be a symlink"),
            });
        }
        let metadata = fs::metadata(directory).map_err(|err| Error::Io {
            path: directory.to_path_buf(),
            message: format!("cannot stat {source_name} parent"),
            source: err,
        })?;
        if !metadata.is_dir() {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: format!("{source_name} parent is not a directory"),
            });
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: format!("{source_name} parent is group or world writable"),
            });
        }
        if immediate && metadata.uid() != paths::euid() {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: format!("{source_name} parent is not owned by the daemon user"),
            });
        }
        immediate = false;
        let Some(parent) = directory.parent() else {
            break;
        };
        if parent == directory {
            break;
        }
        current = Some(parent);
    }
    Ok(())
}

/// Read through an `O_NOFOLLOW` descriptor after the metadata checks. This
/// closes the check/use race for the final key file path.
fn read_key_source(path: &Path, source_name: &'static str) -> Result<Option<Vec<u8>>, Error> {
    if !validate_key_source_file(path, source_name)? {
        return Ok(None);
    }
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(err) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                message: format!("cannot open {source_name}"),
                source: err,
            });
        }
    };
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take(MAX_AUTHORIZED_KEYS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::Io {
            path: path.to_path_buf(),
            message: format!("cannot read {source_name}"),
            source: err,
        })?;
    if bytes.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} exceeds the {MAX_AUTHORIZED_KEYS_BYTES} byte limit"),
        });
    }
    Ok(Some(bytes))
}

/// Authentication and key source errors.
#[derive(Debug)]
pub enum Error {
    Home {
        message: String,
    },
    Invalid {
        path: PathBuf,
        reason: String,
    },
    Io {
        path: PathBuf,
        message: String,
        source: io::Error,
    },
    EmptyAuthSnapshot {
        host_path: PathBuf,
        allowed_path: PathBuf,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Home { message } => {
                write!(f, "cannot resolve the daemon home directory: {message}")
            }
            Error::Invalid { path, reason } => {
                write!(f, "invalid key source at {}: {reason}", path.display())
            }
            Error::Io {
                path,
                message,
                source,
            } => write!(f, "{message}: {}: {source}", path.display()),
            Error::EmptyAuthSnapshot {
                host_path,
                allowed_path,
            } => write!(
                f,
                "no accepted keys found in {} or {}",
                host_path.display(),
                allowed_path.display()
            ),
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

/// One accepted authorized-keys entry.
#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub fingerprint: KeyFingerprint,
}

/// The authenticated identity of an SSH connection, fixed for its lifetime.
#[derive(Debug, Clone)]
pub struct Principal {
    pub fingerprint: KeyFingerprint,
    pub role: Role,
}

/// Role granted to a key at authentication time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Normal,
    Admin,
}

/// The validated authentication snapshot: accepted Ed25519 keys mapped to their
/// roles. Connections capture their own clone, so a later reload can only
/// affect new connections.
#[derive(Debug, Clone, Default)]
pub struct AuthSnapshot {
    keys: Vec<AuthorizedKey>,
    principals: std::collections::BTreeMap<KeyFingerprint, Role>,
    admin_count: usize,
}

fn parse_key_source(
    bytes: &[u8],
    path: &Path,
    allow_empty: bool,
) -> Result<Vec<AuthorizedKey>, Error> {
    if bytes.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "file exceeds the 1 MiB limit".into(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid {
        path: path.to_path_buf(),
        reason: "file is not valid UTF-8".into(),
    })?;
    let mut keys: Vec<AuthorizedKey> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.len() > MAX_AUTHORIZED_KEYS_LINE_BYTES {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                reason: format!("line {number} exceeds the 8 KiB limit"),
            });
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split_ascii_whitespace();
        let algorithm = fields.next().unwrap_or_default();
        let blob = fields.next().unwrap_or_default();
        if algorithm != "ssh-ed25519" || blob.is_empty() {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                reason: format!("line {number} is not bare `ssh-ed25519 <base64> [comment]`"),
            });
        }
        let key = russh::keys::PublicKey::from_openssh(trimmed).map_err(|_| Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("line {number} contains an invalid public key"),
        })?;
        if key.algorithm() != russh::keys::Algorithm::Ed25519 {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                reason: format!("line {number} is not an Ed25519 key"),
            });
        }
        let fingerprint = KeyFingerprint::from_ssh_key(&key);
        if keys
            .iter()
            .any(|existing| existing.fingerprint == fingerprint)
        {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                reason: format!("line {number} duplicates an earlier key"),
            });
        }
        drop(key);
        keys.push(AuthorizedKey { fingerprint });
    }
    if keys.is_empty() && !allow_empty {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "no valid Ed25519 key found".into(),
        });
    }
    Ok(keys)
}

impl AuthSnapshot {
    /// Parse an authorized-keys file with the strict bare subset:
    /// `ssh-ed25519 <base64> [comment]`. Options, certificates, non-Ed25519
    /// keys, malformed lines, and duplicate keys invalidate the whole file.
    #[allow(dead_code)]
    pub fn parse_authorized_keys(bytes: &[u8]) -> Result<Vec<AuthorizedKey>, Error> {
        parse_key_source(bytes, Path::new("<authorized_keys>"), false)
    }

    /// Load and validate the full authentication snapshot from host authorized_keys
    /// and sandbox allowed_keys sources.
    pub fn load(host_path: &Path, allowed_path: &Path) -> Result<AuthSnapshot, Error> {
        let host_bytes = read_key_source(host_path, "authorized_keys")?;
        let host_keys = match host_bytes {
            Some(bytes) => parse_key_source(&bytes, host_path, true)?,
            None => Vec::new(),
        };

        let allowed_bytes = read_key_source(allowed_path, "allowed_keys")?;
        let allowed_keys = match allowed_bytes {
            Some(bytes) => parse_key_source(&bytes, allowed_path, true)?,
            None => Vec::new(),
        };

        let mut principals = std::collections::BTreeMap::new();
        let mut keys = Vec::new();
        let mut admin_count = 0;

        for host_key in host_keys {
            if !principals.contains_key(&host_key.fingerprint) {
                principals.insert(host_key.fingerprint.clone(), Role::Admin);
                keys.push(host_key);
                admin_count += 1;
            }
        }

        for allowed_key in allowed_keys {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                principals.entry(allowed_key.fingerprint.clone())
            {
                entry.insert(Role::Normal);
                keys.push(allowed_key);
            }
        }

        if keys.is_empty() {
            return Err(Error::EmptyAuthSnapshot {
                host_path: host_path.to_path_buf(),
                allowed_path: allowed_path.to_path_buf(),
            });
        }

        Ok(AuthSnapshot {
            keys,
            principals,
            admin_count,
        })
    }

    /// Look up an authenticated key and derive its role.
    pub fn authenticate(&self, key: &russh::keys::PublicKey) -> Option<Principal> {
        if key.algorithm() != russh::keys::Algorithm::Ed25519 {
            return None;
        }
        let candidate = KeyFingerprint::from_ssh_key(key);
        self.principals.get(&candidate).map(|&role| Principal {
            fingerprint: candidate,
            role,
        })
    }

    /// Accepted fingerprints, in insertion order (test and audit surface).
    #[allow(dead_code)]
    pub fn keys(&self) -> &[AuthorizedKey] {
        &self.keys
    }

    pub fn admin_count(&self) -> usize {
        self.admin_count
    }
}

/// Maximum size of a single authorized_keys line.
pub const MAX_AUTHORIZED_KEYS_LINE_BYTES: usize = 8 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

    /// The authorized_keys validator intentionally rejects a world-writable
    /// ancestor such as the usual `/tmp`. Keep these fixtures below the crate
    /// workspace so the tests exercise the file checks rather than the
    /// permissions of the host's shared temp directory.
    fn auth_tempdir() -> TempDir {
        tempfile::Builder::new()
            .prefix(".shbox-auth-test-")
            .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("tempdir")
    }

    /// Generate a fresh Ed25519 keypair and return the authorized-keys line
    /// plus its fingerprint.
    fn generated_key() -> (String, KeyFingerprint) {
        let key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("generate");
        let public = key.public_key().clone();
        let line = public.to_openssh().expect("encode");
        (line, KeyFingerprint::from_ssh_key(&public))
    }

    #[test]
    fn parses_bare_authorized_keys() {
        let (line_a, fp_a) = generated_key();
        let (line_b, fp_b) = generated_key();
        let text = format!("\n# comment\n{line_a}\n\n{line_b} extra comment here\n");
        let parsed = AuthSnapshot::parse_authorized_keys(text.as_bytes()).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].fingerprint, fp_a);
        assert_eq!(parsed[1].fingerprint, fp_b);
    }

    #[test]
    fn rejects_options_certificates_and_other_algorithms() {
        let (line, _) = generated_key();
        let blob = line.split_whitespace().nth(1).unwrap().to_string();
        for bad in [
            format!("restrict {line}"),
            format!("command=\"sh\",pty {line}"),
            format!("ssh-ed25519-cert-v01@openssh.com {blob}"),
            format!("ssh-rsa {blob}"),
            format!("ecdsa-sha2-nistp256 {blob}"),
            "ssh-ed25519 not-base64!!".to_string(),
            "ssh-ed25519".to_string(),
        ] {
            let err = AuthSnapshot::parse_authorized_keys(bad.as_bytes()).expect_err(&bad);
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn rejects_duplicates_empty_and_oversized_lines() {
        let (line, _) = generated_key();
        assert!(AuthSnapshot::parse_authorized_keys(b"").is_err());
        let duplicate = format!("{line}\n{line}\n");
        assert!(AuthSnapshot::parse_authorized_keys(duplicate.as_bytes()).is_err());
        let long_line = format!("ssh-ed25519 {} x\n", "A".repeat(9 * 1024));
        assert!(AuthSnapshot::parse_authorized_keys(long_line.as_bytes()).is_err());
    }

    #[test]
    fn snapshot_load_two_sources_roles_and_overlap() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, fp_a) = generated_key();
        let (line_b, fp_b) = generated_key();
        let (key_a, key_b) = {
            let parse = |line: &str| russh::keys::PublicKey::from_openssh(line).expect("parse");
            (parse(&line_a), parse(&line_b))
        };
        // host has key_a; allowed has key_b AND key_a (overlap)
        std::fs::write(&host_path, format!("{line_a}\n")).expect("write host");
        std::fs::write(&allowed_path, format!("{line_b}\n{line_a}\n")).expect("write allowed");

        let snapshot = AuthSnapshot::load(&host_path, &allowed_path).expect("load");
        assert_eq!(snapshot.keys().len(), 2);
        assert_eq!(snapshot.admin_count(), 1);
        let principal_a = snapshot.authenticate(&key_a).expect("auth key_a");
        assert_eq!(principal_a.fingerprint, fp_a);
        assert_eq!(principal_a.role, Role::Admin);
        let principal_b = snapshot.authenticate(&key_b).expect("auth key_b");
        assert_eq!(principal_b.fingerprint, fp_b);
        assert_eq!(principal_b.role, Role::Normal);
    }

    #[test]
    fn snapshot_load_rejects_duplicates_within_single_source() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();

        // Duplicate in host file
        std::fs::write(&host_path, format!("{line_a}\n{line_a}\n")).expect("write host");
        std::fs::write(&allowed_path, format!("{line_b}\n")).expect("write allowed");
        let err = AuthSnapshot::load(&host_path, &allowed_path).expect_err("dup host");
        let message = err.to_string();
        assert!(
            message.contains(&host_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("duplicates an earlier key"), "{message}");

        // Duplicate in allowed file
        std::fs::write(&host_path, format!("{line_a}\n")).expect("write host");
        std::fs::write(&allowed_path, format!("{line_b}\n{line_b}\n")).expect("write allowed");
        let err = AuthSnapshot::load(&host_path, &allowed_path).expect_err("dup allowed");
        let message = err.to_string();
        assert!(
            message.contains(&allowed_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("duplicates an earlier key"), "{message}");
    }

    #[test]
    fn snapshot_load_missing_and_empty_sources() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let missing_host = home.path().join("missing_host");
        let missing_allowed = home.path().join("missing_allowed");
        let (line_a, fp_a) = generated_key();
        let (line_b, fp_b) = generated_key();
        let (key_a, key_b) = {
            let parse = |line: &str| russh::keys::PublicKey::from_openssh(line).expect("parse");
            (parse(&line_a), parse(&line_b))
        };

        std::fs::write(&host_path, format!("{line_a}\n")).expect("write host");
        std::fs::write(&allowed_path, format!("{line_b}\n")).expect("write allowed");

        // Missing host + valid allowed
        let snapshot = AuthSnapshot::load(&missing_host, &allowed_path).expect("missing host");
        assert_eq!(snapshot.admin_count(), 0);
        assert_eq!(snapshot.authenticate(&key_b).unwrap().role, Role::Normal);
        assert_eq!(snapshot.keys()[0].fingerprint, fp_b);

        // Empty host + valid allowed
        let empty_host = home.path().join("empty_host");
        std::fs::write(&empty_host, b"").expect("write empty");
        let snapshot = AuthSnapshot::load(&empty_host, &allowed_path).expect("empty host");
        assert_eq!(snapshot.admin_count(), 0);
        assert_eq!(snapshot.authenticate(&key_b).unwrap().role, Role::Normal);

        // Valid host + missing allowed
        let snapshot = AuthSnapshot::load(&host_path, &missing_allowed).expect("missing allowed");
        assert_eq!(snapshot.admin_count(), 1);
        assert_eq!(snapshot.authenticate(&key_a).unwrap().role, Role::Admin);
        assert_eq!(snapshot.keys()[0].fingerprint, fp_a);

        // Valid host + empty allowed
        let empty_allowed = home.path().join("empty_allowed");
        std::fs::write(&empty_allowed, b"").expect("write empty");
        let snapshot = AuthSnapshot::load(&host_path, &empty_allowed).expect("empty allowed");
        assert_eq!(snapshot.admin_count(), 1);
        assert_eq!(snapshot.authenticate(&key_a).unwrap().role, Role::Admin);

        // Both missing -> empty snapshot error
        let err = AuthSnapshot::load(&missing_host, &missing_allowed).expect_err("both missing");
        assert!(matches!(err, Error::EmptyAuthSnapshot { .. }), "{err}");

        // Both empty -> empty snapshot error
        let err = AuthSnapshot::load(&empty_host, &empty_allowed).expect_err("both empty");
        assert!(matches!(err, Error::EmptyAuthSnapshot { .. }), "{err}");

        // Both comment-only -> empty snapshot error
        let comment_host = home.path().join("comment_host");
        let comment_allowed = home.path().join("comment_allowed");
        std::fs::write(&comment_host, "# comment only\n\n").expect("write comment");
        std::fs::write(&comment_allowed, "# another comment\n").expect("write comment");
        let err = AuthSnapshot::load(&comment_host, &comment_allowed).expect_err("comment only");
        assert!(matches!(err, Error::EmptyAuthSnapshot { .. }), "{err}");
    }

    #[test]
    fn snapshot_load_fails_on_any_malformed_or_unsafe_source() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();

        // Host valid, allowed malformed -> error specifies allowed path
        std::fs::write(&host_path, format!("{line_a}\n")).expect("write host");
        std::fs::write(&allowed_path, "not-a-valid-key\n").expect("write allowed");
        let err = AuthSnapshot::load(&host_path, &allowed_path).expect_err("malformed allowed");
        let message = err.to_string();
        assert!(
            message.contains(&allowed_path.display().to_string()),
            "{message}"
        );

        // Host malformed, allowed valid -> error specifies host path
        std::fs::write(&host_path, "not-a-valid-key\n").expect("write host");
        std::fs::write(&allowed_path, format!("{line_b}\n")).expect("write allowed");
        let err = AuthSnapshot::load(&host_path, &allowed_path).expect_err("malformed host");
        let message = err.to_string();
        assert!(
            message.contains(&host_path.display().to_string()),
            "{message}"
        );
    }

    #[test]
    fn authenticate_rejects_unknown_keys() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, fp_a) = generated_key();
        std::fs::write(&host_path, &line_a).expect("write");
        let snapshot = AuthSnapshot::load(&host_path, &allowed_path).expect("load");
        let (foreign_line, _) = generated_key();
        let foreign_key = russh::keys::PublicKey::from_openssh(&foreign_line).expect("parse");
        assert!(snapshot.authenticate(&foreign_key).is_none());
        assert_eq!(snapshot.keys()[0].fingerprint, fp_a);
    }

    /// Encode bytes as canonical unpadded standard base64 (test-local, so the
    /// parser is checked against an independent implementation).
    fn encode_unpadded(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(BASE64_ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(BASE64_ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(BASE64_ALPHABET[(n >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                out.push(BASE64_ALPHABET[n as usize & 63] as char);
            }
        }
        out
    }

    #[test]
    fn accepts_canonical_fingerprints() {
        let digest = [0u8; 32];
        let raw = format!("SHA256:{}", encode_unpadded(&digest));
        let parsed = KeyFingerprint::parse(&raw).expect("parse");
        assert_eq!(parsed.as_str(), raw);
        assert_eq!(raw.len(), 7 + 43);
    }

    #[test]
    fn rejects_common_malformations() {
        let good = format!("SHA256:{}", encode_unpadded(&[7u8; 32]));
        assert_eq!(
            KeyFingerprint::parse(&good[1..]),
            Err(FingerprintError::MissingPrefix)
        );
        assert_eq!(
            KeyFingerprint::parse(""),
            Err(FingerprintError::MissingPrefix)
        );
        // Wrong body length.
        assert_eq!(
            KeyFingerprint::parse(&format!("SHA256:{}", &good[7..42])),
            Err(FingerprintError::BadLength(35))
        );
        // Padded input is rejected.
        let mut padded = good.clone();
        padded.push('=');
        assert_eq!(
            KeyFingerprint::parse(&padded),
            Err(FingerprintError::BadLength(44))
        );
        // Invalid character.
        assert_eq!(
            KeyFingerprint::parse(&format!("SHA256:{}", "-".repeat(43))),
            Err(FingerprintError::InvalidCharacter(0, b'-'))
        );
    }

    #[test]
    fn rejects_non_zero_trailing_bits() {
        // The canonical encoding of 32 bytes has two zero padding bits in its
        // final character. Take a canonical body, replace the last character
        // with one whose low two bits are non-zero, and the parser must reject
        // it as non-canonical rather than silently reinterpreting the digest.
        let body = encode_unpadded(&[0x0au8; 32]);
        assert_eq!(body.len(), 43);
        let mut chars: Vec<u8> = body.bytes().collect();
        // The canonical final character has zero padding bits (decoded value,
        // not the ASCII byte, carries the trailing bits).
        assert_eq!(base64_value(chars[42]).unwrap() & 0b11, 0);
        let replacement = *BASE64_ALPHABET
            .iter()
            .find(|&&c| base64_value(c).unwrap() & 0b11 != 0)
            .expect("alphabet contains characters with non-zero low bits");
        chars[42] = replacement;
        let mutated = format!("SHA256:{}", String::from_utf8(chars).expect("ascii"));
        assert_eq!(
            KeyFingerprint::parse(&mutated),
            Err(FingerprintError::NonCanonical)
        );
    }

    proptest! {
        #[test]
        fn round_trips_arbitrary_digests(digest in proptest::collection::vec(any::<u8>(), 32)) {
            let raw = format!("SHA256:{}", encode_unpadded(&digest));
            let parsed = KeyFingerprint::parse(&raw).expect("canonical encoding parses");
            assert_eq!(parsed.as_str(), raw);
        }

        #[test]
        fn single_character_mutations_never_change_identity(
            seed in proptest::collection::vec(any::<u8>(), 32),
            index in 0usize..43,
        ) {
            let raw = format!("SHA256:{}", encode_unpadded(&seed));
            let mut chars: Vec<u8> = raw[7..].bytes().collect();
            let replacement = (0..64u8)
                .map(|i| BASE64_ALPHABET[i as usize])
                .find(|&c| c != chars[index])
                .expect("alphabet has 64 characters");
            chars[index] = replacement;
            let mutated = format!("SHA256:{}", String::from_utf8(chars).expect("ascii"));
            match KeyFingerprint::parse(&mutated) {
                // Rejected input never becomes a valid fingerprint...
                Err(_) => {}
                // ...and accepted input still identifies the mutated digest,
                // never the original one.
                Ok(parsed) => assert_ne!(parsed.as_str(), raw),
            }
        }
    }

    #[test]
    fn validates_key_source_file_safety() {
        let home = auth_tempdir();
        let path = home.path().join("keys");
        // Missing -> returns Ok(false)
        assert!(!validate_key_source_file(&path, "test_keys").unwrap());
        // Valid.
        fs::write(&path, b"ssh-ed25519 AAAA test\n").expect("write");
        assert!(validate_key_source_file(&path, "test_keys").unwrap());
        // Group writable -> Err(Invalid)
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).expect("chmod");
        assert!(matches!(
            validate_key_source_file(&path, "test_keys"),
            Err(Error::Invalid { .. })
        ));
    }

    #[test]
    fn rejects_oversized_key_source_file() {
        let home = auth_tempdir();
        let path = home.path().join("keys");
        let line = b"ssh-ed25519 AAAA test\n".repeat(48 * 1024);
        fs::write(&path, &line).expect("write big");
        assert!(matches!(
            validate_key_source_file(&path, "test_keys"),
            Err(Error::Invalid { .. })
        ));
    }

    #[test]
    fn resolves_authorized_keys_default_path() {
        if std::env::var_os("HOME").is_some() {
            let default = resolve_authorized_keys_path().expect("default");
            assert!(default.ends_with(".ssh/authorized_keys"));
        }
    }
}
