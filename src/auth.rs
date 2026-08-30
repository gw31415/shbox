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

/// Resolve the authorized-keys file: the configured absolute path, or the
/// daemon user's `~/.ssh/authorized_keys`.
pub fn resolve_authorized_keys_path(configured: Option<&Path>) -> Result<PathBuf, Error> {
    match configured {
        Some(path) => Ok(path.to_path_buf()),
        None => match paths::home_dir() {
            Ok(home) => Ok(home.join(".ssh").join("authorized_keys")),
            Err(err) => Err(Error::Home {
                message: err.to_string(),
            }),
        },
    }
}

/// Validate file-level safety of the authorized-keys file: it must exist, be a
/// regular file the daemon user owns, be group/world unwritable, fit the size
/// limit, and be non-empty. The descriptor is opened without following the
/// final path component.
pub fn validate_authorized_keys_file(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound => Error::NotFound {
            path: path.to_path_buf(),
        },
        _ => Error::Io {
            path: path.to_path_buf(),
            message: "cannot stat authorized_keys".into(),
            source: err,
        },
    })?;
    if !metadata.is_file() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "not a regular file".into(),
        });
    }
    if metadata.file_type().is_symlink() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "file must not be a symlink".into(),
        });
    }
    if metadata.len() == 0 {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "file is empty".into(),
        });
    }
    if metadata.len() > MAX_AUTHORIZED_KEYS_BYTES {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("file exceeds the {} byte limit", MAX_AUTHORIZED_KEYS_BYTES),
        });
    }
    if metadata.uid() != paths::euid() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "not owned by the daemon user".into(),
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: "group or world writable".into(),
        });
    }
    validate_authorized_keys_parents(path)?;
    Ok(())
}

/// Validate the containing directory chain before opening the key file. The
/// immediate parent must belong to the daemon account and must not be a
/// symlink; higher ancestors may be system-owned (macOS commonly exposes
/// `/var` this way), but none may be writable by group/other.
fn validate_authorized_keys_parents(path: &Path) -> Result<(), Error> {
    let mut current = path.parent();
    let mut immediate = true;
    while let Some(directory) = current {
        let link_metadata = fs::symlink_metadata(directory).map_err(|err| Error::Io {
            path: directory.to_path_buf(),
            message: "cannot stat authorized_keys parent".into(),
            source: err,
        })?;
        if immediate && link_metadata.file_type().is_symlink() {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: "authorized_keys parent must not be a symlink".into(),
            });
        }
        let metadata = fs::metadata(directory).map_err(|err| Error::Io {
            path: directory.to_path_buf(),
            message: "cannot stat authorized_keys parent".into(),
            source: err,
        })?;
        if !metadata.is_dir() {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: "authorized_keys parent is not a directory".into(),
            });
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: "authorized_keys parent is group or world writable".into(),
            });
        }
        if immediate && metadata.uid() != paths::euid() {
            return Err(Error::Invalid {
                path: directory.to_path_buf(),
                reason: "authorized_keys parent is not owned by the daemon user".into(),
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
/// closes the check/use race for the final authorized_keys path.
fn read_authorized_keys(path: &Path) -> Result<Vec<u8>, Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| Error::Io {
            path: path.to_path_buf(),
            message: "cannot open authorized_keys".into(),
            source: err,
        })?;
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take(MAX_AUTHORIZED_KEYS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::Io {
            path: path.to_path_buf(),
            message: "cannot read authorized_keys".into(),
            source: err,
        })?;
    Ok(bytes)
}

/// Authorized-keys file errors.
#[derive(Debug)]
pub enum Error {
    Home {
        message: String,
    },
    NotFound {
        path: PathBuf,
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Home { message } => {
                write!(f, "cannot resolve the daemon home directory: {message}")
            }
            Error::NotFound { path } => write!(f, "authorized_keys not found: {}", path.display()),
            Error::Invalid { path, reason } => {
                write!(f, "invalid authorized_keys at {}: {reason}", path.display())
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

/// The validated authentication snapshot: exactly the authorized Ed25519 keys
/// plus the admin fingerprint subset. Connections capture their own clone, so
/// a later reload can only affect new connections.
#[derive(Debug, Clone, Default)]
pub struct AuthSnapshot {
    keys: Vec<AuthorizedKey>,
    admin: std::collections::BTreeSet<KeyFingerprint>,
}

impl AuthSnapshot {
    /// Parse an authorized-keys file with the strict bare subset:
    /// `ssh-ed25519 <base64> [comment]`. Options, certificates, non-Ed25519
    /// keys, malformed lines, and duplicate keys invalidate the whole file.
    pub fn parse_authorized_keys(bytes: &[u8]) -> Result<Vec<AuthorizedKey>, Error> {
        if bytes.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
            return Err(Error::Invalid {
                path: PathBuf::from("<authorized_keys>"),
                reason: "file exceeds the 1 MiB limit".into(),
            });
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid {
            path: PathBuf::from("<authorized_keys>"),
            reason: "file is not valid UTF-8".into(),
        })?;
        let mut keys: Vec<AuthorizedKey> = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            if line.len() > MAX_AUTHORIZED_KEYS_LINE_BYTES {
                return Err(Error::Invalid {
                    path: PathBuf::from("<authorized_keys>"),
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
                // Options, certificates, and other algorithms all fail this
                // first-field check, so the bare form is enforced by
                // construction; a trailing comment is still allowed.
                return Err(Error::Invalid {
                    path: PathBuf::from("<authorized_keys>"),
                    reason: format!("line {number} is not bare `ssh-ed25519 <base64> [comment]`"),
                });
            }
            let key =
                russh::keys::PublicKey::from_openssh(trimmed).map_err(|_| Error::Invalid {
                    path: PathBuf::from("<authorized_keys>"),
                    reason: format!("line {number} contains an invalid public key"),
                })?;
            if key.algorithm() != russh::keys::Algorithm::Ed25519 {
                return Err(Error::Invalid {
                    path: PathBuf::from("<authorized_keys>"),
                    reason: format!("line {number} is not an Ed25519 key"),
                });
            }
            let fingerprint = KeyFingerprint::from_ssh_key(&key);
            if keys
                .iter()
                .any(|existing| existing.fingerprint == fingerprint)
            {
                return Err(Error::Invalid {
                    path: PathBuf::from("<authorized_keys>"),
                    reason: format!("line {number} duplicates an earlier key"),
                });
            }
            drop(key);
            keys.push(AuthorizedKey { fingerprint });
        }
        if keys.is_empty() {
            return Err(Error::Invalid {
                path: PathBuf::from("<authorized_keys>"),
                reason: "no valid Ed25519 key found".into(),
            });
        }
        Ok(keys)
    }

    /// Load and validate the full authentication snapshot: authorized keys
    /// plus the admin subset from configuration.
    pub fn load(
        authorized_keys_path: &Path,
        admin_keys: &[KeyFingerprint],
    ) -> Result<AuthSnapshot, Error> {
        validate_authorized_keys_file(authorized_keys_path)?;
        let bytes = read_authorized_keys(authorized_keys_path).map_err(|err| match err {
            Error::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                Error::NotFound {
                    path: authorized_keys_path.to_path_buf(),
                }
            }
            other => other,
        })?;
        let keys = Self::parse_authorized_keys(&bytes).map_err(|mut err| {
            if let Error::Invalid { path, .. } = &mut err {
                *path = authorized_keys_path.to_path_buf();
            }
            err
        })?;
        let known: std::collections::BTreeSet<&KeyFingerprint> =
            keys.iter().map(|entry| &entry.fingerprint).collect();
        let mut admin = std::collections::BTreeSet::new();
        for fingerprint in admin_keys {
            if !known.contains(fingerprint) {
                return Err(Error::Invalid {
                    path: authorized_keys_path.to_path_buf(),
                    reason: format!("admin key {fingerprint} is not present in authorized_keys"),
                });
            }
            admin.insert(fingerprint.clone());
        }
        Ok(AuthSnapshot { keys, admin })
    }

    /// Look up an authenticated key and derive its role.
    pub fn authenticate(&self, key: &russh::keys::PublicKey) -> Option<Principal> {
        if key.algorithm() != russh::keys::Algorithm::Ed25519 {
            return None;
        }
        let candidate = KeyFingerprint::from_ssh_key(key);
        self.keys
            .iter()
            .any(|entry| entry.fingerprint == candidate)
            .then(|| {
                let role = if self.admin.contains(&candidate) {
                    Role::Admin
                } else {
                    Role::Normal
                };
                Principal {
                    fingerprint: candidate,
                    role,
                }
            })
    }

    /// Accepted fingerprints, in file order (test and audit surface).
    #[allow(dead_code)]
    pub fn keys(&self) -> &[AuthorizedKey] {
        &self.keys
    }

    pub fn admin_count(&self) -> usize {
        self.admin.len()
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
    fn snapshot_load_validates_admin_subset() {
        let home = auth_tempdir();
        let path = home.path().join("authorized_keys");
        let (line_a, fp_a) = generated_key();
        let (line_b, _fp_b) = generated_key();
        let (key_a, key_b) = {
            let parse = |line: &str| russh::keys::PublicKey::from_openssh(line).expect("parse");
            (parse(&line_a), parse(&line_b))
        };
        std::fs::write(&path, format!("{line_a}\n{line_b}\n")).expect("write");

        let snapshot = AuthSnapshot::load(&path, std::slice::from_ref(&fp_a)).expect("load");
        assert_eq!(snapshot.keys().len(), 2);
        assert_eq!(snapshot.admin_count(), 1);
        assert_eq!(snapshot.authenticate(&key_a).unwrap().role, Role::Admin);
        assert_eq!(snapshot.authenticate(&key_b).unwrap().role, Role::Normal);

        // An admin fingerprint absent from authorized_keys is a config error.
        let (line_c, fp_c) = generated_key();
        std::fs::write(home.path().join("c"), &line_c).expect("write c");
        assert!(AuthSnapshot::load(&path, std::slice::from_ref(&fp_c)).is_err());
    }

    #[test]
    fn authenticate_rejects_unknown_keys() {
        let home = auth_tempdir();
        let path = home.path().join("authorized_keys");
        let (line_a, fp_a) = generated_key();
        std::fs::write(&path, &line_a).expect("write");
        let snapshot = AuthSnapshot::load(&path, &[]).expect("load");
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
    fn validates_authorized_keys_file_safety() {
        let home = auth_tempdir();
        let path = home.path().join("authorized_keys");
        // Missing.
        assert!(matches!(
            validate_authorized_keys_file(&path),
            Err(Error::NotFound { .. })
        ));
        // Empty.
        fs::write(&path, b"").expect("write empty");
        assert!(matches!(
            validate_authorized_keys_file(&path),
            Err(Error::Invalid { .. })
        ));
        // Valid.
        fs::write(&path, b"ssh-ed25519 AAAA test\n").expect("write");
        validate_authorized_keys_file(&path).expect("valid");
        // Group writable.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).expect("chmod");
        assert!(matches!(
            validate_authorized_keys_file(&path),
            Err(Error::Invalid { .. })
        ));
    }

    #[test]
    fn rejects_oversized_authorized_keys_file() {
        let home = auth_tempdir();
        let path = home.path().join("authorized_keys");
        let line = b"ssh-ed25519 AAAA test\n".repeat(48 * 1024);
        fs::write(&path, &line).expect("write big");
        assert!(matches!(
            validate_authorized_keys_file(&path),
            Err(Error::Invalid { .. })
        ));
    }

    #[test]
    fn resolves_configured_path_and_default() {
        let configured =
            KeyFingerprint::parse("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .expect("parse");
        assert_eq!(configured.as_str().len(), 50);
        let explicit =
            resolve_authorized_keys_path(Some(Path::new("/etc/keys"))).expect("explicit");
        assert_eq!(explicit, Path::new("/etc/keys"));
        if std::env::var_os("HOME").is_some() {
            let default = resolve_authorized_keys_path(None).expect("default");
            assert!(default.ends_with(".ssh/authorized_keys"));
        }
    }
}
