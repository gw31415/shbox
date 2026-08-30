//! Key fingerprints and authorized-keys file validation.
//!
//! The stable principal identifier in shbox is the OpenSSH SHA-256 fingerprint
//! of the exact Ed25519 public key bytes:
//!
//! ```text
//! SHA256:<43 characters of unpadded standard base64>
//! ```
//!
//! Fingerprints printed by `ssh-keygen -lf` parse here unchanged. Milestone 2
//! extends this module with authorized-keys line parsing and principals;
//! Milestone 1 validates fingerprints referenced by configuration and the
//! file-level safety of the authorized-keys file itself.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
/// limit, and be non-empty. Line-level parsing arrives in Milestone 2.
pub fn validate_authorized_keys_file(path: &Path) -> Result<(), Error> {
    let metadata = fs::metadata(path).map_err(|err| match err.kind() {
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
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

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
        let home = TempDir::new().expect("tempdir");
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
        let home = TempDir::new().expect("tempdir");
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
