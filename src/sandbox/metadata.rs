//! Durable v1 metadata for one sandbox.
//!
//! Metadata is the ownership and lifecycle source of truth.  It deliberately
//! contains no process or platform fields, so a restart can validate the
//! record without reconstructing an Arapuca object.

use std::fmt;

use serde::Deserialize;

use crate::auth::KeyFingerprint;

use super::id::SandboxId;

/// The only metadata schema version understood by this release.
pub const VERSION: u32 = 1;
/// Bound metadata before handing it to the TOML parser.
pub const MAX_BYTES: usize = 16 * 1024;

/// Durable lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Active,
    Deleting,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Deleting => "deleting",
        }
    }

    fn parse(raw: &str) -> Result<State, Error> {
        match raw {
            "active" => Ok(State::Active),
            "deleting" => Ok(State::Deleting),
            _ => Err(Error::InvalidState(raw.to_string())),
        }
    }
}

/// A validated, durable v1 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    id: SandboxId,
    owner: KeyFingerprint,
    state: State,
}

impl Metadata {
    pub fn active(id: SandboxId, owner: KeyFingerprint) -> Metadata {
        Metadata {
            id,
            owner,
            state: State::Active,
        }
    }

    pub fn id(&self) -> &SandboxId {
        &self.id
    }

    pub fn owner(&self) -> &KeyFingerprint {
        &self.owner
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn is_active(&self) -> bool {
        self.state == State::Active
    }

    pub fn is_deleting(&self) -> bool {
        self.state == State::Deleting
    }

    pub fn with_state(&self, state: State) -> Metadata {
        Metadata {
            id: self.id.clone(),
            owner: self.owner.clone(),
            state,
        }
    }

    /// Encode in a stable field order.  The domain values are already
    /// restricted to ASCII, but debug string quoting keeps this serializer
    /// correct if that restriction is ever widened.
    pub fn encode(&self) -> String {
        format!(
            "version = {VERSION}\nid = {:?}\nowner = {:?}\nstate = {:?}\n",
            self.id.as_str(),
            self.owner.as_str(),
            self.state.as_str(),
        )
    }

    /// Parse and validate a complete metadata document.  `expected_id` is the
    /// directory name and prevents a valid record from being transplanted.
    pub fn decode(bytes: &[u8], expected_id: &SandboxId) -> Result<Metadata, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge(bytes.len()));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::NotUtf8)?;
        let raw: RawMetadata = toml::from_str(text).map_err(Error::Toml)?;
        if raw.version != VERSION {
            return Err(Error::UnsupportedVersion(raw.version));
        }
        let id = SandboxId::parse(&raw.id).map_err(|error| Error::InvalidId {
            reason: error.to_string(),
        })?;
        if &id != expected_id {
            return Err(Error::MismatchedId {
                expected: expected_id.clone(),
                found: id,
            });
        }
        let owner = KeyFingerprint::parse(&raw.owner).map_err(|error| Error::InvalidOwner {
            reason: error.to_string(),
        })?;
        let state = State::parse(&raw.state)?;
        Ok(Metadata { id, owner, state })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMetadata {
    version: u32,
    id: String,
    owner: String,
    state: String,
}

/// Metadata parsing failures.  Storage wraps these as a corrupt management
/// entry and never rewrites the offending bytes.
#[derive(Debug)]
pub enum Error {
    TooLarge(usize),
    NotUtf8,
    Toml(toml::de::Error),
    UnsupportedVersion(u32),
    InvalidId {
        reason: String,
    },
    MismatchedId {
        expected: SandboxId,
        found: SandboxId,
    },
    InvalidOwner {
        reason: String,
    },
    InvalidState(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge(size) => write!(f, "metadata is {size} bytes, limit is {MAX_BYTES}"),
            Error::NotUtf8 => f.write_str("metadata is not valid UTF-8"),
            Error::Toml(error) => write!(f, "metadata is not valid TOML: {error}"),
            Error::UnsupportedVersion(version) => {
                write!(f, "metadata version {version} is unsupported")
            }
            Error::InvalidId { reason, .. } => write!(f, "metadata id is invalid: {reason}"),
            Error::MismatchedId { expected, found } => {
                write!(
                    f,
                    "metadata id does not match directory {expected} (found {found})"
                )
            }
            Error::InvalidOwner { reason } => write!(f, "metadata owner is invalid: {reason}"),
            Error::InvalidState(state) => write!(f, "metadata state {state:?} is invalid"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Toml(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> KeyFingerprint {
        KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).expect("owner")
    }

    #[test]
    fn round_trips_in_deterministic_field_order() {
        let id = SandboxId::parse("dev").expect("id");
        let metadata = Metadata::active(id.clone(), owner());
        let encoded = metadata.encode();
        assert_eq!(
            encoded,
            "version = 1\nid = \"dev\"\nowner = \"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\nstate = \"active\"\n"
        );
        assert_eq!(
            Metadata::decode(encoded.as_bytes(), &id).expect("decode"),
            metadata
        );
    }

    #[test]
    fn deleting_state_preserves_identity() {
        let id = SandboxId::parse("dev").expect("id");
        let metadata = Metadata::active(id.clone(), owner()).with_state(State::Deleting);
        assert!(metadata.is_deleting());
        assert_eq!(metadata.id(), &id);
        assert_eq!(metadata.owner(), &owner());
    }

    #[test]
    fn rejects_unknown_fields_versions_and_values() {
        let id = SandboxId::parse("dev").expect("id");
        let base = Metadata::active(id.clone(), owner()).encode();
        for invalid in [
            format!("{base}extra = true\n"),
            base.replace("version = 1", "version = 2"),
            base.replace("state = \"active\"", "state = \"running\""),
            base.replace("id = \"dev\"", "id = \"../dev\""),
            base.replace(
                "owner = \"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
                "owner = \"bad\"",
            ),
        ] {
            assert!(
                Metadata::decode(invalid.as_bytes(), &id).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rejects_id_mismatch_duplicate_and_oversized_documents() {
        let id = SandboxId::parse("dev").expect("id");
        let other = SandboxId::parse("prod").expect("id");
        let encoded = Metadata::active(other.clone(), owner()).encode();
        assert!(matches!(
            Metadata::decode(encoded.as_bytes(), &id),
            Err(Error::MismatchedId { .. })
        ));
        let duplicate = format!("{encoded}id = \"dev\"\n");
        assert!(Metadata::decode(duplicate.as_bytes(), &other).is_err());
        assert!(matches!(
            Metadata::decode(&vec![b'x'; MAX_BYTES + 1], &id),
            Err(Error::TooLarge(_))
        ));
    }
}
