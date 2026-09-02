//! Validated sandbox identifiers.
//!
//! `SandboxId` is the only value allowed to become a sandbox directory name.
//! The grammar is ASCII, case-sensitive, and deliberately excludes `_` (the
//! reserved host selector), `.`, `/`, whitespace, control characters, and any
//! non-ASCII byte.

use std::fmt;
use std::str::FromStr;

/// Maximum byte length of a sandbox id.
pub const MAX_ID_BYTES: usize = 64;

/// A validated sandbox identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxId(String);

impl SandboxId {
    /// Validate and construct; this is the single point of id validation.
    pub fn parse(raw: &str) -> Result<SandboxId, InvalidSandboxId> {
        let bytes = raw.as_bytes();
        if bytes.is_empty() {
            return Err(InvalidSandboxId::Empty);
        }
        if bytes.len() > MAX_ID_BYTES {
            return Err(InvalidSandboxId::TooLong(bytes.len()));
        }
        let first = bytes[0];
        if !first.is_ascii_alphanumeric() {
            return Err(InvalidSandboxId::Byte(0, first));
        }
        for (index, &byte) in bytes.iter().enumerate().skip(1) {
            if !byte.is_ascii_alphanumeric() && byte != b'-' {
                return Err(InvalidSandboxId::Byte(index, byte));
            }
        }
        Ok(SandboxId(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SandboxId {
    type Err = InvalidSandboxId;

    fn from_str(raw: &str) -> Result<SandboxId, InvalidSandboxId> {
        SandboxId::parse(raw)
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SandboxId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Sandbox id validation failure, carrying the offending byte when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidSandboxId {
    Empty,
    TooLong(usize),
    Byte(usize, u8),
}

impl fmt::Display for InvalidSandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidSandboxId::Empty => write!(f, "sandbox id is empty"),
            InvalidSandboxId::TooLong(length) => {
                write!(
                    f,
                    "sandbox id is {length} bytes, the limit is {MAX_ID_BYTES}"
                )
            }
            InvalidSandboxId::Byte(index, byte) => {
                write!(
                    f,
                    "sandbox id contains invalid byte {byte:#04x} at offset {index}"
                )
            }
        }
    }
}

impl std::error::Error for InvalidSandboxId {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Independent restatement of the documented grammar
    /// `[A-Za-z0-9][A-Za-z0-9-]{0,63}`.
    fn grammar_allows(raw: &str) -> bool {
        let bytes = raw.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= MAX_ID_BYTES
            && bytes[0].is_ascii_alphanumeric()
            && bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    }

    #[test]
    fn accepts_valid_ids() {
        for id in [
            "a",
            "A",
            "0",
            "dev",
            "Dev-1",
            "a-b-c",
            "x0-",
            &"a".repeat(64),
        ] {
            let parsed = SandboxId::parse(id).expect(id);
            assert_eq!(parsed.as_str(), id);
        }
    }

    #[test]
    fn rejects_forbidden_shapes() {
        for id in [
            "",              // empty
            "_",             // host selector
            "-a",            // leading hyphen
            ".a",            // leading dot
            "a b",           // whitespace
            "a/b",           // path separator
            "a_b",           // underscore
            "a.",            // trailing dot
            "a\t",           // control character
            "a\n",           // newline
            "café",          // non-ASCII
            "あ",            // non-ASCII
            &"a".repeat(65), // overlong
        ] {
            let err = SandboxId::parse(id).expect_err(id);
            assert!(!grammar_allows(id), "{id:?} unexpectedly matches grammar");
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn ids_are_case_sensitive_and_ordered() {
        let lower = SandboxId::parse("dev").expect("dev");
        let upper = SandboxId::parse("DEV").expect("DEV");
        assert_ne!(lower, upper);
        assert!(upper < lower); // bytewise ASCII order: 'D' (0x44) sorts before 'd' (0x64)
    }

    proptest! {
        #[test]
        fn accepts_exactly_the_documented_grammar(
            first in "[A-Za-z0-9]",
            rest in proptest::collection::vec("[A-Za-z0-9-]", 0..64),
        ) {
            let raw = format!("{first}{}", rest.join(""));
            assert!(grammar_allows(&raw), "{raw:?}");
            SandboxId::parse(&raw).expect("grammar-valid id parses");
        }

        #[test]
        fn rejects_anything_outside_the_grammar(raw in ".*") {
            let parsed = SandboxId::parse(&raw);
            assert_eq!(parsed.is_ok(), grammar_allows(&raw), "{raw:?}");
        }
    }
}
