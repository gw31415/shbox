//! Subordinate-ID delegation discovery.
//!
//! The daemon account's subordinate UID/GID ranges are discovered through
//! shadow-utils semantics: `getsubids <user>` / `getsubids -g <user>` for
//! discovery and diagnosis, honoring an NSS `subid` backend when one is
//! configured. `/etc/subuid` and `/etc/subgid` are deliberately not parsed
//! as the source of truth.
//!
//! Delegation is treated as *process-lifetime mutable*: the cache checks the
//! cheap source-generation metadata before returning a warm snapshot, and a
//! caller that finds a lease outside that snapshot re-queries before using
//! it. An active lease that falls outside the current delegation stays
//! recorded but blocks new isolated launches.

use std::fmt;
use std::fs;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// One delegated half-open range `[start, start + count)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubidRange {
    start: u32,
    count: u32,
}

impl SubidRange {
    /// Construct a range with checked arithmetic. Rejects zero-length
    /// ranges and end-of-range overflow past the Linux 32-bit ID space.
    pub(crate) fn new(start: u64, count: u64) -> Result<SubidRange, Error> {
        if count == 0 {
            return Err(Error::Range("zero-length subordinate range"));
        }
        if start > u32::MAX as u64 {
            return Err(Error::Range("range start exceeds the 32-bit ID space"));
        }
        let end = start + count;
        if end > u32::MAX as u64 + 1 {
            return Err(Error::Range("range end overflows the 32-bit ID space"));
        }
        Ok(SubidRange {
            start: start as u32,
            count: count as u32,
        })
    }

    pub(crate) fn start(&self) -> u32 {
        self.start
    }

    /// Exclusive end of the range (at most `u32::MAX + 1`).
    fn end(&self) -> u64 {
        self.start as u64 + self.count as u64
    }

    pub(crate) fn contains(&self, id: u32) -> bool {
        let id = id as u64;
        id >= self.start as u64 && id < self.end()
    }

    /// Iterate the IDs of the range in increasing order. The arithmetic is
    /// u64 because a range ending at `u32::MAX + 1` does not fit `u32`.
    pub(crate) fn ids(&self) -> impl Iterator<Item = u32> {
        (self.start as u64..self.end()).map(|id| id as u32)
    }
}

/// The daemon account's current subordinate UID and GID delegations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Delegation {
    pub(crate) uid_ranges: Vec<SubidRange>,
    pub(crate) gid_ranges: Vec<SubidRange>,
}

impl Delegation {
    pub(crate) fn contains_uid(&self, uid: u32) -> bool {
        self.uid_ranges.iter().any(|range| range.contains(uid))
    }

    pub(crate) fn contains_gid(&self, gid: u32) -> bool {
        self.gid_ranges.iter().any(|range| range.contains(gid))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileGeneration {
    present: bool,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl FileGeneration {
    fn read(path: &str) -> FileGeneration {
        match fs::metadata(path) {
            Ok(metadata) => FileGeneration {
                present: true,
                len: metadata.len(),
                modified: metadata.modified().ok(),
            },
            Err(_) => FileGeneration {
                present: false,
                len: 0,
                modified: None,
            },
        }
    }
}

/// A cheap generation for local inputs that can change the result of
/// `getsubids`. NSS-backed deployments still benefit from the cache: their
/// configured source is normally stable for the daemon lifetime, while a
/// change to the local NSS/subid configuration invalidates the snapshot
/// synchronously on the next use.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DelegationGeneration {
    subuid: FileGeneration,
    subgid: FileGeneration,
    nsswitch: FileGeneration,
}

impl DelegationGeneration {
    fn current() -> DelegationGeneration {
        DelegationGeneration {
            subuid: FileGeneration::read("/etc/subuid"),
            subgid: FileGeneration::read("/etc/subgid"),
            nsswitch: FileGeneration::read("/etc/nsswitch.conf"),
        }
    }
}

#[derive(Debug)]
struct CachedDelegation {
    generation: DelegationGeneration,
    delegation: Delegation,
}

/// Process-lifetime delegation cache. The account lookup and delegation
/// snapshot share this object so a warm launch does not repeat either NSS
/// lookup or the two `getsubids` subprocesses.
#[derive(Debug, Default)]
pub(crate) struct DelegationCache {
    account: OnceLock<Result<String, Error>>,
    cached: Mutex<Option<CachedDelegation>>,
}

impl DelegationCache {
    pub(crate) fn query(&self) -> Result<Delegation, Error> {
        self.query_with_generation(false)
    }

    /// Force one fresh query. This is the fail-closed path used when a cached
    /// delegation no longer contains a lease's IDs.
    pub(crate) fn refresh(&self) -> Result<Delegation, Error> {
        self.query_with_generation(true)
    }

    fn query_with_generation(&self, force: bool) -> Result<Delegation, Error> {
        let generation = DelegationGeneration::current();
        if !force
            && let Some(cached) = self
                .cached
                .lock()
                .map_err(|_| Error::CachePoisoned)?
                .as_ref()
            && cached.generation == generation
        {
            return Ok(cached.delegation.clone());
        }

        // Check the source generation again after the potentially slow NSS
        // query. A configuration edit racing the query must not publish a
        // snapshot under the wrong generation.
        let account = self.current_account_name()?;
        let delegation = query_for_account(&account)?;
        let after = DelegationGeneration::current();
        if generation != after {
            let delegation = query_for_account(&account)?;
            let final_generation = DelegationGeneration::current();
            if final_generation != after {
                return Err(Error::GenerationChanged);
            }
            self.publish(final_generation, delegation.clone())?;
            return Ok(delegation);
        }
        self.publish(generation, delegation.clone())?;
        Ok(delegation)
    }

    fn publish(
        &self,
        generation: DelegationGeneration,
        delegation: Delegation,
    ) -> Result<(), Error> {
        let mut cached = self.cached.lock().map_err(|_| Error::CachePoisoned)?;
        if cached
            .as_ref()
            .is_none_or(|entry| entry.generation != generation)
        {
            *cached = Some(CachedDelegation {
                generation,
                delegation,
            });
        }
        Ok(())
    }

    fn current_account_name(&self) -> Result<String, Error> {
        self.account
            .get_or_init(resolve_current_account_name)
            .clone()
    }
}

static PROCESS_DELEGATION_CACHE: OnceLock<DelegationCache> = OnceLock::new();

/// Parse `getsubids` output. Each non-empty line is
/// `<list-index>: <name> <start> <count>`; the index is a list ordinal and
/// otherwise ignored. Malformed lines, zero-length ranges, and values that
/// overflow the Linux ID space are rejected, because a mis-parsed pool is a
/// security boundary and not a best-effort cache.
pub(crate) fn parse_getsubids_output(output: &str) -> Result<Vec<SubidRange>, Error> {
    let mut ranges = Vec::new();
    for line in output.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (index, rest) = line
            .split_once(':')
            .ok_or_else(|| Error::MalformedLine(line.to_string()))?;
        if index.trim().parse::<u32>().is_err() {
            return Err(Error::MalformedLine(line.to_string()));
        }
        let mut fields = rest.split_whitespace();
        let name = fields.next();
        let start = fields.next();
        let count = fields.next();
        let (Some(name), Some(start), Some(count), None) = (name, start, count, fields.next())
        else {
            return Err(Error::MalformedLine(line.to_string()));
        };
        if name.is_empty() {
            return Err(Error::MalformedLine(line.to_string()));
        }
        let start: u64 = start
            .parse()
            .map_err(|_| Error::MalformedLine(line.to_string()))?;
        let count: u64 = count
            .parse()
            .map_err(|_| Error::MalformedLine(line.to_string()))?;
        ranges.push(
            SubidRange::new(start, count).map_err(|error| Error::MalformedRange {
                line: line.to_string(),
                reason: error.to_string(),
            })?,
        );
    }
    Ok(ranges)
}

/// Query the current delegation for the daemon account (`getsubids` and
/// `getsubids -g`). A missing or failing helper is a distinct error so
/// capability diagnostics can name it; nothing is guessed from
/// `/etc/subuid` instead.
pub(crate) fn query_delegation() -> Result<Delegation, Error> {
    PROCESS_DELEGATION_CACHE
        .get_or_init(DelegationCache::default)
        .query()
}

fn query_for_account(user: &str) -> Result<Delegation, Error> {
    let uid_ranges = run_getsubids(&[user])?;
    let gid_ranges = run_getsubids(&["-g", user])?;
    Ok(Delegation {
        uid_ranges,
        gid_ranges,
    })
}

fn run_getsubids(args: &[&str]) -> Result<Vec<SubidRange>, Error> {
    let output = Command::new("getsubids")
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
        )
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::HelperMissing
            } else {
                Error::HelperIo(error.to_string())
            }
        })?;
    if !output.status.success() {
        return Err(Error::HelperFailed {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_getsubids_output(&stdout)
}

/// Resolve the daemon account name for `geteuid()` via the passwd database.
fn resolve_current_account_name() -> Result<String, Error> {
    // SAFETY: getpwuid_r fills the provided buffer per POSIX; a zero return
    // with a non-null result pointer marks success.
    unsafe {
        let mut passwd: libc::passwd = std::mem::zeroed();
        let mut buffer = [0_u8; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let code = libc::getpwuid_r(
            libc::geteuid(),
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        );
        if code != 0 || result.is_null() {
            return Err(Error::AccountLookup);
        }
        let name = std::ffi::CStr::from_ptr((*result).pw_name)
            .to_str()
            .map_err(|_| Error::AccountLookup)?
            .to_owned();
        Ok(name)
    }
}

/// Delegation discovery failures. `HelperMissing` in particular is a
/// capability-diagnostic input: isolated identity cannot start without it.
#[derive(Debug, Clone)]
pub(crate) enum Error {
    HelperMissing,
    HelperIo(String),
    HelperFailed { code: Option<i32>, stderr: String },
    AccountLookup,
    CachePoisoned,
    GenerationChanged,
    MalformedLine(String),
    MalformedRange { line: String, reason: String },
    Range(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HelperMissing => f.write_str("getsubids is not installed or not on PATH"),
            Error::HelperIo(detail) => write!(f, "getsubids could not be executed: {detail}"),
            Error::HelperFailed { code, stderr } => write!(
                f,
                "getsubids failed with status {code:?}{}",
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                }
            ),
            Error::AccountLookup => f.write_str("the daemon account has no passwd-database name"),
            Error::CachePoisoned => f.write_str("delegation cache is poisoned"),
            Error::GenerationChanged => {
                f.write_str("subordinate-ID delegation changed during discovery")
            }
            Error::MalformedLine(line) => write!(f, "malformed getsubids output line {line:?}"),
            Error::MalformedRange { line, reason } => {
                write!(
                    f,
                    "invalid subordinate range in getsubids line {line:?}: {reason}"
                )
            }
            Error::Range(reason) => write!(f, "invalid subordinate range: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_multiple_ranges() {
        assert_eq!(
            parse_getsubids_output("0: ubuntu 165536 65536\n").expect("parse"),
            vec![SubidRange::new(165536, 65536).expect("range")]
        );
        let ranges = parse_getsubids_output("0: ubuntu 100000 65536\n1: ubuntu 200000 1000\n")
            .expect("parse");
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start(), 100000);
        assert!(ranges[1].contains(200999));
        assert!(!ranges[1].contains(201000));
    }

    #[test]
    fn empty_output_is_no_ranges() {
        assert!(parse_getsubids_output("").expect("parse").is_empty());
        assert!(parse_getsubids_output("\n").expect("parse").is_empty());
    }

    #[test]
    fn rejects_malformed_lines() {
        for bad in [
            "ubuntu 165536 65536\n",              // missing index
            "x: ubuntu 165536 65536\n",           // non-numeric index
            "0: ubuntu 165536\n",                 // missing count
            "0: ubuntu 165536 65536 7\n",         // extra field
            "0: ubuntu 165536 zero\n",            // non-numeric count
            "0: ubuntu 165536 0\n",               // zero-length range
            "0: ubuntu 4294967296 1\n",           // start beyond 32-bit IDs
            "0: ubuntu 4294967295 2\n",           // end overflows 32-bit IDs
            "0: ubuntu 18446744073709551616 1\n", // non-parseable overflow
        ] {
            assert!(
                parse_getsubids_output(bad).is_err(),
                "accepted malformed output: {bad:?}"
            );
        }
    }

    #[test]
    fn range_end_may_reach_but_not_pass_the_id_space_end() {
        assert!(SubidRange::new(u32::MAX as u64, 1).is_ok());
        assert!(SubidRange::new(u32::MAX as u64, 2).is_err());
        assert!(SubidRange::new(0, 1).is_ok());
    }

    #[test]
    fn delegation_membership_checks_ranges_independently() {
        let delegation = Delegation {
            uid_ranges: vec![SubidRange::new(100_000, 10).expect("range")],
            gid_ranges: vec![SubidRange::new(200_000, 5).expect("range")],
        };
        assert!(delegation.contains_uid(100_009));
        assert!(!delegation.contains_uid(200_000));
        assert!(delegation.contains_gid(200_004));
        assert!(!delegation.contains_gid(200_005));
    }

    #[test]
    fn query_delegation_reports_a_missing_helper_distinctly() {
        // On hosts without getsubids (e.g. Ubuntu 22.04's shadow 4.8.1)
        // this asserts the real fail-closed diagnostic; on hosts with the
        // helper installed it asserts the happy path instead.
        match query_delegation() {
            Ok(delegation) => {
                assert!(!delegation.uid_ranges.is_empty());
                assert!(!delegation.gid_ranges.is_empty());
            }
            Err(Error::HelperMissing) => {}
            Err(other) => panic!("unexpected delegation error: {other}"),
        }
    }
}
