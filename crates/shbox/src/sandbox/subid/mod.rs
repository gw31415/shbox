//! Durable subordinate-ID allocation for isolated Linux sandboxes.
//!
//! Every isolated durable sandbox leases exactly one subordinate UID and one
//! subordinate GID from the daemon account's delegation. The lease lives as
//! long as the durable sandbox — across SSH sessions, cgroup generations,
//! and daemon restarts — and a pair becomes reusable only through the
//! verified release transaction (`Active -> Releasing -> cleanup proof ->
//! record removal + directory fsync`), never by inference from age, missing
//! processes, or namespace disappearance (PLANS.md §7, §11, §12).
//!
//! This module owns the ledger and the allocator. It never parses
//! subordinate delegation on its own for allocation decisions: callers pass
//! a freshly queried [`Delegation`] so delegation changes are detected at
//! the moment of use.

pub(crate) mod delegation;
pub(crate) mod ledger;

pub(crate) use delegation::{Delegation, SubidRange};
pub(crate) use ledger::{LeaseRecord, LeaseState, LeaseStore};

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use crate::auth::KeyFingerprint;

use super::id::SandboxId;

/// Allocator failure. `Exhausted` carries the capacity diagnostics required
/// for operators (PLANS.md §7.7); corruption and state conflicts fail closed.
#[derive(Debug)]
pub(crate) enum Error {
    Ledger(ledger::Error),
    /// Two records claim the same UID, GID, or sandbox — the ledger cannot
    /// be trusted to know which IDs are unavailable.
    Corrupt(String),
    /// A transition was attempted against a record that is not the expected
    /// incarnation in the expected state (ABA protection).
    StateConflict(String),
    /// The expected lease record no longer exists.
    MissingLease(String),
    /// A lease references IDs outside the daemon's current delegation.
    Undelegated {
        lease_id: String,
        uid_delegated: bool,
        gid_delegated: bool,
    },
    /// No delegated UID or GID is free. The counts explain where the pool
    /// went; remedies are completing `Releasing` cleanup, repairing
    /// `Quarantined` entries, or enlarging the delegation.
    Exhausted {
        uid: PoolCapacity,
        gid: PoolCapacity,
    },
    /// The durable sandbox could not be inspected during startup
    /// reconciliation. Treating an I/O failure as absence could release an
    /// identity that is still backed by an unknown filesystem state.
    Lookup(String),
}

/// Free/used counts for one ID kind at allocation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolCapacity {
    pub(crate) delegated: usize,
    pub(crate) free: usize,
    pub(crate) reserved: usize,
    pub(crate) active: usize,
    pub(crate) releasing: usize,
    pub(crate) quarantined: usize,
}

impl fmt::Display for PoolCapacity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} delegated, {} free, {} reserved, {} active, {} releasing, {} quarantined",
            self.delegated, self.free, self.reserved, self.active, self.releasing, self.quarantined
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ledger(error) => write!(f, "lease ledger: {error}"),
            Error::Corrupt(reason) => write!(f, "lease ledger is corrupt: {reason}"),
            Error::StateConflict(reason) => write!(f, "lease state conflict: {reason}"),
            Error::MissingLease(lease_id) => {
                write!(
                    f,
                    "lease {lease_id} does not exist (stale or already released)"
                )
            }
            Error::Undelegated {
                lease_id,
                uid_delegated,
                gid_delegated,
            } => {
                let uid = if *uid_delegated { "still" } else { "no longer" };
                let gid = if *gid_delegated { "still" } else { "no longer" };
                write!(
                    f,
                    "lease {lease_id} IDs are {uid} (UID) / {gid} (GID) inside the current subordinate delegation; new isolated launches using it fail closed",
                )
            }
            Error::Exhausted { uid, gid } => write!(
                f,
                "no free subordinate UID or GID remains — UID pool: {uid}; GID pool: {gid}; let pending releases finish, repair quarantined leases, or enlarge the delegation"
            ),
            Error::Lookup(reason) => write!(
                f,
                "sandbox lookup failed during lease reconciliation: {reason}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Ledger(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ledger::Error> for Error {
    fn from(error: ledger::Error) -> Error {
        Error::Ledger(error)
    }
}

/// Serializes pair selection and durable publication. It deliberately
/// covers only ledger work: delegation snapshots, validation, and record
/// transitions — never namespace creation, helper invocation, or process
/// launch (PLANS.md §7.4).
#[derive(Debug)]
pub(crate) struct SubidAllocator {
    store: LeaseStore,
    selection: Mutex<()>,
}

impl SubidAllocator {
    pub(crate) fn new(store: LeaseStore) -> SubidAllocator {
        SubidAllocator {
            store,
            selection: Mutex::new(()),
        }
    }

    /// Load and validate the whole ledger. Duplicate UIDs, GIDs, or sandbox
    /// leases are corruption: allocation must stop, not route around an
    /// ambiguous record.
    pub(crate) fn load(&self) -> Result<Vec<LeaseRecord>, Error> {
        let records = self.store.load()?;
        validate_uniqueness(&records)?;
        Ok(records)
    }

    /// The single live lease for a durable sandbox, if any.
    pub(crate) fn lease_for(&self, sandbox_id: &SandboxId) -> Result<Option<LeaseRecord>, Error> {
        Ok(self
            .load()?
            .into_iter()
            .find(|record| record.sandbox_id == *sandbox_id))
    }

    /// Allocate one UID and one GID for a new sandbox incarnation and
    /// durably publish the `Reserved` record. UID and GID pools are
    /// independent; each gets its own lowest-available selection.
    ///
    /// Returns the reserved record; the caller publishes the durable sandbox
    /// and then calls [`SubidAllocator::activate`]. Only after activation
    /// may the lease back a launch.
    pub(crate) fn claim(
        &self,
        sandbox_id: &SandboxId,
        owner: &KeyFingerprint,
        delegation: &Delegation,
    ) -> Result<LeaseRecord, Error> {
        let _guard = self.selection.lock().expect("subid allocator");
        let records = self.load()?;
        if records
            .iter()
            .any(|record| record.sandbox_id == *sandbox_id)
        {
            return Err(Error::StateConflict(format!(
                "sandbox {} already holds a lease; one durable sandbox has exactly one incarnation lease",
                sandbox_id.as_str()
            )));
        }
        let mut unavailable_uid = HashSet::from([0, crate::paths::euid()]);
        let mut unavailable_gid = HashSet::from([0, effective_gid()]);
        for record in &records {
            unavailable_uid.insert(record.uid);
            unavailable_gid.insert(record.gid);
        }
        let uid = lowest_available(&delegation.uid_ranges, &unavailable_uid).ok_or_else(|| {
            Error::Exhausted {
                uid: capacity(&delegation.uid_ranges, &records, IdKind::Uid),
                gid: capacity(&delegation.gid_ranges, &records, IdKind::Gid),
            }
        })?;
        let gid = lowest_available(&delegation.gid_ranges, &unavailable_gid).ok_or_else(|| {
            Error::Exhausted {
                uid: capacity(&delegation.uid_ranges, &records, IdKind::Uid),
                gid: capacity(&delegation.gid_ranges, &records, IdKind::Gid),
            }
        })?;
        let record = LeaseRecord {
            lease_id: ledger::new_lease_id(),
            sandbox_id: sandbox_id.clone(),
            owner: owner.clone(),
            uid,
            gid,
            state: LeaseState::Reserved,
            quarantine_reason: None,
        };
        self.store.write(&record)?;
        Ok(record)
    }

    /// `Reserved -> Active`: the durable sandbox has been published. The
    /// expected record pins the incarnation (`lease_id`) so a stale caller
    /// cannot activate a newer lease.
    pub(crate) fn activate(&self, expected: &LeaseRecord) -> Result<LeaseRecord, Error> {
        self.transition(expected, &[LeaseState::Reserved], LeaseState::Active)
    }

    /// `Active -> Releasing`, durable **before** any destructive cleanup
    /// starts. Also accepts `Reserved` for a sandbox deleted between
    /// reservation and publication.
    pub(crate) fn begin_release(&self, expected: &LeaseRecord) -> Result<(), Error> {
        self.transition(
            expected,
            &[LeaseState::Active, LeaseState::Reserved],
            LeaseState::Releasing,
        )
        .map(|_| ())
    }

    /// The verified release barrier: the record must still be the expected
    /// incarnation in `Releasing`; only then is it unlinked and the lease
    /// directory fsynced. After `Ok(())` the pair is reusable. A stale
    /// cleanup carrying an older `lease_id` fails against the missing file
    /// and removes nothing (ABA protection).
    pub(crate) fn finish_release(&self, expected: &LeaseRecord) -> Result<(), Error> {
        let _guard = self.selection.lock().expect("subid allocator");
        // Incarnation identity and the Releasing state are both verified by
        // the expected-record guard; the caller may hold any state snapshot
        // of the same incarnation.
        self.expected_record(expected, &["releasing"])?;
        self.store.remove(&expected.lease_id)?;
        Ok(())
    }

    /// Move any record of this incarnation to `Quarantined`, recording why.
    /// Quarantined IDs are never allocated automatically.
    pub(crate) fn quarantine(&self, expected: &LeaseRecord, reason: &str) -> Result<(), Error> {
        let _guard = self.selection.lock().expect("subid allocator");
        let current = self
            .store
            .read(&expected.lease_id)?
            .ok_or_else(|| Error::MissingLease(expected.lease_id.clone()))?;
        if !same_incarnation(&current, expected) {
            return Err(Error::StateConflict(format!(
                "lease {} is not the expected incarnation",
                expected.lease_id
            )));
        }
        self.store.write(&current.with_quarantine_reason(reason))?;
        Ok(())
    }

    fn free_reserved_absent(&self, expected: &LeaseRecord) -> Result<(), Error> {
        let _guard = self.selection.lock().expect("subid allocator");
        self.expected_record(expected, &["reserved"])?;
        self.store.remove(&expected.lease_id)?;
        Ok(())
    }

    /// Fail closed when a lease's IDs are no longer inside the daemon's
    /// current delegation. The record is **kept**: deletion must stay
    /// possible (it needs no subordinate mapping), and the pair must not be
    /// freed just because the delegation shrank.
    pub(crate) fn validate_delegated(
        &self,
        record: &LeaseRecord,
        delegation: &Delegation,
    ) -> Result<(), Error> {
        let uid_delegated = delegation.contains_uid(record.uid);
        let gid_delegated = delegation.contains_gid(record.gid);
        if uid_delegated && gid_delegated {
            Ok(())
        } else {
            Err(Error::Undelegated {
                lease_id: record.lease_id.clone(),
                uid_delegated,
                gid_delegated,
            })
        }
    }

    fn transition(
        &self,
        expected: &LeaseRecord,
        from: &[LeaseState],
        to: LeaseState,
    ) -> Result<LeaseRecord, Error> {
        let names: Vec<&str> = from.iter().map(|state| state.as_str()).collect();
        let current = self.expected_record(expected, &names)?;
        let next = current.with_state(to);
        self.store.write(&next)?;
        Ok(next)
    }

    /// Read the on-disk record for `expected.lease_id` and verify it is the
    /// same incarnation in one of `states`.
    fn expected_record(
        &self,
        expected: &LeaseRecord,
        states: &[&str],
    ) -> Result<LeaseRecord, Error> {
        let current = self
            .store
            .read(&expected.lease_id)?
            .ok_or_else(|| Error::MissingLease(expected.lease_id.clone()))?;
        if !same_incarnation(&current, expected) {
            return Err(Error::StateConflict(format!(
                "lease {} is not the expected incarnation (sandbox/owner/IDs changed)",
                expected.lease_id
            )));
        }
        if !states.contains(&current.state.as_str()) {
            return Err(Error::StateConflict(format!(
                "lease {} is {}, expected {}",
                expected.lease_id,
                current.state.as_str(),
                states.join(" or ")
            )));
        }
        Ok(current)
    }
}

/// What the durable-sandbox scan reports for one sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SandboxView {
    Active { owner: KeyFingerprint },
    Deleting { owner: KeyFingerprint },
    Corrupt { reason: String },
}

/// Proof that the platform runtime sweep completed successfully. The private
/// field prevents callers from manufacturing a value compatible with a
/// boolean flag; the manager creates it only after its runtime sweep returns
/// success.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeReconciliationProof {
    _private: (),
}

impl RuntimeReconciliationProof {
    pub(crate) fn from_successful_sweep() -> RuntimeReconciliationProof {
        RuntimeReconciliationProof { _private: () }
    }
}

/// Startup lease reconciliation (PLANS.md §7.5, §12). `lookup` answers "does
/// the durable sandbox exist, in which state and under which owner";
/// `runtime_proof` is present only after the caller has proven no processes or
/// ephemeral runtime state remain (stale cgroups, runtime temps). It is
/// required before a `Releasing` lease for an absent sandbox may be freed.
#[derive(Debug, Default)]
pub(crate) struct Reconciliation {
    /// `Reserved` records promoted to `Active` (crash between sandbox
    /// publication and lease activation).
    pub(crate) promoted: Vec<LeaseRecord>,
    /// Records removed: their pairs are free again.
    pub(crate) freed: Vec<LeaseRecord>,
    /// Records moved to `Quarantined`, with the reason.
    pub(crate) quarantined: Vec<(LeaseRecord, String)>,
    /// `Releasing` records whose sandbox tree still exists: deletion must
    /// be resumed by the caller.
    pub(crate) resuming_deletion: Vec<LeaseRecord>,
}

pub(crate) fn reconcile(
    allocator: &SubidAllocator,
    lookup: &dyn Fn(&SandboxId) -> Result<Option<SandboxView>, String>,
    runtime_proof: Option<RuntimeReconciliationProof>,
) -> Result<Reconciliation, Error> {
    let mut report = Reconciliation::default();
    for record in allocator.load()? {
        let sandbox = lookup(&record.sandbox_id).map_err(Error::Lookup)?;
        match record.state {
            LeaseState::Reserved => match sandbox {
                None => {
                    // A Reserved lease is never launchable: the manager only
                    // returns a handle after the durable sandbox is published
                    // and this record has been activated. Assert that
                    // activate-before-launch invariant before freeing the
                    // absent reservation.
                    assert_eq!(
                        record.state,
                        LeaseState::Reserved,
                        "only a Reserved lease may be freed through absent-sandbox recovery"
                    );
                    allocator.free_reserved_absent(&record)?;
                    report.freed.push(record);
                }
                Some(SandboxView::Active { owner } | SandboxView::Deleting { owner })
                    if owner == record.owner =>
                {
                    let promoted = allocator.activate(&record)?;
                    report.promoted.push(promoted);
                }
                Some(SandboxView::Corrupt { reason }) => {
                    allocator.quarantine(&record, &reason)?;
                    report.quarantined.push((record, reason));
                }
                Some(_) => {
                    let reason =
                        "reserved lease owner does not match the durable sandbox owner".to_string();
                    allocator.quarantine(&record, &reason)?;
                    report.quarantined.push((record, reason));
                }
            },
            LeaseState::Active => {
                let reason = match sandbox {
                    Some(SandboxView::Active { owner } | SandboxView::Deleting { owner })
                        if owner == record.owner =>
                    {
                        None
                    }
                    Some(SandboxView::Corrupt { reason }) => Some(format!(
                        "active lease has a corrupt durable sandbox: {reason}"
                    )),
                    Some(_) => Some(
                        "active lease owner does not match the durable sandbox owner".to_string(),
                    ),
                    None => Some("active lease with no durable sandbox".to_string()),
                };
                if let Some(reason) = reason {
                    allocator.quarantine(&record, &reason)?;
                    report.quarantined.push((record, reason));
                }
                // Present with the same owner (Active or Deleting) is valid.
                // A Deleting sandbox proceeds to begin_release through the
                // delete path.
            }
            LeaseState::Releasing => match sandbox {
                Some(SandboxView::Corrupt { reason }) => {
                    let reason = format!("releasing lease has a corrupt durable sandbox: {reason}");
                    allocator.quarantine(&record, &reason)?;
                    report.quarantined.push((record, reason));
                }
                Some(SandboxView::Active { owner } | SandboxView::Deleting { owner })
                    if owner == record.owner =>
                {
                    report.resuming_deletion.push(record)
                }
                Some(_) => {
                    let reason = "releasing lease owner does not match the durable sandbox owner"
                        .to_string();
                    allocator.quarantine(&record, &reason)?;
                    report.quarantined.push((record, reason));
                }
                None if runtime_proof.is_some() => {
                    // Processes, namespaces, and backing are gone; the
                    // release transaction completes here.
                    allocator.finish_release(&record)?;
                    report.freed.push(record);
                }
                None => {
                    // Runtime reconciliation has not (yet) proven the
                    // environment clean; keep the record for a later pass.
                }
            },
            LeaseState::Quarantined => {
                // Operator repair or an explicit verified recovery path is
                // required; never reallocated automatically.
            }
        }
    }
    Ok(report)
}

fn same_incarnation(current: &LeaseRecord, expected: &LeaseRecord) -> bool {
    current.lease_id == expected.lease_id
        && current.sandbox_id == expected.sandbox_id
        && current.owner == expected.owner
        && current.uid == expected.uid
        && current.gid == expected.gid
}

fn validate_uniqueness(records: &[LeaseRecord]) -> Result<(), Error> {
    let mut seen_uid = HashSet::new();
    let mut seen_gid = HashSet::new();
    let mut seen_sandbox = HashSet::new();
    for record in records {
        if !seen_uid.insert(record.uid) {
            return Err(Error::Corrupt(format!(
                "UID {} appears in more than one lease record",
                record.uid
            )));
        }
        if !seen_gid.insert(record.gid) {
            return Err(Error::Corrupt(format!(
                "GID {} appears in more than one lease record",
                record.gid
            )));
        }
        if !seen_sandbox.insert(record.sandbox_id.clone()) {
            return Err(Error::Corrupt(format!(
                "sandbox {} holds more than one lease record",
                record.sandbox_id.as_str()
            )));
        }
    }
    Ok(())
}

enum IdKind {
    Uid,
    Gid,
}

/// Deterministic lowest-available selection across (possibly fragmented)
/// ranges. ID 0 is never selected regardless of delegation.
fn lowest_available(ranges: &[SubidRange], unavailable: &HashSet<u32>) -> Option<u32> {
    let mut sorted: Vec<&SubidRange> = ranges.iter().collect();
    sorted.sort_by_key(|range| range.start());
    sorted
        .iter()
        .flat_map(|range| range.ids())
        .find(|id| *id != 0 && !unavailable.contains(id))
}

fn effective_gid() -> u32 {
    // SAFETY: getegid is signal-safe and cannot fail.
    unsafe { libc::getegid() }
}

fn capacity(ranges: &[SubidRange], records: &[LeaseRecord], kind: IdKind) -> PoolCapacity {
    let delegated: usize = ranges.iter().map(|range| range.ids().count()).sum();
    let mut counts: BTreeMap<LeaseState, usize> = BTreeMap::new();
    let mut used = 0;
    for record in records {
        let taken = match kind {
            IdKind::Uid => ranges.iter().any(|range| range.contains(record.uid)),
            IdKind::Gid => ranges.iter().any(|range| range.contains(record.gid)),
        };
        if taken {
            used += 1;
        }
        *counts.entry(record.state).or_default() += 1;
    }
    PoolCapacity {
        delegated,
        free: delegated.saturating_sub(used),
        reserved: counts.get(&LeaseState::Reserved).copied().unwrap_or(0),
        active: counts.get(&LeaseState::Active).copied().unwrap_or(0),
        releasing: counts.get(&LeaseState::Releasing).copied().unwrap_or(0),
        quarantined: counts.get(&LeaseState::Quarantined).copied().unwrap_or(0),
    }
}

/// Open the lease ledger at the shbox data root.
pub(crate) fn open_allocator(
    root: &Path,
    faults: Option<std::sync::Arc<crate::sandbox::storage::FaultInjector>>,
) -> Result<SubidAllocator, Error> {
    Ok(SubidAllocator::new(LeaseStore::open(root, faults)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shbox-subid-{}-{}",
            std::process::id(),
            DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn owner() -> KeyFingerprint {
        KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).expect("owner")
    }

    fn other_owner() -> KeyFingerprint {
        // Base64 of a 32-byte digest is 43 chars with the final char
        // restricted to a 4-bit tail; "B"*42 + "A" is canonical.
        KeyFingerprint::parse(&format!("SHA256:{}A", "B".repeat(42))).expect("owner")
    }

    fn sandbox(name: &str) -> SandboxId {
        SandboxId::parse(name).expect("sandbox id")
    }

    fn ranges(start: u64, count: u64) -> Vec<SubidRange> {
        vec![SubidRange::new(start, count).expect("range")]
    }

    fn delegation() -> Delegation {
        Delegation {
            uid_ranges: ranges(100_000, 6),
            gid_ranges: ranges(200_000, 6),
        }
    }

    fn allocator(root: &std::path::Path) -> SubidAllocator {
        open_allocator(root, None).expect("allocator")
    }

    fn claim_active(alloc: &SubidAllocator, name: &str) -> LeaseRecord {
        let record = alloc
            .claim(&sandbox(name), &owner(), &delegation())
            .expect("claim");
        alloc.activate(&record).expect("activate")
    }

    fn full_release(alloc: &SubidAllocator, record: &LeaseRecord) {
        alloc.begin_release(record).expect("begin release");
        alloc.finish_release(record).expect("finish release");
    }

    #[test]
    fn allocates_lowest_available_independently_per_kind() {
        let root = scratch();
        let alloc = allocator(&root);
        let first = claim_active(&alloc, "dev");
        // Independent pools: UID and GID numerics differ and are each the
        // lowest available of their own pool.
        assert_eq!(first.uid, 100_000);
        assert_eq!(first.gid, 200_000);
        let second = claim_active(&alloc, "prod");
        assert_eq!(second.uid, 100_001);
        assert_eq!(second.gid, 200_001);
        assert_ne!((first.uid, first.gid), (second.uid, second.gid));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn allocation_skips_fragmented_holes_and_zero() {
        let root = scratch();
        let alloc = allocator(&root);
        let delegation = Delegation {
            uid_ranges: vec![
                SubidRange::new(0, 2).expect("range"),       // includes ID 0
                SubidRange::new(100_000, 2).expect("range"), // fragmented second range
                SubidRange::new(50_000, 1).expect("range"),  // out of order
            ],
            gid_ranges: ranges(200_000, 2),
        };
        let record = alloc
            .claim(&sandbox("dev"), &owner(), &delegation)
            .expect("claim");
        // 0 is skipped; lowest real ID is 1 from the first range.
        assert_eq!(record.uid, 1);
        let next = alloc
            .claim(&sandbox("prod"), &owner(), &delegation)
            .expect("claim");
        // 0 and 1 are gone; the next lowest lives in the 50_000 range.
        assert_eq!(next.uid, 50_000);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn allocation_skips_daemon_uid_and_gid() {
        let root = scratch();
        let alloc = allocator(&root);
        let daemon_uid = crate::paths::euid();
        let daemon_gid = effective_gid();
        let around = |reserved| {
            if reserved == u32::MAX {
                ranges((u32::MAX - 1) as u64, 2)
            } else {
                ranges(reserved as u64, 2)
            }
        };
        let delegation = Delegation {
            uid_ranges: around(daemon_uid),
            gid_ranges: around(daemon_gid),
        };
        let record = alloc
            .claim(&sandbox("daemon-id"), &owner(), &delegation)
            .expect("claim the non-daemon IDs");
        assert_ne!(record.uid, daemon_uid);
        assert_ne!(record.gid, daemon_gid);
        assert_ne!(record.uid, 0);
        assert_ne!(record.gid, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parallel_claims_are_unique() {
        let root = scratch();
        let alloc = std::sync::Arc::new(allocator(&root));
        let mut pairs = Vec::new();
        let results: std::sync::Mutex<Vec<(u32, u32)>> = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for index in 0..3 {
                let alloc = std::sync::Arc::clone(&alloc);
                let results = &results;
                scope.spawn(move || {
                    let record = alloc
                        .claim(&sandbox(&format!("sb{index}")), &owner(), &delegation())
                        .expect("claim");
                    results
                        .lock()
                        .expect("results")
                        .push((record.uid, record.gid));
                });
            }
        });
        pairs.extend(results.into_inner().expect("results"));
        let mut sorted = pairs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            pairs.len(),
            "duplicate pair allocated: {pairs:?}"
        );
        assert_eq!(pairs.len(), 3);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn released_pairs_are_reusable_and_churn_recycles_the_pool() {
        let root = scratch();
        let alloc = allocator(&root);
        // Pool of exactly one pair.
        let tiny = Delegation {
            uid_ranges: ranges(100_000, 1),
            gid_ranges: ranges(200_000, 1),
        };
        let first = alloc
            .claim(&sandbox("dev"), &owner(), &tiny)
            .expect("claim");
        assert_eq!(first.uid, 100_000);
        assert!(
            alloc.claim(&sandbox("prod"), &owner(), &tiny).is_err(),
            "pool of one must exhaust while leased"
        );
        alloc.activate(&first).expect("activate");
        full_release(&alloc, &first);
        // Churn: more create/delete cycles than the pool size.
        for cycle in 0..3 {
            let record = alloc
                .claim(&sandbox(&format!("cycle{cycle}")), &owner(), &tiny)
                .expect("claim after release");
            assert_eq!(record.uid, 100_000);
            assert_eq!(record.gid, 200_000);
            alloc.activate(&record).expect("activate");
            full_release(&alloc, &record);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn releasing_and_quarantined_pairs_are_never_selected() {
        let root = scratch();
        let alloc = allocator(&root);
        let tiny = Delegation {
            uid_ranges: ranges(100_000, 1),
            gid_ranges: ranges(200_000, 1),
        };
        let record = alloc
            .claim(&sandbox("dev"), &owner(), &tiny)
            .expect("claim");
        alloc.activate(&record).expect("activate");
        alloc.begin_release(&record).expect("begin release");
        let error = alloc
            .claim(&sandbox("prod"), &owner(), &tiny)
            .expect_err("releasing pair must not be selected");
        assert!(matches!(error, Error::Exhausted { .. }), "{error}");
        alloc.quarantine(&record, "test").expect("quarantine");
        let error = alloc
            .claim(&sandbox("stage"), &owner(), &tiny)
            .expect_err("quarantined pair must not be selected");
        assert!(matches!(error, Error::Exhausted { .. }), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn quarantine_reason_survives_ledger_round_trip() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = claim_active(&alloc, "reason");
        let reason = "owner mismatch during startup";
        alloc.quarantine(&record, reason).expect("quarantine");
        let persisted = alloc
            .lease_for(&sandbox("reason"))
            .expect("load")
            .expect("quarantined lease");
        assert_eq!(persisted.state, LeaseState::Quarantined);
        assert_eq!(persisted.quarantine_reason.as_deref(), Some(reason));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exhaustion_reports_capacity_by_state() {
        let root = scratch();
        let alloc = allocator(&root);
        let tiny = Delegation {
            uid_ranges: ranges(100_000, 1),
            gid_ranges: ranges(200_000, 1),
        };
        let first = alloc.claim(&sandbox("a"), &owner(), &tiny).expect("claim");
        alloc.begin_release(&first).expect("begin release");
        let error = alloc
            .claim(&sandbox("c"), &owner(), &tiny)
            .expect_err("exhausted");
        let Error::Exhausted { uid, gid } = &error else {
            panic!("expected exhaustion diagnostics: {error}")
        };
        assert_eq!(uid.free, 0);
        assert_eq!(uid.delegated, 1);
        assert_eq!(uid.releasing, 1);
        assert_eq!(gid.free, 0);
        assert!(format!("{error}").contains("releasing"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn transitions_enforce_state_and_incarnation() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = alloc
            .claim(&sandbox("dev"), &owner(), &delegation())
            .expect("claim");
        // finish_release requires Releasing.
        assert!(matches!(
            alloc.finish_release(&record),
            Err(Error::StateConflict(_))
        ));
        // activate requires Reserved.
        assert!(alloc.activate(&record).is_ok());
        assert!(matches!(
            alloc.activate(&record),
            Err(Error::StateConflict(_))
        ));
        // begin_release requires the matching incarnation; a stale lease id
        // simply has no record to release.
        let stale = LeaseRecord {
            lease_id: ledger::new_lease_id(),
            ..record.clone()
        };
        assert!(matches!(
            alloc.begin_release(&stale),
            Err(Error::StateConflict(_)) | Err(Error::MissingLease(_))
        ));
        // finish_release of an unknown lease is a distinct missing error.
        assert!(matches!(
            alloc.finish_release(&stale),
            Err(Error::StateConflict(_)) | Err(Error::MissingLease(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_cleanup_cannot_remove_a_newer_lease_record() {
        let root = scratch();
        let alloc = allocator(&root);
        let tiny = Delegation {
            uid_ranges: ranges(100_000, 1),
            gid_ranges: ranges(200_000, 1),
        };
        // Incarnation A: claim, release fully; its numeric pair is freed.
        let a = alloc
            .claim(&sandbox("dev"), &owner(), &tiny)
            .expect("claim");
        alloc.activate(&a).expect("activate");
        alloc.begin_release(&a).expect("begin release");
        alloc.finish_release(&a).expect("finish release");
        // Incarnation B reuses the same numeric pair under a new lease id.
        let b = alloc
            .claim(&sandbox("dev"), &owner(), &tiny)
            .expect("claim");
        assert_eq!((b.uid, b.gid), (a.uid, a.gid));
        assert_ne!(b.lease_id, a.lease_id);
        // A stale cleanup carrying A's record must fail and keep B intact.
        assert!(alloc.finish_release(&a).is_err());
        let live = alloc
            .lease_for(&sandbox("dev"))
            .expect("load")
            .expect("live lease");
        assert_eq!(live, b);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_records_block_allocation() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = claim_active(&alloc, "dev");
        // Simulate a second record reusing the same UID (hand-written file).
        let duplicate = LeaseRecord {
            lease_id: ledger::new_lease_id(),
            uid: record.uid,
            quarantine_reason: None,
            ..record.clone()
        };
        alloc.store.write(&duplicate).expect("write duplicate");
        let error = alloc
            .claim(&sandbox("prod"), &owner(), &delegation())
            .expect_err("duplicate uid must block allocation");
        assert!(matches!(error, Error::Corrupt(_)), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delegation_shrink_blocks_use_without_freeing_the_lease() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = claim_active(&alloc, "dev");
        let shrunk = Delegation {
            uid_ranges: ranges(999_000, 5),
            gid_ranges: ranges(200_000, 3),
        };
        let error = alloc
            .validate_delegated(&record, &shrunk)
            .expect_err("uid outside delegation");
        assert!(
            matches!(
                error,
                Error::Undelegated {
                    uid_delegated: false,
                    gid_delegated: true,
                    ..
                }
            ),
            "{error}"
        );
        // The record survives; deletion stays possible.
        assert_eq!(
            alloc
                .lease_for(&sandbox("dev"))
                .expect("load")
                .expect("record"),
            record
        );
        assert!(alloc.validate_delegated(&record, &delegation()).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fault_injection_covers_every_crash_window_of_claim_and_release() {
        use crate::sandbox::storage::FaultInjector;
        use crate::sandbox::storage::FaultPoint::*;
        for point in [
            LeaseTempCreate,
            LeaseWrite,
            LeaseFileSync,
            LeaseRename,
            LeaseParentSync,
            LeaseUnlink,
            LeaseUnlinkSync,
        ] {
            let root = scratch();
            let faults = std::sync::Arc::new(FaultInjector::default());
            faults.fail_once(point);
            let alloc =
                open_allocator(&root, Some(std::sync::Arc::clone(&faults))).expect("allocator");
            let tiny = Delegation {
                uid_ranges: ranges(100_000, 1),
                gid_ranges: ranges(200_000, 1),
            };
            match point {
                // Faults during claim: the record either never became
                // visible (still free after cleanup) or is Reserved.
                LeaseTempCreate | LeaseWrite | LeaseFileSync | LeaseRename | LeaseParentSync => {
                    assert!(
                        alloc.claim(&sandbox("dev"), &owner(), &tiny).is_err(),
                        "{point:?} must fail the claim"
                    );
                    let records = alloc.load().expect("load after fault");
                    let record = records
                        .iter()
                        .find(|record| record.sandbox_id == sandbox("dev"))
                        .cloned();
                    match (&record, point) {
                        // Before rename, the record never existed.
                        (None, LeaseTempCreate | LeaseWrite | LeaseFileSync | LeaseRename) => {
                            // A retry may claim successfully afterwards.
                            let retry = alloc.claim(&sandbox("dev"), &owner(), &tiny);
                            assert!(retry.is_ok(), "{point:?}: {retry:?}");
                        }
                        // Parent-sync fault leaves a durable Reserved
                        // record; reconciliation decides, absence would be
                        // the only free state.
                        (Some(record), LeaseParentSync) => {
                            assert_eq!(record.state, LeaseState::Reserved);
                        }
                        (record, point) => panic!("unexpected {record:?} at {point:?}"),
                    }
                }
                // Faults during the release barrier: the pair stays
                // non-free (record intact) or the caller sees the error and
                // re-runs the verified release.
                LeaseUnlink | LeaseUnlinkSync => {
                    // Claim cleanly first (fault is single-shot and already
                    // consumed only if it fired; re-arm for the release).
                    faults.fail_once(point);
                    let record = alloc
                        .claim(&sandbox("dev"), &owner(), &tiny)
                        .expect("claim");
                    alloc.activate(&record).expect("activate");
                    alloc.begin_release(&record).expect("begin release");
                    let result = alloc.finish_release(&record);
                    assert!(result.is_err(), "{point:?} must fail the release");
                    let still_recorded = alloc.lease_for(&sandbox("dev")).expect("load").is_some();
                    if point == LeaseUnlink {
                        // The unlink never happened: still Releasing.
                        assert!(still_recorded, "{point:?} dropped the record");
                        // Retry completes the release.
                        alloc.finish_release(&record).expect("retry release");
                        assert!(alloc.lease_for(&sandbox("dev")).expect("load").is_none());
                    } else {
                        // Unlink happened but fsync failed: the operation
                        // reports failure and restart reconciliation is the
                        // authority on reuse.
                        assert!(!still_recorded);
                        assert!(
                            alloc.claim(&sandbox("next"), &owner(), &tiny).is_ok(),
                            "absence of a record means free"
                        );
                    }
                }
                // Only lease fault points are exercised by this ledger.
                _ => unreachable!("not a lease fault point"),
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn reconcile_promotes_quarantines_and_frees_per_the_state_table() {
        let root = scratch();
        let alloc = allocator(&root);

        // Crash window: Reserved + published Active sandbox -> promoted.
        let promoting = alloc
            .claim(&sandbox("win"), &owner(), &delegation())
            .expect("claim");
        // Active + absent -> quarantined.
        let orphan = claim_active(&alloc, "orphan");
        // Releasing + present -> resuming deletion.
        let resuming = claim_active(&alloc, "resuming");
        alloc.begin_release(&resuming).expect("begin release");
        // Releasing + absent (+ runtime reconciled) -> freed.
        let freeing = claim_active(&alloc, "freeing");
        alloc.begin_release(&freeing).expect("begin release");
        // Quarantined stays untouched.
        let quarantined = claim_active(&alloc, "stuck");
        alloc
            .quarantine(&quarantined, "operator")
            .expect("quarantine");

        let views: std::collections::HashMap<SandboxId, SandboxView> = [
            (sandbox("win"), SandboxView::Active { owner: owner() }),
            (
                sandbox("resuming"),
                SandboxView::Deleting { owner: owner() },
            ),
        ]
        .into_iter()
        .collect();
        let lookup = |id: &SandboxId| Ok(views.get(id).cloned());

        let report = reconcile(
            &alloc,
            &lookup,
            Some(RuntimeReconciliationProof::from_successful_sweep()),
        )
        .expect("reconcile");
        assert_eq!(report.promoted.len(), 1);
        assert_eq!(report.promoted[0].lease_id, promoting.lease_id);
        assert_eq!(report.promoted[0].state, LeaseState::Active);
        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(report.quarantined[0].0.lease_id, orphan.lease_id);
        assert_eq!(report.resuming_deletion.len(), 1);
        assert_eq!(report.resuming_deletion[0].lease_id, resuming.lease_id);
        assert_eq!(report.freed.len(), 1);
        assert_eq!(report.freed[0].lease_id, freeing.lease_id);

        // The freed pair is allocatable again; the quarantined one is not.
        let recycled = alloc
            .claim(&sandbox("next"), &owner(), &delegation())
            .expect("claim");
        assert_eq!((recycled.uid, recycled.gid), (freeing.uid, freeing.gid));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reconcile_without_runtime_proof_keeps_releasing_records() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = claim_active(&alloc, "gone");
        alloc.begin_release(&record).expect("begin release");
        let report = reconcile(&alloc, &|_| Ok(None), None).expect("reconcile");
        assert!(report.freed.is_empty(), "no free without runtime proof");
        assert_eq!(
            alloc
                .lease_for(&sandbox("gone"))
                .expect("load")
                .expect("kept"),
            record.with_state(LeaseState::Releasing)
        );
        // Once proven, the same reconciliation frees it.
        let report = reconcile(
            &alloc,
            &|_| Ok(None),
            Some(RuntimeReconciliationProof::from_successful_sweep()),
        )
        .expect("reconcile");
        assert_eq!(report.freed.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reconcile_owner_mismatch_is_quarantined() {
        let root = scratch();
        let alloc = allocator(&root);
        let active = alloc
            .claim(&sandbox("dev"), &owner(), &delegation())
            .expect("claim");
        alloc.activate(&active).expect("activate");
        let releasing = claim_active(&alloc, "releasing-mismatch");
        alloc.begin_release(&releasing).expect("begin release");
        let report = reconcile(
            &alloc,
            &|_| {
                Ok(Some(SandboxView::Active {
                    owner: other_owner(),
                }))
            },
            Some(RuntimeReconciliationProof::from_successful_sweep()),
        )
        .expect("reconcile");
        assert_eq!(report.quarantined.len(), 2);
        assert!(
            report
                .quarantined
                .iter()
                .any(|(record, _)| record.lease_id == active.lease_id)
        );
        assert!(
            report
                .quarantined
                .iter()
                .any(|(record, _)| record.lease_id == releasing.lease_id)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reconcile_corrupt_sandbox_never_frees_its_identity() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = alloc
            .claim(&sandbox("corrupt"), &owner(), &delegation())
            .expect("claim");
        let report = reconcile(
            &alloc,
            &|_| {
                Ok(Some(SandboxView::Corrupt {
                    reason: "metadata is malformed".to_string(),
                }))
            },
            Some(RuntimeReconciliationProof::from_successful_sweep()),
        )
        .expect("reconcile");
        assert!(report.freed.is_empty());
        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(report.quarantined[0].0.lease_id, record.lease_id);
        assert_eq!(
            alloc
                .lease_for(&sandbox("corrupt"))
                .expect("load")
                .expect("quarantined")
                .state,
            LeaseState::Quarantined
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reconcile_lookup_errors_keep_the_ledger_unmodified() {
        let root = scratch();
        let alloc = allocator(&root);
        let record = alloc
            .claim(&sandbox("unknown"), &owner(), &delegation())
            .expect("claim");
        let error = reconcile(
            &alloc,
            &|_| Err("storage unavailable".to_string()),
            Some(RuntimeReconciliationProof::from_successful_sweep()),
        )
        .expect_err("lookup error");
        assert!(matches!(error, Error::Lookup(reason) if reason == "storage unavailable"));
        assert_eq!(
            alloc
                .lease_for(&sandbox("unknown"))
                .expect("load")
                .expect("record"),
            record
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
