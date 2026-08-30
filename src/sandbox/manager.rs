//! Deep lifecycle module for durable sandbox ownership and state.
//!
//! SSH code does not know the on-disk layout.  It asks this module to claim,
//! list, or delete a validated ID; this module owns the storage transaction,
//! ownership check, count ledger, and the runtime registry placeholder used by
//! later process-launch milestones.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::auth::{KeyFingerprint, Principal, Role};
use crate::config::Caps;
use crate::paths::Paths;
use crate::platform::{self, LaunchRequest, ProcessLauncher};

use super::id::SandboxId;
use super::metadata::{Metadata, State};
use super::storage::{self, Entry, Storage};

/// The result of an idempotent delete request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteResult {
    /// No valid, authorized target existed.  This is intentionally
    /// indistinguishable from a non-owner target to a remote caller.
    Noop,
    /// The target tree and durable record were removed.
    Deleted,
}

/// A claimed sandbox passed to a later process launcher.  Claiming commits
/// metadata first, so a launch failure never rolls back ownership or data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxHandle {
    id: SandboxId,
    owner: KeyFingerprint,
    workspace: PathBuf,
    created: bool,
}

impl SandboxHandle {
    pub(crate) fn id(&self) -> &SandboxId {
        &self.id
    }

    pub(crate) fn owner(&self) -> &KeyFingerprint {
        &self.owner
    }

    pub(crate) fn workspace(&self) -> &PathBuf {
        &self.workspace
    }

    pub(crate) fn created(&self) -> bool {
        self.created
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeMarker {
    Launching,
    Running,
}

#[derive(Debug)]
struct RuntimeEntry {
    marker: RuntimeMarker,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    process: Option<Arc<dyn platform::RunningProcess>>,
}

#[derive(Debug, Default)]
struct Ledger {
    records: BTreeMap<SandboxId, Metadata>,
    blocked: BTreeSet<SandboxId>,
    unknown_entries: usize,
    owner_counts: BTreeMap<KeyFingerprint, usize>,
    reserved_sandboxes: usize,
    runtime: HashMap<SandboxId, RuntimeEntry>,
}

/// Persistent sandbox lifecycle service.  The type is intentionally
/// crate-private: it is an internal seam, not a backend/plugin API.
#[derive(Debug)]
pub(crate) struct SandboxManager {
    storage: Storage,
    caps: Caps,
    ledger: Mutex<Ledger>,
    lifecycle_locks: Mutex<HashMap<SandboxId, Arc<Mutex<()>>>>,
}

impl SandboxManager {
    /// Load the registry and resume every durable Deleting intent.  A
    /// deletion failure leaves its valid Deleting record in place and does not
    /// prevent unrelated IDs from being served.
    pub(crate) fn open(paths: &Paths, caps: Caps) -> Result<SandboxManager, Error> {
        Self::open_with_faults(paths, caps, None)
    }

    pub(crate) fn open_with_faults(
        paths: &Paths,
        caps: Caps,
        faults: Option<Arc<storage::FaultInjector>>,
    ) -> Result<SandboxManager, Error> {
        let storage =
            Storage::with_faults(paths.sandboxes_root(), faults).map_err(Error::Storage)?;
        let manager = SandboxManager {
            storage,
            caps,
            ledger: Mutex::new(Ledger::default()),
            lifecycle_locks: Mutex::new(HashMap::new()),
        };
        manager.load_registry()?;
        manager.reconcile_deleting();
        Ok(manager)
    }

    /// Atomically claim an ID for the principal, creating its workspace only
    /// when the ID is truly absent.  Existing Active records consume no new
    /// sandbox count.
    pub(crate) fn claim(
        &self,
        principal: &Principal,
        id: &SandboxId,
    ) -> Result<SandboxHandle, Error> {
        let lifecycle_lock = self.lifecycle_lock(id);
        let _guard = lifecycle_lock.lock().expect("sandbox lifecycle lock");
        match self.storage.inspect(id).map_err(Error::Storage)? {
            Entry::Active(metadata) => {
                if !self.note_valid_record(id, &metadata) {
                    return Err(Error::Unavailable);
                }
                if !authorized(principal, metadata.owner()) {
                    return Err(Error::Unavailable);
                }
                Ok(self.handle(&metadata, false))
            }
            Entry::Deleting(metadata) => {
                self.note_valid_record(id, &metadata);
                Err(Error::Unavailable)
            }
            Entry::Corrupt { reason } => {
                self.note_corrupt(id, reason);
                Err(Error::Unavailable)
            }
            Entry::Absent => {
                // A failed root fsync may leave the namespace absent while
                // the durable result is still uncertain. Keep an in-memory
                // record from being overwritten until a fresh manager scan
                // establishes the post-restart state.
                if self.is_blocked(id) || self.has_record(id) {
                    return Err(Error::Unavailable);
                }
                self.reserve_sandbox(&principal.fingerprint)?;
                let created = self.storage.create_active(id, &principal.fingerprint);
                match created {
                    Ok(metadata) => {
                        self.insert_reserved(metadata.clone());
                        Ok(self.handle(&metadata, true))
                    }
                    Err(error) => {
                        self.release_sandbox(&principal.fingerprint);
                        if matches!(error, storage::Error::AlreadyExists { .. }) {
                            Err(Error::Unavailable)
                        } else {
                            Err(Error::Storage(error))
                        }
                    }
                }
            }
        }
    }

    /// Return a fresh metadata snapshot filtered by the caller's role.  A
    /// corrupt or Deleting entry is never returned.  The scan is read-only
    /// with respect to the in-memory ledger: a partial directory observed
    /// while another ID is publishing metadata must not become permanently
    /// blocked as corruption.
    pub(crate) fn list(&self, principal: &Principal) -> Result<Vec<SandboxId>, Error> {
        let scan = self.storage.scan().map_err(Error::Storage)?;
        let blocked = self.ledger.lock().expect("sandbox ledger").blocked.clone();
        let mut result: Vec<SandboxId> = scan
            .entries
            .into_iter()
            .filter_map(|(id, entry)| match entry {
                Entry::Active(metadata)
                    if !blocked.contains(&id) && authorized(principal, metadata.owner()) =>
                {
                    Some(id)
                }
                _ => None,
            })
            .collect();
        result.sort();
        result.dedup();
        Ok(result)
    }

    /// Begin and complete a delete.  The durable Deleting transition is
    /// written before tree removal.  A failure therefore leaves a hidden,
    /// retryable Deleting record rather than exposing an apparently Active
    /// sandbox after a partial cleanup.
    pub(crate) fn delete(
        &self,
        principal: &Principal,
        id: &SandboxId,
    ) -> Result<DeleteResult, Error> {
        let lifecycle_lock = self.lifecycle_lock(id);
        let _guard = lifecycle_lock.lock().expect("sandbox lifecycle lock");
        let entry = self.storage.inspect(id).map_err(Error::Storage)?;
        let metadata = match entry {
            Entry::Absent => {
                self.remove_record(id);
                return Ok(DeleteResult::Noop);
            }
            Entry::Corrupt { reason } => {
                self.note_corrupt(id, reason);
                return Err(Error::Unavailable);
            }
            Entry::Active(metadata) | Entry::Deleting(metadata) => metadata,
        };
        if !self.note_valid_record(id, &metadata) {
            return Err(Error::Unavailable);
        }
        if !authorized(principal, metadata.owner()) {
            return Ok(DeleteResult::Noop);
        }

        if metadata.state() == State::Active {
            let deleting = metadata.with_state(State::Deleting);
            self.storage
                .write_metadata(&deleting)
                .map_err(Error::Storage)?;
            self.replace_record(deleting);
        }
        // Cancel a launch/running process before opening the directory tree
        // for deletion. The lifecycle lock prevents a new launch for this ID;
        // the cancellation token closes the small adapter race window.
        self.cancel_runtime(id);
        self.storage
            .remove_tree(id)
            .map_err(|source| Error::Cleanup { source })?;
        self.remove_record(id);
        Ok(DeleteResult::Deleted)
    }

    /// Number of durable entries still consuming the global sandbox count.
    /// This is primarily a test/diagnostic seam for later request admission.
    pub(crate) fn sandbox_count(&self) -> usize {
        self.ledger.lock().expect("sandbox ledger").records.len()
    }

    /// Register a launch marker and invoke the private process seam. A delete
    /// racing with the adapter sets the cancellation flag; a process returned
    /// after that point is terminated before it can escape the registry.
    pub(crate) fn launch_with(
        &self,
        handle: &SandboxHandle,
        launcher: &dyn ProcessLauncher,
    ) -> Result<Arc<dyn platform::RunningProcess>, Error> {
        let cancelled = self.begin_launch(handle)?;
        let request = LaunchRequest {
            sandbox_id: handle.id.clone(),
            workspace: handle.workspace.clone(),
        };
        let process = match launcher.launch(request) {
            Ok(process) => process,
            Err(error) => {
                self.clear_runtime_if(handle.id(), &cancelled);
                return Err(Error::Launch(error));
            }
        };
        if !self.finish_launch(handle.id(), &cancelled, Arc::clone(&process)) {
            process.terminate();
            return Err(Error::Unavailable);
        }
        Ok(process)
    }

    fn begin_launch(
        &self,
        handle: &SandboxHandle,
    ) -> Result<Arc<std::sync::atomic::AtomicBool>, Error> {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        let Some(metadata) = ledger.records.get(handle.id()) else {
            return Err(Error::Unavailable);
        };
        if metadata.state() != State::Active || metadata.owner() != handle.owner() {
            return Err(Error::Unavailable);
        }
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if ledger
            .runtime
            .insert(
                handle.id().clone(),
                RuntimeEntry {
                    marker: RuntimeMarker::Launching,
                    cancelled: Arc::clone(&cancelled),
                    process: None,
                },
            )
            .is_some()
        {
            return Err(Error::AlreadyRunning);
        }
        Ok(cancelled)
    }

    fn finish_launch(
        &self,
        id: &SandboxId,
        cancelled: &Arc<std::sync::atomic::AtomicBool>,
        process: Arc<dyn platform::RunningProcess>,
    ) -> bool {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        match ledger.runtime.get_mut(id) {
            Some(entry)
                if entry.marker == RuntimeMarker::Launching
                    && Arc::ptr_eq(&entry.cancelled, cancelled)
                    && !cancelled.load(std::sync::atomic::Ordering::Acquire) =>
            {
                entry.marker = RuntimeMarker::Running;
                entry.process = Some(process);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn clear_runtime(&self, id: &SandboxId) {
        self.ledger
            .lock()
            .expect("sandbox ledger")
            .runtime
            .remove(id);
    }

    fn clear_runtime_if(&self, id: &SandboxId, cancelled: &Arc<std::sync::atomic::AtomicBool>) {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        let remove = ledger
            .runtime
            .get(id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.cancelled, cancelled));
        if remove {
            ledger.runtime.remove(id);
        }
    }

    fn cancel_runtime(&self, id: &SandboxId) {
        let entry = self
            .ledger
            .lock()
            .expect("sandbox ledger")
            .runtime
            .remove(id);
        if let Some(entry) = entry {
            entry
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            if let Some(process) = entry.process {
                process.terminate();
            }
        }
    }

    fn load_registry(&self) -> Result<(), Error> {
        let scan = self.storage.scan().map_err(Error::Storage)?;
        self.reconcile_scan(scan);
        Ok(())
    }

    fn reconcile_deleting(&self) {
        let deleting: Vec<SandboxId> = self
            .ledger
            .lock()
            .expect("sandbox ledger")
            .records
            .iter()
            .filter(|(_, metadata)| metadata.state() == State::Deleting)
            .map(|(id, _)| id.clone())
            .collect();
        for id in deleting {
            match self.storage.remove_tree(&id) {
                Ok(()) => self.remove_record(&id),
                Err(error) => {
                    tracing::warn!(sandbox_id = %id, "sandbox deletion reconciliation is pending: {error}");
                }
            }
        }
    }

    fn reconcile_scan(&self, scan: storage::ScanResult) {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        ledger.unknown_entries = scan.unknown_entries;
        let mut seen = BTreeSet::new();
        for (id, entry) in scan.entries {
            seen.insert(id.clone());
            match entry {
                Entry::Active(metadata) | Entry::Deleting(metadata) => {
                    let same = ledger
                        .records
                        .get(&id)
                        .is_none_or(|existing| same_identity(existing, &metadata));
                    if same {
                        if let Some(previous) = ledger.records.insert(id.clone(), metadata.clone())
                        {
                            if previous.owner() != metadata.owner() {
                                decrement_owner(&mut ledger.owner_counts, previous.owner());
                                increment_owner(&mut ledger.owner_counts, metadata.owner());
                            }
                        } else {
                            increment_owner(&mut ledger.owner_counts, metadata.owner());
                        }
                        ledger.blocked.remove(&id);
                    } else {
                        remove_record_from_ledger(&mut ledger, &id);
                        ledger.blocked.insert(id);
                    }
                }
                Entry::Corrupt { .. } => {
                    remove_record_from_ledger(&mut ledger, &id);
                    ledger.blocked.insert(id);
                }
                Entry::Absent => {}
            }
        }
        let stale: Vec<SandboxId> = ledger
            .records
            .keys()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .collect();
        for id in stale {
            remove_record_from_ledger(&mut ledger, &id);
        }
    }

    fn note_valid_record(&self, id: &SandboxId, metadata: &Metadata) -> bool {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        if ledger.blocked.contains(id) {
            return false;
        }
        match ledger.records.get(id) {
            Some(existing) if !same_identity(existing, metadata) => {
                remove_record_from_ledger(&mut ledger, id);
                ledger.blocked.insert(id.clone());
                false
            }
            Some(_) => {
                ledger.records.insert(id.clone(), metadata.clone());
                true
            }
            None => {
                increment_owner(&mut ledger.owner_counts, metadata.owner());
                ledger.records.insert(id.clone(), metadata.clone());
                true
            }
        }
    }

    fn note_corrupt(&self, id: &SandboxId, _reason: String) {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        remove_record_from_ledger(&mut ledger, id);
        ledger.blocked.insert(id.clone());
    }

    fn is_blocked(&self, id: &SandboxId) -> bool {
        self.ledger
            .lock()
            .expect("sandbox ledger")
            .blocked
            .contains(id)
    }

    fn has_record(&self, id: &SandboxId) -> bool {
        self.ledger
            .lock()
            .expect("sandbox ledger")
            .records
            .contains_key(id)
    }

    fn reserve_sandbox(&self, owner: &KeyFingerprint) -> Result<(), Error> {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        if ledger
            .records
            .len()
            .saturating_add(ledger.reserved_sandboxes)
            >= self.caps.max_sandboxes as usize
        {
            return Err(Error::Limit("max_sandboxes"));
        }
        if ledger.owner_counts.get(owner).copied().unwrap_or(0)
            >= self.caps.max_sandboxes_per_owner as usize
        {
            return Err(Error::Limit("max_sandboxes_per_owner"));
        }
        ledger.reserved_sandboxes += 1;
        increment_owner(&mut ledger.owner_counts, owner);
        Ok(())
    }

    fn release_sandbox(&self, owner: &KeyFingerprint) {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        ledger.reserved_sandboxes = ledger.reserved_sandboxes.saturating_sub(1);
        decrement_owner(&mut ledger.owner_counts, owner);
    }

    fn insert_reserved(&self, metadata: Metadata) {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        ledger.reserved_sandboxes = ledger.reserved_sandboxes.saturating_sub(1);
        ledger.records.insert(metadata.id().clone(), metadata);
    }

    fn replace_record(&self, metadata: Metadata) {
        let mut ledger = self.ledger.lock().expect("sandbox ledger");
        ledger.records.insert(metadata.id().clone(), metadata);
    }

    fn remove_record(&self, id: &SandboxId) {
        remove_record_from_ledger(&mut self.ledger.lock().expect("sandbox ledger"), id);
    }

    fn handle(&self, metadata: &Metadata, created: bool) -> SandboxHandle {
        SandboxHandle {
            id: metadata.id().clone(),
            owner: metadata.owner().clone(),
            workspace: self.storage.workspace_path(metadata.id()),
            created,
        }
    }

    fn lifecycle_lock(&self, id: &SandboxId) -> Arc<Mutex<()>> {
        let mut locks = self
            .lifecycle_locks
            .lock()
            .expect("sandbox lifecycle locks");
        locks
            .entry(id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

fn authorized(principal: &Principal, owner: &KeyFingerprint) -> bool {
    principal.role == Role::Admin || principal.fingerprint == *owner
}

fn same_identity(left: &Metadata, right: &Metadata) -> bool {
    left.id() == right.id() && left.owner() == right.owner()
}

fn increment_owner(counts: &mut BTreeMap<KeyFingerprint, usize>, owner: &KeyFingerprint) {
    *counts.entry(owner.clone()).or_default() += 1;
}

fn decrement_owner(counts: &mut BTreeMap<KeyFingerprint, usize>, owner: &KeyFingerprint) {
    let Some(count) = counts.get_mut(owner) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        counts.remove(owner);
    }
}

fn remove_record_from_ledger(ledger: &mut Ledger, id: &SandboxId) {
    if let Some(metadata) = ledger.records.remove(id) {
        decrement_owner(&mut ledger.owner_counts, metadata.owner());
    }
    if let Some(entry) = ledger.runtime.remove(id) {
        entry
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(process) = entry.process {
            process.terminate();
        }
    }
}

/// Manager-level errors are intentionally small; remote protocol mapping can
/// turn all authorization/corruption details into one generic response.
#[derive(Debug)]
pub(crate) enum Error {
    Storage(storage::Error),
    Cleanup { source: storage::Error },
    Launch(platform::LaunchError),
    Limit(&'static str),
    AlreadyRunning,
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Storage(error) => write!(f, "sandbox storage failed: {error}"),
            Error::Cleanup { source } => write!(f, "sandbox cleanup failed: {source}"),
            Error::Launch(source) => write!(f, "sandbox process launch failed: {source}"),
            Error::Limit(name) => write!(f, "sandbox capacity limit reached: {name}"),
            Error::AlreadyRunning => f.write_str("sandbox channel is already running"),
            Error::Unavailable => f.write_str("sandbox is unavailable"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Storage(error) => Some(error),
            Error::Cleanup { source } => Some(source),
            Error::Launch(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::KeyFingerprint;
    use crate::platform::FakeLauncher;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::thread;
    use tempfile::TempDir;

    fn fingerprint(fill: char) -> KeyFingerprint {
        KeyFingerprint::parse(&format!("SHA256:{}A", fill.to_string().repeat(42)))
            .expect("fingerprint")
    }

    fn principal(fill: char, role: Role) -> Principal {
        Principal {
            fingerprint: fingerprint(fill),
            role,
        }
    }

    fn manager(caps: Caps) -> (TempDir, SandboxManager) {
        let root = TempDir::new().expect("tempdir");
        let paths = paths_for(&root);
        paths.ensure().expect("paths");
        let manager = SandboxManager::open(&paths, caps).expect("manager");
        (root, manager)
    }

    fn paths_for(root: &TempDir) -> Paths {
        Paths::from_roots(
            root.path().join("config"),
            root.path().join("data"),
            root.path().join("state"),
        )
    }

    #[test]
    fn first_owner_wins_and_list_is_filtered_and_sorted() {
        let (_root, manager) = manager(Caps::default());
        let owner = principal('A', Role::Normal);
        let other = principal('B', Role::Normal);
        let admin = principal('C', Role::Admin);
        let dev = SandboxId::parse("dev").expect("id");
        let prod = SandboxId::parse("prod").expect("id");

        assert!(manager.claim(&owner, &dev).expect("claim").created());
        assert!(matches!(
            manager.claim(&other, &dev),
            Err(Error::Unavailable)
        ));
        assert!(!manager.claim(&owner, &dev).expect("reuse").created());
        manager.claim(&other, &prod).expect("other claim");
        assert_eq!(manager.list(&owner).expect("owner list"), vec![dev.clone()]);
        assert_eq!(manager.list(&admin).expect("admin list"), vec![dev, prod]);
    }

    #[test]
    fn count_limit_does_not_consume_existing_or_failed_claims() {
        let caps = Caps {
            max_sandboxes: 1,
            max_sandboxes_per_owner: 1,
            ..Caps::default()
        };
        let (_root, manager) = manager(caps);
        let owner = principal('A', Role::Normal);
        let first = SandboxId::parse("first").expect("id");
        let second = SandboxId::parse("second").expect("id");
        manager.claim(&owner, &first).expect("first claim");
        assert!(matches!(
            manager.claim(&owner, &second),
            Err(Error::Limit(_))
        ));
        assert_eq!(manager.sandbox_count(), 1);
        manager.claim(&owner, &first).expect("existing claim");
        assert_eq!(manager.sandbox_count(), 1);
    }

    #[test]
    fn delete_is_idempotent_and_allows_later_reclaim() {
        let (_root, manager) = manager(Caps::default());
        let owner = principal('A', Role::Normal);
        let other = principal('B', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        manager.claim(&owner, &id).expect("claim");
        assert_eq!(
            manager.delete(&other, &id).expect("foreign delete"),
            DeleteResult::Noop
        );
        assert_eq!(
            manager.delete(&owner, &id).expect("delete"),
            DeleteResult::Deleted
        );
        assert_eq!(
            manager.delete(&owner, &id).expect("repeat"),
            DeleteResult::Noop
        );
        assert!(manager.claim(&other, &id).expect("new owner").created());
    }

    #[test]
    fn deleting_metadata_is_resumed_on_restart() {
        let (root, manager) = manager(Caps::default());
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        let handle = manager.claim(&owner, &id).expect("claim");
        manager
            .storage
            .write_metadata(
                &Metadata::active(id.clone(), owner.fingerprint.clone())
                    .with_state(State::Deleting),
            )
            .expect("mark deleting");
        assert!(matches!(
            manager
                .storage
                .write_metadata(&Metadata::active(id.clone(), owner.fingerprint.clone())),
            Err(storage::Error::Corrupt { .. })
        ));
        drop(manager);
        let paths = paths_for(&root);
        let restarted = SandboxManager::open(&paths, Caps::default()).expect("restart");
        assert_eq!(
            restarted.list(&owner).expect("list"),
            Vec::<SandboxId>::new()
        );
        assert!(!handle.workspace().exists());
        assert!(restarted.claim(&owner, &id).expect("reclaim").created());
    }

    #[test]
    fn deleting_record_survives_a_missing_workspace_on_restart() {
        let (root, manager) = manager(Caps::default());
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        let handle = manager.claim(&owner, &id).expect("claim");
        manager
            .storage
            .write_metadata(
                &Metadata::active(id.clone(), owner.fingerprint.clone())
                    .with_state(State::Deleting),
            )
            .expect("mark deleting");
        fs::remove_dir(handle.workspace()).expect("partial workspace removal");
        drop(manager);

        let restarted = SandboxManager::open(&paths_for(&root), Caps::default()).expect("restart");
        assert!(restarted.list(&owner).expect("list").is_empty());
        assert!(restarted.claim(&owner, &id).expect("reclaim").created());
    }

    #[test]
    fn corrupt_entry_is_hidden_and_not_rewritten() {
        let root = TempDir::new().expect("tempdir");
        let paths = Paths::from_roots(
            root.path().join("config"),
            root.path().join("data"),
            root.path().join("state"),
        );
        paths.ensure().expect("paths");
        let id = SandboxId::parse("dev").expect("id");
        let entry = paths.sandboxes_root().join(id.as_str());
        fs::create_dir(&entry).expect("entry");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("mode");
        fs::write(entry.join("metadata.toml"), b"not metadata\n").expect("corrupt");
        fs::set_permissions(
            entry.join("metadata.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("metadata mode");
        fs::create_dir(entry.join("workspace")).expect("workspace");
        let before = fs::read(entry.join("metadata.toml")).expect("read");
        let manager = SandboxManager::open(&paths, Caps::default()).expect("manager");
        assert!(
            manager
                .list(&principal('A', Role::Admin))
                .expect("list")
                .is_empty()
        );
        assert!(matches!(
            manager.claim(&principal('A', Role::Admin), &id),
            Err(Error::Unavailable)
        ));
        assert_eq!(fs::read(entry.join("metadata.toml")).expect("read"), before);
    }

    #[test]
    fn workspace_symlink_is_removed_without_touching_target() {
        let (root, manager) = manager(Caps::default());
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        let handle = manager.claim(&owner, &id).expect("claim");
        let outside = root.path().join("outside");
        fs::write(&outside, b"keep").expect("outside");
        symlink(&outside, handle.workspace().join("link")).expect("symlink");
        manager.delete(&owner, &id).expect("delete");
        assert_eq!(fs::read(&outside).expect("outside remains"), b"keep");
    }

    #[test]
    fn management_symlink_is_blocked_without_touching_its_target() {
        let root = TempDir::new().expect("tempdir");
        let paths = paths_for(&root);
        paths.ensure().expect("paths");
        let outside = root.path().join("outside");
        fs::create_dir(&outside).expect("outside dir");
        fs::write(outside.join("sentinel"), b"keep").expect("sentinel");
        let linked = paths.sandboxes_root().join("linked");
        symlink(&outside, &linked).expect("management symlink");

        let manager = SandboxManager::open(&paths, Caps::default()).expect("manager");
        let admin = principal('A', Role::Admin);
        assert!(manager.list(&admin).expect("list").is_empty());
        assert!(matches!(
            manager.delete(&admin, &SandboxId::parse("linked").expect("id")),
            Err(Error::Unavailable)
        ));
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("sentinel"),
            b"keep"
        );
        assert!(
            manager
                .claim(
                    &principal('B', Role::Normal),
                    &SandboxId::parse("safe").expect("id")
                )
                .is_ok()
        );
    }

    #[test]
    fn metadata_faults_leave_a_restartable_or_blocked_state() {
        let root = TempDir::new().expect("tempdir");
        let paths = paths_for(&root);
        paths.ensure().expect("paths");
        let faults = Arc::new(storage::FaultInjector::default());
        let manager =
            SandboxManager::open_with_faults(&paths, Caps::default(), Some(Arc::clone(&faults)))
                .expect("manager");
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");

        faults.fail_once(storage::FaultPoint::MetadataRename);
        assert!(manager.claim(&owner, &id).is_err());
        assert_eq!(manager.sandbox_count(), 0);
        drop(manager);

        // A failed publish leaves a partial management directory blocked for
        // operator inspection; restart never silently reclaims it.
        let restarted = SandboxManager::open(&paths, Caps::default()).expect("restart");
        assert!(restarted.list(&owner).expect("list").is_empty());
        assert!(matches!(
            restarted.claim(&owner, &id),
            Err(Error::Unavailable)
        ));

        let root = TempDir::new().expect("second tempdir");
        let paths = paths_for(&root);
        paths.ensure().expect("paths");
        let faults = Arc::new(storage::FaultInjector::default());
        let manager =
            SandboxManager::open_with_faults(&paths, Caps::default(), Some(Arc::clone(&faults)))
                .expect("manager");
        faults.fail_once(storage::FaultPoint::MetadataParentSync);
        assert!(manager.claim(&owner, &id).is_err());
        drop(manager);
        let restarted = SandboxManager::open(&paths, Caps::default()).expect("restart");
        assert_eq!(restarted.list(&owner).expect("list"), vec![id]);
    }

    #[test]
    fn every_create_fault_has_a_defined_restart_outcome() {
        #[derive(Debug)]
        enum Recovery {
            Absent,
            Blocked,
            Active,
        }

        let cases = [
            (
                storage::FaultPoint::CreateSandboxDirectory,
                Recovery::Absent,
            ),
            (storage::FaultPoint::CreateWorkspace, Recovery::Blocked),
            (storage::FaultPoint::MetadataTempCreate, Recovery::Blocked),
            (storage::FaultPoint::MetadataWrite, Recovery::Blocked),
            (storage::FaultPoint::MetadataFileSync, Recovery::Blocked),
            (storage::FaultPoint::MetadataRename, Recovery::Blocked),
            (storage::FaultPoint::MetadataParentSync, Recovery::Active),
            (storage::FaultPoint::RegistryParentSync, Recovery::Active),
        ];
        let owner = principal('A', Role::Normal);
        let admin = principal('B', Role::Admin);

        for (point, recovery) in cases {
            let root = TempDir::new().expect("tempdir");
            let paths = paths_for(&root);
            paths.ensure().expect("paths");
            let faults = Arc::new(storage::FaultInjector::default());
            let manager = SandboxManager::open_with_faults(
                &paths,
                Caps::default(),
                Some(Arc::clone(&faults)),
            )
            .expect("manager");
            let id = SandboxId::parse("dev").expect("id");
            faults.fail_once(point);
            assert!(manager.claim(&owner, &id).is_err(), "{point:?}");
            drop(manager);

            let restarted = SandboxManager::open(&paths, Caps::default()).expect("restart");
            match recovery {
                Recovery::Absent => {
                    assert!(restarted.claim(&owner, &id).expect("reclaim").created());
                }
                Recovery::Blocked => {
                    assert!(restarted.list(&admin).expect("list").is_empty());
                    assert!(matches!(
                        restarted.claim(&owner, &id),
                        Err(Error::Unavailable)
                    ));
                }
                Recovery::Active => {
                    assert_eq!(restarted.list(&owner).expect("list"), vec![id.clone()]);
                    assert!(!restarted.claim(&owner, &id).expect("reuse").created());
                }
            }
        }
    }

    #[test]
    fn delete_fault_keeps_deleting_and_startup_retry_finishes_it() {
        let root = TempDir::new().expect("tempdir");
        let paths = paths_for(&root);
        paths.ensure().expect("paths");
        let faults = Arc::new(storage::FaultInjector::default());
        let manager =
            SandboxManager::open_with_faults(&paths, Caps::default(), Some(Arc::clone(&faults)))
                .expect("manager");
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        manager.claim(&owner, &id).expect("claim");
        faults.fail_once(storage::FaultPoint::DeleteEntry);
        assert!(matches!(
            manager.delete(&owner, &id),
            Err(Error::Cleanup { .. })
        ));
        assert!(manager.list(&owner).expect("deleting list").is_empty());
        assert!(matches!(
            manager.claim(&owner, &id),
            Err(Error::Unavailable)
        ));
        assert_eq!(
            manager.delete(&owner, &id).expect("retry delete"),
            DeleteResult::Deleted
        );
        drop(manager);

        let restarted = SandboxManager::open(&paths, Caps::default()).expect("restart");
        assert!(restarted.list(&owner).expect("list").is_empty());
        assert!(restarted.claim(&owner, &id).expect("reclaim").created());
    }

    #[test]
    fn root_sync_fault_is_reconciled_as_absent() {
        let root = TempDir::new().expect("tempdir");
        let paths = paths_for(&root);
        paths.ensure().expect("paths");
        let faults = Arc::new(storage::FaultInjector::default());
        let manager =
            SandboxManager::open_with_faults(&paths, Caps::default(), Some(Arc::clone(&faults)))
                .expect("manager");
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        manager.claim(&owner, &id).expect("claim");
        faults.fail_once(storage::FaultPoint::DeleteRootSync);
        assert!(matches!(
            manager.delete(&owner, &id),
            Err(Error::Cleanup { .. })
        ));
        drop(manager);
        let restarted = SandboxManager::open(&paths, Caps::default()).expect("restart");
        assert_eq!(restarted.sandbox_count(), 0);
        assert!(restarted.claim(&owner, &id).expect("reclaim").created());
    }

    #[test]
    fn launch_failure_keeps_the_claim_and_clears_the_runtime_marker() {
        let (_root, manager) = manager(Caps::default());
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        let handle = manager.claim(&owner, &id).expect("claim");
        let launcher = FakeLauncher::default();
        launcher.fail_next();
        assert!(matches!(
            manager.launch_with(&handle, &launcher),
            Err(Error::Launch(_))
        ));
        assert_eq!(launcher.launch_count(), 1);
        assert!(!manager.claim(&owner, &id).expect("retry").created());
    }

    #[test]
    fn delete_wins_against_a_barriered_launch_and_terminates_late_process() {
        let (_root, manager) = manager(Caps::default());
        let manager = Arc::new(manager);
        let owner = principal('A', Role::Normal);
        let id = SandboxId::parse("dev").expect("id");
        let handle = manager.claim(&owner, &id).expect("claim");
        let launcher = FakeLauncher::default();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        launcher.set_barrier(Arc::clone(&barrier));
        let launch_manager = Arc::clone(&manager);
        let launch_handle = handle.clone();
        let launch_launcher = launcher.clone();
        let join =
            thread::spawn(move || launch_manager.launch_with(&launch_handle, &launch_launcher));
        for _ in 0..100 {
            if launcher.launch_count() == 1 {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(
            launcher.launch_count(),
            1,
            "launch reached the fake barrier"
        );
        assert_eq!(
            manager.delete(&owner, &id).expect("delete"),
            DeleteResult::Deleted
        );
        barrier.wait();
        assert!(matches!(
            join.join().expect("launch join"),
            Err(Error::Unavailable)
        ));
        assert!(launcher.last_process().expect("late process").terminated());
        assert_eq!(manager.sandbox_count(), 0);
    }

    #[test]
    fn distinct_ids_share_one_atomic_global_reservation() {
        let caps = Caps {
            max_sandboxes: 1,
            max_sandboxes_per_owner: 2,
            ..Caps::default()
        };
        let (_root, manager) = manager(caps);
        let manager = Arc::new(manager);
        let first_id = SandboxId::parse("first").expect("id");
        let second_id = SandboxId::parse("second").expect("id");
        let left_manager = Arc::clone(&manager);
        let right_manager = Arc::clone(&manager);
        let left =
            thread::spawn(move || left_manager.claim(&principal('A', Role::Normal), &first_id));
        let right =
            thread::spawn(move || right_manager.claim(&principal('B', Role::Normal), &second_id));
        let left = left.join().expect("left");
        let right = right.join().expect("right");
        assert_eq!(left.is_ok() as u8 + right.is_ok() as u8, 1);
        assert!(matches!(
            left.as_ref().err().or(right.as_ref().err()),
            Some(Error::Limit("max_sandboxes"))
        ));
        assert_eq!(manager.sandbox_count(), 1);
    }

    #[test]
    fn concurrent_claims_have_one_durable_owner() {
        let (_root, manager) = manager(Caps::default());
        let manager = Arc::new(manager);
        let id = SandboxId::parse("dev").expect("id");
        let first = Arc::clone(&manager);
        let second = Arc::clone(&manager);
        let left = thread::spawn(move || first.claim(&principal('A', Role::Normal), &id));
        let id = SandboxId::parse("dev").expect("id");
        let right = thread::spawn(move || second.claim(&principal('B', Role::Normal), &id));
        let left = left.join().expect("left");
        let right = right.join().expect("right");
        assert_eq!(left.is_ok() as u8 + right.is_ok() as u8, 1);
        assert_eq!(manager.sandbox_count(), 1);
    }
}
