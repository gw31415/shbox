//! Durable subordinate-ID lease records.
//!
//! One lease record names one non-free UID+GID pair leased to one durable
//! sandbox incarnation. **Free is represented by the absence of a record**:
//! there is no persistent `Free` or `Retired` history (PLANS.md §7.1).
//!
//! Records live in their own daemon-owned directory, separate from portable
//! sandbox `metadata.toml`, so the lease ledger remains the transaction
//! boundary for ID reuse and never leaks Linux platform state into
//! portable metadata.
//!
//! Every write is durable before it is reported: temp file, write, fsync,
//! rename, parent-directory fsync — the same crash windows as the metadata
//! writer, with fault-injection points to match.
//!
//! Mutating operations are additionally serialized **across processes** by an
//! exclusive [`LeaseStore::lock`] on `<ledger>/.lease.lock` (`flock(2)`): one
//! read-modify-write — scan, verify, write — must complete under one hold, or
//! two daemons can select the same lowest-available pair. The lock file is
//! created once and never unlinked (see [`LOCK_FILE_NAME`]).
//!
//! The allocator acquires its process-local selection mutex before this
//! ledger lock. Any future code that needs both must use that same order and
//! must not acquire the mutex while holding this flock. A process crash while
//! holding the flock releases it in the kernel.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

use crate::auth::KeyFingerprint;
use crate::sandbox::storage::{
    DirFd, FaultInjector, FaultPoint, create_file_at, errno_is, is_directory, is_regular,
    mode_bits, open_directory_path, read_file_at, read_names, rename_at, stat_at, sync_directory,
    unlink_at,
};

use super::super::id::SandboxId;

/// The only lease-record schema version understood by this release.
pub(crate) const VERSION: u32 = 1;
/// Bound a record before handing it to the TOML parser.
pub(crate) const MAX_RECORD_BYTES: usize = 4 * 1024;
/// Lease tokens are 128 random bits, hex-encoded (32 lowercase chars).
const LEASE_ID_HEX: usize = 32;
const RECORD_SUFFIX: &str = ".toml";
const TEMP_PREFIX: &str = ".lease.toml.tmp";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Cross-process ledger lock, inside the ledger directory so it is covered by
/// the same ownership validation as the records.
///
/// The file is created once and **never unlinked**: unlinking a held lock file
/// would let the next opener create a fresh inode and take a lock that
/// excludes nothing. A leftover file is therefore normal, carries no state,
/// and is skipped by [`LeaseStore::load`].
const LOCK_FILE_NAME: &[u8] = b".lease.lock\0";
const LOCK_FILE_BASENAME: &str = ".lease.lock";

/// Durable lease state. All four recorded states exclude their UID/GID from
/// allocation; only record removal (absence) makes a pair free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LeaseState {
    /// Allocated; the durable sandbox is not yet published.
    Reserved,
    /// The durable sandbox exists; the pair is leased to it.
    Active,
    /// Deletion is in progress; the pair is not free until verified release.
    Releasing,
    /// Ambiguous state requiring operator repair; never auto-allocated.
    Quarantined,
}

impl LeaseState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LeaseState::Reserved => "reserved",
            LeaseState::Active => "active",
            LeaseState::Releasing => "releasing",
            LeaseState::Quarantined => "quarantined",
        }
    }

    fn parse(raw: &str) -> Result<LeaseState, Error> {
        match raw {
            "reserved" => Ok(LeaseState::Reserved),
            "active" => Ok(LeaseState::Active),
            "releasing" => Ok(LeaseState::Releasing),
            "quarantined" => Ok(LeaseState::Quarantined),
            _ => Err(Error::InvalidState(raw.to_string())),
        }
    }
}

/// A validated lease record. `lease_id` identifies one sandbox incarnation;
/// any release or cleanup operation must present the exact expected
/// `lease_id` so a stale cleanup from an old incarnation can never remove a
/// newer lease (ABA protection, PLANS.md §7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseRecord {
    pub(crate) lease_id: String,
    pub(crate) sandbox_id: SandboxId,
    pub(crate) owner: KeyFingerprint,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) state: LeaseState,
    /// Why this lease was quarantined, if it is quarantined.
    pub(crate) quarantine_reason: Option<String>,
}

impl LeaseRecord {
    pub(crate) fn with_state(&self, state: LeaseState) -> LeaseRecord {
        LeaseRecord {
            lease_id: self.lease_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            owner: self.owner.clone(),
            uid: self.uid,
            gid: self.gid,
            state,
            quarantine_reason: (state == LeaseState::Quarantined)
                .then(|| self.quarantine_reason.clone())
                .flatten(),
        }
    }

    pub(crate) fn with_quarantine_reason(&self, reason: &str) -> LeaseRecord {
        let mut record = self.with_state(LeaseState::Quarantined);
        record.quarantine_reason = Some(reason.to_string());
        record
    }

    /// Encode in a stable field order. Domain values are ASCII-restricted;
    /// debug string quoting keeps the serializer correct if that widens.
    pub(crate) fn encode(&self) -> String {
        let mut encoded = format!(
            "version = {VERSION}\nlease_id = {:?}\nsandbox_id = {:?}\nowner = {:?}\nuid = {}\ngid = {}\nstate = {:?}\n",
            self.lease_id,
            self.sandbox_id.as_str(),
            self.owner.as_str(),
            self.uid,
            self.gid,
            self.state.as_str(),
        );
        if let Some(reason) = &self.quarantine_reason {
            encoded.push_str(&format!("quarantine_reason = {reason:?}\n"));
        }
        encoded
    }

    /// The record's file name: `<lease_id>.toml`. The lease token is the
    /// name, so file identity and incarnation identity are the same thing.
    pub(crate) fn file_name(&self) -> String {
        format!("{}{RECORD_SUFFIX}", self.lease_id)
    }

    pub(crate) fn decode(bytes: &[u8], expected_lease_id: &str) -> Result<LeaseRecord, Error> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::TooLarge(bytes.len()));
        }
        // Reject a malformed caller-supplied identity before trusting it in
        // comparisons.
        validate_lease_id(expected_lease_id)?;
        let text = std::str::from_utf8(bytes).map_err(|_| Error::NotUtf8)?;
        let raw: RawLease = toml::from_str(text).map_err(Error::Toml)?;
        if raw.version != VERSION {
            return Err(Error::UnsupportedVersion(raw.version));
        }
        if raw.lease_id != expected_lease_id {
            return Err(Error::MismatchedLeaseId {
                expected: expected_lease_id.to_string(),
                found: raw.lease_id,
            });
        }
        validate_lease_id(&raw.lease_id)?;
        let sandbox_id =
            SandboxId::parse(&raw.sandbox_id).map_err(|error| Error::InvalidSandboxId {
                reason: error.to_string(),
            })?;
        let owner = KeyFingerprint::parse(&raw.owner).map_err(|error| Error::InvalidOwner {
            reason: error.to_string(),
        })?;
        if raw.uid == 0 || raw.gid == 0 {
            return Err(Error::ZeroId);
        }
        let state = LeaseState::parse(&raw.state)?;
        if raw.quarantine_reason.is_some() && state != LeaseState::Quarantined {
            return Err(Error::InvalidQuarantineReason);
        }
        Ok(LeaseRecord {
            lease_id: raw.lease_id,
            sandbox_id,
            owner,
            uid: raw.uid,
            gid: raw.gid,
            state,
            quarantine_reason: raw.quarantine_reason,
        })
    }
}

/// A random lease token: 128 bits, lowercase hex. Length and alphabet make
/// it a safe single path component by construction.
pub(crate) fn new_lease_id() -> String {
    let token: u128 = rand::random();
    format!("{token:032x}")
}

pub(crate) fn validate_lease_id(lease_id: &str) -> Result<(), Error> {
    let valid = lease_id.len() == LEASE_ID_HEX
        && lease_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidLeaseId(lease_id.to_string()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLease {
    version: u32,
    lease_id: String,
    sandbox_id: String,
    owner: String,
    uid: u32,
    gid: u32,
    state: String,
    #[serde(default)]
    quarantine_reason: Option<String>,
}

/// Filesystem-backed lease ledger. The directory is validated like every
/// other shbox-owned root: no symlink, daemon-owned, not group/world
/// writable. Any file that is not a valid `<lease-id>.toml` record is a
/// hard error — an unreadable record means an unknown ID may be in use, so
/// allocation fails closed instead of skipping it.
#[derive(Debug)]
pub(crate) struct LeaseStore {
    root: PathBuf,
    faults: Option<Arc<FaultInjector>>,
    /// Descriptor of `LOCK_FILE_NAME`, open for the whole store lifetime so
    /// every `flock` in this process targets one open file description.
    lock_file: File,
}

impl LeaseStore {
    /// Open the ledger, creating the directory with mode `0700` on first
    /// use and validating it on every use.
    pub(crate) fn open(
        root: &Path,
        faults: Option<Arc<FaultInjector>>,
    ) -> Result<LeaseStore, Error> {
        match std::fs::create_dir(root) {
            Ok(()) => {
                // New roots are private regardless of the caller's umask;
                // existing directories are validated below and never
                // chmod'ed (the same contract as the XDG roots).
                let permissions = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(root, permissions)
                    .map_err(|error| Error::io("set the lease directory mode", root, error))?;
                sync_parent_directory(root)?;
            }
            Err(error) if !errno_is(&error, libc::EEXIST) => {
                return Err(Error::io("create the lease directory", root, error));
            }
            Err(_) => {}
        }
        let directory = open_directory_path(root)
            .map_err(|error| Error::io("open the lease directory", root, error))?;
        validate_ownership(root, directory.as_raw_fd())?;
        let lock_file = open_lock_file(root, directory.as_raw_fd())?;
        Ok(LeaseStore {
            root: root.to_path_buf(),
            faults,
            lock_file,
        })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Take the exclusive cross-process ledger lock, waiting until every other
    /// holder releases it or exits. The hold spans exactly one read-modify-
    /// write and is released when the returned [`LedgerLock`] is dropped.
    ///
    /// A holder that dies — crash or `kill -9` — has the lock released by the
    /// kernel, so a crashed daemon can never wedge the ledger; the only
    /// residue is the empty lock file, which is expected and skipped on scan.
    pub(crate) fn lock(&self) -> Result<LedgerLock<'_>, Error> {
        loop {
            // SAFETY: the descriptor is valid for the store's lifetime.
            if unsafe { libc::flock(self.lock_file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(self.io("lock the lease ledger", error));
        }
        Ok(LedgerLock {
            file: &self.lock_file,
        })
    }

    /// Load every record. Corrupt records, duplicate lease IDs, and unknown
    /// file names are errors: the caller must not allocate around them.
    pub(crate) fn load(&self) -> Result<Vec<LeaseRecord>, Error> {
        let directory = self.open_root()?;
        let mut records = Vec::new();
        for name in read_names(directory.as_raw_fd()).map_err(|error| self.io("scan", error))? {
            let name = String::from_utf8_lossy(&name).into_owned();
            if name.starts_with(TEMP_PREFIX) {
                // A crashed writer's temp file. It was never renamed into a
                // lease, so it holds no live pair: skip it without deleting.
                // Deletion happens only in `remove_stale_temps`, which runs
                // under the exclusive flock — deleting here would race an
                // in-flight write from a thread sharing this store's lock
                // file descriptor (flock does not exclude same-description
                // holders) or from a lock-holding writer observed by a
                // flock-less reader.
                continue;
            }
            if name == LOCK_FILE_BASENAME {
                // The cross-process lock file, not a lease. It must survive
                // the scan: it is deliberately never removed.
                continue;
            }
            let record = self.read_named(&directory, &name)?;
            records.push(record);
        }
        records.sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
        Ok(records)
    }

    /// Remove crashed writers' temp files. Call ONLY while holding the
    /// exclusive flock from [`LeaseStore::lock`]: temp files are also
    /// created by in-flight writes, so sweeping anywhere else (including the
    /// flock-less [`LeaseStore::load`] scan) can delete a live write's temp
    /// file and fail its rename.
    pub(crate) fn remove_stale_temps(&self) -> Result<(), Error> {
        let directory = self.open_root()?;
        for name in read_names(directory.as_raw_fd()).map_err(|error| self.io("scan", error))? {
            let name = String::from_utf8_lossy(&name).into_owned();
            if name.starts_with(TEMP_PREFIX) {
                unlink_at(directory.as_raw_fd(), name.as_bytes(), 0)
                    .map_err(|error| self.io("remove a stale temp file", error))?;
            }
        }
        Ok(())
    }

    /// Read one record by lease ID. Absence is `Ok(None)`.
    pub(crate) fn read(&self, lease_id: &str) -> Result<Option<LeaseRecord>, Error> {
        validate_lease_id(lease_id)?;
        let directory = self.open_root()?;
        let name = format!("{lease_id}{RECORD_SUFFIX}");
        match stat_at(directory.as_raw_fd(), name.as_bytes()) {
            Ok(_) => Ok(Some(self.read_named(&directory, &name)?)),
            Err(error) if errno_is(&error, libc::ENOENT) => Ok(None),
            Err(error) => Err(self.io("stat a lease record", error)),
        }
    }

    fn read_named(&self, directory: &DirFd, name: &str) -> Result<LeaseRecord, Error> {
        let lease_id = name
            .strip_suffix(RECORD_SUFFIX)
            .ok_or_else(|| Error::UnknownFileName(name.to_string()))?;
        validate_lease_id(lease_id).map_err(|_| Error::UnknownFileName(name.to_string()))?;
        let stat = stat_at(directory.as_raw_fd(), name.as_bytes())
            .map_err(|error| self.io("stat a lease record", error))?;
        if !is_regular(stat.st_mode) {
            return Err(Error::UnknownFileName(name.to_string()));
        }
        if mode_bits(stat.st_mode) & 0o022 != 0 {
            return Err(Error::CorruptRecord {
                name: name.to_string(),
                reason: "record is group or world writable".to_string(),
            });
        }
        let bytes = read_file_at(directory.as_raw_fd(), name.as_bytes(), MAX_RECORD_BYTES)
            .map_err(|error| self.io("read a lease record", error))?;
        LeaseRecord::decode(&bytes, lease_id).map_err(|error| Error::CorruptRecord {
            name: name.to_string(),
            reason: error.to_string(),
        })
    }

    /// Durably publish a record (create or state transition). The write is
    /// atomic: temp file, write, fsync, rename, parent fsync.
    pub(crate) fn write(&self, record: &LeaseRecord) -> Result<(), Error> {
        let directory = self.open_root()?;
        let name = record.file_name();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = format!("{TEMP_PREFIX}-{}-{counter}", std::process::id());
        let result = (|| {
            self.trip(FaultPoint::LeaseTempCreate)?;
            let mut file = create_file_at(directory.as_raw_fd(), temp.as_bytes(), 0o600)
                .map_err(|error| self.io("create a lease temp file", error))?;
            self.trip(FaultPoint::LeaseWrite)?;
            file.write_all(record.encode().as_bytes())
                .map_err(|error| self.io("write a lease record", error))?;
            self.trip(FaultPoint::LeaseFileSync)?;
            file.sync_all()
                .map_err(|error| self.io("fsync a lease record", error))?;
            drop(file);
            self.trip(FaultPoint::LeaseRename)?;
            rename_at(
                directory.as_raw_fd(),
                temp.as_bytes(),
                directory.as_raw_fd(),
                name.as_bytes(),
            )
            .map_err(|error| self.io("rename a lease record into place", error))?;
            self.trip(FaultPoint::LeaseParentSync)?;
            sync_directory(directory.as_raw_fd())
                .map_err(|error| self.io("fsync the lease directory", error))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlink_at(directory.as_raw_fd(), temp.as_bytes(), 0);
        }
        result
    }

    /// Verified record removal: unlink the exact lease file, then fsync the
    /// lease directory. Only after this returns `Ok(())` may the caller
    /// treat the pair as free.
    pub(crate) fn remove(&self, lease_id: &str) -> Result<(), Error> {
        validate_lease_id(lease_id)?;
        let directory = self.open_root()?;
        let name = format!("{lease_id}{RECORD_SUFFIX}");
        self.trip(FaultPoint::LeaseUnlink)?;
        match unlink_at(directory.as_raw_fd(), name.as_bytes(), 0) {
            Ok(()) => {}
            Err(error) if errno_is(&error, libc::ENOENT) => {
                return Err(Error::MissingRecord(lease_id.to_string()));
            }
            Err(error) => return Err(self.io("unlink a lease record", error)),
        }
        self.trip(FaultPoint::LeaseUnlinkSync)?;
        sync_directory(directory.as_raw_fd())
            .map_err(|error| self.io("fsync the lease directory after unlink", error))?;
        Ok(())
    }

    fn open_root(&self) -> Result<DirFd, Error> {
        let directory = open_directory_path(&self.root)
            .map_err(|error| self.io("open the lease directory", error))?;
        validate_ownership(&self.root, directory.as_raw_fd())?;
        Ok(directory)
    }

    fn trip(&self, point: FaultPoint) -> Result<(), Error> {
        if let Some(faults) = &self.faults
            && let Err(error) = faults.trip(point)
        {
            return Err(Error::io("injected lease fault", &self.root, error));
        }
        Ok(())
    }

    fn io(&self, operation: &'static str, error: std::io::Error) -> Error {
        Error::io(operation, &self.root, error)
    }
}

/// A held cross-process ledger lock. Dropping it releases the lock.
#[derive(Debug)]
pub(crate) struct LedgerLock<'a> {
    file: &'a File,
}

impl Drop for LedgerLock<'_> {
    fn drop(&mut self) {
        // SAFETY: the descriptor is valid for the store's lifetime, which
        // outlives this guard.
        if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } != 0 {
            // Not expected for an owned, open descriptor. The lock would then
            // linger until the store itself is closed, so say so.
            tracing::warn!("failed to release the lease ledger lock");
        }
    }
}

/// Open the ledger lock file under the already validated ledger directory,
/// creating it mode `0600` on first use and re-validating it on every open.
fn open_lock_file(root: &Path, directory: std::os::fd::RawFd) -> Result<File, Error> {
    // The trailing NUL is part of the literal: openat takes a C string.
    let fd = unsafe {
        libc::openat(
            directory,
            LOCK_FILE_NAME.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(Error::io(
            "open the lease ledger lock file",
            root,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: openat returned a unique owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let (is_regular, owner, mode) = {
        // SAFETY: zeroed is a valid initialization for libc::stat; fstat fills it.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: stat points to writable storage for the valid descriptor.
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(Error::io(
                "stat the lease ledger lock file",
                root,
                std::io::Error::last_os_error(),
            ));
        }
        (
            is_regular(stat.st_mode),
            stat.st_uid,
            mode_bits(stat.st_mode),
        )
    };
    if !is_regular {
        return Err(Error::UnsafeDirectory(
            root.to_path_buf(),
            "ledger lock file is not a regular file".into(),
        ));
    }
    if owner != crate::paths::euid() {
        return Err(Error::UnsafeDirectory(
            root.to_path_buf(),
            "ledger lock file is not owned by the daemon user".into(),
        ));
    }
    if mode & 0o022 != 0 {
        return Err(Error::UnsafeDirectory(
            root.to_path_buf(),
            "ledger lock file is group or world writable".into(),
        ));
    }
    Ok(file)
}

fn validate_ownership(root: &Path, fd: std::os::fd::RawFd) -> Result<(), Error> {
    // SAFETY: zeroed is a valid initialization for libc::stat; fstat fills it.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: stat points to writable storage for the valid descriptor.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(Error::io(
            "stat the lease directory",
            root,
            std::io::Error::last_os_error(),
        ));
    }
    if !is_directory(stat.st_mode) {
        return Err(Error::UnsafeDirectory(
            root.to_path_buf(),
            "not a directory".into(),
        ));
    }
    if stat.st_uid != crate::paths::euid() {
        return Err(Error::UnsafeDirectory(
            root.to_path_buf(),
            "not owned by the daemon user".into(),
        ));
    }
    if mode_bits(stat.st_mode) & 0o022 != 0 {
        return Err(Error::UnsafeDirectory(
            root.to_path_buf(),
            "group or world writable".into(),
        ));
    }
    Ok(())
}

/// Lease-ledger failures. Corruption is deliberately loud: the caller fails
/// closed rather than allocating around an unreadable record.
#[derive(Debug)]
pub(crate) enum Error {
    Io {
        root: PathBuf,
        operation: &'static str,
        source: std::io::Error,
    },
    UnsafeDirectory(PathBuf, String),
    UnknownFileName(String),
    CorruptRecord {
        name: String,
        reason: String,
    },
    MissingRecord(String),
    TooLarge(usize),
    NotUtf8,
    Toml(toml::de::Error),
    UnsupportedVersion(u32),
    InvalidLeaseId(String),
    MismatchedLeaseId {
        expected: String,
        found: String,
    },
    InvalidSandboxId {
        reason: String,
    },
    InvalidOwner {
        reason: String,
    },
    ZeroId,
    InvalidState(String),
    InvalidQuarantineReason,
}

impl Error {
    fn io(operation: &'static str, root: &Path, source: std::io::Error) -> Error {
        Error::Io {
            root: root.to_path_buf(),
            operation,
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io {
                root,
                operation,
                source,
            } => write!(
                f,
                "could not {operation} under {}: {source}",
                root.display()
            ),
            Error::UnsafeDirectory(root, reason) => {
                write!(f, "lease directory {} is unsafe: {reason}", root.display())
            }
            Error::UnknownFileName(name) => write!(
                f,
                "unexpected file {name:?} in the lease directory (expected <lease-id>.toml)"
            ),
            Error::CorruptRecord { name, reason } => {
                write!(f, "lease record {name:?} is corrupt: {reason}")
            }
            Error::MissingRecord(lease_id) => {
                write!(f, "lease record {lease_id} does not exist")
            }
            Error::TooLarge(size) => {
                write!(
                    f,
                    "lease record is {size} bytes, limit is {MAX_RECORD_BYTES}"
                )
            }
            Error::NotUtf8 => f.write_str("lease record is not valid UTF-8"),
            Error::Toml(error) => write!(f, "lease record is not valid TOML: {error}"),
            Error::UnsupportedVersion(version) => {
                write!(f, "lease record version {version} is unsupported")
            }
            Error::InvalidLeaseId(lease_id) => write!(
                f,
                "lease id {lease_id:?} is not {LEASE_ID_HEX} lowercase hex characters"
            ),
            Error::MismatchedLeaseId { expected, found } => write!(
                f,
                "lease record names incarnation {found:?}, expected {expected:?}"
            ),
            Error::InvalidSandboxId { reason } => {
                write!(f, "lease record sandbox id is invalid: {reason}")
            }
            Error::InvalidOwner { reason } => {
                write!(f, "lease record owner is invalid: {reason}")
            }
            Error::ZeroId => f.write_str("lease record maps UID or GID 0"),
            Error::InvalidState(state) => write!(f, "lease record state {state:?} is invalid"),
            Error::InvalidQuarantineReason => {
                f.write_str("lease record has a quarantine reason but is not quarantined")
            }
        }
    }
}

fn sync_parent_directory(root: &Path) -> Result<(), Error> {
    let parent = root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = open_directory_path(parent)
        .map_err(|error| Error::io("open the lease directory parent", root, error))?;
    sync_directory(directory.as_raw_fd())
        .map_err(|error| Error::io("fsync the lease directory parent", root, error))
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
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

    fn record(state: LeaseState) -> LeaseRecord {
        LeaseRecord {
            lease_id: "a".repeat(LEASE_ID_HEX),
            sandbox_id: SandboxId::parse("dev").expect("id"),
            owner: owner(),
            uid: 100_000,
            gid: 200_000,
            state,
            quarantine_reason: None,
        }
    }

    #[test]
    fn round_trips_in_deterministic_field_order() {
        let record = record(LeaseState::Reserved);
        let encoded = record.encode();
        assert_eq!(
            encoded,
            "version = 1\nlease_id = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nsandbox_id = \"dev\"\nowner = \"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\nuid = 100000\ngid = 200000\nstate = \"reserved\"\n"
        );
        assert_eq!(
            LeaseRecord::decode(encoded.as_bytes(), &record.lease_id).expect("decode"),
            record
        );
    }

    #[test]
    fn rejects_unknown_fields_bad_values_and_mismatched_ids() {
        let record = record(LeaseState::Active);
        let base = record.encode();
        for invalid in [
            format!("{base}extra = true\n"),
            base.replace("version = 1", "version = 2"),
            base.replace("state = \"active\"", "state = \"free\""),
            base.replace("uid = 100000", "uid = 0"),
            base.replace("gid = 200000", "gid = 0"),
            base.replace("sandbox_id = \"dev\"", "sandbox_id = \"../dev\""),
            format!("{base}uid = 100001\n"),
        ] {
            assert!(
                LeaseRecord::decode(invalid.as_bytes(), &record.lease_id).is_err(),
                "{invalid}"
            );
        }
        assert!(matches!(
            LeaseRecord::decode(base.as_bytes(), &"b".repeat(LEASE_ID_HEX)),
            Err(Error::MismatchedLeaseId { .. })
        ));
        assert!(matches!(
            LeaseRecord::decode(base.as_bytes(), &"g".repeat(LEASE_ID_HEX)),
            Err(Error::InvalidLeaseId(_))
        ));
    }

    #[test]
    fn lease_ids_are_32_lowercase_hex_characters() {
        let id = new_lease_id();
        assert_eq!(id.len(), LEASE_ID_HEX);
        assert!(validate_lease_id(&id).is_ok());
        // 128 random bits: collisions are not a concern, distinct draws are.
        assert_ne!(new_lease_id(), new_lease_id());
        for bad in [
            String::new(),
            "A".repeat(LEASE_ID_HEX), // uppercase
            "g".repeat(LEASE_ID_HEX), // outside hex
            "a".repeat(LEASE_ID_HEX - 1),
            "a".repeat(LEASE_ID_HEX + 1),
            format!("{}.toml", "a".repeat(LEASE_ID_HEX)),
        ] {
            assert!(validate_lease_id(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn store_write_load_and_remove_round_trip() {
        let root = std::env::temp_dir().join(format!("shbox-lease-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = LeaseStore::open(&root, None).expect("open");
        let record = record(LeaseState::Active);
        store.write(&record).expect("write");
        assert_eq!(store.load().expect("load"), vec![record.clone()]);
        assert_eq!(
            store.read(&record.lease_id).expect("read"),
            Some(record.clone())
        );
        store.remove(&record.lease_id).expect("remove");
        assert!(store.load().expect("load").is_empty());
        assert_eq!(store.read(&record.lease_id).expect("read"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn quarantine_reason_round_trips() {
        let mut record = record(LeaseState::Quarantined);
        record.quarantine_reason = Some("owner mismatch during startup".to_string());
        let encoded = record.encode();
        assert_eq!(
            LeaseRecord::decode(encoded.as_bytes(), &record.lease_id).expect("decode"),
            record
        );
    }

    #[test]
    fn store_revalidates_directory_mode_on_each_open() {
        let root =
            std::env::temp_dir().join(format!("shbox-lease-test-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = LeaseStore::open(&root, None).expect("open");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770))
            .expect("make the directory unsafe");
        assert!(matches!(
            store.load(),
            Err(Error::UnsafeDirectory(_, reason)) if reason == "group or world writable"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn store_rejects_unexpected_files_and_corrupt_records() {
        let root =
            std::env::temp_dir().join(format!("shbox-lease-test-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = LeaseStore::open(&root, None).expect("open");
        let record = record(LeaseState::Active);
        store.write(&record).expect("write");
        let stray = root.join("not-a-lease.toml");
        std::fs::write(&stray, b"version = 1\n").expect("write stray");
        assert!(matches!(
            store.load(),
            Err(Error::UnknownFileName(name)) if name == "not-a-lease.toml"
        ));
        let _ = std::fs::remove_file(&stray);
        // Corrupt the record body: still fail-closed.
        std::fs::write(root.join(record.file_name()), b"version = 1\n").expect("corrupt");
        assert!(matches!(store.load(), Err(Error::CorruptRecord { .. })));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ledger_lock_excludes_a_second_store_and_is_skipped_by_the_scan() {
        let root =
            std::env::temp_dir().join(format!("shbox-lease-test-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let first = LeaseStore::open(&root, None).expect("open");
        let second = LeaseStore::open(&root, None).expect("open");
        // Separate `open` calls hold separate descriptions, exactly like two
        // daemon processes sharing the directory.
        let guard = first.lock().expect("lock");
        let attempted =
            unsafe { libc::flock(second.lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(attempted, 0, "a second store must be excluded");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        drop(guard);
        // The kernel-released / explicitly unlocked lock is taken again.
        assert_eq!(
            unsafe { libc::flock(second.lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        // The lock file is not a lease record and never trips the scan.
        assert!(first.load().expect("load").is_empty());
        assert_eq!(
            unsafe { libc::flock(second.lock_file.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_reports_missing_records_instead_of_succeeding() {
        let root =
            std::env::temp_dir().join(format!("shbox-lease-test-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = LeaseStore::open(&root, None).expect("open");
        assert!(matches!(
            store.remove(&"c".repeat(LEASE_ID_HEX)),
            Err(Error::MissingRecord(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
