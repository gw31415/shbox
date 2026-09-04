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
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

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
    for (v, group) in values[..40]
        .as_chunks::<4>()
        .0
        .iter()
        .zip(out.as_chunks_mut::<3>().0.iter_mut())
    {
        group[0] = (v[0] << 2) | (v[1] >> 4);
        group[1] = (v[1] << 4) | (v[2] >> 2);
        group[2] = (v[2] << 6) | v[3];
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
    // `symlink_metadata` above reports the link itself, so a symlink lands
    // here as "not a regular file" — no separate symlink check to reach.
    if !metadata.is_file() {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            reason: format!("{source_name} is not a regular file"),
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

/// The validated authentication snapshot: accepted Ed25519 keys mapped to
/// their roles. Snapshots are immutable; the live accepted-key set lives in
/// [`KeyStore`], which swaps one in only after both key sources re-validate in
/// full. A connection keeps the `Principal` it authenticated with, so a later
/// refresh never changes an existing connection's role.
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
    // Duplicate fingerprints are rejected; the auxiliary set keeps detection
    // linear in the key count while the ordered `Vec` preserves file order.
    let mut seen = std::collections::HashSet::new();
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
        if !seen.insert(fingerprint.clone()) {
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
            if let std::collections::btree_map::Entry::Vacant(entry) =
                principals.entry(host_key.fingerprint.clone())
            {
                entry.insert(Role::Admin);
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

/// The observable state of one key source path, taken with
/// `fs::symlink_metadata` so the identity describes the directory entry
/// itself, never a symlink target.
///
/// A missing path is a first-class identity: both key sources may legitimately
/// be absent. `ctime` rather than `mtime` is part of the identity because a
/// permission-only change (exactly what [`validate_key_source_file`] exists to
/// reject) moves `ctime` while leaving `mtime` untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileIdentity {
    /// The path does not exist. Any stat failure folds into this variant on
    /// purpose: it still counts as a change against a cached inode, and the
    /// authoritative reason surfaces from the following full validation.
    Absent,
    /// A statable directory entry: device, inode, status-change time, mode, size.
    Inode {
        dev: u64,
        ino: u64,
        ctime_ns: i64,
        mode: u32,
        size: u64,
    },
}

/// What one request-time refresh check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Identities matched and no revalidation was forced: the live snapshot
    /// was returned untouched.
    Unchanged,
    /// Both key sources were re-read, fully re-validated, and published.
    Reloaded,
}

#[derive(Debug)]
struct StoreState {
    snapshot: Arc<AuthSnapshot>,
    identities: SourceIdentities,
}

/// The two key-source identities by role, so a swapped observe order cannot
/// compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceIdentities {
    /// The host `authorized_keys`.
    host: FileIdentity,
    /// The sandbox `allowed_keys`.
    allowed: FileIdentity,
}

/// The single live key store: the accepted-key snapshot plus the on-disk
/// identities it was built from.
///
/// Every authentication request stats both key sources (two syscalls) and
/// re-runs the full [`AuthSnapshot::load`] validation pipeline only when an
/// identity changed or [`KeyStore::invalidate`] was called. The unchanged
/// comparison runs under a read lock, so concurrent unchanged requests do not
/// serialize behind each other; a changed or forced check takes the write
/// lock, which makes concurrent refreshes single-flight. A failed refresh
/// never publishes: the previous snapshot keeps serving and the *observed*
/// identities are adopted, so a broken file costs at most one rejected parse
/// per on-disk change rather than one per request.
///
/// Locking: one [`std::sync::RwLock`], acquired only on blocking threads and
/// never held across an `.await`. The store owns both paths so a future
/// subsystem that manages keys can serialize the current list and write it
/// back through this same validation path.
#[derive(Debug)]
pub struct KeyStore {
    host_path: PathBuf,
    allowed_path: PathBuf,
    state: RwLock<StoreState>,
    /// Set by [`KeyStore::invalidate`]; consumed under the write guard so a
    /// forced re-read happens exactly once.
    revalidate: AtomicBool,
    /// `AuthSnapshot::load` attempts (initial load included), for tests.
    #[cfg(test)]
    loads: AtomicU64,
}

impl KeyStore {
    /// Build the store from the current contents of both key sources. This is
    /// the boot path and stays fail-closed: an unsafe file, malformed line, or
    /// empty union is an error, never a fallback.
    pub fn load(host_path: &Path, allowed_path: &Path) -> Result<KeyStore, Error> {
        let snapshot = AuthSnapshot::load(host_path, allowed_path)?;
        Ok(KeyStore {
            host_path: host_path.to_path_buf(),
            allowed_path: allowed_path.to_path_buf(),
            state: RwLock::new(StoreState {
                snapshot: Arc::new(snapshot),
                identities: SourceIdentities {
                    host: observe_identity(host_path),
                    allowed: observe_identity(allowed_path),
                },
            }),
            revalidate: AtomicBool::new(false),
            #[cfg(test)]
            loads: AtomicU64::new(1),
        })
    }

    /// The live snapshot without touching the filesystem.
    pub fn snapshot(&self) -> Arc<AuthSnapshot> {
        self.state().snapshot.clone()
    }

    /// Admin keys in the live snapshot. Consumed once at boot to select
    /// managed mode; later refreshes do not re-decide it.
    pub fn admin_count(&self) -> usize {
        self.state().snapshot.admin_count()
    }

    /// The guarded store state. A poisoned lock means a refresh panicked
    /// mid-call; `StoreState` is never half-updated (a new snapshot is
    /// published as one coherent value), so recovering the data is safe and
    /// beats cascading the panic to every later authentication.
    fn state(&self) -> std::sync::RwLockReadGuard<'_, StoreState> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Force the next request-time check to re-read and re-validate both key
    /// sources even when their identities look unchanged (the SIGHUP path).
    /// Performs no I/O itself.
    pub fn invalidate(&self) {
        self.revalidate.store(true, Ordering::Release);
    }

    /// Stat both key sources and, when either changed or the store was
    /// invalidated, re-run the full [`AuthSnapshot::load`] pipeline and
    /// publish the result.
    ///
    /// Blocking (file I/O); call it from `spawn_blocking`. The unchanged
    /// fast path compares the observed identities under a read lock; the
    /// reload path re-observes under the write guard, so concurrent refreshes
    /// remain single-flight. On failure the live snapshot is untouched and
    /// the observed identities are adopted, so the next request does not
    /// re-parse until the on-disk state changes again.
    pub fn refresh_if_changed(&self) -> Result<RefreshOutcome, Error> {
        // Fast path: two stats and an identity comparison. Any change found
        // here falls through to the serialized slow path.
        let observed = SourceIdentities {
            host: observe_identity(&self.host_path),
            allowed: observe_identity(&self.allowed_path),
        };
        if !self.revalidate.load(Ordering::Acquire) {
            let state = self.state();
            if state.identities == observed {
                return Ok(RefreshOutcome::Unchanged);
            }
        }

        // Slow path: see `state()`; a poisoned guard still holds a coherent
        // snapshot. Re-observe under the write guard: concurrent refreshes
        // serialize here, so the first publisher satisfies every other
        // waiter's comparison.
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observed = SourceIdentities {
            host: observe_identity(&self.host_path),
            allowed: observe_identity(&self.allowed_path),
        };
        let forced = self.revalidate.swap(false, Ordering::AcqRel);
        if !forced && state.identities == observed {
            return Ok(RefreshOutcome::Unchanged);
        }
        #[cfg(test)]
        self.loads.fetch_add(1, Ordering::Relaxed);
        match AuthSnapshot::load(&self.host_path, &self.allowed_path) {
            Ok(snapshot) => {
                state.identities = observed;
                state.snapshot = Arc::new(snapshot);
                Ok(RefreshOutcome::Reloaded)
            }
            // Keep the previous snapshot, but adopt the identities just
            // observed so a stable bad state does not re-parse per request.
            Err(error) => {
                state.identities = observed;
                Err(error)
            }
        }
    }

    /// The snapshot to consult for one authentication request: refresh first,
    /// then return whatever is live. Never fails — a rejected refresh keeps
    /// serving the previous snapshot and logs the reason. Every lock is taken
    /// on a blocking thread.
    pub async fn snapshot_for_auth(self: &Arc<Self>) -> Arc<AuthSnapshot> {
        let store = Arc::clone(self);
        let result = tokio::task::spawn_blocking(move || {
            let outcome = store.refresh_if_changed();
            (store.snapshot(), outcome)
        })
        .await;
        match result {
            Ok((snapshot, Ok(RefreshOutcome::Reloaded))) => {
                tracing::info!("key sources changed: authentication snapshot refreshed");
                snapshot
            }
            Ok((snapshot, Ok(RefreshOutcome::Unchanged))) => snapshot,
            Ok((snapshot, Err(error))) => {
                tracing::warn!(
                    error = %error,
                    "key source refresh rejected; keeping the previous authentication snapshot"
                );
                snapshot
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "key refresh task failed; keeping the previous authentication snapshot"
                );
                self.snapshot()
            }
        }
    }

    /// Accepted-key validation attempts so far (initial load included).
    #[cfg(test)]
    pub fn load_count(&self) -> u64 {
        self.loads.load(Ordering::Relaxed)
    }
}

/// Observe one key source's identity. Any stat failure folds into
/// [`FileIdentity::Absent`] on purpose: it still counts as a change against a
/// cached inode, and the authoritative reason surfaces from the following
/// [`AuthSnapshot::load`], which re-stats and re-opens with `O_NOFOLLOW`.
fn observe_identity(path: &Path) -> FileIdentity {
    match fs::symlink_metadata(path) {
        Ok(metadata) => FileIdentity::Inode {
            dev: metadata.dev(),
            ino: metadata.ino(),
            ctime_ns: metadata.ctime_nsec(),
            mode: metadata.mode(),
            size: metadata.len(),
        },
        Err(_) => FileIdentity::Absent,
    }
}

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
        let home = tempfile::Builder::new()
            .prefix(".shbox-auth-test-")
            .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("tempdir");
        // tempfile 3.x creates directories with default permissions
        // (umask-dependent); the parent validator correctly rejects
        // group-writable ancestors, so fixtures must be explicitly private.
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
            .expect("fixture home must be private");
        home
    }

    /// Write a key-source fixture with private permissions. The loader is
    /// right to reject group-writable sources, so fixtures must not depend
    /// on the ambient umask to be acceptable.
    fn write_private(path: &Path, content: impl AsRef<[u8]>) {
        fs::write(path, content).expect("write fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("fixture must be private");
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

    /// Assert a refresh succeeded with the expected outcome. `auth::Error`
    /// carries an `io::Error`, so the result cannot be compared as a whole.
    fn expect_outcome(result: Result<RefreshOutcome, Error>, expected: RefreshOutcome) {
        assert_eq!(result.expect("refresh must succeed"), expected);
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
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n{line_a}\n"));

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
        write_private(&host_path, format!("{line_a}\n{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));
        let err = AuthSnapshot::load(&host_path, &allowed_path).expect_err("dup host");
        let message = err.to_string();
        assert!(
            message.contains(&host_path.display().to_string()),
            "{message}"
        );
        assert!(message.contains("duplicates an earlier key"), "{message}");

        // Duplicate in allowed file
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n{line_b}\n"));
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

        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));

        // Missing host + valid allowed
        let snapshot = AuthSnapshot::load(&missing_host, &allowed_path).expect("missing host");
        assert_eq!(snapshot.admin_count(), 0);
        assert_eq!(snapshot.authenticate(&key_b).unwrap().role, Role::Normal);
        assert_eq!(snapshot.keys()[0].fingerprint, fp_b);

        // Empty host + valid allowed
        let empty_host = home.path().join("empty_host");
        write_private(&empty_host, b"");
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
        write_private(&empty_allowed, b"");
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
        write_private(&comment_host, "# comment only\n\n");
        write_private(&comment_allowed, "# another comment\n");
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
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, "not-a-valid-key\n");
        let err = AuthSnapshot::load(&host_path, &allowed_path).expect_err("malformed allowed");
        let message = err.to_string();
        assert!(
            message.contains(&allowed_path.display().to_string()),
            "{message}"
        );

        // Host malformed, allowed valid -> error specifies host path
        write_private(&host_path, "not-a-valid-key\n");
        write_private(&allowed_path, format!("{line_b}\n"));
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
        write_private(&host_path, &line_a);
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
        let mut padded = good;
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
        write_private(&path, b"ssh-ed25519 AAAA test\n");
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
        write_private(&path, &line);
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

    // ---- KeyStore: request-time refresh over stat identities ----

    #[test]
    fn identity_distinguishes_absent_present_and_rewrites() {
        let home = auth_tempdir();
        let path = home.path().join("authorized_keys");
        assert_eq!(observe_identity(&path), FileIdentity::Absent);
        let (line, _) = generated_key();
        write_private(&path, format!("{line}\n"));
        let present = observe_identity(&path);
        assert!(matches!(present, FileIdentity::Inode { .. }));
        // A permission-only change moves ctime but not mtime; the identity
        // must still change so the next request re-runs the safety checks.
        // Toggle one mode bit instead of assigning a fixed mode: the Linux
        // platform gate runs under `umask 077`, so a newly-created file may
        // already be 0600 and `chmod 0600` would not be a metadata change.
        let mode = fs::symlink_metadata(&path)
            .expect("stat")
            .permissions()
            .mode();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100)).expect("chmod");
        assert_ne!(observe_identity(&path), present);
        fs::remove_file(&path).expect("remove");
        assert_eq!(observe_identity(&path), FileIdentity::Absent);
    }

    #[test]
    fn store_load_is_fail_closed_on_malformed_source() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        // Malformed source.
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, b"garbage\n");
        assert!(KeyStore::load(&host_path, &allowed_path).is_err());
        // Unsafe permissions.
        write_private(&allowed_path, format!("{line_a}\n"));
        fs::set_permissions(&allowed_path, fs::Permissions::from_mode(0o664)).expect("chmod");
        assert!(KeyStore::load(&host_path, &allowed_path).is_err());
        // Empty union (both sources absent).
        fs::set_permissions(&allowed_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::remove_file(&allowed_path).expect("remove allowed");
        fs::remove_file(&host_path).expect("remove host");
        assert!(matches!(
            KeyStore::load(&host_path, &allowed_path),
            Err(Error::EmptyAuthSnapshot { .. })
        ));
    }

    #[test]
    fn store_refresh_rejects_and_keeps_previous_snapshot() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, fp_a) = generated_key();
        let (line_b, _) = generated_key();
        let key_a = russh::keys::PublicKey::from_openssh(&line_a).expect("parse a");
        let key_b = russh::keys::PublicKey::from_openssh(&line_b).expect("parse b");
        write_private(&host_path, format!("{line_a}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        assert_eq!(
            store
                .snapshot()
                .authenticate(&key_a)
                .expect("auth a")
                .fingerprint,
            fp_a
        );

        // A malformed allowed_keys must not publish anything.
        write_private(&allowed_path, b"garbage\n");
        assert!(store.refresh_if_changed().is_err());
        assert!(store.snapshot().authenticate(&key_a).is_some());
        assert!(store.snapshot().authenticate(&key_b).is_none());

        // Fixing the file publishes on the next check.
        write_private(&allowed_path, format!("{line_b}\n"));
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Reloaded);
        assert!(store.snapshot().authenticate(&key_b).is_some());
    }

    #[test]
    fn store_rejects_empty_union_and_keeps_previous() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        let key_a = russh::keys::PublicKey::from_openssh(&line_a).expect("parse a");
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        // Truncating both sources empties the union; the refresh is rejected
        // and the previous snapshot keeps serving.
        write_private(&host_path, "");
        write_private(&allowed_path, "");
        assert!(matches!(
            store.refresh_if_changed(),
            Err(Error::EmptyAuthSnapshot { .. })
        ));
        assert!(store.snapshot().authenticate(&key_a).is_some());
    }

    #[test]
    fn store_caches_the_failed_identity_until_the_file_changes() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        let key_b = russh::keys::PublicKey::from_openssh(&line_b).expect("parse b");
        write_private(&host_path, format!("{line_a}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        // A stable broken file is parsed exactly once, not once per request.
        write_private(&allowed_path, b"garbage\n");
        assert!(store.refresh_if_changed().is_err());
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Unchanged);
        assert_eq!(store.load_count(), 2);
        // The next on-disk change retries the parse and applies it.
        write_private(&allowed_path, format!("{line_b}\n"));
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Reloaded);
        assert!(store.snapshot().authenticate(&key_b).is_some());
        assert_eq!(store.load_count(), 3);
    }

    #[test]
    fn store_caches_identities_for_both_sources_on_failure() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        let (line_c, _) = generated_key();
        let key_c = russh::keys::PublicKey::from_openssh(&line_c).expect("parse c");
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        // A valid host change plus a malformed allowed change rejects whole,
        // matching the old all-or-nothing reload semantics.
        write_private(&host_path, format!("{line_c}\n"));
        write_private(&allowed_path, b"garbage\n");
        assert!(store.refresh_if_changed().is_err());
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Unchanged);
        // Fixing the malformed source publishes both changes at once.
        write_private(&allowed_path, format!("{line_b}\n"));
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Reloaded);
        assert!(store.snapshot().authenticate(&key_c).is_some());
    }

    #[test]
    fn store_invalidate_forces_one_revalidation() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        write_private(&host_path, format!("{line_a}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Unchanged);
        store.invalidate();
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Reloaded);
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Unchanged);
        assert_eq!(store.load_count(), 2);
    }

    #[test]
    fn store_deleted_file_is_a_change_and_may_be_rejected() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        let key_a = russh::keys::PublicKey::from_openssh(&line_a).expect("parse a");
        let key_b = russh::keys::PublicKey::from_openssh(&line_b).expect("parse b");
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        // Deleting the allowed source leaves a valid host-only snapshot.
        fs::remove_file(&allowed_path).expect("remove allowed");
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Reloaded);
        assert!(store.snapshot().authenticate(&key_a).is_some());
        assert!(store.snapshot().authenticate(&key_b).is_none());
        // Deleting the last source empties the union and is rejected, so the
        // previous snapshot keeps serving.
        fs::remove_file(&host_path).expect("remove host");
        assert!(store.refresh_if_changed().is_err());
        assert!(store.snapshot().authenticate(&key_a).is_some());
    }

    #[test]
    fn store_created_host_file_promotes_a_key_to_admin() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let key_a = russh::keys::PublicKey::from_openssh(&line_a).expect("parse a");
        // Boot with the host source absent: the key starts as Normal.
        write_private(&allowed_path, format!("{line_a}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        assert_eq!(
            store.snapshot().authenticate(&key_a).expect("auth").role,
            Role::Normal
        );
        // The host file appears later; the next check grants Admin.
        write_private(&host_path, format!("{line_a}\n"));
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Reloaded);
        assert_eq!(
            store.snapshot().authenticate(&key_a).expect("auth").role,
            Role::Admin
        );
    }

    #[test]
    fn store_reports_unsafe_ancestor_on_forced_refresh() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let key_a = russh::keys::PublicKey::from_openssh(&line_a).expect("parse a");
        write_private(&host_path, format!("{line_a}\n"));
        let store = KeyStore::load(&host_path, &allowed_path).expect("load");
        // An ancestor mode change is invisible to a file-only stat identity:
        // the ordinary check stays Unchanged (the documented limitation), and
        // SIGHUP-style invalidation is what surfaces it.
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o770)).expect("chmod dir");
        expect_outcome(store.refresh_if_changed(), RefreshOutcome::Unchanged);
        store.invalidate();
        let error = store.refresh_if_changed().expect_err("unsafe ancestor");
        assert!(
            error
                .to_string()
                .contains("parent is group or world writable")
        );
        assert!(store.snapshot().authenticate(&key_a).is_some());
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).expect("restore dir");
    }

    #[test]
    fn store_concurrent_refresh_is_single_flight() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        write_private(&host_path, format!("{line_a}\n"));
        let store = Arc::new(KeyStore::load(&host_path, &allowed_path).expect("load"));
        write_private(&allowed_path, format!("{line_b}\n"));
        store.invalidate();
        let waiters = 8;
        let barrier = Arc::new(std::sync::Barrier::new(waiters));
        let handles: Vec<_> = (0..waiters)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.refresh_if_changed()
                })
            })
            .collect();
        let mut reloaded = 0;
        let mut unchanged = 0;
        for handle in handles {
            match handle.join().expect("join") {
                Ok(RefreshOutcome::Reloaded) => reloaded += 1,
                Ok(RefreshOutcome::Unchanged) => unchanged += 1,
                Err(error) => panic!("unexpected refresh failure: {error}"),
            }
        }
        assert_eq!(reloaded, 1);
        assert_eq!(unchanged, waiters - 1);
        assert_eq!(store.load_count(), 2);
    }

    /// Concurrent unchanged refreshes take the read-lock fast path: they all
    /// observe `Unchanged` without serializing behind a writer or forcing a
    /// reload.
    #[test]
    fn store_concurrent_unchanged_refreshes_take_the_fast_path() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));
        let store = Arc::new(KeyStore::load(&host_path, &allowed_path).expect("load"));
        let waiters = 8;
        let barrier = Arc::new(std::sync::Barrier::new(waiters));
        let handles: Vec<_> = (0..waiters)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.refresh_if_changed()
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(
                handle.join().expect("join").expect("refresh"),
                RefreshOutcome::Unchanged
            );
        }
        assert_eq!(store.load_count(), 1, "no reload may be triggered");
    }

    /// Duplicate detection stays linear and order-stable on large key sets.
    #[test]
    fn parses_large_key_sets_in_file_order() {
        let keys: Vec<(String, KeyFingerprint)> = (0..200).map(|_| generated_key()).collect();
        let text = keys
            .iter()
            .map(|(line, _)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = AuthSnapshot::parse_authorized_keys(text.as_bytes()).expect("parse");
        assert_eq!(parsed.len(), keys.len());
        for (entry, (_, expected)) in parsed.iter().zip(keys.iter()) {
            assert_eq!(entry.fingerprint, *expected);
        }
        // A duplicate anywhere still invalidates the whole file.
        let duplicated = format!("{text}\n{}", keys[100].0);
        assert!(AuthSnapshot::parse_authorized_keys(duplicated.as_bytes()).is_err());
    }

    // ---- Performance baselines (M1) ----
    //
    // Replayed with:
    //   cargo test --release --all-features -- baseline -- --ignored --test-threads=1 --nocapture
    // These are measurement scaffolding, not pass/fail performance gates:
    // each test prints a value recorded in PLANS.md and only asserts the
    // workload actually completed.

    fn median_of(cases: usize, run: impl Fn() -> std::time::Duration) -> std::time::Duration {
        let mut samples: Vec<std::time::Duration> = (0..cases).map(|_| run()).collect();
        samples.sort();
        samples[cases / 2]
    }

    /// Scaling of `parse_key_source` versus configured-key count. The
    /// duplicate-fingerprint check makes this quadratic before M3; the
    /// per-key cost printed for n and 2n must match within noise after it.
    #[test]
    #[ignore = "performance baseline; replay with cargo test --release -- baseline -- --ignored --nocapture"]
    fn baseline_parse_key_source_scaling() {
        // Valid Ed25519 keys are required: every line runs through
        // `PublicKey::from_openssh`, so synthetic blobs cannot stand in.
        let keys: Vec<String> = (0..1000).map(|_| generated_key().0).collect();
        for count in [250, 500, 1000] {
            let text = keys[..count].join("\n");
            let elapsed = median_of(5, || {
                let start = std::time::Instant::now();
                let parsed = parse_key_source(text.as_bytes(), Path::new("<baseline>"), true)
                    .expect("parse");
                assert_eq!(parsed.len(), count);
                start.elapsed()
            });
            println!(
                "baseline parse_key_source n={count}: {elapsed:?} ({:?}/key)",
                elapsed / count as u32
            );
        }
    }

    /// Steady-state cost of an unchanged request-time refresh: two
    /// `symlink_metadata` calls plus synchronization, measured alone and
    /// under concurrent refreshers.
    #[test]
    #[ignore = "performance baseline; replay with cargo test --release -- baseline -- --ignored --nocapture"]
    fn baseline_keystore_unchanged_refresh() {
        let home = auth_tempdir();
        let host_path = home.path().join("authorized_keys");
        let allowed_path = home.path().join("allowed_keys");
        let (line_a, _) = generated_key();
        let (line_b, _) = generated_key();
        write_private(&host_path, format!("{line_a}\n"));
        write_private(&allowed_path, format!("{line_b}\n"));
        let store = Arc::new(KeyStore::load(&host_path, &allowed_path).expect("load"));
        assert_eq!(
            store.refresh_if_changed().expect("first refresh"),
            RefreshOutcome::Unchanged
        );

        let iterations = 2_000;
        let elapsed = median_of(5, || {
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                assert_eq!(
                    store.refresh_if_changed().expect("refresh"),
                    RefreshOutcome::Unchanged
                );
            }
            start.elapsed()
        });
        println!(
            "baseline unchanged refresh per call (single thread): {:?}",
            elapsed / iterations
        );

        let threads = 8;
        let per_thread = 500;
        let barrier = Arc::new(std::sync::Barrier::new(threads));
        let start = std::time::Instant::now();
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..per_thread {
                        assert_eq!(
                            store.refresh_if_changed().expect("refresh"),
                            RefreshOutcome::Unchanged
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("join");
        }
        let total = threads * per_thread;
        println!(
            "baseline unchanged refresh per call ({threads} concurrent threads): {:?}",
            start.elapsed() / (total as u32)
        );
    }
}
