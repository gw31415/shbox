//! cgroup v2: a thin, dirfd-centered filesystem wrapper (architecture
//! Phase 3).
//!
//! cgroupfs is a plain filesystem API; rather than pulling in a heavy
//! dependency, this module keeps every string interaction here. The sandbox
//! cgroup is created *before* the child exists and the child is cloned
//! straight into it (`CLONE_INTO_CGROUP`), so resource limits hold from the
//! child's first instruction — there is no apply-after-fork window.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::SandboxError;
use crate::policy::{CgroupParent, Limit, ResourceLimits};

/// Reserved prefix for process domains owned by the durable-domain API.
/// One-shot resource cgroups intentionally use the separate `sandbox-`
/// prefix and are never touched by startup reconciliation.
///
/// Ownership of this prefix is **per delegated parent**: a daemon instance
/// owns every `shbox-domain-*` child of the parent it resolved at startup.
/// The deployment contract therefore requires that a cgroup parent (and the
/// runtime temp root) is delegated to exactly one shbox daemon instance at a
/// time; startup reconciliation of a shared parent would otherwise reclaim
/// another instance's live domains (docs/configuration.md §cgroup-parent).
pub(crate) const PROCESS_DOMAIN_PREFIX: &str = "shbox-domain-";

/// Controllers a `ResourceLimits` needs enabled on the creation parent.
pub(crate) fn needed_controllers(limits: &ResourceLimits) -> Vec<&'static str> {
    let mut controllers = Vec::new();
    if limits.memory_bytes.requires_own_cgroup() || limits.swap_bytes.requires_own_cgroup() {
        controllers.push("memory");
    }
    if limits.cpu_max.requires_own_cgroup() {
        controllers.push("cpu");
    }
    if limits.pids.requires_own_cgroup() {
        controllers.push("pids");
    }
    controllers
}

/// An open sandbox cgroup plus what is needed to remove it again.
///
/// Membership observation (`cgroup.events` `populated`), explicit
/// termination (`cgroup.kill`), and removal are separate operations:
/// removal never kills, and killing never removes. The kernel's membership
/// state — not Rust handle counts — is the authority for every decision.
pub struct Cgroup {
    /// Directory fd of the cgroup itself; also the `CLONE_INTO_CGROUP` fd.
    dir: OwnedFd,
    /// Directory fd of the creation parent.
    parent: OwnedFd,
    name: std::ffi::OsString,
    removed: std::sync::atomic::AtomicBool,
    remove_lock: std::sync::Mutex<()>,
}

impl Cgroup {
    /// The fd to pass to `clone3(CLONE_INTO_CGROUP)`.
    pub fn clone_fd(&self) -> RawFd {
        self.dir.as_raw_fd()
    }

    /// Kill every process in the cgroup (`cgroup.kill`, kernel 5.14+).
    ///
    /// This is the only operation that terminates cgroup members, and it is
    /// always explicit: neither removal nor handle teardown implies it.
    /// Kernels without the file return an error for the caller to combine
    /// with process-group signalling.
    pub fn kill_all(&self) -> io::Result<()> {
        write_control(&self.dir, "cgroup.kill", "1")
    }

    /// Whether the cgroup (or a descendant) still contains processes,
    /// per `cgroup.events` `populated` — the authoritative membership
    /// signal. Unreadable or malformed membership state is returned as an
    /// error so lifecycle callers can fail closed rather than assume empty.
    pub fn is_populated(&self) -> io::Result<bool> {
        populated_from_events(&read_control(&self.dir, "cgroup.events")?)
    }

    /// Block until `populated` reads `0` or `timeout` elapses.
    ///
    /// `cgroup.events` reports membership changes through `POLLPRI`
    /// notifications on kernels with kernfs event triggers; the bounded poll
    /// slice keeps the wait cheap everywhere else instead of a tight read
    /// loop. The polled descriptor itself is drained (`pread` from offset 0)
    /// as kernfs requires, so consecutive polls observe fresh changes.
    pub fn wait_until_empty(&self, timeout: std::time::Duration) -> io::Result<bool> {
        let deadline = std::time::Instant::now() + timeout;
        let events_fd = open_control_read(&self.dir, "cgroup.events")?;
        // One read arms the kernfs poll trigger before the first wait.
        if !populated_from_events(&read_fd_pread(&events_fd)?)? {
            return Ok(true);
        }
        loop {
            if !populated_from_events(&read_fd_pread(&events_fd)?)? {
                return Ok(true);
            }
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return Ok(false);
            };
            let slice = remaining.min(std::time::Duration::from_millis(50));
            let mut poller = libc::pollfd {
                fd: events_fd.as_raw_fd(),
                events: libc::POLLPRI,
                revents: 0,
            };
            // SAFETY: `poller` is one valid pollfd over an owned descriptor.
            let ready = unsafe {
                libc::poll(
                    &mut poller,
                    1,
                    slice.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if ready == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            // Drain the trigger on the polled descriptor itself so the next
            // poll blocks until a new change.
            let _ = read_fd_pread(&events_fd)?;
        }
    }

    /// Remove the cgroup directory, refusing when it is still populated.
    ///
    /// Removal never kills: a populated domain is the caller's explicit
    /// problem (`kill_all` first, then wait, then remove). Idempotent. A
    /// failed removal leaves the handle owning the still-present directory,
    /// so the caller can retry — `removed` is published only after the
    /// unlink is known to have succeeded (`ENOENT` counts as removed).
    pub fn remove_empty(&self) -> io::Result<()> {
        let _remove_guard = self
            .remove_lock
            .lock()
            .map_err(|_| io::Error::other("cgroup removal lock is poisoned"))?;
        if self.removed.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        if self.is_populated().unwrap_or(true) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sandbox cgroup still contains processes",
            ));
        }
        match unlink_directory(self.parent.as_raw_fd(), &self.name) {
            Ok(()) => {
                self.removed
                    .store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.removed
                    .store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.removed.load(std::sync::atomic::Ordering::Acquire) {
            // Best-effort cleanup of an unreleased cgroup. It never kills:
            // processes still inside are somebody's live sandbox members.
            let _ = self.remove_empty();
        }
    }
}

/// Parse `cgroup.events` content for the authoritative `populated` line.
/// Missing or malformed membership state is an error; lifecycle callers then
/// fail closed rather than treating an unknown domain as empty.
fn populated_from_events(events: &str) -> io::Result<bool> {
    for line in events.lines() {
        let Some(value) = line.trim().strip_prefix("populated ") else {
            continue;
        };
        return match value {
            "0" => Ok(false),
            "1" => Ok(true),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid cgroup.events populated value {other:?}"),
            )),
        };
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "cgroup.events did not contain populated state",
    ))
}

/// Read a control descriptor from offset 0 without moving its file offset
/// (`pread`), as kernfs poll triggers require draining the polled fd itself.
fn read_fd_pread(fd: &OwnedFd) -> io::Result<String> {
    let mut buffer = [0_u8; 256];
    // SAFETY: `fd` is owned and `buffer` is a valid writable target.
    let count = unsafe { libc::pread(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf8_lossy(&buffer[..count as usize]).into_owned())
}

// Test seam for fault-transition coverage. Thread-local state prevents a
// parallel unit test from accidentally consuming another test's injected
// unlink failure.
#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_UNLINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Remove a cgroup directory by name relative to its parent descriptor.
fn unlink_directory(parent: RawFd, name: &std::ffi::OsStr) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_UNLINK.with(|fail| fail.replace(false)) {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cgroup name contains NUL"))?;
    // SAFETY: `name` is a NUL-terminated path component and `parent` is an
    // owned directory descriptor held by the caller.
    let result = unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Best-effort rollback for the interval between `mkdirat` and returning a
/// fully configured [`Cgroup`]. The guard is installed immediately after the
/// mkdir succeeds, before any open, descriptor clone, or controller write.
struct CgroupDirectoryGuard<'a> {
    parent: &'a OwnedFd,
    name: std::ffi::OsString,
    armed: bool,
}

impl<'a> CgroupDirectoryGuard<'a> {
    fn new(parent: &'a OwnedFd, name: &str) -> Self {
        Self {
            parent,
            name: name.into(),
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CgroupDirectoryGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlink_directory(self.parent.as_raw_fd(), &self.name);
        }
    }
}

/// A cgroup parent resolved once and reused for every later operation:
/// the open directory descriptor is the authoritative identity, and the
/// path is retained only for diagnostics. Creation and reconciliation
/// performed through one [`ResolvedParent`] can never select different
/// parents (audit B3).
pub(crate) struct ResolvedParent {
    dir: OwnedFd,
    path: PathBuf,
}

impl ResolvedParent {
    /// The resolved parent's path (diagnostics only; enumeration and
    /// creation always use the open descriptor).
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A clone of the open parent descriptor for opening new cgroups.
    fn descriptor(&self) -> Result<OwnedFd, SandboxError> {
        self.dir
            .try_clone()
            .map_err(|error| SandboxError::Io(std::io::Error::other(error)))
    }
}

/// Create a sandbox cgroup under a usable parent and apply the limits.
///
/// Parent resolution order:
/// 1. an explicit [`CgroupParent`] from the config,
/// 2. the parent of the daemon's current cgroup, walking up toward the
///    cgroup2 mount until the needed controllers can be enabled in
///    `subtree_control`.
pub fn create_sandbox_cgroup(
    limits: &ResourceLimits,
    explicit_parent: Option<&CgroupParent>,
    random_suffix: &str,
) -> Result<Cgroup, SandboxError> {
    let parent = resolve_creation_parent(explicit_parent, &needed_controllers(limits))?;
    create_cgroup_under(&parent, limits, "sandbox-", random_suffix)
}

/// Create a durable process-domain cgroup with the reserved ownership prefix.
pub(crate) fn create_process_domain_cgroup(
    limits: &ResourceLimits,
    explicit_parent: Option<&CgroupParent>,
    random_suffix: &str,
) -> Result<Cgroup, SandboxError> {
    let parent = resolve_creation_parent(explicit_parent, &needed_controllers(limits))?;
    create_cgroup_under(&parent, limits, PROCESS_DOMAIN_PREFIX, random_suffix)
}

/// Create a process-domain cgroup below an already-resolved parent.
pub(crate) fn create_process_domain_cgroup_under(
    parent: &ResolvedParent,
    limits: &ResourceLimits,
    random_suffix: &str,
) -> Result<Cgroup, SandboxError> {
    create_cgroup_under(parent, limits, PROCESS_DOMAIN_PREFIX, random_suffix)
}

fn create_cgroup_under(
    parent: &ResolvedParent,
    limits: &ResourceLimits,
    name_prefix: &str,
    random_suffix: &str,
) -> Result<Cgroup, SandboxError> {
    let name = format!("{name_prefix}{random_suffix}");

    for attempt in 0..8 {
        let candidate = if attempt == 0 {
            name.clone()
        } else {
            format!("{name}-{attempt}")
        };
        // SAFETY: mkdirat with a NUL-free candidate name against an owned fd.
        let result = unsafe {
            libc::mkdirat(
                parent.dir.as_raw_fd(),
                format!("{candidate}\0")
                    .as_bytes()
                    .as_ptr()
                    .cast::<libc::c_char>(),
                0o700,
            )
        };
        match result {
            0 => {
                let cleanup = CgroupDirectoryGuard::new(&parent.dir, &candidate);
                let dir = open_directory(&parent.dir, &candidate)?;
                let parent_copy = parent.descriptor()?;
                let cgroup = Cgroup {
                    dir,
                    parent: parent_copy,
                    name: candidate.into(),
                    removed: std::sync::atomic::AtomicBool::new(false),
                    remove_lock: std::sync::Mutex::new(()),
                };
                apply_limits(&cgroup, limits)?;
                cleanup.disarm();
                return Ok(cgroup);
            }
            -1 if super::raw_errno() == libc::EEXIST => continue,
            -1 => {
                return Err(SandboxError::unsupported(
                    "cgroup-v2",
                    format!(
                        "sandbox cgroup could not be created under {}: {}",
                        parent.path.display(),
                        io::Error::last_os_error()
                    ),
                ));
            }
            _ => unreachable!("mkdirat returns 0 or -1"),
        }
    }
    Err(SandboxError::unsupported(
        "cgroup-v2",
        "sandbox cgroup names collided; retry the spawn",
    ))
}

/// Remove stale durable process domains below the resolved delegated parent.
/// Only the reserved [`PROCESS_DOMAIN_PREFIX`] is considered owned; sibling
/// cgroups and one-shot `sandbox-*` cgroups are never inspected or changed.
///
/// Enumeration goes through the open parent descriptor itself (not a
/// re-resolved pathname), so the objects inspected and removed are exactly
/// the children of the parent that was resolved for domain creation.
pub(crate) fn reconcile_process_domain_cgroups(
    parent: &ResolvedParent,
) -> Result<usize, SandboxError> {
    let names = owned_directory_names(&parent.dir)?;

    let mut removed = 0;
    for name in names {
        let cgroup = open_existing_cgroup(parent, &name)?;
        cgroup.kill_all().map_err(SandboxError::Io)?;
        if !cgroup
            .wait_until_empty(std::time::Duration::from_secs(5))
            .map_err(SandboxError::Io)?
        {
            return Err(SandboxError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("stale process domain {name:?} did not empty"),
            )));
        }
        cgroup.remove_empty().map_err(SandboxError::Io)?;
        removed += 1;
    }
    Ok(removed)
}

/// Enumerate direct-child directory names carrying the reserved ownership
/// prefix, reading the already-open parent descriptor via `fdopendir` so
/// directory identity is preserved even if the pathname world changes.
fn owned_directory_names(dir: &OwnedFd) -> Result<Vec<std::ffi::OsString>, SandboxError> {
    // Open `.` relative to the authoritative parent descriptor instead of
    // `dup`ing it: dup would share the directory offset, allowing concurrent
    // enumerations to interfere with one another. openat preserves directory
    // identity while creating an independent open file description.
    // SAFETY: the path is a static NUL-terminated `.` relative to an owned
    // directory descriptor; a non-negative result is a fresh descriptor.
    let iteration_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if iteration_fd == -1 {
        return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `iteration_fd` is a fresh directory descriptor; ownership
    // transfers to the stream on success.
    let stream = unsafe { libc::fdopendir(iteration_fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `iteration_fd` is still ours to close.
        unsafe { libc::close(iteration_fd) };
        return Err(SandboxError::Io(error));
    }
    let mut names = Vec::new();
    loop {
        // readdir reports end-of-directory by returning NULL without setting
        // errno, so clear it first to distinguish that from a real failure.
        // SAFETY: errno access is thread-local and valid on this thread.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` is a valid DIR* from fdopendir and `entry` is only
        // read before the next readdir call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: errno access is thread-local and valid on this thread.
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                // SAFETY: stream is a valid DIR* we own.
                unsafe { libc::closedir(stream) };
                return Err(SandboxError::Io(io::Error::from_raw_os_error(errno)));
            }
            break;
        }
        // SAFETY: d_name is a NUL-terminated array per readdir's contract.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::ffi::OsStr::from_bytes(bytes);
        let is_owned_dir = name
            .to_str()
            .is_some_and(|name| name.starts_with(PROCESS_DOMAIN_PREFIX))
            && entry_is_directory(dir, name);
        if is_owned_dir {
            names.push(name.to_os_string());
        }
    }
    // SAFETY: stream is a valid DIR* we own.
    unsafe { libc::closedir(stream) };
    Ok(names)
}

/// Whether `name` below `dir` is a directory, checked with `fstatat` against
/// the open descriptor (never a re-resolved pathname).
fn entry_is_directory(dir: &OwnedFd, name: &std::ffi::OsStr) -> bool {
    let Ok(path) = std::ffi::CString::new(name.as_bytes()) else {
        return false;
    };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is writable and remains live; `path` is NUL-terminated
    // relative to the owned directory descriptor.
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            path.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    result == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn apply_limits(cgroup: &Cgroup, limits: &ResourceLimits) -> Result<(), SandboxError> {
    let write = |file: &'static str, value: &str| -> Result<(), SandboxError> {
        write_control(&cgroup.dir, file, value).map_err(|error| {
            SandboxError::unsupported(
                "cgroup-v2",
                format!("cgroup control file {file} rejected the policy: {error}"),
            )
        })
    };
    match limits.memory_bytes {
        Limit::Value(bytes) => write("memory.max", &bytes.to_string())?,
        Limit::Unlimited => write("memory.max", "max")?,
        Limit::Inherit => {}
    }
    match limits.swap_bytes {
        Limit::Value(bytes) => write("memory.swap.max", &bytes.to_string())?,
        Limit::Unlimited => write("memory.swap.max", "max")?,
        Limit::Inherit => {}
    }
    match limits.pids {
        Limit::Value(count) => write("pids.max", &count.to_string())?,
        Limit::Unlimited => write("pids.max", "max")?,
        Limit::Inherit => {}
    }
    match limits.cpu_max {
        Limit::Value(cpu) => write("cpu.max", &format!("{} {}", cpu.quota_us, cpu.period_us))?,
        Limit::Unlimited => write("cpu.max", "max 100000")?,
        Limit::Inherit => {}
    }
    Ok(())
}

/// Find a cgroup2 directory under which sandbox cgroups can be created with
/// `needed` controllers enabled, and return it as a resolved parent whose
/// open descriptor is the identity for every later operation on it.
pub(crate) fn resolve_creation_parent(
    explicit: Option<&CgroupParent>,
    needed: &[&str],
) -> Result<ResolvedParent, SandboxError> {
    // The chain of ancestor directories to try, from most to least specific.
    // Auto-discovery starts at the current cgroup's parent. A daemon process
    // is normally in a leaf such as `service-root/daemon`; the empty parent
    // is the cgroup-v2-safe place for `service-root/sandbox-*` children.
    let mut candidates: Vec<PathBuf> = Vec::new();
    let cgroup_mount = cgroup2_mount();
    let hierarchy_root = cgroup_mount
        .as_ref()
        .map(|(mount_point, _)| PathBuf::from(mount_point));
    let hierarchy_root_is_global = cgroup_mount
        .as_ref()
        .is_some_and(|(_, fs_root)| paths_equal(Path::new(fs_root), Path::new("/")));
    if let Some(explicit) = explicit {
        if !explicit.path().is_absolute() {
            return Err(SandboxError::invalid(
                "cgroup_parent",
                format!(
                    "cgroup parent {} is not absolute",
                    explicit.path().display()
                ),
            ));
        }
        candidates.push(explicit.path().to_path_buf());
    } else {
        match (current_cgroup_path(), hierarchy_root.as_deref()) {
            (Some(current), Some(root)) => {
                candidates = auto_creation_parent_candidates(&current, root);
            }
            _ => {
                return Err(SandboxError::unsupported(
                    "cgroup-v2",
                    "no cgroup v2 hierarchy is active on this system",
                ));
            }
        }
    }

    let mut last_error = String::new();
    for candidate in &candidates {
        let dir = match open_directory_at_path(candidate) {
            Ok(dir) => dir,
            Err(error) => {
                last_error = format!("{candidate:?}: {error}");
                continue;
            }
        };
        let is_hierarchy_root = hierarchy_root_is_global
            && hierarchy_root
                .as_deref()
                .is_some_and(|root| paths_equal(root, candidate));
        if !is_hierarchy_root {
            match read_control(&dir, "cgroup.procs") {
                Ok(processes) if !processes.trim().is_empty() => {
                    last_error = format!(
                        "{candidate:?}: cgroup contains member processes and cannot distribute controllers"
                    );
                    continue;
                }
                Ok(_) => {}
                Err(error) => {
                    last_error = format!("{candidate:?}: cgroup.procs could not be read: {error}");
                    continue;
                }
            }
        }
        // Controllers must be listed as available at this level.
        let available = read_control(&dir, "cgroup.controllers").unwrap_or_default();
        let missing: Vec<&str> = needed
            .iter()
            .copied()
            .filter(|controller| !available.split_whitespace().any(|c| c == *controller))
            .collect();
        if !missing.is_empty() {
            last_error = format!("{candidate:?}: controllers {:?} are not available", missing);
            continue;
        }

        // Already-enabled controllers need no write; try to enable the rest.
        let enabled = read_control(&dir, "cgroup.subtree_control").unwrap_or_default();
        let to_enable: Vec<&str> = needed
            .iter()
            .copied()
            .filter(|controller| !enabled.split_whitespace().any(|c| c == *controller))
            .collect();
        if !to_enable.is_empty() {
            let value = to_enable
                .iter()
                .map(|controller| format!("+{controller}"))
                .collect::<Vec<_>>()
                .join(" ");
            if let Err(error) = write_control(&dir, "cgroup.subtree_control", &value) {
                last_error = format!(
                    "{candidate:?}: enabling {value} in cgroup.subtree_control failed: {error}"
                );
                continue;
            }
        }

        // The parent must actually accept child cgroups.
        match probe_writable(&dir) {
            Ok(()) => {
                return Ok(ResolvedParent {
                    dir,
                    path: candidate.clone(),
                });
            }
            Err(error) => {
                last_error = format!("{candidate:?}: {error}");
            }
        }
    }
    Err(SandboxError::unsupported(
        "cgroup-v2",
        format!(
            "no usable cgroup v2 parent for controllers {needed:?}; \
             configure a delegated cgroup parent. Last attempt: {last_error}",
        ),
    ))
}

/// Return auto-discovery candidates without selecting the daemon's populated
/// leaf. The hierarchy root is retained as the final candidate because the
/// kernel explicitly exempts the root cgroup from the no-internal-process
/// constraint.
fn auto_creation_parent_candidates(current: &Path, hierarchy_root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut candidate = if paths_equal(current, hierarchy_root) {
        hierarchy_root.to_path_buf()
    } else if current.starts_with(hierarchy_root) {
        current
            .parent()
            .filter(|parent| parent.starts_with(hierarchy_root))
            .unwrap_or(hierarchy_root)
            .to_path_buf()
    } else {
        hierarchy_root.to_path_buf()
    };

    loop {
        candidates.push(candidate.clone());
        if paths_equal(&candidate, hierarchy_root) {
            break;
        }
        candidate = match candidate.parent() {
            Some(parent) if parent.starts_with(hierarchy_root) => parent.to_path_buf(),
            _ => hierarchy_root.to_path_buf(),
        };
    }
    candidates
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.components().eq(right.components())
}

/// Verify writability by creating and removing a scratch cgroup. The scratch
/// name is unique per call (pid + process-local counter), so concurrent
/// probes of the same candidate cannot interpret each other's directory as
/// `EEXIST` unavailability.
fn probe_writable(dir: &OwnedFd) -> io::Result<()> {
    static PROBE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = PROBE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("probe-{}-{serial}", std::process::id());
    // SAFETY: mkdirat against the owned directory fd with a NUL-terminated
    // scratch name.
    let result = unsafe {
        libc::mkdirat(
            dir.as_raw_fd(),
            format!("{name}\0")
                .as_bytes()
                .as_ptr()
                .cast::<libc::c_char>(),
            0o700,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // Install the rollback guard before any operation after mkdirat can fail.
    let cleanup = CgroupDirectoryGuard::new(dir, &name);
    unlink_directory(dir.as_raw_fd(), std::ffi::OsStr::new(&name))?;
    cleanup.disarm();
    Ok(())
}

/// The daemon's current cgroup2 path (mounted-path form), from
/// `/proc/self/cgroup` and `/proc/self/mountinfo`.
pub fn current_cgroup_path() -> Option<PathBuf> {
    let relative = current_cgroup_relative()?;
    let (mount_point, fs_root) = cgroup2_mount()?;
    let within: &Path = Path::new(&relative);
    if let Ok(stripped) = within.strip_prefix(&fs_root) {
        if stripped.as_os_str().is_empty() {
            return Some(PathBuf::from(mount_point));
        }
        Some(PathBuf::from(mount_point).join(stripped))
    } else {
        // A bind-mount view we cannot map; use the mount point itself.
        Some(PathBuf::from(mount_point))
    }
}

fn current_cgroup_relative() -> Option<String> {
    let mut content = String::new();
    File::open("/proc/self/cgroup")
        .ok()?
        .read_to_string(&mut content)
        .ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
}

fn cgroup2_mount() -> Option<(String, String)> {
    let mut content = String::new();
    File::open("/proc/self/mountinfo")
        .ok()?
        .read_to_string(&mut content)
        .ok()?;
    content.lines().find_map(parse_cgroup2_mountinfo_line)
}

fn parse_cgroup2_mountinfo_line(line: &str) -> Option<(String, String)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let separator = fields.iter().position(|field| *field == "-")?;
    // The six mandatory pre-separator fields are: mount ID, parent ID,
    // major:minor, root, mount point, and mount options.
    if separator < 6 || fields.get(separator + 1)? != &"cgroup2" {
        return None;
    }
    Some((
        unescape_mountinfo(fields.get(4)?)?,
        unescape_mountinfo(fields.get(3)?)?,
    ))
}

/// Decode mountinfo's octal escapes (e.g. `\040` for space).
fn unescape_mountinfo(field: &str) -> Option<String> {
    let mut out = String::with_capacity(field.len());
    let bytes = field.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let value =
                u32::from_str_radix(std::str::from_utf8(&bytes[index + 1..index + 4]).ok()?, 8)
                    .ok()?;
            out.push(char::from_u32(value)?);
            index += 4;
        } else {
            out.push(field[index..].chars().next()?);
            index += field[index..].chars().next()?.len_utf8();
        }
    }
    Some(out)
}

fn open_directory_at_path(path: &Path) -> io::Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)?;
    Ok(file.into())
}

fn open_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, SandboxError> {
    let path = format!("{name}\0");
    // SAFETY: openat against an owned directory fd with a NUL-terminated
    // relative name; a successful result is a uniquely owned descriptor.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            path.as_bytes().as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(SandboxError::unsupported(
            "cgroup-v2",
            format!(
                "sandbox cgroup {name:?} could not be opened: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: fd is a fresh descriptor from a successful openat.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_existing_cgroup(
    parent: &ResolvedParent,
    name: &std::ffi::OsStr,
) -> Result<Cgroup, SandboxError> {
    let name = name.to_str().ok_or_else(|| {
        SandboxError::invalid("cgroup_name", "owned cgroup name is not valid UTF-8")
    })?;
    let dir = open_directory(&parent.dir, name)?;
    let parent_copy = parent.descriptor()?;
    Ok(Cgroup {
        dir,
        parent: parent_copy,
        name: name.into(),
        removed: std::sync::atomic::AtomicBool::new(false),
        remove_lock: std::sync::Mutex::new(()),
    })
}

fn write_control(dir: &OwnedFd, name: &str, value: &str) -> io::Result<()> {
    let path = format!("{name}\0");
    // SAFETY: openat against an owned directory fd with a NUL-terminated
    // relative name; a successful result is a uniquely owned descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            path.as_bytes().as_ptr().cast::<libc::c_char>(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor from a successful openat.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(value.as_bytes())
}

/// Open a control file read-only for poll-based waiting.
fn open_control_read(dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    let path = format!("{name}\0");
    // SAFETY: openat against an owned directory fd with a NUL-terminated
    // relative name; a successful result is a uniquely owned descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            path.as_bytes().as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor from a successful openat.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_control(dir: &OwnedFd, name: &str) -> io::Result<String> {
    let path = format!("{name}\0");
    // SAFETY: openat against an owned directory fd with a NUL-terminated
    // relative name; a successful result is a uniquely owned descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            path.as_bytes().as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor from a successful openat.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_escapes_decode() {
        assert_eq!(
            unescape_mountinfo("/sys/fs/cgroup").as_deref(),
            Some("/sys/fs/cgroup")
        );
        assert_eq!(
            unescape_mountinfo("/mnt/space\\040here").as_deref(),
            Some("/mnt/space here")
        );
    }

    #[test]
    fn mountinfo_parser_finds_filesystem_after_optional_fields() {
        let line = "36 29 0:32 /cgroup /sys/fs/cgroup rw,nosuid,nodev shared:1 master:2 - cgroup2 cgroup rw";
        assert_eq!(
            parse_cgroup2_mountinfo_line(line),
            Some(("/sys/fs/cgroup".into(), "/cgroup".into()))
        );
    }

    #[test]
    fn auto_discovery_uses_service_root_for_a_daemon_leaf() {
        let root = Path::new("/sys/fs/cgroup");
        let current = Path::new("/sys/fs/cgroup/shbox.service/daemon");
        let candidates = auto_creation_parent_candidates(current, root);

        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/sys/fs/cgroup/shbox.service"),
                PathBuf::from("/sys/fs/cgroup"),
            ]
        );
    }

    #[test]
    fn populated_non_root_parent_is_not_usable_for_controller_distribution() {
        let root = tempfile::tempdir().expect("cgroup parent");
        std::fs::write(root.path().join("cgroup.controllers"), b"pids\n").expect("controllers");
        std::fs::write(root.path().join("cgroup.subtree_control"), b"pids\n")
            .expect("subtree control");
        std::fs::write(root.path().join("cgroup.procs"), b"123\n").expect("processes");
        let parent = CgroupParent::new(root.path());

        assert!(resolve_creation_parent(Some(&parent), &["pids"]).is_err());
    }

    #[test]
    fn directory_guard_removes_a_partially_configured_cgroup() {
        let root = tempfile::tempdir().expect("cgroup parent");
        let parent = open_directory_at_path(root.path()).expect("open cgroup parent");
        let name = "partial";
        std::fs::create_dir(root.path().join(name)).expect("mkdir cgroup");

        {
            let _cleanup = CgroupDirectoryGuard::new(&parent, name);
            assert!(root.path().join(name).exists());
        }

        assert!(!root.path().join(name).exists());
    }

    #[test]
    fn cgroup_creation_failure_removes_new_directory() {
        let root = tempfile::tempdir().expect("cgroup parent");
        std::fs::write(root.path().join("cgroup.controllers"), b"pids\n").expect("controllers");
        std::fs::write(root.path().join("cgroup.subtree_control"), b"").expect("subtree control");
        std::fs::write(root.path().join("cgroup.procs"), b"").expect("processes");
        let parent = CgroupParent::new(root.path());
        let limits = ResourceLimits {
            pids: Limit::Value(1),
            ..ResourceLimits::default()
        };

        assert!(create_sandbox_cgroup(&limits, Some(&parent), "rollback").is_err());
        assert!(!root.path().join("sandbox-rollback").exists());
    }

    #[test]
    fn needed_controllers_follow_limits() {
        let mut limits = ResourceLimits::default();
        assert!(needed_controllers(&limits).is_empty());
        limits.pids = Limit::Value(10);
        assert_eq!(needed_controllers(&limits), vec!["pids"]);
        limits.memory_bytes = Limit::Unlimited;
        assert_eq!(needed_controllers(&limits), vec!["memory", "pids"]);
        limits.cpu_max = Limit::Value(crate::policy::CpuMax {
            quota_us: 100_000,
            period_us: 100_000,
        });
        assert_eq!(needed_controllers(&limits), vec!["memory", "cpu", "pids"]);
    }

    #[test]
    fn inherit_limits_leave_controller_files_unchanged() {
        let root = tempfile::tempdir().expect("cgroup directory");
        for file in ["memory.max", "memory.swap.max", "pids.max", "cpu.max"] {
            std::fs::write(root.path().join(file), b"parent-policy\n").expect("controller file");
        }
        let dir = open_directory_at_path(root.path()).expect("open cgroup directory");
        let parent = dir.try_clone().expect("clone cgroup directory");
        let cgroup = Cgroup {
            dir,
            parent,
            name: "test".into(),
            removed: std::sync::atomic::AtomicBool::new(false),
            remove_lock: std::sync::Mutex::new(()),
        };

        apply_limits(&cgroup, &ResourceLimits::default()).expect("inherit limits");

        for file in ["memory.max", "memory.swap.max", "pids.max", "cpu.max"] {
            assert_eq!(
                std::fs::read_to_string(root.path().join(file)).expect("read controller file"),
                "parent-policy\n",
                "Limit::Inherit must not write {file}"
            );
        }
    }

    /// A fake cgroup directory: plain tempdir with the control files the
    /// dirfd-based code reads.
    fn fake_cgroup_parent() -> (tempfile::TempDir, OwnedFd) {
        let root = tempfile::tempdir().expect("cgroup parent");
        std::fs::write(root.path().join("cgroup.controllers"), b"").expect("controllers");
        std::fs::write(root.path().join("cgroup.subtree_control"), b"").expect("subtree");
        std::fs::write(root.path().join("cgroup.procs"), b"").expect("procs");
        let fd = open_directory_at_path(root.path()).expect("open parent");
        (root, fd)
    }

    fn fake_cgroup(parent: &OwnedFd, parent_path: &Path, name: &str) -> Cgroup {
        std::fs::create_dir(parent_path.join(name)).expect("mkdir fake cgroup");
        std::fs::write(
            parent_path.join(name).join("cgroup.events"),
            b"populated 0\n",
        )
        .expect("events");
        Cgroup {
            dir: open_directory(parent, name).expect("open cgroup"),
            parent: parent.try_clone().expect("clone parent fd"),
            name: name.into(),
            removed: std::sync::atomic::AtomicBool::new(false),
            remove_lock: std::sync::Mutex::new(()),
        }
    }

    /// Audit B2: a failed `unlinkat` must not publish `removed`; the next
    /// `remove_empty()` still performs the removal and succeeds.
    #[test]
    fn remove_empty_is_retryable_after_a_failed_unlink() {
        let (root, parent_fd) = fake_cgroup_parent();
        let cgroup = fake_cgroup(&parent_fd, root.path(), "domain");

        FAIL_NEXT_UNLINK.with(|fail| fail.set(true));
        let error = cgroup.remove_empty().expect_err("injected unlink failure");
        assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
        assert!(
            root.path().join("domain").exists(),
            "the cgroup must still be present after a failed removal"
        );

        // The failed attempt must not have published `removed`: the next
        // call performs a real unlink again (observing a second injected
        // failure) instead of returning the stale `Ok(())` of audit B2.
        FAIL_NEXT_UNLINK.with(|fail| fail.set(true));
        let again = cgroup.remove_empty().expect_err("second injected failure");
        assert_eq!(again.raw_os_error(), Some(libc::EBUSY));
        assert!(
            root.path().join("domain").exists(),
            "ownership must be retained across failed removals"
        );
    }

    /// Audit S3: concurrent writability probes of one candidate parent must
    /// all succeed (unique scratch names, no shared `EEXIST`).
    #[test]
    fn concurrent_writability_probes_do_not_conflict() {
        use std::sync::Arc;
        let (root, parent_fd) = fake_cgroup_parent();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            let fd = parent_fd.try_clone().expect("clone parent fd");
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                probe_writable(&fd).expect("concurrent probe")
            }));
        }
        for handle in handles {
            handle.join().expect("probe thread");
        }
        assert_eq!(
            std::fs::read_dir(root.path())
                .expect("parent listing")
                .count(),
            // only the fake control files remain
            3
        );
    }

    /// Audit B3/S2: creation and reconciliation operate on one resolved
    /// parent object, so the reconciled set is exactly the creation parent's
    /// owned children — verified with a second non-owned directory beside it.
    #[test]
    fn resolved_parent_is_shared_by_creation_and_enumeration() {
        let (root, parent_fd) = fake_cgroup_parent();
        let parent = resolve_creation_parent(Some(&CgroupParent::new(root.path())), &[])
            .expect("resolve parent");
        assert_eq!(parent.path(), root.path());

        let domain = fake_cgroup(&parent_fd, root.path(), "shbox-domain-abc");
        std::fs::create_dir(root.path().join("sandbox-oneshot")).expect("one-shot sibling");
        std::fs::create_dir(root.path().join("shbox-domain")).expect("prefix-only file name");

        let names = owned_directory_names(&parent.dir).expect("enumerate owned domains");
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("shbox-domain-abc")],
            "only the owned process-domain prefix is reconciled"
        );
        drop(domain);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_cgroup_path_is_absolute_when_present() {
        if let Some(path) = current_cgroup_path() {
            assert!(path.is_absolute(), "{path:?}");
        }
    }
}
