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

/// Controllers a `ResourceLimits` needs enabled on the creation parent.
fn needed_controllers(limits: &ResourceLimits) -> Vec<&'static str> {
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
    /// signal. An unreadable events file reads as populated: failing open
    /// would risk stranding live processes in a removed domain.
    pub fn is_populated(&self) -> io::Result<bool> {
        let events = read_control(&self.dir, "cgroup.events")?;
        Ok(events
            .lines()
            .any(|line| line.trim_start().starts_with("populated ")
                && line.trim_start().ends_with('1')))
    }

    /// Block until `populated` reads `0` or `timeout` elapses.
    ///
    /// `cgroup.events` supports `poll(2)` notification on kernels with
    /// kernfs event triggers; the bounded poll slice keeps the wait cheap
    /// everywhere else instead of a tight read loop.
    pub fn wait_until_empty(&self, timeout: std::time::Duration) -> io::Result<bool> {
        let deadline = std::time::Instant::now() + timeout;
        // One read arms the kernfs poll trigger before the first wait.
        if !self.is_populated()? {
            return Ok(true);
        }
        let events_fd = open_control_read(&self.dir, "cgroup.events")?;
        loop {
            if !self.is_populated()? {
                return Ok(true);
            }
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
            else {
                return Ok(false);
            };
            let slice = remaining.min(std::time::Duration::from_millis(50));
            let mut poller = libc::pollfd {
                fd: events_fd.as_raw_fd(),
                events: libc::POLLIN,
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
            // Drain the trigger so the next poll blocks until a new change.
            let _ = read_control(&self.dir, "cgroup.events")?;
        }
    }

    /// Remove the cgroup directory, refusing when it is still populated.
    ///
    /// Removal never kills: a populated domain is the caller's explicit
    /// problem (`kill_all` first, then wait, then remove). Idempotent.
    pub fn remove_empty(&self) -> io::Result<()> {
        if self
            .removed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        if self.is_populated().unwrap_or(true) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sandbox cgroup still contains processes",
            ));
        }
        let already_removed =
            self.removed
                .swap(true, std::sync::atomic::Ordering::AcqRel);
        if already_removed {
            return Ok(());
        }
        unlink_directory(self.parent.as_raw_fd(), &self.name)
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self
            .removed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            // Best-effort cleanup of an unreleased cgroup. It never kills:
            // processes still inside are somebody's live sandbox members.
            let _ = self.remove_empty();
        }
    }
}

/// Remove a cgroup directory by name relative to its parent descriptor.
fn unlink_directory(parent: RawFd, name: &std::ffi::OsStr) -> io::Result<()> {
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
    let needed = needed_controllers(limits);
    let parent = resolve_creation_parent(explicit_parent, &needed)?;
    let name = format!("sandbox-{random_suffix}");

    for attempt in 0..8 {
        let candidate = if attempt == 0 {
            name.clone()
        } else {
            format!("{name}-{attempt}")
        };
        // SAFETY: mkdirat with a NUL-free candidate name against an owned fd.
        let result = unsafe {
            libc::mkdirat(
                parent.as_raw_fd(),
                format!("{candidate}\0")
                    .as_bytes()
                    .as_ptr()
                    .cast::<libc::c_char>(),
                0o700,
            )
        };
        match result {
            0 => {
                let cleanup = CgroupDirectoryGuard::new(&parent, &candidate);
                let dir = open_directory(&parent, &candidate)?;
                let parent_copy = parent
                    .try_clone()
                    .map_err(|error| SandboxError::Io(std::io::Error::other(error.to_string())))?;
                let cgroup = Cgroup {
                    dir,
                    parent: parent_copy,
                    name: candidate.into(),
                    removed: std::sync::atomic::AtomicBool::new(false),
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
                        describe_parent(explicit_parent),
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
/// `needed` controllers enabled.
fn resolve_creation_parent(
    explicit: Option<&CgroupParent>,
    needed: &[&str],
) -> Result<OwnedFd, SandboxError> {
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
            Ok(()) => return Ok(dir),
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

/// Verify writability by creating and removing a scratch cgroup.
fn probe_writable(dir: &OwnedFd) -> io::Result<()> {
    let name = format!("probe-{}", std::process::id());
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

fn describe_parent(explicit: Option<&CgroupParent>) -> String {
    explicit.map_or_else(
        || "the resolved cgroup parent".to_string(),
        |parent| parent.path().display().to_string(),
    )
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

    #[cfg(target_os = "linux")]
    #[test]
    fn current_cgroup_path_is_absolute_when_present() {
        if let Some(path) = current_cgroup_path() {
            assert!(path.is_absolute(), "{path:?}");
        }
    }
}
