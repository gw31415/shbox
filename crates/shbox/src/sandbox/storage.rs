//! Safe filesystem operations for the sandbox registry.
//!
//! All management traversal is descriptor-relative and uses no-follow flags.
//! The workspace is application data, so its contents may contain symlinks;
//! deletion removes those links themselves and never follows them.

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::auth::KeyFingerprint;
use crate::paths;

use super::id::SandboxId;
use super::metadata::{self, Metadata, State};

const METADATA_NAME: &[u8] = b"metadata.toml";
const WORKSPACE_NAME: &[u8] = b"workspace";
const TEMP_PREFIX: &str = ".metadata.toml.tmp";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Durable-operation seams used by deterministic recovery tests.  Production
/// storage has no injector attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    CreateSandboxDirectory,
    CreateWorkspace,
    MetadataTempCreate,
    MetadataWrite,
    MetadataFileSync,
    MetadataRename,
    MetadataParentSync,
    RegistryParentSync,
    DeleteEntry,
    DeleteRootSync,
}

#[derive(Debug, Default)]
pub(crate) struct FaultInjector {
    next: Mutex<Option<FaultPoint>>,
}

impl FaultInjector {
    pub(crate) fn fail_once(&self, point: FaultPoint) {
        *self.next.lock().expect("fault injector") = Some(point);
    }

    fn trip(&self, point: FaultPoint) -> Result<(), io::Error> {
        let mut next = self.next.lock().expect("fault injector");
        if *next == Some(point) {
            *next = None;
            return Err(io::Error::other(format!("injected fault at {point:?}")));
        }
        Ok(())
    }
}

/// A validated view of one management entry.
#[derive(Debug)]
pub(crate) enum Entry {
    Absent,
    Active(Metadata),
    Deleting(Metadata),
    Corrupt { reason: String },
}

/// Result of scanning the fixed sandbox root.
#[derive(Debug)]
pub(crate) struct ScanResult {
    pub entries: Vec<(SandboxId, Entry)>,
    pub unknown_entries: usize,
}

/// Filesystem-backed registry.  It intentionally does not implement a
/// filesystem trait: production and tests use the same real POSIX semantics.
#[derive(Debug, Clone)]
pub(crate) struct Storage {
    root: PathBuf,
    faults: Option<Arc<FaultInjector>>,
}

impl Storage {
    pub(crate) fn new(root: &Path) -> Result<Storage, Error> {
        Self::with_faults(root, None)
    }

    pub(crate) fn with_faults(
        root: &Path,
        faults: Option<Arc<FaultInjector>>,
    ) -> Result<Storage, Error> {
        // `paths::Error` implements `std::error::Error`, so it rides along
        // as the io source instead of being flattened to a string.
        paths::validate_dir(root).map_err(|source| Error::Io {
            operation: "validate sandbox root",
            path: root.to_path_buf(),
            source: io::Error::other(source),
        })?;
        Ok(Storage {
            root: root.to_path_buf(),
            faults,
        })
    }

    pub(crate) fn workspace_path(&self, id: &SandboxId) -> PathBuf {
        self.root.join(id.as_str()).join("workspace")
    }

    /// Inspect one entry without following the sandbox directory, metadata,
    /// or workspace path components.
    pub(crate) fn inspect(&self, id: &SandboxId) -> Result<Entry, Error> {
        let root = self.open_root()?;
        let directory = match open_directory_at(root.as_raw_fd(), id.as_str().as_bytes()) {
            Ok(directory) => directory,
            Err(source) if errno_is(&source, libc::ENOENT) => return Ok(Entry::Absent),
            Err(source) if errno_is(&source, libc::ELOOP) => {
                return Ok(Entry::Corrupt {
                    reason: "sandbox directory is a symlink".into(),
                });
            }
            Err(source) if errno_is(&source, libc::ENOTDIR) => {
                return Ok(Entry::Corrupt {
                    reason: "sandbox entry is not a directory".into(),
                });
            }
            Err(source) => return Err(self.io("open sandbox directory", id, source)),
        };
        self.inspect_directory(id, &directory)
    }

    /// Scan every direct registry child. Unknown names are counted as blocked
    /// management entries and are never renamed, removed, or rewritten.
    pub(crate) fn scan(&self) -> Result<ScanResult, Error> {
        let root = self.open_root()?;
        let mut entries = Vec::new();
        let mut unknown_entries = 0;
        for name in read_names(root.as_raw_fd())
            .map_err(|source| self.io_path("scan sandbox root", source))?
        {
            let Ok(raw) = std::str::from_utf8(&name) else {
                unknown_entries += 1;
                continue;
            };
            let Ok(id) = SandboxId::parse(raw) else {
                unknown_entries += 1;
                continue;
            };
            let entry = match open_directory_at(root.as_raw_fd(), name.as_slice()) {
                Ok(directory) => self.inspect_directory(&id, &directory)?,
                Err(source) if errno_is(&source, libc::ELOOP) => Entry::Corrupt {
                    reason: "sandbox directory is a symlink".into(),
                },
                Err(source) if errno_is(&source, libc::ENOTDIR) => Entry::Corrupt {
                    reason: "sandbox entry is not a directory".into(),
                },
                Err(source) => return Err(self.io("open sandbox directory", &id, source)),
            };
            entries.push((id, entry));
        }
        Ok(ScanResult {
            entries,
            unknown_entries,
        })
    }

    /// Publish a new Active record.  The caller holds the validated ID lock;
    /// an existing entry is reported without touching it.
    pub(crate) fn create_active(
        &self,
        id: &SandboxId,
        owner: &KeyFingerprint,
    ) -> Result<Metadata, Error> {
        let root = self.open_root()?;
        self.trip(FaultPoint::CreateSandboxDirectory, id)?;
        if let Err(source) = mkdir_at(root.as_raw_fd(), id.as_str().as_bytes(), 0o700) {
            if errno_is(&source, libc::EEXIST) {
                return Err(Error::AlreadyExists {
                    path: self.entry_path(id),
                });
            }
            return Err(self.io("create sandbox directory", id, source));
        }
        let directory = open_directory_at(root.as_raw_fd(), id.as_str().as_bytes())
            .map_err(|source| self.io("open new sandbox directory", id, source))?;
        self.trip(FaultPoint::CreateWorkspace, id)?;
        mkdir_at(directory.as_raw_fd(), WORKSPACE_NAME, 0o700)
            .map_err(|source| self.io("create sandbox workspace", id, source))?;
        let metadata = Metadata::active(id.clone(), owner.clone());
        write_metadata_at(directory.as_raw_fd(), &metadata, self.faults.as_deref()).map_err(
            |error| Error::with_context("publish sandbox metadata", self.entry_path(id), error),
        )?;
        self.sync_directory(directory.as_raw_fd(), FaultPoint::MetadataParentSync)
            .map_err(|source| self.io("sync sandbox directory", id, source))?;
        self.sync_directory(root.as_raw_fd(), FaultPoint::RegistryParentSync)
            .map_err(|source| self.io("sync sandbox root", id, source))?;
        Ok(metadata)
    }

    /// Atomically replace an already-valid record with a new lifecycle state.
    pub(crate) fn write_metadata(&self, metadata: &Metadata) -> Result<(), Error> {
        let id = metadata.id();
        let root = self.open_root()?;
        let directory = open_directory_at(root.as_raw_fd(), id.as_str().as_bytes())
            .map_err(|source| self.io("open sandbox directory", id, source))?;
        let current = match self.inspect_directory(id, &directory)? {
            Entry::Active(current) | Entry::Deleting(current) => current,
            Entry::Absent => {
                return Err(Error::Corrupt {
                    path: self.entry_path(id),
                    reason: "sandbox disappeared while updating metadata".into(),
                });
            }
            Entry::Corrupt { reason } => {
                return Err(Error::Corrupt {
                    path: self.entry_path(id),
                    reason,
                });
            }
        };
        if current.owner() != metadata.owner() {
            return Err(Error::Corrupt {
                path: self.entry_path(id),
                reason: "metadata owner cannot be changed".into(),
            });
        }
        if current.state() == State::Deleting && metadata.state() == State::Active {
            return Err(Error::Corrupt {
                path: self.entry_path(id),
                reason: "Deleting metadata cannot return to Active".into(),
            });
        }
        write_metadata_at(directory.as_raw_fd(), metadata, self.faults.as_deref()).map_err(
            |error| Error::with_context("replace sandbox metadata", self.entry_path(id), error),
        )?;
        self.sync_directory(directory.as_raw_fd(), FaultPoint::MetadataParentSync)
            .map_err(|source| self.io("sync sandbox metadata", id, source))?;
        Ok(())
    }

    /// Remove a sandbox entry using fd-relative, no-follow tree deletion.
    /// Missing entries are already deleted and therefore succeed.
    pub(crate) fn remove_tree(&self, id: &SandboxId) -> Result<(), Error> {
        let root = self.open_root()?;
        let directory = match open_directory_at(root.as_raw_fd(), id.as_str().as_bytes()) {
            Ok(directory) => directory,
            Err(source) if errno_is(&source, libc::ENOENT) => return Ok(()),
            Err(source) => return Err(self.io("open sandbox for deletion", id, source)),
        };
        remove_children(
            directory.as_raw_fd(),
            &self.entry_path(id),
            self.faults.as_deref(),
        )
        .map_err(|source| self.io("remove sandbox contents", id, source))?;
        if let Some(faults) = &self.faults {
            faults
                .trip(FaultPoint::DeleteEntry)
                .map_err(|source| self.io("remove sandbox metadata", id, source))?;
        }
        // Keep the Deleting record until the workspace is gone. If this
        // unlink is interrupted, startup can still see the durable intent
        // and retry the cleanup (a missing workspace is valid for Deleting).
        unlink_at(directory.as_raw_fd(), METADATA_NAME, 0)
            .map_err(|source| self.io("remove sandbox metadata", id, source))?;
        unlink_at(root.as_raw_fd(), id.as_str().as_bytes(), libc::AT_REMOVEDIR)
            .map_err(|source| self.io("remove sandbox directory", id, source))?;
        self.sync_directory(root.as_raw_fd(), FaultPoint::DeleteRootSync)
            .map_err(|source| self.io("sync sandbox root after deletion", id, source))?;
        Ok(())
    }

    fn inspect_directory(&self, id: &SandboxId, directory: &DirFd) -> Result<Entry, Error> {
        let directory_stat = fstat(directory.as_raw_fd())
            .map_err(|source| self.io("stat sandbox directory", id, source))?;
        if !is_directory(directory_stat.st_mode) {
            return Ok(Entry::Corrupt {
                reason: "sandbox entry is not a directory".into(),
            });
        }
        if directory_stat.st_uid != paths::euid() {
            return Ok(Entry::Corrupt {
                reason: "sandbox directory is not daemon-owned".into(),
            });
        }
        if mode_bits(directory_stat.st_mode) & 0o022 != 0 {
            return Ok(Entry::Corrupt {
                reason: "sandbox directory is group or world writable".into(),
            });
        }

        for name in read_names(directory.as_raw_fd())
            .map_err(|source| self.io("scan sandbox directory", id, source))?
        {
            if name != METADATA_NAME && name != WORKSPACE_NAME {
                return Ok(Entry::Corrupt {
                    reason: "sandbox directory contains an unknown management entry".into(),
                });
            }
        }

        let metadata_stat = match stat_at(directory.as_raw_fd(), METADATA_NAME) {
            Ok(stat) => stat,
            Err(source) if errno_is(&source, libc::ENOENT) => {
                return Ok(Entry::Corrupt {
                    reason: "metadata.toml is missing".into(),
                });
            }
            Err(source) => return Err(self.io("stat sandbox metadata", id, source)),
        };
        if !is_regular(metadata_stat.st_mode) {
            return Ok(Entry::Corrupt {
                reason: "metadata.toml is not a regular file".into(),
            });
        }
        if metadata_stat.st_uid != paths::euid() {
            return Ok(Entry::Corrupt {
                reason: "metadata.toml is not daemon-owned".into(),
            });
        }
        if mode_bits(metadata_stat.st_mode) != 0o600 {
            return Ok(Entry::Corrupt {
                reason: "metadata.toml does not have mode 0600".into(),
            });
        }

        let bytes = read_file_at(directory.as_raw_fd(), METADATA_NAME, metadata::MAX_BYTES)
            .map_err(|source| self.io("read sandbox metadata", id, source))?;
        let metadata = match Metadata::decode(&bytes, id) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Ok(Entry::Corrupt {
                    reason: error.to_string(),
                });
            }
        };

        let workspace_stat = match stat_at(directory.as_raw_fd(), WORKSPACE_NAME) {
            Ok(stat) => stat,
            Err(source) if errno_is(&source, libc::ENOENT) && metadata.is_deleting() => {
                // Workspace removal can be interrupted after its last entry
                // is gone. The durable Deleting record is the recovery
                // intent, so keep it visible to startup reconciliation.
                return Ok(Entry::Deleting(metadata));
            }
            Err(source) if errno_is(&source, libc::ENOENT) => {
                return Ok(Entry::Corrupt {
                    reason: "workspace is missing".into(),
                });
            }
            Err(source) => return Err(self.io("stat sandbox workspace", id, source)),
        };
        if !is_directory(workspace_stat.st_mode) {
            return Ok(Entry::Corrupt {
                reason: "workspace is not a directory".into(),
            });
        }
        if workspace_stat.st_uid != paths::euid() {
            return Ok(Entry::Corrupt {
                reason: "workspace is not daemon-owned".into(),
            });
        }
        if mode_bits(workspace_stat.st_mode) & 0o022 != 0 {
            return Ok(Entry::Corrupt {
                reason: "workspace is group or world writable".into(),
            });
        }

        Ok(match metadata.state() {
            State::Active => Entry::Active(metadata),
            State::Deleting => Entry::Deleting(metadata),
        })
    }

    fn open_root(&self) -> Result<DirFd, Error> {
        open_directory_path(&self.root).map_err(|source| self.io_path("open sandbox root", source))
    }

    fn entry_path(&self, id: &SandboxId) -> PathBuf {
        self.root.join(id.as_str())
    }

    fn io(&self, operation: &'static str, id: &SandboxId, source: io::Error) -> Error {
        Error::Io {
            operation,
            path: self.entry_path(id),
            source,
        }
    }

    fn io_path(&self, operation: &'static str, source: io::Error) -> Error {
        Error::Io {
            operation,
            path: self.root.clone(),
            source,
        }
    }

    fn trip(&self, point: FaultPoint, id: &SandboxId) -> Result<(), Error> {
        let Some(faults) = &self.faults else {
            return Ok(());
        };
        faults
            .trip(point)
            .map_err(|source| self.io("injected storage fault", id, source))
    }

    fn sync_directory(&self, fd: RawFd, point: FaultPoint) -> Result<(), io::Error> {
        if let Some(faults) = &self.faults {
            faults.trip(point)?;
        }
        sync_directory(fd)
    }
}

fn write_metadata_at(
    directory_fd: RawFd,
    metadata: &Metadata,
    faults: Option<&FaultInjector>,
) -> Result<(), io::Error> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("{TEMP_PREFIX}-{}-{counter}", std::process::id());
    let name_bytes = name.as_bytes();
    let result = (|| {
        if let Some(faults) = faults {
            faults.trip(FaultPoint::MetadataTempCreate)?;
        }
        let mut file = create_file_at(directory_fd, name_bytes, 0o600)?;
        if let Some(faults) = faults {
            faults.trip(FaultPoint::MetadataWrite)?;
        }
        file.write_all(metadata.encode().as_bytes())?;
        if let Some(faults) = faults {
            faults.trip(FaultPoint::MetadataFileSync)?;
        }
        file.sync_all()?;
        if let Some(faults) = faults {
            faults.trip(FaultPoint::MetadataRename)?;
        }
        rename_at(directory_fd, name_bytes, directory_fd, METADATA_NAME)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlink_at(directory_fd, name_bytes, 0);
    }
    result
}

fn remove_children(
    directory_fd: RawFd,
    display_path: &Path,
    faults: Option<&FaultInjector>,
) -> Result<(), io::Error> {
    for name in read_names(directory_fd)? {
        if name == METADATA_NAME {
            // The Deleting record is the recovery marker. It is removed only
            // after every other entry has been removed successfully.
            continue;
        }
        let stat = match stat_at(directory_fd, &name) {
            Ok(stat) => stat,
            Err(source) if errno_is(&source, libc::ENOENT) => continue,
            Err(source) => return Err(source),
        };
        if let Some(faults) = faults {
            faults.trip(FaultPoint::DeleteEntry)?;
        }
        if is_directory(stat.st_mode) {
            let child = open_directory_at(directory_fd, &name)?;
            remove_children(
                child.as_raw_fd(),
                &display_path.join(String::from_utf8_lossy(&name).as_ref()),
                faults,
            )?;
            if let Some(faults) = faults {
                faults.trip(FaultPoint::DeleteEntry)?;
            }
            unlink_at(directory_fd, &name, libc::AT_REMOVEDIR)?;
        } else {
            // unlinkat never follows a symlink.  A replacement directory is
            // rejected by this non-AT_REMOVEDIR operation rather than opened.
            unlink_at(directory_fd, &name, 0)?;
        }
    }
    Ok(())
}

struct DirFd {
    fd: RawFd,
}

impl AsRawFd for DirFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for DirFd {
    fn drop(&mut self) {
        // SAFETY: this descriptor is owned by this RAII wrapper.
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn open_directory_path(path: &Path) -> Result<DirFd, io::Error> {
    let path = path_cstring(path)?;
    // O_NONBLOCK prevents a hostile replacement FIFO from making management
    // startup block while the final type check is performed.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = match fstat(fd) {
        Ok(stat) => stat,
        Err(source) => {
            unsafe {
                libc::close(fd);
            }
            return Err(source);
        }
    };
    if !is_directory(stat.st_mode) {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(DirFd { fd })
}

fn open_directory_at(parent: RawFd, name: &[u8]) -> Result<DirFd, io::Error> {
    let name = CString::new(name).map_err(|_| io::Error::other("path component contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = match fstat(fd) {
        Ok(stat) => stat,
        Err(source) => {
            unsafe {
                libc::close(fd);
            }
            return Err(source);
        }
    };
    if !is_directory(stat.st_mode) {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(DirFd { fd })
}

fn create_file_at(parent: RawFd, name: &[u8], mode: u32) -> Result<File, io::Error> {
    let name = CString::new(name).map_err(|_| io::Error::other("path component contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a unique owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_file_at(parent: RawFd, name: &[u8], max_bytes: usize) -> Result<Vec<u8>, io::Error> {
    let name = CString::new(name).map_err(|_| io::Error::other("path component contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a unique owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::other("metadata exceeds the size limit"));
    }
    Ok(bytes)
}

fn read_names(directory_fd: RawFd) -> Result<Vec<Vec<u8>>, io::Error> {
    let duplicate = unsafe { libc::dup(directory_fd) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is an owned descriptor and fdopendir takes ownership.
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let source = io::Error::last_os_error();
        unsafe {
            libc::close(duplicate);
        }
        return Err(source);
    }
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: directory is a valid DIR* until closed below.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let source = io::Error::last_os_error();
            // libc leaves errno at zero for normal end-of-directory.
            if source.raw_os_error().unwrap_or(0) != 0 {
                unsafe {
                    libc::closedir(directory);
                }
                return Err(source);
            }
            break;
        }
        // SAFETY: d_name is a NUL-terminated field owned by readdir's entry.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    unsafe {
        libc::closedir(directory);
    }
    Ok(names)
}

fn path_cstring(path: &Path) -> Result<CString, io::Error> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("path contains NUL"))
}

fn fstat(fd: RawFd) -> Result<libc::stat, io::Error> {
    // SAFETY: zeroed is a valid initialization for libc::stat; fstat fills it.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: stat points to writable storage for the valid descriptor.
    let result = unsafe { libc::fstat(fd, &mut stat) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn stat_at(parent: RawFd, name: &[u8]) -> Result<libc::stat, io::Error> {
    let name = CString::new(name).map_err(|_| io::Error::other("path component contains NUL"))?;
    // SAFETY: zeroed is a valid initialization for libc::stat; fstatat fills it.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: name and stat are valid for this call; AT_SYMLINK_NOFOLLOW is
    // the critical property for management path validation.
    let result =
        unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn mkdir_at(parent: RawFd, name: &[u8], mode: u32) -> Result<(), io::Error> {
    let name = CString::new(name).map_err(|_| io::Error::other("path component contains NUL"))?;
    // SAFETY: name is a valid NUL-terminated component.
    let result = unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn rename_at(from_dir: RawFd, from: &[u8], to_dir: RawFd, to: &[u8]) -> Result<(), io::Error> {
    let from = CString::new(from).map_err(|_| io::Error::other("path component contains NUL"))?;
    let to = CString::new(to).map_err(|_| io::Error::other("path component contains NUL"))?;
    // SAFETY: all descriptors and path components are valid.
    let result = unsafe { libc::renameat(from_dir, from.as_ptr(), to_dir, to.as_ptr()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unlink_at(parent: RawFd, name: &[u8], flags: i32) -> Result<(), io::Error> {
    let name = CString::new(name).map_err(|_| io::Error::other("path component contains NUL"))?;
    // SAFETY: name is a valid NUL-terminated component; unlinkat does not
    // follow symlinks.
    let result = unsafe { libc::unlinkat(parent, name.as_ptr(), flags) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sync_directory(fd: RawFd) -> Result<(), io::Error> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: duplicate is transferred to File.
    let file = unsafe { File::from_raw_fd(duplicate) };
    file.sync_all()
}

fn errno_is(error: &io::Error, errno: i32) -> bool {
    error.raw_os_error() == Some(errno)
}

fn clear_errno() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: this is the current thread's errno slot.
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    // SAFETY: this is the current thread's errno slot.
    unsafe {
        *libc::__error() = 0;
    }
}

fn is_directory(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_regular(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG
}

fn mode_bits(mode: libc::mode_t) -> u32 {
    #[cfg(target_os = "linux")]
    {
        mode & 0o777
    }
    #[cfg(not(target_os = "linux"))]
    {
        mode as u32 & 0o777
    }
}

/// Registry storage errors. Corrupt entries are data failures, not permission
/// to repair: callers must keep the bytes on disk for operator inspection.
#[derive(Debug)]
pub(crate) enum Error {
    AlreadyExists {
        path: PathBuf,
    },
    Corrupt {
        path: PathBuf,
        reason: String,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl Error {
    fn with_context(operation: &'static str, path: PathBuf, source: io::Error) -> Error {
        Error::Io {
            operation,
            path,
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyExists { path } => {
                write!(f, "sandbox entry already exists: {}", path.display())
            }
            Error::Corrupt { path, reason } => {
                write!(f, "corrupt sandbox entry {}: {reason}", path.display())
            }
            Error::Io {
                operation,
                path,
                source,
            } => {
                write!(f, "{operation} {}: {source}", path.display())
            }
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
