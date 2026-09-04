//! Fixed-size protocol and Linux implementation of the privileged ID-map
//! mount broker.
//!
//! The SSH daemon is intentionally not given `CAP_SYS_ADMIN` in the initial
//! user namespace. It sends already-open directory and namespace descriptors
//! over a private `SOCK_SEQPACKET` socket; the broker returns detached mount
//! descriptors and never receives a target mount namespace or a pathname.

#![cfg(target_os = "linux")]

use std::io;
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use shbox_sandbox::IsolatedIdentity;

use super::LaunchError;

pub(crate) const DEFAULT_SOCKET_PATH: &str = "/run/shbox-idmap-broker.sock";
const PROTOCOL_VERSION: u32 = 1;
const OP_CREATE_IDMAPPED_MOUNTS: u32 = 1;
const REQUEST_LEN: usize = 40;
const RESPONSE_LEN: usize = 32;
const SOURCE_FD_COUNT: usize = 3;
const MOUNT_FD_COUNT: usize = 2;

const STATUS_OK: u32 = 0;
const STATUS_INVALID_REQUEST: u32 = 1;
const STATUS_UNAUTHORIZED: u32 = 2;
const STATUS_SOURCE_REJECTED: u32 = 3;
const STATUS_MOUNT_UNSUPPORTED: u32 = 4;

const AT_EMPTY_PATH: u64 = 0x1000;
const OPEN_TREE_CLONE: u64 = 1;
const OPEN_TREE_CLOEXEC: u64 = 0x80000;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;
const MAX_HANDLER_THREADS: usize = 16;
const CLIENT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Detached workspace and runtime-temp views returned by the broker.
#[derive(Debug)]
pub(crate) struct BrokerMounts {
    pub(crate) workspace: OwnedFd,
    pub(crate) runtime: OwnedFd,
}

#[derive(Debug, Clone)]
struct BrokerRoots {
    data: Arc<PinnedRoot>,
    runtime: Arc<PinnedRoot>,
}

#[derive(Debug)]
struct PinnedRoot {
    fd: OwnedFd,
    path: std::path::PathBuf,
}

impl BrokerRoots {
    fn from_paths(data: std::path::PathBuf, runtime: std::path::PathBuf) -> io::Result<Self> {
        Ok(Self {
            data: Arc::new(PinnedRoot::open(data)?),
            runtime: Arc::new(PinnedRoot::open(runtime)?),
        })
    }
}

impl PinnedRoot {
    fn open(configured_path: std::path::PathBuf) -> io::Result<Self> {
        // Resolve the operator configuration once, then keep the opened
        // directory descriptor as the authority for every later lookup.
        let path = std::fs::canonicalize(&configured_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot resolve ID-map broker root {}: {error}",
                    configured_path.display()
                ),
            )
        })?;
        let path_bytes = path.as_os_str().as_bytes();
        let path_cstr = std::ffi::CString::new(path_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ID-map broker root contains an interior NUL",
            )
        })?;
        let fd = unsafe {
            libc::open(
                path_cstr.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!(
                    "cannot open ID-map broker root {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: `fd` is a fresh descriptor owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let metadata = stat_fd(fd.as_raw_fd())?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ID-map broker root {} is not a directory", path.display()),
            ));
        }
        if metadata.st_mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "ID-map broker root {} is group or world writable",
                    path.display()
                ),
            ));
        }
        Ok(Self { fd, path })
    }
}

/// Connect to the broker, create two detached ID-mapped bind mounts, and
/// receive their descriptors in stable workspace/runtime order.
pub(crate) fn create_idmapped_mounts(
    socket_path: &Path,
    identity: IsolatedIdentity,
    mount_idmap_userns: RawFd,
    workspace_source: RawFd,
    runtime_source: RawFd,
) -> Result<BrokerMounts, LaunchError> {
    let socket = connect(socket_path).map_err(|error| {
        LaunchError::with_source("isolated sandbox ID-map mount broker is unavailable", error)
    })?;
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let request = encode_request(request_id, identity);
    send_with_fds(
        socket.as_raw_fd(),
        &request,
        &[mount_idmap_userns, workspace_source, runtime_source],
    )
    .map_err(|error| LaunchError::with_source("ID-map broker request failed", error))?;

    let (response, fds) = receive_message(socket.as_raw_fd(), MOUNT_FD_COUNT)
        .map_err(|error| LaunchError::with_source("ID-map broker response failed", error))?;
    let (status, response_id, mount_count, error_code) = decode_response(&response)?;
    if response_id != request_id {
        return Err(LaunchError::new(
            "ID-map broker returned a mismatched request identifier",
        ));
    }
    if status != STATUS_OK {
        return Err(LaunchError::new(format!(
            "ID-map broker rejected the mount request (status {status}, code {error_code})"
        )));
    }
    if mount_count as usize != MOUNT_FD_COUNT || fds.len() != MOUNT_FD_COUNT {
        return Err(LaunchError::new(
            "ID-map broker returned an invalid detached-mount descriptor count",
        ));
    }
    let mut fds = fds.into_iter();
    Ok(BrokerMounts {
        workspace: fds.next().expect("checked mount fd count"),
        runtime: fds.next().expect("checked mount fd count"),
    })
}

fn encode_request(request_id: u64, identity: IsolatedIdentity) -> [u8; REQUEST_LEN] {
    let mut request = [0_u8; REQUEST_LEN];
    put_u32(&mut request, 0, PROTOCOL_VERSION);
    put_u32(&mut request, 4, OP_CREATE_IDMAPPED_MOUNTS);
    put_u64(&mut request, 8, request_id);
    put_u32(&mut request, 16, effective_uid());
    put_u32(&mut request, 20, effective_gid());
    put_u32(&mut request, 24, identity.host_uid);
    put_u32(&mut request, 28, identity.host_gid);
    put_u32(&mut request, 32, 2);
    request
}

fn connect(path: &Path) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor owned by this function on all paths.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let (address, length) = unix_address(path)?;
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn unix_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ID-map broker socket path is empty or too long",
        ));
    }
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as _,
        sun_path: [0; 108],
    };
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *slot = byte as libc::c_char;
    }
    let length = (size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Ok((address, length))
}

/// Run the socket-activated broker. A service manager must pass exactly one
/// listener as fd 3; accepting a path or creating a listener here would make
/// the privileged endpoint susceptible to an unsafe replacement race.
pub(crate) fn run_from_systemd() -> io::Result<()> {
    let listen_fds = std::env::var("LISTEN_FDS").unwrap_or_default();
    let listen_pid = std::env::var("LISTEN_PID").unwrap_or_default();
    if listen_fds != "1" || listen_pid != std::process::id().to_string() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ID-map broker requires one socket-activated listener",
        ));
    }
    if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: systemd owns fd 3 and LISTEN_FDS validation above establishes
    // that it is the single listener handed to this process.
    let listener = unsafe { OwnedFd::from_raw_fd(3) };
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ID-map broker must run in the initial user namespace as root",
        ));
    }
    let data = std::env::var_os("SHBOX_IDMAP_DATA_ROOT").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ID-map broker data root is not configured",
        )
    })?;
    let runtime = std::env::var_os("SHBOX_IDMAP_RUNTIME_ROOT").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ID-map broker runtime root is not configured",
        )
    })?;
    let roots = BrokerRoots::from_paths(data.into(), runtime.into())?;
    serve(listener, roots)
}

#[derive(Debug)]
struct HandlerSemaphore {
    active: Mutex<usize>,
    available: Condvar,
}

impl HandlerSemaphore {
    fn new() -> Self {
        Self {
            active: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> HandlerPermit {
        let mut active = match self.active.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        while *active >= MAX_HANDLER_THREADS {
            active = match self.available.wait(active) {
                Ok(active) => active,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        *active += 1;
        HandlerPermit {
            semaphore: Arc::clone(self),
        }
    }

    fn release(&self) {
        let mut active = match self.active.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        *active = active.saturating_sub(1);
        self.available.notify_one();
    }
}

struct HandlerPermit {
    semaphore: Arc<HandlerSemaphore>,
}

impl Drop for HandlerPermit {
    fn drop(&mut self) {
        self.semaphore.release();
    }
}

fn serve(listener: OwnedFd, roots: BrokerRoots) -> io::Result<()> {
    let handlers = Arc::new(HandlerSemaphore::new());
    loop {
        let client = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if client < 0 {
            let error = io::Error::last_os_error();
            if is_transient_accept_error(&error) {
                std::thread::sleep(ACCEPT_RETRY_DELAY);
                continue;
            }
            return Err(error);
        }
        // SAFETY: accept4 returned a new owned descriptor.
        let client = unsafe { OwnedFd::from_raw_fd(client) };
        let permit = handlers.acquire();
        let roots = roots.clone();
        let result = std::thread::Builder::new()
            .name("shbox-idmap-client".to_string())
            .spawn(move || {
                let _permit = permit;
                if let Err(error) = handle_client(client, &roots) {
                    tracing::error!(error = %error, "ID-map broker request failed");
                }
            });
        if let Err(error) = result {
            tracing::error!(error = %error, "could not start ID-map broker client handler");
        }
    }
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    match error.raw_os_error() {
        Some(libc::EINTR | libc::EMFILE | libc::ENFILE | libc::ECONNABORTED) => true,
        Some(errno) => errno == libc::EAGAIN || errno == libc::EWOULDBLOCK,
        None => false,
    }
}

fn handle_client(client: OwnedFd, roots: &BrokerRoots) -> io::Result<()> {
    set_receive_timeout(client.as_raw_fd())?;
    let peer = peer_credentials(client.as_raw_fd())?;
    let (request_bytes, fds) = receive_message(client.as_raw_fd(), SOURCE_FD_COUNT)?;
    let request = decode_request(&request_bytes).inspect_err(|_| {
        let _ = send_response(client.as_raw_fd(), STATUS_INVALID_REQUEST, 0, 0, 1, &[]);
    })?;
    if peer.uid == 0
        || request.daemon_uid != peer.uid
        || request.daemon_gid != peer.gid
        || request.source_count as usize != 2
        || fds.len() != SOURCE_FD_COUNT
    {
        send_response(
            client.as_raw_fd(),
            STATUS_UNAUTHORIZED,
            request.request_id,
            0,
            2,
            &[],
        )?;
        return Ok(());
    }
    if request.leased_uid == 0
        || request.leased_gid == 0
        || request.leased_uid == request.daemon_uid
        || request.leased_gid == request.daemon_gid
    {
        send_response(
            client.as_raw_fd(),
            STATUS_INVALID_REQUEST,
            request.request_id,
            0,
            3,
            &[],
        )?;
        return Ok(());
    }
    let mut fds = fds.into_iter();
    let userns = fds.next().expect("checked source fd count");
    let workspace = fds.next().expect("checked source fd count");
    let runtime = fds.next().expect("checked source fd count");
    if !is_user_namespace_fd(userns.as_raw_fd())
        || validate_source_fd(
            workspace.as_raw_fd(),
            request.daemon_uid,
            request.daemon_gid,
            &roots.data,
        )
        .is_err()
        || validate_source_fd(
            runtime.as_raw_fd(),
            request.daemon_uid,
            request.daemon_gid,
            &roots.runtime,
        )
        .is_err()
    {
        send_response(
            client.as_raw_fd(),
            STATUS_SOURCE_REJECTED,
            request.request_id,
            0,
            4,
            &[],
        )?;
        return Ok(());
    }

    let mounts = match create_mounts(
        userns.as_raw_fd(),
        workspace.as_raw_fd(),
        runtime.as_raw_fd(),
        request.leased_uid,
        request.leased_gid,
    ) {
        Ok(mounts) => mounts,
        Err(error) => {
            tracing::error!(error = %error, "ID-map mount construction failed");
            send_response(
                client.as_raw_fd(),
                STATUS_MOUNT_UNSUPPORTED,
                request.request_id,
                0,
                error.raw_os_error().unwrap_or(libc::EIO) as u32,
                &[],
            )?;
            return Ok(());
        }
    };
    send_response(
        client.as_raw_fd(),
        STATUS_OK,
        request.request_id,
        2,
        0,
        &[mounts.0.as_raw_fd(), mounts.1.as_raw_fd()],
    )
}

fn create_mounts(
    userns: RawFd,
    workspace: RawFd,
    runtime: RawFd,
    leased_uid: u32,
    leased_gid: u32,
) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut mounts = Vec::with_capacity(MOUNT_FD_COUNT);
    for source in [workspace, runtime] {
        let detached = unsafe {
            libc::syscall(
                shbox_sandbox::syscall_number("open_tree").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "open_tree is unavailable")
                })?,
                source,
                c"".as_ptr(),
                AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
            )
        };
        if detached < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: syscall returned a new owned descriptor.
        let detached = unsafe { OwnedFd::from_raw_fd(detached as RawFd) };
        let attributes = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns as u64,
        };
        let result = unsafe {
            libc::syscall(
                shbox_sandbox::syscall_number("mount_setattr").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "mount_setattr is unavailable")
                })?,
                detached.as_raw_fd(),
                c"".as_ptr(),
                AT_EMPTY_PATH,
                std::ptr::addr_of!(attributes),
                size_of::<MountAttr>(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        validate_mapped_root(detached.as_raw_fd(), leased_uid, leased_gid)?;
        mounts.push(detached);
    }
    // Keep the IDs in the request part of the checked operation. The kernel
    // validates the user namespace map itself; the explicit non-zero checks
    // above prevent a request from asking for a root/daemon identity.
    let _ = (leased_uid, leased_gid);
    let mut mounts = mounts.into_iter();
    Ok((
        mounts.next().expect("created workspace mount"),
        mounts.next().expect("created runtime mount"),
    ))
}

fn validate_mapped_root(fd: RawFd, expected_uid: u32, expected_gid: u32) -> io::Result<()> {
    let root = unsafe {
        libc::openat(
            fd,
            c".".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::fstat(root, std::ptr::addr_of_mut!(metadata)) };
    unsafe { libc::close(root) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if metadata.st_uid != expected_uid || metadata.st_gid != expected_gid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount ID-map namespace does not translate the source root to the leased IDs",
        ));
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

#[derive(Debug, Clone, Copy)]
struct BrokerRequest {
    request_id: u64,
    daemon_uid: u32,
    daemon_gid: u32,
    leased_uid: u32,
    leased_gid: u32,
    source_count: u32,
}

fn decode_request(bytes: &[u8]) -> io::Result<BrokerRequest> {
    if bytes.len() != REQUEST_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ID-map broker request has the wrong size",
        ));
    }
    if get_u32(bytes, 0) != PROTOCOL_VERSION || get_u32(bytes, 4) != OP_CREATE_IDMAPPED_MOUNTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ID-map broker request has an unsupported operation",
        ));
    }
    if bytes[36..].iter().any(|byte| *byte != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ID-map broker request has non-zero reserved bytes",
        ));
    }
    Ok(BrokerRequest {
        request_id: get_u64(bytes, 8),
        daemon_uid: get_u32(bytes, 16),
        daemon_gid: get_u32(bytes, 20),
        leased_uid: get_u32(bytes, 24),
        leased_gid: get_u32(bytes, 28),
        source_count: get_u32(bytes, 32),
    })
}

fn decode_response(bytes: &[u8]) -> Result<(u32, u64, u32, u32), LaunchError> {
    if bytes.len() != RESPONSE_LEN || get_u32(bytes, 0) != PROTOCOL_VERSION {
        return Err(LaunchError::new(
            "ID-map broker returned an invalid protocol response",
        ));
    }
    if bytes[24..].iter().any(|byte| *byte != 0) {
        return Err(LaunchError::new(
            "ID-map broker returned non-zero reserved bytes",
        ));
    }
    Ok((
        get_u32(bytes, 4),
        get_u64(bytes, 8),
        get_u32(bytes, 16),
        get_u32(bytes, 20),
    ))
}

fn send_response(
    fd: RawFd,
    status: u32,
    request_id: u64,
    mount_count: u32,
    error_code: u32,
    mount_fds: &[RawFd],
) -> io::Result<()> {
    let mut response = [0_u8; RESPONSE_LEN];
    put_u32(&mut response, 0, PROTOCOL_VERSION);
    put_u32(&mut response, 4, status);
    put_u64(&mut response, 8, request_id);
    put_u32(&mut response, 16, mount_count);
    put_u32(&mut response, 20, error_code);
    send_with_fds(fd, &response, mount_fds)
}

fn send_with_fds(fd: RawFd, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let control_len = cmsg_space(size_of_val(fds));
    let mut control = vec![0_u8; control_len];
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = std::ptr::addr_of_mut!(iovec);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    if !fds.is_empty() {
        let header = message.msg_control.cast::<libc::cmsghdr>();
        unsafe {
            (*header).cmsg_len = cmsg_len(size_of_val(fds));
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                cmsg_data(header),
                size_of_val(fds),
            );
        }
    }
    let sent = unsafe { libc::sendmsg(fd, std::ptr::addr_of!(message), libc::MSG_NOSIGNAL) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else if sent as usize != bytes.len() {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short ID-map broker message",
        ))
    } else {
        Ok(())
    }
}

fn receive_message(fd: RawFd, expected_fds: usize) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut bytes = vec![0_u8; RESPONSE_LEN.max(REQUEST_LEN)];
    let mut control = vec![0_u8; cmsg_space(expected_fds * size_of::<RawFd>())];
    let mut iovec = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = std::ptr::addr_of_mut!(iovec);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let received =
        unsafe { libc::recvmsg(fd, std::ptr::addr_of_mut!(message), libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    // Parse and take ownership of every descriptor the kernel placed in the
    // control buffer before inspecting truncation or protocol errors. A
    // malformed burst must not leave SCM_RIGHTS descriptors as unowned raw
    // integers in this process.
    let descriptors = collect_control_fds(&message)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ID-map broker message was truncated",
        ));
    }
    bytes.truncate(received as usize);
    Ok((bytes, descriptors))
}

fn collect_control_fds(message: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let base = message.msg_control.cast::<u8>() as usize;
    let end = base
        .checked_add(message.msg_controllen)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "control buffer overflow"))?;
    let mut descriptors = Vec::new();
    let mut offset = 0;

    while end.saturating_sub(base + offset) >= size_of::<libc::cmsghdr>() {
        let header_address = base + offset;
        // The kernel supplies aligned cmsghdr records. Use unaligned reads
        // nevertheless: `Vec<u8>` does not promise cmsghdr alignment.
        let header = unsafe { std::ptr::read_unaligned(header_address as *const libc::cmsghdr) };
        let length = header.cmsg_len;
        let remaining = end - header_address;
        if length < cmsg_len(0) || length > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ID-map broker control message has an invalid length",
            ));
        }
        let aligned_length = align(length);
        if aligned_length > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ID-map broker control message extends beyond the buffer",
            ));
        }
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let payload_bytes = length - cmsg_header_len();
            if !payload_bytes.is_multiple_of(size_of::<RawFd>()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ID-map broker descriptor payload is not aligned",
                ));
            }
            let data = header_address + cmsg_header_len();
            for index in 0..payload_bytes / size_of::<RawFd>() {
                let raw = unsafe {
                    std::ptr::read_unaligned((data + index * size_of::<RawFd>()) as *const RawFd)
                };
                if raw < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ID-map broker returned a negative descriptor",
                    ));
                }
                // SAFETY: recvmsg installed this non-negative descriptor for
                // this process, and ownership is transferred exactly once.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        offset += aligned_length;
    }
    Ok(descriptors)
}

fn peer_credentials(fd: RawFd) -> io::Result<libc::ucred> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(credentials)
    }
}

fn set_receive_timeout(fd: RawFd) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: CLIENT_RECEIVE_TIMEOUT.as_secs() as _,
        tv_usec: CLIENT_RECEIVE_TIMEOUT.subsec_micros() as _,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, std::ptr::addr_of_mut!(metadata)) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(metadata)
    }
}

fn stat_path(path: &Path) -> io::Result<libc::stat> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ID-map broker path contains an interior NUL",
        )
    })?;
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(path.as_ptr(), std::ptr::addr_of_mut!(metadata)) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(metadata)
    }
}

fn file_identity(metadata: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn openat2_beneath(root: RawFd, relative_path: &Path) -> io::Result<OwnedFd> {
    let relative_path =
        std::ffi::CString::new(relative_path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ID-map broker source path contains an interior NUL",
            )
        })?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    let syscall = shbox_sandbox::syscall_number("openat2").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "ID-map broker requires the openat2 system call",
        )
    })?;
    let fd = unsafe {
        libc::syscall(
            syscall,
            root,
            relative_path.as_ptr(),
            std::ptr::addr_of!(how),
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat2 returned a new descriptor owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn source_path_beneath_root(fd: RawFd, root: &PinnedRoot) -> io::Result<std::path::PathBuf> {
    let link = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;
    let relative = link.strip_prefix(&root.path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ID-map broker source is outside its configured shbox root",
        )
    })?;
    if relative.as_os_str().is_empty() {
        Ok(std::path::PathBuf::from("."))
    } else {
        Ok(relative.to_path_buf())
    }
}

fn validate_source_fd(fd: RawFd, uid: u32, gid: u32, allowed_root: &PinnedRoot) -> io::Result<()> {
    let metadata = stat_fd(fd)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != uid
        || metadata.st_gid != gid
        || metadata.st_mode & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ID-map broker source is not a private daemon-owned directory",
        ));
    }

    // The proc link only supplies a relative name. The pinned root FD and
    // openat2's RESOLVE_BENEATH establish the lookup boundary; the identity
    // comparison ensures the descriptor being mounted is the one looked up.
    let relative = source_path_beneath_root(fd, allowed_root)?;
    let fresh = openat2_beneath(allowed_root.fd.as_raw_fd(), &relative)?;
    if file_identity(&metadata) != file_identity(&stat_fd(fresh.as_raw_fd())?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ID-map broker source descriptor does not match its configured shbox root entry",
        ));
    }
    Ok(())
}

fn is_user_namespace_fd(fd: RawFd) -> bool {
    let is_user_namespace = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .is_some_and(|path| path.starts_with("user:[") && path.ends_with(']'));
    if !is_user_namespace {
        return false;
    }
    let supplied = match stat_fd(fd) {
        Ok(metadata) => file_identity(&metadata),
        Err(_) => return false,
    };
    let initial = match stat_path(Path::new("/proc/self/ns/user")) {
        Ok(metadata) => file_identity(&metadata),
        Err(_) => return false,
    };
    supplied != initial
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    unsafe { libc::getegid() }
}

fn cmsg_header_len() -> usize {
    align(size_of::<libc::cmsghdr>())
}

fn cmsg_len(payload: usize) -> usize {
    cmsg_header_len() + payload
}

fn cmsg_space(payload: usize) -> usize {
    align(size_of::<libc::cmsghdr>()) + align(payload)
}

fn align(value: usize) -> usize {
    let alignment = size_of::<usize>();
    (value + alignment - 1) & !(alignment - 1)
}

unsafe fn cmsg_data(header: *mut libc::cmsghdr) -> *mut u8 {
    unsafe { header.cast::<u8>().add(cmsg_header_len()) }
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed protocol field"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed protocol field"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn fd_count() -> usize {
        fs::read_dir("/proc/self/fd")
            .expect("proc fd directory")
            .count()
    }

    #[test]
    fn request_is_fixed_size_and_round_trips() {
        let request = encode_request(
            42,
            IsolatedIdentity {
                runtime_uid: 1000,
                runtime_gid: 1000,
                host_uid: 165536,
                host_gid: 165537,
            },
        );
        let decoded = decode_request(&request).expect("request");
        assert_eq!(request.len(), REQUEST_LEN);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.daemon_uid, effective_uid());
        assert_eq!(decoded.daemon_gid, effective_gid());
        assert_eq!(decoded.leased_uid, 165536);
        assert_eq!(decoded.leased_gid, 165537);
        assert_eq!(decoded.source_count, 2);
    }

    #[test]
    fn response_rejects_reserved_bytes() {
        let mut response = [0_u8; RESPONSE_LEN];
        put_u32(&mut response, 0, PROTOCOL_VERSION);
        response[24] = 1;
        assert!(decode_response(&response).is_err());
    }

    #[test]
    fn descriptor_messages_round_trip_without_pathnames() {
        let mut sockets = [0_i32; 2];
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sockets.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        let left = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
        let right = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
        let source = std::fs::File::open("/dev/null").expect("source");
        let payload = [7_u8, 8, 9];
        send_with_fds(left.as_raw_fd(), &payload, &[source.as_raw_fd()]).expect("send");
        let (received, fds) = receive_message(right.as_raw_fd(), 1).expect("receive");
        assert_eq!(received, payload);
        assert_eq!(fds.len(), 1);
        assert!(unsafe { libc::fcntl(fds[0].as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[test]
    fn rename_out_and_replace_rejects_the_original_source_fd() {
        let root_parent = tempfile::tempdir().expect("root parent");
        let root_path = root_parent.path().join("data");
        let outside_path = root_parent.path().join("outside");
        fs::create_dir(&root_path).expect("root");
        fs::create_dir(&outside_path).expect("outside");
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).expect("root mode");
        fs::set_permissions(&outside_path, fs::Permissions::from_mode(0o700))
            .expect("outside mode");

        let original_path = root_path.join("workspace");
        fs::create_dir(&original_path).expect("original workspace");
        fs::set_permissions(&original_path, fs::Permissions::from_mode(0o700))
            .expect("original mode");
        let source = fs::File::open(&original_path).expect("source fd");

        fs::rename(&original_path, outside_path.join("workspace")).expect("rename out");
        fs::create_dir(&original_path).expect("replacement workspace");
        fs::set_permissions(&original_path, fs::Permissions::from_mode(0o700))
            .expect("replacement mode");

        let runtime = tempfile::tempdir().expect("runtime root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        let roots =
            BrokerRoots::from_paths(root_path, runtime.path().to_path_buf()).expect("pinned roots");
        assert!(
            validate_source_fd(
                source.as_raw_fd(),
                effective_uid(),
                effective_gid(),
                &roots.data,
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_configured_root_fails_startup_validation() {
        let data = tempfile::tempdir().expect("data root");
        let runtime = tempfile::tempdir().expect("runtime root");
        let file = data.path().join("not-a-directory");
        fs::File::create(&file).expect("root file");
        assert!(BrokerRoots::from_paths(file, runtime.path().to_path_buf()).is_err());

        let writable = data.path().join("writable");
        fs::create_dir(&writable).expect("writable root");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o775)).expect("writable mode");
        assert!(PinnedRoot::open(writable).is_err());
    }

    #[test]
    fn truncated_message_drops_all_received_descriptors() {
        let baseline = fd_count();
        let mut sockets = [0_i32; 2];
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sockets.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        let left = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
        let right = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
        let source = fs::File::open("/dev/null").expect("source");
        let oversized_payload = vec![0_u8; REQUEST_LEN + 1];
        send_with_fds(
            left.as_raw_fd(),
            &oversized_payload,
            &[source.as_raw_fd(), source.as_raw_fd(), source.as_raw_fd()],
        )
        .expect("send malformed message");
        assert!(receive_message(right.as_raw_fd(), SOURCE_FD_COUNT).is_err());
        drop(source);
        drop(left);
        drop(right);
        assert_eq!(fd_count(), baseline, "received descriptors leaked");
    }
}
