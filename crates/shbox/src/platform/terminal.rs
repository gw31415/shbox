//! Unix PTY primitives shared by the host and sandbox process adapters.
//!
//! The process adapters deliberately keep the PTY master in their own
//! lifetime.  This module contains only the small amount of OS glue needed to
//! duplicate that master, apply the SSH-requested terminal state, and expose
//! nonblocking descriptors to Tokio, and a small, audited post-fork child
//! helper that establishes the session and controlling terminal.
//!
//! PTY ownership is shbox's: the launchers allocate the pair, apply the
//! SSH-requested terminal state before spawn, keep only the master plus the
//! lifecycle duplicates, and close every parent-held slave descriptor after
//! the child is running.

use russh::Pty;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const DEFAULT_ROWS: u32 = 24;
const DEFAULT_COLS: u32 = 80;

/// Duplicate a descriptor with close-on-exec set atomically.
pub(crate) fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl is called with a valid borrowed descriptor.  A successful
    // F_DUPFD_CLOEXEC result is a new descriptor owned by this function.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

/// Apply the RFC 4254 requested window dimensions to a PTY master.
///
/// A zero dimension is left untouched. If the other dimension needs to be
/// applied and the current size cannot be queried, the operation fails rather
/// than silently replacing the unspecified dimension. A queried zero
/// dimension uses the same 24x80 fallback as PTY allocation.
pub(crate) fn apply_window_size(fd: RawFd, rows: u32, cols: u32) -> io::Result<()> {
    if rows == 0 && cols == 0 {
        return Ok(());
    }

    let mut size = libc::winsize {
        ws_row: DEFAULT_ROWS as libc::c_ushort,
        ws_col: DEFAULT_COLS as libc::c_ushort,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if rows == 0 || cols == 0 {
        // SAFETY: `size` is a valid writable winsize and fd is an owned PTY
        // descriptor held by the caller.
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if size.ws_row == 0 {
            size.ws_row = DEFAULT_ROWS as libc::c_ushort;
        }
        if size.ws_col == 0 {
            size.ws_col = DEFAULT_COLS as libc::c_ushort;
        }
    }
    if rows != 0 {
        size.ws_row = clamp_dimension(rows);
    }
    if cols != 0 {
        size.ws_col = clamp_dimension(cols);
    }

    // SAFETY: `size` points to a fully initialized winsize for this PTY.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn clamp_dimension(value: u32) -> libc::c_ushort {
    value.clamp(1, u16::MAX as u32) as libc::c_ushort
}

/// Apply the supported RFC 4254 terminal modes to a PTY's termios state.
///
/// Unsupported modes are intentionally ignored.  Boolean values use the SSH
/// convention 0 = off and non-zero = on.  An empty mode vector avoids a
/// needless ioctl, which keeps PTY requests that rely on the platform default
/// harmless.
pub(crate) fn apply_terminal_modes(fd: RawFd, modes: &[(Pty, u32)]) -> io::Result<()> {
    if modes.is_empty() {
        return Ok(());
    }

    let mut state = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: `state` is valid storage for the terminal attributes.
    if unsafe { libc::tcgetattr(fd, &mut state) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let disabled = control_disable_value(fd);
    for &(mode, value) in modes {
        match mode {
            Pty::VINTR => set_control(&mut state, libc::VINTR, value, disabled),
            Pty::VQUIT => set_control(&mut state, libc::VQUIT, value, disabled),
            Pty::VERASE => set_control(&mut state, libc::VERASE, value, disabled),
            Pty::VKILL => set_control(&mut state, libc::VKILL, value, disabled),
            Pty::VEOF => set_control(&mut state, libc::VEOF, value, disabled),
            Pty::VEOL => set_control(&mut state, libc::VEOL, value, disabled),
            Pty::VEOL2 => set_control(&mut state, libc::VEOL2, value, disabled),
            Pty::VSTART => set_control(&mut state, libc::VSTART, value, disabled),
            Pty::VSTOP => set_control(&mut state, libc::VSTOP, value, disabled),
            Pty::VSUSP => set_control(&mut state, libc::VSUSP, value, disabled),

            Pty::IGNPAR => set_flag(&mut state.c_iflag, libc::IGNPAR, value),
            Pty::PARMRK => set_flag(&mut state.c_iflag, libc::PARMRK, value),
            Pty::INPCK => set_flag(&mut state.c_iflag, libc::INPCK, value),
            Pty::ISTRIP => set_flag(&mut state.c_iflag, libc::ISTRIP, value),
            Pty::INLCR => set_flag(&mut state.c_iflag, libc::INLCR, value),
            Pty::IGNCR => set_flag(&mut state.c_iflag, libc::IGNCR, value),
            Pty::ICRNL => set_flag(&mut state.c_iflag, libc::ICRNL, value),
            Pty::IXON => set_flag(&mut state.c_iflag, libc::IXON, value),
            Pty::IXANY => set_flag(&mut state.c_iflag, libc::IXANY, value),
            Pty::IXOFF => set_flag(&mut state.c_iflag, libc::IXOFF, value),

            Pty::ISIG => set_flag(&mut state.c_lflag, libc::ISIG, value),
            Pty::ICANON => set_flag(&mut state.c_lflag, libc::ICANON, value),
            Pty::ECHO => set_flag(&mut state.c_lflag, libc::ECHO, value),
            Pty::ECHOE => set_flag(&mut state.c_lflag, libc::ECHOE, value),
            Pty::ECHOK => set_flag(&mut state.c_lflag, libc::ECHOK, value),
            Pty::ECHONL => set_flag(&mut state.c_lflag, libc::ECHONL, value),
            Pty::NOFLSH => set_flag(&mut state.c_lflag, libc::NOFLSH, value),
            Pty::TOSTOP => set_flag(&mut state.c_lflag, libc::TOSTOP, value),
            Pty::IEXTEN => set_flag(&mut state.c_lflag, libc::IEXTEN, value),

            Pty::OPOST => set_flag(&mut state.c_oflag, libc::OPOST, value),
            Pty::ONLCR => set_flag(&mut state.c_oflag, libc::ONLCR, value),
            Pty::OCRNL => set_flag(&mut state.c_oflag, libc::OCRNL, value),
            Pty::ONOCR => set_flag(&mut state.c_oflag, libc::ONOCR, value),
            Pty::ONLRET => set_flag(&mut state.c_oflag, libc::ONLRET, value),

            Pty::CS7 => set_character_size(&mut state, libc::CS7),
            Pty::CS8 => set_character_size(&mut state, libc::CS8),
            Pty::PARENB => set_flag(&mut state.c_cflag, libc::PARENB, value),
            Pty::PARODD => set_flag(&mut state.c_cflag, libc::PARODD, value),

            Pty::TTY_OP_ISPEED => set_speed(&mut state, value, true)?,
            Pty::TTY_OP_OSPEED => set_speed(&mut state, value, false)?,

            // IUCLC, IMAXBEL, IUTF8, XCASE, ECHOCTL, ECHOKE, PENDIN,
            // OLCUC, extended control characters, and reserved opcodes are
            // platform-specific or outside shbox's minimum mode set.
            _ => {}
        }
    }

    // SAFETY: `state` was read from this terminal and remains initialized.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &state) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_flag(bits: &mut libc::tcflag_t, flag: libc::tcflag_t, value: u32) {
    if value == 0 {
        *bits &= !flag;
    } else {
        *bits |= flag;
    }
}

fn control_disable_value(fd: RawFd) -> libc::cc_t {
    // POSIX exposes the terminal-specific disabled control value through
    // fpathconf. Linux commonly reports NUL while Darwin commonly reports
    // 0xff; RFC 4254's wire value 255 must be translated accordingly.
    // SAFETY: fpathconf reads a property of the caller-owned terminal fd.
    let value = unsafe { libc::fpathconf(fd, libc::_PC_VDISABLE) };
    if value >= 0 && value <= u8::MAX as libc::c_long {
        value as libc::cc_t
    } else {
        u8::MAX as libc::cc_t
    }
}

fn set_control(state: &mut libc::termios, index: usize, value: u32, disabled: libc::cc_t) {
    if index < libc::NCCS && value <= u8::MAX as u32 {
        state.c_cc[index] = if value == u8::MAX as u32 {
            disabled
        } else {
            value as libc::cc_t
        };
    }
}

fn set_character_size(state: &mut libc::termios, size: libc::tcflag_t) {
    state.c_cflag = (state.c_cflag & !libc::CSIZE) | size;
}

fn set_speed(state: &mut libc::termios, value: u32, input: bool) -> io::Result<()> {
    let Some(speed) = baud_rate(value) else {
        return Ok(());
    };
    let result = if input {
        // SAFETY: state is initialized and speed is a libc baud constant.
        unsafe { libc::cfsetispeed(state, speed) }
    } else {
        // SAFETY: state is initialized and speed is a libc baud constant.
        unsafe { libc::cfsetospeed(state, speed) }
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn baud_rate(value: u32) -> Option<libc::speed_t> {
    Some(match value {
        0 => libc::B0,
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        _ => return None,
    })
}

/// An AsyncRead/AsyncWrite wrapper for a nonblocking PTY master duplicate.
pub(crate) struct PtyIo {
    fd: AsyncFd<File>,
}

impl PtyIo {
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        let file: File = fd.into();
        set_nonblocking(file.as_raw_fd())?;
        let fd = AsyncFd::new(file)?;
        Ok(Self { fd })
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on the owned descriptor and preserves all other
    // status flags while adding O_NONBLOCK.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AsyncRead for PtyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(guard)) => guard,
            };
            match guard.try_io(|inner| {
                let target = buffer.initialize_unfilled();
                // SAFETY: target is the initialized writable tail of the
                // caller's ReadBuf and the descriptor is owned by AsyncFd.
                let count = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Err(_) => continue,
                Ok(Ok(0)) => return Poll::Ready(Ok(())),
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => {
                    // Linux reports PTY-master EOF as EIO after the slave is
                    // closed. Treat it as an ordinary end of stream.
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EINTR) => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl AsyncWrite for PtyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(guard)) => guard,
            };
            match guard.try_io(|inner| {
                // SAFETY: data is a valid immutable slice for the duration of
                // this syscall and the descriptor is owned by AsyncFd.
                let count = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        data.as_ptr().cast(),
                        data.len(),
                    )
                };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Err(_) => continue,
                Ok(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "PTY master write returned zero",
                    )));
                }
                Ok(Ok(count)) => return Poll::Ready(Ok(count)),
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EINTR) => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the boxed writer closes only this duplicate.  A PTY does
        // not have a meaningful half-close operation that should be emulated
        // with VEOF or a synthetic byte.
        Poll::Ready(Ok(()))
    }
}

/// A shbox-owned PTY pair.
///
/// `master` is the daemon-side endpoint that lives for the whole session.
/// `slave` is the parent's reference to the terminal device. Both parent-held
/// descriptors are close-on-exec; the child receives only explicit duplicates
/// prepared for its stdio and controlling-terminal setup.
// Consumed by the Linux/macOS launchers (Milestones 3-4); removed there.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PtyPair {
    master: OwnedFd,
    slave: OwnedFd,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PtyPair {
    /// Allocate a PTY and fully prepare the terminal state before spawning.
    pub(crate) fn open(modes: &[(Pty, u32)], rows: u32, cols: u32) -> io::Result<PtyPair> {
        let pair = nix::pty::openpty(None, None).map_err(|_| io::Error::last_os_error())?;
        let master: OwnedFd = pair.master;
        let slave: OwnedFd = pair.slave;

        // Neither parent-held endpoint may leak across exec. In particular,
        // an inherited master would keep the PTY alive after the daemon drops
        // its copy, suppressing the EOF/SIGHUP semantics expected by the
        // session child.
        set_cloexec(master.as_raw_fd())?;
        set_cloexec(slave.as_raw_fd())?;

        // The requested session state exists before user code can observe
        // the terminal. Zero dimensions keep the allocation default.
        apply_terminal_modes(master.as_raw_fd(), modes)?;
        apply_window_size(master.as_raw_fd(), rows, cols)?;
        Ok(PtyPair { master, slave })
    }

    pub(crate) fn master(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// Reserve the explicit close-on-exec child setup descriptor.
    ///
    /// The child setup path must not rely on undocumented stdio setup
    /// ordering, so it is handed a dedicated duplicate with a stable number
    /// instead of guessing which descriptor became fd 0.
    pub(crate) fn reserve_setup_fd(&self) -> io::Result<OwnedFd> {
        // SAFETY: fcntl duplicates the owned, open slave descriptor with
        // close-on-exec applied atomically.
        let duplicate = unsafe { libc::fcntl(self.slave.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    /// The parent's slave reference for tests: kernel-side probes and stdio
    /// duplicates for probe children. Production launchers only ever use the
    /// reserved setup duplicate.
    #[cfg(test)]
    pub(crate) fn slave_for_tests(&self) -> RawFd {
        self.slave.as_raw_fd()
    }

    /// Consume the pair into the daemon-owned master descriptor. Dropping
    /// the pair closes the parent's slave reference, which is the documented
    /// post-spawn step: every child inherits the terminal only through the
    /// reserved setup descriptor and its own stdio duplicates.
    pub(crate) fn into_master(self) -> OwnedFd {
        self.master
    }
}

impl std::fmt::Debug for PtyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyPair")
            .field("master", &self.master.as_raw_fd())
            .finish_non_exhaustive()
    }
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl reads flags of an owned, valid descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl updates only the close-on-exec bit.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fixed-size stage tag for a child setup failure, reported through the
/// launch status pipe without any formatting or allocation.
// Consumed by the Linux/macOS launchers (Milestones 3-4); removed there.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildSetupStage {
    Session,
    ControllingTerminal,
}

// Consumed by the Linux/macOS launchers (Milestones 3-4); removed there.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChildSetupError {
    pub(crate) stage: ChildSetupStage,
    pub(crate) errno: i32,
}

/// Establish the child's Unix session and (optionally) its controlling
/// terminal. Post-fork safe by construction.
///
/// Audit of every operation performed here:
/// - `dup2(setup_fd, 0/1/2)`: fixed-data raw syscall, no allocation.
/// - `close(setup_fd)`: raw syscall.
/// - `setsid()`: raw syscall; makes the child session leader and process
///   group leader. No `setpgid()` follows — `setsid()` already made it the
///   group leader of its new group.
/// - `ioctl(fd, TIOCSCTTY, 0)`: raw syscall. As the first session leader to
///   acquire an unowned terminal, the kernel makes the caller's new process
///   group the terminal's foreground group; `tcsetpgrp()` would be
///   redundant, so it is deliberately not called.
///
/// Errors are returned as a fixed-size stage/errno pair; nothing here
/// formats strings, locks, logs, allocates, or touches Tokio.
///
/// # Safety
/// Must run in the post-fork child before `exec`, with `setup_fd` referring
// Consumed by the Linux/macOS launchers (Milestones 3-4); removed there.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) unsafe fn child_session_setup(
    setup_fd: RawFd,
    acquire_controlling_terminal: bool,
) -> Result<(), ChildSetupError> {
    // SAFETY: the closure of each syscall is documented in the function
    // contract; every call uses fixed data and the caller-owned descriptor.
    unsafe {
        for target in [0, 1, 2] {
            if libc::dup2(setup_fd, target) == -1 {
                return Err(child_setup_error(ChildSetupStage::Session));
            }
        }
        if libc::close(setup_fd) == -1 && errno() != libc::EBADF {
            return Err(child_setup_error(ChildSetupStage::Session));
        }
        if libc::setsid() == -1 {
            return Err(child_setup_error(ChildSetupStage::Session));
        }
        if acquire_controlling_terminal
            && libc::ioctl(
                0,
                libc::TIOCSCTTY as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
            ) == -1
        {
            return Err(child_setup_error(ChildSetupStage::ControllingTerminal));
        }
    }
    Ok(())
}
// Consumed by the Linux/macOS launchers (Milestones 3-4); removed there.
#[cfg_attr(not(test), allow(dead_code))]
fn child_setup_error(stage: ChildSetupStage) -> ChildSetupError {
    ChildSetupError {
        stage,
        errno: errno(),
    }
}

// Consumed by the Linux/macOS launchers (Milestones 3-4); removed there.
#[cfg_attr(not(test), allow(dead_code))]
fn errno() -> i32 {
    // SAFETY: both libc entry points return the calling thread's errno slot.
    // Reading the integer is allocation-free and safe in the post-fork child.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn window_size_preserves_zero_dimensions() {
        let pair = nix::pty::openpty(None, None).expect("openpty");
        let master = pair.master.as_raw_fd();
        apply_window_size(master, 33, 0).expect("resize");
        let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
        assert_eq!(
            unsafe { libc::ioctl(master, libc::TIOCGWINSZ, &mut size) },
            0
        );
        assert_eq!(size.ws_row, 33);
        assert!(size.ws_col > 0);
    }

    #[test]
    fn terminal_modes_turn_off_raw_mode_flags_and_set_control_bytes() {
        let pair = nix::pty::openpty(None, None).expect("openpty");
        let master = pair.master.as_raw_fd();
        let slave = pair.slave.as_raw_fd();
        apply_terminal_modes(
            master,
            &[
                (Pty::ISIG, 0),
                (Pty::ICANON, 0),
                (Pty::ECHO, 0),
                (Pty::ONLCR, 0),
                (Pty::VINTR, 3),
            ],
        )
        .expect("termios");
        let mut state = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut state) }, 0);
        assert_eq!(state.c_lflag & libc::ISIG, 0);
        assert_eq!(state.c_lflag & libc::ICANON, 0);
        assert_eq!(state.c_lflag & libc::ECHO, 0);
        assert_eq!(state.c_oflag & libc::ONLCR, 0);
        assert_eq!(state.c_cc[libc::VINTR], 3);
    }

    #[test]
    fn terminal_mode_255_uses_the_platform_disable_value() {
        let pair = nix::pty::openpty(None, None).expect("openpty");
        let master = pair.master.as_raw_fd();
        let slave = pair.slave.as_raw_fd();
        apply_terminal_modes(master, &[(Pty::VINTR, u8::MAX as u32)]).expect("termios");
        let expected = unsafe { libc::fpathconf(slave, libc::_PC_VDISABLE) };
        assert!(expected >= 0);
        let mut state = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut state) }, 0);
        assert_eq!(state.c_cc[libc::VINTR] as libc::c_long, expected);
    }

    /// The shell used by probe children. Every probe execs a real program
    /// after the audited setup: `Command::spawn` waits for the exec, so a
    /// blocking pre-exec closure would deadlock the parent.
    const PROBE_SHELL: &str = "/bin/sh";

    /// Poll a predicate for up to five seconds.
    fn wait_until(mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        predicate()
    }

    /// Wait for a child with a deadline; kills it on timeout and returns
    /// `None` so the assertion names the hang, not the test harness.
    fn wait_with_timeout(
        child: &mut std::process::Child,
        secs: u64,
    ) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            if let Some(status) = child.try_wait().expect("probe try_wait") {
                return Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Fork a real child through the same pre-exec seam the launchers use:
    /// the audited session setup runs in the child, then the probe shell
    /// execs with the PTY slave as fd 0/1/2.
    fn spawn_setup_child(
        pair: &PtyPair,
        acquire_controlling_terminal: bool,
        script: &str,
    ) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let setup = pair.reserve_setup_fd().expect("reserve setup fd");
        let setup_fd = setup.as_raw_fd();
        let stdin = duplicate_fd(pair.slave_for_tests()).expect("slave stdin dup");
        let stdout = duplicate_fd(pair.slave_for_tests()).expect("slave stdout dup");
        let stderr = duplicate_fd(pair.slave_for_tests()).expect("slave stderr dup");

        let mut command = Command::new(PROBE_SHELL);
        command.arg("-c").arg(script);
        command.stdin(Stdio::from(stdin));
        command.stdout(Stdio::from(stdout));
        command.stderr(Stdio::from(stderr));
        // SAFETY: the closure runs in the post-fork child before the exec
        // and only calls the audited, non-blocking session setup helper.
        unsafe {
            command.pre_exec(move || {
                child_session_setup(setup_fd, acquire_controlling_terminal)
                    .map_err(|error| std::io::Error::from_raw_os_error(error.errno))
            });
        }
        command.spawn().expect("spawn probe child")
    }

    #[test]
    fn pty_child_becomes_session_leader_with_controlling_terminal() {
        let pair =
            PtyPair::open(&[(Pty::ECHO, 0), (Pty::ICANON, 0)], 40, 100).expect("owned pty open");
        let mut child = spawn_setup_child(&pair, true, "sleep 30");
        let pid = child.id() as libc::pid_t;

        // The exec'd shell is the session leader of a fresh session.
        assert!(
            wait_until(|| unsafe { libc::getsid(pid) } == pid),
            "child must be a session leader"
        );

        // The PTY is the controlling terminal of that session, and the
        // child's new group is the terminal's foreground group. TIOCSCTTY
        // sets the foreground group as the first session leader to acquire
        // an unowned terminal; tcsetpgrp is deliberately never called.
        //
        // POSIX only specifies tcgetsid()/tcgetpgrp() when `fd` names the
        // caller's controlling terminal. Darwin permits this cross-session
        // observation, while Linux returns ENOTTY to the parent even though
        // the child's TIOCSCTTY succeeded. On Linux, /proc/<pid>/stat exposes
        // the child's session, controlling-tty device, and foreground pgrp
        // without changing either process.
        #[cfg(target_os = "linux")]
        assert!(wait_until(|| {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                return false;
            };
            let fields: Vec<&str> = fields.split_whitespace().collect();
            let session = fields
                .get(3)
                .and_then(|value| value.parse::<libc::pid_t>().ok());
            let tty_nr = fields.get(4).and_then(|value| value.parse::<i64>().ok());
            let foreground = fields
                .get(5)
                .and_then(|value| value.parse::<libc::pid_t>().ok());
            session == Some(pid) && tty_nr.is_some_and(|tty| tty != 0) && foreground == Some(pid)
        }));
        #[cfg(not(target_os = "linux"))]
        {
            let slave = pair.slave_for_tests();
            assert!(wait_until(|| unsafe { libc::tcgetsid(slave) } == pid as i32));
            assert!(wait_until(
                || unsafe { libc::tcgetpgrp(pair.master()) } == pid
            ));
        }

        // Window size and terminal modes were applied before the spawn.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::ioctl(pair.master(), libc::TIOCGWINSZ, &mut size) },
            0
        );
        assert_eq!((size.ws_row, size.ws_col), (40, 100));
        let mut state: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(pair.slave_for_tests(), &mut state) },
            0
        );
        assert_eq!(state.c_lflag & libc::ECHO, 0);
        assert_eq!(state.c_lflag & libc::ICANON, 0);

        child.kill().expect("kill probe child");
        child.wait().expect("reap probe child");
    }

    #[test]
    fn pty_child_without_ctty_acquisition_has_no_controlling_terminal() {
        let pair = PtyPair::open(&[], 24, 80).expect("owned pty open");
        let mut child = spawn_setup_child(&pair, false, "sleep 30");
        let pid = child.id() as libc::pid_t;

        assert!(wait_until(|| unsafe { libc::getsid(pid) } == pid));
        // The session exists, but the terminal is not attached to that
        // session. Darwin reports an unattached terminal as 0 while Linux may
        // report -1/ENOTTY, so assert the semantic invariant rather than a
        // platform-specific sentinel value.
        assert_ne!(unsafe { libc::tcgetsid(pair.slave_for_tests()) }, pid);
        assert_ne!(unsafe { libc::tcgetpgrp(pair.master()) }, pid);

        child.kill().expect("kill probe child");
        child.wait().expect("reap probe child");
    }

    #[test]
    fn pty_child_observes_terminal_devices_and_requested_state() {
        let pair =
            PtyPair::open(&[(Pty::ECHO, 0), (Pty::ICANON, 0)], 40, 100).expect("owned pty open");
        let script = concat!(
            "[ -t 0 ] || exit 11\n",
            "[ -t 1 ] || exit 12\n",
            "[ -t 2 ] || exit 13\n",
            "echo TTY_OK\n",
            "stty size\n",
            "stty -a\n",
        );
        let mut child = spawn_setup_child(&pair, true, script);

        // Production consumes the pair immediately after spawn: the parent
        // retains only the master and closes its slave copy. Mirror that
        // ownership transition here; keeping the parent slave open prevents
        // Linux PTY masters from ever reporting EOF/EIO after child exit.
        let master = pair.into_master();
        let reader = std::thread::spawn(move || {
            let mut output = Vec::new();
            let mut chunk = [0u8; 256];
            // SAFETY: the loop owns the duplicated master descriptor.
            let master = master;
            loop {
                // SAFETY: read into the fixed stack buffer of the owned fd.
                let count = unsafe {
                    libc::read(master.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len())
                };
                if count <= 0 {
                    break;
                }
                output.extend_from_slice(&chunk[..count as usize]);
            }
            output
        });

        let status = wait_with_timeout(&mut child, 15).expect("probe shell did not exit");
        assert!(status.success(), "isatty checks failed: {status:?}");
        let output = reader.join().expect("reader thread");
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("TTY_OK"), "child output: {text:?}");
        assert!(text.contains("40 100"), "stty size missing: {text:?}");
        assert!(text.contains("-icanon"), "icanon not cleared: {text:?}");
        assert!(text.contains("-echo"), "echo not cleared: {text:?}");
    }

    #[test]
    fn closing_the_master_terminates_slave_reads() {
        let pair = PtyPair::open(&[], 24, 80).expect("owned pty open");
        let script = "read -r line\necho AFTER_READ:$?\n";
        let mut child = spawn_setup_child(&pair, true, script);
        use std::os::unix::process::ExitStatusExt;

        // Production launchers consume the pair after spawn so the parent
        // closes its slave immediately and retains only the daemon-side
        // master. Let the shell park in read(2), then close that master.
        let master = pair.into_master();
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(master);

        // The blocked slave read must end (EOF on macOS, EIO on Linux, or a
        // SIGHUP delivery). Ten seconds of silence means the read hung.
        let status =
            wait_with_timeout(&mut child, 10).expect("slave read must end when the master closes");
        assert!(
            status.code().is_some() || status.signal() == Some(libc::SIGHUP),
            "unexpected exit status: {status:?}"
        );
    }
}
