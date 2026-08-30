//! Unix PTY primitives shared by the host and sandbox process adapters.
//!
//! The process adapters deliberately keep the PTY master in their own
//! lifetime.  This module contains only the small amount of OS glue needed to
//! duplicate that master, apply the SSH-requested terminal state, and expose
//! nonblocking descriptors to Tokio.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use russh::Pty;
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
}
