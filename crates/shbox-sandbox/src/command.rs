//! The spawn request: what to run and how the process is structured.

use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::PathBuf;

/// How the sandbox child's standard streams are connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Stdio {
    /// Connect the stream to `/dev/null`.
    #[default]
    Null,
    /// Create a pipe; the parent holds the other end on
    /// [`crate::SandboxChild`].
    Pipe,
    /// `dup2` an existing parent file descriptor into the child's stream
    /// slot. The descriptor is not consumed by the spawn; the caller keeps
    /// owning its end (for a PTY, the caller keeps the master).
    Fd(RawFd),
}

/// Session structure for the sandboxed process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionSetup {
    /// Stay in the daemon's session and process group.
    #[default]
    Inherit,
    /// `setsid()`: the child becomes a session and process-group leader.
    NewSession,
    /// `setsid()` plus `TIOCSCTTY` on stdin's terminal: the controlling
    /// terminal for interactive/PTY use.
    NewSessionWithControllingTerminal,
}

/// The program, arguments, environment, and process structure for one
/// sandbox spawn.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandSpec {
    /// Program path to `exec`. Interpreted after the filesystem policy is
    /// enforced; the execute policy must cover it.
    pub program: PathBuf,
    /// `argv[1..]`.
    pub args: Vec<OsString>,
    /// Overrides `argv[0]` (e.g. a leading-dash login-shell name). Defaults
    /// to the program path.
    pub argv0: Option<OsString>,
    /// The exact environment: nothing is inherited implicitly.
    pub env: Vec<(OsString, OsString)>,
    /// Working directory; `None` keeps the daemon's. Resolved before
    /// confinement, so it must be reachable under the filesystem policy.
    pub cwd: Option<PathBuf>,
    /// Standard-input connection for the child.
    pub stdin: Stdio,
    /// Standard-output connection for the child.
    pub stdout: Stdio,
    /// Standard-error connection for the child.
    pub stderr: Stdio,
    /// Session structure for the child process.
    pub session: SessionSetup,
}

impl CommandSpec {
    /// A spec running `program` with no arguments, an empty environment, and
    /// null standard streams.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        CommandSpec {
            program: program.into(),
            ..CommandSpec::default()
        }
    }

    /// Append one argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Replace the environment.
    pub fn env<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.env = env.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set all three standard streams at once.
    pub fn stdio(mut self, stdio: Stdio) -> Self {
        self.stdin = stdio;
        self.stdout = stdio;
        self.stderr = stdio;
        self
    }
}
