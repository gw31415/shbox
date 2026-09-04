# shbox-sandbox

Process sandbox primitives for Linux and macOS, extracted from shbox as a
standalone workspace crate.

- **Pure Rust, single binary.** No helper executables, no shell scripts. On
  Linux the only dependencies are `libc`, `landlock` (0.4), and `seccompiler`
  (0.5); cgroup v2 is a thin dirfd-based wrapper inside this crate. On macOS
  the confinement launcher is the OS-provided `/usr/bin/sandbox-exec`.
- **No security profiles.** The crate ships no `Developer`/`Untrusted`/
  `Strict` presets. Filesystem, network, resource, syscall, namespace, and
  capability policy are all explicit per-spawn caller state
  ([`SandboxConfig`]); composing admin/user/session configuration into that
  struct is the embedding application's job.
- **Non-negotiable safety invariants.** `PR_SET_NO_NEW_PRIVS`, capability
  dropping (effective/permitted/inheritable/ambient/bounding), file-descriptor
  hygiene (`close_range`), fail-closed setup, and pidfd-based supervision on
  Linux apply regardless of policy.

## Linux backend (production isolation target)

```
parent:  cgroup create + limits      Landlock ruleset build    seccomp compile
                 │                          │                       │
         ┌───────┴──────────────────────────┴───────────────────────┘
         │
         long-lived spawn-owner thread
         │
         clone3(CLONE_PIDFD | namespaces… [| CLONE_INTO_CGROUP])
         │
child:   PDEATHSIG → userns mapping barrier → mount-rprivate
                  → recursive read-only → detached mount attach → [PID namespace split]
         │
         ├─ no PID namespace: stdio/session/ctty → chdir → hardening → execve
         │
         └─ PID namespace: PID1 supervisor/reaper
                            └─ clone3([CLONE_INTO_CGROUP]) → PID2 user process
                               → stdio/session/ctty → chdir → hardening → execve
```

Every fallible, allocating policy-construction step happens in the parent;
the post-clone paths run fixed allocation-free setup chains. Linux clone calls
are issued by a process-lifetime spawn-owner thread so `PR_SET_PDEATHSIG` is
not tied to a short-lived caller/Tokio worker. There is no fork-then-move-to-
cgroup path: with resource limits configured the user process is born inside
its cgroup (kernel 5.7+ for `CLONE_INTO_CGROUP`; with a PID namespace PID1
stays outside the user quota and creates PID2 into the cgroup). Direct
`Sandbox::spawn` owns a
one-shot cgroup for that launch; callers that need an aggregate durable quota
can create a `ResourceDomain` and place every launch for that sandbox into
the same cgroup. Failures at any stage abort the child before `exec` and are
reported as `SandboxError::Setup` with the named stage.

Supported policy surface: separate Landlock filesystem tiers for read-only,
read-write, and read+execute access, Landlock TCP network restriction,
cgroup v2 `memory.max`/`memory.swap.max`/`pids.max`/
`cpu.max`, seccomp allow/deny filters with argument conditions, per-
namespace selection (user namespaces map the caller to root inside, the
`unshare --map-root-user` model), capability retention, and explicit
inherited file descriptors (which survive exec with their exact numbers).
`IdentityPolicy::Isolated` requires a parent-side `UidGidMapper`; the shbox
adapter supplies shadow-utils mapping and broker-prepared `PreparedMounts`.
Missing mapping or mount prerequisites fail closed.

## macOS backend (best-effort local development isolation)

The same API backed by a parent-generated Seatbelt profile enforced through
the OS-provided `/usr/bin/sandbox-exec` launcher. Seatbelt's in-process API
is deprecated without a stable replacement; the crate deliberately uses the
OS component instead of guessing at private symbol signatures. Linux-only
policy fields (namespaces, seccomp filters, retained capabilities, cpu
quotas, swap limits) are rejected explicitly — never silently ignored.
`memory_bytes` maps to `RLIMIT_AS` and `pids` to `RLIMIT_NPROC`.

## Security boundary

This is a kernel-sharing process sandbox: a strong constraint for untrusted
development workloads, but **not** a VM-equivalent boundary against actively
hostile multi-tenant workloads attempting kernel exploits. For that threat
model, run this sandbox inside a VM/microVM as additional defense-in-depth.

## Usage

```rust
use shbox_sandbox::{CommandSpec, FilesystemPolicy, Limit, NetworkPolicy,
    PathRule, ResourceLimits, Sandbox, SandboxConfig, Stdio};

let sandbox = Sandbox::detect();
let mut command = CommandSpec::new("/bin/sh");
command = command.arg("-c").arg("nproc").cwd(&workspace)
    .env([("PATH", "/usr/bin:/bin")]);
command.stdout = Stdio::Pipe;

let config = SandboxConfig {
    filesystem: FilesystemPolicy::Restricted {
        read_only: vec![PathRule::new("/usr"), PathRule::new("/bin")],
        read_write: vec![PathRule::new(&workspace)],
        execute: Vec::new(),
    },
    network: NetworkPolicy::Disabled,
    resources: ResourceLimits {
        memory_bytes: Limit::Value(512 * 1024 * 1024),
        pids: Limit::Value(64),
        ..ResourceLimits::default()
    },
    ..SandboxConfig::unrestricted()
};

let mut child = sandbox.spawn(command, config)?;
let status = child.wait()?;
```

Platform details and kernel requirements: [../../docs/platforms.md](../../docs/platforms.md).
