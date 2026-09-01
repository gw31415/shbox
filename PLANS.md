# Replace Arapuca with shbox-owned PTY/process control and nono confinement

## Status

This is the active implementation plan for `gw31415/shbox`.

Baseline at the time this plan was rewritten:

- branch: `main`
- previously inspected commit: `2dd5c8eb0ed5cddcc186e293d6704b79dec95a7e`
- Rust edition: 2024
- new minimum Rust version: **1.95**
- production targets to preserve:
  - Linux `x86_64`
  - Linux `aarch64`
  - macOS `arm64`
- current backend to remove: Arapuca pinned at revision `c94802c4d8b6b880334c0d643b16b7326ec7f039`
- replacement Linux confinement crate: **`nono = "=0.74.0"`**
- replacement macOS confinement mechanism: shbox-generated Seatbelt profile executed through `/usr/bin/sandbox-exec`

The architecture decision is final for this migration:

- **PTY and process lifecycle always belong to shbox.**
- **nono is a confinement primitive, not a process launcher.**
- Linux uses nono's prepared Landlock/seccomp primitives so the multithreaded Tokio/russh daemon never performs allocating sandbox setup after `fork()`.
- Linux does not use a sibling runner, self-exec mode, sandbox CLI, container runtime, or delegated control group.
- macOS prepares its Seatbelt policy before spawning, then uses `/usr/bin/sandbox-exec` as the target wrapper after shbox performs PTY/session setup.
- resource limiting is **out of scope**. Do not preserve Arapuca-specific CPU, memory, file-size, open-file, PID/process-count, or cgroup limit behavior merely for compatibility.
- PTY correctness is a **blocking release requirement**, not a best-effort feature.

Before implementation, run:

```sh
git status --short
git branch --show-current
git rev-parse HEAD
```

If HEAD moved since this plan was written, do not reset newer work. Re-read every touched file, preserve the behavioral requirements below, and adapt the edits to the current tree.

This file is an executable specification. Do not substitute a different sandbox library, add runtime backend selection, reintroduce self-exec, weaken a failing sandbox into an unsandboxed launch, or replace the PTY design with a pipe-only abstraction.

---

## User-visible outcome

After completion:

1. `shbox` no longer builds or runs Arapuca.
2. Linux sandboxing uses `nono 0.74.0` as a library.
3. Linux launch does not depend on cgroup v1/v2, controller delegation, `Delegate=`, writable `/sys/fs/cgroup`, Docker, namespaces, root, or a separately installed `nono` executable.
4. macOS remains supported on the existing native Apple Silicon release gates.
5. `shbox` owns `openpty()`, terminal modes, window size, session creation, controlling-terminal acquisition, foreground process-group semantics, signal forwarding, waiting, and cleanup on both platforms.
6. An SSH `pty-req` produces a real controlling terminal with normal interactive shell/job-control behavior.
7. An SSH exec request without `pty-req` remains a normal pipe-based non-PTY execution path.
8. Workspace persistence semantics remain unchanged: the sandbox workspace itself is persistent and directly writable where policy permits.
9. Network-disabled and outbound-network policy remain explicit and tested.
10. The Linux production service can run in Fly.io without delegated cgroup controllers.
11. Resource limits are not part of shbox's sandbox contract after this migration.
12. There is no hidden fallback to unconfined execution.

---

## Non-goals

Do **not** add any of the following while implementing this plan:

- a config option selecting `arapuca`, `nono`, `landlock`, `seatbelt`, or another backend;
- a `nono` CLI subprocess on Linux;
- a `shbox-sandbox-runner` or other sibling helper binary on Linux;
- shbox self-exec or environment-triggered wrapper mode;
- Linux resource cgroups;
- CPU quotas, memory ceilings, process-count limits, file-size limits, or an internal resource-limit compatibility layer;
- Docker/Podman/containerd-based sandboxing;
- Linux user/mount/PID namespaces merely to compensate for removed cgroups;
- copy-on-write workspace branching;
- dynamic sandbox permission expansion after launch;
- raw nono internals in SSH/session code;
- a public policy language exposing nono or Seatbelt implementation details;
- automatic downgrade to an unsandboxed process if the kernel/platform cannot enforce required confinement.

Detached-process containment beyond normal Unix session/process-group semantics is also not a new feature of this migration. A deliberately daemonizing child that creates a new session may escape the SSH session process group. It remains confined by inherited Landlock/Seatbelt policy, but this migration must not claim cgroup-like tree containment where none exists.

---

## Mandatory implementation discipline

1. Read repository-local instructions before editing. If `AGENTS.md` appears in a newer checkout, follow it.
2. Keep the tree buildable after each milestone.
3. Prefer small commits aligned with milestones.
4. Add tests before deleting the old implementation where practical.
5. Fail closed. A sandbox preparation/apply error must fail launch; it must never silently run the command without confinement.
6. Do all allocations, filesystem canonicalization, `CString`/argv/env construction, policy building, logging decisions, and nono preparation in the parent before `fork()`/`exec()` child setup.
7. The post-fork child path must contain only operations proven safe there: fixed-data/raw syscalls, `nono::PreparedLandlockSandbox::apply_raw()`, and `execve()`/the standard-library exec path whose behavior is explicitly tested.
8. Never allocate, log, lock a mutex, access Tokio, resolve paths, build a capability set, construct error strings, or call nono's allocating `Sandbox::apply_*` APIs in the Linux post-fork child.
9. Every platform-specific assumption needs an integration test on that platform.
10. Do not treat a generic GitHub runner as proof of Fly.io kernel capability.
11. Update comments/docs at the same time as behavior. Do not leave Arapuca, Sandlock, runner, cgroup-limit, or resource-limit descriptions that no longer describe production.
12. Preserve generic SSH error behavior. Do not expose detailed host paths or sandbox internals to clients.

---

## Existing contract that must survive

The platform abstraction remains the only launch seam used by SSH/session code. Preserve the equivalent of:

```rust
#[derive(Debug)]
enum LaunchOperation {
    Shell,
    Exec(Vec<u8>),
}

#[derive(Debug)]
struct PtySpec {
    term: String,
    rows: u32,
    cols: u32,
    modes: Vec<(russh::Pty, u32)>,
    window_revision: u64,
}

#[derive(Debug)]
struct LaunchRequest {
    sandbox_id: SandboxId,
    workspace: PathBuf,
    operation: LaunchOperation,
    pty: Option<PtySpec>,
}

trait RunningProcess: std::fmt::Debug + Send + Sync {
    fn terminate(&self);
    fn force_terminate(&self) { self.terminate(); }
    fn wait_for_cleanup(&self, timeout: Duration) -> bool;
    fn signal(&self, _number: i32) {}
    fn resize(&self, _rows: u32, _cols: u32) -> bool { true }
}

trait ProcessLauncher: std::fmt::Debug + Send + Sync {
    fn launch(&self, request: LaunchRequest) -> Result<LaunchedProcess, LaunchError>;
}
```

The exact private type layout may change, but SSH/session code must not import:

- `nono::*`;
- Landlock types;
- Seatbelt/SBPL types;
- raw libc process types;
- backend-specific launch handles.

`UnavailableLauncher` remains fail-closed for unsupported/unavailable production sandboxing.

`FakeLauncher` remains the deterministic test seam for protocol/unit tests.

Keep the existing process-spawn serialization if it is still required for safe descriptor setup, especially on macOS. Do not remove `PROCESS_SPAWN_LOCK` until a test/proof establishes that the CLOEXEC race it protects no longer exists.

---

## Security and lifecycle invariants

### Fail closed

Any failure to prepare or apply required filesystem/network confinement returns `LaunchError`; no target process may execute unconfined.

### Workspace semantics

For each launch:

- resolve the sandbox workspace through the existing trusted registry/path logic;
- canonicalize it before policy preparation;
- grant write access to the workspace;
- do not grant sibling sandbox workspaces;
- do not replace the workspace with a temporary copy;
- use a per-launch private temp directory for `TMPDIR` instead of granting broad host temporary-directory write access.

### Filesystem boundary

Before deleting Arapuca, inventory the exact default readable paths it currently supplies. Freeze a deliberately curated replacement list in backend-neutral policy tests.

The final policy must distinguish:

- executable/runtime system paths required by the configured shell and normal command execution;
- read-only shared system data;
- writable workspace;
- private per-launch temporary directory;
- minimal terminal/device paths required by the platform.

Do not grant `/` read-write. Do not solve an integration failure by broadening the policy without a specific documented reason and regression test.

### Network boundary

Keep the existing public network modes rather than exposing nono configuration directly.

At minimum:

- `Disabled`: outbound Internet/TCP access must fail; unintended bind/listen must fail;
- `Outbound`: ordinary outbound client connections are permitted as intended; unintended listener exposure remains denied where the platform can enforce that distinction.

Map those modes to nono `CapabilitySet`/prepared policy on Linux and equivalent Seatbelt rules on macOS.

If a platform cannot represent an exact distinction, document that platform limitation and test the actual behavior. Never silently report a stronger guarantee than is enforced.

### PTY/session invariant

For a PTY launch, the target must execute in a new session whose controlling terminal is the allocated PTY slave.

The child setup must produce all of the following:

- target is a session leader;
- PTY slave is its controlling terminal;
- target's initial process group is the foreground process group for the terminal;
- fd 0/1/2 refer to the PTY slave;
- shbox retains only the PTY master plus lifecycle handles needed by the session;
- terminal modes and initial window size are applied before user code depends on them;
- `SIGWINCH`/window-size updates are observable by the interactive program;
- terminal-generated `SIGINT`, `SIGTSTP`, etc. reach the foreground job through normal kernel TTY semantics rather than ad-hoc SSH emulation.

Do not call `setpgid()` after a successful `setsid()` for the session leader; `setsid()` already makes it process-group leader. Use `tcsetpgrp()` only where required/proven by the target platform, and assert the final foreground PGID in tests.

### Non-PTY invariant

For a non-PTY exec:

- stdin/stdout/stderr are separate pipes;
- no controlling terminal is acquired;
- output and exit-status behavior remains compatible with the existing SSH tests;
- signal handling remains process-group based where applicable.

### Parent-death behavior

On Linux, set `PR_SET_PDEATHSIG` on the direct session child in the child setup path, then immediately verify the captured parent PID to close the parent-death race.

Use a catchable termination signal only if shbox needs a graceful cleanup phase in the direct child. Otherwise use the simplest proven semantics. Do not claim this kills independently daemonized descendants; `PR_SET_PDEATHSIG` is a direct-parent relationship, not a cgroup replacement.

On macOS there is no direct equivalent. Preserve process-group shutdown and document the platform difference accurately.

### Cleanup invariant

Normal session shutdown must terminate the session process group, wait for the direct child, close the PTY/pipes, and release launch-temp resources.

`wait_for_cleanup()` must not report success while the direct managed child is still alive or shbox still owns its PTY/pipe resources.

The release gate must separately test:

- normal shell exit;
- SSH channel disconnect;
- daemon shutdown;
- forced termination;
- direct-child crash;
- background child in the same process group.

A child that deliberately `setsid()` and daemonizes is outside the strong kill-all guarantee; document and test that the sandbox confinement remains inherited even if such a process survives the SSH process group.

---

## Target source layout

Final platform files should converge on:

```text
src/platform/
├── mod.rs
├── terminal.rs
├── policy.rs
├── linux.rs
└── macos.rs
```

Expected responsibilities:

- `mod.rs`
  - backend-neutral launch traits and result/error types;
  - `production_launcher(...)` construction;
  - fake/unavailable launchers.
- `terminal.rs`
  - PTY pair allocation;
  - fd duplication helpers;
  - terminal mode conversion/application;
  - window-size application;
  - async PTY master I/O;
  - small raw child PTY setup helper whose operations are explicitly audited for post-fork safety.
- `policy.rs`
  - backend-neutral `SandboxLaunchPolicy`;
  - curated read/write/network policy derived from config;
  - launch-temp path policy;
  - no nono/Seatbelt public types.
- `linux.rs`
  - convert common policy to `nono::CapabilitySet`;
  - prepare Linux nono confinement before spawn;
  - PTY/non-PTY launch;
  - Linux parent-death setup;
  - process-group signal/wait/cleanup.
- `macos.rs`
  - build validated Seatbelt profile before spawn;
  - execute `/usr/bin/sandbox-exec` after child PTY/session setup;
  - process-group signal/wait/cleanup.

Final tree must **not** contain:

```text
src/platform/arapuca.rs
src/platform/sandlock.rs
src/platform/linux_runner_protocol.rs
src/bin/shbox-sandbox-runner.rs
```

Do not introduce equivalents under different names.

---

## Platform-neutral launcher construction

`main.rs` should end with a backend-neutral shape similar to:

```rust
let policy = platform::SandboxLaunchPolicy::from_config(&app_config, &sandbox_shell)?;
let launcher = match platform::production_launcher(policy) {
    Ok(launcher) => launcher,
    Err(error) => {
        // sanitized operator log
        Arc::new(platform::UnavailableLauncher::new(...))
    }
};
```

The exact error plumbing can follow existing style, but `main.rs` must not name:

- Arapuca;
- nono;
- Landlock;
- Seatbelt;
- cgroups;
- platform runner binaries.

Use compile-time `cfg(target_os)` selection inside `platform` rather than a runtime backend selector.

---

## Dependency policy

### Final Cargo policy

Set package MSRV to Rust 1.95.

Use an exact nono pin during this migration:

```toml
rust-version = "1.95"

[target.'cfg(target_os = "linux")'.dependencies]
nono = { version = "=0.74.0", default-features = false }
```

Keep `nix`/`libc` only for the Unix primitives shbox actually uses. Ensure `nix` features include the terminal/process functionality required by `openpty`, signal handling, and process setup.

For macOS, keep the smallest dependency set needed to render/validate Seatbelt policy. If the existing plan introduced `seatbelt-rs`, first verify its exact API and whether it can generate the required profile without applying `sandbox_init` inside the multithreaded daemon. If it cannot express shbox's rules cleanly, prefer a small shbox-owned typed SBPL renderer over post-fork `sandbox_init`.

Do **not** add `nono-cli` as a dependency or require a `nono` executable.

### Why nono is Linux-only in the launch implementation

`nono 0.74.0` supports macOS Seatbelt, but its macOS `apply()` path generates a profile `String`/`CString` and calls `sandbox_init()`. That is not the post-fork child path wanted for a permanently multithreaded Tokio/russh daemon.

By contrast, the Linux crate exposes `PreparedLandlockSandbox::apply_raw()`, explicitly intended to apply a policy after preparation using raw syscalls without heap allocation/libc coordination wrappers.

Therefore:

- use nono directly for Linux confinement;
- keep macOS confinement as pre-generated Seatbelt profile + `/usr/bin/sandbox-exec`;
- keep common capability semantics in shbox's `SandboxLaunchPolicy` rather than forcing both OSes through an unsafe common mechanism.

### Dependencies to remove

By completion:

- remove `arapuca` from `Cargo.toml` and `Cargo.lock`;
- remove `sandlock-core` if present from intermediate work;
- remove any runner-only dependencies;
- remove dependencies used solely by cgroup/resource-limit implementation if no longer otherwise needed.

---

## Resource limits

Resource limits are intentionally removed from the sandbox contract.

Delete Arapuca-only internal limit plumbing when nothing else consumes it, including the equivalent of:

- `Limits`;
- `LinuxLimits`;
- `max_memory_mb`;
- `cpu_timeout_secs` if it exists only as an Arapuca sandbox resource control;
- `max_file_size_mb` if it exists only as an Arapuca sandbox resource control;
- `max_open_files` if it exists only as an Arapuca sandbox resource control;
- `max_cpu_pct`;
- `max_pids` / proposed `max_processes`.

Do not replace these with nono CLI cgroup resources or RLIMIT compatibility behavior.

If one of these fields is independently part of a documented public shbox configuration surface at implementation time, stop deleting only that public field and instead:

1. prove where it is exposed;
2. preserve parsing compatibility temporarily;
3. mark it deprecated/ignored only with an explicit test and documentation;
4. do not make sandbox launch depend on cgroups.

At the previously inspected baseline, the limits were internal defaults rather than user TOML, so the expected result is complete removal.

---

# Milestone 0 — re-baseline and lock nono 0.74.0 API assumptions

## Goal

Turn the nono decision into compile-checked facts before changing production launch behavior.

## Work

1. Re-read:
   - `Cargo.toml` / `Cargo.lock`;
   - `src/platform/mod.rs`;
   - `src/platform/terminal.rs`;
   - `src/platform/arapuca.rs`;
   - `src/config.rs`;
   - `src/main.rs`;
   - `tests/ssh_auth.rs`;
   - platform verification scripts;
   - systemd/launchd deployment files;
   - all docs mentioning Arapuca/cgroups/limits.

2. Update MSRV/build tooling from Rust 1.91 to Rust 1.95 everywhere it is pinned.

3. Add `nono = "=0.74.0"` as a Linux target dependency while temporarily retaining Arapuca until the replacement is testable.

4. Inspect the resolved crates.io source actually present in `Cargo.lock`, not only online docs.

5. Add a Linux compile-time spike/test that proves all API names the implementation will use. At minimum verify:
   - `nono::CapabilitySet` construction;
   - filesystem read/write/execute capability APIs chosen for shbox;
   - network/signal/IPC mode APIs chosen for shbox;
   - Linux support/capability inspection API;
   - `nono::sandbox::PreparedLandlockSandbox`;
   - the preparation function used to obtain it, expected to be `prepare_seccomp_with_abi(...)` or the exact 0.74 API equivalent;
   - `PreparedLandlockSandbox::apply_raw()`;
   - any `SeccompOpts` constructor needed for network fallback/baseline behavior.

6. Confirm from resolved source that `apply_raw()`:
   - uses prepared path FDs/rules;
   - does not allocate;
   - does not perform path resolution;
   - applies `no_new_privs`/Landlock/seccomp behavior expected by the chosen preparation API;
   - returns fixed-size/raw error information that can be handled without formatting in the child.

7. Confirm prepared path descriptors are moved above stdio (nono 0.74 currently contains a `move_fd_above_stdio` helper). Add a regression test in shbox that closes one or more parent stdio descriptors before policy preparation/spawn and proves prepared policy FDs do not collide with PTY/pipe fd 0/1/2.

8. Copy the license attribution requirements for Apache-2.0 into the release checklist if needed by the repository's distribution method.

9. Do not write a generic wrapper around unstable guesses. Pin the exact API used by 0.74.0 and let a future dependency upgrade fail at compile time if those internals change.

## Proof

```sh
cargo +1.95 check --locked --all-targets
cargo +1.95 test --locked <nono_api_probe_test_name>
```

Milestone 0 is complete only when the exact Linux prepared-policy API compiles from the resolved `nono 0.74.0` package.

---

# Milestone 1 — extract backend-neutral policy and remove resource-limit semantics

## Goal

Separate “what shbox allows” from the old Arapuca implementation.

## Work

1. Create `src/platform/policy.rs`.

2. Define a private/common `SandboxLaunchPolicy` containing only behavior shbox still needs, such as:
   - configured shell path;
   - network mode;
   - curated read paths;
   - required executable/runtime paths;
   - sandbox environment values that are policy-owned;
   - runtime temp-root information.

3. Do not include resource limit fields.

4. Move policy construction out of `ArapucaLaunchPolicy` without changing active production behavior yet.

5. Inventory Arapuca's `default_sandbox_paths()` result on each supported OS before removing it. Classify every path as:
   - required executable/runtime path;
   - required read-only system data;
   - obsolete Arapuca implementation detail;
   - unsafe/unnecessary broad grant.

6. Freeze the accepted list in tests rather than calling Arapuca from the new policy module.

7. Keep workspace write grants per-launch, not global in the base policy.

8. Add a private runtime temp root under shbox state, e.g.:

```text
<state_dir>/runtime/
```

with owner-only permissions. Each launch gets a unique 0700 directory. Use this as `TMPDIR` and grant only that directory writable.

9. Preserve the existing command validation contract:
   - maximum remote command length 32 KiB;
   - reject NUL;
   - preserve required UTF-8 behavior if the existing shell `-c` contract requires UTF-8;
   - shell operation remains login shell behavior where currently promised.

10. Remove or deprecate internal `Limits`/`LinuxLimits` types once Arapuca no longer requires them. Do not carry them into `SandboxLaunchPolicy`.

## Tests

Add policy tests proving:

- workspace A cannot accidentally grant workspace B;
- launch temp is writable but sibling launch temp is not in the policy;
- network mode maps deterministically;
- command validation remains unchanged;
- no resource-limit values are present in the new policy.

## Proof

All current unit tests pass with Arapuca still temporarily driving production launch.

---

# Milestone 2 — make PTY/process ownership explicitly shbox-owned

## Goal

Build one Unix terminal implementation that both Linux and macOS launchers use.

## Work

1. Extend `src/platform/terminal.rs` around `nix::pty::openpty`.

2. Define an internal PTY pair type that clearly owns:
   - master fd;
   - slave fd;
   - any dedicated duplicate retained for child controlling-terminal setup.

3. Apply initial terminal modes and window size **before spawn** where possible.

4. Add a post-fork-safe child terminal setup helper. It must use only fixed/raw Unix operations and return a compact errno/stage result. It must perform the logical equivalent of:

```text
setsid()
ioctl(slave_fd, TIOCSCTTY, 0)
(optional/proven) tcsetpgrp(slave_fd, getpgrp())
```

5. Do not allocate or format errors in this helper.

6. Ensure the PTY slave survives until child setup but is close-on-exec unless it becomes fd 0/1/2.

7. Parent closes its slave copies immediately after successful spawn.

8. Keep PTY master integration with Tokio through the existing `AsyncFd`/`PtyIo` design.

9. `resize(rows, cols)` applies `TIOCSWINSZ` through the master or another proven terminal fd and updates the revision logic consistently.

10. Keep non-PTY pipe helpers separate; do not emulate non-PTY execution with a PTY.

11. Add low-level local tests independent of nono/Arapuca:
   - `isatty(0/1/2)` in PTY child;
   - `getsid(0) == getpid()` for the initial shell/session leader where appropriate;
   - `tcgetsid(0)` matches the session;
   - `tcgetpgrp(0)` matches the foreground PGID;
   - window size is correct;
   - terminal mode changes take effect;
   - closing master causes expected terminal EOF/HUP behavior.

## Critical rule

The sandbox crate must never become the abstraction that owns the PTY. PTY setup must remain testable without enabling confinement.

---

# Milestone 3 — implement Linux nono launcher

## Goal

Replace Linux Arapuca launch with shbox-owned spawn + nono prepared confinement.

## Parent-side preparation

For every launch, before entering any post-fork path:

1. resolve/canonicalize workspace;
2. create private launch temp directory;
3. build command argv/environment as `CString`/OS-safe structures;
4. resolve the executable/shell path;
5. construct `nono::CapabilitySet` from `SandboxLaunchPolicy` plus workspace/temp grants;
6. query the actual Landlock ABI/support needed by nono;
7. prepare the exact Landlock/seccomp policy into `PreparedLandlockSandbox`;
8. allocate PTY or pipes;
9. prepare all error/status pipe fds required to distinguish child-setup failure from exec failure;
10. prepare parent-death reference PID;
11. prepare any raw pointers/arrays needed by the chosen spawn/exec path.

No child should exist yet while these operations allocate or open policy paths.

## Nono policy mapping

Use nono for confinement only.

Expected mapping:

- filesystem read grants -> nono read capabilities;
- workspace + private temp -> write capabilities;
- shell/program/runtime loaders -> executable/read capabilities required by nono/OS;
- network disabled -> nono network mode/rules that block network;
- network outbound -> minimum network capability that permits client behavior but does not intentionally grant broad listening;
- signal mode -> isolate sandboxed process signals from unrelated host processes where supported;
- IPC mode -> isolate where supported without breaking normal shell/PTY behavior.

Use the strongest policy supported by the actual Fly/Linux target **that still represents the intended shbox semantics**. Do not turn on unrelated nono broker/proxy/elevation features merely because they exist.

Specifically do not adopt:

- nono capability elevation;
- dynamic path approval;
- credential proxying;
- tool-sandbox micro-sandbox orchestration;
- resource cgroups;
- nono CLI profiles/packs.

## Linux spawn path

Implement a direct shbox child spawn. The implementation may use `std::process::Command` with a tightly audited `pre_exec` closure or a small raw fork/exec routine. Choose the smaller implementation that can prove all post-fork operations are safe and fd ordering is deterministic.

If using `Command::pre_exec`:

- prepare every captured value before spawn;
- capture only raw/fixed data plus the prepared nono policy;
- do not call ordinary Rust allocation/logging/path APIs in the closure;
- do not rely on undocumented stdio setup ordering for `TIOCSCTTY`; retain an explicit slave/setup fd and use that fd for controlling-terminal acquisition;
- add a test that proves the closure sees the expected PTY setup fd and final fd 0/1/2.

PTY child path, conceptually:

```text
PR_SET_PDEATHSIG
verify getppid()
setsid()
TIOCSCTTY(slave)
(optional/proven) tcsetpgrp(slave, current_pgrp)
chdir(workspace) using prepared C path / safe raw call
PreparedLandlockSandbox::apply_raw()
exec target
```

Non-PTY child path, conceptually:

```text
PR_SET_PDEATHSIG
verify getppid()
create/retain session or process group appropriate for SSH signal control
chdir(workspace)
PreparedLandlockSandbox::apply_raw()
exec target
```

The exact ordering of `no_new_privs`, Landlock, seccomp, and exec must match nono 0.74's documented/prepared API assumptions. Do not manually duplicate nono's internal rule installation around `apply_raw()`.

## Child error reporting

Create a close-on-exec status pipe before spawn.

If child setup fails before `exec`:

- write a fixed-size stage + errno record using raw `write`;
- `_exit(126)` or another internal reserved status;
- parent translates it to sanitized `LaunchError` and operator diagnostics.

On successful exec the CLOEXEC status fd closes, allowing the parent to distinguish success without string allocation in the child.

Do not send host filesystem policy details to the SSH client.

## Process control

Store at minimum:

- direct child PID;
- session/process-group ID used for signaling;
- PTY master or pipe handles;
- cleanup state + wait notification.

Implement:

- `signal(n)`: target the foreground/session process group consistent with SSH semantics;
- `terminate()`: graceful session-process-group termination;
- `force_terminate()`: SIGKILL session process group;
- `resize()`: PTY window update only when PTY exists;
- wait thread/task: reap direct child exactly once and publish `ProcessExit`;
- launch-temp deletion after direct lifecycle cleanup.

Do not use `kill(-uid)` or any UID-wide cleanup.

## Linux capability preflight

Startup or first-launch preflight must report/fail on the actual kernel requirements needed by the selected nono policy, not cgroups.

At minimum record for operator diagnostics:

- kernel release;
- Landlock support/ABI as exposed through nono;
- which requested filesystem/network/signal/IPC features are enforceable;
- whether nono requires a seccomp fallback for the selected network policy;
- whether that fallback can be installed in the target environment.

Fail closed if a capability required for the configured shbox security contract is unavailable.

Do not add a generic `allow_degraded=true`. Any intentional degradation must be represented as an explicit shbox policy decision with an acceptance test and documentation.

## Linux proof

A real Linux integration run must prove all of:

- workspace read/write succeeds;
- denied outside write fails;
- at least one sensitive outside read chosen by the test is denied;
- network-disabled fails outbound connection;
- outbound mode performs the intended loopback/client connection;
- non-PTY stdout/stderr/status work;
- PTY acceptance suite passes;
- signal forwarding works;
- channel disconnect cleans the direct session/process group;
- daemon shutdown cleans the direct session/process group;
- no `/sys/fs/cgroup` write or controller delegation is required;
- no `nono` executable is invoked.

---

# Milestone 4 — implement macOS Seatbelt launcher with the same PTY ownership

## Goal

Remove Arapuca/selfexec from macOS without moving PTY ownership out of shbox.

## Work

1. Reuse `SandboxLaunchPolicy` and `terminal.rs`.

2. Generate the complete Seatbelt/SBPL profile in the parent before spawn.

3. Profile requirements include:
   - deny-by-default baseline;
   - required process execution/fork behavior;
   - curated read paths;
   - workspace + launch-temp writes;
   - PTY operations (`pseudo-tty`, necessary `/dev/tty`/`/dev/ttys*` ioctl access);
   - signal behavior required for same-sandbox shell jobs;
   - network disabled/outbound mapping;
   - no broad host write grant.

4. Use nono 0.74's macOS implementation as a semantic reference for required PTY/Seatbelt operations, but do not call nono's allocating `Sandbox::apply_auto()` or private profile generator from a post-fork child.

5. Spawn `/usr/bin/sandbox-exec` directly as the child executable/wrapper. Do not resolve it from `PATH`.

6. PTY path:
   - shbox allocates PTY;
   - child establishes new session;
   - child acquires PTY slave with `TIOCSCTTY`;
   - fd 0/1/2 use slave;
   - child execs `/usr/bin/sandbox-exec` with the pre-generated profile and target command;
   - sandboxed target inherits controlling terminal.

7. Non-PTY path uses pipes but the same parent-prepared Seatbelt policy.

8. Delete from `main.rs`:
   - `embedded_arapuca_wrapper_invocation()`;
   - `run_embedded_arapuca_wrapper()`;
   - `ARAPUCA_WRAPPER` handling;
   - Arapuca rlimit/selfexec setup.

9. Do not use direct `sandbox_init()` from a multithreaded post-fork child unless a future API is proven allocation-free and post-fork-safe; it is not required by this plan.

10. Keep exact native macOS 15 and macOS 26 acceptance gates already present unless current CI has intentionally changed supported versions.

## macOS proof

Prove on each blocking native version:

- workspace write succeeds;
- outside write fails;
- selected outside read denial works;
- network modes behave as documented;
- complete PTY acceptance suite passes;
- signal forwarding works;
- no Arapuca wrapper/selfexec path exists;
- `sandbox-exec` invocation is the only external sandbox wrapper;
- normal/forced shutdown reaps the direct child/process group.

---

# Milestone 5 — switch production bootstrap and delete Arapuca/cgroup/limit code

## Goal

Make the new launchers the only production paths.

## Work

1. Change `platform::production_launcher(policy)`:
   - Linux -> `LinuxLauncher` using nono prepared confinement;
   - macOS -> `MacosLauncher` using Seatbelt + sandbox-exec;
   - unsupported platform -> fail-closed launcher/error.

2. Update `main.rs` to construct only the common policy + launcher.

3. Delete `src/platform/arapuca.rs`.

4. Remove Arapuca from Cargo manifest/lock.

5. Remove all Arapuca wrapper/selfexec code.

6. Delete Linux cgroup helpers and all production accesses whose only purpose was sandbox cgroup management, including equivalents of:
   - controller delegation preflight;
   - private child cgroup creation;
   - moving daemon/session PIDs between cgroups;
   - `cgroup.controllers` / `cgroup.subtree_control` writes;
   - `cgroup.procs` manipulation;
   - `cgroups_available()` checks.

7. Delete internal resource-limit types/settings no longer part of the public contract.

8. Remove `ARAPUCA_` launcher-control environment behavior. Do not replace it with public `NONO_` passthrough controls.

9. Remove any intermediate Sandlock or sibling-runner implementation/files if they were created before this plan replaced them.

10. Ensure package metadata/description no longer says “Arapuca sandbox workspaces”.

## Proof

```sh
cargo +1.95 check --locked --all-targets
cargo +1.95 test --locked
```

Source audit must show no production Arapuca/Sandlock/runner/cgroup-limit implementation remains.

Historical migration text in `PLANS.md` may mention removed mechanisms; production source/deploy docs must not require them.

---

# Milestone 6 — rewrite SSH integration tests around backend-neutral sandbox behavior

## Goal

Make PTY and sandbox behavior the contract, not the implementation name.

## `tests/ssh_auth.rs`

1. Rename Arapuca-specific test names to `sandbox_*` / `pty_*` names.

2. Replace:

```text
SHBOX_RUN_ARAPUCA_INTEGRATION
```

with:

```text
SHBOX_RUN_SANDBOX_INTEGRATION=1
```

for gates that exercise the real platform backend.

3. Generic tests that do not enable/possess a real backend must still prove fail-closed behavior rather than skipping into unconfined launch.

4. Preserve existing non-PTY tests for:
   - stdout;
   - stderr;
   - exit status;
   - workspace/environment;
   - EOF semantics;
   - signal handling.

## Blocking PTY acceptance suite

PTY is not accepted until all applicable tests pass through a real OpenSSH client/session path, not merely a local `openpty()` unit test.

Required tests:

1. `tty` / `test -t 0` reports a terminal.
2. fd 0, 1, and 2 are TTYs in a PTY session.
3. `getsid(0)` identifies the new session rather than shbox's daemon session.
4. `tcgetsid(0)` matches the target session.
5. `tcgetpgrp(0)` returns the foreground job's PGID.
6. initial interactive shell prompt/command exchange works.
7. `stty size` matches requested rows/cols.
8. SSH window resize changes `stty size` and/or produces observable `SIGWINCH`.
9. configured terminal modes such as echo/canonical flags are honored.
10. foreground `sleep` + Ctrl-C terminates the foreground job and returns the shell.
11. foreground `sleep` + Ctrl-Z stops the job and returns the shell.
12. `jobs` reports the stopped job.
13. `fg` resumes it as foreground.
14. `bg` behavior is sane where the shell supports it.
15. nested foreground command/process group receives terminal-generated signals, not the shell incorrectly.
16. a TUI/simple raw-mode test can switch terminal modes and restore them.
17. closing/disconnecting the SSH PTY delivers expected HUP/EOF behavior to the managed shell.
18. no PTY slave fd leaks in the daemon after session exit.
19. repeated PTY open/close does not grow fd count.
20. concurrent PTY sessions have distinct controlling terminals and do not receive each other's signals/resize events.

Use robust shell commands and small helper binaries where shell portability makes assertions ambiguous. Do not weaken these to “stdout looked interactive”.

---

# Milestone 7 — platform verification scripts and deployment

## Linux verification script

Rewrite `scripts/verify-linux-platform` so it:

1. requires Rust 1.95 or the repository-pinned equivalent;
2. builds `shbox` only; no Arapuca wrapper, no runner binary, no nono CLI;
3. prints kernel release and nono/Landlock capability diagnostics;
4. does not inspect cgroup delegation as a prerequisite;
5. never writes `/sys/fs/cgroup`;
6. runs unit/compile checks;
7. starts the actual shbox daemon as the intended unprivileged user/context;
8. runs real SSH non-PTY tests;
9. runs the full PTY acceptance suite;
10. runs filesystem/network denial tests;
11. runs normal/forced cleanup tests;
12. exits nonzero on any sandbox or PTY failure.

Diagnostic reads of `/proc` needed to explain kernel behavior are allowed. Cgroup state may be printed only as optional environment diagnostics if useful; it cannot influence sandbox availability.

## macOS verification script

Rewrite `scripts/verify-macos-platform` so it:

1. has no Arapuca build/wrapper checks;
2. verifies native arm64 execution;
3. verifies expected macOS major version for the CI job;
4. verifies `/usr/bin/sandbox-exec` exists and can enforce a tiny deny/allow smoke profile;
5. runs the full real SSH sandbox and PTY suite;
6. confirms no selfexec environment path exists.

## systemd

Update `deploy/systemd/shbox.service`:

- remove `Delegate=cpu cpuset memory pids` and comments requiring delegated controllers;
- keep the dedicated unprivileged service account;
- keep appropriate `NoNewPrivileges`/hardening unless it prevents the proven nono policy setup;
- keep `KillMode=control-group` if it remains useful as a **systemd service-manager cleanup choice**. This string does not mean shbox depends on delegated cgroup controllers; document that distinction if necessary.

Do not add privileges/capabilities merely to make nono work. Landlock is intended for unprivileged use.

## launchd

Update the plist/comments to describe Seatbelt/sandbox-exec rather than Arapuca. Do not add selfexec wrapper variables.

---

# Milestone 8 — CI and release gates

## Goal

Make the release gate match actual production requirements.

1. Change all Rust 1.91 jobs/toolchain pins to Rust 1.95.

2. Preserve build coverage for:
   - Linux x86_64;
   - Linux aarch64;
   - macOS arm64.

3. Preserve blocking native macOS platform gates.

4. Add or designate a real Linux platform gate whose kernel supports the nono policy intended for Fly deployment.

5. Do not label a generic compile-only GitHub Linux job as proof of production confinement.

6. CI must fail if:
   - nono policy preparation fails;
   - required Landlock/network behavior is unavailable;
   - any PTY blocking test fails;
   - denied filesystem/network operations unexpectedly succeed;
   - Arapuca/Sandlock/runner production references reappear.

7. `cargo test`, `cargo clippy`/format checks already required by the repo must run on Rust 1.95.

---

# Milestone 9 — Fly.io acceptance

## Goal

Prove the exact target environment works without cgroup delegation.

Run this on the same Fly.io Machine/image configuration intended for Haven/shbox production.

## Environment observations

Capture, without treating cgroups as prerequisites:

```sh
uname -a
cat /proc/version
id
ulimit -a
```

Also print the nono/Landlock support information exposed by the implementation.

Record:

- Landlock ABI;
- availability of filesystem rights used by policy;
- network rights/fallback used by nono;
- signal/IPC scoping availability if requested;
- seccomp behavior required by nono network fallback, if any.

## Required runtime proof

With the production binary/configuration:

1. start shbox without elevated privileges;
2. authenticate using the normal SSH path;
3. run non-PTY command and verify stdout/stderr/status;
4. open PTY shell and run the complete blocking PTY suite;
5. verify workspace persistence across sessions;
6. verify outside-workspace denial;
7. verify network-disabled mode;
8. verify outbound mode against a controlled endpoint/loopback test;
9. run 20 sequential PTY sessions;
10. run at least 4 concurrent PTY sessions;
11. verify fd count returns near baseline after sessions close;
12. verify no PTY slave/process from one session is reused incorrectly by another;
13. disconnect SSH while foreground and background-same-PGID commands run and verify cleanup;
14. stop shbox normally while sessions exist and verify managed process groups exit;
15. SIGKILL shbox with a direct session child running and verify Linux PDEATHSIG behavior for the direct child;
16. explicitly test/document the behavior of a deliberately detached `setsid()` descendant so the release notes do not claim cgroup-equivalent containment;
17. prove no launch path writes or requires writable cgroup controller files.

Fly acceptance fails if security only works after broadening filesystem/network access beyond the documented policy.

---

# Milestone 10 — documentation rewrite

Update all of:

- `docs/README.md`
- `docs/architecture.md`
- `docs/configuration.md`
- `docs/platforms.md`
- `docs/product.md`
- `docs/release.md`
- `docs/security.md`
- `docs/ssh-protocol.md`
- `docs/testing.md`

Required content:

### Architecture

State clearly:

```text
SSH/session layer
    -> ProcessLauncher
        -> shbox-owned PTY/process lifecycle
        -> OS confinement
            Linux: nono/Landlock (+ nono-selected seccomp fallback as required)
            macOS: Seatbelt via sandbox-exec
```

### PTY

Document that PTY is a first-class SSH feature and shbox directly implements:

- PTY allocation;
- controlling-terminal setup;
- foreground process groups/job control;
- terminal modes;
- resize/SIGWINCH behavior;
- signal forwarding.

### Linux security

Document:

- nono 0.74.0 is used as a library;
- no nono CLI is required;
- no cgroup delegation is required;
- resource limits are not provided by shbox;
- confinement is inherited by descendants;
- process-group cleanup is not the same as cgroup tree containment.

### macOS security

Document:

- Seatbelt policy is generated before spawn;
- `/usr/bin/sandbox-exec` applies it;
- no Arapuca/selfexec wrapper exists;
- PTY remains shbox-owned.

### Configuration

Remove descriptions of internal resource limits if they were not public configuration. Do not add backend selectors or nono-specific knobs.

### Testing/release

Make the full PTY acceptance suite and native platform sandbox tests blocking requirements.

---

# Milestone 11 — final residual audit

## Source/dependency audit

Run searches equivalent to:

```sh
! grep -RIn --exclude-dir=.git --exclude=PLANS.md 'arapuca\|Arapuca' src tests scripts deploy docs Cargo.toml
! grep -RIn --exclude-dir=.git --exclude=PLANS.md 'sandlock\|Sandlock' src tests scripts deploy docs Cargo.toml
! grep -RIn --exclude-dir=.git --exclude=PLANS.md 'shbox-sandbox-runner\|linux_runner_protocol' src tests scripts deploy docs Cargo.toml
! grep -RIn --exclude-dir=.git --exclude=PLANS.md '/sys/fs/cgroup\|cgroup.procs\|cgroup.controllers\|cgroup.subtree_control' src scripts deploy docs
```

`KillMode=control-group` in systemd is an allowed service-manager setting if intentionally retained; exclude/interpret it separately rather than deleting useful systemd cleanup merely to satisfy grep.

Search for stale limit concepts:

```sh
grep -RIn --exclude-dir=.git --exclude=PLANS.md 'max_pids\|max_processes\|max_cpu_pct\|max_memory_mb' src tests docs || true
```

Every remaining hit must have a documented non-sandbox reason or be removed.

Verify dependency tree:

```sh
cargo +1.95 tree | grep -E 'arapuca|sandlock' && exit 1 || true
cargo +1.95 tree | grep 'nono v0.74.0'
```

## Full quality gate

Run the repository's standard format/lint/test commands plus:

```sh
cargo +1.95 check --locked --all-targets
cargo +1.95 test --locked
```

Then run the native Linux/Fly and macOS platform scripts.

---

## Real-platform acceptance matrix

| Requirement | Linux / Fly | macOS 15 arm64 | macOS 26 arm64 |
|---|---:|---:|---:|
| Build Rust 1.95 | required | required | required |
| Real sandbox starts unprivileged | required | required | required |
| Workspace write | required | required | required |
| Outside write denied | required | required | required |
| Selected outside read denied | required | required | required |
| Network disabled | required | required | required |
| Outbound mode | required | required | required |
| Non-PTY stdout/stderr/status | required | required | required |
| `isatty(0/1/2)` | required | required | required |
| controlling TTY (`tcgetsid`) | required | required | required |
| foreground PGID (`tcgetpgrp`) | required | required | required |
| Ctrl-C foreground job | required | required | required |
| Ctrl-Z + jobs + fg | required | required | required |
| resize / SIGWINCH | required | required | required |
| EOF/HUP on disconnect | required | required | required |
| concurrent PTY isolation | required | required | required |
| direct child cleanup | required | required | required |
| no Arapuca/selfexec | required | required | required |
| no cgroup delegation requirement | required | N/A | N/A |
| nono library confinement | required | N/A | N/A |
| Seatbelt sandbox-exec | N/A | required | required |

No release is accepted while a PTY cell marked required is failing or skipped.

---

## Rollback and retry rules

- Before deleting Arapuca, keep commits separated so the new backend implementation can be reverted without losing policy/PTY tests.
- If nono 0.74.0 cannot enforce an intended Linux policy on Fly, do **not** silently fall back to Arapuca, Sandlock, or unconfined execution. Capture the exact missing kernel capability and reassess the policy/library explicitly.
- If a PTY test fails, fix PTY/session/process-group setup first; do not bypass the test with a pseudo-interactive pipe mode.
- If macOS sandbox-exec behavior changes on a supported macOS gate, fail the gate and inspect Seatbelt behavior; do not invoke nono `sandbox_init()` post-fork as a quick workaround.
- If a public resource-limit config surface is discovered during implementation, preserve parse compatibility and document deprecation rather than silently breaking configuration. Do not resurrect cgroups without an explicit new design decision.
- Keep launch-temp cleanup idempotent. Failure to delete an already-removed temp directory is not fatal; failure to remove a still-owned sensitive temp directory should be logged for operators.

---

## Implementation traps explicitly forbidden

1. Do not use `nono run` or shell out to the nono CLI.
2. Do not add a sibling sandbox runner on Linux.
3. Do not self-exec shbox.
4. Do not call allocating nono policy builders in a Linux post-fork child.
5. Do not call macOS `sandbox_init()` from an unsafe multithreaded post-fork path.
6. Do not move PTY creation into nono or sandbox-exec.
7. Do not use pipes as a PTY substitute.
8. Do not call `setpgid()` after `setsid()` on the session leader.
9. Do not globally replace shbox fd 0/1/2 to make child stdio inheritance easier.
10. Do not mutate process-global current directory/environment in the daemon to prepare a child.
11. Do not resolve executable paths after confinement if the resolution itself requires denied filesystem access.
12. Do not let untrusted `PATH` choose `/usr/bin/sandbox-exec` or any sandbox helper.
13. Do not expose nono environment controls to SSH client environment requests.
14. Do not broad-grant `$HOME`, `/tmp`, `/`, `/dev`, or `/proc` to fix one failing tool without analysis.
15. Do not assume Landlock filesystem confinement implies arbitrary syscall confinement.
16. Do not claim RLIMIT/cgroup resource protection; resource limits are out of scope.
17. Do not write `/sys/fs/cgroup` from shbox.
18. Do not kill processes by service UID as session cleanup.
19. Do not claim a detached new-session process is killed if no mechanism proves it.
20. Do not leak host policy paths or raw sandbox diagnostics to the SSH client.
21. Do not make Fly-specific heuristics choose a different backend at runtime.
22. Do not add a user-facing backend selector.
23. Do not keep Arapuca “temporarily” after all replacement release gates pass.
24. Do not accept PTY merely because `test -t 0` succeeds; job-control tests are mandatory.
25. Do not accept a real-platform test that is skipped because capability detection failed; required capability failure is a release failure.
26. Do not depend on undocumented fd ordering without a regression test.
27. Do not forget CLOEXEC/error-pipe behavior around exec failure.
28. Do not duplicate nono's Landlock/seccomp installation logic outside its prepared API.
29. Do not enable nono dynamic capability elevation/proxy features as part of this migration.
30. Do not reintroduce resource limits as a side effect of copying nono-cli execution strategy.

---

## Current progress

- [x] Existing shbox launch abstraction inspected.
- [x] Arapuca/cgroup coupling identified.
- [x] Sandlock 0.8.6 PTY/process ownership mismatch investigated.
- [x] Sandlock selected design abandoned.
- [x] nono 0.74.0 investigated as PTY-compatible confinement primitive.
- [x] Decision: resource limits not required.
- [x] Decision: Rust 1.95 is acceptable and becomes the new MSRV.
- [x] Decision: Linux uses nono prepared confinement; PTY/process lifecycle stays in shbox.
- [x] Decision: macOS keeps shbox-owned PTY and Seatbelt/sandbox-exec rather than post-fork nono `sandbox_init()`.
- [x] Milestone 0 implementation verification in the repository.
- [x] Milestone 1 common policy extraction.
- [x] Milestone 2 shbox-owned PTY implementation.
- [x] Milestone 3 Linux nono launcher.
  - Linux arm64 Docker/Rust 1.95: 157/157 unit tests, `cargo check --all-targets`, and Clippy `-D warnings` pass.
  - macOS arm64/Rust 1.95 regression: 151/151 unit tests, `cargo check --all-targets`, and Clippy `-D warnings` pass.
  - Linux proof covers filesystem allow/deny, sensitive-read denial, disabled/outbound TCP behavior, PTY/session state, signal forwarding, descendant process-group cleanup, child setup status reporting, and recursive launch-temp cleanup.
- [x] Milestone 4 macOS Seatbelt launcher.
  - macOS 26.6.2 arm64/Rust 1.95 native: 157/157 unit tests, `cargo check --all-targets`, and Clippy `-D warnings` pass.
  - Native proof covers deny-by-default filesystem isolation, disabled/client-only outbound TCP, PTY/session state, signal forwarding, TERM/KILL cleanup, daemon shutdown, and recursive launch-temp cleanup.
  - Linux arm64 Docker/Rust 1.95 regression remains green at 157/157 plus check/Clippy.
  - macOS 15 remains a blocking release-matrix run under Milestones 7-8; it is not available on the current macOS 26 host.
- [ ] Milestone 5 Arapuca/cgroup/limit removal.
- [ ] Milestone 6 SSH/PTTY integration suite.
- [ ] Milestone 7 deploy/platform scripts.
- [ ] Milestone 8 CI gates.
- [ ] Milestone 9 Fly acceptance.
- [ ] Milestone 10 docs.
- [ ] Milestone 11 final audit.

---

## Completion definition

The migration is complete only when all of the following are true simultaneously:

- production source contains no Arapuca backend/selfexec path;
- Linux production confinement is `nono 0.74.0` through prepared library APIs;
- Linux requires no delegated cgroup controllers and implements no sandbox resource cgroups;
- resource limits are no longer part of the shbox sandbox implementation unless an independently public compatibility field was proven and explicitly documented;
- no Sandlock or sibling-runner production path remains;
- macOS production confinement is Seatbelt through `/usr/bin/sandbox-exec` with policy prepared before child execution;
- PTY allocation/session/controlling-terminal/job-control behavior is owned by shbox on both OSes;
- all blocking PTY tests pass through real SSH;
- filesystem/network confinement tests pass on each real platform gate;
- Fly.io acceptance passes using the production Machine/image and no cgroup delegation;
- Rust 1.95 is used consistently by package metadata and CI;
- docs accurately describe guarantees and limitations, especially detached-process cleanup;
- the final dependency/source grep is clean;
- `cargo check`, tests, native platform gates, and release checks all pass.

At that point, delete any transitional comments/tests that only existed to compare Arapuca/Sandlock, keep the behavior-oriented regression tests, and merge the migration as the sole supported sandbox architecture.
