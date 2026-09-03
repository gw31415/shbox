# shbox: Sandbox-scoped cgroup lifecycle / tssh compatibility plan

## Goal

Linux sandbox の process lifetime を SSH channel / process group から分離し、sandbox-scoped cgroup を authoritative な process ownership boundary とする。

最終 invariant:

- SSH channel owns transport.
- Process group owns terminal job control.
- cgroup owns all Linux processes belonging to a sandbox runtime.
- Durable sandbox owns workspace and metadata.
- SSH disconnect must not implicitly kill sandbox processes.
- Sandbox deletion and daemon shutdown must be able to kill every sandbox process reliably, including `setsid()`, double-fork, daemonized descendants.
- tssh/tsshd must work without shbox-specific tssh integration: bootstrap SSH may close while tsshd continues over UDP.

Current code already has a sandbox-ID keyed shared `ResourceDomain`, but it is created only when cgroup-backed resource limits are configured.   
Current child/session cleanup still kills process groups both in `shbox` and `shbox-sandbox`, so lifecycle changes must span both layers.  

---

# Milestone 0 — Freeze lifecycle semantics and tests

## Objective

Before changing implementation, encode the intended behavior as tests and documentation.

## Tasks

- Document lifecycle ownership:
  - SSH channel: I/O transport only.
  - PTY/process group: foreground job control and signal routing.
  - sandbox cgroup: process containment.
  - workspace/metadata: durable sandbox state.
- Explicitly document:
  - channel close does not mean sandbox process termination.
  - direct child exit does not mean descendant termination.
  - sandbox delete does terminate every sandbox process.
  - daemon graceful shutdown terminates every sandbox process.
  - daemon crash/restart survival is initially not guaranteed.
- Add failing tests covering:
  - detached descendant survives direct parent exit.
  - `setsid()` descendant survives.
  - channel disconnect does not trigger process termination.
  - explicit sandbox delete still removes all processes.
- Keep existing process-group signal/PTY tests intact.

## Acceptance criteria

- New lifecycle contract is documented.
- Tests fail for the expected current behavior.
- No production behavior changed yet.

---

# Milestone 1 — Generalize `ResourceDomain` into a sandbox process domain

## Objective

Make cgroup creation independent of resource-limit configuration.

Current `ResourceDomain` requires at least one explicit cgroup-backed limit and is described primarily as an aggregate resource-limit domain. 

## Tasks

- Rename or generalize:
  - `ResourceDomain` → preferably `ProcessDomain` or `CgroupDomain`.
- Permit creation with all resource limits set to `Inherit`.
- Keep optional resource limits applied to the same cgroup when configured.
- Ensure every Linux sandbox process domain is created before the first child.
- Continue using `clone3(CLONE_INTO_CGROUP)` so there is no fork/move race.
- Change cgroup creation helpers so an empty set of required controllers is valid.
- Preserve current explicit `cgroup_parent` handling.

## API target

Conceptually:

```rust
let domain = sandbox.create_process_domain(resources, cgroup_parent)?;

sandbox.spawn_in_process_domain(command, config, &domain)?;
```

rather than:

```rust
if resources.requires_cgroup() {
    create_resource_domain(...)
}
```

## Acceptance criteria

- A sandbox with no CPU/memory/PID limit can still have a dedicated cgroup.
- Children are born directly inside that cgroup.
- Existing aggregate resource-limit tests still pass.
- Different sandbox IDs never share a process domain.

---

# Milestone 2 — Separate cgroup observation, kill, and removal

## Objective

Make cgroup membership authoritative instead of Rust handle/reference counts.

Current `ResourceDomain::is_in_use()` is based on `Arc::strong_count`, which cannot detect detached descendants once the direct `SandboxChild` handle disappears. 

Current `Cgroup::remove()` also kills processes implicitly before removal. 

## Tasks

Add explicit cgroup lifecycle operations:

```rust
fn is_populated(&self) -> Result<bool, ...>;
fn wait_until_empty(&self, ...);
fn kill_all(&self) -> Result<(), ...>;
fn remove_empty(&mut self) -> Result<(), ...>;
```

Implementation:

- Read `cgroup.events`.
- Use `populated 0/1` as authoritative membership state.
- Prefer pollable notification on `cgroup.events` rather than busy polling where practical.
- `remove_empty()` must fail if the cgroup is populated.
- `kill_all()` owns `cgroup.kill`.
- Removal must never implicitly kill processes.

Remove lifecycle decisions based on:

```rust
Arc::strong_count(...)
```

Reference counts may remain an internal Rust ownership invariant, but not a process-liveness signal.

## Acceptance criteria

- Double-fork/`setsid()` descendant keeps the domain populated even after direct child handle disappears.
- Empty-domain removal never kills a process.
- Explicit kill reliably transitions domain toward `populated=0`.

---

# Milestone 3 — Stop killing descendants on normal direct-child exit

## Objective

Change normal process completion semantics before touching SSH disconnect handling.

There are currently two independent process-group cleanup paths that must be removed.

### `shbox-sandbox`

`LinuxChild::wait()` / `try_wait()` currently kill the owned process group once the direct child exits. 

### `shbox`

`wait_process()` reaps the direct child, then unconditionally kills the process group. 

## Tasks

- Change normal `SandboxChild::wait()`:
  - wait/reap the direct child only.
  - do not kill its process group.
- Same for `try_wait()`.
- Remove post-wait `kill_process_group()` from `LinuxLauncher::wait_process()`.
- Preserve defensive cleanup for abandoned/unpublished children:
  - failed launch publication.
  - setup failure.
  - dropped child handle before normal ownership transfer.
- Audit `SandboxChild::Drop` separately:
  - normal completed child must not affect surviving descendants.
  - abandoned active child may still receive defensive termination.

## Acceptance criteria

This must work:

```sh
sh -c 'setsid sleep 30 >/dev/null 2>&1 &'
```

After the shell exits:

- direct child has been reaped.
- detached `sleep` remains alive.
- sandbox cgroup remains populated.
- no zombie direct child exists.

---

# Milestone 4 — Make sandbox cgroup mandatory in `LinuxLauncher`

## Objective

Every Linux sandbox launch for the same durable sandbox ID joins the same process domain.

Current `LinuxLauncher` already maintains:

```rust
HashMap<SandboxId, Arc<ResourceDomain>>
```

but only creates entries when resource limits require cgroups. 

## Tasks

- Replace optional resource-domain lookup with mandatory process-domain lookup.
- Lazy-create the process domain on first process launch.
- Key domain ownership by `SandboxId`.
- All subsequent launches for that sandbox use the same domain.
- Do not delete the cgroup merely because one direct launch exits.
- Keep sandbox process-domain state distinct from individual `RuntimeLease`s.

Desired structure:

```text
SandboxId
└── ProcessDomain
    ├── launch A
    │   └── descendants
    ├── launch B
    │   └── descendants
    └── detached background processes
```

## Acceptance criteria

- Two concurrent SSH sessions to one sandbox share one cgroup.
- Two different sandbox IDs use separate cgroups.
- Aggregate `memory.max`, `cpu.max`, `pids.max` still cover all processes belonging to the sandbox.

---

# Milestone 5 — Introduce sandbox runtime-domain state machine

## Objective

Prevent races between empty-domain cleanup, launch, and deletion.

The critical race is:

```text
domain becomes empty
cleanup starts
    ↕
new launch starts
```

## Tasks

Introduce manager-side process-domain state, e.g.:

```rust
enum DomainState {
    Idle,
    Creating,
    Active,
    Deleting,
}
```

Track at minimum:

- sandbox ID.
- domain generation.
- in-flight launch count.
- active process-domain handle.
- deletion state.

Lifecycle:

```text
Idle
  ↓ first launch
Creating
  ↓ domain ready
Active
  ↓ populated=0 && launch_inflight=0
Idle
```

Delete:

```text
Active/Idle
  ↓ durable metadata → Deleting
Deleting
  ↓ reject new launches
  ↓ wait in-flight launch barrier
  ↓ kill/remove process domain
  ↓ delete workspace/metadata
```

Empty cleanup may only remove a domain when:

```text
cgroup populated == 0
AND launch_inflight == 0
AND domain generation unchanged
AND sandbox state == Active
```

## Acceptance criteria

Stress tests must show no process escape under:

- launch vs empty cleanup.
- launch vs delete.
- repeated empty → launch → empty cycles.
- concurrent multiple SSH sessions.

---

# Milestone 6 — Decouple SSH channel teardown from sandbox process teardown

## Objective

After process containment is reliable, stop killing processes because transport disappeared.

Current sandbox bridge treats channel close/connection loss as abnormal teardown and invokes process termination cleanup.   
`wait_for_process_cleanup()` currently performs TERM → wait → KILL. 

## Tasks

Split failure cases into two categories.

### Pre-publication failure

Examples:

- launch failed.
- PTY setup failed.
- resize synchronization failed.
- SSH `CHANNEL_SUCCESS` could not be published.

Behavior:

```text
terminate launch
wait/reap
cleanup
```

No client ever successfully acquired this launch.

### Post-publication transport loss

Examples:

- SSH channel close.
- SSH TCP disconnect.
- connection registry dropped.
- output sink fails.
- client disappears after successful shell/exec acknowledgement.

Behavior:

```text
close transport endpoints
stop pumps
detach PTY/channel ownership
do NOT TERM/KILL sandbox processes
```

Remove use of `wait_for_process_cleanup()` from transport-detach paths.

Keep explicit process termination for:

- sandbox delete.
- daemon shutdown.
- pre-publication failure.

## Acceptance criteria

After successful launch:

```text
client disconnect
→ SSH task exits
→ target process survives
→ cgroup remains populated
```

---

# Milestone 7 — Define PTY detach semantics

## Objective

Avoid keeping a pseudo-terminal artificially alive after its SSH transport disappears.

Current Linux process control holds the PTY master through `lifecycle_fd`. 

## Tasks

Add an explicit transport-detach operation to the sandbox process control abstraction.

Conceptually:

```rust
fn detach_transport(&self);
```

For a PTY-backed launch this should:

- stop SSH input/output pumps.
- close daemon-side PTY master ownership belonging to that channel.
- stop accepting resize requests.
- stop accepting SSH-originated signal requests.
- allow normal kernel PTY hangup semantics to occur.

For non-PTY execution:

- close parent stdin/stdout/stderr pipe ends owned by the channel.
- do not signal the process merely because pipes closed.

Do not emulate persistence by keeping PTY master FDs around indefinitely.

## Acceptance criteria

- normal interactive shell usually terminates according to standard terminal hangup semantics.
- `nohup`, daemonized, detached, `setsid()` processes may survive.
- tsshd launched without requiring persistent PTY survives bootstrap SSH close.
- no PTY FD leak after channel disconnect.

---

# Milestone 8 — Move transient runtime resources to sandbox-runtime scope

## Objective

Ensure descendants do not lose runtime resources when the direct launch exits.

Current TMPDIR is per-launch and is deleted when the direct-child waiter finishes.  

That is incompatible with:

```text
shell exits
└── daemon survives and still references TMPDIR
```

## Tasks

Replace per-launch TMPDIR ownership with sandbox-runtime ownership on Linux.

Suggested layout:

```text
sandbox durable tree
└── workspace

shbox runtime tree
└── sandbox-<id>-<generation>
    └── tmp
```

Properties:

- unique to one active runtime-domain generation.
- mode `0700`.
- available to every launch in that runtime generation.
- deleted only after:
  - domain `populated=0`.
  - no launch is in flight.
- regenerated on next first launch.

Do not tie runtime temp cleanup to direct-child exit.

## Acceptance criteria

- detached descendant retains a valid TMPDIR.
- once the final process exits, runtime TMPDIR is removed.
- workspace remains intact.

---

# Milestone 9 — Make sandbox delete cgroup-authoritative

## Objective

Explicit deletion becomes the hard process-lifecycle boundary.

Current deletion cancels manager runtime entries and then releases the resource domain. 

Runtime entries are insufficient once descendants may outlive their direct launch.

## Tasks

Deletion flow:

```text
1. durable metadata → Deleting
2. reject new launches
3. cancel/wait any launch still in pre-publication state
4. wait launch_inflight == 0
5. process_domain.kill_all()
6. wait until cgroup.events populated=0
7. process_domain.remove_empty()
8. remove runtime temp
9. remove workspace / durable metadata
```

Runtime leases remain useful for launch-race management, but must not be treated as the complete process inventory.

## Acceptance criteria

Deletion reliably kills:

- foreground shell.
- background process.
- `setsid()` process.
- double-fork daemon.
- tsshd.
- processes from multiple simultaneous SSH launches.

No process remains after workspace deletion.

---

# Milestone 10 — Move process-count enforcement to cgroup

## Objective

Correct the meaning of process limits after detached descendants become legitimate.

Current `max_sandbox_processes` counts manager runtime entries, not actual kernel processes. 

## Tasks

- Rename manager-side count limit if retained:
  - e.g. `max_concurrent_launches_per_sandbox`.
- Use cgroup `pids.max` for actual process-count enforcement.
- Ensure child processes/forks consume the same sandbox aggregate PID budget.
- Update config documentation and tests to avoid ambiguous "process" terminology.

## Acceptance criteria

- Forking inside one SSH launch cannot bypass sandbox process-count limits.
- detached descendants remain counted.
- simultaneous launches share the same PID budget.

---

# Milestone 11 — Daemon shutdown and stale-domain reconciliation

## Objective

Ensure processes that have detached from SSH are still owned by shbox operational lifecycle.

## Graceful shutdown

Implement:

```text
stop accepting new sandbox launches
↓
freeze launch admission
↓
wait pre-publication launches
↓
kill_all() each sandbox process domain
↓
wait populated=0
↓
remove runtime domains
↓
exit daemon
```

Do not derive shutdown process inventory from active SSH channels.

## Startup reconciliation

Initially define:

> Processes survive SSH disconnect, but survival across shbox daemon crash/restart is not guaranteed.

Then add stale-cgroup cleanup.

Prefer cgroup names that allow shbox ownership to be identified safely, e.g.:

```text
<configured-shbox-parent>/
└── sandbox-<opaque-runtime-id>
```

Avoid trusting an unsanitized user sandbox ID directly as a filesystem/control-group name.

On startup:

- enumerate only shbox-owned cgroups under the configured delegated parent.
- kill stale members.
- wait empty.
- remove stale cgroups.
- remove corresponding stale runtime temp directories.

Do not touch unrelated sibling cgroups.

## Acceptance criteria

- graceful shutdown leaves no sandbox processes.
- simulated daemon crash + restart cleans stale shbox-owned domains.
- unrelated cgroups are untouched.

---

# Milestone 12 — tssh/tsshd compatibility acceptance

## Objective

Verify the generic lifecycle design against the original motivating workload.

No tssh-specific branch or protocol integration should be added to shbox unless a genuine SSH compatibility gap is discovered.

tsshd opens its own UDP listener and uses SSH connection information when available to choose a server-side address. 

## Tasks

Test:

```text
tssh
↓
SSH connects to shbox
↓
exec tsshd bootstrap
↓
tsshd binds UDP
↓
tsshd reports port/token
↓
bootstrap SSH channel closes
↓
shbox detaches transport
↓
tsshd remains in sandbox cgroup
↓
client establishes UDP session
```

Verify at minimum:

- QUIC mode.
- KCP mode if supported by current tssh.
- connection loss and reconnection.
- server process cleanup when tssh/tsshd actually terminates.
- explicit sandbox delete while an active tssh session exists.
- daemon shutdown during active tssh session.

Also check whether shbox should populate standard OpenSSH variables such as:

```text
SSH_CONNECTION
SSH_CLIENT
```

as a general SSH compatibility feature. Do not introduce them solely as hidden tssh-specific behavior.

## Acceptance criteria

- `tssh --udp` can connect to a shbox sandbox.
- bootstrap SSH disconnect does not kill tsshd.
- tsshd disappears naturally when finished and the runtime cgroup becomes empty.
- sandbox delete reliably kills an active tsshd.
- no tssh-specific lifecycle code exists in shbox.

---

# Milestone 13 — Cleanup legacy process-group ownership assumptions

## Objective

Remove obsolete code and documentation after cgroup lifecycle becomes authoritative.

## Tasks

Audit and remove/rewrite:

- direct-child-exit process-group cleanup.
- channel-disconnect process-group cleanup.
- comments equating process group with sandbox process ownership.
- `PROCESS_GROUP_SETTLE` and polling helpers no longer needed.
- `ResourceDomain::is_in_use()`-style Arc-count lifecycle logic.
- tests asserting disconnect → terminate behavior.
- documentation saying sandbox descendants are cleaned through launch process group.

Retain process groups only for:

- PTY foreground job lookup.
- SSH signal forwarding.
- job-control semantics.
- defensive cleanup of an unpublished/failed launch where appropriate.

## Acceptance criteria

A code search for:

```text
kill_process_group
SIGKILL
SIGTERM
wait_for_process_cleanup
resource domain is still in use
```

must show each remaining use is explicitly associated with:

- delete,
- shutdown,
- failed/unpublished launch,
- or terminal/job-control behavior,

not normal SSH transport teardown.

---

# Final acceptance matrix

| Scenario | Expected |
|---|---|
| foreground command exits | direct child reaped; domain eventually empty |
| shell starts background process and exits | background process survives |
| descendant calls `setsid()` | remains in sandbox cgroup |
| double-fork daemon | remains owned by sandbox cgroup |
| SSH channel closes | transport detaches; no forced process kill |
| SSH TCP connection disappears | same |
| final sandbox process exits | `populated=0`; runtime resources removed |
| reconnect to idle sandbox | new runtime domain may be lazily created |
| reconnect while background process lives | same existing sandbox domain |
| two SSH sessions | same sandbox cgroup |
| resource limits configured | shared aggregate cgroup limits |
| no resource limits configured | dedicated cgroup still exists |
| sandbox delete | `cgroup.kill`; all descendants gone |
| daemon graceful shutdown | all sandbox domains killed |
| daemon crash/restart | stale shbox domains reconciled |
| workspace after runtime becomes empty | preserved |
| tssh bootstrap SSH closes | tsshd survives |
| tssh UDP session active | process remains cgroup-owned |
| tssh ends | domain eventually becomes empty |

---

# Recommended implementation order

Do not start by changing SSH disconnect behavior.

Use this dependency order:

```text
M0  contract/tests
 ↓
M1  always-available process-domain API
 ↓
M2  cgroup populated/kill/remove semantics
 ↓
M3  stop normal direct-child descendant kill
 ↓
M4  always-cgroup LinuxLauncher
 ↓
M5  runtime-domain state machine
 ↓
M6  SSH transport detach
 ↓
M7  PTY detach semantics
 ↓
M8  runtime-scoped TMPDIR
 ↓
M9  delete via cgroup.kill
 ↓
M10 process-count semantics
 ↓
M11 shutdown/startup reconciliation
 ↓
M12 tssh E2E
 ↓
M13 legacy cleanup
```

The critical safety gate is:

> M1–M5 must be complete before M6 removes SSH-disconnect termination.

Until the cgroup is an authoritative ownership boundary and deletion races are closed, allowing processes to survive SSH disconnect would create unmanaged processes.

Each milestone should be implemented, mechanically tested, committed, and only then used as the base for the next milestone.