# Linux sandbox identity isolation with subordinate UID/GID

This is the active implementation plan for adding per-sandbox Linux identity isolation to shbox. It is intentionally implementation-ready: a future contributor should be able to resume from this file and the current tree without relying on chat history.

This plan is **design only**. The repository state used for this design was `main` at `deb3b4db090e8ab5f21bdc75744608a9ecb25ae9`. No implementation is included in this plan creation.

> **Repository note:** while this planning task was in progress, an untracked `docs/linux-identity-isolation.md` appeared in the authoritative worktree from another writer/process. It was not present at the initial clean Git checkpoint and was not created or modified by this task. It contains materially different decisions (notably a two-ID bootstrap model and POSIX-ACL fallback). **This top-level `PLANS.md` is the authoritative active implementation plan for this task; do not combine the two plans implicitly.** Reconcile or remove the competing draft explicitly before an implementation commit if it is still present.

## 0. Execution status (updated as implementation proceeds)

Implementation started 2026-09-04 on a native aarch64 Linux host (Oracle ARM, kernel 6.17 after the Ubuntu 24.04 upgrade). Record per phase: state, actual proof results, and discoveries that constrain later phases.

| Phase | State | Notes |
|---|---|---|
| I0 identity API freeze | **done** | See below. |
| I1 subid ledger | **done** | Ledger, delegation parser, and manager claim/delete/reconcile wiring are implemented; manager wiring landed after the config seam became available. |
| I2 parent mapping barrier | **done (native seam proof)** | Fresh `CLONE_NEWUSER` barrier, exact one-entry map verification, group clear, UID/GID 1000 transition, securebits/NNP/capability drop, and `ShadowUidGidMapper` are implemented. The Ubuntu 24.04 host keeps the distro `uidmap` package, while verified upstream shadow-utils 4.20.2 `getsubids/newuidmap/newgidmap` are installed under `/usr/local` for the production helper path. |
| I3 mount ns + broker | **in progress** | Engine-side prepared mount attachment, generation-scoped auxiliary mount-ID-map namespace, fixed-size SCM_RIGHTS broker protocol/client/server, source-root validation, and systemd units are implemented. 2026-09-04 review found the daemon side statically unreachable (engine_namespaces never set mount=true, so validate_identity failed every isolated launch before clone3; fixed by §24 R-0). Real root-broker/filesystem acceptance is still pending on a supported deployment host. |
| I4 network integration | not started | |
| I5 PID ns compatibility | not started | |
| I6 lifecycle/crash | **in progress** | Durable lease transitions are wired through manager create/delete/startup reconciliation; generation mount-ID-map FD cleanup and crash/native lifecycle acceptance remain. |
| I7 rollout/docs | **in progress** | `sandbox.identity`, broker deployment units, and platform/configuration docs are present; supported-host deployment and full acceptance evidence remain. |
| I8 default isolated | not started | |

**Phase I0 actual results** (`crates/shbox-sandbox` 37 lib tests + 28 integration tests pass; `crates/shbox` 189 unit + 26/32 ssh_auth):

- `IdentityPolicy` (`Host`/`CallerMappedRoot`/`Isolated(IsolatedIdentity)`) added to engine policy; `SandboxConfig.identity` added; `NamespacePolicy.user` removed (CLONE_NEWUSER now derives from identity policy in `namespace_flags`).
- `validate_identity`: isolated requires non-zero runtime/host IDs, a fresh mount namespace, and rejects non-empty `CapabilityPolicy::Retain`.
- `build_child_setup` rejects missing isolated mapping-barrier descriptors and rejects `host_uid == geteuid()` / `host_gid == getegid()`.
- shbox `SandboxLaunchPolicy::engine_identity()` added (Linux: `CallerMappedRoot` only for `network=disabled` — pre-I4 coupling preserved; non-Linux: `Host`). macOS `reject_linux_only_policy` rejects any non-Host identity.
- Spawn tests updated to `IdentityPolicy::CallerMappedRoot`; native behavior unchanged (`user_namespace_maps_caller_to_root` and PID-namespace suites pass).

**Phase I1 actual results** (26 new unit tests in `crates/shbox/src/sandbox/subid/`; whole-crate 215/215 unit tests pass):

- New module `crates/shbox/src/sandbox/subid/` with `delegation.rs` (`getsubids` output parser with checked range arithmetic, `query_delegation()` command wrapper, distinct `HelperMissing` diagnostic), `ledger.rs` (`LeaseRecord` v1 TOML schema keyed by 128-bit hex `lease_id` filename, atomic temp/write/fsync/rename/parent-fsync store with new `FaultPoint::Lease*` injection points, unknown/corrupt files fail closed), and `mod.rs` (`SubidAllocator` with selection mutex, lowest-available independent UID/GID selection skipping ID 0, `claim/activate/begin_release/finish_release/quarantine` with incarnation (ABA) guards, `validate_delegated` shrink check, per-state `PoolCapacity` exhaustion diagnostics, and `reconcile()` implementing the §7.5 state table gated on a caller-asserted `runtime_reconciled` proof).
- `Paths::subid_leases_root()` = `$XDG_DATA_HOME/shbox/subid-leases`, created 0700 and ensured with the other roots; `LeaseStore` re-creates its root 0700 explicitly (umask-independent, validated in tests).
- Storage fs helpers (`DirFd`, open/create/read/stat/rename/unlink-at, `sync_directory`, mode checks, `FaultInjector::trip`) are now `pub(crate)` in `sandbox/storage.rs` and shared with the ledger.
- All I1 proof-list items have passing unit tests (fragmented ranges, independence, parallel uniqueness, fault injection at every crash window, quarantine-not-free, churn recycling, duplicates block, shrink blocks without freeing, exhaustion diagnostics, ABA).

**Phase I1 deviation (historical, now resolved):** manager.rs integration was initially
deferred until the `sandbox.identity` config surface and engine barrier existed. It is
now wired under the I6 lifecycle seam: claim at sandbox creation, release after
runtime/storage cleanup, and startup reconciliation before launch admission.

**Phase I2 actual results:** the engine now owns the parent-side mapping barrier. The
child announces `MAP_READY`, the parent maps through `UidGidMapper`, reads back exact
single-entry `uid_map`/`gid_map` rows plus `setgroups=allow`, then releases the child.
The isolated child clears supplementary groups, transitions all UID/GID slots to
`1000:1000`, locks securebits, sets NNP, and drops all capabilities before exec. The
mapping seam is tested with the production `ShadowUidGidMapper` and its safer
`fd:N` helper form; there is deliberately no PID-path fallback. Ubuntu 24.04's
official `uidmap` package remains available for the base system, while the
verified upstream shadow-utils 4.20.2 helpers are installed in `/usr/local/bin`
and `libsubid.so.6` is kept in its private `/usr/local` library directory.

**Phase I3 current results:** isolated child setup accepts four parent-prepared FDs,
makes the inherited mount tree recursively read-only, and attaches only detached
workspace/runtime mounts with FD-only `move_mount`. A generation-scoped auxiliary
user namespace maps daemon IDs to the leased subordinate IDs and is pinned by an FD.
The shbox side speaks a fixed-size `SOCK_SEQPACKET` + `SCM_RIGHTS` protocol to a
root-only socket-activated broker. Broker requests are peer-credential checked,
source-root checked, and never contain command or pathname input. Root/filesystem
acceptance remains pending on a host with shadow-utils `fd:N` and a supported
ID-mapped backing filesystem.

**Current lifecycle hardening results:** startup reconciliation now distinguishes
`Active`, `Deleting`, and corrupt durable sandbox observations; inspection I/O
errors abort reconciliation instead of being treated as absence. Owner mismatches
quarantine both `Active` and `Releasing` leases. A quarantined identity may be
cleaned with its sandbox tree, but its lease remains quarantined and is never
silently recycled. Host-policy launches also reject an accidentally supplied
isolated lease. The complete workspace test run passes (`shbox` 223, CLI 6,
SSH 32, sandbox 37, spawn 34; 5 ignored benchmarks/tests), and `git diff --check`
is clean.

**Test-infrastructure fix (user-requested, outside the phase plan):** the ambient umask on this host is `0002`, and `tempfile` 3.27 creates directories with default (umask-dependent) permissions, so fixtures landed group-writable and the auth/config/paths validators — correctly — rejected them (26 unit + 6 ssh_auth failures on clean `main`). Fixed by making every validator-adjacent fixture explicitly private (0700 dirs / 0600 files) in `auth.rs`, `hostkey.rs`, `config.rs`, `paths.rs`, and `tests/ssh_auth.rs`; plus the harness root/intermediate dirs. A remaining ssh_auth nuance was fixed by the operator: OpenSSH sometimes renders a server-side channel failure without forwarding the daemon's generic unavailable message, so `sandbox_request_failed_closed` accepts both forms. The current workspace run passes under the default umask (223 + 6 + 32 + 37 + 34; 5 ignored benchmarks/tests).

**Environment discoveries (constrain verification here):**

- Host umask is `0002`; `crates/shbox` auth unit tests and 6 `ssh_auth` integration tests fail on **clean baseline** because test fixtures/config files land group-writable and the loader correctly rejects them. Pre-existing, unrelated to this plan; run `umask 022` to reduce (does not fix the 6 ssh_auth tests — also baseline-failing).
- Only `aarch64-unknown-linux-gnu` toolchain installed: macOS backend edits compile-verified by review only until CI runs them.
- One pre-existing clippy warning in `linux/cgroup.rs` (`manual_c_str_literals`), untouched by this work.
- Host is Ubuntu 24.04.4 (shadow 4.13): official `uidmap`/`libsubid4` remain installed, and verified upstream shadow-utils 4.20.2 `getsubids/newuidmap/newgidmap` are installed under `/usr/local` for shbox. The host has `shbox:231072:65536` subordinate UID/GID delegation, and the production `fd:N` mapper test passes under the loaded AppArmor profile. Native isolated-launch acceptance with the full broker/filesystem mount path remains pending because this host's unprivileged mount namespace boundary rejects the required mount-propagation operation.
- Passwordless sudo is available on this host and was used for the shbox deployment, systemd unit installation, and service restart.

## 1. Background and current state

shbox is a foreground SSH daemon with two intentionally different execution routes:

- a normal sandbox route keyed by `SandboxId`, with durable metadata/workspace and OS confinement; and
- the reserved admin `_` host route, which runs as the daemon account and deliberately bypasses sandbox confinement.

On Linux, normal sandbox launches are implemented through the in-workspace `shbox-sandbox` engine. The current Linux engine already owns:

- `clone3()` and pidfd-based process ownership;
- `CLONE_INTO_CGROUP` and cgroup v2 process/resource containment;
- user, PID, mount, IPC, UTS, and network namespace flags;
- Landlock filesystem/network confinement;
- seccomp-BPF;
- `PR_SET_NO_NEW_PRIVS`;
- capability reduction before `execve()`;
- fixed post-clone FD hygiene;
- a PID-namespace PID1 supervisor/reaper when requested.

The current user namespace implementation is **not identity isolation**. `NamespacePolicy.user: bool` means “create `CLONE_NEWUSER` and map the caller to namespace root”. `crates/shbox-sandbox/src/linux/mod.rs::build_child_setup()` formats:

```text
0 <daemon EUID> 1
0 <daemon EGID> 1
```

and `crates/shbox-sandbox/src/linux/child.rs::child_entry()` writes `setgroups=deny`, `uid_map`, and `gid_map` from inside the newly-created namespace. This is the `unshare --map-root-user` model. The host kernel identity remains the shbox daemon account.

The public shbox policy currently enables that user namespace only for `sandbox.network = "disabled"`, because an unprivileged daemon needs a user namespace in order to create the isolated network namespace. `outbound` currently shares the host network namespace.

The durable filesystem model is also relevant. `crates/shbox/src/sandbox/storage.rs` currently requires the sandbox directory, `metadata.toml`, and `workspace/` to be owned by the daemon EUID and rejects a workspace that is group/world writable. `metadata.toml` version 1 deliberately contains no process/platform fields. The backing workspace survives process-domain generations and SSH sessions until explicit sandbox deletion.

Linux process lifecycle is already sandbox-scoped. `crates/shbox/src/platform/linux.rs` maintains one cgroup process domain per live `SandboxId`, with a runtime generation containing a private `TMPDIR`. A generation can be drained and recreated while the durable sandbox/workspace continues to exist. Therefore subordinate identity cannot be tied to a cgroup generation: it must be tied to the durable sandbox/workspace lifetime.

Startup reconciliation is already fail-closed. `SandboxManager::reconcile_startup()` requires platform resource reconciliation to succeed before it removes any durable `Deleting` workspace. A failed reconciliation keeps the manager unavailable.

No current Issue or open PR was found for this identity-isolation work at plan creation time. No top-level `PLANS.md` existed. `.agents/skills/rolling-plan/SKILL.md` specifies top-level `PLANS.md` as the task-local active-plan convention when no other convention exists.

## 2. Goals

The implementation must make normal Linux sandbox identity a distinct security boundary from the host shbox daemon identity.

A completed implementation must provide all of the following:

1. Every isolated durable sandbox receives a unique subordinate UID and a unique subordinate GID delegated to the shbox daemon account.
2. The runtime command sees a stable numeric UID/GID inside its user namespace; the initial design uses UID/GID `1000`.
3. The host-visible runtime UID/GID is the sandbox's leased subordinate UID/GID, never the daemon EUID/EGID.
4. Namespace UID/GID `0` is not mapped in the normal isolated runtime namespace.
5. Two sandbox incarnations with simultaneously non-free leases never share a host subordinate UID or GID. A numeric pair may be assigned to a later sandbox only after the earlier lease has completed the verified release transaction.
6. No `/etc/passwd` or `/etc/group` user is created per sandbox; there is no `useradd`/`userdel` lifecycle.
7. A sandbox's subordinate identity remains stable across SSH sessions, concurrent launches, cgroup/runtime generations, and daemon restart until the sandbox is deleted.
8. Deleted identities are automatically reclaimable only after a crash-safe proof that no process, namespace-scoped writable filesystem, mount projection, runtime temp, or persistent sandbox backing associated with the lease remains. Uncertain cleanup quarantines the lease instead of reusing it.
9. Persistent backing workspaces remain daemon-owned on the host; recursive `chown` is not the normal path.
10. The sandbox sees its backing workspace and private runtime temp through ID-mapped mounts, making them appear owned by its runtime UID/GID while preserving host backing ownership.
11. cgroups remain the process/resource/lifecycle containment mechanism. User namespaces remain the identity/capability/DAC mechanism. Neither is used as a substitute for the other.
12. Landlock, seccomp, no-new-privs, capability dropping, mount/network namespaces, and cgroups remain defense-in-depth around the new identity layer.
13. Missing user namespace, subordinate-ID, mapping-helper, broker, ID-mapped mount, filesystem, or policy capability causes an explicit diagnostic and fail-closed sandbox launch. There is no silent fallback to daemon identity.
14. The admin `_` host route remains a distinct route and is not forced through isolated sandbox identity.

## 3. Non-goals

This work does not add:

- per-sandbox entries in `/etc/passwd`, `/etc/shadow`, or `/etc/group`;
- `useradd`, `userdel`, home-directory lifecycle, PAM sessions, login accounting, or system NSS identities;
- a full container root filesystem, chroot, pivot-root image manager, or package image lifecycle;
- a promise that shbox is equivalent to a VM against a hostile kernel exploit;
- time-based, best-effort, or unproven subordinate-ID reuse; IDs are reclaimed only through the verified release state machine;
- recursive ownership conversion of a persistent workspace as the standard launch path;
- a user-facing requirement to configure concrete UID/GID numbers per sandbox;
- changes to the admin `_` host-route identity model;
- a replacement for cgroup v2 process inventory/cleanup;
- a replacement for Landlock/seccomp policy;
- macOS subordinate IDs. macOS remains Seatbelt-based and has no Linux user-namespace identity primitive.

Numeric UID `1000` is a namespace-local runtime identity only. This plan does not require `getpwuid(1000)` to resolve to a synthetic account. If application compatibility later requires a synthetic passwd/group view, that is separate work and must not create host accounts.

## 4. Threat model

The primary threat addressed here is compromise or malicious behavior of code running through the normal sandbox route.

Assume a sandboxed command may:

- execute arbitrary user-controlled binaries and shell code;
- deliberately probe shbox management state and other sandboxes;
- exploit a missing or overly-broad Landlock rule;
- create files and leave detached descendants;
- call `setuid`, `setgid`, namespace, mount, and capability-related syscalls unless another layer blocks them;
- race deletion, restart, and concurrent launches;
- leave files behind in any host location it somehow reached through a separate policy defect.

The identity layer is intended to ensure that a Landlock/seccomp policy mistake does not immediately turn into access with the daemon account's DAC identity. It is also intended to make private files created by sandbox A fail ordinary DAC checks when accessed by sandbox B's distinct host identity.

Out of scope remain:

- compromise of the Linux kernel itself;
- compromise of the privileged ID-mapped-mount broker described below;
- an admin credential using the `_` host route;
- arbitrary files intentionally made world-readable/writable by the operator or sandbox workload;
- shared resources whose own ACLs deliberately grant access to both subordinate identities.

## 5. Security invariants

The implementation is incomplete unless native Linux tests prove these invariants.

### 5.1 Runtime identity

For an isolated normal sandbox:

- runtime process host UID != daemon EUID;
- runtime process host GID != daemon EGID;
- sandbox A host UID/GID != sandbox B host UID/GID whenever both leases are simultaneously non-free;
- all concurrent launches of the same durable sandbox use the same leased host UID/GID;
- inside the sandbox, real/effective/saved/fs UID are the configured runtime UID (`1000` initially);
- inside the sandbox, real/effective/saved/fs GID are the configured runtime GID (`1000` initially);
- namespace UID `0` and GID `0` have no mapping;
- `setresuid(0, 0, 0)` and `setresgid(0, 0, 0)` cannot restore a bootstrap/root identity;
- supplementary groups are empty before user code executes;
- `CapEff`, `CapPrm`, `CapInh`, and `CapAmb` are zero at runtime;
- `NoNewPrivs` is `1` before `execve()`;
- no setuid/file-capability exec can regain a more privileged identity.

### 5.2 DAC separation

With only DAC considered:

- a daemon-owned mode `0600` host file is not readable by a sandbox runtime process;
- a mode `0600` file whose raw host ownership is sandbox A's subordinate UID is not readable by sandbox B;
- a Landlock test seam that deliberately omits a denial must not make daemon-private `0600` state readable, demonstrating independent DAC protection;
- a subordinate ID is reusable only after the runtime topology has made persistent raw-subordinate-owned host inodes impossible and lifecycle cleanup has completed; ambiguous state quarantines the ID.

### 5.3 Workspace backing ownership

- durable `workspace/` remains daemon-owned in the host namespace;
- a sandbox sees its workspace root as runtime UID/GID `1000:1000` through an ID-mapped mount;
- files created by the sandbox through that mount are daemon-owned in the host backing tree;
- reopening the same durable sandbox in a later runtime generation sees the same contents with the same namespace ownership;
- no recursive `chown` occurs during ordinary launch, generation rotation, restart, or deletion;
- normal shbox isolated launches expose no inherited writable host regular-file or directory FD to user code: stdio is pipe/PTY, `SandboxConfig.inherited_fds` remains empty, setup/broker/source/target FDs are closed by FD hygiene before `execve`.

### 5.4 Lifecycle

- user namespace disappearance itself requires no explicit persistent cleanup;
- process teardown remains cgroup-authoritative;
- subordinate lease lifetime is durable-sandbox-authoritative;
- a daemon crash cannot cause an issued UID/GID to be silently returned to the free pool;
- `Active`, `Reserved`, `Releasing`, and `Quarantined` leases all exclude their IDs from allocation; only absence of a fully released record is free;
- an ambiguous/corrupt lease is quarantined rather than reused;
- a current `/etc/subuid`/`/etc/subgid` (or NSS subid backend) change that removes an active lease blocks new isolated launches using that lease;
- unsupported capability never silently selects the old daemon-identity path.

## 6. Explicit architecture decisions

These decisions are normative for implementation unless a later code-level constraint is demonstrated and recorded in this file before implementation diverges.

### Decision A: identity is separate from namespace topology

Replace the semantic overload of `NamespacePolicy.user: bool` with an explicit engine identity policy. The engine needs three states during migration and for direct `shbox-sandbox` callers:

```rust
pub enum IdentityPolicy {
    /// No user namespace identity translation.
    Host,

    /// Legacy engine behavior: create a user namespace and map
    /// namespace 0 -> caller EUID/EGID. Kept only for compatibility and
    /// namespace-topology use cases during migration.
    CallerMappedRoot,

    /// Create a fresh user namespace for this launch. The child blocks on a
    /// parent mapping barrier; a parent-side mapper installs exactly the
    /// supplied delegated UID/GID entries before child setup continues.
    Isolated(IsolatedIdentity),
}

pub struct IsolatedIdentity {
    pub runtime_uid: u32, // 1000 in shbox v1
    pub runtime_gid: u32, // 1000 in shbox v1
    pub host_uid: u32,    // leased subordinate UID
    pub host_gid: u32,    // leased subordinate GID
}
```

`NamespacePolicy` continues to describe PID/mount/IPC/UTS/network topology, not “who the process is”. In isolated mode `CLONE_NEWUSER` is derived from `IdentityPolicy::Isolated`; shbox also requests a fresh mount namespace for every isolated launch and requests a fresh network namespace when `network=disabled`.

Do **not** design isolated launch around joining a previously prepared process user namespace. `setns()` into a user namespace requires `CAP_SYS_ADMIN` in the target user namespace, which the normal unprivileged daemon does not hold. Fresh `CLONE_NEWUSER` plus a parent mapping barrier fits the current `clone3` architecture and avoids that privilege requirement.

The generic engine must not allocate durable subordinate IDs or know `SandboxId`. It consumes selected numeric map entries and a parent-side mapping seam. The shbox application owns the durable allocator and supplies a shadow-utils-backed mapper (`newuidmap`/`newgidmap`) to the Linux engine. `CallerMappedRoot` may retain its existing child-self-map path during migration.

### Decision B: one subordinate UID and one subordinate GID per durable sandbox

The allocation unit is exactly one UID plus one GID per durable sandbox, not a large range and not one allocation per process or cgroup generation.

Normal runtime mapping is:

```text
process userns uid_map:  1000 <leased-subuid> 1
process userns gid_map:  1000 <leased-subgid> 1
```

UID/GID zero are deliberately absent.

The one-entry map was validated in Linux syscall probes: a fresh user namespace with only `1000 -> subordinate` can transition to UID/GID1000 with zero effective capabilities, and UID0 cannot be selected because it is unmapped. A separate probe also proved that a fresh user+mount namespace child can attach a privileged-broker-created detached ID-mapped mount and observe the intended 1000:1000 ownership.

A range larger than one is not justified by the current product contract. If a later feature genuinely requires multiple namespace users, evolve the durable lease schema to ranges; do not reserve 65,536 IDs per sandbox preemptively.

### Decision C: lease lifetime is the durable sandbox lifetime

A lease is keyed to a specific durable sandbox incarnation, not to:

- an SSH connection;
- a shell/exec channel;
- a process;
- a `ProcessDomain` cgroup;
- a runtime temp generation.

The same durable sandbox keeps the lease through generation drain/recreation and daemon restart. Explicit sandbox deletion transitions it to `Releasing`; the pair becomes free only after verified cleanup and durable lease-record removal.

### Decision D: subordinate IDs are recycled, but only after a verified release barrier

A permanent `Retired` set would make the pool monotonically exhaust under normal create/delete churn, so it is not the design. IDs are reusable after explicit sandbox deletion, but **only** after a durable release transaction proves that every resource capable of carrying that sandbox identity is gone.

The key filesystem invariant is structural rather than a whole-host inode scan: before user code runs, the fresh sandbox mount namespace makes the inherited host mount tree recursively read-only with `mount_setattr(..., AT_RECURSIVE, MOUNT_ATTR_RDONLY)`. The only writable regular-filesystem views subsequently attached are:

- daemon-owned workspace backing through an ID-mapped mount;
- daemon-owned runtime-temp backing through an ID-mapped mount; and
- explicitly-created ephemeral filesystems whose lifetime is bounded by the sandbox mount namespace.

The ID-mapped views translate sandbox writes back to daemon ownership in the raw host backing tree. `/dev/null` remains usable as a character device and does not create a persistent inode. No ordinary sandbox path receives a writable host directory whose new inodes would be raw-owned by the subordinate UID/GID. This mount-layer invariant is independent of Landlock, so a Landlock write-rule mistake alone cannot leave a persistent subordinate-owned host inode outside managed backing.

Lease states are `Reserved`, `Active`, `Releasing`, and `Quarantined`; **free is represented by no lease record**. All four recorded states exclude their UID/GID from allocation. `Active -> Releasing` is durable before destructive cleanup starts. Only after cgroup/process teardown, per-launch namespace disappearance, detached/idmapped mount teardown, runtime-temp deletion, workspace/sandbox-tree deletion, and parent-directory fsyncs succeed is the lease record itself removed and the lease directory fsynced. At that point the pair is reusable.

If any proof is missing or state is inconsistent, move/keep the lease in `Quarantined`; never infer free from age, lack of a process, or namespace disappearance alone. Pool exhaustion is therefore a real capacity condition only when all delegated IDs are simultaneously Reserved/Active/Releasing/Quarantined, not a consequence of historical sandbox churn.

### Decision E: subordinate delegation is discovered through shadow-utils semantics

Do not parse only `/etc/subuid` and `/etc/subgid` as the source of truth. Current shadow-utils supports an NSS `subid` backend selected through `/etc/nsswitch.conf`.

Use:

```text
getsubids <daemon-user>
getsubids -g <daemon-user>
```

for discovery/diagnosis, and use `newuidmap` / `newgidmap` to install subordinate mappings.

Before invoking the helpers, open `/proc/<keeper-pid>` as a directory FD and use the current shadow-utils `fd:N` form when supported:

```text
newuidmap fd:N 1000 <leased-subuid> 1
newgidmap fd:N 1000 <leased-subgid> 1
```

This avoids PID-reuse TOCTTOU when a namespace keeper dies during setup. The implementation must detect helper/version capability at startup/preflight rather than silently fall back to a racy path.

### Decision F: persistent backing remains daemon-owned; use ID-mapped bind mounts

Do not transfer the durable backing workspace to the subordinate UID.

For a daemon host UID/GID `DUID:DGID` and sandbox subordinate IDs `SUID:SGID`, create a separate mount-ID-map user namespace whose maps are:

```text
uid_map: DUID SUID 1
gid_map: DGID SGID 1
```

The sandbox process user namespace remains:

```text
uid_map: 1000 SUID 1
gid_map: 1000 SGID 1
```

Apply the mount mapping with `mount_setattr(..., MOUNT_ATTR_IDMAP, userns_fd=...)` to detached bind mounts of the daemon-owned workspace and runtime-temp backing.

This mapping direction was validated with a real Linux probe on tmpfs: a daemon-owned backing directory appeared as `1000:1000` in the process user namespace; a file created by namespace UID/GID 1000 remained owned by the daemon UID/GID in the raw host backing tree.

`recursive chown` is not a normal fallback. If an ID-mapped mount cannot be created, isolated launch fails closed.

### Decision G: do not grant CAP_SYS_ADMIN to the long-lived shbox daemon

`MOUNT_ATTR_IDMAP` requires `CAP_SYS_ADMIN` in the user namespace in which the backing filesystem was mounted. Normal ext4/xfs/etc. host filesystems are mounted in the initial user namespace. A daemon that is intentionally unprivileged cannot perform this operation itself merely by entering its sandbox user namespace.

Do not add ambient `CAP_SYS_ADMIN` to `shbox.service`.

Instead add a narrow, socket-activated **ID-map mount broker** running from the same shbox binary in an internal mode. This preserves a single installed binary while keeping initial-user-namespace `CAP_SYS_ADMIN` out of the network-facing daemon process.

The broker is not a general command runner and must not accept arbitrary mount paths from a client. Prefer FD-based requests over path strings.

A POSIX-ACL projection is **not** the automatic fallback in this plan. It would cause sandbox-created backing inodes to become subordinate-owned, require lease-aware traversal/cleanup of hostile mode bits, and change the current daemon-owned storage invariant. Because the requested security model explicitly calls for fail-closed behavior when ID-mapped mounts are unavailable, v1 treats broker/idmapped-mount support as a required isolated-mode capability. ACL projection can be reconsidered later as a separately reviewed backend, not as silent degradation.

### Decision H: process user/mount/network namespaces are fresh per launch; only mount-ID-map state may be generation-scoped

Do not persist or share the process user namespace between launches. Each isolated launch performs one outer `clone3()` with:

- `CLONE_NEWUSER` always;
- `CLONE_NEWNS` always, because writable backing must be overmounted with an ID-mapped view;
- `CLONE_NEWNET` when `network=disabled`;
- optional IPC/UTS/PID flags requested by the generic engine policy;
- existing `CLONE_PIDFD` and `CLONE_INTO_CGROUP` behavior where applicable.

Different concurrent launches of the same durable sandbox therefore use different user/mount/network namespace instances but install the same `1000 -> leased-subid` / `1000 -> leased-subgid` maps. Identity stability is the leased **host ID**, not namespace inode reuse.

A Linux `DomainSlot` generation may retain one auxiliary **mount-ID-map user namespace FD** whose only purpose is to describe the `daemon UID/GID -> leased subordinate UID/GID` mapping consumed by `MOUNT_ATTR_IDMAP`. No runtime process joins that namespace. A short-lived keeper is used only long enough to install the map and open the namespace FD; the FD itself can then pin the namespace for the generation.

At launch time the privileged broker creates fresh detached ID-mapped mount objects for workspace and runtime temp and returns those mount FDs to the daemon. The fresh launch child attaches them inside its own new mount namespace. Thus the broker does not enter sandbox namespaces and the daemon never needs `setns()`.

When a process-domain generation drains, drop the auxiliary mount-ID-map userns FD only after all launches are gone, then clean runtime temp and cgroup state. The durable subid lease remains Active until sandbox deletion.

PID namespaces remain special because the existing outer clone becomes namespace PID1 and creates PID2. The fresh user/mount namespace is still created by that same outer clone; the parent installs its maps before PID1 proceeds to nested `CLONE_INTO_CGROUP`.

## 7. Durable subordinate-ID allocator

### 7.1 Storage location

Keep Linux lease state separate from portable sandbox `metadata.toml`.

Add a daemon-owned directory such as:

```text
$XDG_DATA_HOME/shbox/subid-leases/
```

Each non-free pair receives one lease record named by a random lease token, for example:

```text
subid-leases/<128-bit-token>.toml
```

Suggested schema:

```toml
version = 1
lease_id = "..."
sandbox_id = "dev"
owner = "SHA256:..."
uid = 100000
gid = 200000
state = "reserved" # reserved | active | releasing | quarantined
```

`uid` and `gid` need not have the same numeric value. Treat them as independent delegated pools. Free is represented by **absence of a lease record**; there is no persistent `Free` record and no permanent `Retired` history.

Do not include process IDs, namespace inode numbers, cgroup generation numbers, or helper paths in this durable record.

### 7.2 Why the lease is not embedded in sandbox metadata

`metadata.rs` currently makes a useful portability/lifecycle separation: durable sandbox ownership can be validated without reconstructing Linux platform state. Preserve that property. A macOS sandbox should not suddenly require Linux subid fields.

A separate ledger is also the transaction boundary that prevents reuse while deletion/recovery is incomplete. It may retain `Releasing` or `Quarantined` records after the sandbox tree itself is partly or wholly gone.

### 7.3 Allocation algorithm

Under a process-local allocator mutex, and while the existing daemon singleton/data-root locks prevent a second shbox daemon from allocating from the same ledger:

1. Query the current subordinate UID and GID delegations for the daemon account using `getsubids` and `getsubids -g`.
2. Parse all delegated ranges with checked integer arithmetic. Reject zero-length ranges, wraparound, malformed output, and values outside Linux ID limits.
3. Scan and validate every existing lease file. Any corrupt record blocks allocation rather than being ignored.
4. Build `unavailable_uid` and `unavailable_gid` sets from every `Reserved`, `Active`, `Releasing`, and `Quarantined` record.
5. Select one currently-delegated UID not in `unavailable_uid` and one currently-delegated GID not in `unavailable_gid`. Lowest-available is deterministic and adequate; no random allocator is required.
6. Generate a random lease token.
7. Durably publish one `Reserved` record with temp-file/write/fsync/rename/parent-fsync semantics equivalent to the existing metadata writer.
8. Create/publish the durable sandbox storage.
9. Durably transition the lease to `Active`.
10. Only after step 9 may `claim()` return a handle that can launch.

If sandbox publication fails before it can become launchable, clean any partial sandbox tree under the same lifecycle lock and remove the `Reserved` lease record only after absence is durably established. If publication outcome is ambiguous, transition to `Quarantined` instead of freeing the IDs.

### 7.4 Concurrent sandbox creation and ABA prevention

One allocator mutex serializes pair selection and durable lease publication. This is independent of the per-`SandboxId` lifecycle lock, because two different sandbox IDs can otherwise select the same free pair concurrently.

The random `lease_id` identifies one sandbox incarnation. Any cleanup/release operation must compare the expected `lease_id`; a stale cleanup from an old incarnation must never remove a newer lease record that happens to use the same `SandboxId` or numeric pair.

Do not hold the allocator mutex across slow namespace creation, helper invocation, mount broker calls, process launch, or network I/O. It covers delegation snapshot + ledger validation + allocation/release record transitions.

### 7.5 Existing sandbox lookup and recovery states

At startup and before an isolated launch:

- `Reserved + sandbox absent`: finish cleanup of any partial managed tree; then remove the record and fsync the lease directory, making the pair free.
- `Reserved + matching Active sandbox metadata`: this is the crash window after sandbox publication but before lease activation; validate owner/incarnation and promote to `Active` before any launch admission.
- `Active + matching Active/Deleting sandbox`: normal valid state.
- `Active + sandbox absent`: impossible under the defined delete transaction (`Active -> Releasing` precedes tree removal); quarantine instead of freeing.
- `Releasing + sandbox present`: resume deletion.
- `Releasing + sandbox absent`: after startup cgroup/runtime reconciliation proves no process or ephemeral state remains, remove the lease record and fsync its directory; the pair becomes free.
- `Quarantined`: never allocate automatically. Operator repair or a future explicit verified recovery path is required.
- duplicate lease IDs, duplicate unavailable UID/GID values, owner mismatch, or more than one live lease for the same sandbox incarnation: corruption and fail closed.

### 7.6 Delegation changes

Do not assume `/etc/subuid` and `/etc/subgid` are process-lifetime immutable.

Refresh delegation:

- at Linux launcher preflight for diagnostics;
- before every new allocation;
- before every auxiliary mount-ID-map user namespace creation and before every isolated launch map is installed for an existing lease.

If an active/releasing lease is no longer inside the daemon's current delegated ranges, keep it reserved in the ledger. New launches requiring that map fail closed. Deletion must remain possible without recreating the process user namespace: cgroup termination and removal of daemon-owned backing do not depend on the subordinate mapping.

A freed pair is eligible for later allocation only if it is still delegated at that future allocation time.

### 7.7 Exhaustion and reclamation

Pool capacity is approximately the number of delegated IDs minus currently `Reserved`, `Active`, `Releasing`, and `Quarantined` IDs. Normal successfully deleted sandboxes do **not** consume capacity permanently.

If no free UID or GID remains, allocation fails closed and reports separate UID/GID capacity plus counts by lease state. The expected remedies are to let pending `Releasing` cleanup complete, repair genuinely `Quarantined` entries, or enlarge the account's subordinate delegation; users never configure concrete per-sandbox IDs.

## 8. Race-free namespace bootstrap

The current child-side `/proc/self/{uid,gid}_map` write cannot install arbitrary subordinate IDs for an unprivileged daemon. Isolated mode therefore uses a fresh user namespace per launch and a parent-side mapping handshake while preserving the existing spawn-owner thread and exec-status pipe.

### 8.1 Runtime-generation preparation

A runtime generation whose durable lease is already Active prepares only generation-scoped resources:

```text
LinuxLauncher
  validate Active lease against current subid delegation
  create/obtain cgroup process domain
  create daemon-owned runtime-temp backing

  create auxiliary mount-ID-map userns keeper (CLONE_NEWUSER only)
  keeper stops at mapping barrier
  parent/newuidmap installs: <daemon UID> -> <leased subuid>
  parent/newgidmap installs: <daemon GID> -> <leased subgid>
  read uid_map/gid_map back exactly
  open /proc/<keeper>/ns/user
  release/exit keeper; retain only the userns FD

  publish DomainSlot generation with:
    cgroup + runtime-temp backing + mount-ID-map userns FD
```

The auxiliary mapping namespace is never joined by user code. It exists only as the ID-map descriptor used by `mount_setattr(MOUNT_ATTR_IDMAP)`.

### 8.2 Per-launch parent sequence

Before the outer sandbox `clone3()`:

1. Canonicalize/validate workspace as today and open `O_PATH|O_DIRECTORY|O_NOFOLLOW` FDs for workspace and runtime-temp backing.
2. Ask the privileged broker to create **detached** ID-mapped clones of those two source FDs using the generation's mount-ID-map userns FD. The broker returns mount FDs through `SCM_RIGHTS`; it does not attach them anywhere.
3. Prepare Landlock, seccomp, stdio, PTY/session state, exec-status pipe, and a dedicated mapping synchronization channel.
4. Prepare destination `O_PATH` FDs that refer to workspace/runtime-temp mountpoints in the inherited mount tree; these FDs remain valid after `CLONE_NEWNS` and let the child attach mounts without pathname lookup.
5. Outer `clone3()` uses `CLONE_NEWUSER | CLONE_NEWNS` plus requested PID/IPC/UTS/network flags, `CLONE_PIDFD`, and existing cgroup placement rules.
6. Child performs only PDEATHSIG/liveness setup, emits `MAP_READY`, and blocks.
7. Parent opens `/proc/<child-pid>` once and invokes the configured mapper with the proc-dir `fd:N` form:

   ```text
   newuidmap fd:N 1000 <leased-subuid> 1
   newgidmap fd:N 1000 <leased-subgid> 1
   ```

8. Parent reads back `uid_map`, `gid_map`, and `setgroups`. Exact one-entry maps are mandatory and `setgroups` must still be `allow` so inherited supplementary groups can be cleared.
9. Only then send `MAP_INSTALLED`. Any failure kills/reaps the child through the existing pidfd path and closes the detached mount FDs; no user code runs.

The `fd:N` helper form is mandatory when the installed shadow-utils supports it, because it prevents PID-reuse TOCTTOU between opening `/proc/<pid>` and helper map writes. Do not silently fall back to a decimal PID on a support tier that claims race-free isolated identity.

### 8.3 Why `setgroups=allow` is required in isolated mode

Current caller-root code writes `setgroups=deny` because an unprivileged self-write of `gid_map` requires it. Isolated mode is different: `newgidmap` validates the delegated subgid and performs the privileged parent-side write. Current shadow-utils leaves `setgroups` at its default `allow` when a mapping is backed by a subordinate-GID delegation.

The parent must verify `/proc/<child>/setgroups == "allow"` after `newgidmap`. The child then executes `setgroups(0, NULL)` immediately after the mapping barrier and before any filesystem lookup or user-controlled operation. If `setgroups` is denied or clearing groups fails, launch fails closed. Never carry the daemon's supplementary groups into runtime merely because those group IDs appear unmapped inside the namespace.

### 8.4 Child setup after the mapping barrier

After `MAP_INSTALLED`, the trusted child bootstrap is intentionally narrow:

1. clear supplementary groups;
2. make `/` recursively private in the fresh mount namespace;
3. attach the broker-produced detached workspace and runtime-temp mounts with `move_mount()`, using FD-only source/target forms;
4. if a PID namespace is active, execute the existing nested PID2 `clone3(CLONE_INTO_CGROUP)` **before** changing the raw kernel UID/GID, because cgroup delegation currently belongs to the daemon account;
5. immediately transition the user-process branch (and separately harden PID1) to real/effective/saved GID 1000 and UID 1000;
6. lock the selected securebits, set `PR_SET_NO_NEW_PRIVS`, and reduce effective/permitted/inheritable/ambient capabilities to zero; narrow the bounding set while the required setup capability is still available;
7. only after the identity transition perform user-process `setsid`/TTY/chdir setup against the ID-mapped workspace view;
8. enforce Landlock and seccomp;
9. perform FD hygiene, including all mapping/mount/helper setup FDs;
10. `execve()`.

Before step 5 the child still carries the daemon's raw kernel UID/GID inherited across `clone3`; no user code and no user-controlled pathname lookup is permitted in this interval. The only allowed operations are the fixed mapping barrier, group clear, mount-namespace setup/FD-based mount attach, and (for PID namespaces) the existing nested cgroup clone. This TCB window is tested and kept allocation-free.

For the normal non-PID shbox path, `CLONE_INTO_CGROUP` already happens atomically in the outer clone, so the child can transition to the subordinate runtime identity immediately after mount attachment.

### 8.5 Detached mount FD handoff is part of the design

A Linux syscall probe performed while writing this plan proved the intended privilege split: a process with initial-user-namespace `CAP_SYS_ADMIN` created a detached ID-mapped tmpfs bind mount, a fresh unprivileged user+mount namespace child received/inherited that detached mount FD, and the child successfully attached it with `move_mount()` using `CAP_SYS_ADMIN` only in its own user namespace. The child then switched to UID/GID1000 and observed the mapped ownership.

Therefore the privileged broker need not `setns()` into the sandbox mount namespace. Its responsibility stops at constructing and validating detached mount objects.

## 9. Launch-time identity transition

`IdentityPolicy::Isolated` is a **fresh-userns + parent-mapping** launch mode, not a namespace-join mode.

The existing Linux engine remains responsible for the race-sensitive boundary from `clone3()` through confirmed `execve()`. The new parent/child handshake is integrated alongside the existing status pipe:

```text
parent                         child
------                         -----
prepare policy/mount FDs
clone3(NEWUSER|NEWNS|...)
                               PDEATHSIG/liveness
                               MAP_READY ->
install uid/gid maps
verify maps + setgroups
MAP_INSTALLED ---------------->
                               setgroups([])
                               private mount propagation
                               attach detached ID-mapped mounts
                               [nested PID2 clone if requested]
                               setresgid(1000,...)
                               setresuid(1000,...)
                               securebits / NNP / capabilities=0
                               stdio/session/chdir
                               Landlock
                               seccomp
                               close_range / execve
exec-status EOF <-------------
```

No namespace UID/GID 0 mapping exists, so after the switch there is no mapped bootstrap/root identity to regain. The final invariant is independent of implementation detail: namespace real/effective/saved/fs IDs are 1000, host kernel IDs are the leased subordinate pair, supplementary groups are empty, runtime capability sets are zero, and NNP is set.

Exact securebits/bounding-set sequencing remains an implementation proof item because Linux capability transitions are subtle; the implementation must derive the order from `capabilities(7)` and assert the final `/proc` state, not preserve capabilities merely to make setup convenient.

`CapabilityPolicy::Retain(...)` is incompatible with shbox's normal isolated policy. The public shbox policy continues to use DropAll. For the generic engine, reject retained capabilities with `IdentityPolicy::Isolated` initially unless a separately reviewed capability-bearing isolated mode is designed.

## 10. Workspace and ID-mapped mount design

### 10.1 Backing view versus sandbox view

Host/daemon view:

```text
$XDG_DATA_HOME/shbox/sandboxes/<id>/workspace
owner = daemon UID:GID
mode  = 0700
```

Sandbox mount view at the same pathname inside the generation's mount namespace:

```text
owner visible to process = 1000:1000
backing inode owner       = daemon UID:GID
```

The runtime-temp backing receives the same treatment.

The admin `_` host route never enters this mount namespace. It continues to see the ordinary host filesystem and daemon ownership.

### 10.2 Read-only base mount tree: prerequisite for safe UID reuse

After `CLONE_NEWUSER|CLONE_NEWNS`, parent mapping completion, and recursive-private propagation—but **before** attaching any writable view—the trusted child bootstrap applies:

```text
mount_setattr(AT_FDCWD, "/", AT_RECURSIVE,
              attr_set = MOUNT_ATTR_RDONLY)
```

This makes the inherited host mount tree read-only at the VFS mount layer inside the sandbox namespace. `mount_setattr()` explicitly supports `AT_RECURSIVE` mount-tree attribute changes; a focused Linux probe during plan creation confirmed that a non-root caller in a fresh user+mount namespace could apply this operation and an otherwise writable `/tmp` then returned `EROFS` on file creation.

This is a security invariant, not merely hardening. Automatic subordinate-ID reuse is permitted only because user code cannot create a persistent raw-subordinate-owned inode on an arbitrary host filesystem even if a Landlock write rule is accidentally broadened. After the base tree becomes read-only, the bootstrap may add only a closed set of writable views:

1. ID-mapped daemon-owned `workspace/` backing;
2. ID-mapped daemon-owned runtime-temp backing;
3. explicitly-created ephemeral filesystems whose contents vanish with the launch mount namespace; and
4. non-inode-creating device operations already required by the runtime, currently `/dev/null`.

No ordinary configuration field may add an arbitrary writable host directory without also defining an ownership-preserving projection and updating the lease-reclamation proof. Existing `FilesystemPolicy::Restricted.read_write` therefore cannot by itself make a host mount writable: Landlock permission and mount-layer writability are independent gates.

The same rule applies to inherited FDs. A writable directory/file descriptor opened in the parent mount namespace could bypass pathname topology assumptions, so public shbox isolated policy must keep `inherited_fds` empty and close all setup/broker/source/target descriptors before `execve`. Any future feature that deliberately passes writable host FDs must be incorporated into the ownership/reclamation proof before UID reuse remains enabled.

If recursive read-only application fails on the target kernel/mount topology, isolated launch fails closed. Do not weaken this to “Landlock alone will prevent stale ownership” when automatic UID/GID reuse is enabled.

### 10.3 Broker primitive sequence

For each required writable backing directory, the privileged broker performs only construction of a detached mount object:

1. receive an already-open, validated `O_PATH|O_DIRECTORY|O_NOFOLLOW` source FD plus the mount-ID-map user namespace FD from the daemon;
2. clone the source as a detached bind mount with `open_tree(source_fd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)`;
3. apply `MOUNT_ATTR_IDMAP` with `mount_setattr(detached_fd, "", AT_EMPTY_PATH, ...)` using the supplied mount-ID-map user namespace FD;
4. return the detached mount FD to the daemon via `SCM_RIGHTS`;
5. close all broker-side request/temporary FDs.

The broker does **not** call `setns()` and does **not** attach mounts. The unprivileged sandbox child, after its fresh `CLONE_NEWUSER|CLONE_NEWNS` mapping barrier, owns `CAP_SYS_ADMIN` in the user namespace that owns its mount namespace and attaches each detached mount itself with `move_mount(MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)`.

This split minimizes initial-user-namespace privilege: the broker needs enough privilege for `OPEN_TREE_CLONE` and `MOUNT_ATTR_IDMAP`; target mount-namespace mutation stays inside the sandbox bootstrap.

### 10.4 Broker trust boundary

Use a Unix `SOCK_SEQPACKET`/`SOCK_STREAM` socket created by a systemd socket unit with mode/ownership restricting clients to the shbox service account. Additionally verify `SO_PEERCRED`; never trust filesystem socket permissions alone.

The broker request should be fixed-size/versioned and carry identifiers only for logging/correlation. Security-relevant objects arrive as `SCM_RIGHTS` FDs.

The broker must independently validate:

- peer UID is exactly the configured shbox daemon UID;
- source FDs are directories;
- source stat ownership is daemon UID/GID and mode is not group/world writable;
- source objects are beneath approved shbox data/runtime roots, using fd ancestry or an equivalent race-safe check rather than string prefix comparison;
- userns FD is a non-initial user namespace with exactly the expected one-entry UID/GID mapping (`daemon id -> leased subordinate id`);
- requested operation count and message sizes are bounded;
- no arbitrary filesystem type, device, mount source path, destination path, executable, or free-form mount flag is client-controlled.

The broker never invokes a shell, never executes sandbox/user commands, and never joins a client namespace.

### 10.5 systemd hardening

Add socket/service deployment artifacts, e.g.:

```text
deploy/systemd/shbox-idmap-broker.socket
deploy/systemd/shbox-idmap-broker.service
```

The service runs the same `/usr/local/bin/shbox` binary in a hidden/internal broker mode. It runs as root only because initial-user-namespace `CAP_SYS_ADMIN` is required for ID-mapping ordinary host filesystems. Bound its capabilities to the smallest demonstrated set, expected to be `CAP_SYS_ADMIN`; do not grant that capability to `shbox.service`.

Apply systemd hardening compatible with the required syscalls and filesystem roots: `NoNewPrivileges=yes`, a narrow `CapabilityBoundingSet`, protected system paths, explicit read/write roots, private devices where possible, and a syscall allowlist/denylist after the exact broker call graph is known. The broker has no network-facing listener.

### 10.6 Filesystem support

`mount_setattr(MOUNT_ATTR_IDMAP)` is Linux 5.12+. The underlying filesystem must support ID-mapped mounts. Capability detection must probe the actual filesystem that backs the shbox data/runtime roots; a kernel-version check alone is insufficient.

Do not assume that because a filesystem type normally supports ID maps, a particular layered/container/provider mount accepts them. During this design work, an ID-map attempt against the Docker overlay-backed `/tmp` returned `EINVAL`, while the same mapping on tmpfs succeeded. This is exactly why an operational probe is required.

A production preflight should create a daemon-owned scratch directory on the actual backing filesystem, request an ID-mapped detached clone through the broker, attach it in a throwaway mount namespace, verify ownership translation and write-back ownership, then tear it down. No user data is touched.

### 10.7 Landlock interaction

ID-mapped mounts here are bind-mount views of the same underlying hierarchy, not OverlayFS copies. Linux Landlock documents that path-beneath restrictions follow bind-mounted hierarchies because they refer to the same files.

Nevertheless, add an explicit native test proving the current parent-prepared Landlock rules still allow the intended workspace ID-mapped view and still deny sibling/management paths. Do not infer this from documentation alone when changing the engine mount topology.

## 11. cgroup lifecycle integration

Do not merge identity ownership into the cgroup abstraction. The cgroup remains the authoritative process inventory and termination boundary.

### 11.1 Ordinary generation drain

When a runtime generation becomes empty without deleting the durable sandbox:

```text
last launch waiter/reaper completes
→ verify cgroup populated=0
→ prevent a new launch from joining the retiring generation
→ drop the generation mount-ID-map userns FD after all launch mount namespaces are gone
→ clean daemon-owned runtime-temp backing
→ remove empty cgroup
→ remove DomainSlot generation
→ KEEP durable subid lease Active
```

The exact order of cgroup-directory removal versus namespace/temp removal may be adjusted to fit the existing `DomainSlot` state machine, but ownership handles must never be discarded before the resource they protect is demonstrably gone. A failed cleanup remains represented by retryable state.

### 11.2 Sandbox deletion and lease release

Deletion should become:

```text
1. durably write sandbox metadata state=Deleting
2. durably transition lease Active -> Releasing
3. reject new launches and cancel registered runtime leases
4. graceful TERM / existing channel cleanup
5. cgroup.kill for the sandbox process domain
6. wait cgroup.events populated=0 and all pidfd/reaper cleanup barriers
7. prove all per-launch user/mount/network namespaces are gone; drop generation mount-ID-map userns FD
8. remove daemon-owned runtime-temp backing and fsync its parent
9. validate persistent workspace backing is still daemon-owned and contains no unexpected management object
10. remove the empty cgroup domain
11. safely remove daemon-owned workspace + sandbox metadata tree and fsync the sandbox/data roots
12. under the allocator lock, re-read the expected Releasing record and lease_id
13. unlink the lease record and fsync subid-leases/
14. only now is the UID/GID pair free for a later sandbox
15. remove in-memory sandbox record
```

The critical transaction boundary is step 13. A crash before the lease-directory fsync leaves the pair represented by `Releasing` (or an unlink whose durability is not yet trusted) and startup recovery must conservatively reconcile it before allocation. A new allocation never races ahead of that proof.

If workspace removal succeeds but lease-record removal does not, startup sees `Releasing + sandbox absent`, first completes global runtime/cgroup reconciliation, validates no managed backing remains for that lease, and then removes/fsyncs the record. The pair may then be reused.

If any earlier cleanup step fails, keep `Deleting + Releasing`; do not free the IDs. If state is inconsistent or ownership cannot be proven, transition to `Quarantined`.

### 11.3 Daemon shutdown


Graceful shutdown kills/drains each process domain and tears down generation mount-ID-map userns/runtime-temp state, but it does **not** release Active leases because durable sandboxes still exist. The next daemon reuses each Active lease for the same sandbox.

The second-signal force path may leave cgroup/temp effects for startup cleanup; per-launch user/mount/network namespaces disappear with their processes, but force shutdown never removes a lease record. Absence means free only after the normal verified release transaction.

## 12. Crash recovery and stale state

Startup reconciliation must be expanded into an explicit order:

1. validate/lock XDG roots as today;
2. load and validate the subordinate lease ledger; duplicate IDs or malformed records block allocation;
3. query current subid delegation and helper availability for diagnostics;
4. reconcile stale cgroup process domains: kill, wait empty, remove;
5. remove stale runtime-temp generations after process ownership is gone;
6. per-launch user/mount/network namespaces from the previous daemon disappear when their final cgroup-owned processes die; no persistent namespace cleanup record exists;
7. scan durable sandbox metadata/workspaces;
8. reconcile `Reserved`/`Active`/`Releasing`/`Quarantined` lease records against durable sandbox state;
9. finish partial `Reserved` creation cleanup or promote a proven published sandbox to `Active`;
10. resume every `Releasing` deletion; if its sandbox tree is already absent, verify runtime/cgroup/backing absence before deleting+fsyncing the lease record;
11. keep `Active` leases whose delegation disappeared reserved but unavailable for new launches;
12. quarantine impossible states such as `Active + sandbox absent`, owner/incarnation mismatch, or uncertain filesystem ownership;
13. only then mark `SandboxManager` ready and permit allocation from IDs with no remaining lease record.

A corrupt lease record is security-sensitive because the daemon may not know which numeric ID is unavailable. Do not skip it and continue allocation. Quarantine/fail closed until the ambiguity is repaired.

Crash safety specifically relies on the order `Active -> Releasing -> resource cleanup -> lease unlink -> lease-dir fsync`. No startup path may treat `Deleting`, `Releasing`, a missing cgroup alone, or elapsed time as proof that an ID is free.

## 13. Capability detection and diagnostics

Extend `SandboxCapabilities` and Linux launcher diagnostics enough to distinguish capability classes instead of returning a generic namespace error.

At minimum detect/report:

- user namespace syscall allowed;
- Ubuntu/AppArmor unprivileged-userns policy outcome where identifiable;
- `newuidmap` present and usable;
- `newgidmap` present and usable;
- `getsubids` present and usable;
- at least one subordinate UID range delegated to the daemon account;
- at least one subordinate GID range delegated to the daemon account;
- active lease still belongs to current delegation;
- fresh `clone3(CLONE_NEWUSER | CLONE_NEWNS)` plus parent mapping barrier succeeds;
- `open_tree` available;
- `mount_setattr` / `MOUNT_ATTR_IDMAP` available;
- `move_mount` available;
- backing filesystem accepts ID-mapped mounts;
- ID-map broker socket/service reachable and authentic;
- cgroup v2 parent remains available;
- Landlock ABI requirement remains satisfied;
- seccomp remains available where policy requires it.

Do not collapse all `EPERM` results into “kernel lacks user namespaces”. On Ubuntu 24.04+ AppArmor can restrict unprivileged user namespace creation. Diagnostics should mention the relevant AppArmor restriction/profile when that condition is observed. Deployment guidance should prefer a narrow AppArmor profile granting the shbox daemon the required `userns` capability, not disabling the host-wide restriction.

Capability checks used for a blocking native support claim must perform a real operation, not just inspect sysctls or kernel version strings.

## 14. Configuration and public API

### 14.1 shbox TOML

Keep the operator surface small. Add one sandbox identity policy field for rollout; do not expose subordinate numeric IDs.

Recommended schema:

```toml
[sandbox]
identity = "host"      # compatibility stage only
# identity = "isolated"
```

Semantics:

- `host`: preserve the current host-DAC identity behavior. When `network=disabled`, the engine may still use `CallerMappedRoot` solely to create the network namespace; externally the command still has daemon UID/GID and therefore this is **not** identity isolation.
- `isolated`: require subordinate lease + fresh per-launch user/mount namespace, parent-installed maps, and ID-mapped writable mounts. Any missing prerequisite fails closed.

Rollout changes the default in phases (section 18). After isolated identity has sufficient native acceptance evidence, Linux's omitted default becomes `isolated`. macOS continues to resolve the setting according to its platform contract; initially reject `identity="isolated"` on macOS as unsupported rather than pretending Seatbelt supplies subordinate identity.

Do not add `subuid_start`, `subuid_count`, `uid`, `gid`, helper paths, or broker mount flags to normal user configuration. Subordinate pools are an OS account/deployment concern.

### 14.2 `shbox-sandbox` API

Add identity policy to `SandboxConfig` and remove identity meaning from `NamespacePolicy.user`.

The isolated engine API should consume numeric runtime/host ID maps, prepared detached mount/target FDs, and a parent-side mapping seam. It creates the process user/mount namespace itself with `clone3`. The generic engine must **not** parse subordinate delegation, allocate durable IDs, or know `SandboxId`; those belong to the shbox application/lifecycle layer. The shbox Linux adapter supplies the shadow-utils mapper and selected subordinate IDs.

The engine continues to own the race-sensitive clone/child transition, capability/NNP/Landlock/seccomp ordering, and status-pipe fail-closed semantics.

## 15. Privileged broker protocol

Define the FD protocol before implementing privileged syscalls.

Suggested version-1 operation:

```text
CreateIdmappedMounts {
    protocol_version,
    request_id,
    expected_daemon_uid,
    expected_daemon_gid,
    leased_uid,
    leased_gid,
    source_count = 2,
    fds = [
      mount_idmap_userns,
      workspace_source,
      runtime_temp_source,
    ]
}
```

Successful response carries two detached mount FDs in the same stable order:

```text
Ok { request_id, mount_count = 2 }
SCM_RIGHTS = [workspace_detached_mount, runtime_temp_detached_mount]
```

Failure returns only a stable error code; detailed errno/object diagnostics stay in local logs. No raw SSH/session content crosses this socket.

The daemon opens destination `O_PATH` FDs itself and passes both destination FDs and returned detached mount FDs into `ChildSetup`. The child attaches them after the userns mapping barrier. The broker never receives a target mount namespace or destination path.

All request fields are bounds-checked and encoded with a fixed representation; do not use unconstrained TOML/JSON for a privileged syscall broker. Broker failure is launch-preparation failure and no sandbox child is cloned.

## 16. File/module-level change map

The implementation is expected to touch the following areas. Keep the split close to these responsibilities; do not let `platform/linux.rs` become the durable lease database.

### `crates/shbox-sandbox/src/policy.rs`

- add `IdentityPolicy` / `IsolatedIdentity` numeric map descriptor;
- remove `NamespacePolicy.user` identity semantics;
- require a fresh mount namespace for prepared ID-mapped mounts in isolated mode;
- validate incompatible capability/identity combinations.

### `crates/shbox-sandbox/src/linux/mod.rs`

- replace `format_identity_map(geteuid/getegid)` for isolated mode with a parent mapping barrier;
- add a Linux parent-side mapper seam used after `clone3(CLONE_NEWUSER...)` and before child continuation;
- pass selected one-entry UID/GID maps plus detached mount/source-target FDs into `ChildSetup`;
- retain legacy `CallerMappedRoot` self-map path explicitly during migration;
- derive `CLONE_NEWUSER` from identity policy while nonuser namespace flags remain topology policy;
- preserve spawn-owner thread, status pipe, pidfd, and `CLONE_INTO_CGROUP` guarantees.

### `crates/shbox-sandbox/src/linux/child.rs`

- replace isolated child-self-map writes with `MAP_READY` / `MAP_INSTALLED` barrier handling;
- clear supplementary groups immediately after parent map installation;
- make the fresh mount namespace private and attach prepared detached ID-mapped mounts using raw `move_mount` FD forms;
- add runtime GID/UID transition and securebits/identity failure stages;
- keep pre-transition operations fixed, FD-based, allocation-free, and free of user-controlled path lookup;
- close mapping/mount setup FDs before exec;
- integrate isolated identity with PID1/PID2 branch without executing user code as PID1.

### `crates/shbox-sandbox/src/linux/caps.rs`

- make zero-capability isolated transition explicit;
- add helpers/tests for securebits/bounding/ambient behavior;
- do not silently tolerate a capability state that violates runtime invariants.

### `crates/shbox-sandbox/src/error.rs` / validation

- add stable child stages/features for mapping barrier, recursive read-only mount-tree setup, writable-view attach, credential switch, subordinate identity, and ID-map setup where engine-visible;
- keep errors diagnostic locally while caller-facing SSH behavior remains generic.

### `crates/shbox/src/paths.rs`

- add/validate the `subid-leases` data root;
- add broker socket path only if it belongs under shbox runtime state rather than systemd's configured `/run` path.

### New `crates/shbox/src/sandbox/subid.rs` (Linux-gated where appropriate)

- lease schema encode/decode;
- safe atomic record persistence;
- Reserved/Active/Releasing/Quarantined transitions and verified record removal;
- `getsubids` discovery/parser;
- current-range validation;
- deterministic allocation;
- unavailable-ID ledger scan and safe reclamation;
- startup orphan reconciliation.

If separating storage from allocation makes tests clearer, use `sandbox/subid/storage.rs` and `sandbox/subid/mod.rs`; do not entangle it with `metadata.rs`.

### `crates/shbox/src/sandbox/manager.rs`

- allocate/publish a lease before creating a new isolated sandbox;
- retain/retrieve lease for existing sandbox handles;
- integrate startup lease reconciliation after process cleanup and before readiness;
- remove/free the lease only after safe sandbox deletion and release proof;
- preserve delete/launch locking and capacity semantics.

### `crates/shbox/src/platform/policy.rs`

- map shbox `identity` policy to engine `IdentityPolicy`;
- stop coupling `network=disabled` to the identity abstraction once isolated mode owns userns creation;
- continue selecting optional isolated network namespace for disabled networking.

### `crates/shbox/src/platform/linux.rs`

- extend `DomainSlot::Active/Deleting/CleanupPending` generation state with the auxiliary mount-ID-map userns FD, not a shared process namespace bundle;
- validate the durable lease before generation creation and before each launch map installation;
- create/tear down the mount-ID-map userns around cgroup/runtime-temp generation lifetime;
- before each launch, ask the broker for detached ID-mapped workspace/temp mount FDs and pass them plus destination FDs and selected identity to the engine;
- make the fresh child mount tree recursive-private then recursively read-only before attaching the approved writable views;
- supply the shadow-utils parent mapper (`newuidmap`/`newgidmap`) to the engine launch seam;
- preserve fresh per-launch network namespace behavior for `network=disabled`;
- order mount-idmap-userns/temp/cgroup cleanup safely;
- add platform capability diagnostics.

If this file becomes too large, extract Linux-only helpers into sibling modules such as `platform/linux_identity.rs` and `platform/idmap_client.rs` rather than mixing durable lease storage into the launcher.

### New privileged broker module in `crates/shbox`

Suggested `crates/shbox/src/idmap_broker.rs` plus a small FD-protocol module shared with the client. Responsibilities:

- internal broker mode dispatch;
- Unix peer credential validation;
- SCM_RIGHTS parsing;
- source/mount-ID-map-userns validation;
- `open_tree` / `mount_setattr` detached-mount construction;
- bounded error response;
- no shell/user command execution.

### `crates/shbox/src/main.rs`

- add hidden/internal broker entry mode before normal SSH startup;
- initialize subid capability snapshot/allocator/client in normal Linux startup;
- preserve current behavior where an unavailable sandbox launcher yields fail-closed normal launches while host admin route can remain available;
- include useful startup diagnostics without logging secrets.

### `crates/shbox/src/config.rs`

- add validated `sandbox.identity` enum with staged default;
- reject unknown values and unsupported platform combinations.

### `deploy/systemd/shbox.service`

- keep daemon `User=shbox`, `Group=shbox`;
- do **not** add `CAP_SYS_ADMIN`;
- retain cgroup delegation and `CAP_NET_BIND_SERVICE` only as currently required;
- document AppArmor/userns requirement.

### New systemd broker units

- socket unit restricted to shbox account;
- root broker service using same binary;
- `CapabilityBoundingSet=CAP_SYS_ADMIN` and hardening;
- no external network listener.

### `scripts/verify-linux-platform`

- require/check `getsubids`, `newuidmap`, `newgidmap`;
- print subordinate delegation diagnostics without dumping unrelated account data;
- require the broker/platform fixture for isolated native acceptance;
- add identity/idmap capability probe before full suite;
- preserve non-root daemon test execution.

### Documentation

Update after implementation:

- `docs/architecture.md`: identity boundary and broker;
- `docs/security.md`: DAC invariants, read-only mount-layer ownership containment, and verified UID/GID reuse;
- `docs/platforms.md`: Linux userns/subid/idmapped mount requirements and AppArmor;
- `docs/lifecycle.md`: lease versus cgroup/namespace lifecycle ordering;
- `docs/configuration.md`: `sandbox.identity`, deployment expectations;
- `docs/testing.md`: new native proof items;
- `docs/release.md`: support gate and recorded kernel/filesystem evidence;
- `docs/product.md`: host mode versus isolated sandbox identity;
- `crates/shbox-sandbox/README.md`: new engine identity model/bootstrap.

## 17. Detailed implementation phases

Each phase must end with focused tests before moving on. Do not combine all phases into one unreviewable patch.

### Phase I0 — freeze invariants and API types

Goal: make identity intent representable without changing production behavior.

Edits:

- introduce engine `IdentityPolicy` and namespace create/join types;
- keep current shbox policy selecting legacy behavior;
- add validation for impossible combinations;
- document exact child stages and runtime UID constant.

Proof:

- engine unit tests for policy/default/validation;
- existing macOS/Linux compile tests unchanged;
- current native behavior remains unchanged.

### Phase I1 — subordinate delegation discovery and crash-safe recyclable lease ledger

Goal: allocate one UID+GID durably and recover safely across restart without using it for execution yet.

Edits:

- add paths and lease storage;
- implement `getsubids` parser/range arithmetic;
- implement Reserved/Active/Releasing/Quarantined ledger, allocator mutex, and absence-as-free semantics;
- integrate claim/delete/startup reconciliation behind the new isolated policy only.

Proof:

- allocation from fragmented/multiple UID and GID ranges;
- independent UID/GID selection;
- parallel allocation uniqueness;
- crash fault injection at temp write/fsync/rename/parent fsync;
- `Active + sandbox absent` is quarantined rather than guessed free;
- successfully released lease record is removed+fsynced and its UID/GID become allocatable again;
- corrupted or duplicate lease state blocks/quarantines allocation;
- range shrink blocks launch but does not free ID;
- pool exhaustion diagnostics.

### Phase I2 — fresh per-launch user namespace and parent mapping barrier

Goal: replace child self-map for isolated mode with race-free parent mapping and runtime UID/GID 1000 while preserving the current `clone3`/pidfd architecture.

Edits:

- add mapper/barrier channels to the engine spawn path;
- outer clone creates `CLONE_NEWUSER` for every isolated launch;
- invoke `newuidmap/newgidmap` using an opened `/proc/<pid>` directory and `fd:N`;
- read maps and `setgroups` back exactly before releasing child;
- child clears groups and transitions real/effective/saved UID/GID to 1000;
- enforce zero capabilities, NNP, securebits, and no zero-ID mapping;
- preserve legacy `CallerMappedRoot` separately.

Proof:

- `/proc/<host-pid>/status` host UID/GID are subordinate IDs after setup;
- inside `id -u/-g` = 1000;
- `uid_map/gid_map` contain no UID/GID 0;
- `setgroups` is `allow` at mapping completion and runtime Groups are empty after child clear;
- CapEff/CapPrm/CapInh/CapAmb zero;
- NoNewPrivs=1;
- setresuid/setresgid 0 fail;
- daemon-owned 0600 canary is denied after runtime transition in a test configuration that does not rely on Landlock for that path;
- mapping helper/barrier failure kills/reaps without exec.

### Phase I3 — per-launch mount namespace and detached ID-map broker

Goal: allow the subordinate runtime identity to use daemon-owned durable workspace/temp without chown and without giving `CAP_SYS_ADMIN` to the SSH daemon.

Edits:

- create an auxiliary mount-ID-map userns per runtime generation (`DUID -> SUID`, `DGID -> SGID`);
- add broker protocol/client/server/systemd units;
- broker constructs and returns detached ID-mapped workspace/temp mounts only;
- isolated outer clone always adds `CLONE_NEWNS`;
- child makes propagation private, applies recursive `MOUNT_ATTR_RDONLY` to `/`, then attaches only returned workspace/temp mounts with FD-only `move_mount` after its UID/GID maps are installed;
- add real backing-filesystem capability probe;
- preserve Landlock path grants over bind/idmapped views;
- treat failure of recursive read-only mount-tree setup as fail-closed isolated launch failure.

Proof:

- sandbox sees workspace 1000:1000;
- create/rename/delete works;
- raw host backing owner remains daemon UID/GID;
- large workspace launch performs no recursive chown;
- persistent content works across generation recreation;
- broker rejects wrong peer, wrong source, wrong mount-ID-map userns, arbitrary request shape;
- broker never joins sandbox namespaces;
- broker absence/denial fails closed;
- child can attach a broker-created detached mount using only capabilities in its fresh user namespace;
- `mount_setattr` unsupported and backing FS unsupported fail closed;
- Landlock still denies sibling/management paths;
- with a test seam that deliberately omits Landlock write denial, inherited `/tmp` and other host directories still reject create/write with `EROFS`;
- `/dev/null` remains writable after recursive read-only mount attributes and cannot create a persistent inode;
- no non-idmapped persistent host directory is writable in the production isolated mount topology.

### Phase I4 — network namespace integration and generic namespace combinations

Goal: remove the old coupling `network=disabled -> CallerMappedRoot` and make the fresh isolated launch user namespace own disabled-network topology.

Edits:

- include `CLONE_NEWNET` in the same outer fresh `clone3` when networking is disabled;
- outbound omits `CLONE_NEWNET` and keeps host-network semantics;
- cover IPC/UTS combinations in engine tests without adding `setns()` joins.

Proof:

- TCP and UDP host/external reachability remain denied in disabled mode;
- Landlock network denial still active;
- outbound behavior unchanged;
- same-sandbox concurrent disabled launches may have distinct netns instances, but all remain unreachable and use the same durable host identity;
- runtime cannot regain network-admin capabilities.

### Phase I5 — PID namespace compatibility

Goal: preserve the existing engine's PID1 supervisor contract under a fresh isolated user/mount namespace.

Edits:

- outer clone creates NEWUSER/NEWNS/NEWPID together and blocks at the parent mapping barrier as namespace PID1;
- after map installation, PID1 clears groups, attaches ID-mapped mounts, then performs the existing nested PID2 `CLONE_INTO_CGROUP` before dropping the inherited raw daemon UID/GID;
- both branches are hardened: PID2 transitions to UID/GID1000 and zero caps; PID1 drops to the subordinate identity or another explicitly proven non-daemon mapped state with zero caps before entering its supervisor loop;
- preserve exact signal/status/reaper protocol.

Proof:

- user code remains PID2, never PID1;
- PID1 does not retain daemon DAC identity or effective capabilities after setup;
- PID2 is subordinate host identity / namespace UID1000;
- signals/status/reaping remain exact;
- `CLONE_INTO_CGROUP` remains atomic for user PID2;
- delete catches detached descendants.

### Phase I6 — shbox manager lifecycle/crash integration

Goal: make durable leases, auxiliary mount-ID-map namespace state, cgroups, temps, and workspace one retryable lifecycle.

Edits:

- extend `DomainSlot` state only with generation-scoped mount-ID-map userns ownership;
- implement deletion order from section 11;
- startup order from section 12;
- force-shutdown behavior that never removes/frees lease records accidentally.

Proof:

- injected failure at every cleanup boundary remains recoverable;
- daemon kill -9 then restart preserves Active lease and workspace;
- stale cgroup is killed before workspace reconciliation;
- per-launch user/mount/net namespaces disappear with killed processes and need no durable cleanup record;
- `Deleting + Releasing` with a missing workspace completes recovery and frees the pair only after runtime/backing absence proof;
- concurrent launch/delete cannot publish a process after Deleting;
- concurrent generation drain/recreate cannot use two identities for one sandbox.

### Phase I7 — rollout surface, docs, deployment, native gates

Goal: make the feature operable and supportable.

Edits:

- add `sandbox.identity` staged default;
- package/deploy broker units and subordinate-ID setup guidance;
- Ubuntu AppArmor profile guidance;
- update all architecture/security/lifecycle/testing/release docs;
- extend native Linux gate and CI fixture.

Proof:

- clean Ubuntu deployment with shbox service account, subordinate ranges, AppArmor permission, cgroup delegation, broker, and supported FS passes full native suite;
- absence of each prerequisite produces a specific blocking diagnostic;
- host `_` route remains usable for admin recovery when normal sandbox launcher is unavailable, subject to existing auth policy.

### Phase I8 — change Linux default to isolated

Goal: make identity isolation the normal Linux behavior after compatibility evidence exists.

Prerequisites:

- both supported Linux architectures pass native isolated gate;
- at least one production-like ext4/xfs provider host passes broker/idmap acceptance;
- upgrade/migration tests for existing workspaces pass;
- documentation explains subordinate range provisioning before upgrade.

Edits:

- omitted Linux `sandbox.identity` resolves to isolated;
- retain explicit `identity="host"` for a defined deprecation window if backward compatibility requires it;
- log a high-visibility warning whenever a normal Linux sandbox intentionally uses host identity.

Proof:

- default configuration on a correctly provisioned Linux host proves all security invariants;
- unprovisioned host fails normal sandbox launch rather than falling back to daemon identity.

## 18. Rollout and migration

Do not flip the default in the first implementation commit.

Recommended sequence:

1. **Compatibility release**: add `identity="isolated"` opt-in; omitted/default remains current host-DAC behavior. Emit clear documentation that isolated requires subids + broker + ID-mapped backing filesystem.
2. **Acceptance period**: run native Linux x86_64/aarch64 and production-host acceptance; collect upgrade evidence for existing persistent workspaces.
3. **Default transition**: Linux omitted/default becomes isolated. Existing daemon-owned workspaces need no recursive ownership migration because ID-mapped mounts preserve backing ownership.
4. **Legacy deprecation**: retain explicit `identity="host"` only if operators need it. It must log that normal sandbox processes share daemon DAC identity. Do not conflate it with `_` host mode: normal auth/confinement still applies, but identity isolation is reduced.
5. **Possible removal**: after a documented major/minor compatibility boundary, decide whether normal Linux `identity="host"` should be removed entirely. The `_` admin route remains separate regardless.

A sandbox created before isolated mode may receive its first durable lease at migration/first isolated launch. Persist the lease **before** starting the isolated process. Existing workspace backing requires no chown.

## 19. Test plan

### 19.1 Unit tests — subid ledger

Cover:

- valid one/multiple UID ranges;
- valid one/multiple GID ranges;
- malformed helper output;
- numeric overflow/end-of-range overflow;
- deterministic allocation across holes;
- UID/GID ranges with different starts/lengths;
- exclusion of Active IDs;
- exclusion of Reserved/Active/Releasing/Quarantined IDs;
- duplicate Active sandbox record rejection;
- duplicate issued UID or GID across records rejection;
- owner/sandbox mismatch rejection;
- Active -> Releasing precedes destructive cleanup;
- lease record removal occurs only after Releasing cleanup proof and lease-directory fsync;
- orphan Active reconciliation;
- range disappearance leaves Active reserved;
- exhaustion;
- repeated create/delete churn with a tiny synthetic pool reuses released pairs and does not monotonically consume IDs;
- a Releasing or Quarantined pair is never selected even when it is the only numeric hole;
- crash after lease-record unlink but before lease-directory fsync is reconciled conservatively before reuse;
- ABA protection: stale cleanup carrying an old lease_id cannot delete a newly allocated lease record;
- atomic persistence fault points.

### 19.2 Unit tests — engine identity policy

Cover:

- Host creates no user namespace;
- CallerMappedRoot retains existing mapping semantics;
- Isolated requires valid runtime/host ID mappings and a parent mapper;
- UID/GID zero mappings are not part of isolated policy;
- retained capability policy is rejected if not explicitly supported;
- mapping barrier and prepared mount/target FD conflicts with stdio/report/inherited FDs are rejected;
- child-stage error encoding covers mapping barrier, group clear, mount attach, securebits, setresuid, and setresgid.

### 19.3 Native engine integration tests

Run as the real non-root service-style account with delegated subids:

- host `/proc/<pid>/status` has leased subordinate UID/GID;
- process `/proc/self/status` and `id` report namespace 1000:1000;
- `/proc/self/uid_map` and `gid_map` exactly one entry and no zero mapping;
- Groups empty;
- CapEff/CapPrm/CapInh/CapAmb all zero;
- NoNewPrivs=1;
- attempt to become UID/GID0 fails;
- daemon-private 0600 file denied;
- Landlock/seccomp remain enforced after fresh namespace creation and identity transition;
- close-range removes all mapping, detached-mount, target, broker, and helper FDs.

### 19.4 Cross-sandbox DAC tests

Create A and B simultaneously:

- host subordinate UID/GID differ;
- A creates mode0600 subordinate-owned scratch inode outside ID-mapped daemon backing in a dedicated test fixture;
- B cannot read it by DAC;
- B creates its own and A cannot read it;
- same-sandbox concurrent launches can access same identity-owned private file as expected;
- after fully deleting A, create C and prove A's UID/GID **may** be reused only after the release barrier; if reused, no A-owned persistent inode or process is accessible to C;

### 19.5 Workspace/idmap tests

- daemon-owned workspace 0700 becomes 1000:1000 in sandbox view;
- read/write/create/rename/unlink work;
- created host backing files remain daemon-owned;
- preexisting daemon-owned files appear 1000-owned in sandbox;
- host mode sees original ownership;
- runtime-temp behaves identically;
- no recursive chown is observed (large/deep fixture plus syscall/mtime/ownership assertions);
- generation drain/recreate keeps contents and ownership;
- daemon restart keeps contents and lease;
- Landlock grants bind/idmapped workspace but not sibling sandbox;
- base inherited mount tree is recursively read-only before writable projections attach;
- deliberate Landlock write-policy widening still cannot create a file under inherited `/tmp`/host directories because the mount layer returns `EROFS`;
- only workspace/runtime-temp ID-mapped views and explicitly ephemeral mounts can create regular files;
- created files in persistent writable views remain daemon-owned in the raw backing tree.

### 19.6 Broker negative tests

- non-shbox peer rejected by `SO_PEERCRED`;
- missing SCM_RIGHTS FD rejected;
- wrong FD type rejected;
- source not daemon-owned rejected;
- unsafe source mode rejected;
- source outside approved roots rejected;
- initial userns supplied as mount-idmap namespace rejected;
- userns map not exactly `DUID -> SUID`, `DGID -> SGID` rejected;
- mount-ID-map userns map mismatch and unexpected namespace type are rejected;
- too many views/message too large rejected;
- unsupported FS returns stable capability error;
- broker crash during setup leaves no published generation/user command.

### 19.7 Lifecycle/crash tests

- parallel launches use one durable identity;
- empty cgroup generation rotates without changing identity;
- delete kills setsid/double-fork descendants before namespace/workspace teardown;
- delete while launch creation is at namespace-helper barrier;
- delete while broker is constructing detached mounts or child is waiting at the map barrier;
- daemon SIGKILL with active process then restart;
- daemon crash after `Reserved` lease publish before sandbox publish -> partial tree cleanup then safe record removal, or quarantine if ambiguous;
- crash after sandbox Deleting before cgroup kill;
- crash after workspace removal before Releasing lease unlink -> restart verifies runtime/backing absence, removes+fsyncs lease record, then allows reuse;
- stale runtime temp;
- stale cgroup;
- force shutdown never frees existing sandbox identities;
- repeated create/delete cycles greater than the delegated pool size succeed by recycling fully released pairs, provided no lease is Quarantined;
- reuse never occurs before `Releasing` cleanup and lease-directory fsync complete.

### 19.8 Capability/failure tests

- user namespaces disabled by kernel/provider;
- Ubuntu AppArmor userns denial;
- `getsubids` missing;
- `newuidmap` missing;
- `newgidmap` missing;
- no delegated UID range;
- no delegated GID range;
- active range removed after daemon start;
- helper rejects map;
- `fd:N` helper capability unavailable;
- `open_tree` unavailable;
- `mount_setattr` unavailable;
- ID-mapped mount unsupported by actual backing FS;
- broker socket missing;
- broker permission/auth failure;
- cgroup delegation missing;
- Landlock missing/ABI too old.

Every case must be either a startup/platform-unavailable diagnostic or an isolated launch error. None may run the requested command with daemon host identity.

### 19.9 Ubuntu AppArmor acceptance

On Ubuntu hosts with unprivileged-userns restriction enabled:

- first prove an unprofiled/disallowed shbox userns attempt fails;
- install the narrowly-scoped shbox AppArmor permission/profile required for user namespace creation;
- keep the global restriction enabled;
- rerun the native gate and prove isolated launch succeeds;
- document the profile rather than instructing operators to globally set `kernel.apparmor_restrict_unprivileged_userns=0`.

### 19.10 Full SSH acceptance

Extend `crates/shbox/tests/ssh_auth.rs` / native gate so a real OpenSSH client proves:

- shell and exec identity;
- PTY identity;
- HOME/PWD workspace write;
- persistence across reconnect;
- concurrent channels same sandbox identity;
- different sandbox identities;
- network disabled/outbound behavior;
- disconnect/detached descendant cgroup containment;
- delete cleanup;
- daemon restart recovery;
- admin `_` host route remains daemon identity and is not accidentally sent through the isolated fresh-userns/mount path.

## 20. Completion criteria

This plan is complete only when implementation can demonstrate all of the following on supported native Linux targets:

1. Normal isolated sandbox host UID/GID are leased subordinate IDs, not the daemon account.
2. Simultaneously non-free sandbox leases have different subordinate UID/GID pairs; a fully released pair can be safely reused by a later sandbox.
3. Same durable sandbox keeps its identity across concurrent launches, runtime-generation churn, reconnects, and restart.
4. Namespace runtime UID/GID are 1000:1000, supplementary groups are empty, UID/GID0 are unmapped, capability sets are zero, and NNP=1.
5. Host daemon-private 0600 data is independently DAC-inaccessible.
6. Cross-sandbox private subordinate-owned data is DAC-inaccessible.
7. Workspace/temp are writable through ID-mapped mounts while raw backing ownership remains daemon-owned.
8. No ordinary path recursively chowns persistent workspace data.
9. cgroup cleanup still catches detached descendants and remains the process inventory boundary.
10. Explicit delete transitions the lease to Releasing before cleanup and frees the UID/GID only after process/namespace/filesystem cleanup, lease-record unlink, and lease-directory fsync; normal churn therefore reuses capacity safely.
11. Crash/restart cannot cause premature reassignment: any lease whose release durability is uncertain remains unavailable until reconciliation completes.
12. Current subid delegation changes are detected and fail closed.
13. Unsupported userns/helper/AppArmor/broker/idmap/filesystem capability never silently falls back.
14. Admin `_` host route remains intentionally separate.
15. Linux native support gate passes on each declared architecture/provider tuple with the real broker, delegated account, actual backing filesystem, Landlock, cgroup, OpenSSH, and PTY path.
16. Documentation and deployment artifacts match the tested behavior.

## 21. Open questions and explicit deferred choices

These are the only material questions intentionally left for implementation-time proof; they must not be resolved by silent behavioral fallback.

### Q1. Exact securebits sequence

The desired final state is fixed, but the precise securebits/capset/setresuid ordering should be proven against the supported kernels while implementing Phase I2. Record the chosen order and its kernel rationale in `child.rs` and `docs/security.md`.

### Q2. Generic engine PID namespace representation

Public shbox does not currently request PID isolation, but `shbox-sandbox` supports it. Phase I5 must preserve PID1 + atomic `CLONE_INTO_CGROUP` semantics when the **outer clone itself** creates the fresh user/mount/PID namespaces and waits for parent mapping. The remaining proof is the exact point at which PID1/PID2 leave the inherited daemon kernel credential; dropping PID support is not permitted.

### Q3. Broker source-FD ancestry proof

The preferred protocol is pathless/FD-based. During Phase I3 choose the strongest practical fd-relative proof that each supplied workspace/runtime **source** belongs to the shbox-owned roots and corresponds to the expected sandbox/runtime object, using `openat2`/mount APIs/stat information rather than textual prefix trust. If the kernel lacks a fully pathless ancestry proof, constrain the broker with systemd filesystem policy, document the exact trust/race model, and add corresponding negative tests.

### Q4. Filesystem/provider support set

Do not hard-code a broad filesystem allowlist based on kernel documentation. The release support matrix is determined by the real backing-filesystem probe plus native acceptance on the provider tuple. Kernel documentation currently lists ID-map support for common filesystems including ext4/xfs and newer support for several others, but actual layered mounts may still reject `MOUNT_ATTR_IDMAP`.

## 22. Linux API references used for this design

Implementation should re-check the running kernel and current headers/man pages rather than copying numeric ABI details blindly. The design was based on:

- `user_namespaces(7)`: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
- `setns(2)`: https://man7.org/linux/man-pages/man2/setns.2.html
- `newuidmap(1)`: https://man7.org/linux/man-pages/man1/newuidmap.1.html
- `newgidmap(1)`: https://man7.org/linux/man-pages/man1/newgidmap.1.html
- `getsubids(1)`: https://man7.org/linux/man-pages/man1/getsubids.1.html
- `subuid(5)` / `subgid(5)`: https://man7.org/linux/man-pages/man5/subuid.5.html and https://man7.org/linux/man-pages/man5/subgid.5.html
- `open_tree(2)`: https://man7.org/linux/man-pages/man2/open_tree.2.html
- `mount_setattr(2)`: https://man7.org/linux/man-pages/man2/mount_setattr.2.html
- `move_mount(2)`: https://man7.org/linux/man-pages/man2/move_mount.2.html
- kernel ID-mapping documentation: https://docs.kernel.org/filesystems/idmappings.html
- kernel Landlock documentation: https://docs.kernel.org/userspace-api/landlock.html
- Ubuntu AppArmor unprivileged-userns documentation: https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/

## 23. Verification notes from plan creation

These observations are not release evidence; they exist so a future implementer understands why several design decisions are explicit.

- The authoritative worktree was `/Users/ama/shbox`, branch `main`, tracking `origin/main`, clean at the beginning of planning, HEAD `deb3b4db090e8ab5f21bdc75744608a9ecb25ae9`.
- Current host is macOS arm64, so production Linux behavior was not inferred from the host.
- A privileged Linux Docker VM was used only for focused syscall feasibility probes.
- A one-entry process userns mapping `1000 -> subordinate` successfully transitioned a fresh namespace process to UID/GID1000 with `CapEff=0`; UID0 was unmapped. A separate check confirmed `setns()` into a target user namespace is not the right normal-daemon architecture because it requires `CAP_SYS_ADMIN` in that target namespace.
- An ID-mapped mount probe on tmpfs confirmed the mapping composition `mount map DUID -> SUID` plus `process map 1000 -> SUID`: sandbox-visible ownership was 1000:1000 while newly-created raw backing files remained daemon-owned. A second probe confirmed a broker-like privileged parent can create that detached ID-mapped mount and a fresh user+mount-namespace child can attach it itself with `move_mount()`.
- A fresh-user+mount-namespace probe applied `mount_setattr("/", AT_RECURSIVE, MOUNT_ATTR_RDONLY)` as a non-root caller after userns setup; creating a file under inherited `/tmp` then failed with `EROFS`, while opening/writing `/dev/null` still succeeded. This supports the mount-layer invariant required for bounded UID/GID reuse.
- An attempt on the Docker overlay-backed `/tmp` returned `EINVAL`, reinforcing the requirement for an actual backing-filesystem capability probe rather than a kernel-version-only check.

These probes must be replaced by repository-native tests and supported-host acceptance during implementation.

## 24. Review-remediation plan (2026-09-04 review, agent execution contract)

Scope: fix every finding of the 2026-09-04 safety/performance/standards review of
`origin/main...78247d0` (2 blocking, ~20 should-fix, notes). Most code will be
written by subagents (glm-flash or luna-xhigh class). §24.0 records the
calibration experiment that fixes how detailed each item must be; §24.1 is the
mandatory execution contract; §24.2 lists the items at the calibrated
granularity. Tiers: **S** mechanical (<=3 files, no design choice), **M** logic
fix with test, **L** security/perf/cross-cutting.

### 24.0 Calibration experiment (2026-09-04): required item granularity

Method. 2 representative tasks x 3 detail levels x 2 models = 8 runs, each in an
isolated git worktree at 78247d0, agents forbidden from running builds, central
evaluation (`cargo check`, `cargo fmt --check`, targeted `cargo test`, new-failure
diff vs clean-tree baseline). Rework = follow-up prompts needed for acceptance.
- T-A (mechanical): single named const for runtime UID/GID 1000 at
  `platform/policy.rs:~398` + `sandbox/manager.rs:~1291`; remove stale
  `#[allow(dead_code)]` on `Paths::subid_leases_root` (`paths.rs`).
- T-B (logic): `engine_namespaces` sets `namespaces.mount = true` iff identity is
  `Isolated` + policy-level test per identity mode.
- L1 = goal + file:line pointers. L2 = L1 + change sketch + test spec + non-goals.
  L3 = L2 + why-context, exact spots, edge cases, acceptance criteria, verify
  commands. Models: claude `glm-5.3-flash[1m]` vs codex `gpt-5.6-luna` @ xhigh.

Results (all 8 compiled first try; functional rework was zero at every level):

| run | wall | check | fmt | tests | rework |
|---|---|---|---|---|---|
| TA-L1 glm | 266s | clean | 1 import-order nit | 0 new fails | trivial (`cargo fmt`) |
| TA-L1 luna | 107s | clean | 1 import-order nit | 0 new fails | trivial (`cargo fmt`) |
| TB-L1 glm | 439s | clean | clean | new 4-combo test passes | none |
| TB-L1 luna | 93s | clean | 1 import-order nit | new 2-mode test passes | trivial (`cargo fmt`) |
| TB-L2 glm | 299s | clean | clean | new 4-combo+identity test passes | none |
| TB-L2 luna | 89s | clean | clean | extended existing test passes | none |
| TB-L3 glm | 200s | clean | clean | new 3-mode test passes | none |
| TB-L3 luna | 117s | clean | clean | new 3-mode test passes | none |

Capability assessment (critical, for routing in §24.1).
- glm-flash: slow (200-440s), thorough, faster with MORE detail (439s at L1 ->
  200s at L3: detail replaces exploration). Surfaces uncertainties honestly,
  self-runs `rustfmt --check` unprompted, notices adjacent issues (docs already
  claiming the behavior, `(Isolated,None)` interplay, second stale allow).
  Scope discipline held (1 file for T-B). Verbose output. 3 parallel sessions
  hit API 429 rate limits with retries.
- luna-xhigh: fast (~90-120s regardless of detail), literal, minimal-precise.
  Test breadth is thin by default (2 modes where 4 fit; extends rather than adds).
  Always reports "unsure: nothing" (confidence, not evidence of scrutiny).
  Skips self-checks it could have run (no `rustfmt --check`, hence 2 fmt nits).
  No scope violations in 4 runs.
- Caveats: agents were forbidden builds, so compiler-iteration loops are
  unmeasured; n=8 on small (1-5 file) tasks. Large cross-cutting tasks were NOT
  calibrated and default to tier L.
- Decision: L1 is functionally sufficient for S/M class tasks; L2's test spec
  buys breadth (worth it for M); L items need full L3. Unlike the experiment,
  real runs MUST include `cargo fmt --check` + relevant tests in every item
  (eliminates the only rework class observed).

### 24.1 Execution contract (mandatory for every item)

1. One item = one work unit. Touch ONLY the files whitelisted in the item.
2. Output contract: (1) files changed, (2) summary, (3) uncertainties.
3. Gate per item: `cargo fmt --check` clean, `cargo check -p <crate> --tests`
   clean, listed tests pass on a namespace-capable Linux host (container EACCES
   failures in `engine_capability_probe`, `isolated_identity`, `linux_only` are
   environmental, not regressions: compare against the clean-tree baseline).
4. Routing: S/M items -> luna (fast); L or discovery-heavy items -> glm (max 2
   parallel sessions: 429 risk); M either. Commit per completed item.
5. Order follows §24.2 dependencies. R-0 first: nothing isolated-path is testable
   without it. R-3 before any concurrency test.

### 24.2 Items

#### R-0. `Isolated` sets `namespaces.mount = true` [M, either | blocking B1]
- Goal: isolated launches pass engine `validate_identity` (mount-ns requirement).
- Files: `crates/shbox/src/platform/policy.rs` (`engine_namespaces` ~:378,
  test ~:982). Ref: `crates/shbox-sandbox/src/validate.rs` (`validate_identity`),
  `NamespacePolicy::default` (`crates/shbox-sandbox/src/policy.rs`).
- Change: match on identity; `Isolated` -> `mount = true`; `Host`/
  `CallerMappedRoot` unchanged. Leave non-Linux arm (~:418) as is.
- Test: assert the whole `NamespacePolicy` per identity mode (Host,
  CallerMappedRoot, Isolated); engine `spawn.rs` hand-sets `mount = true` so only
  a policy-level test catches this coupling.
- Acceptance: Isolated -> mount true, others false; check clean; new test passes;
  no other files. Non-goals: engine changes, macOS behavior, `(Isolated,None)` arm.
- (Calibrated at L1-L3 with zero rework; any tier works.)

#### R-1. `(Isolated, None)` arm returns `Err` [M, either]
- Files: `crates/shbox/src/platform/policy.rs:397`.
- Change: stop fabricating `host_uid: 0, host_gid: 0` (engine rejects it anyway);
  return `Err` so the launcher's precise "no active lease" diagnostic survives.
- Test: no-lease isolated policy construction errors (extend R-0 test module).
- Acceptance: check clean; tests pass. Non-goals: lease lifecycle changes.

#### R-2. Reject `identity = "isolated"` on non-Linux at config validation [M, either]
- Files: `crates/shbox/src/config.rs` (`validate_identity` ~:308, test ~:1046),
  `platform/policy.rs:412`, `platform/macos.rs:77`.
- Change: `not(target_os = "linux")` + `isolated` -> validation error (PLANS.md
  §14.1 mandates this; current silent Host-downgrade is forbidden behavior).
- Test: `build_ok(identity=isolated)` becomes Linux-only; non-Linux reject assert.
- Acceptance: macOS path rejects; Linux unchanged. Non-goals: engine changes.

#### R-3. Exclusive ledger locking across processes [L, glm | blocking B2]
- Context: `selection` is a per-process `Mutex` (`subid/mod.rs:139-143,183`); two
  daemon instances can claim the same lowest-available pair -> two live sandboxes
  share one subordinate UID.
- Files: `crates/shbox/src/sandbox/subid/mod.rs`, `ledger.rs` (lockfile helper).
- Change: `flock` a ledger-dir lockfile around claim AND all transitions
  (activate/begin_release/finish_release/quarantine); read-modify-write under one
  guard with state re-verified at write (also fixes the unlocked-transition
  overwrite at `mod.rs:298-309,259-274`); replace `lock().expect()` with
  `PoisonError::into_inner` continuation.
- Edge: lock ordering vs future `flock` users (document); crash while holding
  flock = released by kernel, safe.
- Test: two allocators on one dir, concurrent claims -> zero pair overlap;
  poison-then-claim continues; quarantine-vs-activate race test.
- Acceptance: race tests pass; existing 26 subid tests green. Non-goals: lockfile
  location outside ledger dir.

#### R-4. Broker confinement on fd identity, not paths [L, glm]
- Context: root broker (`platform/idmap_broker.rs:641`) `canonicalize`s a path
  string; a daemon-owned dir renamed out of the root + replaced passes validation
  while the fd mounts the moved-out tree.
- Files: `crates/shbox/src/platform/idmap_broker.rs`.
- Change: compare `st_dev`/`st_ino` of the supplied fd against a fresh
  `openat2(RESOLVE_BENEATH)` open from a pinned root fd. Same treatment for
  deleted-detection (`:634-635`, drop the `" (deleted)"` suffix compare) and
  userns-fd check (`:651-656`, inode-compare vs `/proc/self/ns/user`, reject
  initial-ns inode). Validate configured roots once at startup (`:179-190`).
- Test: rename-out + replace negative test; bad-roots startup-failure test.
- Acceptance: negatives rejected; existing broker tests green. Non-goals: protocol
  changes.

#### R-5. Broker fd-leak, thread bound, accept discipline [L, glm]
- Files: `crates/shbox/src/platform/idmap_broker.rs:551-577,220,546,210-215`.
- Change: collect the whole control buffer into `OwnedFd`s before any error return
  (drop-guard all paths); semaphore-bounded handlers (e.g. 16) + `SO_RCVTIMEO` on
  `recvmsg`; sleep-and-continue on transient accept errno (EMFILE/ENFILE/
  ECONNABORTED) instead of exiting `serve()`.
- Test: `/proc/self/fd` count before/after malformed-message burst; thread-count
  bound under N idle connections.
- Acceptance: no leak; bound holds. Non-goals: connection reuse (deferred §24.3).

#### R-6. Ledger transition atomicity + durability gaps [M, either]
- Files: `subid/mod.rs:298-309,259-274`, `ledger.rs:216-229,360-362`.
- Change: (a) transitions under the R-3 guard with re-verify (if R-3 landed
  first, only re-verify remains); (b) parent-dir fsync after ledger-dir
  create/chmod; (c) `open_root` re-validates owner/mode on every open, not once
  at `:232`.
- Test: create/chmod durability (fault-injection if available); chmod-after-open
  detected.
- Acceptance: tests pass. Non-goals: schema changes.

#### R-7. Lease selection exclusions + typed reconcile proof [M, either]
- Files: `subid/mod.rs:503-510,371,441-450,376-382`.
- Change: subtract daemon euid/egid (plus reserved set) at selection alongside
  the ID-0 exclusion; replace `runtime_reconciled: bool` with a typed
  proof/token produced by the runtime sweep; assert (not just document) the
  activate-before-launch invariant behind `Reserved`+absent freeing.
- Test: delegation containing daemon IDs never handed out; premature-`true`
  becomes a type error (compile-level acceptance).
- Acceptance: tests pass. Non-goals: allocator algorithm changes.

#### R-8. Delegation cache + single-read `lease_for` [L, glm | perf blocking]
- Context: every launch spawns `getsubids` + `getsubids -g` (`manager.rs:631,652,
  1274,1285`; 4 execs on claim) and `lease_for` full-scans O(n) (`manager.rs:1278`
  -> `store.load()`).
- Files: `manager.rs`, `subid/delegation.rs:131,141`, `subid/mod.rs:163`,
  `ledger.rs:245,267`.
- Change: daemon-lifetime delegation cache with generation check (keep
  re-query-before-use on shrink: fail-closed behavior preserved); `lease_for`
  via the single-file `read()` fast path (`ledger.rs:267`); hoist one `load()`
  snapshot indexed by `SandboxId` for `reconcile_deleting` (`manager.rs:1057`)
  shared with `reconcile_subid_leases:296`.
- Edge: NSS backends (sssd/LDAP) have real latency; cache invalidation must not
  widen the shrink window (re-check on use, not only on timer).
- Test: spawn-count per launch = 0 after warm; shrink-delegation fail-closed
  maintained; 1000-lease launch latency flat (bench, not a unit assert).
- Acceptance: bench numbers recorded in the commit message. Non-goals: broker
  connection reuse.

#### R-9. Mutex-hold narrowing on launch paths [L, glm | perf blocking]
- Files: `manager.rs:738,752` (ledger mutex across `storage.inspect()`),
  `platform/linux.rs:144` (`slots` mutex across `cgroup.events` read),
  `subid/mod.rs:183` (claim mutex across load+write+fsync).
- Change: lock -> inspect/I/O -> re-lock -> re-validate pattern in all three
  (coordinate R-9c with R-3's flock design).
- Test: concurrent-launch throughput bench; existing race tests green.
- Acceptance: no throughput regression vs pre-change; invariants documented where
  a TOCTOU window is explicitly accepted (double-`inspect` at
  `manager.rs:342,618` resolved the same way: pass validated metadata through
  `begin_launch` or comment the window).

#### R-10. Claim-path write/scan efficiency [M, either]
- Files: `subid/mod.rs:503,512`, `ledger.rs:304,342`.
- Change: replace 65k linear `lowest_available` scan + per-claim `HashSet` rebuild
  with a sorted free-list/interval set; coalesce Reserved->Active double write
  where publication is atomic (update crash-window fault tests accordingly).
- Test: existing fault-injection + ABA tests green; claim bench noted.
- Acceptance: tests pass. Non-goals: ledger schema change.

#### R-11. Error-type, const, lint hygiene [S, luna]
- Files: `manager.rs:1462` (`Error::Subid(String)` -> `Error::Subid(subid::Error)`,
  13 call sites; keeps `HelperMissing` diagnostic), `policy.rs:398` +
  `manager.rs:1291` (single const for runtime 1000; experiment validated the shape,
  either crate home acceptable, document the choice), `paths.rs:119` (remove stale
  allow), `config.rs:943,1389,1396` (3 clippy test warnings).
- Test: `HelperMissing` message preserved assert; full bin tests green.
- Acceptance: `cargo clippy --all-targets` zero warnings; PLANS.md clippy
  accounting updated.

#### R-12. Broker/systemd/profile hardening + SAFETY sweep [M, luna]
- Files: `idmap_broker.rs` (SAFETY comments: prioritize cmsg walks `561-588,696`
  and syscall casts `336,357`; `get_u32/get_u64` `:720,728` -> `Result`; protocol
  constants `:431-458` alignment), `deploy/systemd/shbox-idmap-broker.service`
  (`SystemCallFilter` allowlist + `MemoryMax`/task limits), AppArmor (separate
  broker invocation path from the daemon binary profile).
- Test: no behavior change (existing tests green); `systemd-analyze security`
  delta recorded.
- Acceptance: zero-behavior diff + recorded hardening delta. Non-goals: protocol
  redesign.

#### R-13. Quarantine reason persistence [S, luna]
- Files: `subid/mod.rs:260` (persist reason in record or sidecar; operators need
  durable evidence for repair).
- Test: quarantine round-trip preserves reason.
- Acceptance: test passes. Non-goals: tombstones (deferred: any out-of-band unlink
  still silently frees; operator-only repair verb is future work).

### 24.3 Explicitly deferred (measure first, per §24.2 R-8/R-9 benches)

Broker connection reuse / mount batching; lingering idle generations
(`linux.rs:667,247`); `duplicate_fd` skip (`linux.rs:498,622`); `PathRule`
interning (`policy.rs:329,340`); cgroup poll tuning (`cgroup.rs:95,143`).
Adopt only if post-R-8/R-9 latency breakdown justifies each.

### 24.4 Final gate (after all items)

1. `cargo fmt --check` clean. 2. `cargo clippy --all-targets` zero warnings.
3. Full `cargo test` green on a namespace-capable Linux host (the 9 container
   environmental failures must turn green there). 4. New tests enumerated in
   §24.2 present and passing. 5. PLANS.md §0 caveat corrected (I3 integration was
   statically unreachable pre-R-0, not merely pending a host) and evidence
   retention (§12) extended with delegation/broker availability.

### 24.5 Execution record (2026-09-04, all items complete)

| item | commit | agent | notes |
|---|---|---|---|
| R-0 mount flag + policy test | 89d4047 | reuse of calibrated TB-L1 patch | 4-combo test; central re-verify |
| R-11a const + stale allow | 9b64b9f | reuse of calibrated TA-L1 patch | import order via cargo fmt |
| R-1 lease-less Err, R-2 non-Linux reject | ebd8cc4 | codex/luna | engine_identity -> Result + try_ variant; macOS defense in depth |
| R-6 transitions/durability, R-7 exclusions/typed proof, R-13 reason | 82a581b | codex/luna | 32 subid tests |
| R-3 cross-process flock | 038057e | codex/luna over partial glm session | glm bg session stalled (no edits 10+ min, own worktree); +3 race tests, 35 green |
| R-4 confinement, R-5 leak/threads | 80f4d7e | codex/luna | 1 reviewer fixup (umask-sensitive fixture); 6 broker tests |
| R-8 cache/fast-path, R-9 mutex narrowing | c9a4a44 | codex/luna | reviewer follow-up: scan-time temp sweep raced same-fd threads (flock is re-entrant); load() now skips, sweep runs under flock+selection |
| R-12 SAFETY/systemd/profile | ba75ced | codex/luna | zero behavior diff |
| R-10 free-list/coalesce | f9733a2 | codex/luna | fault windows kept covered |
| R-11b typed errors/clippy | 0bc0f8f | codex/luna | shbox clippy zero |
| pre-existing cgroup clippy warning | (this commit) | reviewer direct | 1-line c" literal; workspace clippy now zero warnings |
| §0 I3 caveat correction | (this commit) | reviewer direct | defect recorded, not just host-pending |

Final gate state: fmt clean, workspace clippy zero warnings, bin tests 236
passed + 1 environmental failure (`engine_capability_probe`, needs user-ns;
turns green on a capable host along with the 8 spawn/env tests). New tests
added across items: +13 net (policy mount/lease-less/macOS, subid race/lease,
broker negative/leak/roots, HelperMissing message, free-list). Routing lesson
applied: glm stalled twice on L items (>10 min, one session wrote to its own
worktree); codex completed all waves — L items went to codex with L3 detail.
