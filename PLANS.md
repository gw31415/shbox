# Milestone 9 — Fly.io acceptance

## Goal

Prove the exact production Fly.io Machine/image works with the new shbox Linux backend and **without delegated cgroup controllers**.

This must run on the same Machine/image configuration intended for Haven/shbox production. GitHub-hosted Linux or local Docker results do not substitute for this acceptance.

## Current blocker

The current checkout does not have enough production Fly context to run this gate:

- no `flyctl` available;
- no `FLY_API_TOKEN` available;
- no target Fly Machine configuration in this repository;
- the inspected consumer production image still pins an older shbox/runtime stack.

Before running acceptance, update the production image to an immutable revision containing the completed native nono/PTTY implementation.

## Environment observations

Capture:

```sh
uname -a
cat /proc/version
id
ulimit -a
```

Also record shbox/nono diagnostics:

- shbox revision;
- Rust version used to build the production binary;
- nono `0.74.0`;
- Landlock ABI;
- filesystem rights used by the policy;
- network handling/fallback selected by nono;
- signal/IPC scoping availability;
- seccomp fallback behavior, if any.

Cgroup information may be observed for diagnostics, but writable controller delegation is **not** a prerequisite.

## Required runtime proof

Using the production binary/configuration:

1. start shbox without elevated privileges;
2. authenticate through the normal SSH path;
3. run a non-PTY command and verify stdout, stderr, and exit status;
4. open a PTY shell and run the complete blocking PTY suite;
5. verify workspace persistence across sessions;
6. verify outside-workspace write denial and selected sensitive read denial;
7. verify `network = "disabled"` rejects a controlled connection;
8. verify `network = "outbound"` reaches a controlled endpoint;
9. run 20 sequential PTY sessions;
10. run at least 4 concurrent PTY sessions;
11. verify daemon fd count returns near baseline after sessions close;
12. verify PTY/session state is not reused or leaked across sessions;
13. disconnect SSH while foreground and background same-PGID commands run and verify cleanup;
14. stop shbox normally while sessions exist and verify managed process groups exit;
15. SIGKILL shbox with a direct session child running and verify Linux parent-death behavior;
16. deliberately create a detached `setsid()` descendant and record its behavior so release claims do not imply process-tree containment;
17. prove no sandbox launch path requires or writes cgroup controller files.

## Acceptance criteria

Fly acceptance passes only if all required runtime proof succeeds with the documented filesystem/network policy unchanged.

Do not broaden filesystem or network access merely to make the production environment pass.

Do not fall back to an alternative sandbox backend or unconfined execution if Landlock/nono prerequisites are missing. Record the exact unsupported capability instead.

## After acceptance

When this gate passes:

1. record the Fly Machine/image identity, kernel, shbox revision, nono/Landlock diagnostics, and test results here;
2. perform the final residual audit on that same revision;
3. remove `PLANS.md` if no further migration work remains.
