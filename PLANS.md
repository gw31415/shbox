# shbox CLI / configuration simplification — rolling execution plan

## User value and how to observe it

Operators configure shbox with one small TOML file that holds only persistent policy
(`authorized_keys`, `admin_keys`, `sandbox_shell`, `read_paths`, `sandbox_env`). Everything
that is decided once at daemon start moves to the command line, and resource limits become
non-configurable built-in safety defaults. Shell completions and a man page are generated
from the same CLI declaration that `--help` uses.

Observed behavior after this work:

```console
shbox --listen 127.0.0.1:2222 --network outbound --log-level debug --authorized-keys-host-access
shbox --completions zsh    # completion script on stdout, exit 0, no daemon
shbox --man > shbox.1      # roff man page on stdout, exit 0, no daemon
```

A config file still carrying `listen`, `network`, `log_level`, `limits`, or `caps` is
rejected at startup (`unknown field`), not silently ignored.

## Current state (facts this work depends on)

- Crate: single binary `shbox`, edition 2024, `rust-version = 1.91`.
  `usage = { package = "usage-rs", version = "=6.5.0" }` is already a dependency with
  default features only (`spec`, `help`, `diagnostics`).
- `src/main.rs` — `#[derive(usage::Cli)] #[usage(bin = "shbox", version)] struct Args {}`;
  `Args::parse()` handles `--help`/`--version`. `run()` does bootstrap then serves.
- `src/config.rs` — `RawConfig` (serde, `deny_unknown_fields`) with
  `listen/authorized_keys/admin_keys/sandbox_shell/network/read_paths/log_level/sandbox_env/limits/caps`;
  `build()` validates into immutable `Config`. Also defines `NetworkMode`, `LogLevel`,
  `Limits`, `LinuxLimits`, `Caps`, and the raw serde views `RawLimits`/`RawLinuxLimits`/`RawCaps`.
- Consumers to rewire:
  - `src/main.rs`: `Config::load_snapshot`, `logging.set_level`, `AuthSnapshot::load`,
    `ArapucaLaunchPolicy::from_config`, `SandboxManager::open*(&paths, *config.caps(), …)`,
    `server::bind_all(config.listen())`, reload path
    `load_reload_snapshot` (rejects `listen` change, reloads caps/limits/log level),
    `SshServer::new(shared, key, &app_config)`.
  - `src/server.rs`: `SshServer::new` reads `app_config.caps()`;
    `SshServer::reload` calls `sandbox.reload_caps`, `limiter.reload_caps`,
    `host_process_limiter.reload_caps`; `Limiter::reload_caps` and
    `HostProcessLimiter::reload_caps` exist for that.
  - `src/platform/arapuca.rs`: `ArapucaLaunchPolicy::from_config(config, shell)` captures
    `network`, `read_paths`, `sandbox_env`, `limits`; `reload_policy()` swaps it on SIGHUP.
  - `src/sandbox/manager.rs`: holds caps (`reload_caps` at line ~200).
  - `src/ssh/mod.rs`: `Shared { auth, config, account, sandbox }` snapshot per connection.
  - `src/logging.rs`: `init(LevelFilter)` returns `Logging` with runtime `set_level`;
    `level_filter(LogLevel)` maps.
  - `src/auth.rs`: `AuthSnapshot::load(authorized_keys_path, admin_keys)` builds
    `keys + admin` set; `authenticate()` maps fingerprint → `Role::Normal`/`Role::Admin`.
- Tests: unit tests in each module; integration `tests/ssh_auth.rs` (OpenSSH end-to-end).
  Platform gates: `scripts/verify-linux-platform`, `scripts/verify-macos-platform`.
- Docs: `docs/configuration.md` (biggest), `docs/security.md`, `docs/testing.md`,
  `docs/architecture.md`, `docs/product.md`, `docs/platforms.md`;
  deployment examples `deploy/systemd/shbox.service`, `deploy/launchd/com.example.shbox.plist`.

### usage-rs 6.5.0 API findings (verified with the compiler, not just sources)

- Dependency naming: `usage-lib`'s lib target is literally named `usage`, so the facade
  cannot also be aliased `usage`. `Cargo.toml` declares
  `usage-rs = { package = "usage-rs", version = "=6.5.0", features = ["completions"] }`
  (crate `usage_rs`) and `usage-lib = "=6.5.0"` (crate `usage`). The derive reads the
  manifest and emits `::usage_rs::…` paths, so `use usage_rs::Cli;` + `#[usage(...)]` works.
- Completions: `#[usage(completion)]` on the `Cli` derive + the `completions` feature
  generate `Args::completion_script(usage_rs::complete::Shell) -> String` in process.
  The generated script calls the shbox binary itself (`shbox __complete_word__ …`) at
  shell runtime — no external `usage` executable anywhere.
- Enums: a field must be annotated `#[usage(long, value_enum)]` (not just a type-level
  derive) to bind through `usage_rs::ValueEnum`; variant spellings are kebab-case by
  default, overridden with `#[usage(name = "powershell")]` on the variant.
- `usage_rs::Error` implements neither `Display` nor `ToString` (Debug only).
- Man pages: usage-lib `docs::manpage::ManpageRenderer::new(spec).with_section(1).render()`;
  the only public raw-KDL entry is `usage::Spec::parse_spec` (bare `#[deprecated]`, no
  replacement), fed by the derive's `Args::to_kdl()`. roff output escapes flag hyphens
  (`\-\-completions`).

## Milestones

Each milestone is independently verifiable; commit (via `$archive-commit`) and push after
each verified slice. Prune this plan in the same commit that implements a milestone.

### M1 — `--completions` / `--man` output actions (implemented; prune with this commit)

Done in `src/main.rs` + `tests/cli_output.rs`: `CompletionShell` (bash|zsh|fish|powershell),
`Args::output_action()` with conflict rejection, in-process `completion_script` and
`render_man_page`, `emit()` writing stdout before any daemon input is touched. Verified by
119 bin unit tests, 6 `cli_output` integration tests, clippy `-D warnings` clean.

### M2 — operational options on `Args`; `listen`/`network`/`log_level` leave TOML

- Goal: `RawConfig`/`Config` lose `listen`, `network`, `log_level` (fields, accessors,
  validators); daemon takes them from `Args`; `deny_unknown_fields` makes old configs an
  explicit error; SIGHUP no longer touches any of the three.
- Edits: `src/config.rs`, `src/main.rs` (bind from args, `logging.init(args level)` and
  drop the reload `set_level`), `src/ssh/mod.rs` `Shared` config usage as needed,
  reload path keeps only file-backed policy.
- Result: old fields in TOML fail with `unknown field`; defaults equal today's defaults.
- Proof: updated `src/config.rs` tests (old fields rejected, minimal/empty config OK),
  `cargo test --locked --all-targets -- --test-threads=1`.

### M3 — Caps/Limits become non-configurable built-ins

- Goal: `RawLimits`/`RawLinuxLimits`/`RawCaps` and their validation are deleted; current
  default values are unchanged and produced by a single built-in definition; no reload or
  TOML path can change them; `Caps`/`Limits` domain types stay for the Arapuca boundary.
- Edits: `src/config.rs` (constants/`Default` only), `src/server.rs`
  (delete `reload_caps` on `Limiter`/`HostProcessLimiter` and their call sites in
  `SshServer::reload`; construct limiters from the built-in), `src/sandbox/manager.rs`
  (drop `reload_caps`), `src/main.rs`.
- Result: values identical to today (`32/128/16/128/16/6/1024/128/30`,
  limits `0/0/0/1024` + Linux `0/256`), unreachable from config.
- Proof: `defaults_match_documented_values` test kept/updated; old `[limits]`/`[caps]`
  TOML rejected as unknown fields; full test suite.

### M4 — `--authorized-keys-host-access` wired into auth roles

- Goal: flag-on makes every authenticated authorized key `Role::Admin`
  (`Admin = flag OR fingerprint ∈ admin_keys`); flag-off is byte-for-byte current
  behavior; `admin_keys` validation rules unchanged; flag never appears in TOML.
- Edits: `src/auth.rs` (`AuthSnapshot::load` gains `all_authorized_keys_admin: bool`),
  `src/main.rs` (bootstrap and reload pass the CLI flag), unit tests.
- Result: flag on → ordinary key can `ssh _@host` (host shell/exec, PTY, full sandbox
  list/manage/delete); flag off → ordinary key rejected for `_`.
- Proof: `src/auth.rs` unit tests (flag on/off matrix, admin validation still enforced),
  `tests/ssh_auth.rs` OpenSSH integration update.

### M5 — Reload reduced to file-backed policy

- Goal: SIGHUP reloads only `authorized_keys/admin_keys/sandbox_shell/read_paths/
  sandbox_env`; the restart-only `listen` comparison, cap/limit replacement, and log-level
  switch are gone from the reload path; `ArapucaLauncher::reload_policy` keeps receiving
  the new launch policy built from file config + CLI network mode + built-in limits.
- Edits: `src/main.rs` (`load_reload_snapshot`), keep connection-role snapshot semantics
  (`Shared` per connection unchanged).
- Result: reload tests prove network/log-level/caps/limits/listen/host-access are absent
  from the reload path; keys added after reload are picked up by new connections.
- Proof: focused reload unit tests + integration; full suite.

### M6 — Documentation, deployment examples, platform gates

- Goal: docs describe the new contract; systemd/launchd examples pass the moved options
  as CLI arguments; no stale `listen/network/log_level/limits/caps` TOML text remains.
- Edits: `docs/configuration.md` (shrink), `docs/security.md` (flag authority:
  host access == daemon user authority), `docs/testing.md`, `docs/architecture.md`,
  `docs/product.md`, `docs/platforms.md`, `deploy/systemd/shbox.service`,
  `deploy/launchd/com.example.shbox.plist`.
- Result: grep for the removed field names finds no remaining documentation of them as
  config keys; examples boot a daemon equivalent to defaults.
- Proof: `grep -rn "log_level\|max_open_files" docs/ deploy/` review; doc links valid.

### M7 — Full verification sweep

- Goal: every quality gate green on current stable and MSRV 1.91; real-CLI completion/man
  checks; platform release-gate rerun where applicable on this machine.
- Commands (from repo root):
  ```console
  cargo fmt --all -- --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo test --locked --all-targets -- --test-threads=1
  cargo build --locked --all-targets
  cargo +1.91.0 clippy --locked --all-targets --all-features -- -D warnings
  cargo +1.91.0 test --locked --all-targets -- --test-threads=1
  cargo +1.91.0 build --locked --all-targets
  ./scripts/verify-macos-platform   # this machine; Linux gate needs a Linux host/CI
  ```
- Proof: command transcripts recorded in the archive-commit payloads.

## Acceptance criteria (remaining)

- [ ] Config has no `listen`, `network`, `log_level`, `limits`, `caps`; old fields are
      explicitly rejected.
- [ ] No external path can change Caps/Limits; default behavior unchanged.
- [ ] `shbox` with no args still runs the daemon; no run subcommand added.
- [ ] listen/network/log-level settable on the CLI; unspecified ⇒ current defaults.
- [ ] `--authorized-keys-host-access` promotes all authorized keys to Admin; off ⇒
      selective `admin_keys` behavior preserved.
- [ ] `--completions bash|zsh|fish|powershell` and `--man` print to stdout, exit 0,
      with zero side effects and no external `usage` executable.
- [ ] `usage-rs` declaration is the single source of truth for help/completions/man.
- [ ] SIGHUP reloads only file-backed policy.
- [ ] `cargo fmt/clippy/test/build` and MSRV 1.91 gates pass.

## Decisions and discoveries (live)

- Output actions are emitted in `main()` before the tokio runtime exists, so
  `--completions`/`--man` cannot touch config, keys, sockets, or logging.
- Unsupported completion shells are ValueEnum parse errors (non-zero exit) rather than a
  runtime `Shell::from_name` miss; the accepted set is exactly the four documented shells.
- M1 was committed alone (before the operational flags) because a flag-bearing `Args`
  with unread fields would trip `dead_code` under `-D warnings`, and an intermediate
  daemon that ignores its own flags is not a coherent slice.
- Rollback: work is a series of ordinary commits on
  `feat/cli-config-simplification`; any milestone can be reverted by
  `git revert <commit>` without data risk (no external state is touched).

## Risks / constraints

- `--authorized-keys-host-access` grants daemon-user authority by design; document that
  prominently (docs/security.md) rather than inventing a partial host role.
- The completion scripts generated by usage invoke the shbox binary for dynamic
  completion; verify the hidden completion intercept is compiled in (needs the
  `completions` feature at shbox compile time, not just at runtime).
- Linux-only behavior (`[limits.linux]`) cannot be compiled on this macOS host; the
  `#[cfg(target_os = "linux")]` code paths must be kept compile-correct and are covered by
  the Linux CI/MSRV gates and `scripts/verify-linux-platform` on a Linux host.
- OpenSSH integration tests need `sshd`-free loopback fixtures; keep using the existing
  `tests/fixtures/ssh_config` harness style.
