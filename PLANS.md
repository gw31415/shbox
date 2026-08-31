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

### usage-rs 6.5.0 API findings (verified from the vendored crate sources)

- `usage-derive` generates `Args::spec() -> usage_argv Spec`, `Args::to_kdl() -> String`,
  and typed `FromStr`-based flag parsing; `#[usage(long)]` per field.
- Completions are behind a crate feature: enable
  `usage = { package = "usage-rs", version = "=6.5.0", features = ["completions"] }`.
  With `#[usage(completion)]` on the derive, `Args::completion_script(shell) -> String` is
  generated (in-process; the generated script calls the shbox binary itself at shell
  runtime — no external `usage` executable is required to generate or to complete).
  `usage::complete::Shell` is `#[non_exhaustive]` with
  `Bash/Elvish/Zsh/Fish/Nu/PowerShell` and `Shell::from_name` accepting
  `bash|elvish|zsh|fish|nu|nushell|powershell|pwsh`.
- Man page rendering lives in `usage-lib` (`docs::manpage::ManpageRenderer::new(spec)
  .with_section(1).render()`), a separate crate from `usage-argv` with its own `Spec` type
  (usage-lib does not depend on usage-argv). MSRV of usage-lib 6.5.0 is 1.91; default
  features include `docs`→`manpage`. Bridge in-process:
  `Args::to_kdl()` → `usage_lib::Spec::parse_spec(&kdl)` → `ManpageRenderer`.
  The derive stays the single source of truth; no hand-written roff, no duplicate flag table.
- Repeated flags: `Vec<T>` fields collect repeated `--flag value`; validation of
  duplicates/emptiness stays our job after parse. Verify both with a compiler probe first
  (Milestone 1 acceptance).

## Milestones

Each milestone is independently verifiable; commit (via `$archive-commit`) and push after
each verified slice. Prune this plan in the same commit that implements a milestone.

### M1 — CLI surface on `Args` (options + output actions)

- Goal: `Args` carries `--listen` (repeatable), `--network`, `--log-level`,
  `--authorized-keys-host-access`, `--completions <SHELL>`, `--man`; typed parsing
  rejects invalid values before bootstrap; output actions are side-effect free and
  mutually exclusive; defaults are `0.0.0.0:22` / `disabled` / `info` / false.
- Edits: `src/main.rs` (Args definition, completion/man emission before any IO),
  `Cargo.toml` (usage features, add `usage-lib = "=6.5.0"`); compiler probe test for
  `Vec<SocketAddr>` repeated flags and enum-from-str behavior where uncertain.
- Result: `shbox --completions bash|zsh|fish|powershell` and `shbox --man` print and exit 0
  without touching config/keys/host key/sockets; `--completions nu` exits non-zero;
  `--completions bash --man` exits non-zero; invalid `--listen`/`--network`/`--log-level`
  values are parse errors.
- Proof: `cargo test --locked --all-targets -- --test-threads=1` plus a unit test module
  for `Args` covering the plan's CLI parser matrix, and a real-CLI check
  (`cargo run -- --completions zsh | head`, `--man | head`, exit codes).

### M2 — `listen`/`network`/`log_level` move from TOML to CLI

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

- Completions use the derive-generated `completion_script` (`#[usage(completion)]` +
  `features = ["completions"]`) rather than `usage::complete::complete(&CompleteOptions)`:
  it is the in-process path that embeds the CLI's own spec and needs no external binary.
  Shell name mapping via `usage::complete::Shell::from_name`; unsupported names are our
  typed-parse/argument error (non-zero exit).
- Man pages require adding `usage-lib = "=6.5.0"` (separate crate from `usage-rs`;
  its `Spec` is distinct from the `usage-argv` `Spec`). Bridge by KDL round-trip
  (`to_kdl()` → `Spec::parse_spec`) so the derive remains authoritative.
- `NetworkMode`/`LogLevel` domain types stay in `config.rs` and are constructed from CLI
  values (typed at the `Args` layer) instead of from TOML strings.
- `--listen` validation (duplicates, empty) happens after parse in our code; parse itself
  rejects malformed `SocketAddr`.
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
