# Testing と release gate

この文書は shbox v0.1 の試験契約を定める。compile の成功だけでは sandbox support の証拠にならない。正式な platform gate は、実 OS confinement、実 OpenSSH client、実 PTY/job-control、cleanup を同じ native runner で通す。

## 1. 基本方針

試験は次の層に分ける。

1. domain/unit/property test
2. compile/Clippy/format
3. 実 OpenSSH integration
4. native OS confinement gate
5. production target acceptance

上位の層を下位の成功で代用しない。特に generic Linux build job は Landlock の production capability を証明しない。

Rust の必須 baseline は **1.95** である。CI では Rust 1.95 をrelease baselineとして実行し、stableもforward-compatibility確認として実行する。

## 2. CI support matrix

| Tuple | Build coverage | Native blocking gate |
|---|---:|---:|
| Linux x86_64 | required | required |
| Linux aarch64 | required | required |
| macOS 15 arm64 | required | required |
| macOS 26 arm64 | additional fixed-version gate | required |

macOSは固定OS majorのrunnerで試験し、`macos-latest`から将来versionまでを一括保証しない。Linuxもnative kernel上のconfinement gateを必須とする。

## 3. 標準quality gate

最低限、次をRust 1.95で通す。

```sh
cargo +1.95 fmt --all -- --check
cargo +1.95 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95 test --locked --all-targets -- --test-threads=1
cargo +1.95 build --locked --all-targets
cargo +1.95 check --locked --all-targets
```

CIはさらにstable toolchainでもformat/Clippy/test/buildを実行する。

## 4. Domain / unit / property test

### 4.1 入力と設定

必須項目:

- `SandboxId` が `[A-Za-z0-9][A-Za-z0-9-]{0,63}` と完全一致すること
- `_`、path separator、Unicode、control character、overlong IDを拒否すること
- unknown TOML fieldを拒否すること
- `sandbox.network` は `disabled` / `outbound` だけを受理すること
- `sandbox.read_paths` はabsolute/canonical pathだけを受理し、shbox管理rootを公開しないこと
- environment name/value、reserved name/prefix、NUL、size limitを検証すること
- config/key/host-key/XDG pathのownership・mode・symlink safetyを検証すること

### 4.2 Sandbox lifecycle

必須項目:

- first-owner-wins
- global/per-owner sandbox caps
- atomic reservation
- metadata state transitionとcrash recovery
- deleteのidempotency
- create/delete競合
- startup reconciliation
- management/workspace symlink attack拒否
- process lease capのatomicity
- daemon shutdown時の全runtime lease cleanup

### 4.3 ProcessLauncher seam

fake launcherでは次を決定的に試験する。

- shell/exec request mapping
- PTY / non-PTY stream semantics
- stdin/stdout/stderr ownership
- resize
- signal forwarding
- terminate / force terminate
- launch failure
- concurrent launchとdelete barrier

fake launcherの成功はnative sandbox gateの代用ではない。

## 5. Linux native confinement test

Linux production backendはworkspace内の`shbox-sandbox` engine（landlock 0.4 / seccompiler 0.5）を使い、Landlock ruleset・seccomp BPF・cgroupをparent側で準備してchildで適用する。engine自体のunit/integration testは`cargo test -p shbox-sandbox`で実行される。

`scripts/verify-linux-platform --arch x86_64|aarch64` はblocking gateであり、次を確認する。

- native architecture
- non-root execution
- Rust 1.95
- pinned landlock 0.4 / seccompiler 0.5（engine crate）
- 実kernelのLandlock ABI
- network rights availability
- signal/IPC scoping availability
- Landlock network mediationの有効性（ABI 4+）
- locked release build
- full native OpenSSH/PTTY suite
- `cargo check --all-targets`

Linux sandbox availability には、resource limit の有無にかかわらず書き込み可能な cgroup v2 parent が必要である。無い場合は launch が fail closed する。環境診断として `/proc/self/cgroup` を表示する。

### 5.1 Filesystem proof

実launcherで最低限次を証明する。

- workspace read/write成功
- sandbox-runtime-scoped `TMPDIR` read/write成功（Linux）
- sandbox外write拒否
- 選択したsensitive sandbox外read拒否
- configured read-only pathはreadのみ許可
- sibling workspace / sibling launch-tempにgrantがない
- child-created temp entriesを含め、runtime domain drain後にLinux runtime tempがcleanupされる

### 5.2 Network proof

`disabled`:

- fresh user+network namespace が作成され、host/external route/interface を共有しないこと
- 実TCP `connect()` が失敗すること
- 実UDP送信でhost/external endpointへ到達できないこと

`outbound`:

- controlled endpointへのclient connectionが成功すること

`outbound` のportable contractは任意宛先へのclient connectionが使えることまでである。Linuxでは現在これより広いsocket accessが可能になり得るが、macOSはbind/inboundをallowしない。testはclient successを必須にし、portableなinbound behaviorを仮定しない。

engine 単体で all-network denial を検証する場合は、必要な user namespace または privilege setup とともに `NetworkNamespacePolicy::Isolated` を明示し、fresh network namespaceから外部到達性がないことを確認する。public shbox adapter は `network = "disabled"` からこの構成を自動的に選択する。

### 5.3 Process cleanup proof

- PID namespace無しではdirect childをreapする前にinitial owned process groupの残processを停止すること
- PID namespace有りではinternal PID1 supervisorの下でuser commandがPID2として動き、signal/status forwardingとnamespace descendant teardownが成立すること
- signal requestがowned foreground/process groupへ届くこと
- disconnectではtransportだけをdetachし、delete/daemon shutdownでmanaged groupを停止すること
- Linux cloneはprocess-lifetime spawn-owner threadが担当し、engine-owned direct childはdaemon death時のparent-death signalを持つこと

Landlock confinement inheritanceとprocess cleanupは別の保証である。意図的に新sessionへdetachしたdescendantを、process-group cleanupが完全なprocess tree containmentとして回収するとは主張しない。

## 6. macOS native confinement test

`scripts/verify-macos-platform --os 15|26` はblocking gateであり、次を確認する。

- native arm64
- expected macOS major
- non-root execution
- Rust 1.95
- `/usr/bin/sandbox-exec` の存在
- tiny allow profileが実行可能
- tiny deny profileが指定readを実際に拒否
- locked release build
- full OpenSSH/PTTY suite
- `cargo check --all-targets`

production launcherはSeatbelt profileをspawn前に構築し、`sandbox-exec -p <profile> -- <shell>`で適用する。PTYはshboxが所有するため、Seatbelt smokeだけでPTY correctnessを代用しない。

macOS resource-limit testでは `memory_max` が `RLIMIT_AS`、`pids_max` が `RLIMIT_NPROC` に変換されること、`cpu_quota_micros` または `swap_max` の指定が launch 前に fail closed することを確認する。

## 7. OpenSSH / PTY blocking suite

`SHBOX_RUN_SANDBOX_INTEGRATION=1` で実sandbox acceptanceを有効にする。

全supported native tupleで最低限次を必須とする。

### 7.1 non-PTY

- command bytes -> selected shell `-c`
- stdin/stdout/stderr分離
- exit-status
- signal終了時のexit-signal
- workspace/HOME/PWD/SHELL/TMPDIR environment

### 7.2 PTY identity

- fd 0/1/2 がTTY
- childがdaemonとは別session leader
- `getsid()` と `tcgetsid()` が一致
- foreground PGIDと`tcgetpgrp()`が一致
- concurrent PTYが別terminal device identityを持つ

identity probeはpathを再openせず、実PTY fdに対する`isatty`/session/ioctl/fstat情報を使う。

### 7.3 Interactive job control

実interactive shellで次を確認する。

- foreground command
- Ctrl-C
- Ctrl-Z
- `jobs`
- `bg`
- `fg`
- nested foreground processへのterminal signal
- raw-mode変更とrestore

pipeをPTYの代用にしてはならない。

### 7.4 Terminal modes / resize

- initial rows/columns
- zero dimensionsを含むrequest semantics
- known POSIX terminal control characters/flags
- unknown modeの安全なignore
- `window-change`
- session Aのresizeがsession Bへ漏れないこと

### 7.5 Disconnect / cleanup / FD lifecycle

- client disconnect後にPTY transportがdetachされ、`setsid()` descendantが生存できること
- sandbox delete後にdetach済みdescendantもcgroup経由で終了/reapされること
- repeated PTY open/close後にdaemon fd countがbaseline付近へ戻ること
- daemonがPTY slave fdを保持しないこと
- session Aへのsignalがsession Bへ漏れないこと
- daemon graceful shutdownでmanaged processを停止すること
- second shutdown signalでforce cleanupへ移行できること

## 8. Authentication / protocol integration

実OpenSSH harnessでは次も必須である。

- Ed25519 public-key authentication
- normal key / admin key role分離
- selector ownership enforcement
- `_` host selectorはadminだけ
- list/delete subsystem
- env request拒否
- unknown subsystem拒否
- key file変更の次authへの反映
- malformed key update時のlast-known-good snapshot維持
- SIGHUP再検証
- multiple independent connections

## 9. CI migration guards

release workflowは `v*` tag push時（または明示的なmanual dispatch時）だけ実行する。通常のbranch push/PRでは重いnative matrixを起動しない。

release workflowはproduction inputsに、廃止済みsandbox backend、sibling launcher helper、launcher-control environment path、project-owned external sandbox CLI invocation、resource limit 無指定時の sandbox 用 control-group filesystem write pathが再導入された場合に失敗する（macOSの固定OS component `/usr/bin/sandbox-exec` は許可）。

このguardはbehavior testの代用ではなく、release時にarchitecture regressionを拒否する追加条件である。開発中の検出はlocal checksを使い、必要な場合だけmanual dispatchする。

## 10. 現在のCI証拠

PR run `33518661744`、commit `aff82c4` でnative release gateは全job成功した。

- Rust 1.95 quality gate: success
- stable quality gate: success
- Linux x86_64 build: success
- Linux aarch64 build: success
- macOS arm64 build: success
- Linux x86_64 native confinement: success
- Linux aarch64 native confinement: success
- macOS 15 arm64 Seatbelt: success
- macOS 26 arm64 Seatbelt: success

Linux native jobsはkernel `6.17.0-1022-azure`、Landlock ABI V6、network support有効を報告した（nono `0.74.0` 時代の記録。engine 移行後に再取得する）。

macOS jobsは `15.7.7` と `26.5.2` のarm64 runnerでSeatbelt deny/allow smokeとfull suiteを通した。

## 11. Production target acceptance

GitHub native gateがgreenでも、Fly production tupleのacceptanceを代用しない。production image/Machine上で次を別途実測する。

- unprivileged daemon startup
- normal SSH auth
- non-PTY streams/status
- full PTY suite
- workspace persistence
- filesystem deny
- disabled/outbound network
- 20 sequential PTY sessions
- 4 concurrent PTY sessions
- fd baseline回復
- disconnect transport detach / detached descendant survival
- graceful daemon shutdown
- Linux daemon SIGKILL時のdirect-child parent-death behavior
- deliberately detached descendantの明示的な制約確認
- resource limit の有無にかかわらず sandbox launch が delegated cgroup v2 process domain を使い、指定 limit が同じ domain に適用されること

このproduction acceptanceがないtupleを「Fly verified」と記載してはならない。

## 12. Release checklist

- [ ] Rust 1.95 format / Clippy / tests / build pass
- [ ] stable forward-compatibility quality pass
- [ ] Linux x86_64 build pass
- [ ] Linux aarch64 build pass
- [ ] macOS arm64 build pass
- [ ] Linux x86_64 native confinement pass
- [ ] Linux aarch64 native confinement pass
- [ ] macOS 15 arm64 Seatbelt pass
- [ ] macOS 26 arm64 Seatbelt pass
- [ ] migration guards pass
- [ ] production target acceptance recorded for any production support claim

## 13. 関連文書

- [architecture.md](architecture.md)
- [platforms.md](platforms.md)
- [security.md](security.md)
- [ssh-protocol.md](ssh-protocol.md)
- [release.md](release.md)
