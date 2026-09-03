# Release gate / operational runbook

## 1. Release decision

shboxのrelease可否は、compile成功ではなくnative platform gateとproduction target acceptanceで決める。

現在の正式CI証拠はPR run `33518661744`、commit `aff82c4` である。このrunではRust 1.95/stable quality、supported-target build、Linux native confinement、macOS native Seatbeltの全jobがsuccessになった。

Fly Machinesでのproduction acceptanceは2026-09-02に実施したが、ゲストカーネルがLandlockを提供しないため成立しなかった（§9）。GitHub-hosted Linux gateの成功をFly Machine/imageの実証に読み替えてはならない。

## 2. CI execution policy

重いnative matrixは通常のbranch push/PRでは自動実行しない。自動triggerは `v*` version tag pushだけとし、必要なpreflightだけ `workflow_dispatch` で明示実行する。

これによりLinux x86_64/aarch64とmacOS 15/26のnative gateを開発中の各pushで消費せず、release candidate revisionに対して一度だけblocking validationを行う。

## 2. Current CI evidence

| Gate | Status | Evidence |
|---|---|---|
| Rust 1.95 quality | PASS | run `33518661744` |
| stable quality | PASS | same run |
| Linux x86_64 build | PASS | same run |
| Linux aarch64 build | PASS | same run |
| macOS arm64 build | PASS | same run |
| Linux x86_64 native confinement | PASS | kernel `6.17.0-1022-azure`, Landlock V6 |
| Linux aarch64 native confinement | PASS | kernel `6.17.0-1022-azure`, Landlock V6 |
| macOS 15 arm64 native Seatbelt | PASS | macOS `15.7.7` |
| macOS 26 arm64 native Seatbelt | PASS | macOS `26.5.2` |
| Fly production target | BLOCKED | Fly Machines guest kernel provides no Landlock; see §9 |

Linux native jobs reported:

- landlock `0.4` / seccompiler `0.5`（shbox-sandbox engine）
- Landlock ABI V6
- network support available
- signal/IPC scoping available
- seccomp network fallback: none
- non-root runner uid

macOS jobs proved a small Seatbelt allow profile and a small deny profile before running the full OpenSSH/PTTY suite.

## 3. Required Rust baseline

Release baseline is Rust **1.95**.

```sh
cargo +1.95 fmt --all -- --check
cargo +1.95 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95 test --locked --all-targets -- --test-threads=1
cargo +1.95 build --locked --all-targets
cargo +1.95 check --locked --all-targets
```

Stable is an additional forward-compatibility gate, not a replacement for the 1.95 baseline.

## 4. Native platform scripts

### Linux

```sh
./scripts/verify-linux-platform --arch x86_64
./scripts/verify-linux-platform --arch aarch64
```

scriptは次をfail-closedで確認する。

- native target
- non-root execution
- Rust 1.95
- pinned landlock 0.4 / seccompiler 0.5
- real Landlock capability probe
- locked release build
- full OpenSSH/PTTY acceptance
- `cargo check --all-targets`

Linux sandbox launch では resource limit の有無にかかわらず書き込み可能な cgroup v2 parent が必要で、`/proc/self/cgroup` はその capability 診断として表示する。

### macOS

```sh
./scripts/verify-macos-platform --os 15
./scripts/verify-macos-platform --os 26
```

scriptは次を確認する。

- native arm64
- expected OS major
- non-root execution
- Rust 1.95
- `/usr/bin/sandbox-exec`
- Seatbelt deny/allow smoke
- locked release build
- full OpenSSH/PTTY acceptance
- `cargo check --all-targets`

## 5. Blocking PTY acceptance

native platform gateは `SHBOX_RUN_SANDBOX_INTEGRATION=1` で実sandbox/PTTY suiteを有効にする。

release-blocking項目:

- PTY fd 0/1/2
- controlling terminal
- session leader
- foreground process group
- Ctrl-C
- Ctrl-Z / jobs / bg / fg
- terminal mode application and restore
- resize/window-change
- PTY stream semantics
- concurrent PTY isolation
- disconnect transport detach / detached descendant survival
- daemon fd/slave-fd leak absence
- shutdown cleanup

どれかがfailまたはskipなら、そのplatform tupleをrelease supportとして扱わない。

## 6. Linux confinement release contract

Linux sandboxはworkspace内crate `shbox-sandbox`（landlock `0.4` / seccompiler `0.5`）を利用する。外部sandbox executableはdeploy artifactに不要である。

release時に確認する契約:

- Landlock filesystem confinementが実kernelでprepare/applyできる
- workspaceとruntime tempだけがsandbox launchのwrite grantを持つ
- selected outside readが拒否される
- outside writeが拒否される
- `network = "disabled"` でfresh network namespaceが使われ、実TCP `connect()`と実UDP送信のhost/external reachabilityが拒否される
- `network = "outbound"` でcontrolled client endpointへの接続が成功する（portableなinbound behaviorは要求しない）
- resource limit 無指定時は sandbox launch が control-group delegation を必要としない

Linuxでは設定した memory/swap/PID/CPU limit を cgroup v2 で適用し、macOSでは memory/PID limit をそれぞれ `RLIMIT_AS`/`RLIMIT_NPROC` で適用する。macOSのCPU quota/swap limitは指定時にfail closedする。process group cleanupを完全なprocess-tree containmentとして表現しない。

## 7. macOS confinement release contract

macOSではparent側でSeatbelt profileを生成し、childを `/usr/bin/sandbox-exec -p <profile> -- <shell>` として起動する。

release時に確認する契約:

- `sandbox-exec`が対象OSで利用可能
- deny/allow smokeが実際にenforceされる
- workspace/temp writeとsystem runtime readが必要最小限で成立する
- `memory_max`/`pids_max` は rlimit として適用され、`cpu_quota_micros`/`swap_max` は fail closed する
- PTY allocation/session/job-controlはshbox-owned pathで成立する
- self-exec wrapperは存在しない

## 8. Production target acceptance

production support claimには、productionと同じimage/Machine configurationでの実測が必要である。

最低限、次をartifactへ記録する。

```sh
uname -a
cat /proc/version
id
ulimit -a
```

加えて実装のLinux capability probeから次を記録する。

- Landlock ABI
- network availability
- signal/IPC scoping availability
- seccomp network fallback

runtime proof:

1. unprivileged shbox startup
2. normal SSH authentication
3. non-PTY stdout/stderr/status
4. full PTY blocking suite
5. workspace persistence across sessions
6. outside-workspace denial
7. network-disabled behavior
8. outbound controlled endpoint
9. 20 sequential PTY sessions
10. 4 concurrent PTY sessions
11. daemon fd count recovery
12. PTY/session non-reuse isolation
13. SSH disconnect transport detach / detached descendant survival
14. graceful shbox shutdown cleanup
15. Linux daemon SIGKILL時のengine-owned direct child parent-death behavior（clone ownerがprocess-lifetime threadであることを含む）
16. deliberately detached new-session descendantの挙動記録
17. resource limit の有無にかかわらず delegated cgroup v2 process domain を使い、指定 limit が同じ domain に適用されること

このacceptanceはfilesystem/network grantを文書化されたpolicyより広げて通してはならない。

## 9. Fly status: BLOCKED (attempted 2026-09-02, failed)

Fly Machines上でproduction acceptanceを試みたが、成功しなかった。Fly Machinesはこのプロジェクトの正式production targetではない。

実施内容: このrepositoryの受入用container（`cargo build --locked --release`によるrevision `d86b3eb`、Rust 1.95.0、locked `Cargo.lock`、nono `0.74.0`、Debian 12 runtime、非root uid 1000）をapp `shbox-fly-acceptance`（region nrt、`shared-cpu-1x` 256MB、x86_64）へdeployし、同一Machine/image構成で検証した。

結果:

- ゲストカーネルは `6.12.105-fly`。`landlock_create_ruleset` が `ENOSYS` を返す（`Seccomp: 0`でフィルタによる隠蔽ではない）。Landlock LSMが無効なため `production_launcher` preflightは失敗し、sandbox launchはすべてfail-closedになった。設計どおりfallbackやpolicy拡張は行わず、この事実を記録として確定させた。
- 実測できた項目: 非root startup、admin keyによる正規OpenSSH認証（host mode `_`）、resource limit 無指定時に cgroup controller file を使わない起動パス。sandbox launchを要するproof item（PTY suite、永続化、network mode検証等）は実行不能。
- 非特権コンテキストでの実測: `unshare(CLONE_NEWUSER)` とseccomp filterは利用可能、`chroot` と単独のmount nsは不可。usernsベースのsandboxは技術的には成立しうるが、nono/Landlockとは別の新backend実装であり、現行releaseの範囲外。
- 公開networkの制約: Flyのshared IPv4はraw TCP（SSH）をedgeで切断するため、公開SSHにはdedicated IPv4が必要。検証はprivate network（`fly proxy`）で実施した。

結論: Fly MachinesではLandlockベースのshboxは動作しない。Landlock対応カーネルを持つprovider targetでのacceptanceが、このgateの成立条件である。受入用container一式（Dockerfile、`deploy/fly/`、`fly.toml`）とplanはこの判断とともにrepositoryから削除した。

## 10. Deploy hardening

### systemd

`deploy/systemd/shbox.service` は専用unprivileged userを使う。`NoNewPrivileges`等のservice hardeningを維持する。

`KillMode=control-group` はsystemd自身のservice cleanup choiceであり、shbox sandbox backendのcontroller delegation requirementを意味しない。

### launchd

launchdでも専用account、safe file modes、固定XDG rootsを使う。macOS sandboxはSeatbeltであり、追加launcher wrapper environmentは不要である。

## 11. Migration regression guards

CIはproduction source/deployに次の種類のarchitecture regressionが戻った場合にfailする。

- retired sandbox backend
- sibling sandbox launcher helper
- launcher control/self-exec environment path
- project-owned external sandbox CLI invocation（macOSの固定OS component `/usr/bin/sandbox-exec` は許可）
- sandbox process domain の control-group filesystem writes/delegation requirements

これらのstatic guardに加え、native behavior gateも必須である。

## 12. Evidence retention

release evidenceには最低限次を保存する。

- git commit
- `Cargo.lock`
- Rust/Cargo version
- OS/kernel version
- architecture
- executing username/uid
- OpenSSH version
- Landlock/cgroup capability diagnostics on Linux
- Seatbelt smoke result on macOS
- platform script exit status
- full OpenSSH/PTTY test result
- production target observations（そのtupleをproduction supportとしてclaimする場合）

## 13. Status update rule

support matrixは同一commitのpassing evidenceがある場合だけ更新する。

- compile-only: build coverage
- native platform script: OS/backend support evidence
- production Machine/image acceptance: production deployment evidence

これらを混同しない。新しいOS major、kernel family、production imageへ移行した場合は、そのtupleを再実測する。

## 14. 関連文書

- [testing.md](testing.md)
- [platforms.md](platforms.md)
- [security.md](security.md)
- [architecture.md](architecture.md)
