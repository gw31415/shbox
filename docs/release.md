# Release gate / operational runbook

## 1. Release decision

shboxのrelease可否は、compile成功ではなくnative platform gateとproduction target acceptanceで決める。

現在の正式CI証拠はPR run `33518661744`、commit `aff82c4` である。このrunではRust 1.95/stable quality、supported-target build、Linux native confinement、macOS native Seatbeltの全jobがsuccessになった。

Fly production acceptanceはまだ別項目として未完了である。GitHub-hosted Linux gateの成功をFly Machine/imageの実証に読み替えてはならない。

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
| Fly production target | NOT YET VERIFIED | exact production image/Machine evidence required |

Linux native jobs reported:

- nono `0.74.0`
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
- pinned nono 0.74.0
- real Landlock capability probe
- locked release build
- full OpenSSH/PTTY acceptance
- `cargo check --all-targets`

control-group delegationは前提ではない。`/proc/self/cgroup` は任意の環境診断としてのみ表示する。

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
- disconnect cleanup
- daemon fd/slave-fd leak absence
- shutdown cleanup

どれかがfailまたはskipなら、そのplatform tupleをrelease supportとして扱わない。

## 6. Linux confinement release contract

Linux sandboxはnono `0.74.0`をlibraryとして利用する。nono executableはdeploy artifactに不要である。

release時に確認する契約:

- Landlock filesystem confinementが実kernelでprepare/applyできる
- workspaceとlaunch tempだけがrequest-local write grantを持つ
- selected outside readが拒否される
- outside writeが拒否される
- `network = "disabled"` で実TCP connectが拒否される
- `network = "outbound"` でcontrolled client endpointへの接続が成功する（portableなinbound behaviorは要求しない）
- sandbox launchはcontrol-group delegationを必要としない

shboxはCPU/memory/PID quotaをsandbox featureとして提供しない。process group cleanupを完全なprocess-tree containmentとして表現しない。

## 7. macOS confinement release contract

macOSではparent側でSeatbelt profileを生成し、childを `/usr/bin/sandbox-exec -p <profile> -- <shell>` として起動する。

release時に確認する契約:

- `sandbox-exec`が対象OSで利用可能
- deny/allow smokeが実際にenforceされる
- workspace/temp writeとsystem runtime readが必要最小限で成立する
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
13. SSH disconnect cleanup
14. graceful shbox shutdown cleanup
15. Linux daemon SIGKILL時のdirect child parent-death behavior
16. deliberately detached new-session descendantの挙動記録
17. sandbox launchがwritable control-group controller filesを必要としないこと

このacceptanceはfilesystem/network grantを文書化されたpolicyより広げて通してはならない。

## 9. Current Fly status

現時点では、このrepositoryから利用できるFly credential/CLI/Machine configurationがなく、productionと同一imageのacceptance artifactも記録されていない。そのためFly tupleは **NOT YET VERIFIED** とする。

また、consumer側production imageがこのbranchのnative confinement実装をpinした証拠がない状態では、別のLinux container testをFly acceptanceとして扱わない。

この状態はCI native Linux supportとは区別する。CIはLinux backendの実動証拠を提供するが、Fly固有のkernel/image/runtime topologyまで保証しない。

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
- external sandbox CLI invocation
- sandbox用control-group filesystem writes/delegation requirements

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
- nono/Landlock capability diagnostics on Linux
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
