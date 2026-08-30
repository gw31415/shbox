# M8 release gate / operational runbook

## Release decision

**BLOCKED — UNVERIFIED (2026-08-31).**

同一 commit で blocking suite を通過した実 platform の記録がまだありません。直近の hosted run
`33323898522`（commit `1a393e9`）も stable と Rust 1.91 の quality job が
`clippy::useless_conversion`（Linux の `mode_t = u32` に対する `u32::from`）で失敗し、
Linux/macOS の platform job は skipped でした。初回 run `33323095132`（commit `14a590e`）も
clippy で失敗しています。したがって、Linux x86_64、Linux aarch64、
macOS 15 arm64、macOS 26 arm64 のいずれも formal support 済み、または ship 可能とは扱いません。
build 成功、runner label、Arapuca upstream の一般的な対応表だけではこの状態を解除できません。

GitHub Actions はクレジットを消費するため、`1a393e9` 以降の hosted rerun は行わない。以下の
local Docker/native evidence は開発上の回帰確認であり、formal release evidence への昇格条件は
変更しない。

次の全てを同一 commit の blocking run で確認し、workflow log を保存できた場合だけ tuple ごとに `VERIFIED` へ更新します。一つでも未実行、前提不足、失敗、または証跡欠落なら、その tuple と release は `BLOCKED / UNVERIFIED` のままです。

| tuple / gate | 現在の状態 | blocking 条件 |
| --- | --- | --- |
| Rust 1.91.0: fmt / clippy / test / build | **HOSTED STALE / LOCAL PASS**（latest run `33323898522` の後に修正） | formal status には同一 commit の blocking evidence が必要。hosted rerun は実施しない |
| Rust stable: fmt / clippy / test / build | **HOSTED STALE / LOCAL PASS**（latest run `33323898522` の後に修正） | formal status には同一 commit の blocking evidence が必要。hosted rerun は実施しない |
| Linux x86_64 | **BLOCKED / UNVERIFIED**（runs は skipped） | 専用 delegated cgroup v2 runner、native build、real Arapuca、real OpenSSH suite |
| Linux aarch64 | **BLOCKED / UNVERIFIED**（runs は skipped） | 専用 delegated cgroup v2 runner、native build、real Arapuca、real OpenSSH suite |
| macOS 15 arm64 | **BLOCKED / UNVERIFIED**（runs は skipped） | 固定 `macos-15` runner、native arm64、Seatbelt、real Arapuca、real OpenSSH suite |
| macOS 26 arm64 | **BLOCKED / UNVERIFIED** (local preflight passed) | 固定 `macos-26` runner、native arm64、Seatbelt、real Arapuca、real OpenSSH suite |

### Local preflight evidence (not formal support evidence)

2026-08-31 の開発ホストでは、macOS `26.6.2` / native `arm64` / uid `501` 上で、外部 `arapuca`
が PATH に無い状態の native build と real OpenSSH suite を実行し、embedded rlimit wrapper、
Seatbelt、suite `21 passed` を確認した。

```console
command -v arapuca   # no output
RUSTC_WRAPPER= cargo build --locked --release
RUSTC_WRAPPER= cargo test --locked --test ssh_auth -- --test-threads=1
```

これは hosted `macos-26` workflow の同一 commit log ではないため、macOS 26 tuple の formal status と release decision は変更しない。`scripts/verify-macos-platform` は pinned 外部 wrapper の provenance も検査するため、別 wrapper の互換性を確認したい場合に使う。

同日、`docker run --platform linux/arm64` の `rust:1.97-bookworm` と `rust:1.91.0-bookworm` で
fmt / clippy / test / build を実行した。Linux container は delegated cgroup scope を提供しないため、
real-platform gate の代替とはせず、通常の fail-closed と SSH harness/build の回帰確認として扱う。

## 実行 artifact

`.github/workflows/m8-release-gate.yml` は `main` への push、`v*` tag、または手動 dispatch で次を実行します。PR の untrusted code を self-hosted runner へ送らないよう、workflow に pull request trigger はありません。platform job に `continue-on-error` や prerequisite 不在時の skip はなく、前提が無ければ job は失敗します。

- `Rust 1.91.0` と `stable` の各々で `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets --all-features -- -D warnings`、`cargo test --locked --all-targets -- --test-threads=1`、`cargo build --locked --all-targets` を実行します。
- `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、`aarch64-apple-darwin` の locked build を固定 target で実行します。
- Linux gate は専用 label `m8-linux-x86_64-cgroup` または `m8-linux-aarch64-cgroup` の self-hosted runner に限定します。
- macOS gate は mutable な `macos-latest` を使わず、`macos-15` と `macos-26` をそれぞれ指定します。スクリプト側でも `sw_vers` と `uname -m` を再確認します。
- `scripts/verify-linux-platform` と `scripts/verify-macos-platform` は、前提確認後に pinned revision から wrapper を自分で build し、その private wrapper を `PATH` の先頭に置いて `cargo build --locked` と `SHBOX_RUN_ARAPUCA_INTEGRATION=1 cargo test --locked --test ssh_auth -- --test-threads=1` を実行します。これは `tests/ssh_auth.rs` の real OpenSSH harness を使う blocking suite です。macOS arm64 の通常 shbox 実行には別 wrapper は不要ですが、script は pinned 外部 wrapper の provenance/互換性を検査する gate として残します。外部の wrapper path や revision 宣言を provenance として信頼しません。

## Arapuca prerequisite と lock

Arapuca は package version `0.2.7` と、次の full Git revision の組合せだけを許可します。

```text
https://github.com/LeGambiArt/arapuca
c94802c4d8b6b880334c0d643b16b7326ec7f039
```

両 gate は `Cargo.toml` の dependency と `Cargo.lock` の `0.2.7` package source がこの revision に一致することを検査します。各 script は wrapper を次の exact revision から build し、同じ private build の `PATH` を使って suite を起動します。

```sh
./scripts/verify-linux-platform --arch x86_64 --target x86_64-unknown-linux-gnu
./scripts/verify-macos-platform --os 15
```

固定 revision の clone/build が失敗する、wrapper が実行できない、または version が `0.2.7` でない場合、各 script は test を skip せず直ちに non-zero で終了します。wrapper の不在を direct host execution へ degrade する経路は gate にありません。

## Linux delegated cgroup gate

Linux script は native `x86_64` または `aarch64`、kernel 5.13 以上、non-root account、unified cgroup v2 を要求します。現在の service cgroup に `cpu`、`cpuset`、`memory`、`pids` が `cgroup.controllers` と `cgroup.subtree_control` の両方で確認できなければ失敗します。

さらに、script は現在の cgroup の下に専用 child を作り、短命な helper だけを `cgroup.procs` へ移動して、child の controller と membership を検査します。helper の終了後に child が空でなければ、未知の process を kill せず gate を失敗させます。これにより shared/root cgroup の見かけ上の存在だけを delegated gate の成功としません。

実行例は次のとおりです。実行するアカウントが専用 runner/service account であることを運用者が確認し、必要なら `SHBOX_EXPECTED_USER` も設定します。

```sh
SHBOX_EXPECTED_USER=shbox \
  ./scripts/verify-linux-platform --arch x86_64 --target x86_64-unknown-linux-gnu

SHBOX_EXPECTED_USER=shbox \
  ./scripts/verify-linux-platform --arch aarch64 --target aarch64-unknown-linux-gnu
```

```sh
./scripts/verify-macos-platform --os 15
./scripts/verify-macos-platform --os 26
```

`SHBOX_EXPECTED_USER` を省略した場合も uid 0 は拒否されますが、release evidence には実行 username、uid、専用 runner label、`/proc/self/cgroup`、required controller の値を必ず残します。

## OpenSSH suite と evidence

platform script は `ssh`、`ssh-keygen`、`cargo metadata --locked`、固定 target の build を確認してから integration environment を明示的に有効化します。suite のログには少なくとも次を同じ run で残します。

- `rustc -vV` の host と toolchain、Cargo lock check の結果
- `uname -s` / `uname -m` / `uname -r`、Linux の cgroup path と controller 内容、または macOS の `sw_vers -productVersion`
- 実行 username と uid、Arapuca wrapper path/version、宣言した full revision
- `tests/ssh_auth.rs` の serial real OpenSSH suite の全 test 結果

integration environment を設定しない通常の Linux Rust test job は、wrapper/delegated cgroup が無いときの fail-closed behavior を検査します。macOS arm64 の通常 test は embedded wrapper により Seatbelt の成功経路を検査します。platform job は前提を確認した後にだけ integration environment を設定するため、単に adapter が unavailable だったことを成功証拠にしません。

## 配備 artifact

Linux の最小 unit は [`deploy/systemd/shbox.service`](../deploy/systemd/shbox.service) です。unit の要点は次のとおりです。

- `User=shbox`、`Group=shbox`、`UMask=0077` で non-root の dedicated account を固定します。
- `Delegate=cpu cpuset memory pids` を指定します。service cgroup に無関係な process を置かず、Arapuca がその下に private child を作れることを実機で確認します。
- port 22 を使う場合だけ `CAP_NET_BIND_SERVICE` を ambient/bounding set に渡します。別 port と operator-managed forwarding を使う場合は不要です。
- `KillMode=control-group` と停止 timeout を指定し、daemon の process descendants を unit の lifecycle に残しません。
- `XDG_CONFIG_HOME=/etc`、`XDG_DATA_HOME=/var/lib`、`XDG_STATE_HOME=/var/lib/shbox-state` は xdg の `shbox` prefix を含むため、実際の application roots は `/etc/shbox`、`/var/lib/shbox`、`/var/lib/shbox-state/shbox` です。三つの親 directory と config/authorized key は事前に専用 account 所有、非 writable な mode にします。

macOS の launchd 例は [`deploy/launchd/com.example.shbox.plist`](../deploy/launchd/com.example.shbox.plist) です。`UserName=shbox` と dedicated home/XDG roots を固定し、launchd が収集する stderr/stdout path も account-owned path にしています。この plist は account、directory、owner、mode の provisioning や installer/start/stop command を含みません。

macOS backend は Apple の deprecated `/usr/bin/sandbox-exec` (Seatbelt) に依存します。15/26 の arm64 gate がその exact OS で実際に通るまで、将来 OS や macOS x86_64 へ support claim を広げません。Seatbelt が無い、probe が失敗する、OS major version または architecture が違う場合は script が fail closed します。

## Verification status update rule

この文書の matrix を `VERIFIED` に変更するのは、workflow run URL、commit、固定 OS/architecture、全 blocking job の成功ログが揃った後だけにしてください。現時点では成功証跡がなく、初回 run は失敗しているため、M8 は未完了であり release は blocking です。
