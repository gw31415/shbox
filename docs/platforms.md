# Platform boundary

shbox の正式 support は「target で build できる」ことではなく、native OS/architecture 上で real confinement と real OpenSSH/PTTY blocking suite が passing であることを意味する。

## 1. 共通 architecture

```text
SSH/session layer
    -> ProcessLauncher
        -> shbox-owned PTY/process lifecycle
        -> shbox-sandbox engine (in-workspace crate)
            Linux: clone3 + pidfd + Landlock + seccomp
                   + durable cgroup v2 process domain (CLONE_INTO_CGROUP)
                   + namespaces + subordinate identity + ID-mapped mounts
                   + no_new_privs + capability drop
            macOS: generated Seatbelt profile
                   via /usr/bin/sandbox-exec
```

`ProcessLauncher` は private test seam であり public backend selector ではない。shbox の policy 層は backend-neutral で、shell、network mode、read-only paths、environment、private runtime temp root、resource limits を表現し、launch ごとに explicit な engine `SandboxConfig` へ解決する。engine crate 自体は preset/profile を持たない（[crates/shbox-sandbox](../crates/shbox-sandbox/README.md)）。

両 platform とも shbox 自身が次を所有する。

- child spawn/wait/reap
- process session/group
- PTY pair と descriptor lifetime
- controlling terminal
- terminal modes/size
- signal/resize forwarding
- runtime temp cleanup

confinement library/tool に PTY ownership を委譲しない。

## 2. Linux

### 2.1 Confinement

Linux は workspace 内の `shbox-sandbox` crate（`landlock 0.4` / `seccompiler 0.5` / libc のみ）を engine として使う。外部 executable/CLI は必要ない。

parent process は child を作る前に:

- Landlock ABI を detect
- filesystem/network policy を Landlock ruleset として構築（path fd はこの時点で open・pin される）
- seccomp policy があれば BPF program まで compile
- public shbox adapter は resource limit の有無にかかわらず `SandboxId` 共有 process domain cgroup を child 生成前に準備し、explicit limit があれば同じ domain に書き込む
- argv/envp/cwd を C string まで marshal

`[sandbox] identity = "isolated"` を選択した場合は、subordinate UID/GID lease
に対する parent mapping barrier を完了し、root の socket-activated
`shbox-idmap-broker` から detached ID-mapped workspace/runtime mount FD を受け
取る。broker は任意 pathname や command を受け取らず、source directory FD と
mount-ID-map user namespace FD だけを検証する。broker または ID-mapped mount が
利用できない場合は host identity に戻さず launch を拒否する。

する。実際の `clone3` は process-lifetime の専用 spawn-owner thread が担当するため、`PR_SET_PDEATHSIG` の親 thread は短命な Tokio blocking worker にならない。PID namespace 無しでは user child を `clone3(CLONE_PIDFD | … | CLONE_INTO_CGROUP)` で直接生成する。PID namespace 有りでは outer clone を内部 PID1 supervisor/reaper とし、user PID2 を同じ process domain cgroup 内へ直接生成する。post-clone path は固定順序・allocation-free で、path lookup、policy allocation、filter compile を行わない。

engine の invariant（no_new_privs、capability drop、FD hygiene、setup 失敗時の fail-closed、pidfd supervision）は shbox policy からは弱められない。

### 2.2 Filesystem policy

per launch write access:

- current sandbox workspace
- sandbox-runtime-scoped private temp on Linux; unique private launch temp on macOS
- `/dev/null`

curated read-only baseline は ordinary command runtime に必要な system binaries/libraries、select TLS/resolver/account data、entropy devices、`/dev/tty` に限定する。

特に host-shared temporary tree、procfs、sysfs、全 PTY namespace を broad grant しない。operator `read_paths` は追加 read-only grant である。

Landlock restriction は descendant に継承される。

### 2.3 Network

`disabled` は fresh user+network namespace と Landlock network rules を組み合わせる。fresh network namespace が host/external network reachability を切り離し、child は capability drop 後に exec されるため初期状態で down の loopback を再構成できない。Landlock（ABI 4+）は TCP `bind`/`connect` も deny する。必要な namespace setup または Landlock network rights が利用できなければ launch は fail closed する。

`outbound` のpublic contractは任意remote endpointへのclient connectionを利用可能にすることまでとする。Linux mappingは `NetworkPolicy::Unrestricted`（Landlock network ruleなし）であり、任意remote portへのconnectだけをwildcard許可してbindだけを禁止するportless Landlock ruleとして偽装しない。このためLinuxではcontractより広いsocket operationが可能になり得る。macOSは別途bind/inbound ruleを付与しない。

Ubuntu 24.04 では `kernel.apparmor_restrict_unprivileged_userns=1` の環境を想定し、
deployment artifact の `deploy/apparmor/usr.local.bin.shbox` をロードする。この専用
profile により shbox の bootstrap user namespace だけが generic
`unprivileged_userns` profile による `CAP_SETGID`/`CAP_SYS_ADMIN` 拒否を受けない。

### 2.4 seccomp / namespaces

engine は per-sandbox な seccomp filter（allowlist/denylist/argument filter）と namespace 選択（pid/mount/ipc/uts/net）を `SandboxConfig` 経由で提供する。user namespace はこの topology 選択には含まれず、identity policy（`IdentityPolicy::Host`/`CallerMappedRoot`/`Isolated`）から導かれる。`CallerMappedRoot` と `Isolated` が fresh user namespace（`CLONE_NEWUSER`）を作り、`Isolated` は加えて fresh mount namespace（ID-mapped writable view の置き換え用）と空の capability set を要求する。shbox の Linux mapping では、`network = "disabled"` のとき network namespace を分離し、host 互換 mode はその network namespace を unprivileged に作るため `CallerMappedRoot` user namespace を使う（`network = "outbound"` の host 互換 mode は user namespace を作らない）。pid/ipc/uts namespace と syscall filter は現時点では有効化しない。capability drop と no_new_privs は policy によらず常に適用される。

### 2.5 PTY/process setup

PTY child:

1. parent-death signal
2. PTY slave -> fd 0/1/2
3. `setsid()`
4. controlling terminal acquisition
5. workspace `chdir`
6. prepared confinement apply
7. shell exec

non-PTY childもnew sessionを作り、pipesをfd0/1/2へ接続して同じconfinementを適用する。

setup failureはstatus pipeでparentへ返し、partially configured childを公開しない。

### 2.6 cgroup v2 process domain

public shbox adapter は resource limit の有無にかかわらず `SandboxId` ごとに一つの durable process domain cgroup を作り、同じ sandbox の全 concurrent launch を `clone3(CLONE_INTO_CGROUP)` で最初からその cgroup に入れる（limit 適用前の window が存在しない）。explicit limit があれば同じ domain に適用し、すべて `Inherit` でも process ownership boundary として cgroup を保持する。child exit では shared domain を削除せず、sandbox deletion が runtime cleanup を完了した後に release/remove する。`cpu_period_micros` 単独では cgroup limit を変更しない。direct `shbox-sandbox::Sandbox::spawn` は resource limit 指定時に one-shot per-launch cgroup を所有する。

cgroup parent は auto-discovery（自身の cgroup から上位へ、必要 controller を `subtree_control` に有効化できる最初の階層）または `[sandbox] cgroup_parent` で明示指定できる。書き込み可能な cgroup 階層が無い場合、public sandbox launch は limit の有無にかかわらず fail closed する。

明示 limit は parent/ancestor cgroup の制限に追加される制限であり、child が inherited cgroup restriction を解除または引き上げることはできない。

systemd の `KillMode=control-group` を deployment artifact で使う場合、それはservice managerがdaemon service全体をcleanupする方針であり、per-sandbox cgroup delegationとは別の概念である。

systemd deployment では `Delegate=cpu memory pids` と `DelegateSubgroup=daemon` を設定し、daemon
自身を delegated leaf に置く。systemd は指定 controller を delegated subtree から利用可能にするが、
`cgroup.subtree_control` 自体は有効化しないため、shbox が limit 用 child cgroup の作成時に必要な
controller だけを有効化する。`DelegateSubgroup` を持たない古い systemd はこの
deployment tier の対象外であり、launcher wrapper で代替しない。

### 2.7 Resource limits

per-sandbox の memory/swap/PID/CPU quota は `[sandbox]` 設定（[configuration.md](configuration.md)）で付与する。無指定の分野は provider/service manager 側の resource controls を継承する（`Inherit`）。macOS では memory/PID のみがそれぞれ `RLIMIT_AS`/`RLIMIT_NPROC` に変換され、CPU quota と swap limit は startup で fail closed する。

### 2.8 Lifecycle containment

Linux の SandboxId ごとの durable cgroup process domain が process ownership unit で
あり、engine-owned direct child の parent-death behavior と組み合わせて delete/
shutdown の全 process 回収を担う。PID namespace 有りでは direct child は内部 PID1
supervisor であり、通常の signal/wait API は PID1 経由で logical user PID2 を扱う。
PID1 teardown と cgroup kill は、それぞれの namespace/domain 内の残processを終了させる。

descendant が意図的に `setsid()` して別 session/process groupへ detachしても、同じ
Linux process domain に留まる限り cgroup membership による回収対象である。process
group は terminal signal/job-control と publication前の防御 cleanup に限定する。
Landlock等のconfinement継承とprocess lifecycle containmentは別軸である。

## 3. macOS

### 3.1 Confinement

macOS は parent process が Seatbelt profile を文字列として完全に生成し、固定 OS コンポーネント `/usr/bin/sandbox-exec` を exec して適用する。project-owned な外部 helper binary、sibling launcher、self-exec path は許可しない。

profileはdeny-defaultで、validated policyから:

- curated read-only system/runtime paths
- current workspace/private temp write access
- required process/session/device operations
- configured network mode

を構築する。

`network = "disabled"` では network allow rule を出力しないため、macOS の Seatbelt path は network operation を許可しない。`outbound` は client-only TCP rule を出力する。macOS の resource limit は `memory_max`/`pids_max` を `RLIMIT_AS`/`RLIMIT_NPROC` に変換し、CPU quota/swap limit は startup で fail closed する。

macOS に Linux user namespace identity の primitive はなく、engine mapping は identity を常に host 相当に解決する。`identity = "isolated"` は macOS では support されず、subordinate delegation の照会の時点で通常 sandbox の作成が fail closed する（engine も非 `Host` identity とあらゆる namespace/seccomp/capability 要求を明示的に拒否する）。

post-fork childで動的policy builderを呼ばない。

### 3.2 PTY

PTY allocation/session/controlling-terminal/termios/window sizeはSeatbelt toolではなくshboxが直接行う。spawn後parentはslave/setup descriptorsを保持せずmasterだけをruntime lifecycleとして保持する。

### 3.3 Seatbelt support policy

`/usr/bin/sandbox-exec` はAppleのstable public APIとして将来保証されているinterfaceではないため、supportはmacOS major/arm64 tupleごとにnative gateで固定する。

blocking platform scriptは:

- actual `sw_vers`
- native `arm64`
- executable existence
- tiny allow profile
- explicit deny profile enforcement
- full OpenSSH/PTTY suite

を確認する。

想定versionと異なるrunnerを「newerなのでたぶん動く」と成功扱いにしない。

## 4. Support matrix

Milestone 8 CI evidence（run `33518661744`）:

| tuple | build | native confinement/PTTY | observed environment |
|---|---|---|---|
| Linux x86_64 | pass | pass | kernel `6.17.0-1022-azure`, Landlock ABI V6 |
| Linux aarch64 | pass | pass | kernel `6.17.0-1022-azure`, Landlock ABI V6 |
| macOS 15 arm64 | pass | pass | macOS `15.7.7`, Seatbelt smoke pass |
| macOS 26 arm64 | build/native pass | pass | macOS `26.5.2`, Seatbelt smoke pass |

Linux CIでは両architectureともLandlock network capability=trueだった（nono時代の記録。engine移行後のmatrixは各targetでverify scriptを再実行して更新する）。

### 4.1 Production-provider acceptance

generic hosted Linux gateはLinux implementationのnative proofだが、特定provider kernel/imageのproduction acceptanceとは別である。Fly.ioを正式targetとする場合は、そのproduction Machine/image configuration上で [release.md](release.md) のprovider acceptanceを別途通す。2026-09-02の実測でFly Machinesのゲストカーネル（`6.12.105-fly`）はLandlockを提供しないことが確認されたため、Fly Machinesは現時点で正式targetになれない（[release.md](release.md) §9）。

## 5. Deployment prerequisites

### Linux

- supported native Linux architecture
- Rust build artifact generated from locked dependencies
- unprivileged dedicated service account
- kernelがLandlock ABI 4+（6.7+）を提供すること（filesystem/network policy 用）
- 書き込み可能な cgroup v2 階層（delegation）。limit の有無にかかわらず、すべての Linux sandbox launch が専用 process domain cgroup を必要とするため必須
- `identity = "isolated"` 使用時: daemon account への subordinate UID/GID delegation（shadow-utils `getsubids` で照会）と、root で動く socket-activated `shbox-idmap-broker`（`deploy/systemd/shbox-idmap-broker.socket` / `.service` が `/run/shbox-idmap-broker.sock` で `shbox --internal-idmap-broker` を起動する）
- Ubuntu 24.04 で `kernel.apparmor_restrict_unprivileged_userns=1` の場合は `deploy/apparmor/usr.local.bin.shbox` のロード（§2.3）
- safe XDG config/data/state directories
- OpenSSH-facing listener bind capability

port 22 bindだけのために必要ならservice managerで`CAP_NET_BIND_SERVICE`をdaemonに与えられる。sandbox childに追加capabilityを与える理由にはしない。

### macOS

- native arm64
- explicitly tested macOS major
- `/usr/bin/sandbox-exec` enforcement smoke pass
- dedicated daemon account / safe XDG paths

## 6. PTY platform contract

全正式platformで次をreal OpenSSH pathから証明する。

- fd 0/1/2 are TTYs
- sandbox gets a new session
- `tcgetsid(0)` matches target session
- foreground process group matches `tcgetpgrp(0)`
- interactive shell exchange
- Ctrl-C foreground interrupt
- Ctrl-Z stop + `jobs` + `bg` + `fg`
- raw-mode change/restore
- initial size and later resize/SIGWINCH
- disconnect transport detach / detached descendant survival
- no daemon-held PTY slave
- repeated session fd baseline recovery
- concurrent PTY signal/resize/terminal isolation

PTY semanticsはbackend implementation detailではなくSSH product contractである。

## 7. Host mode

admin `_` host modeはsandbox launcher/confinementを経由しない。daemon accountのhost shell/homeを使う。host processには独自のsession/process-group/parent-death cleanupを持つが、sandbox filesystem/network policyは適用されない。

## 8. Fail-closed behavior

production launcher preflightまたはlaunchに失敗したとき:

- unconfined sandbox commandへfallbackしない
-別OS backendを代替実行しない
- unsupported/degraded policyを成功として報告しない
- clientにはgeneric failureを返し、operator logへ診断を残す

## 9. Verification commands

Linux:

```sh
scripts/verify-linux-platform --arch x86_64
scripts/verify-linux-platform --arch aarch64
```

macOS:

```sh
scripts/verify-macos-platform --os 15
scripts/verify-macos-platform --os 26
```

scriptsはRust 1.95、locked dependency、real native backend、real OpenSSH/PTTY suiteをblockingにする。
