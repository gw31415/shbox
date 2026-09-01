# Platform boundary

shbox の正式 support は「target で build できる」ことではなく、native OS/architecture 上で real confinement と real OpenSSH/PTTY blocking suite が passing であることを意味する。

## 1. 共通 architecture

```text
SSH/session layer
    -> ProcessLauncher
        -> shbox-owned PTY/process lifecycle
        -> OS confinement
            Linux: nono 0.74.0 / Landlock
                   (+ nono-selected seccomp fallback when required)
            macOS: generated Seatbelt profile
                   via /usr/bin/sandbox-exec
```

`ProcessLauncher` は private test seam であり public backend selector ではない。policy は backend-neutral で、shell、network mode、read-only paths、environment、private launch temp root を表す。

両 platform とも shbox 自身が次を所有する。

- child spawn/wait/reap
- process session/group
- PTY pair と descriptor lifetime
- controlling terminal
- terminal modes/size
- signal/resize forwarding
- launch temp cleanup

confinement library/tool に PTY ownership を委譲しない。

## 2. Linux

### 2.1 Confinement

Linux は pinned `nono = 0.74.0` を Rust library として使う。外部 executable/CLI は必要ない。

parent process は child を作る前に:

- Landlock ABI を detect
- readable/writable path capability を prepare
- network mode を prepare
- signal/IPC scope request を prepare
- kernel capabilityに応じた seccomp network fallbackをprepare

する。

prepared policy だけを post-fork child へ持ち込み、child は raw/fixed setup後に `apply_raw` を行う。path lookupやpolicy allocationをmultithreaded post-fork childで行わない。

### 2.2 Filesystem policy

per launch write access:

- current sandbox workspace
- unique private launch temp
- `/dev/null`

curated read-only baseline は ordinary command runtime に必要な system binaries/libraries、select TLS/resolver/account data、entropy devices、`/dev/tty` に限定する。

特に host-shared temporary tree、procfs、sysfs、全 PTY namespace を broad grant しない。operator `read_paths` は追加 read-only grant である。

Landlock restriction は descendant に継承される。

### 2.3 Network

`disabled` は nono network blocked policy。Landlock network mediation が不足するkernelでは、nonoが選択するseccomp fallbackを利用する。fallback preparation/applicationに失敗すればlaunchを拒否する。

`outbound` のpublic contractは任意remote endpointへのclient connectionを利用可能にすることまでとする。Linuxのnono mappingは現在 `AllowAll` であり、任意remote portへのconnectだけをwildcard許可してbindだけを禁止するportless Landlock ruleとして偽装しない。このためLinuxではcontractより広いsocket operationが可能になり得る。macOSは別途bind/inbound ruleを付与しない。inbound listenerの可否をportable contractとして依存してはならない。

### 2.4 Signal/IPC scope

nono policy は signal isolation と shared-memory-oriented IPC modeをrequestする。kernel ABIがscopingを提供する場合はそれを利用する。release diagnosticsは実ABIとnetwork/scoping capabilityを記録する。

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

### 2.6 cgroup delegation は prerequisite ではない

shbox sandbox runtime は delegated cgroup controllers を要求せず、sandbox launch のために cgroup filesystem を変更しない。

systemd の `KillMode=control-group` を deployment artifact で使う場合、それはservice managerがdaemon service全体をcleanupする方針であり、shbox sandbox implementationのcontroller delegationとは別の概念である。

### 2.7 Resource limits

shboxはper-sandbox CPU/memory/PID/file quotaを提供しない。provider/service managerのresource controlsとsandbox confinementを混同しない。

### 2.8 Lifecycle containment limitation

shboxはinitial sandbox session/process groupをownership unitとしてsignal/cleanupする。direct childにはparent-death behaviorも設定する。

ただしdescendantが意図的に`setsid()`して別session/process groupへdetachすると、元process groupに対するlifecycle cleanupから外れ得る。これはcgroup tree containmentと同じ保証ではない。

Landlock等のconfinement継承とprocess lifecycle containmentは別軸である。

## 3. macOS

### 3.1 Confinement

macOS は parent process が Seatbelt profile を文字列として完全に生成し、固定system path `/usr/bin/sandbox-exec` をexecして適用する。

profileはdeny-defaultで、validated policyから:

- curated read-only system/runtime paths
- current workspace/private temp write access
- required process/session/device operations
- configured network mode

を構築する。

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

Linux CIでは両architectureともnetwork/scoping capability=true、seccomp network fallback=Noneだった。

### 4.1 Production-provider acceptance

generic hosted Linux gateはLinux implementationのnative proofだが、特定provider kernel/imageのproduction acceptanceとは別である。Fly.ioを正式targetとする場合は、そのproduction Machine/image configuration上で [release.md](release.md) のprovider acceptanceを別途通す。2026-09-02の実測でFly Machinesのゲストカーネル（`6.12.105-fly`）はLandlockを提供しないことが確認されたため、Fly Machinesは現時点で正式targetになれない（[release.md](release.md) §9）。

## 5. Deployment prerequisites

### Linux

- supported native Linux architecture
- Rust build artifact generated from locked dependencies
- unprivileged dedicated service account
- kernelがrequired nono policyをprepare/applyできること
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
- disconnect cleanup
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
