# Architecture and lifecycle

shbox は durable sandbox metadata/workspace と disposable process lifecycle を分離する SSH daemon である。SSH handler は filesystem policy や OS sandbox API を直接操作せず、`SandboxManager` と `ProcessLauncher` を境界として利用する。

## 1. System boundary

```text
OpenSSH client
    |
    v
russh SSH/session layer
    |
    +--> auth / role / selector routing
    |
    +--> SandboxManager ------------------------------+
    |      durable metadata + workspace ownership     |
    |                                                 |
    +--> ProcessLauncher <-----------------------------+
           |
           +--> shbox-owned process lifecycle
           |      fork/exec, wait/reap, process group,
           |      signal forwarding, shutdown cleanup
           |
           +--> shbox-owned PTY lifecycle
           |      allocation, fd 0/1/2, setsid,
           |      controlling TTY, termios, resize
           |
           +--> OS confinement
                  Linux: shbox-sandbox engine
                         (clone3+pidfd / Landlock / seccomp / cgroup v2)
                  macOS: generated Seatbelt profile
                         applied by /usr/bin/sandbox-exec
```

Host selector `_` は例外であり、admin key のみが daemon account の host process route を使う。host mode は sandbox confinement を経由しないため、admin credential は強い権限境界である。

## 2. Domain model

### 2.1 Principal

認証済み Ed25519 key fingerprint と role（normal/admin）を connection state に固定する。username は routing selector であり identity ではない。

### 2.2 Sandbox ID

`SandboxId` は ASCII・case-sensitive で、grammar は次の通り。

```text
[A-Za-z0-9][A-Za-z0-9-]{0,63}
```

`_` は host selector なので sandbox ID にならない。path separator、dot、underscore、whitespace、Unicode は拒否する。

### 2.3 Persistent sandbox record

各 sandbox は XDG data root 以下に durable metadata と workspace を持つ。metadata は owner fingerprint と lifecycle state を記録し、workspace と同じ sandbox directory に属する。

概念的な state は次である。

```text
Absent -> Active -> Deleting -> Absent
```

create/claim は owner を durable に確定してから process launch を許可する。delete は `Deleting` を durable に記録してから runtime を停止し、workspace/metadata を削除する。crash 後は startup reconciliation が incomplete delete を再開する。

## 3. Persistent layout

`xdg` crate の application prefix `shbox` を使う。

```text
$XDG_CONFIG_HOME/shbox/config.toml       optional, operator input
$XDG_CONFIG_HOME/shbox/allowed_keys      sandbox-only public keys

$XDG_DATA_HOME/shbox/registry.lock
$XDG_DATA_HOME/shbox/sandboxes/<id>/     metadata + workspace

$XDG_STATE_HOME/shbox/host_key
$XDG_STATE_HOME/shbox/lock
$XDG_STATE_HOME/shbox/runtime/           sandbox-runtime private temp root
```

shbox が作成する directory は owner-only を要求し、symlink や group/world writable path を拒否する。config directory は operator input なので自動作成しない。

## 4. Module boundaries

### 4.1 `SandboxManager`

`SandboxManager` は次を所有する。

- owner claim と metadata transition
- global/per-owner sandbox caps
- workspace path validation
- active runtime lease registry
- delete と startup reconciliation
- daemon shutdown 時の sandbox runtime drain

SSH handler は metadata file を直接編集しない。

### 4.2 `ProcessLauncher`

`ProcessLauncher` は private trait であり、public plugin/backend selector ではない。入力は validated workspace、shell/exec operation、PTY specification。出力は owned stdin/stdout/stderr、process control、wait result である。

backend-neutral policy は一度だけ構築し、以下を保持する。

- validated shell
- `disabled` / `outbound` network policy
- curated + configured read-only paths
- operator sandbox environment
- private runtime temp root (Linux generation-scoped; per-launch on macOS)
- configured per-sandbox resource limits with platform-specific enforcement

file-size、open-file、workspace disk quota は policy に存在しない。

### 4.3 Linux launcher

Linux launcher は parent 側で shbox policy を engine の `SandboxConfig` へ解決し、engine が Landlock ruleset 構築・seccomp compile・必要な cgroup 作成をすべて child 生成前に終える。実際の `clone3` は process-lifetime の専用 spawn-owner thread が行い、`PR_SET_PDEATHSIG` が短命な caller thread に結び付かないようにする。PID namespace 無しでは user child が direct clone、PID namespace 有りでは direct clone が内部 PID1 supervisor/reaper となり user command はその PID2 child として動く。

post-fork child が行うのは、事前準備済み data を使った raw/fixed operation に限定する。

1. parent-death signal を設定し namespace-aware に parent liveness を確認
2. user/mount namespace の初期化
3. PID namespace 有りなら内部 PID1 が user PID2 を nested clone（limit 時は `CLONE_INTO_CGROUP`）
4. user process が PTY/pipes を fd 0/1/2 に揃え `setsid()` / controlling terminal / `chdir` を実施
5. `no_new_privs` / capability / Landlock / seccomp / FD hygiene を適用
6. target shell を `exec`

child setup failure は CLOEXEC status pipe で stage/errno を parent に返し、client には generic launch failure を返す。

confinement engine は workspace 内 crate `shbox-sandbox`（landlock 0.4 / seccompiler 0.5）である。Linux では project-owned な外部 sandbox executable、sibling helper、self-exec path を使わない。

### 4.4 macOS launcher

macOS launcher は parent 側で deny-default Seatbelt profile を生成する。profile は workspace/private temp を writable、curated system/runtime paths を readable とし、network mode を shbox policy から決定する。

PTY/session setup は shbox child setup が行い、その後固定 OS コンポーネント `/usr/bin/sandbox-exec -p <profile> <shell> ...` を exec する。project-owned な別 helper や self-exec path はない。`/usr/bin/sandbox-exec` は macOS で許可された OS component であり、project artifact として配布する helper ではない。

### 4.5 Network and resource semantics

現在の shbox Linux adapter は `network = "disabled"` を fresh user+network namespace に写像し、host/external network reachability を切り離す。child は exec 前に capability を drop するため、sandboxed program は初期状態で down の loopback を有効化できない。さらに Landlock の network rights（ABI 4+）で TCP `bind`/`connect` も deny する。`outbound` は host network namespace を共有する。

すべての public shbox Linux launch は、resource limit の有無にかかわらず `SandboxId` ごとに一つの durable な process domain（専用 cgroup v2）を作成し、同じ `SandboxId` の concurrent launch で共有する。child は `clone3(CLONE_INTO_CGROUP)` で最初からその domain 内に生成されるため、limit 適用前の window は存在しない。child が終了しても domain は削除せず、sandbox deletion が runtime cancellation と child cleanup を完了した後に release/remove する。直接 `shbox-sandbox::Sandbox::spawn` を利用する engine path は、resource limit を使う場合に spawn ごとの one-shot per-child cgroup semantics を採用し得る。明示 limit は parent/ancestor cgroup の制限に追加され、child が inherited cgroup restriction を解除または引き上げることはできない。macOS は `memory_max` を `RLIMIT_AS`、`pids_max` を `RLIMIT_NPROC` として exec 前に適用し、CPU quota と swap limit は unsupported として fail closed する。

## 5. Startup and readiness

startup の主要順序は次である。

1. XDG paths resolve/validate
2. config snapshot load/validate
3. data/state lock acquisition
4. host key load/create
5. authorized key snapshot load
6. daemon account/sandbox shell resolve
7. backend-neutral launch policy construct
8. production `ProcessLauncher` preflight
9. listener bind
10. managed mode なら startup reconciliation

config と launch policy は process-lifetime snapshot であり SIGHUP では再読込しない。SIGHUP は key source の再検証だけを強制する。

sandbox backend preflight が利用不能な場合、sandbox shell/exec は fail closed にする。host mode や metadata operationへ unconfined sandbox fallback はしない。

## 6. Atomic claim and ownership

最初に valid key で sandbox ID に接続した principal が owner claim を作る。claim は atomic global reservation と metadata write を経て durable になる。同じ ID への競合 claim は一人だけが成功する。

owner だけが通常の shell/exec と delete を行える。admin は管理 route を持つが、identity/ownership の記録を曖昧にしない。

## 7. Process launch

一つの SSH shell/exec channel は一つの launch に対応する。同一 sandbox で複数 channel/process を並行実行でき、共有するのは durable workspace だけである。

launch ごとの disposable state:

- engine-owned direct child + logical user process group/session（PID namespace 有りでは direct child は内部 PID1、user process は PID2）
- PTY master/slave（PTY request 時）
- stdin/stdout/stderr pipes（non-PTY 時）
- sandbox-runtime-scoped private `TMPDIR` (Linux); per-launch private temp on macOS
- runtime lease

workspace は `HOME` と initial `PWD` になる。shell は `SHELL`。PTY request があると `TERM` は request 値が authoritative で、`TMPDIR` は shbox の private runtime directory が authoritative である。Linux では同じ sandbox runtime-domain generation の launch が同じ `TMPDIR` を共有し、domain が空になった後にだけ削除する。

## 8. PTY lifecycle

PTY は SSH の first-class feature であり shbox が直接実装する。

1. parent が PTY pair を allocate
2. request terminal modes と initial rows/columns を slave に設定
3. child setup 専用 FD を CLOEXEC で予約
4. child が slave を fd 0/1/2 へ duplicate
5. child が新しい session を作り controlling terminal を取得
6. parent は slave/setup FD を閉じ、master だけを lifecycle ownership として保持
7. stdout/stderr は terminal stream として merge
8. `window-change` は master への ioctl で size を更新
9. SSH signal request は foreground process groupへ転送

interactive shell の job control、Ctrl-C、Ctrl-Z、`jobs`/`fg`/`bg` は OS の controlling-terminal/foreground-PGID semantics をそのまま使う。

## 9. Process control and cleanup

normal completion では engine-owned direct child を必ず一度 reap する。PID namespace 無しでは reap 前に残る owned process group を force-cleanup する。PID namespace 有りでは内部 PID1 が user PID2 の status を返し、残descendantを停止/reapしてから終了する。最後に private temp を削除する。

published sandbox launchではchannel close/client disconnectはtransport endpointだけをdetachし、processをterminateしない。publication前の失敗、sandbox delete、daemon shutdownではmanaged processをgraceful terminationからforce-killへ進める。SSH connection handler が drop すると channel registry の mailbox sender を全て閉じ、bridge task がdisconnectを観測できるようにする。

Linux の engine-owned direct sandbox child には parent-death signal を設定し、その clone は process-lifetime spawn-owner thread が担当する。daemon の abrupt death 時に process の生存は保証しないが、restart 時は delegated parent の `shbox-domain-*` と runtime root の `sandbox-*` generation を ownership prefix で reconcile する。prefix 外の sibling cgroup/file は変更しない。

### 9.1 重要な containment limit

process-group cleanup は cgroup tree containment と同一ではない。sandbox descendant が自ら `setsid()` して新しい session/process groupへ deliberate に detach した場合、shbox の元 process group cleanup から外れ得る。

filesystem/network confinement は子孫へ継承されるが、process-tree lifecycle の強制回収を cgroup 相当として主張しない。この差は security/release 文書と Fly acceptance で明示的に試験する。

## 10. Delete and recovery

delete は runtime と persistent state の競合を避ける。

1. Active metadata を Deleting に durable transition
2. new launch を拒否
3. registered runtime leases を terminate/force cleanup
4. workspace tree を安全に削除
5. metadata を削除
6. global reservation を解放

resource limit を使う Linux sandbox では、child exit だけでは `SandboxId` の durable resource domain を削除しない。runtime cancellation と child cleanup の完了後、この delete path が domain を release/remove する。

途中 crash では `Deleting` record が restart 後の再開点になる。target workspace が既に無い場合も idempotent に完了する。

## 11. List semantics

`list` は current principal から見える valid Active metadata の ID を sorted で返す。corrupt/unsafe entry は公開せず、勝手に修復して ownership を推測しない。

## 12. Shutdown

最初の SIGINT/SIGTERM は listener を止め、host/sandbox runtime を drain する。二回目の shutdown signal は force-stop pathへ移る。

host process も sandbox process も direct child ownership と process-group cleanupを持つ。正常 shutdown は waiter/cleanup completion を待つ。

## 13. Concurrency invariants

- global connection/channel/process/sandbox caps は atomic に enforce する。
- one sandbox は複数 runtime leases を持てる。
- delete は new launch と競合しても最終的に全 lease を停止する。
- PTY slave/setup descriptors は spawn 後 parent に残さない。
- concurrent PTYs は controlling terminal、foreground PGID、window size、signals を共有しない。
- one connection の teardown はその connection の channel mailboxes を確実に閉じる。

## 14. Error and panic policy

remote input、authorization denial、unsupported request、sandbox policy/preflight failure、I/O failure は operational error であり daemon panic にしない。client へは sensitive path/backend detail を出さず generic failure と protocol status/signalを返す。

panic/abort は内部 invariant 破壊に限定する。
