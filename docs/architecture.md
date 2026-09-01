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
                  Linux: nono 0.74.0 / Landlock
                         + nono-selected seccomp fallback
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
$XDG_STATE_HOME/shbox/runtime/           per-launch private temp root
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
- per-launch private temp root

CPU、memory、PID、file quota の sandbox resource limits は policy に存在しない。

### 4.3 Linux launcher

Linux launcher は parent 側で filesystem/network capability set と nono policy を prepare する。child を作る前に path lookup、allocation、Landlock ABI detection を終える。

post-fork child が行うのは、事前準備済み data を使った raw/fixed operation に限定する。

1. parent-death signal を設定し parent PID を再確認
2. PTY なら fd 0/1/2 を slave に揃える
3. `setsid()`
4. PTY なら controlling terminal を取得
5. workspace へ `chdir`
6. prepared nono sandbox を raw apply
7. target shell を `exec`

child setup failure は CLOEXEC status pipe で stage/errno を parent に返し、client には generic launch failure を返す。

nono 0.74.0 は library としてのみ利用する。外部 nono executable は不要である。

### 4.4 macOS launcher

macOS launcher は parent 側で deny-default Seatbelt profile を生成する。profile は workspace/private temp を writable、curated system/runtime paths を readable とし、network mode を shbox policy から決定する。

PTY/session setup は shbox child setup が行い、その後 `/usr/bin/sandbox-exec -p <profile> <shell> ...` を exec する。別 helper や self-exec path はない。

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

- direct child + process group/session
- PTY master/slave（PTY request 時）
- stdin/stdout/stderr pipes（non-PTY 時）
- private `TMPDIR`
- runtime lease

workspace は `HOME` と initial `PWD` になる。shell は `SHELL`。PTY request があると `TERM` は request 値が authoritative で、`TMPDIR` は shbox の private launch directory が authoritative である。

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

normal completion では direct child を必ず一度 reap し、残る owned process group を force-cleanup して private temp を削除する。

channel close/client disconnect/delete/daemon shutdown では managed process groupへ graceful termination を送り、grace period 後に kill へ escalate する。SSH connection handler が drop すると channel registry の mailbox sender を全て閉じ、bridge task が disconnect を観測できるようにする。

Linux direct sandbox child は parent-death signal を設定するため daemon の abrupt deathでも direct child cleanupを補助する。

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
