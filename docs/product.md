# shbox 製品仕様

## 1. 目的

shbox は標準 SSH client を front end として、同一 Unix host 上に durable workspace と OS-confined command execution を提供する Rust daemon である。

利用者は SSH username として sandbox ID を指定し、通常の shell/remote exec/PTTY を使う。専用 client、HTTP API、container runtime、public backend selector は必要ない。

## 2. 想定利用者と信頼境界

sandbox 内で実行される code は不正または buggy であり得る。shbox は filesystem/network access を OS mechanism で狭めるが、host kernel/root/admin credential の compromise まで防ぐ完全な hostile multi-tenant hypervisor ではない。

主要 trust boundary:

- daemon service account と host OS/kernel
- Ed25519 authentication keys
- admin key と reserved host selector `_`
- persistent XDG data/state roots
- Linux nono/Landlock または macOS Seatbelt confinement

詳細は [security.md](security.md) を参照する。

## 3. 用語とモデル

### 3.1 Principal

認証済み Ed25519 public key fingerprint と role。username は identity ではなく selector である。

### 3.2 Sandbox

sandbox は次の durable state を持つ。

- validated sandbox ID
- owner fingerprint
- lifecycle metadata
- workspace

process、PTY、environment、launch temp は durable sandbox stateではない。

### 3.3 Launch

一回の shell または exec request は一つの disposable launch を作る。同じ sandbox の複数 launch は workspace を共有できるが、process/session/PTY/TMPDIR はそれぞれ独立する。

### 3.4 SSH connection と channel

一つの SSH connection は複数 channel を持てる。各 terminal operation は channel ごとに一回だけ開始できる。

## 4. Local daemon CLI

shbox の通常実行には subcommand がない。

```sh
shbox [--listen ADDR]... [--log-level LEVEL]
```

主な option:

- `--listen ADDR`: config の `listen` を完全に override。repeatable。
- `--log-level error|warn|info|debug|trace`: config の `log_level` を override。
- `--completions bash|elvish|fish|powershell|zsh`: completion script を stdout に出して終了。
- `--man`: roff man page を stdout に出して終了。
- standard help/version option。

`--completions` と `--man` は同時指定できない。sandbox policy に CLI mirror はない。

## 5. SSH から見た利用方法

### 5.1 Sandbox shell

```sh
ssh sandbox-id@example
```

username が valid `SandboxId` の場合、認証 principal の ownership policy を通して sandbox shellを開始する。初回 claim が許可される principal は durable owner を確定する。

PTY を requestした通常 interactive SSH は shbox-owned PTYを使う。

### 5.2 Remote command

```sh
ssh sandbox-id@example 'command ...'
```

remote command bytes は configured shell の `-c` 引数として渡す。command は 32 KiB 上限、NUL/非UTF-8を拒否する。

non-PTY では stdout と stderr を別 streamとして返し、exit codeまたはexit signalをSSHへ伝える。

### 5.3 List subsystem

SSH subsystem `list` は current principal が見える Active sandbox IDs を sorted text で返す。

例:

```sh
ssh -s user@example list
```

list は filesystem scanの結果を ownership推測として公開せず、valid metadataだけを正本とする。

### 5.4 Delete subsystem

SSH subsystem `delete` は selectorとして指定された sandbox を owner/admin policyに従って削除する。

概念例:

```sh
ssh -s sandbox-id@example delete
```

delete は active runtimeを停止し、durable workspace/metadataをidempotentに削除する。`_` は delete targetにならない。

## 6. Admin と host mode

admin keyだけが username `_` を利用できる。

```sh
ssh _@example 'host command'
```

host modeはdaemon accountのlogin shell/homeを使い、sandbox confinementを経由しない。したがってadmin keyはsandbox owner keyより強いcredentialとして扱う。

admin keyがstartup時に一つも無い場合、daemonはsandbox-only modeとなりhost selectorにrecovery routeを提供しない。

## 7. Ownership と persistence

workspace と metadata は明示deleteまで残る。session切断やprocess終了ではworkspaceを削除しない。

一方、次はlaunch終了時に残さない。

- process/session/process group
- PTY
- pipe endpoints
- private per-launch `TMPDIR`
- runtime lease

shbox は同じworkspaceを使う複数process間のapplication-level file lock/single-writer semanticsを提供しない。

## 8. Terminal と process の観測可能な契約

PTYはfirst-class SSH featureである。shbox自身が次を実装する。

- PTY allocation
- fd 0/1/2 のterminal接続
- new session / controlling terminal
- foreground process group とjob control
- POSIX terminal modes
- initial rows/columns
- `window-change` によるresize
- terminal-generated Ctrl-C/Ctrl-Z semantics
- SSH signal forwarding

real OpenSSH acceptanceでは`isatty(0/1/2)`、`getsid`/`tcgetsid`、`getpgrp`/`tcgetpgrp`、interactive prompt、Ctrl-C、Ctrl-Z、`jobs`/`bg`/`fg`、raw-mode restore、concurrent PTY isolationをblocking testとする。

PTY modeではstdout/stderrはterminal streamにmergeする。non-PTYでは分離する。

client EOFはnon-PTY stdinを閉じる。PTY EOFのためにshboxが勝手に`0x04`をinjectすることはない。channel close/disconnectはmanaged process cleanupを開始する。

## 9. Process cleanup

normal exitではdirect childをreapし、owned process groupの残留processをcleanupする。

channel close、client disconnect、sandbox delete、daemon shutdownではgraceful termination後にforce-killへescalateする。

Linux direct sandbox childにはparent-death behaviorが設定される。ただしprocess-group cleanupはcgroup tree containmentではない。descendantがdeliberateに`setsid()`してdetachした場合、元process groupのlifecycle ownershipから外れ得る。filesystem/network confinementの継承とprocess-tree cleanupの強度を同一視しない。

## 10. Network と filesystem

### 10.1 Filesystem

sandbox launchは次のwrite surfaceだけを意図する。

- own workspace
- own private launch temp
- `/dev/null`

curated runtime/system pathsとoperatorの`read_paths`はread-onlyである。他sandbox workspace、shbox config/state/metadata、host-shared temporary treeを自動で公開しない。

### 10.2 Network

`[sandbox] network`:

- `disabled`: outbound TCPを含むnetwork accessをblocking policyで拒否する。
- `outbound`: outbound client connectionを利用可能にする。destination allowlistやproxy policyではない。Linuxの現在のmappingはこれより広いsocket accessを許し得る一方、macOSはbind/inbound ruleを付与しないため、inbound listenerの可否をcross-platform contractとして依存してはならない。

Linuxではnono/Landlockを使用し、必要な古いkernel capability差にはnonoが選択するseccomp fallbackだけを利用する。macOSではgenerated Seatbelt profileでpolicyを表す。

## 11. Environment

sandbox launchは最低限次をshboxが管理する。

- `HOME=<workspace>`
- `PWD=<workspace>`
- `SHELL=<validated shell>`
- `TMPDIR=<private launch temp>`
- PTY時の`TERM=<pty-req value>`

operatorは`[sandbox.env]`から追加environmentを与えられるが、loader/interpreter/proxy/launcher injectionに使えるreserved names/prefixesは拒否する。SSH `env` requestはsandbox環境へ反映しない。

## 12. 非目標

v0.1は次を提供しない。

- container/VM lifecycle
- persistent rootfs image
- sandbox attach API
- UID/GID switching per sandbox
- CPU/memory/PID/file-size/open-file quota
- workspace quota
- port forwarding
- SFTP
- public backend/plugin selection
- backend-specific raw policy knobs
- process-group cleanupをcgroup tree containmentとして扱う保証

host/service manager側のresource policyを別途使うことは可能だが、それはshbox sandbox featureではない。

## 13. Compatibility と support

Rust MSRVは1.95。正式platform supportは実native gateのpassing evidenceがあるtupleだけに付与する。

現在のCI evidenceとFly acceptance状況は [release.md](release.md)、platform semanticsは [platforms.md](platforms.md) を参照する。
