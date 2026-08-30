# Platform と Arapuca の境界

この文書は、shbox が依存する OS 機能、Arapuca の利用範囲、配備条件を定める。ここでいう「対応」は、単にコンパイルできることではなく、後述する実 Arapuca・実 OpenSSH の統合試験を通過した OS/architecture の組合せを指す。

## 1. 責務の境界

shbox の Sandbox は、次の二つを合わせた論理リソースである。

```text
$XDG_DATA_HOME/shbox/sandboxes/<sandbox-id>/
├── metadata.toml       # shbox が所有する versioned metadata
└── workspace/          # 永続データ
```

metadata と workspace の所有権、作成・一覧・削除、状態遷移、認可、per-ID lock は shbox の `SandboxManager` が持つ。owner fingerprint は metadata に保存し、通常鍵には自分の Sandbox だけ、admin 鍵には全 Sandbox を見せる。

Arapuca v0.2.7 の通常 `Isolation::Process` は永続 Sandbox オブジェクトではない。公開されている primitive は、一回の `Sandbox::launch` と一個の `Process` handle であり、persistent resource の create/list/delete、別 process の attach、高水準の PTY resize operation は提供しない。したがって、同一 Sandbox の複数 shell/exec は、同じ shbox workspace を各々の disposable Arapuca process に共有させる構成になる。process、PTY、環境、外部インストールは接続終了時に残さない。

microVM の state API を通常 Process backend の代替として扱わない。永続 VM を利用する設計、VM image、guest attach、VM lifecycle は v0.1 の対象外である。

### 1.1 内部 adapter

実装は、SSH 層から Arapuca の型と詳細を直接見せない。

```text
SSH/russh
    ↓ shbox の domain interface
SandboxManager ── private ProcessLauncher seam
                         ↓
                  Arapuca adapter
```

`ProcessLauncher` は private なテスト seam とし、本番実装だけが Arapuca を呼ぶ。テストでは fault injection と barrier を持つ fake launcher を使う。公開設定や公開 plugin として backend を差し替える機構は作らない。

Arapuca backend は起動時に一度だけ初期化し、同じ daemon 内で共有する。初期化に失敗した場合、Arapuca を必要とする sandbox shell/exec/PTY は利用不可のままにし、SIGHUP で再構築しない。metadata の reconciliation 完了後は認可済み list/delete を利用できる。process 起動の復旧には daemon の再起動を要する。SIGHUP は shbox の設定・認証・新規 process への適用だけを更新する。

各 process に渡す内部 `task_id` は、外部 Sandbox ID と同一視しない。形式は次のとおりとする。

```text
<sandbox-id>-<128-bit random hex>
```

全体を ASCII の英数字と `-`、128 bytes 以下に収め、launch ごとに active lease と衝突を確認して再試行する。外部 ID は監査上の correlation として別に保持する。これは Arapuca が `task_id` を英数字/`-`、128 bytes 以下に制限し、Linux cgroup 名を task ID だけから作るためである。

## 2. Arapuca の固定と公開しない設定

初期実装は crates.io 版ではなく、次の git revision を直接 pin する。

```toml
arapuca = { git = "https://github.com/LeGambiArt/arapuca", rev = "c94802c4d8b6b880334c0d643b16b7326ec7f039" }
```

この revision の package version は `0.2.7` のままだが、`v0.2.7` tag の正式リリースではない。PR #82 由来の macOS PTY `file-ioctl` と `/var` ancestor 修正を含む未リリースの累積 tip である。仕様、Cargo.lock、リリースノートには package version と full revision の両方を記録する。正式版へ移行する場合も、差分確認と全統合試験を先に行う。

shbox の設定は `network = "disabled" | "outbound"`、共通 resource limit、追加 read-only path、workspace 環境変数などの shbox 用語だけを公開する。`Isolation`、`seccomp_profile`、`cgroup_policy`、`allow_exec`、`use_netns`、`task_id` などの Arapuca option を TOML の直接の露出名にはしない。内部 adapter が固定した安全な mapping を使う。

### 2.1 Profile の mapping

- shell/exec は shell を起動するため、内部 profile は実行を許可する。ただし追加 write path は作らず、実行可能な read-only system path と workspace だけを明示する。
- `read_paths` は管理者が設定した絶対 path と、shell/loader/TLS に必要な curated system path に限定する。
- workspace は `read/write`、他の Sandbox directory、shbox の metadata、cgroup filesystem は渡さない。
- client の SSH environment request は受け付けず、Sandbox 側の環境は shbox が構成する。`HOME` と `PWD` は workspace、`SHELL` は選択 shell、`TMPDIR` は launch ごとの private temporary directory にする。Arapuca の現行実装に依存するため、最終値は各正式 platform の統合試験で確認する。
- daemon の UID/GID の切り替えは行わない。host mode も同じ daemon service account で動き、別 identity は sudo、service manager、OS 側の配備責務とする。
- 同一 workspace への同時 read/write は許可する。shbox はファイル lock や単一 writer を提供せず、更新の整合性は利用するプログラムと通常の filesystem semantics に委ねる。

resource の既定値は、`max_open_files = 1024`、Linux の `max_pids = 256`、その他の memory/CPU/time/file-size limit は `0`（無制限）とする。workspace 全体の disk quota は設けず、必要なら per-file size limit と operator の filesystem 監視で扱う。

Linux の固定 curated read set は、存在する次の path に限る。

```text
/usr
/lib
/lib64
/bin
/sbin
/etc/ssl
/etc/pki
/etc/ca-certificates
/etc/resolv.conf
/etc/hosts
/etc/host.conf
/etc/nsswitch.conf
/etc/ld.so.cache
/etc/localtime
/etc/passwd
/etc/group
/dev/null
/dev/zero
/dev/urandom
/dev/random
```

`/proc`、`/sys`、blanket `/dev`、`/dev/pts`、`/dev/tty`、host 共用 `/tmp` は内部 set に
含めない。distribution に存在しない optional entry は追加しないが、selected shell と loader
に必要な path を適用できない場合は launch を失敗させる。macOS の system path は pinned
Seatbelt profile の固定 allowlist を用い、利用者の `read_paths` だけを追加する。どちらも
workspace 以外の追加 write path は作らない。

## 3. Network policy

ネットワーク設定は全 Sandbox 共通で、次の二つだけとする。

| shbox 設定 | 内部の意味 | 契約 |
|---|---|---|
| `disabled` | strict network-deny profile | outbound/inbound ともに許可しない |
| `outbound` | baseline profile | unrestricted TCP/UDP/DNS network capability。主用途は outbound、host filtering なし |

inbound listener、port forwarding、per-Sandbox allowlist、proxy endpoint の設定は v0.1 で提供しない。`outbound` は初期版から実装し、ユーザーが利用する唯一の許可ネットワーク形態とする。ここでも Arapuca の raw network option や syscall profile 名は公開しない。

`outbound` の内部 profile は `disabled` より syscall/network isolation が弱い。選択時は
startup/reload の host log に warning を残す。shbox は inbound port mapping を作らないが、
Baseline と host network namespace の組合せは全 OS で bind/listen を禁止する egress-only
security boundary ではない。外部からの到達は host firewall で制御し、正式 platform ごとに
実際の socket behavior を記録する。

## 4. OS/architecture matrix

正式対応は、表の組合せごとに acceptance suite を通過した場合だけ有効になる。OS の「以上」を一括保証せず、試験した OS image/version を support matrix に列挙する。

| OS / architecture | v0.1 の扱い | isolation / 制約 |
|---|---|---|
| Linux `x86_64` | 正式対応候補。実機試験必須 | Landlock/seccomp、cgroups v2、process group。cgroup scope が専用 delegated でない場合は sandbox backend を fail closed |
| Linux `aarch64` | 正式対応候補。実機試験必須 | x86_64 と同じ契約。ただし wrapper と kernel capability は個別検証 |
| macOS `arm64` | 正式対応候補。macOS 15/26 を初期試験対象 | Apple Seatbelt (`sandbox-exec`) と rlimit。cgroup はなく、memory/CPU の意味は Linux と異なる |
| macOS `x86_64` | 未検証・非対応 | upstream release は cross-build のみで native runtime/PTY 試験を保証しない |
| Windows | 非対応 | xdg は Unix/Redox 限定で、Arapuca の Process に Unix PTY/signal API がない |
| その他 | 非対応 | Arapuca の degraded/unsupported backend を正式契約にしない |

macOS の正式対応は、対象 OS version と arm64 の組合せを固定して実測する。Arapuca v0.2.7 の説明にある「macOS 15 まで functional」を、将来 OS への保証とは解釈しない。`macos-latest` のような mutable runner label だけを根拠に support claim を作らず、試験時に `sw_vers` と `uname -m` を記録する。

### 4.1 Port 22 cutover

shbox の host key は OpenSSH daemon の host key を流用せず、XDG state に独立して生成する。
既存 sshd から同じ host/port 22 を切り替えると、client からは host key 変更として見える。
operator は切替前に新 fingerprint を安全な別経路で確認し、known_hosts を意図的に更新する。

SSH だけが復旧経路の VPS では、authorized key、admin fingerprint、service account の XDG
directory と config を先に準備し、`ssh _@host` が利用できることを別 port または既存 session
から確認してから port 22 を切り替える。admin 無しの sandbox-only mode を唯一の復旧経路に
しない。shbox は既存 sshd の停止、known_hosts 更新、firewall 変更を自動実行しない。

### 4.2 Linux prerequisites

正式な Linux backend には、少なくとも次を要求する。

1. Linux kernel 5.13 以上と cgroups v2。
2. `cpu`、`cpuset`、`memory`、`pids` controller が shbox service に delegated されていること。
3. Arapuca の必要な wrapper/loader と launch capability が利用可能であること。
4. shbox daemon が、delegated scope の下に private child cgroup を作成し、そこへ自身を移動できること。

Arapuca は `/proc/self/cgroup` から自身の scope を自動検出し、backend manager の生成時に `arapuca-*` の stale group を cleanup する。shbox は backend 初期化前に delegated scope の下へ自身専用の random-named child cgroup を作り、daemon PID だけを移動する。これにより Arapuca の cleanup と controller 操作はその private child 以下に限定される。child の作成・PID 移動・required controller の検証に失敗した場合は sandbox backend を fail closed にする。親 scope は他用途と共有されていてもよいが、同じ service account が private child へ無関係な process を追加してはならず、親で `cpu`、`cpuset`、`memory`、`pids` が child に pre-delegate されていなければならない。limits が無い場合も manager 初期化時の cleanup は起こり得る。

systemd の delegated user/service scope の最小例は次のとおりである。実際のユーザー名、binary path、port 権限は配備環境に合わせる。

```ini
# /etc/systemd/system/shbox.service
[Unit]
Description=shbox SSH sandbox daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=shbox
Group=shbox
ExecStart=/usr/local/bin/shbox
Restart=on-failure
Delegate=cpu cpuset memory pids
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`Delegate` は controller の権限委譲を示すだけで、scope の専用性を自動で保証しない。service の子 process を別用途で起動せず、XDG data/state/config directory を `shbox` が所有することを運用で保証する。Arapuca の Linux wrapper が要求する host/kernel 条件も起動前に確認し、満たせなければ sandbox launch を拒否する。

### 4.3 macOS prerequisites

macOS backend は `sandbox-exec` が利用できることを要求する。Arapuca は Seatbelt の deny-default profile と rlimit/watchdog を使用するが、cgroups v2、Linux の CPU quota、PID limit、per-host network filtering は提供しない。memory は RSS polling の best effort、CPU percentage は Linux quota と同じ意味ではない。対応表に「適用されない」制限を適用済みとして表示しない。

固定先 `c948...` は、v0.2.7 tag に無かった次の修正を含む。

- PTY slave `/dev/ttys*` の terminal ioctl を許可する。
- `/var` symlink の ancestor traversal を許可する。

それでも upstream の CI は広い PTY compatibility を保証しないため、raw mode、`stty`、window resize、子孫 process cleanup は shbox の macOS integration suite で必須検証する。失敗した OS/version 組合せは正式対応から外す。

macOS の launchd 配備例は次のように、persistent path を持つ専用 service account で実行する。launchd はインストーラではなく、運用者が適切な owner/mode と XDG directory を事前に準備する。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.shbox</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/shbox</string>
  </array>
  <key>UserName</key>
  <string>shbox</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
```

shbox は stderr にだけ log を出し、launchd または operator が外部で収集する。上の例は
shbox 自身の file logging/rotation を追加しない。

port 22 を非 root account で bind できるかは macOS の配備方法に依存する。必要なら shbox を明示的な unprivileged port へ bind し、OS の packet-filter/NAT で port 22 から転送する。shbox は inherited socket activation や UID switch を暗黙に仮定しない。

## 5. PTY と process lifecycle adapter

SSH の `pty-req` から TERM、rows、columns、pixel dimensions、terminal modes を受け取る。shbox は rows/columns と、実装する POSIX terminal modes だけを Arapuca process に反映し、pixel dimensions と未知 mode は仕様どおり副作用なく無視する。後続の `window-change` は rows/columns を更新する。

Arapuca に高水準の resize operation はない。Unix では `Process::pty_master()` から得た master FD に adapter が OS の `TIOCSWINSZ` 相当 ioctl と terminal mode 操作を行う。FD の lifetime は Process に束縛されるため、Process と所有済み FD を bridge task の lifetime 中保持し、borrowed FD を跨いで不正に保存しない。PTY では stdout/stderr は terminal stream に統合され、非 PTY では SSH stdout と extended stderr を分ける。

固定 revision は `openpty` 時に SSH request の size/modes を受け取る API を持たず、
target の `spawn()` 後にだけ master FD を返す。v0.1 は trusted child launcher も
Arapuca fork も使わない。そのため adapter は launch 直後、SSH I/O bridge を公開する
前に request 値を適用するが、target の最初の命令との race は解消できない。初期値には
daemon FD 0 の size、取得不能時は Arapuca の `24x80` fallback が短時間見え得る。
target 実行前の厳密な size/mode 保証は既知の制限として release note に残し、将来
Arapuca の pre-exec API または十分に監査した launcher を採用する場合だけ契約を強める。
launch 後の size/mode 適用に失敗した process は client へ公開せず、直ちに cleanup して
shell/exec request を失敗させる。

process は channel 単位で一つだけ起動する。各 channel の shell/exec/subsystem は一回だけ受理し、同一 SSH connection 上の複数 channel は許可する。disconnect、channel close、delete、daemon shutdown では process group を対象に終了させる。まず graceful termination を試み、5 秒後に強制停止する。正常終了後も子孫が残らないことを Linux の cgroup/process group、macOS の shbox adapter の process group cleanup で保証し、保証できない platform は正式対応にしない。

client EOF 後は既受信入力を drain し、新しい channel data を process へ渡さない。非 PTY
では stdin pipe を閉じる。PTY では write 用 master duplicate だけを閉じ、read/lifecycle
用 duplicate を保持し、`VEOF` を合成しないため、child stdin の EOF は保証しない。
いずれも process の出力と終了 status を転送し、完了時は SSH の EOF、exit-status、
channel close を正しい順で送る。client への送信失敗や unbounded output は process cleanup
と backpressure の対象になる。

## 6. Host mode

admin key が username `_` を selector として使う場合、sandbox profile を通さない host shell/exec/PTY/resize/signal を利用できる。SFTP subsystem、agent/X11/port/streamlocal forwarding は提供せず、SCP 互換性は保証しない。host process は daemon と同じ UID/GID、login shell、account home cwd で起動するが、環境は `HOME` を含め daemon service environment をそのまま継承する。remote exec はその shell の `-c` semantics に従う。

host mode は daemon service の環境変数を全て継承する。service environment に秘密情報を置くと admin shell/exec から読めるため、配備時に秘密を混在させない。通常の Sandbox は client environment を継承しない。

## 7. 既知の制限と運用上の前提

- Arapuca Process backend だけでは persistent rootfs、named sandbox、attach、workspace quota、UID/GID switch はできない。
- workspace は共有 filesystem であり、同時更新の lock/transaction は提供しない。
- XDG の `xdg` crate は Windows target に使えない。Windows fallback を隠れて追加せず、formal support を明記した Linux/macOS の試験済み target に限定する。
- Linux の cgroup scope は Arapuca の自動 discovery と startup cleanup に依存する。同じ scope に別 orchestrator を置かない。
- macOS の Seatbelt、rlimit、RSS monitor は Linux と等価ではない。適用されない limit を成功扱いにしない。
- Arapuca の raw audit、network proxy、seccomp、cgroup path などは shbox の外部設定にしない。
- 不完全な backend、missing prerequisite、権限不足では direct host execution に degrade せず、Arapuca が必要な Sandbox shell/exec/PTY を fail closed にする。

## 8. 一次情報

- [Arapuca v0.2.7 README](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/README.md)
- [Arapuca Process platform trait](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/platform/mod.rs)
- [Arapuca Linux platform](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/platform/linux.rs)
- [Arapuca cgroup manager](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/cgroup.rs)
- [Pinned Arapuca environment and curated paths](https://raw.githubusercontent.com/LeGambiArt/arapuca/c94802c4d8b6b880334c0d643b16b7326ec7f039/src/env.rs)
- [Arapuca v0.2.7 tag](https://github.com/LeGambiArt/arapuca/releases/tag/v0.2.7)
- [Arapuca cumulative macOS fixes](https://github.com/LeGambiArt/arapuca/commit/c94802c4d8b6b880334c0d643b16b7326ec7f039)
- [Arapuca v0.2.7 to c948 cumulative diff](https://github.com/LeGambiArt/arapuca/compare/v0.2.7...c94802c4d8b6b880334c0d643b16b7326ec7f039.diff)
- [OpenSSH ssh(1) manual](https://man.openbsd.org/ssh)
- [RFC 4254: SSH connection protocol](https://www.rfc-editor.org/rfc/rfc4254)
- [xdg `BaseDirectories`](https://docs.rs/xdg/3.0.0/xdg/struct.BaseDirectories.html)
- [Cargo git dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
