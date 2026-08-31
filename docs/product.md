# shbox 製品仕様

この文書は shbox v0.1 の外部仕様の正本である。実装上の構造、OS ごとの制約、設定項目の詳細は [architecture.md](./architecture.md)、[platforms.md](./platforms.md)、[configuration.md](./configuration.md) を参照する。

## 1. 目的

shbox は、標準的な SSH クライアントをフロントエンドとして、同一ホスト上の Arapuca で保護した作業環境を提供する Rust daemon である。HTTP、WebSocket、独自の wire protocol、専用 client は持たない。

v0.1 が提供する利用価値は次のとおりである。

- SSH username だけで sandbox を遅延作成し、同じ sandbox を再利用できる
- sandbox ごとに独立した対話 shell と remote command を起動できる
- 同一 sandbox へ複数の shell/exec を同時に接続できる
- 標準 SSH の stdin、stdout、stderr、EOF、終了 status、PTY、terminal resize を使える
- SSH subsystem で sandbox の一覧取得と削除を行える
- 接続や daemon の再起動後も sandbox の metadata と workspace を保持できる

shbox 自体は端末 session の永続化を行わない。永続するのは sandbox の論理的な所有情報と workspace 上のデータだけである。

## 2. 想定利用者と信頼境界

初期版は単一ホストで、単一の operator または信頼できる小規模チームが使う alpha 品質の製品である。稼働率、性能、長期互換性の SLA は提供しない。

sandbox 内で実行されるコードは悪意を持つ可能性がある。ただし shbox は、それ自体が完全な security boundary、untrusted multi-tenant platform、または hostile tenant 向けの isolation 製品であるとは約束しない。実際の制限は Arapuca と OS の能力、daemon の配備、ホストの DAC/capability に依存する。信頼境界と配備条件は [security.md](./security.md) と [platforms.md](./platforms.md) に定義する。

v0.1 の正式対応対象は、実装と実機統合試験に合格した次の組合せに限る。

- Linux `x86_64`
- Linux `aarch64`
- macOS `arm64`

macOS の特定 version は、固定した CI runner で試験した version だけを対応表に掲載する。「macOS 15 以上」など将来 version までの一括保証はしない。macOS `x86_64`、Windows、その他の target は v0.1 の正式対応外である。

## 3. 用語とモデル

### 3.1 Principal

SSH 公開鍵そのものを認証主体とする。principal の安定した識別子は、authorized key に含まれる Ed25519 公開鍵の正確な SHA-256 fingerprint（`SHA256:<unpadded-base64>`）である。username は OS アカウントではない。

### 3.2 Sandbox

sandbox は次の組み合わせである。

- shbox が所有する metadata
- `$XDG_DATA_HOME/shbox/sandboxes/<SandboxId>/workspace` の永続 workspace
- その workspace を共有して一時的に起動される、接続単位の Arapuca process 群

Arapuca の通常 Process backend は永続的な named sandbox object ではない。したがって、process、PTY、環境変数、workspace 外の一時ファイルは接続や process の終了時に残らない。一方、workspace 内のファイルと ownership metadata は明示的に delete されるまで残る。複数 process 間のファイル競合やアプリケーションの整合性は利用者の責任であり、shbox は file lock や single-writer 制御を提供しない。

### 3.3 SSH connection と channel

一つの SSH connection は複数の session channel を multiplex できる。認証済み principal と role は connection 単位、PTY、process、resize、channel lifecycle は channel 単位で管理する。一つの channel で成立できる shell、exec、subsystem は一つだけである。同じ sandbox への別 channel は別の disposable process/PTY になる。

## 4. Local daemon CLI

`shbox` は foreground server であり、引数なしの実行が daemon 起動を意味する。

```console
shbox
```

CLI parser には `usage-rs` を使用し、v0.1 の表面は次の process-lifetime options と output
actions を持つ。

```text
Usage: shbox

Options:
  -h, --help
  -V, --version
      --listen <ADDR>
      --network <MODE>
      --log-level <LEVEL>
      --authorized-keys-host-access
      --completions <SHELL>
      --man
```

`--listen` は repeat 可能で、未指定時は `0.0.0.0:22`。`--network` は `disabled`（default）
または `outbound`、`--log-level` は `error`、`warn`、`info`（default）、`debug`、`trace`。
`--authorized-keys-host-access` は全 authorized key に host/admin 権限を与える。
`--completions` と `--man` は daemon を起動せず stdout に出力する。
subcommand、daemonize、管理 command、`--config`、`--host-key`、`--authorized-keys` などの
server 設定 option は持たない。sandbox 操作には SSH、
service lifecycle には systemd/launchd など外部 service manager を使う。

## 5. SSH から見た利用方法

### 5.1 Sandbox shell

```console
ssh <sandbox-id>@host
```

たとえば次の接続は `dev` sandbox を作成または再利用する。

```console
ssh dev@shbox.example.com
```

有効な公開鍵で認証し、username が有効な SandboxId なら、sandbox を atomic に get-or-create して shell channel を開始する。SSH client が username を省略した場合は client が選んだデフォルト username が送信される。匿名 username は存在しない。

通常の sandbox shell のデフォルトは daemon を実行する OS ユーザーの login shell である。passwd entry が空の場合だけ `/bin/sh` を fallback とする。選ばれた非空 path が存在しない、通常 file でない、または実行できない場合は起動・reload を失敗させる。interactive shell は login mode で起動する。`sandbox_shell` が設定されている場合はその絶対 path を使用する。

### 5.2 Remote command

```console
ssh <sandbox-id>@host '<command>'
```

```console
ssh dev@shbox.example.com 'cargo test'
```

remote command は標準 SSH の exec request として一つの command string で受け取る。sandbox shell と同じ shell を command interpreter として `-c` で起動する。通常の remote command は login shell としてではなく `shell -c` として実行されるが、`/bin/sh` を常に強制する仕様ではない。PTY が要求されれば PTY 上でも exec できる。

client の環境変数を sandbox に自動転送しない。sandbox 用の環境変数は設定ファイルの `sandbox_env` だけで定義する。

### 5.3 List

一覧は SSH subsystem `list` で取得する。

```console
ssh -s user@shbox.example.com list
```

通常鍵の場合、username は意味的に無視され、認証鍵が所有する sandbox だけを返す。admin key の場合は全 sandbox を返す。admin key で全件取得する標準形は次である。

```console
ssh -s _@shbox.example.com list
```

出力は次の形式に固定する。

- 有効な `Active` metadata を持つ sandbox のみ
- 1 行に 1 ID、header なし、各行末尾に LF
- bytewise の ASCII 昇順、重複なし
- 0 件なら stdout は 0 bytes
- 成功時の SSH exit status は `0`
- metadata がまだ publish されていない partial create、`Deleting`、欠落・破損 metadata の sandbox は表示しない

`list` は引数を持たない。OpenSSH の subsystem request には argv がなく、`list extra` のような呼び出しは `list extra` という名前として扱われるため拒否する。

### 5.4 Delete

対象 ID を username に置き、`delete` subsystem を呼ぶ。

```console
ssh -s dev@shbox.example.com delete
```

admin が任意の sandbox を削除する場合も対象 ID を username にする。`_` は host selector であり、delete の対象にはならない。

delete は対象 ID の lifecycle lock を取得し、次の順序で処理する。

1. metadata を `Deleting` に遷移させる
2. 対象 sandbox の shell、PTY、exec process だけを停止する
3. Arapuca process を停止して回収する
4. workspace と metadata を sandbox root から削除する
5. workload channel を閉じ、delete request channel 自体には結果 status を返してから閉じる

削除中は同じ ID の新しい shell/exec を拒否する。途中で失敗した場合は `Deleting` のまま隠し、data を勝手に再作成しない。次回起動時の reconcile、owner/admin による再 delete、または operator の修復で再試行できる。成功した delete は永久的で、trash、undo、backup はない。削除完了後に同じ ID へ接続すると、新しい sandbox として lazy create される。

対象が存在しない場合、または通常鍵が所有していない ID を指定した場合は、存在の有無を開示しない idempotent no-op とする。stdout/stderr は空、exit status は `0` である。ただし ID 自体が不正、または実際の I/O・permission 失敗で完了できない場合は non-zero とする。

## 6. Admin と host mode

admin key は設定で複数指定できる。admin key は全 sandbox の list、shell、exec、delete を行え、sandbox 所有者による制限を受けない。`--authorized-keys-host-access` を指定すると、
`admin_keys` に列挙していない authorized key も同じ Admin role になる。この flag は daemon の
process lifetime 中固定であり、config file や reload から変更できない。

username `_` は admin 専用の host selector である。

```console
ssh _@shbox.example.com
ssh _@shbox.example.com 'uname -a'
ssh -t _@shbox.example.com
```

`_` で利用できる host mode は、daemon と同じ OS user/group でホスト上に process を起動し、shell、exec、PTY、resize、signal を提供する。初期 cwd は daemon account の home とする一方、環境変数は `HOME` を含めて daemon の service environment をそのまま継承し、shbox は上書きしない。operator は service の `HOME` を account home と整合させ、秘密を環境へ置かない。host mode がサービス秘密を読めることは仕様上のリスクとして受け入れる。

host mode は SFTP subsystem、port forwarding、agent forwarding、X11 forwarding、streamlocal forwarding を提供しない。SCP に固有の protocol 対応や互換性も保証しない。legacy SCP が `exec` として送る command は、他の remote command と区別せず通常の exec 規則で処理する。未知または不要な channel/request は拒否する。通常鍵による `_` の利用、admin 以外の host access、host mode からの sandbox 迂回は拒否する。

admin key が `_` 以外の有効な SandboxId を指定した場合は、その sandbox の admin として扱う。存在しない ID を admin が最初に作成した場合、その admin key の fingerprint を owner として metadata に記録する。

admin を一つも設定しない構成も有効であり、host-access flag も無ければ sandbox-only mode
になる。この場合 `_` は利用できず、全件管理と host bypass は存在しない。admin key の設定
変更は [configuration.md](./configuration.md) の reload 規則に従う。

## 7. 所有権と可視性

最初に成功した claimant の公開鍵 fingerprint が sandbox の owner になる。create race では一つの key だけが atomic に owner となり、敗者には所有者や存在を開示しない。owner は自分の sandbox に shell、exec、list、delete を行える。通常鍵は他 owner の sandbox を見られず、既知の ID を指定しても同じ nondisclosing denial になる。

一つの sandbox に owner は一つだけで、sharing、transfer、owner rotation API は v0.1 にない。authorized key を削除しても sandbox data は削除せず orphan とする。admin は orphan を利用・削除でき、同じ公開鍵を再登録すれば元の owner として戻る。

## 8. Terminal と process の観測可能な契約

- shell/exec ごとに disposable process を作る。PTY は channel ごとに独立する。
- 同一 sandbox への複数 channel と同時 exec を許可する。
- `pty-req` の rows/columns と主な POSIX terminal mode を process launch 直後、client へ I/O bridge を公開する前に反映する。適用に失敗した process は公開せず cleanup する。固定 Arapuca API の制約により、target の最初の命令より前の反映は保証しない。pixel dimensions と未知 mode は無視する。
- `window-change` の rows/columns を PTY に反映する。
- PTY では stdout/stderr は端末 stream に統合される。PTY なしでは stdout と stderr を SSH の別 stream に送る。
- client EOF 後は新しい入力を送らず、process の残りの出力と終了 status は継続して返す。非 PTY では child stdin の EOF になるが、PTY では child が EOF を観測する保証はなく、`VEOF` byte を合成しない。
- process 完了時は出力、EOF、exit-status または exit-signal、channel close の順序を保つ。
- SSH signal request は既知の POSIX signal だけを process group に転送する。未知の signal は拒否する。
- client disconnect、delete、daemon shutdown では関連 process を graceful に終了し、5 秒後に force cleanup する。daemon crash でも OS の parent-death、process group、Linux cgroup の機構を使って残留 process を回収する。
- terminal の detach/reattach、session ID、scrollback、replay、persistent PTY、multiplexer 特有の互換性は提供しない。

## 9. Network と環境

sandbox の network policy は daemon 起動時の `--network` で選ぶ次の二つだけである。

- `disabled`（デフォルト）：外部 network を許可しない
- `outbound`：初期 v0.1 から利用できる unrestricted TCP/UDP/DNS network capability。主用途は outbound 通信であり、宛先 allowlist は提供しない

`outbound` で shbox 自身が port mapping や SSH forwarding を作ることはないが、全 OS で
socket を egress-only に制約する security boundary は約束しない。process が bind/listen
できるかは Arapuca/OS と host firewall に依存する。operator は外部からの到達を host
firewall で遮断する。これは shbox の意味論であり、Arapuca の raw profile option や network
mode を設定ファイルに露出しない。host mode は sandbox network policy の対象外である。
SIGHUP で network mode は変わらない。

workspace は sandbox process の HOME と cwd になる。追加の sandbox environment は config からのみ注入し、loader injection、`ARAPUCA_*`、その他の管理用変数は受け付けない。詳細は [configuration.md](./configuration.md) を参照する。

## 10. 非目標

v0.1 では次を実装しない。

- HTTP、REST、WebSocket、Web UI、browser terminal protocol
- 専用 client CLI、`run`/`list`/`delete` 等の daemon CLI subcommand
- persistent terminal、detach/reattach、replay、scrollback 保存
- sandbox の sharing/transfer/migration、billing、multi-node scheduler
- container backend、VM orchestration、backend selector、Kubernetes integration
- OIDC、Cloudflare Access などの外部 identity integration
- SFTP subsystem、SCP 互換性、port/agent/X11/streamlocal forwarding
- service の install/start/stop や systemd の管理機能

## 11. 互換性と versioning

SSH protocol は RFC 4254 の session/channel semantics に従う。v0.1 で compatibility と CI の対象にする client は現行の OpenSSH とし、他の SSH client は best effort とする。SSH subsystem は argv を持たないため、list/delete は引数なしの単一名で表現できる範囲に限定する。

実装は Arapuca v0.2.7 package の次の git revision に固定する。

```text
c94802c4d8b6b880334c0d643b16b7326ec7f039
```

これは v0.2.7 tag `8c61b0d` の後に macOS PTY の `file-ioctl` と `/var` traversal を修正した未リリースの累積 revision である。依存更新はこの revision の差分確認と、対応する Linux/macOS の全統合試験を通過した場合だけ行う。package version `0.2.7` だけをもって正式 upstream release や互換保証とは扱わない。

v0.1 の外部契約はリリースごとに固定する。0.x の minor release は、変更点を明記したうえで破壊的変更を許容する。metadata は version `1` のみを認識し、未知 version は list/delete/create の対象にせず block する。自動 migration は行わない。

## 12. 関連文書

- [configuration.md](./configuration.md): TOML、既定値、reload、固定パス
- [security.md](./security.md): 脅威境界、認証、ownership、host bypass
- [architecture.md](./architecture.md): module、state、storage、lifecycle
- [ssh-protocol.md](./ssh-protocol.md): russh channel、PTY、stream、終了規則
- [platforms.md](./platforms.md): Arapuca adapter、OS capability、配備条件
- [testing.md](./testing.md): acceptance criteria、実機試験、support matrix
