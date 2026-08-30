# セキュリティ仕様

この文書は、`shbox` v0.1 の認証、認可、sandbox の境界、データ保護、SSH
公開面を定義する。実装はここで定める不変条件を満たさなければならない。

`shbox` は SSH 接続を Arapuca の per-process sandbox に変換する daemon で
ある。Arapuca が提供するのはプロセス起動の制限であり、永続 sandbox の所有権、
metadata、workspace、認可、削除は `shbox` の責務である。Arapuca は次の revision
へ固定する。

`c94802c4d8b6b880334c0d643b16b7326ec7f039`（package version は upstream の
`0.2.7` のまま）。この revision は macOS の PTY ioctl と `/var` traversal の
修正を含むが、正式な semver release としては扱わない。

## 1. 信頼境界と脅威モデル

### 1.1 前提

- v0.1 は単一ホスト上で、単一 operator または信頼できる小規模チームが使う。
- sandbox 内で実行されるコードは悪意を持つ可能性がある。コードの安全性を
  前提に、認証や resource 制限を省略してはならない。
- ただし `shbox` 自体は独立した security boundary や、信頼されない tenant
  間の強い隔離を保証しない。隔離の強度は Arapuca、OS、kernel、daemon の
  配備権限に依存する。
- daemon は専用の非 root service account で動かす。sandbox process は
  v0.1 では daemon と同じ OS uid/gid で起動し、SSH username を OS account
  や uid に変換しない。
- host mode は admin に意図的に host process を実行させる機能であり、sandbox
  escape を防ぐ機能ではない。admin key の保護と daemon 配備環境の保護を
  分離して扱う。

### 1.2 保護対象

保護対象は、次の順に扱う。

1. authorized keys、host private key、admin key の設定。
2. sandbox metadata（owner fingerprint と lifecycle state）。
3. 各 sandbox の workspace と、他 sandbox の metadata/workspace。
4. daemon の listen socket、XDG state/data の lock、設定ファイル。
5. connection/channel の認証済み role と process handle。

通常の sandbox key に対しては、他の sandbox の存在、owner、path、process、
エラーの内部詳細を開示しない。admin はこの原則の意図した例外である。

### 1.3 想定する攻撃

攻撃者は有効な通常 key を持っている場合、所有する workspace 内のファイルを
読み書きし、許可された read-only path を読み、設定された network policy の
範囲で process を実行できる。さらに、SSH protocol を不正な順序・サイズ・
切断で呼び出し、resource cap に達する操作を試みることができる。

攻撃者は、次の操作を通常 key で行えない。

- 他人の sandbox の list、shell、exec、delete。
- `_` host selector による host shell/exec/PTY。
- SSH port forwarding、agent/X11 forwarding、SFTP などの別経路。
- Arapuca の raw profile、cgroup、network、UID/GID 設定の変更。

kernel、Arapuca、OpenSSH/russh、ホスト root、または admin key が侵害された
場合の安全性はこの仕様の保証対象外である。

## 2. 認証と principal

### 2.1 SSH 認証

- 認証方式は Ed25519 public key のみとする。
- `none`、password、keyboard-interactive、certificate key、その他の
  public-key algorithm は拒否する。
- 公開鍵の ownership 判定は、署名検証が完了した認証 callback で行う。
  key の ownership を確認していない probe（offered key）だけで role や
  state を変更してはならない。
- SSH username は OS login username ではなく、後述する selector である。
  認証時点では `_` 以外の username を受け入れ、shell/exec/delete を実行する
  時点で selector として検証する。`_` は admin host selector として予約する。

### 2.2 authorized_keys の形式

authorized keys は OpenSSH 形式の **一つのファイル**から読む。既定パスは
daemon 実行ユーザーの `~/.ssh/authorized_keys`、設定で絶対パスを変更できる。

受け入れる行は次の形式に限る。

```text
ssh-ed25519 <base64-public-key> [comment]
```

- 空行と、行頭のコメント（`#`）は無視する。
- key options、command restriction、environment option、証明書形式は
  受け入れない。コメントは保存せず認証にも使わない。
- base64 と公開鍵 blob が不正、または unsupported な行が一つでもあれば、
  ファイル全体を設定エラーとして扱う。壊れた行を黙って無視しない。
- 同一の公開鍵が複数行に現れる場合も設定エラーとする。
- 1 行は最大 8 KiB、ファイル全体は最大 1 MiB とする。
- 空ファイルは無効であり、少なくとも一つの Ed25519 key が必要である。

admin key は設定の `admin_keys` に fingerprint の配列として指定する。指定は
複数可能で、次の OpenSSH 表記に完全一致させる。

```text
SHA256:<padding なしの base64>
```

fingerprint はコメントや入力行の文字列ではなく、authorized key の公開鍵 blob
から計算する。同じ fingerprint の重複、authorized_keys に存在しない fingerprint、
Ed25519 でない fingerprint は設定エラーとする。

authorized_keys のファイルと親ディレクトリ、設定ファイル、XDG state/data の
管理ディレクトリは daemon user が所有し、group/world writable であってはならない。
権限不備は起動・reload の失敗とする。秘密鍵を authorized_keys に置かず、host
private key は XDG state 配下の mode `0600` のファイルに保存する。

### 2.3 認証 snapshot

起動時に authorized_keys と admin_keys を読み込む。`SIGHUP` では新しい内容を
全体検証し、成功した場合だけ一括で置き換える。失敗した場合は直前の認証設定を
保持し、既存接続も新規接続も中断しない。

認証成功時に connection へ、少なくとも次を保存する。

- public key の fingerprint。
- normal/admin の role。
- 認証時 username と selector context。

この snapshot は接続が閉じるまで変わらない。reload で key を削除しても既存
connection は切断されず、既存 connection が開く新しい channel も同じ role を
使う。新規 connection は新しい authorized_keys で認証する。

## 3. role、selector、所有権

### 3.1 role matrix

`admin_keys` が空または未指定なら admin は存在せず、daemon は sandbox-only
mode で動く。admin key を設定した場合、その key は自動的に全 sandbox 権限と
host 権限を持つ。host 専用の別 role は設けない。

| principal | selector | shell / exec | list | delete | host mode |
|---|---|---|---|---|---|
| 通常 key | 自分が owner の有効な SandboxId | 自分の sandbox のみ | 自分の sandbox のみ | 自分の sandbox のみ | 不可 |
| admin key | 任意の有効な SandboxId | 全 sandbox | 全 sandbox | 全 sandbox | `_` で可 |
| 未認証 | なし | 不可 | 不可 | 不可 | 不可 |

通常 key が別 owner の ID を指定した場合、その ID の存在・owner・path を推測
できる応答を返さない。`list` は通常 key の fingerprint で owner filter し、
username を list の selector として使わない。admin の全件 list は次で行う。

```console
ssh -s _@host list
```

`_` は SandboxId ではない。admin であっても `_` を delete target に指定しては
ならず、削除対象は常に通常の SandboxId とする。

### 3.2 SandboxId

SandboxId は ASCII の case-sensitive identifier である。

```text
[A-Za-z0-9][A-Za-z0-9-]{0,63}
```

`_`、`.`、`/`、空白、制御文字、Unicode、空文字を禁止する。`_` は host selector
として予約され、ID validation を通過しない。検証済み `SandboxId` と raw username
を型または専用境界で分離し、validation を一箇所に集約する。

### 3.3 owner fingerprint

各 sandbox の owner は Ed25519 public key の SHA-256 fingerprint 一つである。
key の共有、owner transfer、owner rotation API は v0.1 にない。

- sandbox が初めて作られるとき、作成を atomic に完了した key が owner になる。
- 同一 ID を複数 key が同時に作ろうとした場合、勝者一つだけが owner になる。
  敗者には存在や勝者を示さない一般的な拒否を返す。
- owner key を authorized_keys から削除しても sandbox は削除しない。sandbox は
  orphan として残り、admin が利用・削除できる。後で同一 key を再登録した場合は
  exact fingerprint で元の owner 権限に戻る。
- admin が通常の SandboxId で sandbox を初めて作った場合、metadata の owner は
  その admin key の fingerprint とする。

## 4. metadata、filesystem、lifecycle の保護

### 4.1 永続データ

persist するのは、各 sandbox の metadata と workspace filesystem だけである。
概念上の配置は次のとおり。

```text
$XDG_DATA_HOME/shbox/sandboxes/<SandboxId>/
├── metadata.toml   # version 1, mode 0600
└── workspace/      # mode 0700
```

管理用ファイル名は `metadata.toml` に固定し、sandbox 間で共有しない。metadata は
version `1`、owner fingerprint、`Active` または `Deleting` state のみを持つ。
未知 version は list や操作で使用せず、migration も自動実行しない。

filesystem の管理 root、sandbox directory、metadata は daemon user 所有とし、
原則 mode `0700` / `0600` にする。状態変更は一時ファイルへの write、file fsync、
atomic rename、親 directory fsync の順で行う。workspace 内のアプリケーション
データの fsync は利用者の責務である。

### 4.2 path safety

- sandbox root の外へ出る relative path、`..`、管理 root の symlink、別 sandbox
  を指す symlink を管理対象として受け入れない。
- workspace 内の symlink はアプリケーションデータとして許可できるが、管理
  metadata や管理 directory の解決には no-follow と root containment check を
  適用する。
- delete は path を文字列連結して行わず、canonical/root containment を確認した
  handle または安全な directory traversal で実行する。workspace 内の symlink に
  よって sandbox root 外を削除してはならない。
- list は `Active` で完全に検証できる metadata だけを返す。missing/corrupt
  metadata、metadata 未 publish の partial create、`Deleting`、symlink である管理 entry は list から隠し、
  自動修復・自動削除しない。admin の修復は out-of-band とする。

### 4.3 lock と同時実行

同一 sandbox data root または同一 state root への daemon 二重起動を、
`$XDG_DATA_HOME/shbox/registry.lock` と `$XDG_STATE_HOME/shbox/lock` の exclusive
advisory lock で拒否する。両方を non-blocking で取得できた場合だけ起動する。per-ID
lock により create、delete、owner claim、metadata 更新を直列化するが、異なる
ID の操作は並列に処理してよい。

一つの workspace を複数 process が同時に read/write できる。`shbox` は file lock、
single-writer、アプリケーションレベルの merge を提供しない。共有書き込みに伴う
データ競合は sandbox 内アプリケーションの責務である。

delete は metadata を `Deleting` にしてから workload を停止し、対象 channel と
process を閉じ、workspace と metadata を削除する。`Deleting` 中は新しい shell
と exec を拒否し、list から隠す。途中で失敗した場合は `Deleting` のまま残して
再試行可能にし、別 ID や daemon 全体を巻き込まない。成功した delete は完全削除
であり、trash、undo、backup は作らない。削除後の新しい shell/exec は同じ ID を
新規 sandbox として lazy-create できる。

## 5. sandbox process の境界

### 5.1 Arapuca adapter

各 shell/exec/PTY は disposable な Arapuca Process を一つ持つ。同じ sandbox の
複数 process は共有 workspace を使うが、process、PTY、environment、Arapuca の
private temporary directory は共有しない。process が終了・切断しても metadata と
workspace は残る。

`SandboxManager` が owner、metadata、per-ID state、process lifetime を所有し、
SSH 層へ raw Arapuca object を公開しない。process launch は private な
`ProcessLauncher` seam の後ろに置く。production adapter は固定 revision の
Arapuca を使い、test adapter は故障・競合を決定的に注入できるものとする。

Arapuca 固有の profile、`task_id`、cgroup path、wrapper、network syscall flag
などは shbox の設定項目として直接公開しない。利用者が設定できるのは shbox の
domain semantics（network、read-only path、shell、resource cap など）だけで、
Arapuca への mapping は adapter の内部実装とする。

### 5.2 identity、environment、path

- sandbox process は daemon の uid/gid で起動する。別 uid/gid への変更、追加
  supplementary group、OS account の選択は行わない。
- `HOME` と `PWD` は sandbox の workspace、`SHELL` は選択された shell にする。
  `Config.env` は server-managed な clean environment を作るためにだけ使い、
  client の env request や client の環境を持ち込まない。
- sandbox env の名前は POSIX identifier、値は UTF-8 で NUL を含まず、値は最大
  4 KiB。`HOME`、`PWD`、`SHELL`、`ARAPUCA_*`、loader/interpreter injection
  変数、その他の managed name は利用者設定から拒否する。
- workspace は read/write、追加設定は既存の絶対 canonical path に限る read-only
  path とする。shbox の private directory、他 sandbox、管理 metadata を追加
  path にできない。追加 write path は公開しない。
- Arapuca が利用できない、Linux の必要な cgroup delegation がない、または
  launch が安全な profile を適用できない場合、sandbox request は失敗させる。
  host process を代替として直接実行する degraded fallback はない。

### 5.3 network

network policy は全 sandbox 共通の `disabled` または `outbound` だけである。
per-sandbox、per-owner、inbound listener の設定はない。

- `disabled` は strict な network denial を使用する。
- `outbound` は初期版から対応し、unrestricted な TCP/UDP/DNS network capability を許可
  する。主用途は outbound で、外向き通信の宛先 allowlist は設けない。shbox 自身は port
  mapping/forwarding を作らないが、全 OS で bind/listen を禁止する egress-only 境界は
  約束しない。外部からの到達は host firewall で制御する。

`outbound` は悪意あるコードから外部 endpoint へ接続できる強い権限なので、
operator は機密情報を workspace、環境、read-only path に置かない。

### 5.4 resource cap

既定の同時実行上限は次のとおりである。設定で変更できる値も daemon 全体または
sandbox 全体の policy とし、owner ごとの任意 override は設けない。

| 対象 | 既定値 |
|---|---:|
| 未認証接続 | 32 |
| 全接続 | 128 |
| 1 connection の session channel | 16 |
| sandbox 全体の同時 process | 128 |
| host mode の同時 process | 16 |
| sandbox 総数 | 1024 |
| owner 一人あたりの sandbox 数 | 128 |
| authentication attempts | 6 |
| command payload | 32 KiB |
| PTY TERM | 256 bytes |
| subsystem name | 64 bytes |
| open files | 1024 |
| Linux `max_pids` cgroup limit | 256 |

`[limits]` の resource 値 `0` はその limit がないことを意味する。一方、`[caps]` の
connection、channel、process、sandbox、timeout 上限に `0` は指定できない。Linux の
process、memory、CPU、file、cgroup の強制方法と macOS の best-effort な差異は
platform 文書で定める。macOS で Linux の cgroup/pid/CPU quota と同じ強度を
主張しない。

Linux は cgroup v2 と delegated `cpu cpuset memory pids` を持つ専用 scope に
daemon を配置する。Arapuca は現在の process の cgroup scope を自動検出し、起動
時に `arapuca-*` を掃除するため、他の daemon と scope を共有してはならない。
専用 scope または必要な controller が確認できないときは sandbox backend を
利用不能にする。

## 6. host mode の特別な境界

admin key だけが `_` selector を使える。

```console
ssh _@host
ssh _@host command
ssh -t _@host
```

host mode は Arapuca を通さず、daemon service account の login shell と home cwd を
使い、shell、exec、PTY、resize、signal を提供する。環境は `HOME` を含めて service
environment を上書きせず継承するため、operator は account home と環境を整合させる。host mode に入った process
は sandbox workspace の path policy や network policy で制限しない。admin key を
持つ者は host を完全に信頼できる者でなければならない。

host mode では service の環境変数を全て継承する。したがって、
service unit や launchd の environment に token、秘密鍵、database password など
を置くと、それらは admin の host shell/exec から見える。secret を含む service
environment を運用で与えない。通常の sandbox mode は server が作る clean
environment を使い、service environment 全体を継承しない。

admin key を設定しない場合は sandbox-only mode で `_` route は認証されない。
admin key がある managed mode では `_` listener を先に公開して復旧経路を確保
できるが、filesystem reconciliation が終わるまで sandbox 操作は fail closed
とする。sandbox-only mode は reconciliation 完了後に listener を公開する。

## 7. SSH 攻撃面と拒否する機能

受け入れるのは session channel 上の shell、exec、PTY、window-change、signal、
EOF、`list`/`delete` subsystem だけである。

明示的に拒否するもの:

- `direct-tcpip`、forwarded TCP、Unix/streamlocal forwarding。
- agent forwarding、X11 forwarding、port forwarding。
- `env` request。client の環境を sandbox/host に注入しない。
- SFTP と未知の subsystem。v0.1 の subsystem は `list` と `delete` のみ。legacy SCP
  は通常の exec と区別できないため特別許可・拒否せず、互換性を保証しない。
- channel 上で複数の shell/exec/subsystem を開始すること。
- PTY を要求した `list`/`delete`。

非 session channel を開く callback、未知 request、request の順序違反は server
panic ではなく channel failure または一般的な拒否として処理する。forwarding を
受け入れたかのような空実装にしてはならない。

## 8. エラー、非開示、ログ

### 8.1 client への応答

remote には、安定した短い一般エラーだけを返す。次を SSH response、stderr、
または subsystem status に含めない。

- filesystem の絶対 path、XDG path、cgroup path。
- owner/admin の fingerprint。
- 内部 error chain、backtrace、Arapuca の raw message。
- 他 sandbox の存在、state、process、削除理由。

通常の認可拒否、invalid selector、malformed request、resource cap 超過は同じ
カテゴリの一般的な拒否として扱う。`delete` の absent または非 owner は stdout/
stderr を空にし、exit status `0` の no-op として存在を非開示にする。実際の内部
障害は non-zero とするが、内部詳細は log にだけ記録する。remote command 自体の
stdout/stderr は変換・記録せず、process の出力をそのまま転送する。

### 8.2 log

`tracing` の structured compact text を stderr に出力し、UTC RFC3339 の timestamp
を付ける。file log、rotation、`RUST_LOG` は v0.1 にない。`log_level` は
`error`、`warn`、`info`、`debug`、`trace` から設定し、既定は `info`、SIGHUP で
reload する。

必要な監査情報として、connection ID、channel ID、remote IP、key fingerprint、
role、selector/ID、operation、result、duration、exit status を記録してよい。
値は control character と改行を sanitize する。

次は決して log しない。

- private key、secret、sandbox environment の値。
- terminal input、stdin、terminal output。
- command text、shell startup script の内容。
- raw authorized_keys の全文。

Arapuca の raw file/network audit は無効で、shbox の公開設定にもしない。内部
invariant violation は位置と backtrace を log して daemon を abort する。認証失敗、
切断、EOF、invalid ID、通常の Arapuca/IO failure は operational/remote error と
して処理し、remote input だけで daemon 全体を panic させない。

## 9. reload と shutdown

SIGHUP は authorized_keys/admin_keys、shell、sandbox environment、network policy、
read-only paths、resource caps、connection caps、log level を全体検証したうえで
atomic に反映する。listen address、host key、data root の変更は restart-only
とし、SIGHUP で既存 listener を切り替えない。reload failure は古い設定を保持する。

最後の admin key を reload で削除すると、新規 connection は sandbox-only mode になり、
新しい admin/host access はできなくなる。既存の admin connection は connection
snapshot の規則に従い、disconnect まで権利を保持する。

SIGINT/SIGTERM では新しい認証・channel・process を受け付けず、既存の process/PTY
を並列に graceful close する。5 秒後に残存 process を force stop し、workspace と
metadata は削除しない。二度目の signal は即時 force stop とする。client disconnect
でも対象 channel の process だけを graceful close し、別 channel/connection を
不必要に切断しない。

## 10. security acceptance criteria

実装と release gate は少なくとも次を確認する。

- owner/admin/非 owner の shell、exec、list、delete の認可 matrix。
- `_` の host access、通常 key の拒否、admin の `_` delete 拒否。
- authorized_keys の malformed/options/certificate/unsupported key、サイズ、
  permission、atomic SIGHUP reload。
- key 削除後の既存 connection snapshot と、新規 connection の拒否。
- 同時 claim、delete 中の新規 request、corrupt metadata、symlink traversal、
  restart 後の owner persistence。
- payload/connections/channels/process/sandbox の各 cap と bounded output buffer。
- Linux dedicated cgroup scope、Arapuca unavailable 時の fail-closed。
- sandbox からの service environment、他 sandbox path、管理 metadata、無制限の
  read/write path へのアクセス拒否。
- host mode が service environment を継承すること、および秘密を service env に
  置かない配備文書。
- forwarding、X11/agent/env/SFTP/未知 subsystem の拒否で server が panic しない
  こと。

## 参考仕様

- [RFC 4254: The Secure Shell (SSH) Connection Protocol](https://www.rfc-editor.org/rfc/rfc4254)
- [OpenBSD ssh(1) manual](https://man.openbsd.org/ssh)
- [russh 0.63.1 `server::Handler`](https://docs.rs/russh/0.63.1/russh/server/trait.Handler.html)
- [Arapuca v0.2.7 source revision](https://github.com/LeGambiArt/arapuca/commit/c94802c4d8b6b880334c0d643b16b7326ec7f039)
- [Arapuca v0.2.7 `validate.rs`](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/validate.rs)
