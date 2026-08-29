# shbox 実装計画書

## 1. 概要

`shbox` は、SSH をフロントエンドとして利用し、Arapuca による軽量 sandbox を操作する Rust 製サーバーである。

コンテナや独自の HTTP / WebSocket API を持たず、標準的な SSH クライアントだけで以下を実現する。

- sandbox の lazy creation
- sandbox への対話接続
- sandbox 内での command 実行
- sandbox 一覧取得
- sandbox 削除
- 同一 sandbox への複数同時接続
- PTY
- terminal resize
- 通常の SSH stdin / stdout / stderr / exit status semantics

`shbox` 自身は terminal session の永続化機構を持たない。

---

# 2. 基本設計

## 2.1 SSH をそのまま API として利用する

可能な限り SSH 標準機能をそのまま利用する。

| SSH 機能 | shbox における意味 |
|---|---|
| username | sandbox ID |
| shell request | sandbox 内の interactive shell |
| exec request | sandbox 内で command 実行 |
| pty-req | PTY 作成・設定 |
| window-change | PTY resize |
| subsystem `list` | sandbox 一覧 |
| subsystem `delete` | sandbox 削除 |

独自の wire protocol は作らない。

---

## 2.2 薄い adapter に留める

`shbox` の責務は、

```text
SSH
 ↓
russh
 ↓
shbox
 ↓
Arapuca
 ↓
sandbox
```

という変換に限定する。

sandbox orchestration platform にはしない。

明確に必要になるまで、以下は追加しない。

- HTTP API
- REST API
- WebSocket API
- Web UI
- browser terminal protocol
- 専用 client CLI
- backend 選択機構
- multi-node scheduler
- VM orchestration

---

# 3. 外部インターフェース

## 3.1 Interactive shell

```console
ssh <id>@host
```

例:

```console
ssh dev@shbox.example.com
```

動作:

1. SSH username を sandbox ID として解釈
2. sandbox ID を validation
3. sandbox が存在しなければ作成
4. 存在すれば既存 sandbox を利用
5. 接続ごとに disposable PTY を作成
6. sandbox 内で shell を起動
7. SSH channel と PTY を bridge

SSH connection が切断された場合、その connection に対応する PTY / shell のみ終了する。

sandbox 自体は残る。

---

## 3.2 Exec

```console
ssh <id>@host <command>
```

例:

```console
ssh dev@shbox.example.com 'cargo test'
```

動作:

1. username → sandbox ID
2. sandbox を get-or-create
3. sandbox 内で command 実行
4. SSH stdin → process stdin
5. process stdout → SSH stdout
6. process stderr → SSH stderr
7. process exit code → SSH exit status

PTY が要求された場合は PTY 上でも exec 可能にする。

```console
ssh -t dev@shbox.example.com htop
```

`exec` は管理 API として使わず、通常の SSH remote-command semantics とする。

---

## 3.3 List

sandbox 一覧は SSH subsystem とする。

```console
ssh -s host list
```

`list` では SSH username を無視する。

出力例:

```text
alpha
dev
issue-15
test
```

仕様:

- 1 sandbox ID / 1 行
- header なし
- bytewise / ASCII 昇順
- 各 ID の末尾に LF
- sandbox 0件なら stdout 0 bytes
- 成功時 exit status `0`
- 失敗時 non-zero

JSON は標準形式にしない。

Unix command と直接組み合わせやすい plain text を優先する。

---

## 3.4 Delete

sandbox 削除も SSH subsystem とする。

```console
ssh -s <id>@host delete
```

例:

```console
ssh -s dev@shbox.example.com delete
```

動作:

1. username → sandbox ID
2. ID validation
3. 対象 sandbox の workload を停止
4. PTY / process /関連 SSH channel を終了
5. Arapuca sandbox resource を削除
6. sandbox 永続データを削除
7. exit status を返す

`delete` を shell command として起動せず、SSH subsystem request として直接処理する。

---

# 4. Sandbox ID

SSH username を sandbox ID として使用する。

予約 username は設けない。

デフォルト sandbox や random sandbox ID の自動生成も行わない。

`ssh host` の場合は SSH client が送った username をそのまま sandbox ID として扱う。

候補となる ID 制約:

```text
[A-Za-z0-9][A-Za-z0-9._-]{0,63}
```

禁止:

- 空文字列
- whitespace
- control character
- `/`
- その他 path / ID として危険な文字

validation は一箇所に集約する。

可能なら、

```rust
struct SandboxId(...)
```

のように validation 済み ID と raw string を型で分離する。

---

# 5. Sandbox lifecycle

明示的な create API は作らない。

shell / exec が create operation を兼ねる。

```text
shell / exec
      │
      ▼
sandbox exists?
   ┌──┴──┐
   │     │
  yes    no
   │     │
   │   create
   │     │
   └──┬──┘
      ▼
    execute
```

つまり、

```console
ssh dev@host
```

または、

```console
ssh dev@host command
```

だけで sandbox を利用開始できる。

削除のみ明示操作とする。

---

# 6. PTY lifecycle

sandbox と PTY の lifetime は分離する。

```text
Sandbox dev
├── SSH channel A → PTY A
├── SSH channel B → PTY B
├── SSH channel C → PTY C
└── exec process D
```

同一 sandbox への複数同時接続を正式に許可する。

各 PTY は独立する。

SSH channel が終了したら、その PTY / shell のみ終了する。

sandbox 自体は残す。

---

# 7. Terminal session persistence

`shbox` 自身では persistent terminal session を実装しない。

以下は責務外とする。

- persistent PTY
- detach / reattach
- terminal session ID
- reconnect buffer
- scrollback 保存
- replay
- multi-client terminal sharing

特定の terminal multiplexer に対する特別対応や互換性保証も行わない。

`shbox` が保証するのは標準的な SSH / PTY semantics までとする。

---

# 8. Authentication

public key authentication を基本とする。

意味論を明確に分離する。

```text
SSH public key = 接続者の認証
SSH username   = sandbox ID
```

username は OS user account ではない。

したがって、

```console
ssh dev@host
```

の `dev` は OS login user ではなく sandbox selector である。

authorized keys のデフォルト:

```text
~/.ssh/authorized_keys
```

ここでの `~` は `shbox` daemon を実行しているユーザーの home directory。

sandbox ごとに authorized_keys は分けない。

---

# 9. Rust 技術構成

主要 dependency:

- Rust
- Tokio
- russh
- Arapuca
- usage-rs
- xdg
- tracing
- tracing-subscriber
- TOML parser

原則として dependency は必要最小限にする。

使用しないもの:

- `anyhow`
- 原則として `thiserror`
- `clap`
- HTTP framework
- WebSocket framework
- container runtime

---

# 10. CLI

`shbox` は client CLI ではなく daemon である。

何も指定せず実行すること自体が server 起動を意味する。

```console
shbox
```

サブコマンドは設けない。

以下は作らない。

```text
shbox run
shbox serve
shbox start
shbox stop
shbox status
shbox doctor
shbox setup
shbox list
shbox delete
shbox exec
```

sandbox 操作は SSH から行う。

---

## 10.1 CLI parser

CLI parser には `usage-rs` を使用する。

CLI の表面仕様は基本的に以下のみ。

```text
Usage: shbox

Options:
  -h, --help
  -V, --version
```

server configuration 用 CLI option は設けない。

以下は作らない。

- `--listen`
- `--config`
- `--host-key`
- `--authorized-keys`

---

# 11. XDG 方針

ファイル配置は原則として XDG Base Directory Specification に従う。

XDG directory の解決は自前実装せず、Rust の `xdg` crate を使用する。

概念的には `BaseDirectories` を `shbox` prefix で使用し、

- config
- data
- state
- runtime

を取得する。

`HOME` fallback や XDG environment variable の解釈を shbox 側で再実装しない。

---

## 11.1 Config

```text
$XDG_CONFIG_HOME/shbox/config.toml
```

標準 fallback:

```text
~/.config/shbox/config.toml
```

設定ファイルが存在しない場合は built-in default を使用する。

---

## 11.2 Sandbox data

sandbox は persistent user data を持ち得るため `XDG_DATA_HOME` に置く。

```text
$XDG_DATA_HOME/shbox/sandboxes/
```

標準 fallback:

```text
~/.local/share/shbox/sandboxes/
```

各 sandbox:

```text
$XDG_DATA_HOME/shbox/sandboxes/<id>/
```

例:

```text
~/.local/share/shbox/
└── sandboxes/
    ├── dev/
    ├── issue-15/
    └── test/
```

Arapuca が sandbox root 以下の独自レイアウトを持つ場合、その内部構造は Arapuca に任せる。

shbox は必要以上に内部ファイル構造を規定しない。

---

## 11.3 State

host key などは `XDG_STATE_HOME` に置く。

```text
$XDG_STATE_HOME/shbox/host_key
```

標準 fallback:

```text
~/.local/state/shbox/host_key
```

host key は shbox 専用とする。

既存 OpenSSH server の host key を暗黙に流用しない。

存在しなければ初回起動時に生成する。

初期形式は Ed25519 を基本とする。

---

## 11.4 Runtime

`XDG_RUNTIME_DIR` は実際に必要になった場合のみ使用する。

候補:

- process lifetime の lock
- Unix socket
- 一時 runtime metadata

現時点では必須としない。

---

## 11.5 Cache

`XDG_CACHE_HOME` は現時点では使用しない。

---

# 12. Configuration

設定は、

```text
config.toml
 ↓
built-in default
```

の2段階のみとする。

個別設定用 environment variable や CLI override は v0.1 では設けない。

XDG directory を指定する標準 environment variable のみ `xdg` crate 経由で利用する。

---

## 12.1 Listen

一般的な SSH server と同じく port `22` をデフォルトとする。

```toml
listen = "0.0.0.0:22"
```

bind できなければ明示的な起動エラーとする。

`2222` 等への自動 fallback はしない。

---

## 12.2 authorized_keys

built-in default:

```text
~/.ssh/authorized_keys
```

必要な場合のみ設定ファイルで変更する。

例:

```toml
authorized_keys = "/etc/shbox/authorized_keys"
```

---

## 12.3 host key

built-in default は XDG state directory から算出する。

通常は設定不要とする。

必要性が生じた場合のみ config option として公開する。

---

## 12.4 sandbox root

built-in default:

```text
$XDG_DATA_HOME/shbox/sandboxes/
```

通常は変更不要とする。

Arapuca の運用上 sandbox root の変更が必要になった場合のみ設定項目として追加する。

不要な configuration option を先回りして増やさない。

---

# 13. Project structure

初期段階では単一 crate とする。

```text
shbox/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── server.rs
│   ├── session.rs
│   ├── sandbox.rs
│   ├── arapuca.rs
│   └── auth.rs
└── tests/
    └── ssh.rs
```

最初から workspace 化しない。

巨大な `error.rs` も作らない。

---

# 14. Module responsibilities

## `main.rs`

- usage-rs による CLI parsing
- xdg initialization
- configuration load
- tracing initialization
- Tokio runtime
- host initialization
- SSH server startup
- graceful shutdown
- startup error の最終表示

---

## `config.rs`

- `xdg` crate を使った config path 解決
- config.toml 読み込み
- defaults 適用
- validation

XDG environment variable を直接解釈するコードは書かない。

---

## `server.rs`

- russh server
- SSH connection acceptance
- authentication
- connection lifecycle

---

## `session.rs`

- SSH channel state
- `pty-req`
- `shell`
- `exec`
- `window-change`
- `subsystem`
- channel data
- EOF
- close
- exit status

---

## `sandbox.rs`

- `SandboxId`
- ID validation
- sandbox path
- sandbox lifecycle
- get-or-create
- list
- delete
- concurrency control

---

## `arapuca.rs`

Arapuca 固有処理をまとめる。

- sandbox creation
- sandbox lookup
- listing
- deletion
- process spawn
- PTY spawn
- PTY resize
- workload termination

russh 固有コードと Arapuca 固有コードを不必要に混在させない。

---

## `auth.rs`

- authorized_keys 読み込み
- public key authentication

username ごとの OS account lookup は行わない。

---

# 15. Arapuca integration

Arapuca backend 用の巨大な abstraction framework は作らない。

必要な operation は概念的に以下程度。

```text
get_or_create(id)
list()
delete(id)
spawn(...)
spawn_pty(...)
resize(...)
```

実際の Arapuca API が十分なら concrete type をそのまま利用する。

最初から trait を作る必要はない。

sandbox path は原則として、

```text
$XDG_DATA_HOME/shbox/sandboxes/<id>
```

を基準とする。

Arapuca が別の内部構造を要求する場合でも、可能な限り XDG data directory 配下へ収める。

---

# 16. Sandbox list の source of truth

`list` のためだけに別 metadata database を作らない。

以下のいずれかを authoritative source とする。

1. Arapuca 自身が提供する sandbox 列挙機能
2. `$XDG_DATA_HOME/shbox/sandboxes/<id>` の存在

Arapuca が正確な列挙機能を提供するならそれを優先する。

filesystem と別 metadata を二重管理しない。

---

# 17. Exec implementation

最初に interactive shell より `exec` を実装する。

理由:

- PTY 固有処理が少ない
- sandbox lifecycle を先に確認できる
- process spawn を独立して検証できる
- stdin / stdout / stderr を先に確立できる
- exit status semantics を確認できる

実装対象:

- SSH exec request
- command execution
- stdin forwarding
- stdout forwarding
- stderr forwarding
- EOF
- exit status
- client disconnect

command string の実行方法は OpenSSH の一般的な remote command semantics に近づける。

実際に shell を介するかは Arapuca の process API を踏まえて決定する。

---

# 18. Interactive shell / PTY

対応する SSH request:

- `pty-req`
- `shell`
- `window-change`
- channel data
- EOF
- close

PTY request から受け取るもの:

- terminal type
- columns
- rows
- pixel width
- pixel height
- terminal modes

実際に必要な値のみ backend PTY に反映する。

---

# 19. Terminal resize

SSH 標準の `window-change` をそのまま利用する。

```text
client resize
    ↓
SSH window-change
    ↓
shbox
    ↓
Arapuca / PTY resize
```

独自 resize protocol は作らない。

---

# 20. Signal handling

interactive PTY では client input を基本的にそのまま PTY へ流す。

例えば Ctrl-C:

```text
0x03
 ↓
PTY line discipline
 ↓
SIGINT
```

Ctrl-C 用の独自 protocol 処理は不要。

SSH `signal` request については、exec process に自然に転送できる場合に対応する。

---

# 21. Subsystems

v0.1 の subsystem は2つだけ。

```text
list
delete
```

未知の subsystem は拒否する。

---

## `list`

- username は無視
- sandbox 一覧を取得
- bytewise sort
- plain text
- exit status を返す

---

## `delete`

- username を sandbox ID とする
- ID validation
- workload を終了
- Arapuca sandbox を削除
- sandbox data を削除
- exit status を返す

---

# 22. Concurrency

同一 sandbox への複数同時アクセスを正式にサポートする。

考慮する race:

```text
attach || attach
exec   || exec
attach || exec
attach || delete
exec   || delete
create || create
create || delete
list   || create
list   || delete
```

`get_or_create(id)` は外部から atomic に見える必要がある。

同一 ID の sandbox が同時 create で二重生成されてはならない。

Arapuca が atomic primitive を持つならそれを優先する。

不足する場合のみ shbox 側で最小限の同期を追加する。

---

# 23. Delete semantics

sandbox 削除時には以下を対象とする。

- interactive shell
- PTY
- exec process
- active SSH channel
- Arapuca sandbox resource
- `$XDG_DATA_HOME/shbox/sandboxes/<id>` の永続データ

削除後、同じ ID に shell / exec が来れば新しい sandbox として lazy create する。

SSH connection 全体を閉じるか対象 channel のみ閉じるかは russh の channel model に合わせ、必要最小限の範囲を閉じる。

---

# 24. Error / panic 方針

## 24.1 基本原則

失敗を3種類に分類する。

```text
普通に起こり得る operational failure
    → 通常エラー

remote client から普通に発生し得る event
    → SSH protocol semantics で処理

内部 invariant が成立していれば起こらない
    → panic
```

---

## 24.2 通常エラー

以下は panic させない。

- config syntax error
- 不正な設定値
- port bind failure
- permission denied
- authorized_keys 読み込み失敗
- host key 読み込み失敗
- host key 保存失敗
- XDG directory 作成失敗
- sandbox data directory 作成失敗
- sandbox data 削除失敗
- disk full
- file descriptor exhaustion
- socket/resource 不足
- Arapuca 初期化に必要な環境条件不足

適切な stderr を出し、必要なら non-zero exit とする。

自動 fallback で隠さない。

---

## 24.3 SSH 上の通常イベント

以下は server panic の対象にしない。

- authentication failure
- client disconnect
- connection reset
- EOF
- channel close
- invalid sandbox ID
- malformed request
- unsupported request
- unknown subsystem

remote client の入力だけで server process 全体を panic させられないようにする。

---

## 24.4 Panic

panic は internal invariant violation に限定する。

例:

- validation 済み `SandboxId` が invalid state になった
- state machine 上 unreachable な状態
- resource ownership の内部前提が壊れた
- concurrency control 上不可能な重複状態
- コード上必ず存在すると保証された値が存在しない

この場合は無理に Error 型へ変換せず、その場で panic する。

backtrace から発生位置を追跡できることを優先する。

---

## 24.5 Error abstraction

使用しない:

- `anyhow`
- 巨大な `ShboxError`
- 外部 error を何層も包む wrapper

`thiserror` も初期実装では使用しない。

独自 error type は、shbox の仕様として明確に説明できるものが実際に必要な場合だけ作る。

エラーを単に上へバケツリレーするための Error hierarchy は作らない。

---

# 25. Logging

`tracing` を使用する。

記録候補:

- server startup / shutdown
- SSH connection start / end
- authentication result
- sandbox create
- sandbox delete
- shell start / end
- exec start / end
- subsystem invocation
- operational error

記録しないもの:

- terminal input
- stdin 内容
- private key
- secret
- 不要な authorized key 詳細

command string についても無条件には保存しない。

---

# 26. Test 方針

実際の OpenSSH client を使った integration test を重視する。

---

## 26.1 Exec

```console
ssh dev@127.0.0.1 'printf hello'
```

確認:

- sandbox lazy creation
- stdout
- stderr
- stdin
- exit status

---

## 26.2 Sandbox persistence

sandbox 作成後、

```text
$XDG_DATA_HOME/shbox/sandboxes/dev/
```

に対応する永続データが存在することを確認する。

SSH disconnect 後も残ることを確認する。

---

## 26.3 List

```console
ssh -s 127.0.0.1 list
```

確認:

- 1行1 ID
- sorting
- empty output
- exit status
- username が sandbox として作成されない

---

## 26.4 Delete

```console
ssh -s dev@127.0.0.1 delete
```

確認:

- sandbox が削除される
- workload が終了する
- XDG data 上の sandbox data が削除される
- list から消える
- 再接続すると新規作成される

---

## 26.5 Interactive shell

```console
ssh -tt dev@127.0.0.1
```

確認:

- shell startup
- input/output
- EOF
- disconnect
- PTY cleanup
- sandbox persistence

---

## 26.6 Resize

terminal size の変更が PTY に反映されることを確認する。

---

## 26.7 Concurrent access

同一 sandbox への複数接続で、

- independent PTY
- shared sandbox
- concurrent exec

が成立することを確認する。

---

## 26.8 Delete during connection

接続中 sandbox を削除して、

- workload 終了
- PTY cleanup
- sandbox data 削除
- server process 継続

を確認する。

---

## 26.9 Operational errors

以下が panic にならないことを確認する。

- malformed config
- port already in use
- unreadable authorized_keys
- unwritable host key destination
- unwritable XDG data directory

---

## 26.10 Hostile / malformed SSH input

以下で server 全体が panic しないことを確認する。

- invalid sandbox ID
- unknown subsystem
- unsupported request
- abrupt disconnect
- malformed protocol input

---

# 27. 実装順序

## Phase 1: Project skeleton

- Cargo project
- dependency 最小化
- `usage-rs`
- `xdg`
- tracing
- Tokio runtime
- module skeleton

---

## Phase 2: XDG / configuration / host initialization

- `xdg::BaseDirectories`
- config path 解決
- data path 解決
- state path 解決
- config.toml load
- built-in defaults
- config validation
- sandbox root preparation
- host key load / generation
- authorized_keys load
- operational error reporting

---

## Phase 3: russh server / authentication

- SSH listen
- connection handling
- public key authentication
- username 取得
- protocol-level failure handling

---

## Phase 4: Arapuca integration

- `SandboxId`
- ID validation
- sandbox path resolution
- sandbox existence
- create
- get-or-create
- list
- delete
- process spawn

---

## Phase 5: Exec

- exec request
- command spawn
- stdin
- stdout
- stderr
- EOF
- exit status
- disconnect

---

## Phase 6: Interactive shell / PTY

- pty-req
- shell request
- PTY spawn
- SSH ↔ PTY bridge
- channel lifecycle

---

## Phase 7: Terminal details

- window-change
- PTY resize
- 必要な terminal modes
- signal forwarding の必要範囲

---

## Phase 8: Subsystems

- `list`
- `delete`
- unknown subsystem rejection

---

## Phase 9: Concurrency / lifecycle

- atomic get-or-create
- simultaneous attach
- simultaneous exec
- attach/delete race
- create/delete race
- filesystem / Arapuca consistency
- cleanup

---

## Phase 10: Integration tests

- OpenSSH based tests
- XDG layout
- exec
- shell
- PTY
- resize
- list
- delete
- concurrency
- operational error
- malformed input

---

# 28. v0.1 完成条件

```text
[ ] shbox 単体実行で SSH server を起動できる

[ ] CLI parser に usage-rs を使用する
[ ] CLI に server configuration option を持たない
[ ] CLI subcommand を持たない

[ ] XDG path 解決に xdg crate を使用する
[ ] XDG path を自前で再実装しない

[ ] config.toml を XDG_CONFIG_HOME/shbox/ から読む
[ ] config.toml がなくても built-in default で起動する

[ ] sandbox を XDG_DATA_HOME/shbox/sandboxes/ に保存する
[ ] SSH disconnect で sandbox data を削除しない
[ ] delete で sandbox data を削除する

[ ] host key を XDG_STATE_HOME/shbox/ に保持する
[ ] host key がなければ生成する

[ ] port 22 をデフォルトとして利用する
[ ] ~/.ssh/authorized_keys をデフォルトとして利用する

[ ] public key authentication が動作する
[ ] username を sandbox ID として扱う

[ ] sandbox を lazy create できる
[ ] 既存 sandbox を再利用できる

[ ] exec request が動作する
[ ] stdin/stdout/stderr が正しく転送される
[ ] exit status を正しく返す

[ ] interactive shell が動作する
[ ] connection/channel ごとに disposable PTY を作成できる
[ ] PTY resize が動作する

[ ] 同一 sandbox に複数同時接続できる

[ ] subsystem list が動作する
[ ] list では username を無視する

[ ] subsystem delete が動作する
[ ] delete 時に対象 workload を終了する
[ ] delete 時に sandbox data を削除する

[ ] lifecycle race に耐える
[ ] Arapuca state と filesystem state を不整合にしない

[ ] operational error を panic させない
[ ] remote input による通常異常で server 全体を panic させない
[ ] internal invariant violation は panic する

[ ] anyhow を使用しない
[ ] thiserror を不要に導入しない
[ ] 巨大な統合 Error 型を持たない

[ ] OpenSSH client を利用した integration test が通る

[ ] HTTP server を持たない
[ ] WebSocket server を持たない
[ ] 専用 client CLI を必要としない
```

---

# 29. 非目標

v0.1 では以下を実装しない。

- HTTP API
- REST API
- WebSocket API
- Web UI
- browser terminal protocol
- 専用 client CLI
- CLI 管理サブコマンド
- persistent terminal session
- terminal replay
- scrollback storage
- terminal multiplexer 固有対応
- default sandbox
- random sandbox ID 自動生成
- reserved username
- container backend
- backend selector
- Kubernetes integration
- VM orchestration
- OIDC
- Cloudflare Access integration
- multi-node scheduling
- sandbox migration
- resource billing
- `doctor`
- `setup`
- service installation
- systemd 管理機能

---

# 30. 最終原則

`shbox` は、

**標準 SSH interface を Arapuca sandbox に接続する、小さく予測可能な Rust daemon**

として維持する。

新しい機能を追加するときは、以下の順序で判断する。

1. SSH 標準機能で表現できないか
2. Arapuca の primitive をそのまま利用できないか
3. Rust / OS の標準機能で十分ではないか
4. XDG の既存 semantics に自然に配置できないか
5. 新しい abstraction が本当に必要か
6. 新しい dependency が本当に必要か
7. 独自 protocol / client が本当に必要か

エラー処理は、

```text
普通に起こる
    → 通常エラー

remote input として起こる
    → SSH protocol として処理

起こるはずがない
    → panic
```

を基本とする。

実装全体を通じて、抽象化・設定・依存関係・独自 protocol を先回りして増やさず、必要なものだけを追加する。