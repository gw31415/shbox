# shbox v0.1 の実装

これは shbox v0.1 のアクティブな rolling execution plan です。未完了の実装作業だけを記載
しています。実装者は、設計インタビューをやり直さなくても、このファイルと現在の working tree
から作業を再開できなければなりません。

規範となるプロダクト仕様は [docs/README.md](docs/README.md) に索引されています。この plan が
それらの文書と矛盾する場合は、実装前に plan を修正してください。仕様を黙って変更しては
なりません。

## 目的と観測可能な成果

認証済みの鍵が、通常の OpenSSH コマンドを通じて永続 sandbox workspace を遅延作成し、利用できる
foreground Rust SSH daemon を提供します。通常の鍵は、その鍵が所有する sandbox だけを参照・操作
できます。設定された admin key はすべての sandbox を操作でき、予約済み username _ を使って
緊急時の host shell または remote command を実行できます。各 sandbox の shell/exec は使い捨ての
Arapuca process であり、切断しても永続 workspace は削除されません。

成果は、次のようなコマンドで観測できます。

```console
ssh dev@host
ssh dev@host 'cargo test'
ssh -s host list
ssh -s dev@host delete
ssh _@host
ssh -s _@host list
```

必要なクライアントは OpenSSH client だけです。HTTP/WebSocket service、management CLI、backend
selector、installer、永続 terminal session はありません。

## 現在の状態

- Milestone 1 から Milestone 7 までは完了し、各検証証跡ごと git history に archive 済みである。
  stable 1.97 と MSRV 1.91 の両方で fmt / clippy (`-D warnings`) /
  `cargo test --locked --all-targets` が通り、OpenSSH harness は 21 test を通過する。M8 の
  real Arapuca 6 test は明示的な integration gate で実行する。
- Cargo.lock に重要 dependency が固定されて記録されている: arapuca 0.2.7 git rev
  `c94802c4d8b6b880334c0d643b16b7326ec7f039`、russh 0.63.1 (default-features 無効 + `ring`
  backend)、usage-rs 6.5.0、xdg 3.0.0。russh 経由の鍵生成は ssh-key 0.7.0-rc.11 と
  rand 0.10 (`rand::rng()`) に依存する。
- src/ の現状: `main.rs` は validated snapshot と process-lifetime Arapuca adapter を
  組み立て、実際の russh listener を SIGINT/SIGTERM まで serve する。`auth.rs` は bounded な Ed25519 authorized_keys parser、
  ownership-safe file validation、connection-scoped Principal を持つ。`server.rs` は
  concurrent connection handling、handshake/auth timeout、connection/auth caps、
  all-or-nothing bind を持つ。`ssh/` は session channel、admin-only `_` host shell/exec/PTY、
  generic unavailable な未接続 request と request rejection を実装済み。`sandbox/` は
  v1 metadata、fd-relative no-follow storage、owner/count admission、Active/Deleting
  lifecycle、filtered list/delete、startup reconciliation、manager-owned runtime launcher seam、
  per-launch lease を持つ。`ssh/` は manager-backed list/delete と bounded sandbox stream
  bridge を持ち、`main.rs` は sandbox-only mode では bind 前に registry を scan/reconcile し、
  managed mode では認可済み recovery route を先に公開した上で background reconciliation を
  fail-closed readiness として完了させる。`main.rs` と `server.rs` は validated SIGHUP reload、
  graceful/forced shutdown、dynamic caps、host task registry を実装し、既存の process/connection
  を新しい低い cap だけで evict しない。
  `platform/arapuca.rs` は pinned runtime の profile/env mapping、unique task lease、owned
  non-PTY pipes、daemon-owned spawn lock、private Linux cgroup child、process-group kill、
  blocking wait と cleanup を実装する。manager は workspace delete 前の runtime reap/cleanup
  barrier を持つ。
  `config.rs`、`paths.rs`、`lockfile.rs`、`hostkey.rs`、`account.rs`、`logging.rs`、
  `sandbox/id.rs`、`platform/mod.rs` は引き続き各 domain の基盤である。
- M5--M7 の formal platform acceptance は、外部の Arapuca wrapper と Linux の delegated
  cgroup child 作成権限が必要なため、現 macOS 開発環境では fail-closed が観測された状態で
  ある。wrapper を含む実行環境での full exec/environment/network/descendant evidence は
  M8 の release gate に残る。M7 の reload、shutdown、recovery、dynamic limits、hostile
  concurrency 実装と local suite は完了している。
- 実装時に判明した依存の挙動: `xdg` 3.0.0 の `BaseDirectories::with_prefix` は
  `get_*_home()` の戻り値に既に prefix を付けるため、`Paths::from_roots` は
  shbox-scoped root を受ける。usage-rs の `Cli` derive は `parse()` 自体が process
  entry であり、`--help`/`--version` はその中で処理される。CLI の説明文は `Args` の
  doc comment から生成される。
- Arapuca の公開 API は `Profile`、`Config`、`Process`、`sanitize_task_id`、`platform::Sandbox`
  trait まで adapter で compile/検証済みである。実 runtime の platform acceptance は M8
  の dedicated environment gate に残る。

以下のすべてのコマンドは、repository root で実行します。

```text
/Users/ama/shbox
```

## 固定制約

- Rust MSRV は 1.91 です。CI は MSRV と current stable をテストしなければなりません。
- russh は 0.63.1 に厳密固定します。GHSA-m65r-rprj-r5rg を跨いで downgrade しては
  なりません。
- Arapuca は full revision
  c94802c4d8b6b880334c0d643b16b7326ec7f039 に固定した Git dependency です。package version は
  0.2.7 のままです。この両方の事実を記録します。
- usage-rs は subcommand のない shbox CLI のため 6.5.0 に、xdg は XDG path resolution
  のため 3.0.0 に固定します。
- 対応 target は Unix です。Linux x86_64/aarch64 および macOS arm64 を、blocking
  platform suite の対象とします。Windows は対応しません。
- Arapuca の profile/cgroup/seccomp field を直接公開しません。Config には shbox の domain
  concept を入れます。
- anyhow、public backend plugin API、filesystem trait、monolithic global error enum は導入
  しません。デフォルトでは thiserror も追加せず、まず小さな module-local error type と
  source chain を優先します。具体的に同じ boilerplate が繰り返され、それを減らす理由がある
  場合に限り derive dependency を追加します。
- v0.1 は一つの package/crate のままにします。先回りして repository を Cargo workspace に
  変換しません。
- 無関係な working-tree の変更を保持します。untracked であることだけを理由に file を
  破棄・再生成してはなりません。

## アーキテクチャの方向づけ

deep Module は [docs/architecture.md](docs/architecture.md) に記載する SandboxManager です。
metadata、ownership check、per-ID state、workspace path、process admission、runtime cleanup、
list、delete、startup reconciliation を所有します。SSH handler は小さな Interface だけを呼び、
on-disk layout や Arapuca type を知りません。

ProcessLauncher は crate-private な test Seam です。production Adapter は Arapuca と OS の
PTY/ioctl/process-group operation を包みます。fault Adapter は deterministic な barrier、output、
exit、delay、failure injection を提供します。これは設定可能な backend ではありません。

storage の test には実際の temporary XDG tree を使います。filesystem を抽象化しません。
SandboxId、key fingerprint、selector、principal、metadata state、connection ID、channel ID
には validated domain type を使います。raw remote string を path operation に到達させては
なりません。

## 進捗

- [x] Milestone 4 — deterministic launcher による SSH request semantics
- [x] Milestone 5 — production Arapuca non-PTY process Adapter
- [x] Milestone 6 — PTY、terminal modes、resize、signals、bounded bridging
- [x] Milestone 7 — recovery、reload、shutdown、limits、hostile concurrency
- [ ] Milestone 8 — real-platform release gates と operational examples

milestone は、proof を実行し、ユーザーから観測可能な結果が仕様と一致した後にだけ完了に
してください。作業が uncommitted の間は、実際の command/result を記録します。commit が
求められた場合は、repository の commit skill で検証済みの完了コンテキストを archive してから、
未完了作業と現在の制約だけが残るようにこの plan を compact します。

## Milestone 8 — real-platform release gates と operational examples

M8 の workflow、fail-closed platform scripts、real OpenSSH cases、運用 artifact、release
runbook の実装は完了した。formal support の宣言は、下記の未完了 tuple の hosted blocking
evidence が揃うまで行わない。

### 実装済み

- `.github/workflows/m8-release-gate.yml` が Rust 1.91/stable quality、supported target build、
  delegated Linux、固定 macOS 15/26 runner を実行する。
- `scripts/verify-linux-platform` と `scripts/verify-macos-platform` が exact OS/architecture、
  prerequisite、lock pin、pinned Arapuca wrapper build、real suite を fail-closed で検査する。
- `deploy/systemd/shbox.service`、`deploy/launchd/com.example.shbox.plist`、`docs/release.md`
  が dedicated account、cgroup/Seatbelt 制約、未検証状態を記録する。

### 未完了の受入れ

- [ ] 同一 commit の hosted workflow で Rust 1.91 と stable quality job が成功する。
- [ ] Linux x86_64 delegated cgroup v2 上で real suite が成功する。
- [ ] Linux aarch64 delegated cgroup v2 上で real suite が成功する。
- [ ] macOS 15 arm64 fixed runner 上で real suite が成功する。
- [ ] macOS 26 arm64 fixed runner 上で real suite が成功する（local preflight は pass 済みだが formal evidence ではない）。

### 現在の証跡

- 通常の serial OpenSSH harness は `21 passed`。macOS 26.6.2 arm64 の local gate も pinned
  Arapuca、Seatbelt、real suite `21 passed`、gate `PASS` まで確認済み。
- 同一 commit `14a590e` の hosted run
  `33323095132` は stable と Rust 1.91 の quality job が clippy で失敗し、Linux/macOS の
  real-platform jobs は skipped になった。失敗原因は Linux cfg でのみ生きる RAII field の
  dead-code 警告と、Linux の `mode_t` に対する不要な同型 cast であり、working tree で修正済み
  である。修正を follow-up commit に archive してから hosted run を再実行する。
- Linux と macOS 15 の専用 runner、および修正後の同一 commit の hosted workflow log は未取得である。
- 上記が完了するまで M8 と release status は `[ ]` / `BLOCKED — UNVERIFIED` のままにする。

## milestone 横断の受け入れ条件

v0.1 の完了を宣言する前に、コード inspection だけでなく観測可能な test によって次をすべて
検証します。

- [docs/security.md](docs/security.md) に記載した exact authentication/authorization matrix。
- [docs/ssh-protocol.md](docs/ssh-protocol.md) に記載した shell/exec/list/delete、PTY/non-PTY
  stream、signal、EOF、exit、channel ordering。
- [docs/architecture.md](docs/architecture.md) に記載した atomic owner claim、filtered list、
  durable Deleting recovery、safe deletion、cross-ID blocking がないこと。
- [docs/configuration.md](docs/configuration.md) に記載したすべての default、validation rule、
  reload boundary、cap。
- [docs/platforms.md](docs/platforms.md) に記載した Linux/macOS isolation mapping、dedicated
  cgroup requirement、pin した macOS fix、network mode、support gate。
- command text、terminal content、private key、sandbox file content、secret environment value
  が log に出力されないこと。
- remote/operational error が daemon-wide panic を起こさず、所有 operation が終了した後に
  process/PTY/channel task leak がないこと。

## 冪等性、retry、rollback、cleanup

- test は temporary XDG root と test-specific listener に対してだけ実行します。operator の
  実際の ~/.local/share/shbox や port 22 を test の対象にしてはなりません。
- metadata write と delete recovery は、すべての fault point で idempotent でなければなりません。
  startup または delete の再実行は進行してよいですが、owner を変更したり data を復活させたり
  してはなりません。
- milestone が失敗した場合は、その milestone で意図的に変更した file だけを revert するか
  forward に修復します。無関係な user change を reset してはなりません。古い binary を使って
  unknown metadata を migrate または rewrite してはなりません。
- すべての test daemon/process group を kill し、harness が割り当てた exact temporary
  directory だけを削除します。path が表示され、secret を含まない場合に限り failed-test
  artifact を保持します。
- dependency upgrade、特に Arapuca/russh は、別途 review する change です。compile と完全な
  formal-platform suite が成功するまでは old lockfile を利用可能な状態に保ちます。
- deleted sandbox data の automatic rollback はありません。test は disposable workspace を
  使い、必要なら operator が external backup を手配します。

## proof で解消すべき既知の実装リスク

- pin した Arapuca revision は unreleased commit で、package version はまだ 0.2.7 です。
  `platform/arapuca.rs` が `Config` と `Process` を組み立てますが、wrapper と formal
  platform environment がない開発環境では実 process behavior を成功扱いにしません。
- Arapuca の effective HOME override order は、comments と衝突する implementation behavior
  です。使用可能と扱う前に、Linux と macOS の environment integration test が必須です。
- macOS Seatbelt は deprecated であり、upstream の public CI は各 named OS version の raw PTY
  behavior を証明しません。shbox 自身の pinned-version integration job が evidence です。
- Arapuca は Linux の cgroup scope を discover・mutate し、startup stale cleanup を実行します。
  dedicated delegated scope を shbox が検証した後にだけ、一度だけ構築します。
- Arapuca は blocking wait と lifetime-bound PTY descriptor を公開します。ownership と
  blocking-task test で、Process も cleanup responsibility も早期に drop されないことを
  証明しなければなりません。
- 固定 Arapuca revision は target spawn 後にしか PTY master を caller へ返しません。v0.1 の
  post-launch size/mode 適用には target startup との race が残ります。pre-exec guarantee を
  必要とする場合は、将来 Arapuca API extension または監査済み child launcher を別設計として
  採用し、契約と formal-platform suite を更新します。
- port 22 には通常、external privilege/capability setup が必要です。shbox は bind failure
  を明示し、fallback port を決して選んではなりません。
