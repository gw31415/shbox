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

- リポジトリは単一の Rust package、shbox version 0.1.0、edition 2024 です。
- src/main.rs はまだ生成された Hello, world! プログラムです。
- Cargo.toml に依存関係はありません。
- docs/ 以下の仕様が実装契約です。
- Cargo.lock はローカルにすでに存在する場合があります。Milestone 1 で意図的に再生成して
  検証するまでは、ユーザーの作業として扱ってください。最終 application repository では
  lockfile を追跡対象にします。
- 実装、test harness、CI workflow、deployment example、release artifact はまだありません。

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

- [ ] Milestone 1 — package foundation、typed configuration、process bootstrap
- [ ] Milestone 2 — public-key SSH server と admin host route
- [ ] Milestone 3 — durable SandboxManager storage と ownership
- [ ] Milestone 4 — deterministic launcher による SSH request semantics
- [ ] Milestone 5 — production Arapuca non-PTY process Adapter
- [ ] Milestone 6 — PTY、terminal modes、resize、signals、bounded bridging
- [ ] Milestone 7 — recovery、reload、shutdown、limits、hostile concurrency
- [ ] Milestone 8 — real-platform release gates と operational examples

milestone は、proof を実行し、ユーザーから観測可能な結果が仕様と一致した後にだけ完了に
してください。作業が uncommitted の間は、実際の command/result を記録します。commit が
求められた場合は、repository の commit skill で検証済みの完了コンテキストを archive してから、
未完了作業と現在の制約だけが残るようにこの plan を compact します。

## Milestone 1 — package foundation、typed configuration、process bootstrap

### 目標

shbox、shbox --help、shbox --version が動作し、SSH connection をまだ受け付けずに、
startup がすべての local input を解決・検証します。無効な state は sandbox process を一つも
開始する前に失敗しなければなりません。

### 編集内容

1. src/main.rs を Tokio foreground bootstrap と小さな signal loop に置き換えます。
2. [docs/configuration.md](docs/configuration.md) の exact schema に従う src/config.rs を追加
   します。built-in defaults、optional TOML、deny_unknown_fields、absolute-path validation、
   duplicate detection、field-size limits、immutable runtime snapshots を実装します。
3. XDG path resolution と安全な directory creation を追加します。config/data/state path は
   validated な Paths value に保持し、標準 XDG variable 以外の CLI/env override は追加
   しません。
4. UTC RFC 3339 timestamp と動的 log-level reload を備えた structured tracing initialization
   を追加します。
5. Ed25519 host-key の load/atomic-create と permission check を追加します。さらに
   `$XDG_DATA_HOME/shbox/registry.lock` と `$XDG_STATE_HOME/shbox/lock` をこの順で
   non-blocking に取得し、同じ data root または state root の二重 daemon を拒否します。
6. 重要な dependency を厳密宣言します。Arapuca を full rev で pin し、文書化した
   russh crypto backend を一つ有効にし、その後 Cargo.lock を意図的に再生成して追跡します。
7. configuration、SandboxId grammar、path validation、limits、environment name/value、fingerprint
   syntax、missing config、unsafe permissions の unit/property test を追加します。

### 成果

- 引数なしで initialization が開始します。subcommand や server-setting flag はありません。
- missing config では built-in defaults を使います。malformed config、missing/empty authorized
  keys、unsafe file permissions、corrupt host key、duplicate data/state daemon lock、bind できない
  configured path は明示的なエラーになります。同じ data root と別 state/listener、および
  同じ state root と別 data/listener の第二 daemon も拒否します。
- missing host key は mode 0600 で atomic に作成します。既存の invalid key は決して置換
  しません。

### 検証

実行:

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked config
cargo run --locked -- --help
cargo run --locked -- --version
```

期待結果: すべての check が Rust 1.91 と stable で通ること。help には -h/--help と
-V/--version だけが表示されること。property test が、非 ASCII、slash、dot、underscore、
leading hyphen、empty、overlong なすべての SandboxId を拒否すること。

## Milestone 2 — public-key SSH server と admin host route

### 目標

OpenSSH client が authorized Ed25519 key で認証できます。通常ユーザーは host へ escape
できず、admin は _ を使って daemon-account の login shell または remote command を実行
できます。sandbox request は、後の milestone まで意図した unavailable response を返しても
構いません。

### 編集内容

1. bounded な OpenSSH authorized-keys subset を parse し、SHA-256 fingerprint を計算し、
   admin_keys を検証して、auth_publickey からだけ connection-scoped Principal を生成する
   src/auth.rs を追加します。auth_publickey_offered は決して使いません。
2. public-key-only の russh::server::Config、Ed25519 host key、handshake/auth timeout、
   auth-attempt/connection caps、all-or-nothing listener binding を備えた src/server.rs を
   追加します。
3. src/ssh/ の下に per-connection/per-channel state を追加します。session channel だけを
   accept し、forwarding、agent、X11、streamlocal、SFTP、client environment、その他すべての
   unused request を reject します。
4. _ の authorization と host shell/exec/PTY spawning を実装します。daemon account の login
   shell、その account home を cwd、既存の HOME を含む daemon service environment 全体、
   daemon uid/gid を使います。interactive shell は login mode、remote command は同じ shell
   と -c を使います。
5. role と auth/config snapshot を connection-scoped に保ちます。複数 channel は principal を
  共有しますが、request/PTY/process state は独立して保持します。
6. 生成した Ed25519 key を使い、accepted/rejected role/username pair と confirmed session
   channel より前に受信した channel request をテストします。

### 成果

- ssh _@host と ssh _@host command は admin key だけで動作します。
- 通常の authorized key が _ を使った場合、および none/password/keyboard-interactive
  authentication はすべて、role や key-set を漏らさず失敗します。
- 既存の authenticated connection は切断まで自身の role を保持します。

### 検証

isolated test config/listener を使い、repository integration harness と直接 OpenSSH を実行:

```console
cargo test --locked --test ssh_auth -- --test-threads=1
ssh -F tests/fixtures/ssh_config _@127.0.0.1 'printf host-ok'
```

期待結果: admin command は正確に host-ok を出力して exit 0。normal key で同じ command は
reject。forwarding と env request は reject。reject された channel が connection 上の他の
channel を終了させないこと。

## Milestone 3 — durable SandboxManager storage と ownership

### 目標

Arapuca なしで、persistent metadata/workspace の atomic な first-owner-wins creation、filtered
list、idempotent delete、corruption blocking、crash-resumable な Deleting state を実装します。

### 編集内容

1. src/sandbox/ の下に validated domain type と v1 metadata parser/serializer を追加します。
2. safe no-follow/open-at-style storage operation、明示的 mode、atomic file
   fsync/rename/parent-fsync、sandbox root の外へ cross できない deletion を実装します。
3. keyed lock、atomic owner/count reservation、Active/Deleting admission、filtered sorted list、
   runtime registry placeholder を備えた SandboxManager を実装します。
4. startup scan を実装します。valid Active record を load し、Deleting record を resume し、
   missing/corrupt/unknown-version management entry は block しますが決して mutate しません。
   owner/admin の再 delete は保存済み owner fingerprint で認可し、state を再書込みせず
   Deleting cleanup を再開します。startup reconciliation は caller 無しで durable intent を
   再開します。
5. private な ProcessLauncher Seam と deterministic fake Adapter を実装します。
6. 二つの key による一つの ID の claim、create-vs-delete、delete-vs-launch、異なる二つの ID、
   count reservation、transition 中の list の barrier-driven race を追加します。
7. すべての durable write/rename/fsync/delete step の周囲に fault point を追加し、各 injected
   failure の後に manager を restart します。

### 成果

- 一つの fingerprint だけが ID を所有します。losing key は foreign sandbox の存在と
  absent/inaccessible target を区別できません。
- claim 後の launch failure では、owner/workspace が retry 用に残ります。
- Deleting entry は隠され、deletion 完了まで launch を block します。
- corrupt entry は ID を block し、admin/out-of-band inspection 用に残ります。

### 検証

```console
cargo test --locked sandbox::
cargo test --locked --test lifecycle_races -- --test-threads=1
cargo test --locked --test crash_recovery -- --test-threads=1
```

期待結果: deterministic race test が繰り返し通ること。各 simulated crash の後、registry が
指定された recoverable state のいずれかになること。hostile symlink と special file が、
temporary XDG root の外で read/delete を発生させないこと。

## Milestone 4 — deterministic launcher による SSH request semantics

### 目標

OS process の複雑さを導入する前に、fake launcher を使って、すべての user-visible SSH
shell/exec/list/delete semantics、stream、exit notification、role filtering、capacity limit、
channel isolation を動作させます。

### 編集内容

1. session handler を小さな Interface だけを通じて SandboxManager に接続します。
2. channel ごとに terminal operation を一つだけ実装します。shell、exec、subsystem のいずれか
   が成功した channel では、後続の terminal operation を fail させます。先行する PTY request
   は channel state になります。
3. non-PTY の stdin/stdout/stderr を実装し、stderr は SSH extended data type 1 にします。
   PTY は一つの terminal stream とします。
4. client EOF 後は既受信入力を drain し、新しい入力を process へ送りません。fake launcher
   では、non-PTY の stdin pipe close と、PTY の write 側だけを閉じて child EOF を保証しない
   state を別々にモデル化します。いずれも output を drain し、指定された順序で EOF、
   exit-status または exit-signal、close を送信します。PTY に `VEOF` byte を合成しません。
5. exact な list と delete subsystem behavior を実装します。list は admin の全 sandbox
   list に _ を受け付けます。delete は通常の SandboxId を必要とします。両方とも PTY を
   reject します。
6. request size、channel/process/count、per-owner、global limit を atomic に enforce します。
   bridge queue をすべて bounded にし、backpressure を伝播させます。
7. internal failure を stable な generic client error に map し、command text や terminal I/O
   を log しないようにします。

### 成果

- 通常の list は所有する Active ID だけを返し、admin list はすべての Active ID を ASCII 順で
 返します。
- absent または inaccessible な valid ID を delete すると、output なし・exit 0 になります。
  実際の deletion failure は non-zero です。
- 一つの channel を閉じるとその process だけを kill します。delete は対象 process/channel
  を閉じますが、無関係な sandbox や multiplexed SSH connection 全体には影響しません。

### 検証

```console
cargo test --locked --test ssh_protocol -- --test-threads=1
cargo test --locked --test ssh_concurrency -- --test-threads=1
cargo test --locked --test ssh_backpressure -- --test-threads=1
```

期待結果: byte-for-byte の list output、分離された non-PTY stderr、PTY の merged output、
non-PTY/PTY それぞれの EOF semantics、終了 ordering、exit status/signal、generic failure、
multi-channel isolation が
[docs/ssh-protocol.md](docs/ssh-protocol.md) と一致すること。

## Milestone 5 — production Arapuca non-PTY process Adapter

### 目標

Sandbox exec を、persistent workspace の HOME/cwd、clean environment、read policy、resource
limit、disabled または unrestricted outbound networking、信頼できる wait、完全な process cleanup
を備えた実 Arapuca Process として実行します。

### 編集内容

1. 一つの process-lifetime Arapuca platform instance を包む production Adapter を実装します。
   connection ごと、または SIGHUP 時に再構築してはなりません。
2. Linux では cgroup v2、required delegated controller、wrapper/runtime prerequisite、shbox
   だけを含む dedicated scope を preflight します。scope が shared または invalid なら
   sandbox backend を fail closed にします。
3. validated な shbox policy だけを Arapuca profile へ変換します。workspace write access、
   curated/configured canonical read path、allow-exec、common/platform limit、network mode を
   含めます。raw Arapuca control は private に保ちます。
4. launch ごとに unique な <sandbox-id>-<128-bit-random-hex> task ID を生成し、active lease
   set を維持します。external ID は log/correlation 用に分離して保持します。
5. workspace の HOME、cwd、shell、sanitized global sandbox environment を渡します。pin した
   Arapuca revision が Linux と macOS の両方で最終 environment を実際に提供することを検証
   します。
6. owned pipe で non-PTY stdio を bridge し、blocking な Process::wait() を blocking task で
   実行します。wait と cleanup が完了するまで Process を保持します。
7. process-group termination と Arapuca cleanup を実装し、descendant をテストします。

### 成果

- ssh id@host command は configured sandbox shell を -c 付きで使い、persistent workspace
  home/cwd、分離された stdout/stderr、remote exit status を提供します。
- network = "disabled" は outbound connection を作れません。network = "outbound" は v0.1
  から unrestricted outbound TCP/UDP/DNS をサポートし、isolation posture が低下することを
  log します。
- backend initialization または launch failure が unsandboxed host process へ fallback する
  ことはありません。

### 検証

各 candidate formal platform の、required delegated/service environment 下で:

```console
cargo test --locked --test arapuca_exec -- --test-threads=1
cargo test --locked --test arapuca_environment -- --test-threads=1
cargo test --locked --test arapuca_network -- --test-threads=1
cargo test --locked --test arapuca_cleanup -- --test-threads=1
```

期待結果: workspace file は reconnect/restart 後も残り、process-local state は残らないこと。
disabled networking は fail し、outbound mode は controlled test endpoint に到達すること。
disconnect/delete/shutdown の後に child と descendant の PID が消えること。

## Milestone 6 — PTY、terminal modes、resize、signals、bounded bridging

### 目標

raw mode と process-group cleanup を含め、すべての正式対応 platform で interactive session と
ssh -t session が通常の SSH terminal のように動作します。

### 編集内容

1. Arapuca Process を保持したまま、lifetime-bound な PTY master を read、write、lifecycle
   用に duplicate/own して async I/O に使います。
2. Arapuca が target を spawn して master FD を返した直後、I/O bridge の公開前に、
   rows/columns と RFC 4254 POSIX terminal mode のうち対応するものを適用します。固定
   revision には pre-exec hook がなく、v0.1 は trusted child launcher を導入しないため、
   target の最初の命令より前の反映は保証しません。pixel dimension、RFC が要求する zero
   dimension、unknown terminal mode は ignore します。size/mode 適用に失敗した process は
   cleanup し、部分適用した PTY を client へ公開しません。
3. window-change を desired-size revision と platform PTY-master の TIOCSWINSZ Adapter で
   処理します。PTY 未要求なら無視し、pty-req 後・master 生成前なら state だけを更新し、
   running なら state と ioctl の両方を更新します。launch race では最新 revision の適用後に
   bridge-ready を publish します。Arapuca に resize method があるとは主張しません。
4. 対応する SSH signal name を process group へ translate します。unknown name は reject し、
   通常の Ctrl-C terminal behavior を保持します。
5. interactive shell を login mode で、PTY exec を同じ shell -c contract で実行します。
   PTY output は merged、non-PTY stderr は分離したままにします。
6. macOS の raw-mode tcsetattr/tcgetattr、pin した Seatbelt /dev/ttys* file-ioctl rule、
   /var traversal fix、resize、descendant cleanup を実行します。
7. client EOF では既受信入力を drain して write duplicate だけを閉じ、read/lifecycle
   duplicate を保持します。PTY child の EOF/hangup は保証せず、`VEOF` や `0x04` を合成
   しません。明示 close/disconnect/delete/shutdown は通常の termination contract に従います。

### 成果

- ssh id@host、ssh -t id@host command、full-screen terminal application、resize、
  Ctrl-C、explicit signal request、disconnect cleanup が各 formal target で動作します。
- 一つの slow client が unbounded memory growth を作れません。send failure は process cleanup
  を発生させます。
- bridge 公開後には要求した PTY size/modes を観測できますが、target startup の最初の命令で
  それらを観測できるとは約束しません。

### 検証

```console
cargo test --locked --test pty -- --test-threads=1
cargo test --locked --test pty_raw_mode -- --test-threads=1
cargo test --locked --test pty_resize -- --test-threads=1
cargo test --locked --test pty_signals -- --test-threads=1
```

期待結果: bridge 開始後の controlled program が要求された size/mode と subsequent resize を
観測すること。target の最初の命令で request 値を観測する test は v0.1 の gate にしません。
non-PTY の `cat` は client EOF で終了し、PTY は client EOF で synthetic byte/hangup を受けずに
出力を続けること。macOS で raw mode が成功すること。signal termination が exit-signal を
報告すること。cleanup 後にすべての process-group member が消えること。

## Milestone 7 — recovery、reload、shutdown、limits、hostile concurrency

### 目標

config/key reload、abrupt disconnect、daemon termination、malformed remote request、partial
filesystem failure、maximum concurrency の下でも、完全な daemon が bounded かつ recoverable
であり続けます。

### 編集内容

1. atomic SIGHUP reload を実装します。新しい auth/role snapshot は新規 connection に、新しい
   execution setting は新規 process に適用します。failure が一つでもあれば古い snapshot を
   保持します。listen address は restart-only とします。
2. SIGINT/SIGTERM の graceful shutdown を実装します。admission を停止し、runtime process を
   parallel に terminate し、5 秒待ち、group を force し、log を flush して listener/lock
   を解放します。二回目の signal では直ちに終了します。
3. startup reconciliation と managed-mode の早期 _ access を実装します。sandbox-only mode
   では listener を公開する前に reconciliation を完了しなければなりません。
4. validated snapshot からすべての connection/channel/process/sandbox cap と auth/handshake
   timeout を enforce します。limit が減少しただけで既存 work を evict してはなりません。
5. hostile/malformed SSH test、oversized field test、slow-reader/writer test、disconnect storm、
   repeated reload、backend-unavailable behavior、daemon crash、process descendant escape attempt
   を追加します。
6. operational error が panic しないようにします。明示的な invariant test を追加し、invariant
   panic は location と backtrace を log してから daemon を abort します。未知の state のまま
   継続してはなりません。

### 成果

- reload が partially updated policy を作ることはありません。最後の admin を削除すると
  sandbox-only mode に入り、既存の admin connection は切断まで元の role を保持します。
- resource use は configured cap と bounded queue によって bounded です。
- 対応する crash/disconnect/delete/shutdown case で、指定された cleanup window と platform
  watchdog behavior を超えて workload が実行中のまま残りません。

### 検証

```console
cargo test --locked --all-targets
cargo test --locked --test reload -- --test-threads=1
cargo test --locked --test limits -- --test-threads=1
cargo test --locked --test hostile_ssh -- --test-threads=1
cargo test --locked --test daemon_crash -- --test-threads=1
```

期待結果: suite が繰り返し実行しても flaky にならずに通ること。backpressure case の memory
が bounded であること。daemon を panic/abort で終了させるのは deliberate invariant fixture
だけであること。

## Milestone 8 — real-platform release gates と operational examples

### 目標

full behavior が実証された OS/version/architecture combination だけを ship し、external
prerequisite を安全に満たすために必要な deployment guidance を operator に提供します。

### 編集内容

1. Rust 1.91 と stable の CI を追加します。format、warnings denied の clippy、
   unit/property/state/fake-launcher test、supported target の build check を実行します。
2. blocking な real-platform job、または同等の記録可能な release pipeline を追加します。
   - Linux x86_64、dedicated delegated cgroup v2 scope
   - Linux aarch64、dedicated delegated cgroup v2 scope
   - macOS 15 arm64
   - macOS 26 arm64
3. Milestone 5--7 の real OpenSSH/Arapuca suite を、列挙した各 tuple で実行します。full passing
   run のない tuple は unverified であり、formal に supported ではありません。macOS x86_64
   cross-build は informational only です。
4. dedicated non-root service account、port-22 capability、required な
   Delegate=cpu cpuset memory pids、private state/data、delegated scope 内に無関係な process
   を置かないことを含む Linux systemd unit example を追加します。
5. dedicated service account と deprecated Seatbelt dependency および tested OS version への
   明示的な warning を含む macOS launchd example を追加します。installer/start/stop command
   は追加しません。
6. tracked lockfile と exact git revision から source distribution/build が reproducible である
   ことを検証します。
7. すべての behavior を docs/ と照合し、tested support table を実際の runner image/version
   で更新します。満たされていない condition は contract を黙って弱めず、blocking として
   記録します。

### 成果

- release documentation が exact tested OS version/architecture と Arapuca revision を明記
  します。
- operator は Arapuca の cgroup scope を共有せず、fallback として sandbox process を host
  上で直接実行することもなく、daemon を deploy できます。
- current OpenSSH が compatibility guarantee です。他の RFC 4254 client は best effort の
  ままです。

### 検証

release pipeline は少なくとも次を実行しなければなりません。

```console
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
```

さらに、この milestone で生成した platform script を、例えば次のように実行します。

```console
./scripts/verify-linux-platform
./scripts/verify-macos-platform
```

期待結果: すべての formal tuple が exact OS image、architecture、Rust version、Arapuca
revision、OpenSSH version、passing full suite を報告すること。required tuple が skip、
cross-compile only、または mutable で記録のない image 上で実行された場合は formal-support
claim を公開しません。

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
  abstraction を作る前に、その exact public API を compile します。
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
