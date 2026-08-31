# host認可鍵とsandbox許可鍵の分離 — 実装計画

## 目的

shboxのSSH公開鍵を、権限の由来が明確な二つのファイルへ分離する。

- daemon実行ユーザーの `~/.ssh/authorized_keys` はhost認可鍵である。ここにある鍵はすべて
  `Admin` であり、host selector `_` と全sandboxの操作を許可される。
- `$XDG_CONFIG_HOME/shbox/allowed_keys` はsandbox許可鍵である。ここだけにある鍵は
  `Normal` であり、自分が所有するsandboxだけを利用できる。
- 同じ鍵が両方にある場合は一つのidentityとして扱い、強い権限である `Admin` を付与する。

この変更により、Admin判定を設定中のfingerprint配列や起動時flagから切り離す。
`admin_keys`、TOMLの `authorized_keys`、`--authorized-keys-host-access` は廃止し、
互換aliasや暗黙のfallbackは設けない。

本ファイルは別エージェントへ渡す自己完結した実装計画である。この計画作成時点では実装を
変更しない。対象branchは `feat/cli-config-simplification`、既存PRは #1 である。

## 確定した仕様

### 鍵ファイルと権限

| source | 固定path | 付与するrole | host `_` | sandbox |
| --- | --- | --- | --- | --- |
| host認可鍵 | daemon accountの `~/.ssh/authorized_keys` | `Admin` | 許可 | 全sandboxを管理・利用可能 |
| sandbox許可鍵 | `$XDG_CONFIG_HOME/shbox/allowed_keys` | `Normal` | 拒否 | fingerprintがownerであるsandboxのみ |
| 両方にある鍵 | 上記二つ | `Admin` | 許可 | 全sandboxを管理・利用可能 |

`~` は文字列展開ではなく、現在のdaemon accountのhome directoryから解決する。
host認可鍵のpathはTOMLやCLIで変更できない。`allowed_keys` も `Paths` が導出する固定pathであり、
TOML fieldにはしない。

各sourceは個別には未作成、空、blank/commentのみを許す。ただし二つを合成した結果に有効な鍵が
一つもない場合、起動は失敗する。reload時に合成結果が空になった場合もreload全体を拒否して
以前のsnapshotを維持する。これにより、host Adminが存在しないsandbox-only構成を許しながら、
到達不能なdaemonの起動やreloadによる全identity消失を防ぐ。

### 鍵構文とidentity

両ファイルに同じparserと上限を使う。受理する形式は現在のshboxが採用しているstrictなbare
OpenSSH Ed25519 subsetとする。

```text
ssh-ed25519 <base64> [comment]
```

- 空行と `#` で始まるcomment行は無視する。
- authorized_keys options、certificate、Ed25519以外のalgorithm、malformed UTF-8、
  malformed base64、8 KiBを超える行、1 MiBを超えるファイルはsource全体のerrorとする。
- commentはidentityに含めない。identityは公開鍵bytesから計算した既存の
  `SHA256:<unpadded-base64>` fingerprintである。
- 同一source内のduplicate keyは誤設定としてsource全体を拒否する。
- 二つのsource間の重複は有効であり、duplicate errorにしない。合成後は一件にdeduplicateし、
  `Admin` を優先する。
- 一方でも存在するファイルがmalformedまたはunsafeなら、起動またはreload全体を拒否する。

既存のfile safety契約を両sourceへ適用する。存在するkey fileはdaemon user所有のregular fileで、
symlinkではなく、group/world writableではないこと。直近parentもdaemon user所有のdirectoryで、
symlinkおよびgroup/world writableを拒否すること。上位ancestorにも既存のwrite permission検査を
適用し、最終pathは `O_NOFOLLOW` で開くこと。errorには `authorized_keys` と `allowed_keys` の
どちらが失敗したか、実pathと理由を含める。公開鍵本文や全fingerprint一覧はlogへ出さない。

### 認証snapshotとreload

起動時はTOML、host認可鍵、sandbox許可鍵をすべて検証してから一つのimmutable snapshotを公開する。
`AuthSnapshot` が「受理するfingerprint」と「そのfingerprintのrole」を所有し、SSH connectionは
authentication完了時のprincipalをconnection lifetime中保持する。

SIGHUPでは次を一つのreload単位として読み、すべて成功した場合だけserverへpublishする。

1. `$XDG_CONFIG_HOME/shbox/config.toml`
2. daemon accountの `~/.ssh/authorized_keys`
3. `$XDG_CONFIG_HOME/shbox/allowed_keys`
4. configから導出するsandbox shell/read path/environment policy

どれか一つでもmissing policy違反、permission違反、parse error、空の合成key setになれば、
config・auth・sandbox policyのどの部分もpublishしない。既存connectionは常に旧principalを維持し、
reload後の新規connectionだけが新snapshotを使う。ここでいうatomicは「検証済みsnapshotの
一括publish」であり、二つのfilesystem fileを同時transactionとして読むという意味ではない。
運用者は複数fileを更新し終えてからSIGHUPを送る。

起動時のmanaged/sandbox-only分岐は、設定中の `admin_keys` ではなく初期
`AuthSnapshot::admin_count() > 0` から導出する。SIGHUPでAdmin数が変わっても、process-lifetimeの
backend、listener、startup reconciliation taskを再構築しない。これは現在のreload境界を維持する。

### 廃止するinterface

- TOML `admin_keys`
- TOML `authorized_keys`
- CLI `--authorized-keys-host-access`
- `Config::admin_keys()`、`Config::authorized_keys()`、`Config::managed_mode()`
- `AuthSnapshot` の `all_authorized_keys_admin` stateと、admin fingerprint配列を受け取るload API

`RawConfig` は `serde(deny_unknown_fields)` を維持し、旧 `admin_keys`、旧 `authorized_keys`、
誤ってTOMLへ書いた `allowed_keys` をunknown fieldとしてfail closedにする。CLI parserも旧flagを
unknown optionとしてnon-zero exitにする。help、man page、completion、配備例から旧interfaceを除く。

## 現在の実装からの変更点

現在のbranchでは、単一のauthorized_keys sourceを読み、TOML `admin_keys` のsubsetまたは
`--authorized-keys-host-access` で `Admin` を決めている。以下の順序で変更する。

### 1. path modelを追加する — `src/paths.rs`

- `Paths` に `allowed_keys_file: PathBuf` を追加する。
- `Paths::from_roots()` で `config_dir.join("allowed_keys")` を設定する。
- `Paths::allowed_keys_file(&self) -> &Path` を公開する。
- module-level XDG layoutとpath unit testを更新する。
- `Paths::ensure()` が作るconfig directoryのowner/mode契約を変えない。

### 2. config schemaから認証authorityを除く — `src/config.rs`

- `Config` と `RawConfig` から `authorized_keys` と `admin_keys` を削除する。
- 上記fieldのgetter、`managed_mode()`、admin fingerprint parse/duplicate validationを削除する。
- 不要になる `KeyFingerprint` importを削除する。
- configの責務を `sandbox_shell`、`read_paths`、`sandbox_env` のfile-backed sandbox policyだけにする。
- full-document/default/relative-path testを新schemaへ直す。
- retired field rejection testに `authorized_keys`、`admin_keys`、`allowed_keys` を明示的に含める。

### 3. authentication moduleを二source snapshotへする — `src/auth.rs`

- `resolve_authorized_keys_path(configured)` を引数なしにし、daemon accountの
  `~/.ssh/authorized_keys` だけを返す。
- authorized_keys固有名になっているvalidation/read helperを、pathを受ける共通key-source helperへ
  deepeningする。size、owner、mode、ancestor、`O_NOFOLLOW` の既存contractは弱めない。
- parser内部に「空sourceを許す」modeを追加する。公開parserの既存strict testを維持する必要が
  ある場合、file loader側だけが空を許すprivate APIに分ける。
- `AuthSnapshot::load(host_path, allowed_path)` に変更する。両sourceを読み切ってから次の順序で
  deterministicにmergeする。
  1. host entriesを挿入し、すべて `Admin` とする。
  2. allowed entriesのうち未登録fingerprintだけを `Normal` として挿入する。
  3. allowed側にhostと同じfingerprintがあれば新規entryを作らず `Admin` を維持する。
- `all_authorized_keys_admin` fieldを削除する。`authenticate()` はsnapshot内のroleだけを見る。
- `admin_count()` は合成snapshot内の `Admin` 件数を返す。
- 二sourceがそれぞれempty/missingでも、最終unionがnon-emptyなら成功させる。union emptyは
  source pathを含む明確なauth snapshot errorにする。
- file validationとopenの間でfileが消えた場合もpanicせず、snapshot load errorとして扱う。

推奨data structureはfingerprintで一意化できるmap/setと、必要なら監査・test用のdeterministicな
entry順序を別に保持する形である。role判定のたびに二つのfile由来vectorをlinear scanする実装は
避ける。ただし既存の公開surfaceを不要に広げない。

### 4. bootstrapとSIGHUPを新snapshotへ接続する — `src/main.rs`

- `Args::authorized_keys_host_access` とusage annotationを削除する。
- `KeyFingerprint` がdebug loggingだけに残るならimportとfingerprint一覧logを削除する。
- startupでhost pathを引数なしresolverから、allowed pathを `Paths` から取得し、
  `AuthSnapshot::load(&host_path, paths.allowed_keys_file())` を一度だけ呼ぶ。
- `managed_mode` を初期snapshotのAdmin数から導出する。Adminが0なら既存のsandbox-only startup
  behaviorを維持する。
- startup logはhost Admin数とaccepted key総数などcountだけを出し、鍵本文やfingerprint一覧を
  出さない。
- `load_reload_snapshot()` から `all_authorized_keys_admin` parameterを削除し、固定した二pathから
  auth snapshotを再構築する。
- reload成功時の `server.reload(next_shared)` と、失敗時にprevious snapshotを維持する流れを
  変えない。
- `--listen`、`--network`、`--log-level` とbuilt-in caps/limitsがprocess-lifetimeである契約は
  今回の変更対象外とする。

### 5. real SSH fixtureを二source化する — `tests/ssh_auth.rs`

- fixtureごとにisolatedなfake `HOME` とXDG rootsを作る。
- fake `HOME/.ssh/authorized_keys` にhost Admin key、
  fake `$XDG_CONFIG_HOME/shbox/allowed_keys` にNormal keyを書く。
- config fixtureから `authorized_keys` と `admin_keys` を削除し、daemon processへfake `HOME` を渡す。
- `start_with_host_access` と旧flag分岐を削除する。
- host/allowed fileを独立更新できるhelperを用意し、permissionはproduction validatorを通る値にする。
- 既存のhost route、sandbox ownership、management、SIGHUP testを新authority sourceに読み替える。

## テスト駆動の実装順序

実装担当は次のred-green-refactor順で進める。失敗が期待どおりの仕様差分であることを確認してから
production codeを変更する。

### A. unit/config/CLI testを先に赤くする

- host-only keyはacceptedかつ `Admin`。
- allowed-only keyはacceptedかつ `Normal`。
- overlap keyは一件だけで `Admin`。
- host内duplicate、allowed内duplicateはそれぞれerror。
- host missing + allowed valid、host empty + allowed validは成功。
- host valid + allowed missing、host valid + allowed emptyは成功。
- host/allowedの両方がmissing、empty、またはcomment-onlyでunion emptyなら失敗。
- 一方のmalformed、oversized、symlink、wrong owner、group/world writableでsnapshot全体が失敗。
- error textが失敗したsource名とpathを区別する。
- old TOML fields三種がunknown fieldとして失敗。
- `shbox --help`、生成man、completionに旧flagが現れず、旧flagの実行がnon-zeroになる。

### B. integration testを先に赤くする

- host keyで `_` のshell/exec/PTYが成功する。
- host keyでownerに関係なくsandbox list/shell/exec/deleteが可能。
- allowed-only keyは `_` でgeneric publickey denialとなり、role/key-set情報を漏らさない。
- allowed-only keyは自分のsandboxだけを作成・利用・削除でき、他ownerのsandboxを拒否される。
- 同じkeyを両fileに置くとAdminとして認証される。
- unknown keyとunsupported authentication methodは従来どおり拒否される。
- SIGHUPでhost fileからkeyを除くと新規connectionはhostを拒否されるが、既存ControlMaster
  connectionのAdmin principalは維持される。
- SIGHUPでallowed fileからkeyを除くと新規connectionは認証失敗し、既存connectionは維持される。
- host/allowedの追加は新規connectionに反映される。
- 一方をmalformedにしたreloadは、他方とconfigがvalidでも全体を拒否し、旧snapshotを維持する。
- 二sourceを空にするreloadは拒否し、最後のvalid snapshotを維持する。
- retired TOML fieldを含むreloadはauth変更も含めてatomicに拒否する。

### C. production codeを実装し、green後に整理する

- `src/paths.rs`、`src/config.rs`、`src/auth.rs`、`src/main.rs` の順に最小変更を行う。
- focused unit test、CLI test、SSH testの順でgreenにする。
- 共通key-source validationとsnapshot mergeの責務を `auth` module内に閉じる。
- compiler warning、dead compatibility path、旧用語を除去する。

## 文書と配備例の更新

少なくとも次を検索し、実装と同じcontractへ更新する。

- `docs/README.md`: Admin/Normalの定義。
- `docs/configuration.md`: TOML schema、XDG layout、startup、SIGHUP、migration。
- `docs/security.md`: trust boundary、file permission、role、reload、logging。
- `docs/product.md`: CLI usage、host selector、global sandbox administration。
- `docs/architecture.md`: auth snapshotとXDG tree。
- `docs/testing.md`: 二source matrix、test件数、verification evidence。
- `docs/platforms.md`: 配備例中のdaemon home/XDG key placement。
- `deploy/systemd/shbox.service` と `deploy/launchd/com.example.shbox.plist`: retired flag/fieldがないこと、
  daemon accountのhomeとXDG config pathが意図したkey sourceを指すこと。

最終的に次をrepository全体で検索し、migration説明とretired-field rejection test以外のstale referenceを
ゼロにする。

```console
rg -n 'admin_keys|authorized-keys-host-access|authorized_keys\s*=|allowed_keys'
```

migration guideには次を明記する。

1. 旧 `admin_keys` に列挙していたhost-capable keyをdaemon accountの
   `~/.ssh/authorized_keys` へ移す。
2. 旧authorized keyのうちsandbox-onlyにしたいkeyを
   `$XDG_CONFIG_HOME/shbox/allowed_keys` へ移す。
3. `config.toml` から `authorized_keys` と `admin_keys` を削除する。
4. service argsから `--authorized-keys-host-access` を削除する。
5. owner/modeを検証してからdaemonをrestartする。旧configを残したままでは意図的に起動失敗する。

## 検証gate

focused testがgreenになった後、同じcommitで次を実行し、command・toolchain・件数・結果を
`docs/testing.md` またはPR本文へ記録する。

```console
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets -- --test-threads=1
cargo build --locked --all-targets
cargo +1.91.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.91.0 test --locked --all-targets -- --test-threads=1
cargo +1.91.0 build --locked --all-targets
RUSTC_WRAPPER= cargo build --locked --release
RUSTC_WRAPPER= cargo test --locked --test ssh_auth -- --test-threads=1
```

macOS arm64のblocking platform gateは `scripts/verify-macos-platform` の前提を満たすhostで実行する。
LinuxのArapuca/cgroup成功経路はnative Linux delegated cgroup環境で
`scripts/verify-linux-platform` を実行する。実行環境がなければpassing扱いにせず、PRに明確な
deferred gateとして残す。support matrixは固定OS/architectureと同一commitの証跡なしに更新しない。

## 完了条件

- [x] `~/.ssh/authorized_keys` の全keyが `Admin` になり、hostと全sandboxを利用できる。
- [x] `$XDG_CONFIG_HOME/shbox/allowed_keys` だけのkeyは `Normal` になり、所有sandboxだけを利用できる。
- [x] overlapは `Admin`、source内duplicateはerrorになる。
- [x] 各sourceのmissing/emptyを許しつつ、空unionは起動・reloadで拒否される。
- [x] malformed/unsafeな一sourceがstartup/reload全体をfail closedにする。
- [x] 既存connectionのroleがreload後も変わらず、新規connectionだけが新snapshotを見る。
- [x] TOML `admin_keys`、TOML `authorized_keys`、CLI `--authorized-keys-host-access` が実装・help・
      man・completion・配備例から消え、入力された場合は明示的に失敗する。
- [x] stable、MSRV、real OpenSSH、利用可能なplatform gateが同一commitで通る。
- [x] repository全体の文書とmigration説明が実装に一致する。

## 実装上のリスクと非目標

- host `authorized_keys` への追加はdaemon accountのhost権限と全sandbox管理権限の付与である。
  一般的なSSH鍵登録より強いtrust boundaryとして文書化する。
- fileを分離しても公開鍵はsecretではないが、fingerprint一覧はuser enumerationに使えるため、
  authentication errorとlogで余分に露出しない。
- 二fileのcross-filesystem transaction、鍵管理UI、鍵の自動migration、authorized_keys options対応、
  certificate authority対応は今回のscope外である。
- listener/network/logging/resource-limitの前回変更、sandbox ownership metadata、host key、Arapuca
  backendの設計は変更しない。
- rollbackは実装commitの通常の `git revert` と旧config/key layoutの復元で行う。実装が既存key
  fileを自動削除・自動書換えしてはならない。

## 進捗

- [x] ユーザー方針を二source authority modelとして記録した。
- [x] path、role precedence、empty-source、reload、migrationの仕様判断を記録した。
- [x] 実装担当エージェントがred testを追加する。
- [x] 実装担当エージェントがproduction codeを変更する。
- [x] 文書・配備例を更新する。
- [x] 全検証gateを実行する。
- [ ] commit、push、PR Ready確認を完了する。

## 決定記録

- 2026-08-31: host authorityは別のadmin fingerprint listではなく、daemon accountの
  `~/.ssh/authorized_keys` membershipから直接導出する。
- 2026-08-31: sandbox-only authorityはshbox config rootの固定 `allowed_keys` fileから導出し、
  TOML path overrideは設けない。
- 2026-08-31: overlapは設定errorではなくAdmin precedenceとする。これはhost keyがsandboxも利用できる
  というcontractを保つためである。
- 2026-08-31: host sourceを必須にはしない。旧構成で可能だったAdminなしのsandbox-only運用を
  維持するためである。ただし二sourceのunionはnon-emptyを必須にする。
- 2026-08-31: SIGHUPのatomicityはvalidated snapshotの一括publishを意味し、filesystem間transactionは
  提供しない。
- 2026-08-31: retired interfaceはsilent ignoreせずfail closedにする。誤った移行状態で意図しない
  authorityを付与しないためである。
