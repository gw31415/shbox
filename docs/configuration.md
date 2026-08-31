# shbox 設定仕様

この文書は shbox v0.1 の TOML 設定と、設定に由来するファイル配置・reload の正本である。外部から見える動作は [product.md](./product.md)、SSH request の詳細は [ssh-protocol.md](./ssh-protocol.md)、OS ごとの適用条件は [platforms.md](./platforms.md) を参照する。

## 1. 基本方針

設定ファイルは任意である。設定ファイルが存在しない場合は、target OS に応じた built-in default で起動する。設定ファイルを使う場合は、`serde` と `toml` による typed parse を行い、未知の field、重複 key、不正な型、不正な値は起動または reload の失敗とする。値を黙って丸めたり、未知の設定を無視したりしない。

すべての設定は config file に書ける。トップ直下の `listen` と `log_level` には、同じ項目に
対応する CLI flag（`--listen`、`--log-level`）が上から重なり、指定時は config 値を置き換える。
CLI はこのトップレベル項目にだけ存在し、`[sandbox]` 以下の項目に対応する flag は意図的に
作らない。`--network` は存在せず、network policy は `[sandbox] network` だけである。
これらの operational 設定は process-lifetime であり、SIGHUP でも変わらない。
`XDG_CONFIG_HOME`、`XDG_DATA_HOME`、`XDG_STATE_HOME`、必要な場合の `XDG_RUNTIME_DIR` は、
`xdg` crate の標準的な path 解決だけに使う。shbox の機能設定に `SHBOX_*` や `RUST_LOG` を使わない。

設定ファイルの最大サイズは 1 MiB である。初回起動時に読み込めない、parse できない、validation に失敗する設定は、古い設定へ fallback せず明示的に失敗する。SIGHUP 時は後述の atomic reload 規則を適用する。

## 2. 完全な v0.1 TOML schema

この例は全 target で使える field を示す。コメントは説明用であり、指定しない
field は built-in default が適用される。`[sandbox] shell` や `[sandbox] read_paths`
のような path は、設定ファイルに明示する場合は絶対 path でなければならない。
文字列配列の項目（`listen`、`[sandbox] read_paths`）は、要素 1 つの配列の代わりに
単一 string も受け付ける。`listen = "127.0.0.1:2222"` は
`listen = ["127.0.0.1:2222"]` と同じであり、これ以外の型は parse error になる。

```toml
# SSH listener の bind address 配列。省略時は ["0.0.0.0:22"]。
listen = ["127.0.0.1:2222"]

# daemon log 詳細度。省略時は "info"。
log_level = "info"

[sandbox]
# 省略時は daemon OS user の login shell（passwd entry が空なら /bin/sh）。
# 指定時は絶対 path の executable。
shell = "/bin/bash"

# sandbox process の network policy。disabled または outbound。省略時は disabled。
network = "disabled"

# sandbox process に追加する read-only subtree。空配列が default。
read_paths = []

# sandbox 全体に注入する環境変数。空 table が default。
[sandbox.env]
# LANG = "C.UTF-8"
```

`listen` と `log_level` はトップレベルの config 項目であり、同じ項目に対応する CLI flag が
上から重なる。CLI はこの二つにだけ存在し、`[sandbox]` 以下の項目に対応する flag は作らない。
例えば次のように起動する。

```console
shbox --listen 127.0.0.1:2222 --log-level debug
```

この file schema 以外の field は v0.1 に存在しない。resource limits/caps や
`[sandbox]` 項目の CLI flag は存在せず、旧綴り（トップレベルの `sandbox_shell`、
`read_paths`、`[sandbox_env]`、`network`）も `deny_unknown_fields` により明示的に拒否される。
`host_key`、`sandbox_root`、`runtime_dir`、`selector`、`uid`、`gid`、`cgroup`、`seccomp`、
`landlock`、`seatbelt`、`task_id`、`network_proxy_socket` などの内部設定も公開しない。

## 3. Field の意味

### 3.1 `listen`

SSH listener の bind address 配列で、default は `["0.0.0.0:22"]`。文字列配列項目共通の
規則に従い、単一 string も受け付ける（`listen = "127.0.0.1:2222"` は
`listen = ["127.0.0.1:2222"]` と同じ）。CLI `--listen` を一つでも
指定すると config 値を完全に置き換え、repeat して複数 address を指定できる。複数指定時は
すべての address を bind できた場合だけ起動を成功とし、一つでも失敗したら全体を失敗させる。
`2222` などへの自動 fallback はない。IPv6 wildcard は `listen = ["[::]:22"]` または
`--listen '[::]:22'` のように明示する。空配列、重複、無効な socket address は拒否する。

listener は process-lifetime の設定であり、SIGHUP では再 bind しない。config file 上で
`listen` を変えた SIGHUP は reload 全体を拒否する。変更には daemon の restart が必要である。

### 3.2 鍵ファイルと権限（host 認可鍵・sandbox 許可鍵）

SSH 公開鍵は TOML 設定ではなく、明確な由来を持つ二つのファイルから読み込む。

1. **Host 認可鍵**: daemon account の `~/.ssh/authorized_keys`
   ここにある鍵はすべて `Admin` であり、host selector `_` と全 sandbox の操作を許可される。
2. **Sandbox 許可鍵**: `$XDG_CONFIG_HOME/shbox/allowed_keys`
   ここだけにある鍵は `Normal` であり、自分が所有する sandbox だけを利用できる。
3. **両方にある鍵**: 一つの identity として扱い、強い権限である `Admin` を付与する。

`~` は文字列展開ではなく、現在の daemon account の home directory から解決する。`allowed_keys` も `Paths` が導出する固定 path であり、TOML や CLI で変更できない。

受理する行は次の bare OpenSSH Ed25519 形式だけである。

```text
ssh-ed25519 <base64-public-key> [comment]
```

空行と `#` で始まるコメントは無視する。options、証明書、別 algorithm、壊れた base64、同一 source 内の重複 key、未知の line format は source 全体の error とする。1 行の上限は 8 KiB、ファイル全体の上限は 1 MiB。

各 source は個別には未作成、空、blank/comment のみを許す。ただし二つを合成した結果に有効な鍵が一つもない場合、起動や reload は拒否される。

存在する key file は daemon user 所有の regular file で、symlink ではなく、group/world writable であってはならない。直近 parent も daemon user 所有の directory で、symlink および group/world writable を拒否する。上位 ancestor にも write permission 検査を適用し、最終 path は `O_NOFOLLOW` で開く。

admin key は全 sandbox を可視・操作でき、`_` host selector による host shell/exec/PTY/resize/signal を利用できる。`_` を通常 key で使うことはできない。SIGHUP で host file から鍵を削除して admin なしの sandbox-only mode に遷移することも可能である。既存 admin connection の権利は切断まで変わらない。
### 3.4 `[sandbox] shell`

省略時は daemon OS user の passwd entry の login shell を使い、その entry が空の場合だけ `/bin/sh` を fallback とする。passwd entry または設定で選ばれた非空 path が存在しない、通常 file でない、実行できない場合は startup/reload error とする。指定値は絶対 path の executable 一つだけであり、shell command、argv、shell fragment は指定しない。

interactive shell はこの shell を login mode で起動する。remote `exec` は同じ shell を `-c <command>` で起動するため、remote command の既定を常に `/bin/sh` にするわけではない。host mode には `host_shell` 設定を設けず、daemon OS user の login shell を使う。host mode でも passwd entry が空の場合だけ `/bin/sh` を fallback とし、非空の path が無効なら startup/reload error とする。

### 3.5 `[sandbox] network`

値は `disabled` または `outbound` のみである。省略時は `disabled`。この項目に対応する CLI flag は存在しない。

- `disabled`（default）：sandbox からの外部 network を許可しない
- `outbound`：初期 v0.1 から利用できる unrestricted TCP/UDP/DNS network capability。主用途は outbound 通信

shbox は inbound port mapping や SSH forwarding を設定できない。ただし `outbound` は全 OS
で bind/listen syscall を禁止する egress-only security boundary ではない。外部からの到達制御は
host firewall の責務である。per-sandbox policy、per-host allowlist は設定できない。host mode は
この field の対象外であり、daemon の通常の host network namespace を使う。network policy に
関する Arapuca の profile 名や syscall flag は公開しない。

`outbound` を選ぶと syscall/network isolation が `disabled` より弱くなるため、startup に
一度、明示的な warning を host log に記録する。network mode は process-lifetime であり、
config file 上で変えた SIGHUP は reload 全体を拒否する。変更には daemon の restart が必要である。

### 3.6 `[sandbox] read_paths`

sandbox process が追加で read-only で参照できる絶対 path の配列である。default は空配列だが、実装は OS と Arapuca の実行に必要な system/runtime/TLS path を内部の curated set として追加する。文字列配列項目共通の規則に従い、単一 string も受け付ける。利用者が指定した path は write permission を付与しない。

各 path は startup/reload 時に存在を確認し、canonical absolute path に解決する。`~`、environment variable、relative path、NUL、重複、存在しない path は拒否する。shbox の state/data/private root、他 sandbox の workspace、管理用 lock/host-key path を追加 read path にすることも拒否する。通常の OS DAC が先に適用され、read path の指定によって権限が昇格することはない。

### 3.7 `[sandbox.env]`

全 sandbox process に共通して渡す追加 environment の table である。client の `env` request や client-side environment は転送しない。値は UTF-8、NUL なし、1 value あたり 4 KiB 以下とする。name は POSIX environment name（`[A-Za-z_][A-Za-z0-9_]*`）でなければならない。

shbox は追加値を適用する前に、次の base environment を構成する。

| name | base value |
|---|---|
| `HOME` | 対象 sandbox の workspace |
| `PWD` | 対象 sandbox の workspace。実際の cwd も同じ |
| `SHELL` | validation 済みの selected sandbox shell |
| `TMPDIR` | launch ごとの private temporary directory |
| `PATH` | Linux は `/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin`。macOS は先頭に `/opt/homebrew/bin` を加える |
| `LANG` | `C.UTF-8` |

`PATH` と `LANG` は `sandbox.env` で明示的に上書きできる。それ以外の上表の name と
PTY request から管理する `TERM` は上書きできない。

次の prefix/name は設定 error として拒否する。これは黙って drop する allowlist ではなく、
config 全体の validation rule である。

- managed/reserved: `HOME`, `PWD`, `SHELL`, `TMPDIR`, `TERM` と `SHBOX_` prefix
- launcher/runtime prefixes: `ARAPUCA_`, `LD_`, `DYLD_`, `COR_`, `CORECLR_`,
  `DOTNET_`, `COMPLUS_`
- launcher/platform names: `AGENT_NETWORK_PROXY`, `__COMPAT_LAYER`, `COMSPEC`,
  `PSModulePath`, `PATHEXT`
- interpreter injection: `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `PYTHONHOME`, `NODE_OPTIONS`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`,
  `ZDOTDIR`, `IFS`, `PROMPT_COMMAND`
- runtime/tool injection: `GCONV_PATH`, `HOSTALIASES`, `LOCPATH`, `GETCONF_DIR`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`, `GOFLAGS`, `GIT_CONFIG_GLOBAL`,
  `GIT_CONFIG_SYSTEM`, `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXEC_PATH`,
  `GIT_TEMPLATE_DIR`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `GIT_EDITOR`,
  `GIT_SEQUENCE_EDITOR`, `OPENSSL_CONF`, `EDITOR`, `VISUAL`, `PAGER`, `CARGO_HOME`
- proxy/certificate injection: `http_proxy`, `HTTP_PROXY`, `https_proxy`, `HTTPS_PROXY`,
  `ALL_PROXY`, `all_proxy`, `NO_PROXY`, `no_proxy`, `ftp_proxy`, `FTP_PROXY`,
  `SOCKS_PROXY`, `socks_proxy`, `CGI_HTTP_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`

workspace は sandbox process の HOME と cwd になるが、これは `sandbox.env` で設定するものではない。秘密情報を環境変数へ置くことは推奨しない。host mode はこの table を注入する sandbox mode と異なり、daemon service environment 全体を継承する。

### 3.8 組み込み resource limits

resource limit は TOML field ではなく、全 daemon が共有する組み込み安全既定値である。値は
変更できず、0 は該当する limit 無制限を表す。

| field | default | v0.1 の意味 |
| --- | ---: | --- |
| `max_memory_mb` | `0` | launch ごとの process group の memory ceiling。Linux は delegated cgroup の hard limit、macOS は RSS monitor による best-effort。 |
| `cpu_timeout_secs` | `0` | process の累積 CPU time 上限。wall-clock timeout ではない。 |
| `max_file_size_mb` | `0` | process が作成できる単一 file の上限。 |
| `max_open_files` | `1024` | process あたりの open file descriptor 上限。 |

macOS は Linux cgroup と同じ hard-limit/quota semantics を約束しない。unsupported な enforcement を有効と表示したり、値を別の limit へ暗黙変換したりしない。wrapper や OS の能力不足で指定 limit を適用できない場合は sandbox launch を fail closed にするか、[platforms.md](./platforms.md) の capability policy に従って明示的に拒否する。

### 3.9 Linux の組み込み limits

Linux target では次の cgroup limits も組み込みで適用する。TOML table として指定することは
できない。

| field | default | 意味 |
| --- | ---: | --- |
| `max_cpu_pct` | `0` | cgroup v2 の CPU quota。`0` は quota 無し。 |
| `max_pids` | `256` | launch ごとの cgroup PID 上限。 |

Linux では Arapuca の cgroup v2 を利用するため、daemon は他 process と共有しない dedicated delegated cgroup scope に配備する。kernel、controller delegation、scope の検証に失敗した場合は sandbox backend を利用不可とし、host process の直接実行へ degrade しない。raw cgroup path、controller、cleanup policy は設定できない。

macOS では Linux-only の cgroup quota/pid semantics は存在せず、platform の組み込み policy
に従う。resource values は platform 間で暗黙変換しない。

### 3.10 組み込み concurrency caps

接続や shbox 管理対象の同時実行数を制限する。0 は無制限ではなく、field ごとに 0 を
禁止する。次の組み込み値を持ち、設定ファイルや reload から変更できない。

| field | default | 対象 |
| --- | ---: | --- |
| `max_unauthenticated_connections` | `32` | 認証完了前の同時 connection |
| `max_connections` | `128` | 全 SSH connection |
| `max_channels_per_connection` | `16` | 一つの connection 内の channel |
| `max_sandbox_processes` | `128` | 全 sandbox shell/exec process |
| `max_host_processes` | `16` | host mode process |
| `max_auth_attempts` | `6` | 一つの connection の認証試行 |
| `max_sandboxes` | `1024` | 全 sandbox |
| `max_sandboxes_per_owner` | `128` | 一つの owner fingerprint の sandbox |
| `handshake_timeout_secs` | `30` | SSH handshake/authentication 完了まで |

認証済み connection に idle timeout は設けない。上限到達時は新規 request を protocol error または resource exhaustion として拒否し、既存の process を無関係に kill しない。admin-created sandbox も sandbox 数上限へ算入する。

v0.1 は source IP ごとの rate limiter や ban list を内蔵しない。internet-facing 配備の
rate limit、deny list、接続元制限は host firewall または上流 network の責務である。

### 3.11 `log_level`

`error`、`warn`、`info`、`debug`、`trace` のいずれか。default は `info`。CLI `--log-level`
を指定すると config 値を置き換える。ログは `tracing` の構造化 compact text として
UTC RFC3339 timestamp 付きで daemon の stderr に出す。log level は process-lifetime で、
SIGHUP では変わらない。config file 上で変えた SIGHUP は reload 全体を拒否する。
log file、rotation、client が指定する log level、`RUST_LOG` は v0.1 にない。

connection/channel ID、remote address、key fingerprint、role、selector/ID、operation、result、duration、exit status は安全に sanitize して記録できる。command text、terminal I/O、stdin、stdout、stderr、秘密、Arapuca raw audit は記録しない。

## 4. 固定 XDG path と file permissions

XDG directory の lookup は `xdg::BaseDirectories` に `shbox` prefix を付けて行う。shbox は fallback や environment variable 解釈を再実装しない。v0.1 の正式 target は Unix 系の Linux/macOS であり、`xdg` crate を必須にするため Windows path backend は提供しない。

| 用途 | path |
| --- | --- |
| config | `$XDG_CONFIG_HOME/shbox/config.toml`（fallback `~/.config/shbox/config.toml`） |
| sandbox 許可鍵 | `$XDG_CONFIG_HOME/shbox/allowed_keys`（fallback `~/.config/shbox/allowed_keys`） |
| host 認可鍵 | `~/.ssh/authorized_keys`（daemon account の home directory） |
| sandbox data | `$XDG_DATA_HOME/shbox/sandboxes/`（fallback `~/.local/share/shbox/sandboxes/`） |
| host key | `$XDG_STATE_HOME/shbox/host_key`（fallback `~/.local/state/shbox/host_key`） |
| registry lock | `$XDG_DATA_HOME/shbox/registry.lock`（fallback `~/.local/share/shbox/registry.lock`） |
| daemon state lock | `$XDG_STATE_HOME/shbox/lock`（fallback `~/.local/state/shbox/lock`） |
上記の `host_key`、二つの lock、sandbox root は固定 path であり、config field で変更できない。XDG runtime directory は v0.1 の必須 storage ではなく、cache directory も使用しない。sandbox data は runtime に置かない。

host key は Ed25519 とし、無い場合だけ初回起動時に atomic create する。mode `0600`、daemon owner 固定であり、破損、wrong owner、group/world writable、保存失敗は startup error である。既存 host key の自動 rotation や OpenSSH daemon key の暗黙流用はしない。

sandbox data root と各 sandbox directory は daemon owner の mode `0700`、metadata は mode `0600` を基本とする。管理対象の path とその親が別 owner、group/world writable、symlink による root 外参照になる場合は拒否する。workspace 内の利用者データに symlink があること自体は許可できるが、delete は sandbox root の外へ追跡しない。

daemon は data 側の registry lock と state 側の daemon lock をこの順で non-blocking に取得し、process lifetime 中保持する。どちらか一方でも取得できなければ、既に取得した lock を解放して起動を失敗させる。同じ sandbox data root または同じ state root を共有する第二 daemon は、listen address が異なっても起動できない。lock path は daemon owner の通常 file、mode `0600` とし、symlink や unsafe permission を拒否する。sandbox ごとに別の lifecycle lock を持つため、別 ID の create/delete は並行できる。

## 5. Startup と mode

起動時は次の順で初期化する。

1. CLI を parse し、`listen` と `log_level` の上書き要求を保持する
2. XDG path を解決し、data の registry lock と state の daemon lock を取得する
3. config（または built-in default）を parse/validate する
4. `listen` と `log_level` を config 値と CLI 層から確定し、logging を初期化する
5. host 認可鍵（`~/.ssh/authorized_keys`）と sandbox 許可鍵（`$XDG_CONFIG_HOME/shbox/allowed_keys`）から auth snapshot を構築する
6. host key を初期化する
7. Arapuca backend を一度だけ生成する
8. managed mode（初期 Admin 数 > 0）なら listener を bind し、`_` だけを ready にする
9. metadata を reconcile し、valid な `Active`/`Deleting` state を確認する
10. sandbox operation を ready にし、sandbox-only mode（初期 Admin 数 == 0）ならここで listener を bind する

Admin key が一つ以上ある managed mode では、host selector `_` を reconciliation より先に利用可能にする。reconcile が完了するまで sandbox operation は `not ready` として拒否する。Admin が無い sandbox-only mode では、reconcile 完了前に listener を公開しない。

sandbox-only mode は有効な構成だが、port 22 の listener に admin recovery route が無い
ことを startup log で warning として一度通知する。

Arapuca backend の初期化や sandbox capability の検証に失敗しても daemon は起動できる。managed mode では SSH/host route を利用でき、sandbox-only mode でも reconciliation の完了後は listener を公開する。Linux で外部 `arapuca` wrapper または delegated cgroup が利用できない場合、または対応外 platform の場合、Arapuca が必要な sandbox shell/exec/PTY は fail closed とし、ホスト上で直接 command を実行する fallback はない。macOS arm64 では、別途 `arapuca` を PATH にインストールしていなくても、shbox 自身が rlimit wrapper として動作する。metadata に基づく認可済み `list`/`delete` は reconciliation 後に利用できる。backend は SIGHUP で再構築せず、sandbox process の復旧には daemon restart が必要である。

## 6. Reload

SIGHUP は、ファイルを新しい typed config として全体 parse/validate し、成功した場合だけ一つの
immutable snapshot として置き換える。parse、permission、path、key、platform capability の
いずれかに失敗した場合は、旧 snapshot、既存 connection、既存 process を維持する。

reload は次の 4 項目を一つの reload 単位として読み、すべて成功した場合だけ atomic に publish する。

1. `$XDG_CONFIG_HOME/shbox/config.toml`
2. daemon account の `~/.ssh/authorized_keys`
3. `$XDG_CONFIG_HOME/shbox/allowed_keys`
4. config から導出する sandbox shell/read path/environment policy

どれか一つでも missing policy 違反、permission 違反、parse error、空の合成 key set になれば、config・auth・sandbox policy のどの部分も publish しない。

変更後の値は、新しい connection と新しく作る process/sandbox operation に適用する。既存 connection
の認証済み role/ownership rights、既存 process、既存 PTY は切断・再起動しない。既存 admin
connection は、reload で最後の admin key が削除されても切断まで admin のままである。

`listen`、`log_level`、`[sandbox] network`、組み込み caps/limits、host key path、
XDG root、固定 selector `_`、metadata version は process の lifetime 中固定である。
SIGHUP で読んだ config がこれらの値を前 snapshot から変えていた場合、auth や sandbox
policy の変更を含めて reload 全体が拒否され、旧 snapshot が維持される。listener は
再 bind されない。これらの変更を適用するには daemon を restart する。

通常起動時に config file が無くても default で動作する。起動後に config file を新しく作成して
SIGHUP した場合は、それを検証して採用できる。config が引き続き無ければ built-in default を
維持する。一度 file から config を採用した daemon で、その file が SIGHUP 時に消えた場合は
default へ戻らず reload を失敗させ、旧 config を保持する。

## 7. Validation と失敗時の観測

設定エラーは daemon の起動失敗または SIGHUP の reload failure として operator の stderr/log に出す。内部 path、fingerprint、error chain は host log に限り、SSH client へは一般化した安定 error だけを返す。command output と terminal I/O は汚染しない。

config、authorized_keys、host key、XDG directory の作成・permission・disk full・bind failure、Arapuca capability 不足は operational failure であり panic させない。remote の不正 username、unknown subsystem、unsupported request、disconnect も daemon 全体を panic させない。内部 invariant の破壊だけは location/backtrace をログし daemon を abort する。

プロトコル入力には次の固定上限を適用する。これらは TOML field ではない。

| 入力 | 上限 |
| --- | ---: |
| SSH exec command string | 32 KiB |
| terminal type (`TERM`) | 256 bytes |
| subsystem name | 64 bytes |
| authorized key 1 行 | 8 KiB |
| authorized key file | 1 MiB |
| config file | 1 MiB |
| sandbox metadata | 16 KiB |

上限を超えた入力は切り詰めず拒否する。bounded buffer と SSH window backpressure を使い、client の送信失敗や channel close では対応する process を回収する。


## 8. 移行ガイド（Migration Guide）

### 8.1 旧 auth 設定からの移行

旧設定（`admin_keys`、TOML の `authorized_keys`、CLI `--authorized-keys-host-access`）から移行する場合は次を実施する。

1. 旧 `admin_keys` に列挙していた host-capable key を daemon account の `~/.ssh/authorized_keys` へ移す。
2. 旧 authorized key のうち sandbox-only にしたい key を `$XDG_CONFIG_HOME/shbox/allowed_keys` へ移す。
3. `config.toml` から `authorized_keys` と `admin_keys` を削除する。
4. service args / CLI から `--authorized-keys-host-access` を削除する。
5. owner / mode（鍵ファイル `0600`、ディレクトリ `0700`）を検証してから daemon を restart する。旧 config を残したままでは意図的に起動失敗する。

### 8.2 `[sandbox]` テーブルと config への operational 設定統一への移行

旧綴りと CLI flag は unknown field / unknown flag として拒否される。次を実施する。

1. service args / CLI から `--network disabled|outbound` を削除し、`config.toml` の
   `[sandbox] network = "..."` に置き換える。`network` に対応する CLI flag は存在しない。
2. `config.toml` のトップレベル `sandbox_shell = "..."` を `[sandbox] shell = "..."` へ、
   トップレベル `read_paths = [...]` を `[sandbox] read_paths = [...]` へ、
   `[sandbox_env]` を `[sandbox.env]` へ移す。
3. `listen` と `log_level` はトップレベルに書ける。service args で `--listen` /
   `--log-level` を渡し続けることもでき、その場合は config 値を置き換える。両方に書いた
   場合は CLI が勝つ。
4. `listen`、`log_level`、`[sandbox] network` は process-lifetime である。SIGHUP の
   reload でこれらを変更すると reload 全体が拒否され、旧設定が維持される。変更の適用には
   daemon の restart を行う。

## 9. 関連文書

- [product.md](./product.md): 外部 API、ownership、host mode、compatibility
- [security.md](./security.md): 脅威境界、key role、filesystem safety
- [architecture.md](./architecture.md): config snapshot と module 境界
- [ssh-protocol.md](./ssh-protocol.md): request/channel semantics
- [platforms.md](./platforms.md): Linux cgroup、macOS capability、Arapuca revision
- [testing.md](./testing.md): configuration、reload、permission の acceptance test
