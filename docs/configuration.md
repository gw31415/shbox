# shbox 設定仕様

この文書は v0.1 の公開 TOML schema、CLI override、XDG layout、built-in concurrency cap を定義する。backend selector や raw backend option は公開しないが、§4.4 の resource limit（Linux の `cgroup_parent` を含む）は platform-specific な公開設定である。

## 1. 読み込みと lifetime

設定は daemon 起動時に一度だけ読み、完全に validation した immutable snapshot として保持する。設定変更を適用するには daemon restart が必要である。SIGHUP は key source の再検証だけを強制し、TOML は再読込しない。

config file が存在しなければ built-in defaults を使う。存在するが unreadable、unsafe、oversized、invalid TOML の場合は起動失敗であり defaults へ黙って fallback しない。

最大 config size は 1 MiB。unknown field はすべて拒否する。

## 2. 完全な TOML schema

```toml
# 省略時: ["tcp://0.0.0.0:22"] (tcp build のみ)
listen = ["tcp://0.0.0.0:22"]

# error | warn | info | debug | trace
# 省略時: info
log_level = "info"

[sandbox]
# 省略時: daemon OS user の login shell。
# passwd の shell が空なら /bin/sh。
# 指定時: absolute executable path。
shell = "/bin/bash"

# disabled | outbound
# 省略時: disabled
network = "disabled"

# host | isolated
# 省略時: host（互換モード。isolated は subordinate ID と broker が必要）
identity = "host"

# 追加 read-only path。単一 string も一要素配列として受理する。
# 省略時: []
read_paths = ["/opt/toolchain"]

# resource limits。すべて省略時は parent の制限を継承する。
# memory_max = 1073741824
# swap_max = 536870912
# pids_max = 64
# cpu_quota_micros = 50000
# cpu_period_micros = 100000
# cgroup_parent = "/sys/fs/cgroup/shbox"

[sandbox.env]
# operator が全 sandbox launch に追加する environment。
# PATH と LANG は必要なら上書きできる。
PATH = "/usr/local/bin:/usr/bin:/bin"
LANG = "C.UTF-8"
```

この schema 以外の field は v0.1 では存在しない。

## 3. Top-level fields

### 3.1 `listen`

`listen` は transport 修飾付き endpoint URI の一個または配列。default は `tcp://0.0.0.0:22`（`tcp` feature が有効な build のみ。`ws`-only build では `listen` の明示指定が必須）。

- 空配列は禁止。
- endpoint は `tcp://host:port` または `ws://host:port/path`。他の scheme（`wss` を含む）は拒否。
- build に含まれない transport を要求する endpoint は fail-closed で拒否する。
- duplicate endpoint は禁止。
- CLI `--listen` が一つでも指定された場合、config の list 全体を置き換える。

例:

```toml
listen = ["tcp://127.0.0.1:2222", "tcp://[::1]:2222"]
```

`ws` build での WebSocket transport（SSH byte stream の transport adapter にすぎず、追加の application protocol はない。`wss://` は reverse proxy で終端する）:

```toml
listen = ["ws://0.0.0.0:8080/ssh"]
```

WebSocket 接続は `Sec-WebSocket-Protocol: ssh` の要求・選択を必須とし、frame は binary のみ。URL の query parameter は sandbox 選択や認可に一切使われない。sandbox 選択は SSH username のみが権威を持つ。

### 3.2 `log_level`

許可値:

```text
error warn info debug trace
```

CLI `--log-level` が指定された場合は config 値を override する。

## 4. `[sandbox]`

### 4.1 `shell`

absolute path だけを受け付ける。NUL を含めない。startup 時に最終 shell を決定し executable であることを確認する。

省略時は daemon account の passwd login shell を使い、空 entry の場合だけ `/bin/sh` を使う。

shell は process-lifetime policy の一部であり、request ごとに選択できない。

### 4.2 `network`

許可値は二つだけ。

| value | contract |
|---|---|
| `disabled` | host/external network reachability を拒否する。default。Linux では fresh user+network namespace に隔離し、加えて Landlock が TCP `bind`/`connect` を拒否する。macOS では deny-default Seatbelt profile が network operation を許可しない。 |
| `outbound` | ordinary network socket use を許す。port allowlist/proxy policy ではない。 |

Linux/macOS の enforcement 差は [platforms.md](platforms.md) を参照する。

`outbound` は isolation を弱めるため startup log で operator に警告する。外部到達範囲をさらに制限したい場合は host/provider firewall を併用する。

### 4.3 `identity`

`host`（default）は従来互換の daemon host identity を使う。`isolated` は
Linux の通常 sandbox に durable な subordinate UID/GID lease、fresh user/mount
namespace、parent-installed one-entry map、ID-mapped workspace/runtime mount を
要求する。`newuidmap`/`newgidmap`、subid delegation、socket-activated privileged
ID-map broker、kernel/filesystem の ID-mapped mount 対応のいずれかが欠けている
場合、launch は daemon identity に fallback せず fail closed する。

この設定は daemon 起動時の immutable snapshot であり、admin の `_` host route
には適用されない。`runtime_uid`/`runtime_gid` は namespace 内の `1000:1000`
で固定され、host-visible ID は shbox が lease した値になる。通常の launch で
workspace を recursive `chown` することはない。

### 4.4 `read_paths`

sandbox process に追加で read-only access を与える absolute path。single string または string array。

validation:

- absolute path 必須
- NUL 禁止
- startup 時に存在して canonicalize できること
- duplicate canonical path 禁止
- shbox config/data/state roots 自身やその subtree を expose しないこと

この値は write permission を与えない。workspace/private runtime temp の write grant は shbox の launch policy からのみ作る。

OS が ordinary command runtime に必要とする system/runtime path は implementation の curated set として別途追加され、public config には列挙しない。

### 4.5 Resource limits

`sandbox` table の optional key で、sandbox ごとの resource limit を指定する。Linux では cgroup v2、macOS では表現可能な値を child の `setrlimit` に変換する。macOS で CPU quota または swap limit を指定した場合は起動を fail closed する。`cgroup_parent` は Linux 用であり、macOS では使われない。

| key | Linux | macOS |
|---|---|---|
| `memory_max` | `memory.max`、bytes | `RLIMIT_AS`、address-space bytes（RSS ceiling ではない） |
| `swap_max` | `memory.swap.max`、bytes | unsupported。指定時は fail closed |
| `pids_max` | `pids.max`、process count | `RLIMIT_NPROC`、OS/user-scope の process limit |
| `cpu_quota_micros` | `cpu.max` の quota、microseconds of CPU per period | unsupported。指定時は fail closed |
| `cpu_period_micros` | `cpu.max` の period、1000..=1000000（quota 指定時だけ有効。default 100000） | CPU quota が unsupported のため、quota なしでは効果なし |
| `cgroup_parent` | per-`SandboxId` process domain cgroup の作成先となる absolute cgroup v2 directory | 使用しない |

`memory_max`、`swap_max`、`pids_max`、`cpu_quota_micros` の省略は `Inherit` であり、その controller に対する sandbox-local の変更を行わない。public shbox adapter は設定の有無にかかわらず `SandboxId` ごとに一つの durable な process domain（専用 cgroup v2）を作成し、同じ `SandboxId` の concurrent launch はその domain を共有する。child は `clone3(CLONE_INTO_CGROUP)` で最初から domain 内に生成されるため、limit 適用前の window は存在しない。child が終了しても domain は削除せず、sandbox deletion または daemon shutdown が runtime cancellation と child cleanup を完了した後に domain を release/remove する。daemon crash/restart では次回 startup が shbox 所有の `shbox-domain-*` と `sandbox-*` runtime generation を回収するが、名前 prefix 外の sibling cgroup や file は変更しない。明示 limit は ancestor cgroup の制限に追加される制限であり、child が親・祖先 cgroup の制限を解除または引き上げることはできない。

なお、`shbox-sandbox::Sandbox::spawn` を直接利用する engine path は、resource limit を使う場合に spawn ごとの one-shot per-child cgroup semantics を採用し得る。これは public shbox adapter の `SandboxId` 共有 domain とは別の lifecycle である。

`cgroup_parent` 省略時は engine が自身の cgroup から上位へ探索し、process domain を作成できる階層を使う。書き込み可能な階層が無ければ Linux sandbox launch は fail closed する。systemd で delegation する場合は当該 unit に `Delegate=cpu memory pids` を設定し、その cgroup directory を `cgroup_parent` に指定するのが確実である。systemd は controller を利用可能にするが `cgroup.subtree_control` は有効化しないため、shbox が limit 用 child cgroup の作成時に必要な controller だけを有効化する。

**排他所有権**: `cgroup_parent` と runtime temp root は、それぞれ同時に 1 つの shbox daemon instance だけが所有する。daemon は起動時の reconciliation で当該 parent 直下のすべての `shbox-domain-*` cgroup（および runtime root 直下のすべての `sandbox-*` tree）を自らの所有物として回収する。この名前空間は per-daemon-instance ではないため、2 つの daemon が同一の parent/runtime root を共有する構成は支持されず、一方の起動が他方の稼働中 domain を kill する。複数 daemon を動かす場合は親子の異なる delegated directory をそれぞれに与えること。

macOS の `memory_max` は `RLIMIT_AS`、`pids_max` は `RLIMIT_NPROC` として child の exec 前に設定され、descendant に継承される。これらは Linux cgroup tree quota ではない。

### 4.5 `[sandbox.env]`

全 sandbox launch に追加する `name = "value"` table。

name は POSIX identifier:

```text
[A-Za-z_][A-Za-z0-9_]*
```

value は UTF-8 TOML string で、NUL を含めず 4 KiB 以下。

`PATH` と `LANG` は operator override を許可する。一方、shbox が authoritative に設定する名前や injection-sensitive 名は拒否する。

代表的な managed names:

```text
HOME PWD SHELL TMPDIR TERM
```

代表的な拒否カテゴリ:

- dynamic loader / runtime injection
- interpreter startup hooks
- proxy/certificate redirection
- Git tool/askpass/editor injection
- shell startup/environment hooks

reserved prefixes:

```text
SHBOX_
LD_
DYLD_
COR_
CORECLR_
DOTNET_
COMPLUS_
```

SSH client の `env` request は受理して sandbox environment に加えない。

## 5. Launch-time authoritative environment

各 launch で shbox が次を設定する。

```text
HOME=<sandbox workspace>
PWD=<sandbox workspace>
SHELL=<validated configured/resolved shell>
TMPDIR=<private sandbox-runtime directory on Linux; unique launch directory on macOS>
```

PTY request 時:

```text
TERM=<pty-req term>
```

これらは `[sandbox.env]` より authoritative であり shadow できない。

Linux の private `TMPDIR` は sandbox runtime-domain generation ごとに一つ、macOS では launch ごとに一つ作る。いずれも owner-only directory とし、Linux では cgroup が空になり in-flight launch がなくなった後、macOS では launch cleanup で recursive に削除する。host-wide `/tmp` を writable sandbox path として自動 grant しない。

## 6. Built-in concurrency caps

以下は config field ではなく daemon の built-in admission/safety caps である。

| cap | default |
|---|---:|
| unauthenticated connections | 32 |
| total connections | 128 |
| channels per connection | 16 |
| concurrent launch operations per sandbox | 128 |
| concurrent host-mode processes | 16 |
| auth attempts per connection | 6 |
| total sandboxes | 1024 |
| sandboxes per owner | 128 |
| SSH handshake timeout | 30 s |

これらは admission/concurrency limit であり、§4.4 の per-sandbox resource limits の代替ではない。file-size/open-file quota を設定する機能でもない。`concurrent launch operations per sandbox`（内部 cap 名 `max_concurrent_launches_per_sandbox`）は `SandboxId` ごとの launch 数に対して数えられ、Linux の実 process 数は `pids.max` が cgroup 全体で数える（daemon 全体での global cap ではない）。

## 7. Unsupported resource controls

§4.4 に記載した memory、swap、PID、CPU の limit は platform ごとに実装される。v0.1 で提供しない per-launch/per-sandbox quota は次の通りである。

- file-size quota
- open-file quota
- workspace disk quota

macOS では CPU quota と swap limit も表現できず、指定すると黙って無視せず fail closed する。operator が systemd、container runtime、VM/provider、OS account policy などで追加の service-level resource controls を設定することは可能だが、それは shbox public sandbox contract の代替ではない。

旧設定名らしき unknown field を互換目的で黙って受理することもしない。`deny_unknown_fields` により明示的な config error になる。

## 8. XDG layout

`xdg` crate の application prefix `shbox` を使う。

```text
$XDG_CONFIG_HOME/shbox/config.toml
$XDG_CONFIG_HOME/shbox/allowed_keys

$XDG_DATA_HOME/shbox/registry.lock
$XDG_DATA_HOME/shbox/sandboxes/<id>/

$XDG_STATE_HOME/shbox/host_key
$XDG_STATE_HOME/shbox/lock
$XDG_STATE_HOME/shbox/runtime/
```

通常の XDG fallback は `xdg` crate に従う。

### 8.1 Directory safety

shbox が write する data/state/runtime directory は:

- real directory
- daemon effective UID 所有
- group/world writable でない
- symlink でない

ことを要求する。missing directory は owner-only mode で作成し validation する。

config directory は operator-provided input のため shbox は作成しない。存在する場合は同じ safety criteria で validation する。

### 8.2 Files

host key、lock file、key source、config はそれぞれ専用 validation を持つ。unsafe ownership/mode/symlink は operational startup/auth failure であり、黙って chmod/chown して信頼境界を変えない。

## 9. Authentication key sources

二つの public-key source を使う。

- daemon account の `~/.ssh/authorized_keys`: admin/host-mode source
- `$XDG_CONFIG_HOME/shbox/allowed_keys`: sandbox-only source

両方に同じ key が存在すれば admin role を得る。key source は maximum 1 MiB、各 line maximum 8 KiB。

accepted key syntax は bare Ed25519 authorized-key line。authorized-key options、certificate、他 algorithm は拒否する。

key sources は authentication request ごとに identity を再確認する。invalid update では previous valid snapshot を保持して fail closed にし、SIGHUP は再検証を強制する。

## 10. Startup behavior

config snapshot と account/shell/key paths の validation 後、backend-neutral launch policy を構築し production launcher を preflight する。

OS confinement prerequisite が利用できない場合、daemon 自体は metadata/host-mode recovery のため起動できるが sandbox launch は `UnavailableLauncher` を通じて fail closed になる。unconfined host execution へ downgrade しない。

## 11. CLI layering

CLI は top-level operational fields だけを override する。

```text
--listen ENDPOINT   repeatable; config listen を置換 (tcp://ADDR または ws://ADDR/PATH)
--log-level LEVEL   config log_level を置換
```

sandbox shell/network/read paths/environment の CLI option は存在しない。

`--completions` と `--man` は output action であり daemon を起動しない。

## 12. 関連文書

- [architecture.md](architecture.md) — snapshot と launcher boundary
- [platforms.md](platforms.md) — Linux/macOS policy mapping
- [security.md](security.md) — environment/path trust boundary
- [testing.md](testing.md) — schema/property/native tests
