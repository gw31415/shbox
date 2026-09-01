# shbox 設定仕様

この文書は v0.1 の公開 TOML schema、CLI override、XDG layout、built-in concurrency cap を定義する。backend 固有 option や sandbox CPU/memory/PID/file quota は公開設定ではない。

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

# 追加 read-only path。単一 string も一要素配列として受理する。
# 省略時: []
read_paths = ["/opt/toolchain"]

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
| `disabled` | sandbox network access を blocking policy で拒否する。default。 |
| `outbound` | ordinary network socket use を許す。port allowlist/proxy policy ではない。 |

Linux/macOS の enforcement 差は [platforms.md](platforms.md) を参照する。

`outbound` は isolation を弱めるため startup log で operator に警告する。外部到達範囲をさらに制限したい場合は host/provider firewall を併用する。

### 4.3 `read_paths`

sandbox process に追加で read-only access を与える absolute path。single string または string array。

validation:

- absolute path 必須
- NUL 禁止
- startup 時に存在して canonicalize できること
- duplicate canonical path 禁止
- shbox config/data/state roots 自身やその subtree を expose しないこと

この値は write permission を与えない。workspace/private launch temp の write grant は request-local policy からのみ作る。

OS が ordinary command runtime に必要とする system/runtime path は implementation の curated set として別途追加され、public config には列挙しない。

### 4.4 `[sandbox.env]`

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
TMPDIR=<unique private launch directory>
```

PTY request 時:

```text
TERM=<pty-req term>
```

これらは `[sandbox.env]` より authoritative であり shadow できない。

private `TMPDIR` は launch ごとに unique、owner-only directory とし、launch cleanup で recursive に削除する。host-wide `/tmp` を writable sandbox path として自動 grant しない。

## 6. Built-in concurrency caps

以下は config field ではなく daemon の built-in admission/safety caps である。

| cap | default |
|---|---:|
| unauthenticated connections | 32 |
| total connections | 128 |
| channels per connection | 16 |
| concurrent sandbox processes | 128 |
| concurrent host-mode processes | 16 |
| auth attempts per connection | 6 |
| total sandboxes | 1024 |
| sandboxes per owner | 128 |
| SSH handshake timeout | 30 s |

これらは admission/concurrency limit であり、sandbox 内の process に CPU quota、memory ceiling、PID tree quota、file-size/open-file quota を設定する resource-control feature ではない。

## 7. Sandbox resource limits は提供しない

v0.1 の shbox sandbox policy には次の per-launch/per-sandbox resource quota はない。

- CPU percentage/quota
- memory/RSS ceiling
- process/PID count quota
- file-size quota
- open-file quota
- workspace disk quota

operator が systemd、container runtime、VM/provider、OS account policy などで service-level resource controls を設定することは可能だが、それは shbox public sandbox contract ではない。

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
