# Testing と release gate

この文書は、shbox の実装を v0.1 の契約として認めるための試験計画と検証記録である。unit/state test と実 OpenSSH harness の手元証跡は更新済みで、Linux aarch64 の実 Arapuca と delegated cgroup を必要とする同等 gate も native arm64 Docker で検証済みである。組合せごとのログと revision を保存し、full passing run のあるものだけを正式対応とする。

## 1. 試験の基本方針

- Rust の unit/property test だけで完了とせず、実 OpenSSH client と実 Arapuca process を使う。
- remote input に起因する通常エラーは server panic にならないことを確認する。内部 invariant violation の panic は仕様上許容するが、location/backtrace を structured log に残して daemon を abort する。
- テストごとに一時 XDG config/data/state/runtime directory と専用 Ed25519 key を用意し、実ユーザーの鍵、HOME、workspace、秘密情報を使わない。
- macOS と Linux の isolation を同じ強度だと見なさない。OS 固有の「適用済み」「best effort」「非対応」を結果に記録する。
- network は `disabled` と unrestricted `outbound` の二つを試験する。inbound service、forwarding、host filtering を製品機能として扱わない。各 platform の bind/listen behavior は security boundary として合否判定せず、実態を記録する。

## 2. 正式 support matrix

release gate は OS/architecture/version の tuple 単位で判定する。mutable な `macos-latest` だけでは version を特定できないため、runner は固定し、各試験の冒頭で実際の version と architecture を出力する。

| 組合せ | 初期扱い | gate |
|---|---|---|
| Linux `x86_64` | 正式対応候補 | 専用 delegated cgroup scope 上で全必須 suite を通過 |
| Linux `aarch64` | local equivalent verified / formal support unclaimed | native arm64 Docker 上で全必須 suite を通過。hosted formal artifact は作成しない |
| macOS 15 `arm64` | 初期試験対象・正式対応候補 | `sandbox-exec`、PTY/raw mode、resize、cleanup を含む全必須 suite を通過 |
| macOS 26 `arm64` | 初期試験対象・正式対応候補 | 同上。runner image/version を記録し、将来 version を自動包含しない |
| macOS `x86_64` | 未検証・非対応 | upstream の cross-build だけでは gate を満たさない |
| Windows / その他 | 非対応 | v0.1 gate の対象外 |

Arapuca は package version `0.2.7` の次の git revision を使う。

```text
c94802c4d8b6b880334c0d643b16b7326ec7f039
```

この revision は v0.2.7 tag 後の macOS PTY ioctl と `/var` traversal 修正を含む未リリース tip である。テスト結果には Cargo.lock の Arapuca revision、Rust version、OpenSSH version、kernel/OS version を記録する。

正式対応を名乗るには、対象 tuple の build、unit、integration、fault、hostile suite が全て通過しなければならない。環境を用意できない組合せは「未検証」とし、対応済みとは記載しない。

## 3. 外部試験環境

### 3.1 共通

最低限、次を試験環境に用意する。

- Rust MSRV 1.91 と stable の両方。CI は少なくともこの二つで `cargo test --locked` を実行する。
- OpenSSH client (`ssh`, `ssh-keygen`)。russh の server と別 process として接続する。
- Arapuca の git revision を取得できる Cargo 環境。
- Ed25519 の試験鍵、admin 鍵、非 owner 鍵、未登録鍵。
- loopback の一時 TCP port を listen する shbox 設定。port 22 の privileged bind は CI に要求しない。

テスト用 authorized_keys は bare `algorithm base64 [comment]` 形式だけを使う。options、証明書、非 Ed25519 key、malformed line を別ケースで検証する。鍵 fingerprint は exact public-key bytes の `SHA256:<unpadded-base64>` として比較する。

### 3.2 Linux

Linux の実 Arapuca suite は cgroups v2、`cpu`/`cpuset`/`memory`/`pids` controller の delegation、必要な kernel/wrapper capability が揃った service scope で実行する。shbox は起動時にその scope の下へ private child cgroup を作り、daemon PID だけを移動して Arapuca の stale cleanup 範囲を閉じる。child 作成・移動・controller 検証ができない場合は backend unavailable として扱う。次のような事前情報を artifact に保存する。

```console
uname -a
uname -m
cat /proc/self/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```

private child を作成できない runner では、cgroup を使う real integration を成功扱いにしない。Arapuca manager の startup cleanup が現在の child 以下の `arapuca-*` group を kill/remove し得るためである。必要な delegated scope の配備例は [platforms.md](platforms.md) を参照する。

### 3.3 macOS

macOS suite は固定された macOS 15 arm64 と macOS 26 arm64 で実行する。開始時に次を出力する。

```console
sw_vers
uname -m
sandbox-exec --version
```

`macos-latest` の label が指す version を遡って推測しない。Arapuca v0.2.7 tag 自体には PTY `file-ioctl` 修正がないため、Cargo の git revision が `c948...` であることを必ず検査する。macOS x86_64 は native runtime が未検証なので、cross-build の成功だけで gate を通さない。

## 4. Unit と domain test

### 4.1 入力・設定・認証

- Sandbox ID は `[A-Za-z0-9][A-Za-z0-9-]{0,63}`、case-sensitive。空、`_`、`.`、slash、Unicode、64 bytes 超を受理しない。内部 Arapuca task ID は `<id>-<32 lowercase hex>` とし、許可文字と 128-byte 上限を再検証する。
- host selector は `_` のみ。通常 key の `_` 認証、admin 以外の host shell/exec、通常 key の全件 list を拒否する。
- public-key authentication は Ed25519 のみ。none/password/keyboard-interactive と未知 key algorithm を拒否する。
- authorized_keys の blank/comment は無視し、options、certificate、malformed/unsupported line は設定エラーとする。
- admin fingerprint は authorized key と一致する必要があり、重複指定は設定エラーとする。
  admin 配列が空でも起動できるが、`--authorized-keys-host-access` が無ければ sandbox-only
  mode とする。flag を指定した場合は全 authorized key の host access を検証する。
- config file は任意。欠落時は built-in default、存在時は typed TOML の unknown field/型/範囲エラーを拒否する。SIGHUP の失敗は旧設定を保持する。
- managed env、`ARAPUCA_*`、loader injection、NUL、非 UTF-8、4 KiB 超の environment value を拒否する。client の env request は Sandbox に渡さない。
- `--network disabled|outbound`、`--log-level error|warn|info|debug|trace` の enum 以外、
  `--listen` の重複、config file の operational option/resource cap/limit field を拒否する。

### 4.2 Metadata と lifecycle

- metadata version は v1 のみ。未知 version は list/delete の対象から隠し、自動 migration や自動修復をしない。
- metadata state は `Active` または `Deleting`。作成中の claim は内部 state として管理し、metadata は atomic temp write、file fsync、rename、parent fsync の順で公開する。
- owner は public key の SHA-256 fingerprint 一個。最初の atomic claimant が所有し、競合した claimant は存在を開示しない generic error を受ける。
- `Active` だけを list の snapshot に含め、owner は自分のもの、admin は全件を bytewise ASCII 昇順で取得する。create/delete の途中結果を list に混ぜない。
- absent/non-owner の delete は stdout/stderr 空、exit 0 の idempotent no-op。実際の I/O、permission、cleanup failure は non-zero とする。
- `Deleting` 中は新規 shell/exec を拒否し、同 ID は list から隠す。部分 delete 後も `Deleting` を残し、再 delete または startup reconciliation で retry できる。
- `Deleting` への durable 遷移後に crash した fixture は、startup reconciliation なら caller
  無しで、再 delete なら保存済み owner または admin だけが state を再書込みせず cleanup を
  再開する。通常の non-owner は存在を開示せず no-op のままとする。
- 成功した delete は workspace、metadata、全 target process/PTY を永久に削除する。trash、undo、backup は作らない。
- workspace 内の symlink は利用プログラムのデータとして許可するが、metadata/管理 entry の symlink と root 外への delete traversal は拒否する。

### 4.3 SSH channel semantics

- connection に認証済み principal/role と selector を保存し、channel ごとに PTY/process を保持する。同一 connection の複数 channel は許可する。
- 一 channel で shell/exec/subsystem を二度受け付けない。list/delete は PTY request 付きでは拒否する。
- `pty-req` の rows/columns、[SSH protocol 仕様](ssh-protocol.md) が列挙する POSIX
  terminal modes、`window-change` の rows/columns を channel state に保存する。各 mode の
  on/off/control-character 値を検証し、未知 mode/pixel dimensions は副作用なく無視する。
- 非 PTY の stdout/stderr は分離し、PTY では terminal stream に統合する。client EOF
  後も process output と exit status は継続する。非 PTY は stdin pipe を閉じ、PTY は
  新規入力を止めるだけで child EOF を保証せず、synthetic `VEOF` を注入しない。
- process 完了時は output、SSH EOF、exit-status/exit-signal、channel close の順序を検証する。transport/request failure は client から 255 相当として観測される。
- process を持たない list/delete も、成功・失敗・absent/no-op の全経路で output、server EOF、
  exit-status、channel close の順に完了し、OpenSSH client が待ち続けない。
- PTY のない channel への `window-change` は response・state change・process side effect なしで
  無視し、その channel と connection の後続 operation を壊さない。
- `pty-req` 後、shell/exec 前の `window-change` は保存した desired size を更新する。fake
  launch barrier 中の複数 resize も含め、bridge-ready になる時点で最後の non-zero
  rows/columns が適用され、古い request が後勝ちで上書きしない。
- host mode の shell/exec/PTY/resize/signal は admin `_` のみ。SFTP、agent/X11/direct-tcpip/streamlocal forwarding は reject する。legacy SCP command は通常の exec と同じ扱いであり、互換性を保証しない。

## 5. Property、fault、race test

### 5.1 Property test

次の純粋な domain function に対して property test を書く。

- Sandbox ID validation、task ID suffix の 128-byte 上限、random suffix の再試行。
- TOML の unknown field、limit、environment、path、admin fingerprint の validation。
- metadata encode/decode、version rejection、owner fingerprint の round-trip。
- connection role、selector、channel state の遷移と、PTY/list/delete の組合せ。
- list の sorted unique snapshot と owner/admin filter。

SSH packet format 自体の custom fuzzer は作らない。transport framing と protocol parser は russh に委ね、shbox 独自の request/state mapping を property test する。

### 5.2 Fake launcher と fault injection

private `ProcessLauncher` seam に barrier、遅延、指定エラーを持つ fake を実装する。少なくとも次を決定的に再現する。

- 同じ ID の二つの create が一つだけ owner/workspace を claim する。
- sandbox count が上限に達していても既存 Active sandbox の shell/exec は再利用でき、新しい
  ID だけが拒否される。失敗した create reservation は上限を消費し続けない。
- 異なる ID は並列に進み、同じ ID だけが直列化される。
- create と delete、attach と delete、SIGHUP と新規 launch の race。
- `Launching` marker の publish 直後、OS spawn 中、spawn 成功直後の各 barrier で delete を開始し、
  cancel または即時回収によって process と reservation が一つも残らないこと。
- process spawn 後の metadata failure、workspace failure、PTY/ioctl failure、stdout/stderr channel close。
- graceful stop の 5 秒 deadline と force stop、partial delete の `Deleting` 保持。
- startup reconciliation の retry、corrupt/missing metadata の quarantine/非表示。
- process 出力が bounded buffer を超えたときの backpressure と cleanup。

### 5.3 Filesystem test

実 filesystem の一時 XDG tree を使って、owner/mode、atomic rename、parent fsync、no-follow
path、root 外 symlink、二つの advisory lock、再起動後の metadata/workspace 復元を検証する。
同じ data root と別 state/listener、同じ state root と別 data/listener の各組合せで第二 daemon
が起動できないことも確認する。filesystem trait を production abstraction にしない。
破損・権限変更・プロセス kill は test fixture が明示的に作る。

## 6. OpenSSH integration suite

test harness は shbox を一時 config で起動し、実 `ssh` client から接続する。以下は代表的な command 例であり、`$PORT`、`$OWNER_KEY`、`$ADMIN_KEY` は harness が作る。

リポジトリに含まれる現在の OpenSSH harness は、次のコマンドで実行する。stable と MSRV
1.91 の各 full test run で unit/state 113 件、harness 21 件が通過する（Linux target では
Linux-only crash test を含むため 22 件）。うち M8 の real
Arapuca cases 6 件は `SHBOX_RUN_ARAPUCA_INTEGRATION` を設定した platform gate でだけ実行し、
通常 run では fail-closed 側を安全に確認して終了する。loopback bind を
制限する環境では、`server::tests::bind_all_is_all_or_nothing` だけが権限エラーになるため、
release artifact を作る際は loopback bind を許可した runner で再実行する。

```console
RUSTC_WRAPPER= cargo test --locked --test ssh_auth -- --test-threads=1
RUSTC_WRAPPER= cargo +1.91.0 test --locked --test ssh_auth -- --test-threads=1
```

Linux の通常 OpenSSH test は、wrapper と delegated cgroup がない開発環境でも安全性を検証できるよう、sandbox request が status 111 の generic failure になることを既定の合格条件にする。Linux で実 Arapuca の成功経路を試験する場合だけ `SHBOX_RUN_ARAPUCA_INTEGRATION=1` を test process と daemon に継承させ、sandbox exec が status 0 と期待 output を返すことを要求する。macOS arm64 は shbox 自身の embedded rlimit wrapper を使うため、通常の OpenSSH test が Seatbelt の成功経路を実行する。両方の結果を一つの `or` 条件で合格扱いにしてはならない。

### 6.1 exec、ownership、list、delete

```console
ssh -F /dev/null -T -i "$OWNER_KEY" -p "$PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  dev@127.0.0.1 'printf hello'

ssh -F /dev/null -T -i "$OWNER_KEY" -p "$PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  dev@127.0.0.1 'printf out; printf err >&2; exit 7'

ssh -F /dev/null -T -s -i "$ADMIN_KEY" -p "$PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  _@127.0.0.1 list

ssh -F /dev/null -T -s -i "$OWNER_KEY" -p "$PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  dev@127.0.0.1 list

ssh -F /dev/null -T -s -i "$OWNER_KEY" -p "$PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  dev@127.0.0.1 delete
```

検証内容:

- 初回 exec が lazy create し、stdout/stderr と exit 7 がそれぞれ観測できる。
- owner list は自分の ID だけ、admin list は全 Active ID を LF 区切りの ASCII 昇順で返す。
- `_` は admin key でだけ list できる。通常 key の `_`、admin 以外の全件 list、non-owner delete は存在を開示しない。
- absent delete は空出力 exit 0。成功 delete 後は list から消え、再接続で新規 claim になる。
- list/delete に PTY を要求すると generic failure になり、shell/exec channel は作られない。

### 6.2 shell、PTY、resize、EOF

次の OpenSSH command は手動診断には使えるが、target が post-launch ioctl より先に
`stty` を実行し得るため、初期 size の合否判定には使わない。

```console
ssh -F /dev/null -tt -i "$OWNER_KEY" -p "$PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  dev@127.0.0.1 'printf "$(stty size)\\n"'
```

合否用の protocol-aware PTY driver は `pty-req` の後に shell request の success を待ち、
server が size/modes を適用して I/O bridge を公開してから `stty` 相当の probe を送る。
その上で次を OpenSSH channel 上で実測する。

- rows/columns と terminal modes が I/O bridge 開始後の shell に反映される。
- size/mode ioctl の失敗時は process を cleanup し、部分適用した PTY を client へ公開しない。
- 固定 Arapuca revision では target spawn 前の反映を保証できないことを回帰 test と
  release note で可視化する。target の最初の命令が request 値を必ず観測する test は
  v0.1 の合格条件にしない。
- rows または columns の一方だけが `0` の request は、その dimension だけを変更せず、
  非 `0` の dimension は反映する。両方 `0` でも fallback size を `0x0` にしない。
- `pty-req` と shell request の間に `window-change` を送り、shell success 後の probe が
  最新の desired size を観測する。launch barrier と resize の race でも更新を失わない。
- `window-change` で rows/columns を変更すると `stty size` 相当の結果が変わる。
- raw mode、Ctrl-C/known signal、terminal output の統合が動く。
- 非 PTY の `cat` は client EOF で終了し、その後の output/status が届く。PTY では
  client EOF 後も child に synthetic byte/hangup が届かず、別途出力でき、明示的な
  close/disconnect で cleanup される。
- disconnect は該当 channel の process/PTY だけを終了し、workspace は保持する。
- 同一 Sandbox の複数 channel が独立 PTY/process となり、互いの terminal state を共有しない。

単なる remote command の成功だけを PTY/resize の証拠にしない。`window-change` を送れる PTY driver または OpenSSH integration harness を使う。

### 6.3 host mode

admin key で `ssh _@host` の shell、remote exec、PTY、resize、signal を試し、実行 user、login shell、HOME、service environment を確認する。sandbox profile の HOME、workspace、network 制限が host mode に漏れないこと、通常 key では `_` が認証/selector として使えないことを併せて確認する。秘密を含む service environment を試験 fixture に置かない。

## 7. 実 Arapuca integration suite

全正式 tuple で、fake launcher だけでなく固定 revision の実 Arapuca を呼ぶ。

### 7.1 共通 process/workspace

- `HOME` と `PWD` が対象 workspace に対応し、shell/exec の process が workspace の外へ metadata/他 Sandbox を書けない。
- client env が process に混入せず、shbox の Sandbox env が全 launch に一貫して渡る。
- `disabled` では outbound socket/DNS が拒否され、`outbound` では controlled endpoint への TCP/UDP/DNS が利用できる。shbox が inbound port mapping や SSH forwarding を作らないことを確認し、各 platform で bind/listen が可能かを測定して artifact に残す。egress-only enforcement の合格条件にはしない。
- max open files=1024、Linux max pids=256 の既定が適用され、0 の limit は無制限として扱われる。OS が提供しない limit を適用済みと表示しない。
- 同一 workspace への concurrent read/write、separate process、task ID suffix、監査 correlation を検証する。
- shell/exec の正常終了、signal 終了、5 秒 graceful deadline、force kill、descendant cleanup を検証する。

### 7.2 Linux 固有

- Landlock/seccomp、workspace path、curated system read path、loader/shell の execute が実際に機能する。
- delegated cgroup に memory/pids/cpu limit を作成し、同一 Sandbox の複数 process が task ID collision なしで動く。
- disconnect、delete、daemon shutdown、daemon crash のいずれでも cgroup/process group の descendants が SLA 内に消える。
- cgroup manager の起動時 cleanup が他 process を kill しない専用 scope 条件を確認する。

### 7.3 macOS 固有

- macOS 15/26 arm64 の各 runner で Seatbelt deny-default、workspace read/write、curated system path、shell/loader を実測する。
- PTY の `/dev/ttys*` ioctl、raw mode、`tcgetattr/tcsetattr`、window resize を検証する。これは `c948...` 修正が実際に利用されていることの確認も兼ねる。
- `/var` symlink traversal を必要な read case で検証する。
- memory/RSS monitor、rlimit、process group cleanup を測定し、Linux cgroup quota/PID limit と同一視しない。
- delete、disconnect、shutdown、daemon crash 後に descendants が残らない hard contract を検証する。失敗した OS version は正式対応から外す。

## 8. Crash、reload、hostile suite

### 8.1 Crash と restart

- shell/exec 中の daemon を SIGKILL し、child process/PTY が 5 秒以内に終了する。
- metadata と workspace は残り、再起動後に Active Sandbox と owner が復元される。
- 起動時の metadata 未 publish の partial create、`Deleting`、corrupt metadata、missing workspace、symlink entry を list/delete が安全に扱う。
- graceful SIGINT/SIGTERM は新規接続を止め、最大 5 秒で全 runtime process を cleanup し、workspace を削除しない。二回目の signal は即時停止する。

### 8.2 Reload

- SIGHUP で authorized_keys、admin_keys、shell、Sandbox env、read paths だけが atomic に更新
  される。CLI の listener/network/log-level/host-access と built-in limits/caps は変わらない。
- config 無しの defaults で起動した後に config file を作ると valid SIGHUP で採用される。一度
  file を採用した後に削除すると reload failure になり、旧 snapshot を保持する。
- 新しい connection/process には新設定、既存 connection には元の role/rights を適用する。
- 認証ファイル/config が壊れている、または使用中の config が消えた場合は旧設定を保持する。最後の admin を削除する valid reload は適用し、sandbox-only mode に遷移する。
- listen socket は reload せず、CLI の変更には restart を要求する。旧 field を config に追加した
  reload は unknown field として拒否する。
- admin を削除しても既存 admin connection は disconnect まで維持し、新規 admin connection は拒否する。

### 8.3 Hostile input

malformed/oversized sandbox ID、username `_`、unknown subsystem/request、PTY pixel/mode、abrupt EOF、auth probe、unsupported key、malformed TOML/authorized_keys、path traversal、management symlink、environment injection、large continuous output を投入する。期待する結果は、接続単位の generic error/拒否、bounded resource、対象 process cleanup、server process の継続である。

forwarding、X11、agent、SFTP、direct-tcpip、streamlocal request は明示 reject し、default accept に依存しない。legacy SCP の command 名を protocol request と誤認せず、通常 exec として扱う。

## 9. 実行コマンド例と artifact

実装後の基本 gate は次のように実行する。

```console
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets -- --test-threads=1
cargo test --locked --test ssh_auth -- --test-threads=1
```

Arapuca が取得できない、cgroup delegation がない、macOS runner version が想定外、OpenSSH client がない場合は integration job を成功扱いにしない。代わりに「環境 prerequisite 未達」として記録する。

各 job は少なくとも次を artifact として保存する。

- git commit、Cargo.lock の Arapuca URL/revision/package version、Rust/Cargo version
- OS version、kernel version、architecture、OpenSSH client version
- shbox config の redact 済み validation summary（鍵本体、command、terminal I/O は含めない）
- test output、exit status、process/cgroup cleanup の観測結果
- failure 時の generic client output と host log の対応する connection/channel ID

## 10. Release gate checklist

```text
[ ] Rust 1.91 と stable の fmt/clippy/unit/property test が通る
[ ] Linux x86_64 の実 OpenSSH + 実 Arapuca suite が専用 delegated scope で通る
[ ] Linux aarch64 の実 OpenSSH + 実 Arapuca suite が通る
[ ] macOS 15 arm64 の PTY/raw-mode/resize/cleanup suite が通る
[ ] macOS 26 arm64 の PTY/raw-mode/resize/cleanup suite が通る
[ ] owner/admin/host selector/_/non-disclosure の認証 matrix が通る
[ ] list/delete/partial create/Active/Deleting/再起動の lifecycle が通る
[ ] disabled/outbound network の両方が通る
[ ] disconnect/delete/shutdown/crash の descendant cleanup が通る
[ ] reload、config/auth failure、hostile input が server panic なしで通る
[ ] bounded buffer/backpressure と全 cap が通る
[ ] 未検証の OS/architecture/version を正式対応表に含めていない
```

## 11. 一次情報

- [Arapuca v0.2.7 README / requirements](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/README.md)
- [Arapuca Linux platform](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/platform/linux.rs)
- [Arapuca cgroup manager](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/cgroup.rs)
- [Arapuca process API](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/process.rs)
- [Arapuca Darwin platform](https://raw.githubusercontent.com/LeGambiArt/arapuca/v0.2.7/src/platform/darwin/mod.rs)
- [Arapuca cumulative macOS fixes](https://github.com/LeGambiArt/arapuca/commit/c94802c4d8b6b880334c0d643b16b7326ec7f039)
- [Arapuca v0.2.7 release](https://github.com/LeGambiArt/arapuca/releases/tag/v0.2.7)
- [russh server Handler](https://docs.rs/russh/0.63.1/russh/server/trait.Handler.html)
- [OpenBSD ssh(1) manual](https://man.openbsd.org/ssh)
- [RFC 4254: SSH connection protocol](https://www.rfc-editor.org/rfc/rfc4254)
- [xdg `BaseDirectories`](https://docs.rs/xdg/3.0.0/xdg/struct.BaseDirectories.html)
