# SSH protocol 仕様

`shbox` の外部 API は SSH だけである。本書は RFC 4254 の session/channel
semantics と、そこへ shbox の sandbox selector、admin host selector、list/delete
を割り当てる方法を定義する。独自 packet、独自 client、HTTP、WebSocket は作らない。

本書の例で `host` は SSH server の hostname、`<id>` は有効な SandboxId を表す。
SSH username は OS login username ではない。

## 1. 接続、認証、channel

### 1.1 connection-scoped state

SSH username と public-key authentication は接続単位で確定する。認証成功後の
russh Handler は、fingerprint、role、認証時 username を保持する。同じ connection
上の複数 session channel はその principal を共有する。

connection は次の状態を持つ。

```text
Transport
  -> Authenticating
  -> Authenticated { fingerprint, role, username }
  -> Closing
  -> Closed
```

public key の署名検証を伴う authentication のみを accept し、none/password/
keyboard-interactive や Ed25519 以外は reject する。authentication timeout は
30 秒、最大 authentication attempts は 6 回である。認証済み connection に
idle timeout は設定しないが、全接続数と channel 数の cap は継続して適用する。

`SIGHUP` で認証設定が reload されても、既存 connection の role は変わらない。
key が削除された既存 admin connection も disconnect まで admin として動く。新規
connection は reload 後の key 一覧で認証する。

### 1.2 channel-scoped state

v0.1 で開ける channel は session channel だけである。1 connection あたり最大
16 channel。各 channel は独立した PTY/process と stdin/stdout/stderr bridge を
持つ。

```text
Opening -> Open -> Running(operation) -> Draining -> Closed
```

channel state に次を記録する。

- PTY の有無、TERM、現在の rows/columns、terminal modes。
- operation が `shell`、`exec`、`list`、`delete` のどれか。
- stdin の open/EOF、process handle、終了結果、close 状態。

一つの channel で成功できる shell、exec、subsystem は一つだけである。`pty-req`
は operation より前にだけ受け入れる。開始済み channel に対する別の
shell/exec/subsystem、重複 pty request、その他の順序違反は channel failure とする。
`window-change` だけは例外で、`pty-req` を受けていない channel では response も副作用も
なく無視する。`pty-req` 済みなら、process launch の前でも後でも次節の desired size を
更新する。
別 channel なら同じ connection、同じ sandbox で並列に実行できる。

### 1.3 接続数と入力上限

既定 cap は次のとおりであり、設定可能な cap も daemon 全体で適用する。

| 項目 | 既定値 |
|---|---:|
| 未認証 connection | 32 |
| 全 connection | 128 |
| session channel / connection | 16 |
| sandbox process（全 sandbox 合計） | 128 |
| host process | 16 |
| auth attempts | 6 |
| exec command | 32 KiB |
| terminal type (`TERM`) | 256 bytes |
| subsystem name | 64 bytes |

さらに authorized key の 1 行は 8 KiB、file は 1 MiB、config は 1 MiB、metadata
は 16 KiB までとする。上限を超えた入力は、入力を切り詰めず request failure と
して処理する。channel data と process output は bounded buffer と SSH window
flow control を使い、client が遅い場合に daemon が無制限に memory を確保しない。

## 2. selector と role routing

### 2.1 normal sandbox mode

通常の username は、認証時にはそのまま受け入れ、shell/exec/delete の request
開始時に次の SandboxId へ validation する。

```text
[A-Za-z0-9][A-Za-z0-9-]{0,63}
```

case-sensitive であり、空文字、`_`、`.`、`/`、空白、制御文字、Unicode は拒否
する。通常 key は自分が owner の sandbox だけを shell/exec/delete できる。
他 owner の ID を指定した場合、存在を推測できない一般的な拒否を返す。

通常 key の `list` は username を sandbox selector として使わず、認証 fingerprint
が owner である sandbox の一覧だけを返す。したがって list の username は任意の
通常 username でよい（ただし `_` は admin context）。実装・運用では明示的に
`<id>@host` を指定する方が client の default username に依存しない。

### 2.2 `_` host mode

`_` は host selector として予約される。

- 通常 key の `_` authentication は拒否する。
- admin key の `_` は sandbox selector ではなく host context になる。
- host context で shell、exec、PTY、window-change、signal を使える。
- host context では list は admin の全 sandbox を対象にできる。
- `_` を delete の対象にしてはならない。admin も通常の SandboxId を username
  にして delete する。

admin key は全 sandbox の shell/exec/list/delete と `_` host mode の両方を持つ。
host 専用の別 role はない。admin key が一つも設定されていない場合、`_` route は
認証されず、server は sandbox-only mode で動く。

## 3. client command mapping

### 3.1 shell

PTY 付き対話 shell:

```console
ssh -tt <id>@host
```

PTY なしの対話 shell も許可する。

```console
ssh -T <id>@host
```

admin host shell:

```console
ssh _@host
ssh -tt _@host
```

`ssh host` のように username を省略した場合、OpenSSH は匿名 username を送る
のではなく、client の既定 username を送る。その値が通常の selector として有効
かどうかは request 時に判定される。

### 3.2 remote exec

```console
ssh <id>@host '<command>'
ssh -t <id>@host '<command>'
ssh _@host '<command>'
```

通常 key は owner sandbox 内、admin の `_` は host、admin の通常 ID は任意の
sandbox 内で実行する。exec に PTY が付けば PTY stream semantics、付かなければ
pipe semantics を使う。

### 3.3 `list` subsystem

通常 key の owner 一覧:

```console
ssh -s <id>@host list
```

ここで `<id>` は list の filter ではない。認証 key の owner filter が使われる。
admin の全件一覧:

```console
ssh -s _@host list
```

`list` は PTY を要求してはならない。成功時は次の plain text を stdout に出す。

- 1 ID 1 行、各行の末尾は LF。
- header、JSON、色、余分な空白はない。
- bytewise ASCII 昇順で重複なし。
- 有効な `Active` metadata だけを対象にする。
- 通常 key は owner の sandbox、admin は全 sandbox。
- 0 件なら stdout は 0 bytes、exit status は `0`。

list の snapshot は request 開始時点に近い一貫した読み取りでよい。create/delete
を待って全体を停止しない。metadata 未 publish の partial create、`Deleting`、
corrupt/missing metadata は一覧に出さない。

一覧 bytes を送り終えたら、server-to-client EOF、exit-status `0`、channel close の順で
必ず完了する。失敗時も、送信する一般化済み stderr があればそれを先に送り、EOF、non-zero
exit-status、close の順で完了する。

### 3.4 `delete` subsystem

通常 key が自分の sandbox を削除する場合:

```console
ssh -s <id>@host delete
```

admin も同じ形式で任意の通常 SandboxId を削除する。

```console
ssh -s other-id@host delete
```

次は常に拒否する。

```console
ssh -s _@host delete
```

`delete` は PTY を要求してはならない。処理は per-ID lock の下で metadata を
`Deleting` にし、対象 sandbox の process、PTY、関連 channel を停止・close し、
workspace と metadata を永久削除する。SSH connection 全体ではなく対象 workload channel
だけを閉じる。delete request の管理 channel 自体は、下記の結果通知が完了するまで閉じない。

対象が存在しない、または通常 key が owner でない場合は、存在を開示しないため
stdout/stderr を空にして exit status `0` の idempotent no-op とする。invalid
SandboxId、PTY付き、unknown request、実際の削除障害は一般的な failure とし、
内部 path や owner を返さない。`Deleting` 中の同じ ID は list に出ず、新しい
shell/exec は削除完了まで拒否する。失敗した delete は `Deleting` のまま残り、
owner/admin の再試行または起動時 reconciliation の対象にできる。

delete の結果も、一般化済み output があればそれを送った後、server-to-client EOF、
exit-status、channel close の順で完了する。成功および absent/non-owner no-op の status は
`0`、実際の失敗は non-zero であり、どの経路でも request channel を開いたまま残さない。

### 3.5 subsystem に引数はない

SSH subsystem request は argv の配列ではなく、1 個の name string である。OpenSSH
client は positional command arguments を空白で連結して送るため、次は `list`
に引数を渡す呼び出しではない。

```console
ssh -s _@host list extra
```

wire 上の subsystem name は `list extra` となり、未知 subsystem として拒否する。
v0.1 では list/delete の追加オプションや独自 parser を定義しない。

## 4. shell と command の意味

### 4.1 shell の選択

設定の `[sandbox] shell` が指定されていればその absolute executable path を使う。未設定
なら daemon OS user の passwd entry にある login shell を使い、entry が空の場合だけ
`/bin/sh` を fallback とする。選ばれた非空 path が存在しない、通常 file でない、または
実行できない場合は startup/reload error とする。host mode でも同じ daemon account の
login shell と home cwd を使う。`/bin/sh` は常に強制する値ではない。

### 4.2 interactive shell

shell request は channel あたり一度だけ受け入れる。shell を login mode で起動
するため、OpenSSH の session shell に近い `argv[0]` の login-shell semantics
（basename の先頭に `-`）を使う。shell option を勝手に追加して、各 shell に
固有でない mode を要求してはならない。

sandbox mode では `HOME` と `PWD` をその sandbox の workspace にし、`SHELL` を
選択した shell にする。clean environment 以外の client environment は取り込ま
ない。host mode の初期 cwd は daemon account の home だが、environment は `HOME` を
含め daemon service environment を変更せず継承する。operator は両者を整合させる。

### 4.3 remote exec

SSH `exec` request の command は raw byte string であり、argv 配列ではない。
OpenSSH の positional arguments は client 側で一つの文字列に連結される。

shbox はその文字列を分割・再解釈せず、選択した shell に次の形で渡す。

```text
<selected-shell> -c <raw-command>
```

remote exec は login mode ではない。これは OpenSSH の remote command と同じく、
login shell を選択しても `-c` invocation で実行するためである。従って quote、
pipe、redirect、shell builtin の意味は選択された shell の `-c` semantics に従う。
argv を直接指定する API や、独自の shell parser は提供しない。

command payload は最大 32 KiB で、NUL を含めない。Linux/macOS の Unix byte string
としてそのまま shell の `-c` argument へ渡し、UTF-8 であることは要求しない。
文字 encoding の解釈は選択された shell と locale に従う。command text は log に
保存しない。

## 5. PTY、terminal mode、resize

### 5.1 `pty-req`

PTY request は shell/exec の前に一度だけ受け入れる。request の fields は次の
ように扱う。

| field | shbox の扱い |
|---|---|
| TERM | 最大 256 bytes、NUL なしで process の `TERM` に設定 |
| columns/rows | process launch 後、最初に設定する PTY window size として保存 |
| pixel width/height | 保存・強制せず無視 |
| encoded terminal modes | POSIX の主要 mode を反映し、未知 mode は無視 |

RFC 4254 に従い、dimension が `0` の場合はその dimension を ignore する。PTY を
作れない OS/backend、invalid TERM、または上限超過は channel failure とする。

「主要 mode」は、対象 OS の termios が提供する次の RFC mode を最低集合とする。

- control characters: `VINTR`, `VQUIT`, `VERASE`, `VKILL`, `VEOF`, `VEOL`, `VEOL2`,
  `VSTART`, `VSTOP`, `VSUSP`
- input flags: `IGNPAR`, `PARMRK`, `INPCK`, `ISTRIP`, `INLCR`, `IGNCR`, `ICRNL`,
  `IXON`, `IXANY`, `IXOFF`
- local flags: `ISIG`, `ICANON`, `ECHO`, `ECHOE`, `ECHOK`, `ECHONL`, `NOFLSH`,
  `TOSTOP`, `IEXTEN`
- output flags: `OPOST`, `ONLCR`, `OCRNL`, `ONOCR`, `ONLRET`
- control flags: `CS7`, `CS8`, `PARENB`, `PARODD`
- speed: `TTY_OP_ISPEED`, `TTY_OP_OSPEED`

対象 OS に存在しない mode、RFC で予約された未知 opcode、pixel dimensions は副作用なく無視する。
boolean flag は値 `0` を off、非 `0` を on として適用する。

Arapuca Process API に高水準 resize operation はないため、内部 adapter が Unix
PTY master に OS の window-size ioctl と terminal mode 操作を行う。ただし固定
revision の公開 API は、target を spawn した後にしか PTY master を caller へ返さない。
v0.1 は trusted child launcher や Arapuca fork を導入しないため、rows/columns と
terminal modes は process launch 直後、I/O bridge の公開前に適用するが、target の
最初の命令より前に反映されることは保証しない。Arapuca が親 daemon の terminal size
を取得できればその値、取得できなければ `24x80` が短時間観測され得る。起動直後の
program が SSH request の値を必ず読む必要がある用途は v0.1 の非対応範囲である。
request 値の ioctl/terminal mode 適用に失敗した場合は process を cleanup し、shell/exec
request を失敗させる。部分適用した PTY を client へ公開しない。

macOS は PTY `file-ioctl` 修正を含む固定 revision で試験する。Arapuca の内部 task id
は外部 SandboxId と同一にせず、launch ごとに
`<sandbox-id>-<128-bit-random-hex>` を割り当てる。

### 5.2 stream semantics

PTY なしの process は SSH の channel data semantics を次のように bridge する。

```text
SSH channel data                 -> process stdin
process stdout                   -> SSH channel data
process stderr                   -> SSH extended data, type 1
```

PTY ありでは child の stdout/stderr は terminal stream に統合され、SSH channel
data へ送る。PTY mode で stdout と stderr の分離を約束しない。各方向は SSH
window/backpressure に従い、遅い client が daemon memory を無制限に消費しない。

### 5.3 `window-change`

`window-change` は channel ごとの desired rows/columns を更新する。対応は PTY lifecycle
によって次の三つに分ける。

- `pty-req` 未受理: response も state change もなく無視する。
- `pty-req` 受理済み、master 未生成: non-zero dimension だけを channel state に保存し、
  後続 launch で最新値を適用する。
- master 生成済み: non-zero dimension を state と PTY master の両方へ反映する。

launch と `window-change` は channel lifecycle 上で直列化する。launch 中に desired size が
変わった場合、adapter は最新 revision を master へ再適用してから shell/exec success と
I/O bridge を公開し、更新を取りこぼさない。pixel dimensions は保存・強制しない。RFC の
とおり通常は `want_reply=false` であり、success/failure response を返さない。

## 6. EOF、終了、signal、close

### 6.1 EOF と終了順序

client が channel EOF を送った場合は、既に受信した入力を drain した後、その channel
から新しい data を process へ送らない。stdout/stderr の読み取り、process の終了待ち、
exit status の転送は継続し、EOF だけで channel 全体を close しない。

非 PTY process では stdin pipe の writer を閉じるため、child は stdin EOF を観測する。
PTY process では write 用に duplicate した master FD だけを閉じ、出力読取り用と
lifecycle 保持用の master FD は残す。PTY slave の child が EOF や hangup を観測する
ことは保証しない。`VEOF` や `0x04` を合成してはならない。raw/noncanonical mode では
それらが EOF を意味せず、実際の client input を改変するためである。PTY 内の program
へ EOF 相当を伝えたい利用者は、terminal mode に応じた入力（canonical mode なら通常
Ctrl-D）を EOF request より前に送る。

process が正常終了したら、出力を drain してから次の順に channel を完了させる。

```text
remaining output
  -> server-to-client channel EOF
  -> exit-status
  -> channel close
```

POSIX の raw wait status を wire へ送ってはならない。process が通常終了した場合は、
adapter が `ExitStatus::code()` 相当で正規化した終了 code を non-negative `u32` へ変換し、
SSH `exit-status` として送る。signal 終了は次節の `exit-signal` とし、通常終了へ変換しない。
server が request を拒否した、transport が失敗した、または channel が通信不能になった
場合、OpenSSH client 側の status は通常 `255` となる。

### 6.2 signal

SSH `signal` request の名前を POSIX signal name に対応づけ、対象 process group
へ送る。認識できない signal name は実行せず request を拒否する。

v0.1 が受け付ける wire name は RFC 4254 の `ABRT`, `ALRM`, `FPE`, `HUP`, `ILL`,
`INT`, `KILL`, `PIPE`, `QUIT`, `SEGV`, `TERM`, `USR1`, `USR2` である。`SIG` prefix
付き、空文字、その他の name は拒否する。対象 OS が name に対応する signal を提供しない
場合も拒否する。

PTY で Ctrl-C などを入力した場合は入力 byte を PTY に渡し、PTY line discipline
に signal generation を任せる。Ctrl-C 用の独自 SSH request は作らない。

process が signal で終了した場合は exit-status ではなく RFC 4254 の `exit-signal`
を使う。signal name は `SIG` prefix なし、core dump flag は OS から判定できる値（不明なら
`false`）、error message と language tag は空文字にする。path、fingerprint、internal
error chain を含めない。

### 6.3 channel close と disconnect

client の channel close、transport disconnect、server shutdown は対象 channel
の process/PTY を graceful close する。最大 5 秒待っても終了しなければ process
group を force stop し、子孫を残さない。対象 channel 以外の同一 connection の
channel や、同一 sandbox の別 process は不必要に停止しない。

delete は対象 sandbox に属する全 channel/process を同じ規則で停止する。sandbox
自体の metadata/workspace は disconnect では消さず、明示 delete でのみ消す。

## 7. request validation と拒否

### 7.1 request の順序

典型的な session channel は次の順序で進む。

```text
channel-open(session)
  -> [pty-req]
  -> shell | exec | subsystem
  -> [data / window-change / signal / eof]
  -> drain / exit-status or exit-signal / close
```

`channel-open` は各 session で accept/reject を明示する。drop や未処理 callback
に任せない。`pty-req`、`shell`、`exec`、`subsystem`、`window-change`、`signal` の
各 callback は channel state と connection role を確認し、失敗時は russh の
channel failure semantics を使う。

### 7.2 subsystem

v0.1 の名前は `list` と `delete` だけである。名前は最大 64 bytes、引数はない。
未知名、追加文字、PTY 付き list/delete、開始済み channel の subsystem request
は拒否する。

### 7.3 拒否する request/channel

次の request/channel を accept しない。

- `env` request（client environment の注入）。
- agent/X11 forwarding、`direct-tcpip`、forwarded-tcpip、streamlocal forwarding。
- SFTP と未知の subsystem。legacy SCP の `scp -t`/`scp -f` は wire 上では通常の
  exec command なので、名前を特別判定せず他の exec と同じ規則で処理する。SCP の
  availability や互換性は保証しない。
- 一つの channel での二つ目の shell/exec/subsystem。
- 未知の channel request、未検証の signal、サイズ上限超過。

RFC 上 reply を要求しない request は不要な success response を返さない。reply が
要求された request に対しては、成功時 `channel_success`、拒否時
`channel_failure` を使用する。`window-change` は通常 `want_reply=false` で処理する。

## 8. stream backpressure と cleanup

process reader は `Handle::data` と `Handle::extended_data(type=1)` の送信結果を
確認する。channel closed、SSH window の停止、client disconnect は process reader
を永久に待たせない。非 PTY は stdin pipe、PTY は write 用 master duplicate を閉じ
（child EOF は保証しない）、該当 process の graceful cleanup へ進める。

stdout と stderr は wire 上別 message stream なので、PTY なしでは相互の厳密な
時間順序を保証しない。各 stream の順序と bytes は保持する。PTY ありでは terminal
stream の順序だけが意味を持つ。

process、PTY master、reader task、channel handle は cycle が切断されたときに必ず
解放する。process の同期 wait は async runtime を block しないよう dedicated
blocking task/thread に隔離する。切断時に Arapuca Process handle を誤って先に drop
して process を止める設計にせず、lifecycle owner が wait/cleanup を完了させる。

## 9. concurrency と状態遷移

同じ SandboxId に次の組み合わせを同時に許可する。

```text
attach || attach
exec   || exec
attach || exec
list   || create
list   || delete
```

各 attach/exec は別 process/PTY であり、workspace だけを共有する。per-ID lock は
get-or-create、owner claim、delete、metadata write を atomic に見せる。

delete と shell/exec が競合した場合は、先に `Deleting` へ遷移を確定した側が勝つ。
その後の新しい shell/exec は一般的な拒否となり、既存 channel は delete によって
停止する。delete 完了後に来た新しい shell/exec は同じ ID を新規 claim/create
できる。create の claim と delete が race して owner や workspace を二重化しては
ならない。

list は request 開始時点に近い Active snapshot を読む。作成・削除の lock を
全 sandbox に広げて server を停止させず、snapshot 外の state は次回 list に
反映する。

## 10. error と exit status

認証 failure、invalid selector、unsupported request、unknown subsystem、resource
cap 超過は server panic ではなく一般的な拒否である。remote には、絶対 path、
fingerprint、Arapuca の error chain、他 sandbox の state を含めない。

`list` の成功は exit status `0`、失敗は non-zero。`delete` の absent/non-owner
no-op は空 output と status `0`、実際の削除障害は non-zero。interactive/exec の
process が返す status/signal は process の結果を表し、server の protocol error
と混同しない。

## 参考仕様

- [RFC 4254: The Secure Shell (SSH) Connection Protocol](https://www.rfc-editor.org/rfc/rfc4254)
  （channel、PTY、window-change、env、exec、shell、subsystem、signal、EOF、exit status）
- [OpenBSD ssh(1) manual](https://man.openbsd.org/ssh)
  （`-s` subsystem、username、remote command、exit status）
- [OpenSSH `clientloop.c`](https://raw.githubusercontent.com/openssh/openssh-portable/master/clientloop.c)
  （remote command と subsystem name の wire 送信）
- [russh 0.63.1 `server::Handler`](https://docs.rs/russh/0.63.1/russh/server/trait.Handler.html)
- [russh 0.63.1 `server::Session`](https://docs.rs/russh/0.63.1/russh/server/struct.Session.html)
- [Arapuca v0.2.7 fixed revision](https://github.com/LeGambiArt/arapuca/commit/c94802c4d8b6b880334c0d643b16b7326ec7f039)
