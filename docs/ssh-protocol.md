# SSH protocol 仕様

この文書は shbox v0.1 が SSH transport 上で公開する request、routing、stream、PTY、signal、close semantics を定義する。OS confinement implementation は protocol surface に露出しない。

## 1. Connection state

connection ごとに保持する主な state:

- authenticated `Principal`
- authentication username（selector context）
- connection admission slot
- bounded channel registry
- per-channel request/mailbox state

principal は認証済み Ed25519 key fingerprint と role であり、username 自体は identity ではない。

### 1.1 Authentication

public-key authenticationのみを通常の認証方式として受理する。invalid key/non-public-key methodは拒否する。

認証成功時に principal と username を connection state に固定する。後続 channel が別 username/identity として振る舞うことはない。

### 1.2 Admission caps

built-in defaults:

- unauthenticated connections: 32
- total connections: 128
- channels per connection: 16
- auth attempts: 6
- handshake timeout: 30 seconds

cap超過は既存connectionをevictせずnew admissionを拒否する。

## 2. Selector routing

### 2.1 Sandbox selector

normal username は `SandboxId` としてparseする。

```text
[A-Za-z0-9][A-Za-z0-9-]{0,63}
```

invalid selectorはgeneric refusal。

valid ID は `SandboxManager` のownership/claim policyを通ってsandbox routeへ進む。

### 2.2 Host selector `_`

`_` はreserved host route。admin roleだけが利用できる。

host modeはdaemon accountのlogin shell/homeを使い、sandbox confinementを適用しない。normal keyに対しては存在を特別に開示せず拒否する。

## 3. Channel lifecycle

channel open時にbounded registry entryを作る。terminal operation開始時にevent receiverを一度だけtakeし `started=true` にする。

同一channelで複数のshell/exec/subsystem operationを開始しない。

connection handlerがdropした場合、registry全体をclearし、started bridgeが持つevent receiverをsender-dropでwakeさせる。connection stateがbridge側の`Arc`で残ってもmanaged processを孤立させない。

## 4. Shell request

### 4.1 Sandbox shell

valid sandbox selectorでshell requestを受けると:

1. ownership/claim確認
2. current PTY snapshot取得（あれば）
3. `LaunchOperation::Shell`
4. `SandboxManager::launch`
5. launch成功後にchannel success
6. bridge task開始

shellはvalidated sandbox shellをOpenSSH流のlogin shell形式、すなわち:

```text
executable: <configured-shell>
argv[0]: -<basename>
argv[1..]: なし
```

で起動する。`-l` 等のshell固有optionは付けない。Linuxはshboxが直接execし、macOSはsandbox-execの内側で固定の `/bin/sh` 経由の `exec -a` によりargv[0]を設定する(exec chainは同一PID)。

### 4.2 Host shell

admin `_` routeではdaemon accountのhost shellを起動する。PTY semanticsはsandboxと同じSSH contractを持つが、confinement policyは異なる。

## 5. Exec request

remote command bytesは最大32 KiB。NULは禁止。UTF-8である要件はない。

sandbox execはraw command bytesをそのままvalidated shellへ:

```text
<shell> -c <command>
```

の単一引数として渡す。分割・再tokenize・解釈・正規化・transcodeは行わない。quoting、redirect、pipeline、builtin、locale/encodingの解釈は選択されたshellの責任である。

host execもbounded commandをhost shell `-c`へ渡す。

launch開始前にrequestをacknowledgeしない。spawn/setup/confinement失敗時はgeneric failureを返す。

## 6. Subsystems

### 6.1 `list`

`list` はcurrent principalから見えるActive sandbox IDsをsorted textとして返す。

PTY付きlistは拒否する。subsystemに追加argumentはない。

### 6.2 `delete`

`delete` はcurrent selectorのsandboxをownership policyに従って削除する。

`_` はdelete targetにならない。invalid sandbox selectorも拒否する。

### 6.3 Unsupported subsystem

SFTPを含むunknown subsystemは明示的に拒否する。

## 7. PTY request

PTY requestはshell/exec開始前に受理できる。

保存する値:

- terminal name（最大256 bytes）
- rows / columns
- terminal modes
- window revision

pixel dimensionsはv0.1のterminal sizing contractには使わない。

寸法0はRFC 4254 §6.2の "Zero dimension parameters MUST be ignored" に従い無視する。初回 `pty-req` では無視した0寸法に24x80のdefaultを適用し、`window-change` では0寸法を適用せず他軸の値を維持する。OpenSSH sshdがclient指定値(0を含む)を素通しするのに対する、意図的な偏差である。

PTY request後、launch時に shbox が自身でPTY pairをallocateし、terminal modesとinitial window sizeをbridge公開前に適用する。

## 8. PTY child semantics

real target processは次を満たす。

- fd 0 is TTY
- fd 1 is TTY
- fd 2 is TTY
- daemonとは別のnew session
- controlling terminal session IDがtarget sessionと一致
- foreground process groupがterminal foreground PGIDと一致

これによりordinary interactive shell job controlが機能する。

### 8.1 Stream shape

PTY modeではterminal masterから単一output streamを読み、SSH dataとして送る。stderr extended-dataへ分離しない。

non-PTY modeではstdoutをSSH data、stderrをextended-data type 1として分離する。

## 9. Terminal modes

SSH `pty-req` のknown POSIX modesをtermiosへ写像する。少なくともreal acceptanceで以下の性質を固定する。

- canonical/raw flag変更が反映される
- ECHO等のmodeが反映される
- VINTR/VSUSP等のcontrol characterが反映される
- RFCのdisabled valueをOSの`_POSIX_VDISABLE`相当へ変換する

unknown modeは安全に無視する。

## 10. Window change

PTY channelの`window-change`はrows/columnsとmonotonic revisionを更新する。

launch中に初期snapshotより新しいresizeが届いた場合、launch完了時にlatest revisionへsynchronizeしてold sizeで上書きしない。

running PTYではmasterへwindow-size ioctlを行う。foreground processはOSのSIGWINCH semanticsを観測できる。

non-PTY channelのwindow changeはterminal resizeとして扱わない。

## 11. Client data / stdin

channel dataはbounded mailbox経由でprocess stdinへ流す。

mailbox full時にinputをsilent dropしない。channelをcloseしbridge teardownを開始する。

PTYではmaster write endpoint、non-PTYではstdin pipeへ書く。

## 12. EOF semantics

### 12.1 Non-PTY

client EOFでstdin write endpointをdropする。childは通常のpipe EOFを読む。

EOF後のclient dataはprocessへ渡さない。stdout/stderrとexit statusは引き続きclientへ返す。

### 12.2 PTY

client EOFでshboxがterminal inputへsynthetic VEOF byte（例: `0x04`）を注入することはない。write duplicateを閉じるだけであり、terminal-specific EOF generationを偽装しない。

channel close/transport disconnectはEOFとは別で、sandbox launchではtransport endpointだけをdetachする。process terminationは開始しない（sandbox delete/daemon shutdownおよびpublication前失敗を除く）。

## 13. Signal request

RFC 4254で扱うknown signal nameだけをlibc signalへmappingする。不明signalはforwardしない。

signal requestは転送の成否に応じて `CHANNEL_SUCCESS` / `CHANNEL_FAILURE` で応答する。russhがclient側 `want_reply` を見て応答を抑制するため、handlerは無条件にreply APIを呼ぶ。mailbox満杯でsignalをenqueueできない場合もchannelをterminateせず `CHANNEL_FAILURE` で応答する(signal配送はbest-effortであり、data/EOFのようなbackpressure teardown対象ではない)。

PTY sandbox processではcurrent foreground process groupをtargetにする。これによりshell自身ではなくforeground jobへsignalが届く。

non-PTYではowned session/process groupへsignalする。

real acceptanceではCtrl-C/Ctrl-Zのterminal-generated signalsに加え、SSH signal requestのforwardingも検証する。

## 14. Job control

PTY contractは単なる`isatty`だけではない。blocking suiteでreal interactive `/bin/bash`を使い:

1. deterministic prompt exchange
2. foreground `sleep`
3. Ctrl-Cでinterruptしshell継続
4. foreground jobをCtrl-Zでstop
5. `jobs`にStopped/Suspendedとして表示
6. `bg`でresume
7. `fg`でforeground復帰
8. Ctrl-Cで終了
9. nested foreground process groupへのsignal
10. raw terminal mode変更と完全restore

を確認する。

## 15. Exit reporting

process完了後、output pumpがEOFまでdrainしてからprotocol completionを行う。

normal exit:

```text
SSH EOF
exit-status
channel close
```

signal exit:

```text
SSH EOF
exit-signal
channel close
```

internal wait/channel failureは255のgeneric failureへnormalizeし、raw backend errorをclientへ出さない。

## 16. Launch failure

requestを実行できない場合、channelをsilent hangさせず、まずrequest自体に `CHANNEL_FAILURE` で応答し(RFC 4254 §5.4、clientが `want_reply=false` の場合はrusshが応答を抑制)、generic stderr、EOF、exit status 255、closeの順で完了させる。

client-visible generic message:

```text
shbox: request cannot be completed
```

internal path/kernel/policy detailsはoperator logだけに残す。

## 17. Channel close / disconnect

started channelがcloseされた場合はbridgeへ`Close` eventを送る。mailboxがfullで送れない場合registry entryをremoveしsenderをdropする。

connection自体が終了した場合はconnection handler drop時に全registry senderをdropする。

sandbox bridgeはpublished launchのaborted pathで:

1. output pumps停止
2. stdin/stdout/stderrのchannel-owned endpointとPTY masterをdetach
3. processをcgroup内に残したままchannel close

publication前の失敗、sandbox delete、daemon shutdownは別のterminate/reap/cleanup pathを使う。

を行う。

ここで process group は channel の所有権を表さない。Linux sandbox の process ownership
は SandboxId ごとの cgroup domain にあり、PTY/job-control と signal forwarding の
process-group操作は transport detach では開始しない。

## 18. Daemon shutdown

first shutdown signalでnew listener workを止め、host/sandbox runtimeをdrainする。second shutdown signalでforce-stopへ移行する。

SSH channelのprocess ownershipとdaemon global shutdown ownershipがraceしてもdirect childを二重reapしない。

## 19. Environment request

SSH `env` requestはsandbox/host process environmentへ反映しない。request拒否だけでconnection全体をkillしない。

sandbox environmentはconfig snapshotとshbox authoritative valuesだけから構成する。

## 20. Backpressure

outputはbounded chunk/channelを使う。client送信failure、pump failure、event mailbox failureはそのchannelをaborted cleanupへ送る。

一つのslow/broken channelがunbounded memory growthや他channelのprocess ownership喪失を起こさないことを優先する。

## 21. Concurrency

同一connection上の複数channel、同一sandboxの複数process、別sandboxのprocessを並行実行できる。

blocking testsはconcurrent PTYsで:

- distinct terminal device identity
- distinct session/foreground PGID
- resize isolation
- signal isolation
- client disconnect isolation

を検証する。

## 22. 拒否する protocol surface

v0.1で公開しないもの:

- SFTP
- port forwarding
- agent forwarding
- X11 forwarding
- client-controlled process environment
- backend-specific subsystem
- sandbox attach/resume protocol
- user-selectable confinement backend

## 23. Related documents

- [product.md](product.md)
- [architecture.md](architecture.md)
- [security.md](security.md)
- [testing.md](testing.md)
