# PLANS.md — 標準sshd挙動パリティ (issues #2, #3 + パリティ調査結果の修正)

ブランチ: `stdssh-parity`(main `6ae9d29` から分岐)。Draft PR: `main` 向けに作成する。

## 目的とユーザー価値

shboxを標準的なOpenSSH `sshd` と同じセッション挙動に揃える。観察方法:

- `ssh admin@host` で host route に入り、対話シェルが login shell として振る舞う(既に正しい)。
- sandbox route (`ssh sandboxid@host`) で `exec` した際、非UTF-8バイト列を含むコマンドが拒否されずバイト等価でシェルへ渡る。
- sandbox route で `ssh -t` なしのシェル要求が login shell (`argv[0] = -<basename>`) として起動する。
- SSH `signal` リクエスト(`want_reply=1`)に応答が返る。未送信のままクライアントが待ち続けない。
- プロセスがシグナル死亡したとき `exit-signal` の名前が実際のシグナルと一致する。

## 現在の前提(調査済み事実)

- Arapuca依存は撤去済み。sandbox launchはshbox自身が所有する(`src/platform/linux.rs` nono / `src/platform/macos.rs` sandbox-exec)。Issue #2/#3の「vehicle問題」コメントは陳腐化している。
- `src/platform/policy.rs:383` `validated_shell_command` が `LaunchOperation::Exec` を `String::from_utf8` で検証しており、非UTF-8を拒否する(#3本体)。`LaunchOperation::Shell` は `None` を返す。
- `src/platform/linux.rs:210-215` と `src/platform/macos.rs:141-147` が Shell を `command.arg("-l")` で起動する(#2本体)。host mode (`src/ssh/host.rs:152`) は既に `arg0(-<basename>)`。
- Linuxはshboxが直接 `execve(shell)` するため `std::os::unix::process::CommandExt::arg0` が使える。macOSは `/usr/bin/sandbox-exec` が子のargv[0]を「渡されたパスそのもの」に設定することを実機で確認済み。`/bin/sh -c 'exec -a <argv0> <shell>'` を挟むとsandbox-exec内側でもargv[0]制御できることを実機で確認済み(execチェーンは同一PID、直接子は設定シェルのまま)。
- russh 0.63.1 (vendored source確認):
  - `Session::channel_success/channel_failure` は `channel.wants_reply` を見て、clientが `want_reply=0` なら送信を抑制する。handlerは無条件にreply APIを呼んでよい。
  - `src/ssh/mod.rs:694` `signal` handlerは既知シグナル転送時に一切応答しない → `want_reply=1` のクライアントがハングする。
  - mailbox満杯時のsignalはchannel全体をcloseする(`src/ssh/mod.rs:708`)。sshdはsignalで接続を落とさない。
  - 未知のchannel request(例: RFC 4335 `break`)はrusshが自動で `CHANNEL_FAILURE` を返す。未知のglobal request(例: `no-more-sessions@openssh.com`)も自動で `REQUEST_FAILURE` を返す。OpenSSH clientは `no-more-sessions` を `want_reply=0` で送るため、この挙動はクライアントから観測不能でRFC 4254/4335準拠。shbox層での追加handlerは存在しない(russhにhookが無い)ため対応不要。
  - russh clientの `Channel::signal` は `want_reply=0` 固定。replyそのものはテストから観測できないため、統合テストは「signal転送が機能し、channelが継続すること」を検証する(docs §13のreal acceptance要件)。
- RFC 4254 §6.2は "Zero dimension parameters MUST be ignored" を定める。初回 `pty-req` の 0寸法を24x80へ置換する現行挙動(`src/ssh/host.rs:36`)はRFC準拠の正当な解釈であり、sshdの素通し(0x0適用)との差は**意図的偏差**として維持する。修正はコメントとdocs契約の明記のみ。※本計画以前の調査発言(「RFCに規則が無い」)は誤りだったため訂正。
- CI quality gate(ローカルで実行する正規コマンド, Rust 1.95):
  ```sh
  cargo fmt --all -- --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo test --locked --all-targets -- --test-threads=1
  ```
  native gate(Linux実機)はrelease専用(`.github/workflows/release-gate.yml`)。Linux固有の実launchテストは `#[cfg(target_os = "linux")]` で書き、release gateで検証する(本作業マシンはmacOS arm64)。

## マイルストーン

### M1. SSH signalリクエストの応答とbackpressure安全性

- **Goal**: 既知シグナル転送成功時に `channel_success` を返す。mailbox満杯時はchannelを落とさず `channel_failure` を返す。未知シグナルは現行どおり拒否。
- **Edits**: `src/ssh/mod.rs` `signal()`。docs/ssh-protocol.md §13に応答契約を追記。
- **Proof**: `cargo test --locked --all-targets -- --test-threads=1`。`tests/ssh_auth.rs` にrussh clientベースのsignal転送テストを追加(execした `sleep` をsignalで停止させ、exit-signal INTが届き、channelが正常完結すること。未知シグナル名でもchannelが継続すること)。docs §13が要求する「SSH signal request forwarding の real acceptance」をこれで満たす。

### M2. exit-signal名の正確な報告

- **Goal**: 13名のRFC 4254集合外のシグナル死亡が `TERM` と誤報されない。
- **Edits**: `src/ssh/host.rs` `name_from_signal` を主要POSIX集合へ拡張(TRAP/SYS/VTALRM/PROF/WINCH/XCPU/XFSZ/TSTP/CONT/TTIN/TTOU/URG/CHLD/STOP/IO + cfg付きEMT/STKFLT)。`src/ssh/channel.rs` `signal_name_to_sig` も同集合を `Sig::Custom` で対応。`unwrap_or("TERM")` は到達不能フォールバックとして残しdebug logを足す。リクエスト受理側 `signal_from_name` は13名のまま(docs §13契約)。
- **Proof**: `supported_signal_names_round_trip` テスト拡張 + 全ゲート。

### M3. sandbox execの生バイト保持 (Issue #3)

- **Goal**: 非UTF-8・NUL無し・32KiB以下のexecコマンドがバイト等価で `<shell> -c` の単一引数になる。UTF-8要求を廃止。
- **Edits**: `src/platform/policy.rs` `validated_shell_command` を `Result<Option<OsString>, LaunchError>` へ(`OsStr::from_bytes`)。`src/platform/linux.rs` / `macos.rs` は `arg(OsString)` をそのまま渡す。docs/ssh-protocol.md §5の「UTF-8 command」記述を生バイト契約へ修正。
- **Proof**: policy.rsユニットテスト(非UTF-8受理+バイト保存、NUL/超過は維持)。macOS実launchテスト(`printf %s 'x<0xFF>y'` 相当のバイト列をexecしstdoutをバイト比較)。Linux同等テストを `#[cfg(target_os = "linux")]` で追加(release gate検証)。

### M4. sandbox shellのlogin argv[0] (Issue #2)

- **Goal**: sandbox `shell` を `argv[0] = -<basename>`・追加option無しで起動。exec は非login `-c` のまま。
- **Edits**: `src/platform/policy.rs` に `login_shell_argv0(shell) -> Result<OsString, LaunchError>` を追加。linux.rsは `Command::arg0`。macos.rsは `/bin/sh -c 'exec -a <argv0> <shell>'` ラッパー(実機検証済み手順; 定数 `LOGIN_WRAPPER_SHELL`)。docs/ssh-protocol.md §4.1にargv[0]契約とmacOS execチェーンを明記。
- **Proof**: policy.rsユニットテスト(argv0生成)。macOS実launchテスト(Shell起動→stdinへ `echo $0` →stdout `-sh` 確認)。Linux同等テストをcfg付きで追加(release gate検証)。
- **Rollback**: 各プラットフォームlaunchは1関数に収まるためrevertで戻る。`-l` 依存の挙動(設定シェルが `-l` を解釈できない場合の起動失敗)からの移行なので、失敗時はgeneric launch failure (docs §16) として表面化する。

### M5. PTYゼロ寸法の契約明記(コード挙動は変更しない)

- **Goal**: RFC 4254 §6.2 "Zero dimension parameters MUST be ignored" に基づく現行挙動(初回0寸法→24x80代替、window-changeの0寸法→無視/他軸維持)をsshdとの意図的偏差として契約文書に固定する。
- **Edits**: `src/ssh/host.rs` `window_size` コメントのRFC引用を正確化。docs/ssh-protocol.md §7にゼロ寸法方針を追記。
- **Proof**: 全ゲート(ドキュメントのみ)。

### M6. 境界ケースの検証記録(コード変更なし)

- **Goal**: `break`(RFC 4335)等の未知channel requestとglobal requestがrussh自動failureでRFC準拠に処理されることを確認済みとして記録する。
- **Edits**: なし。本計画とPR本文に記録。vendored russhソース(`~/.cargo/registry/src/.../russh-0.63.1/src/server/encrypted.rs` の `_ =>` 分岐)で確認済み。
- **Proof**: この計画項目の分類 = `deviated`(対応不要と判定)。

## 分類ステータス

| 項目 | 分類 |
|---|---|
| M1 signal応答 | 未実装(本計画で実装) |
| M2 exit-signal名 | 未実装 |
| M3 exec生バイト (#3) | 未実装 |
| M4 login argv[0] (#2) | 未実装 |
| M5 ゼロ寸法契約 | 未実装(docsのみ) |
| M6 break/global request | deviated — russh自動failureでRFC準拠、対応不要 |
| 起動失敗exit 111 (docs §16) | deviated — 意図的設計、変更しない |

## 完了条件

- 上表の未実装5項目がすべて実装・検証済みになり、この計画から「完了記録」が削除されている(rolling運用)。
- macOSで全ゲート通過。Linux固有テストはcfg gateで追加し、release gateでの検証をPR本文に明記。
- `stdssh-parity` ブランチがpushされ、`main` 向けDraft PRが作成済み(Closes #2, #3)。
