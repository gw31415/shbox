# PLANS.md — 標準sshd挙動パリティ (issues #2, #3 + パリティ調査結果の修正)

ブランチ: `stdssh-parity`(main `6ae9d29` から分岐)。Draft PR: `main` 向けに作成する。

## 完了済み(詳細はgit history)

- M1 signal応答 + mailbox満杯時teardown廃止 (`fix(ssh): answer signal requests...`)
- M2 exit-signal名の正確な報告(同commit)
- M3 sandbox exec生バイト保持(#3)
- M4 sandbox shell login argv[0](#2)
- M5 PTYゼロ寸法契約の明記(RFC 4254 §6.2準拠の意図的偏差として記録)
- M6 break/global request — deviated(対応不要): 未知channel requestはrusshが `CHANNEL_FAILURE`、未知global requestは `REQUEST_FAILURE` を自動返信しRFC準拠。OpenSSH clientはこれらを観測しない。
- M7 RFC再監査 + exit 255統一: launch失敗時にrequest自体へ `CHANNEL_FAILURE` を応答(RFC 4254 §5.4)、host窓同期失敗時のsilent hang廃止(docs §16)、generic exit statusを111からsshdと同じ255へ統一。
- R1 Linux aarch64検証: Docker Desktop VM(arm64 Linux)で `cargo clippy` + `cargo test --test-threads=1` を実行し全件合格。正式リリースゲート(`release-gate.yml`)の結果が最終証跡。

## 記録として残す判断

- 初回pty-reqの0寸法は24x80代替、window-changeの0寸法は他軸維持。RFC 4254 §6.2 "Zero dimension parameters MUST be ignored" に基づくsshdとの意図的偏差。
- **russh 0.63.1 upstream既知クオーク**: 未知global request(例: OpenSSH clientがauth直後に `want_reply=0` で送る `no-more-sessions@openssh.com`)に対し、`want_reply=0` でも無条件に `REQUEST_FAILURE` を返す(RFC 4254 §4の "MUST NOT send response" 違反)。shbox層にはglobal requestの汎用hookが存在せず修正不可。OpenSSH clientはunsolicitedな `REQUEST_FAILURE` を無視するため実害なし — vendored source(`ServerSession::request_failure` はwants_replyを検査しない、`channel_success/failure` は検査する)で確認済み。
- 起動失敗時のgeneric exit statusは255(docs §16)。かつての111は廃止済み。
