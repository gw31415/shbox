# PLANS.md — 標準sshd挙動パリティ (issues #2, #3 + パリティ調査結果の修正)

ブランチ: `stdssh-parity`(main `6ae9d29` から分岐)。Draft PR: `main` 向けに作成する。

## 残作業

### R1. Linux native gateでの実launch検証

- **内容**: M3/M4で追加した `exec_preserves_non_utf8_command_bytes` と `shell_request_starts_a_login_argv0_shell`(`src/platform/linux.rs`、`#[cfg(target_os = "linux")]`)はmacOSでは実行できない。release gate(`.github/workflows/release-gate.yml`)はrelease専用のため、`workflow_dispatch` での事前実行かタグリリース時に結果を確認する。
- **期待値**: 両テストとも `/bin/sh` がlogin argv[0](`-sh`)で起動し、非UTF-8バイト列(`x ff fe y`)がバイト等価でstdoutへ返る。nono profileは `/bin` をExecutableRuntimeとして許可するため追加のpath許可は不要なはず。`/etc/profile` はcurated外のためlogin shellに読めないが、shellは黙ってスキップするため `$0` 観測には影響しない。
- **失敗時**: Linuxのargv[0]パスは `Command::arg0` の直接execでありmacOS実機で検証済みの `$0` プローブと同一の観測系。失敗時はnono prepared policyのexec許可と `arg0` とpre_execの併用可否を `scripts/verify-linux-platform` で切り分ける。

## 完了済み(詳細はgit history)

- M1 signal応答 + mailbox満杯時teardown廃止 (`fix(ssh): answer signal requests...`)
- M2 exit-signal名の正確な報告(同commit)
- M3 sandbox exec生バイト保持(#3)
- M4 sandbox shell login argv[0](#2)
- M5 PTYゼロ寸法契約の明記(RFC 4254 §6.2準拠の意図的偏差として記録)
- M6 break/global request — deviated(対応不要): 未知channel requestはrusshが `CHANNEL_FAILURE`、未知global requestは `REQUEST_FAILURE` を自動返信しRFC準拠。OpenSSH clientはこれらを観測しない。

## 記録として残す判断

- 起動失敗時のexit 111(docs §16)は意図的設計。sshdの255とは意図的に異なる。
- 初回pty-reqの0寸法は24x80代替、window-changeの0寸法は他軸維持。RFC 4254 §6.2 "Zero dimension parameters MUST be ignored" に基づくsshdとの意図的偏差。
