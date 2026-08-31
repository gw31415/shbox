# shbox specification

この directory は shbox v0.1 の仕様の正本である。実装と文書が異なる場合、未解決の差分として
扱い、どちらかへ暗黙に寄せてはならない。

## Reading order

1. [Product and external interface](product.md) — 目的、利用者から見える操作、非目標
2. [Security model](security.md) — 認証、所有権、admin/host access、信頼境界
3. [SSH protocol](ssh-protocol.md) — request、channel、PTY、stream、終了規則
4. [Architecture and lifecycle](architecture.md) — module 境界、永続状態、並行処理、復旧
5. [Configuration](configuration.md) — TOML schema、既定値、validation、鍵の更新
6. [Platforms](platforms.md) — Arapuca Adapter、OS 差、配備条件、正式対応範囲
7. [Testing and release gates](testing.md) — acceptance test と正式対応の証明条件

実装の検証状況と運用上の再開手順は [Testing and release gates](testing.md) と
[release runbook](release.md) に記録する。

## Normative language

- **必須**: v0.1 の適合実装が満たさなければならない。
- **禁止**: v0.1 の適合実装が行ってはならない。
- **推奨**: 強い既定方針。同等の性質と検証を示せる場合だけ変更できる。
- **非目標**: v0.1 が interface、互換性、運用を保証しない機能。

英語の `MUST`、`MUST NOT`、`SHOULD` を引用するときは RFC の意味で使う。文書内の例は、
「例」と明記しない限り protocol/config contract の一部である。

## Core vocabulary

- **Sandbox**: shbox が所有する永続 metadata と workspace、およびそこへ接続する一時的な
  sandboxed process の論理的集合。
- **Workspace**: sandbox ごとに永続化され、process の `HOME` と初期 cwd になる directory。
- **Arapuca process**: 一回の shell/exec のために起動する隔離 process。永続 sandbox object
  ではない。
- **Owner**: sandbox を最初に atomic claim した正確な Ed25519 public key fingerprint。
- **Admin**: daemon 実行ユーザーの `~/.ssh/authorized_keys` に登録され、認証にも成功した host 認可 key。host selector `_` と全 sandbox の操作権限を持つ。
- **Normal**: `$XDG_CONFIG_HOME/shbox/allowed_keys` だけに登録された sandbox 許可 key。自分が所有する sandbox だけを利用できる。
- **Host selector**: admin だけが使える予約 SSH username `_`。
- **Managed mode**: 一つ以上の admin key が設定された動作 mode。
- **Sandbox-only mode**: admin key がなく、host access を持たない動作 mode。
- **Formal support**: 対象 OS/version/architecture で全 blocking integration suite に合格した
  組合せ。build 成功や upstream の一般的な対応表だけでは正式対応にならない。

## Change discipline

仕様変更では、影響する全文書と acceptance test を同時に更新する。特に次は一文書だけで
変更してはならない。

- selector、role、ownership: `product.md`、`security.md`、`ssh-protocol.md`
- metadata/lifecycle: `architecture.md`、`testing.md`
- config default/validation: `configuration.md`、`testing.md`
- OS behavior/dependency revision: `platforms.md`、`testing.md`、`release.md`
- user-visible request/output: `product.md`、`ssh-protocol.md`、integration test

Arapuca 固有 field や backend selector を利用者向け config に直接露出しない。新しい設定が
必要な場合は、まず shbox の domain concept として意味・全 platform での契約・検証方法を
定義する。
