# Maintenance: upstream update policy

shbox は `russh`、`ssh-key`、`tokio`、`nix` などの外部 crate に依存しており、これらの upstream 更新に壊されず、かつ遅れないための運営方法を定める。ここでの「互換性が破壊されない」とは、shbox の外部契約（docs/README.md の各文書、特に ssh-protocol.md と configuration.md）が変更を要求されないことを指す。契約側を変える変更は maintenance ではなく仕様変更であり、docs の該当文書の更新を前提とする。

## 1. 依存関係の区分

| 区分 | 対象 | 方針 |
|---|---|---|
| SSH 契約系 | `russh`, `ssh-key`, `ssh-encoding` | major / pre-release (`0.x`, `-rc`) の bump は breaking の可能性が高い。release gate 前に必ず OpenSSH 互換 acceptance を通すまで merge しない。 |
| runtime 系 | `tokio`, `futures-util`, `tokio-tungstenite` | minor は追従可。feature flag（`ws`）の default 挙動を変えない。 |
| platform 系 | `nix`, `libc`, `landlock`, `seccompiler` | API 変更が頻繁。Linux/macOS 両 native gate での確認を必須とする。 |
| その他 | `serde`, `toml`, `tracing`, `usage-rs` 等 | patch/minor は `cargo update` で追従してよい。 |

`ssh-key` の `-rc` 版を指定している期間は、正式版が出た時点で rc 指定を外す移行を最優先タスクとする。

Linux の `identity = "isolated"` が使う `newuidmap` / `newgidmap` / `getsubids` は crates.io の依存ではなく、administrator 提供の shadow-utils helper（PATH 上の setuid binary と NSS `subid` backend）である。これらは lockfile で pin できないため、distro 側の変更（`getsubids` の出力形式や subordinate delegation の与え方を含む）は platform 系と同じく Linux native gate で確認する。

## 2. 更新手順

1. 更新は crate 単位で行い、`Cargo.toml` の bump と lockfile 更新を同一 commit にまとめる（`chore(deps)`）。
2. 更新ごとに最低限 `cargo check --all-features`、`cargo test`、`cargo clippy` を通す。
3. SSH 契約系・platform 系の更新は、docs/testing.md の OpenSSH / native platform acceptance を対象環境で実行してから merge する。
4. upstream の changelog / breaking change を確認し、shbox 側の外部契約に影響する場合は docs を先に更新する。

## 3. 遅れないための運営体制

- **定期的な棚卸し**: 依存関係の age を定期的に確認し、SSH 契約系で 2 minor 以上、その他で semver 互換の範囲で放置されている依存がないかを見直す。
- **セキュリティ更新は最優先**: advisory が発行された依存は区分にかかわらず直ちに handover して §2 の手順を圧縮して実施する。
- **契約テストを更新の防波堤にする**: OpenSSH クライアントとの相互運用テストが upstream の breaking change を最初に検出する。このテストを軽量化・削除しない。
- **feature gate で optional な追従を隔離する**: 新 transport 等の追従は `ws` のように feature gate の背後に置き、default build への影響を排除する。

## 4. 判断の記録

破壊的変更への追従で shbox 側のコードを書き換えた場合は、どう移行したかを commit message（`chore(deps)` / `feat!`）に残す。docs の文書と実装が衝突した場合は、docs/README.md の規定に従い release 前にどちらかを一致させる。
