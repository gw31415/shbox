# shbox: sandbox-scoped cgroup lifecycle / tssh compatibility plan

## Goal and observable value

Linux sandbox の process lifetime を SSH channel / process group から分離し、sandbox-scoped cgroup を authoritative な process ownership boundary とする。最終的に、SSH disconnect は transport だけを閉じ、sandbox delete と daemon shutdown は `setsid()`・double-fork・daemonized descendant・tsshd を含む全 process を回収する。runtime temporary resources は sandbox runtime の寿命に従い、workspace は保持する。

## Current state

- M0–M5 は `bc29aa8` から `3b1043e`、M6 は `5766419`、M7 は `cee682d`、M8 は `2237bc8`、M9 は `ea0beba`、M10 は `ed7e187`、M11 はこのコミットの履歴に保存する。次は M12 の tssh acceptance、最後に M13 の legacy cleanup である。delete・shutdown・publication 前失敗は terminate path を維持する。
- Linux launcher は `SandboxId` ごとの state machine と mandatory `ProcessDomain` を持ち、cgroup の `populated` / `kill_all` / `remove_empty` を lifecycle 判断に使う。
- `plan-cgroup.md` がこのタスクの active execution plan。完了した計画本文はコミット履歴に保存し、各 milestone の archival commit と同時にここから除去する。
- `.serena/.gitignore` は既存の未追跡補助ファイルであり、計画実装のコミットには含めない。

## M12 — tssh/tsshd compatibility acceptance

Goal: tssh-specific lifecycle code を追加せず、bootstrap SSH close 後も tsshd が cgroup-owned のまま UDP session を提供することを実証する。

Implementation and proof:

- repository / environment に存在する tssh の実行方法を確認し、可能なら QUIC、KCP（対応時）、connection loss/reconnect、active session 中の delete、daemon shutdown を acceptance test する。
- tsshd が自然終了した場合の domain drain を確認する。
- `SSH_CONNECTION` / `SSH_CLIENT` は一般的な SSH compatibility の必要性が証明された場合のみ追加する。
- tssh が利用できない場合は、利用不能の正確な理由・実行した代替 acceptance・残る外部依存を plan に記録し、他の milestone を先に完了する。

## M13 — Cleanup legacy process-group ownership assumptions

Goal: cgroup lifecycle が authoritative になった後、obsolete な process-group ownership 説明と cleanup helper を整理する。

Implementation:

- `kill_process_group`、`SIGTERM`、`SIGKILL`、`wait_for_process_cleanup`、`PROCESS_GROUP_SETTLE`、Arc count lifecycle 判定を検索し、delete・shutdown・failed/unpublished launch・terminal/job-control に限定する。不要な helper と legacy test を削除する。
- channel disconnect が process termination を意味する古い docs/tests/comments を更新する。process group は foreground lookup、signal forwarding、job control、未公開 launch の防御 cleanup にだけ残す。
- `docs/architecture.md`、`docs/product.md`、`docs/security.md`、`docs/testing.md`、`docs/release.md`、`docs/ssh-protocol.md` の lifecycle contract を最終実装へ揃える。

Proof:

- `rg` の各残存箇所を分類し、意図しない disconnect teardown がないことを確認する。
- fmt、check、clippy、workspace tests、必要な native sandbox acceptance を実行し、warning/環境依存を記録する。

## Final acceptance matrix

| Scenario | Expected |
| --- | --- |
| foreground command exits | direct child reaped; domain eventually empty |
| shell starts background / `setsid()` / double-fork daemon | descendant survives direct child exit and remains cgroup-owned |
| SSH channel or TCP connection closes | transport detaches; no forced process kill |
| final process exits | `populated=0`; runtime temp is removed; workspace remains |
| reconnect to idle/living sandbox | new generation or existing domain is selected correctly |
| two SSH sessions | same sandbox cgroup and aggregate limits |
| sandbox delete | cgroup kill removes every descendant before durable deletion |
| daemon graceful shutdown | all sandbox domains and runtime resources are removed |
| daemon crash/restart | stale shbox-owned domains are reconciled; unrelated cgroups untouched |
| tssh bootstrap closes | tsshd survives and remains reachable until it exits or is deleted |

## Verification and recovery

- Work from `/home/ubuntu/shbox`; do not stage `.serena/.gitignore` or unrelated user changes.
- Before each milestone commit, run targeted acceptance plus `cargo fmt --package shbox` (automatic formatting), `cargo fmt --package shbox -- --check`, `cargo check --workspace --all-targets`, `cargo clippy --workspace --all-targets`, and the relevant `systemd-run --user --scope` native integration command when cgroup delegation is required.
- Each milestone is committed separately with an archival Conventional Commit. Do not amend, push, or create a PR.
- If a cleanup operation fails, retain the durable `Deleting` state and leave enough ownership metadata for retry; never delete a workspace while its process domain is still populated.
