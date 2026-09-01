# shbox specification

このディレクトリは shbox v0.1 の外部契約、内部境界、security/release 条件を記述する。実装と文書が衝突した場合は、release 前にどちらかを修正して一致させる。古い backend や移行用互換経路を仕様として残さない。

## Reading order

1. [product.md](product.md) — 利用者から見た目的、SSH 操作、非目標
2. [architecture.md](architecture.md) — lifecycle、`ProcessLauncher`、PTY/process ownership
3. [configuration.md](configuration.md) — TOML、XDG path、built-in concurrency caps
4. [ssh-protocol.md](ssh-protocol.md) — SSH request/stream/signal semantics
5. [security.md](security.md) — trust boundary、OS confinement、既知の限界
6. [platforms.md](platforms.md) — Linux/macOS backend と正式 support 条件
7. [testing.md](testing.md) — unit/OpenSSH/native platform acceptance
8. [release.md](release.md) — blocking CI、release evidence、deployment gate

## Normative language

`must` / 「必須」は release-blocking contract、`must not` / 「禁止」は実装・運用の禁止事項を表す。`may` / 「可能」は optional behavior である。

正式 support は「コンパイルできる」ことではなく、対象 OS/architecture 上で実 confinement と実 OpenSSH/PTTY acceptance が passing であることを意味する。

## Core vocabulary

- **Principal**: 認証済み Ed25519 public key fingerprint と role の組。
- **Sandbox**: durable metadata と workspace を持つ shbox resource。ID は `[A-Za-z0-9][A-Za-z0-9-]{0,63}`。
- **Workspace**: sandbox に永続する唯一の writable project tree。
- **Launch**: shell/exec 一回に対応する disposable process lifecycle。process、PTY、private `TMPDIR` は durable ではない。
- **ProcessLauncher**: backend-neutral な private launch seam。SSH 層は OS confinement implementation を知らない。
- **PTY**: shbox が直接 allocate/own する pseudo-terminal。OS confinement layer の責務ではない。
- **Host mode**: admin key が username `_` を使ったときだけ利用できる daemon account 上の非-sandbox route。

## Current architecture

```text
SSH/session layer
    -> ProcessLauncher
        -> shbox-owned PTY/process lifecycle
        -> OS confinement
            Linux: nono 0.74.0 / Landlock
                   (+ nono-selected seccomp fallback when required)
            macOS: generated Seatbelt profile via /usr/bin/sandbox-exec
```

Linux では nono を library として利用し、外部 sandbox CLI、sibling helper、delegated cgroup controller を必要としない。macOS では parent process が Seatbelt profile を構築し、`/usr/bin/sandbox-exec` に適用を委ねる。両 OS とも PTY/session/process-group lifecycle は shbox 自身が所有する。

## Change discipline

- public config に backend selector や backend 固有 option を追加しない。
- sandbox resource limits（CPU/memory/PID/file quota）を shbox の機能として暗黙に復活させない。
- PTY failure を pipe ベースの疑似 interactive mode で回避しない。
- Linux confinement failure を unconfined execution に degrade しない。
- macOS Seatbelt prerequisite failure を unconfined execution に degrade しない。
- release 前に [testing.md](testing.md) と [release.md](release.md) の blocking matrix を実行する。
