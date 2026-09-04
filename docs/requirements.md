# 動作要件 (requirements)

この文書は shbox daemon を動かす OS/account/kernel/cgroup/user ID の前提を定義する。満たさない項目がある場合、sandbox launch は fail closed する（unconfined 実行への fallback はしない）。

## 1. 共通

- Rust 1.95 / locked `Cargo.lock` で build した artifact を使う。
- daemon は非 root の専用 service account で動かすこと（`User=shbox` / `Group=shbox`）。root 実行は不可（platform gate も root を拒否する）。
- config/data/state/runtime の XDG roots は daemon 所有・symlink でない・group/world writable でない real directory であること（詳細は [configuration.md](configuration.md) §8）。
- SSH listener の bind 権限を持つこと。port 22 を使う場合のみ service manager 側で `CAP_NET_BIND_SERVICE` を daemon に与えてよい。sandbox child に追加 capability を与える理由にはしない。

## 2. Linux（全 sandbox launch に必須）

- kernel が Landlock ABI 4+（6.7+）を提供すること。filesystem/network policy に使う。不足時は launch を拒否する。
- 書き込み可能な cgroup v2 階層（delegation）。resource limit の有無にかかわらず全 launch が `SandboxId` ごとの専用 process domain cgroup（`CLONE_INTO_CGROUP`）を必要とするため必須。書き込み可能な階層が無ければ fail closed。
- systemd deployment では unit に `Delegate=cpu memory pids` と `DelegateSubgroup=daemon` を設定し（systemd 255+ が対象。`DelegateSubgroup` を持たない古い systemd は対象外）、daemon を delegated leaf に置く。`[sandbox] cgroup_parent` にその delegated directory を指定するのが確実。省略時は自身の cgroup からの auto-discovery を使う。
- `cgroup_parent` と runtime temp root は同時に 1 つの daemon instance のみが所有する（排他所有権）。2 daemon で共有しない。起動時 reconciliation が `shbox-domain-*` / `sandbox-*` を自らの所有物として回収する。
- daemon unit の `NoNewPrivileges=false` を維持すること。`identity = "isolated"` の parent-side map で root 所有 setuid helper（`newuidmap`/`newgidmap`）を呼ぶためである。user code 実行前の `no_new_privs` は sandbox child 自身が設定する。
- Ubuntu 24.04 で `kernel.apparmor_restrict_unprivileged_userns=1` の場合は `deploy/apparmor/usr.local.bin.shbox` をロードすること（§2.3、[platforms.md](platforms.md) §2.3）。

## 3. Linux の user ID まわり

- default（`identity = "host"`）は daemon の DAC identity で動く互換 mode である。`network = "disabled"` 時の caller-mapped user namespace（`unshare --map-root-user` 相当）は isolation ではない。
- `identity = "isolated"` を使う場合の追加要件（いずれかが欠けたら fail closed し、`host` に fallback しない）:
  - daemon account への subordinate UID/GID delegation。照会は shadow-utils `getsubids`（NSS `subid` backend に従う）で行い、`/etc/subuid` を直接 parse しない。
  - administrator 所有の shadow-utils helper `newuidmap` / `newgidmap` / `getsubids` が PATH 上にあること（project-owned helper への置き換えはしない）。
  - root で socket-activated される `shbox-idmap-broker`（`deploy/systemd/shbox-idmap-broker.socket` / `.service`、`/run/shbox-idmap-broker.sock` で `shbox --internal-idmap-broker` を起動、`CAP_SYS_ADMIN` に限定）。
  - kernel/filesystem の ID-mapped mount 対応（`open_tree` / `mount_setattr` + `MOUNT_ATTR_IDMAP`、Linux 5.12+。kernel version だけでなく data/runtime root を置く backing filesystem の実 probe で確認すること）。
- isolated runtime の見え方（固定仕様）:
  - namespace 内 UID/GID は `1000:1000`（real/effective/saved）。UID/GID 0 は map しない。
  - host-visible ID は lease された subordinate ID であり、daemon 自身の UID/GID は lease に選ばない。
  - workspace/runtime temp への書き込みは leased ID に map された detached mount 経由のみ。継承 mount tree は再帰 read-only。host 上の file owner は leased ID となり daemon 作成 file と DAC level で区別される。
  - lease は durable sandbox と同寿命（SSH session / daemon restart を跨ぐ）。ledger は `$XDG_DATA_HOME/shbox/subid-leases`。

## 4. macOS

- native arm64、かつ native gate で enforcement smoke が passing した tested major のみ。
- `/usr/bin/sandbox-exec` が存在し、deny/allow smoke が enforce されること。
- `identity = "isolated"` は非対応。指定した sandbox 作成は fail closed する（Linux user namespace の primitive がないため）。

## 5. 確認方法

```sh
uname -r            # Landlock ABI 4+ (6.7+) か
cat /proc/self/cgroup   # delegated cgroup v2 parent の診断
getsubids -l            # isolated 用: daemon account の UID delegation
getsubids -g -l         # isolated 用: GID delegation
scripts/verify-linux-platform --arch x86_64  # または aarch64
```

fail closed のまとめ: Landlock 不足、writable cgroup 階層なし、namespace/setup 失敗、subordinate delegation・helper・broker・ID-mapped mount のいずれかの欠落があれば、その launch（isolated の場合は当該 sandbox の新規 launch）を拒否し、daemon identity での実行や別 OS backend への代替はしない。

## 6. 関連文書

- [platforms.md](platforms.md) §2/§5 — Linux backend と deployment prerequisites
- [configuration.md](configuration.md) §4.3/§4.5 — `identity` と resource limits / `cgroup_parent`
- [security.md](security.md) §5.2.1 — identity isolation の機構と fail-closed 条件
- [release.md](release.md) §8/§10 — provider acceptance と deploy hardening
