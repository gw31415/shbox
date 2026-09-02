# shbox

Foreground SSH daemon that maps OpenSSH clients onto persistent sandbox workspaces.

- Rust 1.95 / edition 2024
- Main dependencies: `russh` 0.63, `tokio` 1, `ssh-key` 0.7.0-rc
- Transports: `tcp` (default feature), `ws` (feature-gated WebSocket)

## Workspace layout

| crate | role |
|---|---|
| `crates/shbox` | the SSH daemon (transport, auth, sessions, sandbox workspaces) |
| `crates/shbox-sandbox` | sandbox engine: Linux `clone3`+pidfd / Landlock / seccomp / cgroup v2, macOS Seatbelt |

The daemon composes its per-launch policy (curated readable system paths,
per-launch workspace, network mode, resource limits) into an explicit
`shbox-sandbox` `SandboxConfig`; the engine crate itself ships no security
profiles. See [crates/shbox-sandbox/README.md](crates/shbox-sandbox/README.md).

## Build

```sh
cargo build
cargo test
```

## Documentation

The specification lives in [docs/](docs/README.md). See in particular:

- [docs/product.md](docs/product.md) — purpose and SSH operations
- [docs/configuration.md](docs/configuration.md) — TOML and XDG paths
- [docs/release.md](docs/release.md) — release gates and CI evidence
- [docs/maintenance.md](docs/maintenance.md) — dependency update policy

## Status

v0.1, `publish = false`. Not a drop-in OpenSSH replacement; see [docs/product.md](docs/product.md) for non-goals.
