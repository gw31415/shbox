//! Seatbelt profile generation (architecture Phase 10).
//!
//! The profile is generated completely in the parent from the caller's
//! [`FilesystemPolicy`] and [`NetworkPolicy`]. It is a deny-default profile
//! with explicit grants; `Unrestricted` policies emit the corresponding
//! broad allows rather than dropping the deny-default.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::command::SessionSetup;
use crate::error::SandboxError;
use crate::policy::{FilesystemPolicy, NetworkPolicy};

/// Render the Seatbelt profile for one sandbox.
pub fn build_profile(
    filesystem: &FilesystemPolicy,
    network: NetworkPolicy,
    session: SessionSetup,
) -> Result<String, SandboxError> {
    let mut profile = String::with_capacity(8192);
    writeln!(&mut profile, "(version 1)").expect("write profile");
    writeln!(&mut profile, "(deny default)").expect("write profile");

    // Process/session behavior: fork/exec, self and same-sandbox inspection
    // and signaling. This baseline mirrors the shbox-audited policy.
    writeln!(&mut profile, "(allow process-fork)").expect("write profile");
    writeln!(&mut profile, "(allow process-info* (target self))").expect("write profile");
    writeln!(&mut profile, "(allow process-info* (target same-sandbox))").expect("write profile");
    writeln!(&mut profile, "(allow signal (target self))").expect("write profile");
    writeln!(&mut profile, "(allow signal (target same-sandbox))").expect("write profile");
    writeln!(&mut profile, "(allow sysctl-read)").expect("write profile");
    writeln!(&mut profile, "(allow system-fsctl)").expect("write profile");
    writeln!(&mut profile, "(allow system-info)").expect("write profile");

    // Mach/IPC baseline for ordinary runtimes; credential-bearing security
    // services stay denied.
    writeln!(&mut profile, "(allow mach-lookup)").expect("write profile");
    for service in [
        "com.apple.SecurityServer",
        "com.apple.securityd",
        "com.apple.security.keychaind",
        "com.apple.secd",
        "com.apple.security.agent",
    ] {
        writeln!(
            &mut profile,
            "(deny mach-lookup (global-name \"{service}\"))"
        )
        .expect("write profile");
    }
    writeln!(&mut profile, "(allow mach-per-user-lookup)").expect("write profile");
    writeln!(&mut profile, "(allow mach-task-name)").expect("write profile");
    writeln!(&mut profile, "(deny mach-priv*)").expect("write profile");
    writeln!(&mut profile, "(allow ipc-posix-shm-read-data)").expect("write profile");
    writeln!(&mut profile, "(allow ipc-posix-shm-write-data)").expect("write profile");
    writeln!(&mut profile, "(allow ipc-posix-shm-write-create)").expect("write profile");

    let FilesystemPolicy::Restricted {
        read_only,
        read_write,
        execute,
    } = filesystem
    else {
        // Explicitly unrestricted: broad file grants, deny-default keeps
        // applying to everything not listed here (nothing).
        writeln!(&mut profile, "(allow file-read*)").expect("write profile");
        writeln!(&mut profile, "(allow file-write*)").expect("write profile");
        writeln!(&mut profile, "(allow file-map-executable)").expect("write profile");
        writeln!(&mut profile, "(allow process-exec*)").expect("write profile");
        append_network_rules(&mut profile, network);
        return Ok(profile);
    };

    // dyld needs root metadata plus every ancestor of a granted path;
    // ancestors receive metadata only. Rule paths are canonicalized first:
    // Seatbelt filters match on the resolved path, and e.g. macOS /var is a
    // symlink to /private/var.
    writeln!(&mut profile, "(allow file-read* (literal \"/\"))").expect("write profile");
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let canonical_rules = |rules: &[crate::policy::PathRule]| -> Vec<PathBuf> {
        rules.iter().map(|rule| canonical(&rule.path)).collect()
    };
    let read_only: Vec<PathBuf> = canonical_rules(read_only);
    let read_write: Vec<PathBuf> = canonical_rules(read_write);
    let execute: Vec<PathBuf> = canonical_rules(execute);

    let mut ancestors = BTreeSet::new();
    for path in read_only
        .iter()
        .chain(read_write.iter())
        .chain(execute.iter())
    {
        let mut current = path.parent();
        while let Some(parent) = current {
            if parent == Path::new("/") || parent.as_os_str().is_empty() {
                break;
            }
            ancestors.insert(parent.to_path_buf());
            current = parent.parent();
        }
    }
    for ancestor in ancestors {
        append_path_rule(&mut profile, "file-read-metadata", "subpath", &ancestor)?;
    }

    // Keep the macOS tiers faithful to their names. Unlike Landlock, Seatbelt
    // can distinguish reading a path from mapping and executing it.
    for path in &read_only {
        append_existing_rule(&mut profile, "file-read*", path)?;
    }
    for rules in [&read_write, &execute] {
        for path in rules {
            append_existing_rule(&mut profile, "file-read*", path)?;
            append_existing_rule(&mut profile, "file-map-executable", path)?;
            append_existing_rule(&mut profile, "process-exec*", path)?;
        }
    }
    for path in &read_write {
        append_existing_rule(&mut profile, "file-write*", path)?;
    }

    if matches!(session, SessionSetup::NewSessionWithControllingTerminal) {
        writeln!(&mut profile, "(allow pseudo-tty)").expect("write profile");
        writeln!(&mut profile, "(allow file-read* (literal \"/dev/tty\"))").expect("write profile");
        writeln!(&mut profile, "(allow file-write* (literal \"/dev/tty\"))")
            .expect("write profile");
        writeln!(&mut profile, "(allow file-ioctl (literal \"/dev/tty\"))").expect("write profile");
        writeln!(
            &mut profile,
            "(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))"
        )
        .expect("write profile");
        writeln!(
            &mut profile,
            "(allow file-ioctl (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))"
        )
        .expect("write profile");
    }

    append_network_rules(&mut profile, network);
    Ok(profile)
}

fn append_network_rules(profile: &mut String, network: NetworkPolicy) {
    match network {
        NetworkPolicy::Unrestricted => {
            writeln!(profile, "(allow network-outbound)").expect("write profile");
            writeln!(profile, "(allow network-bind)").expect("write profile");
            writeln!(profile, "(allow network-inbound)").expect("write profile");
        }
        NetworkPolicy::OutboundTcp => {
            // Client-only TCP: no bind/inbound rules are emitted.
            for domain in ["AF_INET", "AF_INET6", "AF_UNIX"] {
                writeln!(
                    profile,
                    "(allow system-socket (socket-domain {domain}) (socket-type SOCK_STREAM))"
                )
                .expect("write profile");
            }
            writeln!(profile, "(allow network-outbound (remote tcp))").expect("write profile");
            for path in ["/private/var/run/mDNSResponder", "/var/run/mDNSResponder"] {
                writeln!(profile, "(allow network-outbound (path \"{path}\"))")
                    .expect("write profile");
            }
        }
        NetworkPolicy::Disabled => {}
    }
}

fn append_existing_rule(
    profile: &mut String,
    operation: &str,
    path: &Path,
) -> Result<(), SandboxError> {
    let metadata = fs::metadata(path).map_err(|_| {
        SandboxError::invalid(
            "filesystem",
            format!(
                "rule path {} became unavailable for Seatbelt",
                path.display()
            ),
        )
    })?;
    let filter = if metadata.is_dir() {
        "subpath"
    } else {
        "literal"
    };
    append_path_rule(profile, operation, filter, path)
}

fn append_path_rule(
    profile: &mut String,
    operation: &str,
    filter: &str,
    path: &Path,
) -> Result<(), SandboxError> {
    let escaped = escape_path(path)?;
    writeln!(profile, "(allow {operation} ({filter} \"{escaped}\"))").expect("write profile");
    Ok(())
}

/// Escape a path for a double-quoted Seatbelt literal. Control characters
/// are rejected outright rather than escaped into a form Seatbelt might
/// reinterpret.
fn escape_path(path: &Path) -> Result<String, SandboxError> {
    let value = path.to_str().ok_or_else(|| {
        SandboxError::invalid(
            "filesystem",
            "path is not valid UTF-8 for a Seatbelt profile",
        )
    })?;
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                return Err(SandboxError::invalid(
                    "filesystem",
                    "path contains a control character unsupported by Seatbelt",
                ));
            }
            character => escaped.push(character),
        }
    }
    Ok(escaped)
}

/// Single-quote a value so `/bin/sh` passes it through verbatim inside the
/// `exec -a` wrapper used for explicit `argv[0]` overrides.
pub fn sh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PathRule;

    fn restricted(read_only: Vec<PathRule>, read_write: Vec<PathRule>) -> FilesystemPolicy {
        FilesystemPolicy::Restricted {
            read_only,
            read_write,
            execute: Vec::new(),
        }
    }

    #[test]
    fn profile_is_deny_default_and_scopes_writes_and_network() {
        let workspace = tempfile::tempdir().expect("workspace");
        let profile = build_profile(
            &restricted(
                vec![PathRule::new("/usr")],
                vec![PathRule::new(workspace.path())],
            ),
            NetworkPolicy::Disabled,
            SessionSetup::NewSessionWithControllingTerminal,
        )
        .expect("profile");
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow pseudo-tty)"));
        assert!(!profile.contains("(allow file-write* (subpath \"/\"))"));
        assert!(!profile.contains("(allow network-outbound"));

        let outbound = build_profile(
            &restricted(vec![PathRule::new("/usr")], Vec::new()),
            NetworkPolicy::OutboundTcp,
            SessionSetup::Inherit,
        )
        .expect("profile");
        assert!(outbound.contains("(allow network-outbound (remote tcp))"));
        assert!(!outbound.contains("(allow network-bind)"));
        assert!(!outbound.contains("(allow network-inbound)"));
    }

    #[test]
    fn unrestricted_policy_emits_broad_allows() {
        let profile = build_profile(
            &FilesystemPolicy::Unrestricted,
            NetworkPolicy::Unrestricted,
            SessionSetup::Inherit,
        )
        .expect("profile");
        assert!(profile.contains("(allow file-read*)"));
        assert!(profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn restricted_filesystem_tiers_keep_read_only_non_executable() {
        let root = tempfile::tempdir().expect("filesystem root");
        let read_only = root.path().join("read-only");
        let read_write = root.path().join("read-write");
        let execute = root.path().join("execute");
        for path in [&read_only, &read_write, &execute] {
            std::fs::create_dir(path).expect("tier directory");
        }
        let canonical = |path: &Path| {
            std::fs::canonicalize(path)
                .expect("canonical tier")
                .display()
                .to_string()
        };
        let profile = build_profile(
            &FilesystemPolicy::Restricted {
                read_only: vec![PathRule::new(&read_only)],
                read_write: vec![PathRule::new(&read_write)],
                execute: vec![PathRule::new(&execute)],
            },
            NetworkPolicy::Disabled,
            SessionSetup::Inherit,
        )
        .expect("profile");

        let read_only = canonical(&read_only);
        let read_write = canonical(&read_write);
        let execute = canonical(&execute);
        assert!(profile.contains(&format!("(allow file-read* (subpath \"{read_only}\"))")));
        assert!(!profile.contains(&format!(
            "(allow file-map-executable (subpath \"{read_only}\"))"
        )));
        assert!(!profile.contains(&format!("(allow process-exec* (subpath \"{read_only}\"))")));
        assert!(!profile.contains(&format!("(allow file-write* (subpath \"{read_only}\"))")));

        for path in [&read_write, &execute] {
            assert!(profile.contains(&format!("(allow file-read* (subpath \"{path}\"))")));
            assert!(profile.contains(&format!("(allow file-map-executable (subpath \"{path}\"))")));
            assert!(profile.contains(&format!("(allow process-exec* (subpath \"{path}\"))")));
        }
        assert!(profile.contains(&format!("(allow file-write* (subpath \"{read_write}\"))")));
        assert!(!profile.contains(&format!("(allow file-write* (subpath \"{execute}\"))")));
    }

    #[test]
    fn path_escaping_cannot_inject_a_rule() {
        let escaped = escape_path(Path::new("/tmp/x\"\n(allow default)")).expect("escaped");
        assert!(escaped.contains("\\\""), "escaped path: {escaped:?}");
        assert!(!escaped.contains('\n'), "raw newline survived");
    }

    #[test]
    fn sh_quoting_closes_and_reopens_single_quotes() {
        assert_eq!(sh_single_quote("-sh"), "'-sh'");
        assert_eq!(
            sh_single_quote("/opt/sh'ells/zsh"),
            "'/opt/sh'\\''ells/zsh'"
        );
    }
}
