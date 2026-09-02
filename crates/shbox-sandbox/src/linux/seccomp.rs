//! seccomp-BPF compilation (architecture Phase 7).
//!
//! The policy-to-BPF compilation is entirely parent-side (`seccompiler`).
//! The child only issues `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, …)`
//! with the serialized program — no allocation, no error construction.
//!
//! The crate provides no syscall profiles: the allowlist/denylist, argument
//! filters, and default action all come from the caller's
//! [`SyscallPolicy`]. Compilation failures (unknown syscalls, contradictory
//! filters) are [`SandboxError::InvalidPolicy`] *before* any child exists;
//! installation failures abort the child before `exec`.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction as CompiledAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

use crate::error::SandboxError;
use crate::policy::{ArgLen, CmpOp, SeccompAction, Syscall, SyscallPolicy};

/// The serialized BPF program handed to the child, or `None` when no filter
/// is requested.
pub type CompiledSeccomp = Option<BpfProgram>;

/// Resolve a syscall name on this architecture.
pub fn syscall_number(name: &str) -> Option<i64> {
    super::syscall_names::syscall_number(name)
}

/// Compile the policy into a BPF program.
pub fn compile(policy: &SyscallPolicy) -> Result<CompiledSeccomp, SandboxError> {
    let SyscallPolicy::Filter {
        default_action,
        matched_action,
        rules,
    } = policy
    else {
        return Ok(None);
    };

    let mut compiled_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for rule in rules {
        let number = match rule.syscall {
            Syscall::Named(name) => syscall_number(name).ok_or_else(|| {
                SandboxError::invalid(
                    "syscalls.rules",
                    format!("unknown syscall name {name:?} for this architecture"),
                )
            })?,
            Syscall::Number(number) => number,
        };
        if rule.conditions.is_empty() {
            // An empty rule list matches on the syscall number alone.
            compiled_rules.entry(number).or_default();
            continue;
        }
        let mut conditions = Vec::with_capacity(rule.conditions.len());
        for condition in &rule.conditions {
            conditions.push(
                SeccompCondition::new(
                    condition.arg,
                    match condition.len {
                        ArgLen::Dword => SeccompCmpArgLen::Dword,
                        ArgLen::Qword => SeccompCmpArgLen::Qword,
                    },
                    match condition.op {
                        CmpOp::Equal => SeccompCmpOp::Eq,
                        CmpOp::Greater => SeccompCmpOp::Gt,
                        CmpOp::GreaterEqual => SeccompCmpOp::Ge,
                        CmpOp::Less => SeccompCmpOp::Lt,
                        CmpOp::LessEqual => SeccompCmpOp::Le,
                        CmpOp::MaskedEqual => SeccompCmpOp::MaskedEq(condition.value),
                        CmpOp::NotEqual => SeccompCmpOp::Ne,
                    },
                    condition.value,
                )
                .map_err(|error| {
                    SandboxError::invalid(
                        "syscalls.rules",
                        format!("condition rejected by the compiler: {error}"),
                    )
                })?,
            );
        }
        let compiled = SeccompRule::new(conditions).map_err(|error| {
            SandboxError::invalid(
                "syscalls.rules",
                format!("rule rejected by the compiler: {error}"),
            )
        })?;
        compiled_rules.entry(number).or_default().push(compiled);
    }

    let filter = SeccompFilter::new(
        compiled_rules,
        compile_action(*default_action),
        compile_action(*matched_action),
        target_arch()?,
    )
    .map_err(|error| {
        SandboxError::invalid("syscalls", format!("filter compilation failed: {error}"))
    })?;

    let program: BpfProgram = filter
        .try_into()
        .map_err(|error: seccompiler::BackendError| {
            SandboxError::invalid(
                "syscalls",
                format!("BPF program generation failed: {error}"),
            )
        })?;
    if program.is_empty() {
        return Err(SandboxError::invalid(
            "syscalls",
            "compiled filter is empty",
        ));
    }
    // The kernel interface takes the program length as u16; check it here so
    // an oversized policy is a named InvalidPolicy instead of a wrapped
    // length (or an opaque EINVAL) in the child.
    if program.len() > libc::c_ushort::MAX as usize {
        return Err(SandboxError::invalid(
            "syscalls",
            format!(
                "compiled filter has {} instructions; the kernel interface accepts at most {}",
                program.len(),
                libc::c_ushort::MAX
            ),
        ));
    }
    Ok(Some(program))
}

fn compile_action(action: SeccompAction) -> CompiledAction {
    match action {
        SeccompAction::Allow => CompiledAction::Allow,
        SeccompAction::Errno(errno) => CompiledAction::Errno(errno),
        SeccompAction::KillThread => CompiledAction::KillThread,
        SeccompAction::KillProcess => CompiledAction::KillProcess,
        SeccompAction::Log => CompiledAction::Log,
        SeccompAction::Trace(value) => CompiledAction::Trace(value),
        SeccompAction::Trap => CompiledAction::Trap,
    }
}

fn target_arch() -> Result<TargetArch, SandboxError> {
    std::env::consts::ARCH.try_into().map_err(|_| {
        SandboxError::unsupported(
            "seccomp",
            format!(
                "no seccomp program layout exists for architecture {}",
                std::env::consts::ARCH
            ),
        )
    })
}

/// Install a compiled program on the calling thread. Runs in the child
/// between `clone3` and `execve`; raw errno on failure, no allocation.
/// `program` is parent-compiled memory inherited copy-on-write.
pub fn apply_raw(program: &[seccompiler::sock_filter]) -> Result<(), i32> {
    #[repr(C)]
    struct SockFprog {
        len: libc::c_ushort,
        filter: *const seccompiler::sock_filter,
    }
    // Checked conversion: a wrapped length would make the kernel install a
    // prefix of the program. The parent rejects oversized programs at
    // compile time; this backstop fails closed with EINVAL.
    let len = u16::try_from(program.len()).map_err(|_| libc::EINVAL)?;
    let fprog = SockFprog {
        len,
        filter: program.as_ptr(),
    };
    // SAFETY: fprog points at initialized stack storage and the filter
    // slice is inherited parent memory the kernel only reads.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &fprog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    } == -1
    {
        return Err(super::raw_errno());
    }
    Ok(())
}
