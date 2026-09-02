//! Child-side capability dropping (architecture Phase 5).
//!
//! Everything here runs post-`clone3` in the child and must stay
//! allocation-free: fixed buffers, raw syscalls only.

/// `_LINUX_CAPABILITY_VERSION_3`.
const CAPABILITY_VERSION_3: libc::c_uint = 0x2008_0522;
const CAP_SETPCAP: u32 = 8;

// prctl operations not universally present in the libc crate.
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_CAP_AMBIENT: libc::c_int = 38;
const PR_CAP_AMBIENT_RAISE: libc::c_int = 2;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct CapUserHeader {
    version: libc::c_uint,
    pid: libc::c_int,
}

/// Drop capabilities down to `retain_mask` (bit `n` = capability `n`).
///
/// `PR_SET_NO_NEW_PRIVS` must already be active. The bounding set is narrowed
/// first when the caller still has `CAP_SETPCAP`; an unprivileged daemon is
/// allowed to leave its inherited bounding set unchanged because
/// `no_new_privs` prevents `execve` from gaining capabilities from setuid or
/// file-capability metadata. The effective/permitted/inheritable and ambient
/// sets are always reduced to the requested mask.
///
/// Runs post-`clone3` in the child; allocation-free.
pub(super) fn drop_capabilities(retain_mask: u64) -> Result<(), i32> {
    // Bounding-set modification requires CAP_SETPCAP. When available, drop
    // every other non-retained capability first and CAP_SETPCAP itself last;
    // otherwise dropping CAP_SETPCAP early would make the remainder fail.
    if let Err(errno) = drop_bounding_set(retain_mask)
        && errno != libc::EPERM
    {
        return Err(errno);
    }

    let header = CapUserHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let low = retain_mask as u32;
    let high = (retain_mask >> 32) as u32;
    let data = [
        CapUserData {
            effective: low,
            permitted: low,
            inheritable: low,
        },
        CapUserData {
            effective: high,
            permitted: high,
            inheritable: high,
        },
    ];
    // SAFETY: Linux capability v3 expects one header followed by two
    // __user_cap_data_struct entries, each containing three u32 fields.
    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapUserHeader,
            data.as_ptr(),
        )
    } == -1
    {
        return Err(super::raw_errno());
    }

    // Clear the whole ambient set, then re-raise the retained capabilities.
    // SAFETY: fixed prctl operation codes with scalar arguments.
    if unsafe {
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    } == -1
    {
        // Kernels without ambient support (pre-4.3) return EINVAL or ENODATA;
        // nothing could have been raised there, so it is safe to continue.
        let errno = super::raw_errno();
        if errno != libc::EINVAL && errno != libc::ENOTSUP && errno != libc::ENODATA {
            return Err(errno);
        }
    }

    for cap in 0..=u32::from(crate::policy::CAP_LAST_NUMBER) {
        if retain_mask & (1_u64 << cap) == 0 {
            continue;
        }
        // SAFETY: scalar prctl raising one ambient capability retained in
        // the permitted and inheritable sets by the capset above.
        if unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                cap as libc::c_ulong,
                0,
                0,
            )
        } == -1
        {
            return Err(super::raw_errno());
        }
    }
    Ok(())
}

fn drop_bounding_set(retain_mask: u64) -> Result<(), i32> {
    for cap in 0..=u32::from(crate::policy::CAP_LAST_NUMBER) {
        if cap == CAP_SETPCAP || retain_mask & (1_u64 << cap) != 0 {
            continue;
        }
        // SAFETY: scalar prctl dropping one bounding-set capability.
        if unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) } == -1 {
            let errno = super::raw_errno();
            // EINVAL marks an unknown (already dropped / unsupported)
            // capability number; dropping it again is a no-op.
            if errno != libc::EINVAL {
                return Err(errno);
            }
        }
    }

    if retain_mask & (1_u64 << CAP_SETPCAP) == 0 {
        // SAFETY: CAP_SETPCAP is deliberately dropped last so this operation
        // cannot revoke the privilege needed by preceding drops.
        if unsafe { libc::prctl(PR_CAPBSET_DROP, CAP_SETPCAP as libc::c_ulong, 0, 0, 0) } == -1 {
            let errno = super::raw_errno();
            if errno != libc::EINVAL {
                return Err(errno);
            }
        }
    }
    Ok(())
}

/// Build the retain bit mask from a policy's retained capability list.
pub(super) fn retain_mask(retained: &[crate::policy::Capability]) -> u64 {
    let mut mask = 0_u64;
    for capability in retained {
        mask |= 1_u64 << capability.number();
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::super::raw_errno;

    #[test]
    fn capability_v3_data_matches_uapi_layout() {
        assert_eq!(std::mem::size_of::<super::CapUserData>(), 12);
        assert_eq!(std::mem::size_of::<[super::CapUserData; 2]>(), 24);
    }

    #[test]
    fn retain_mask_bits_follow_capability_numbers() {
        use crate::policy::Capability;
        assert_eq!(super::retain_mask(&[]), 0);
        assert_eq!(
            super::retain_mask(&[Capability::CAP_NET_BIND_SERVICE]),
            1_u64 << Capability::CAP_NET_BIND_SERVICE.number()
        );
        assert_eq!(
            super::retain_mask(&[Capability::CAP_SYS_ADMIN, Capability::CAP_BPF]),
            (1_u64 << Capability::CAP_SYS_ADMIN.number()) | (1_u64 << Capability::CAP_BPF.number())
        );
        assert!(Capability::from_number(41).is_none());
        assert_eq!(Capability::from_number(0).unwrap().number(), 0);
        assert_eq!(raw_errno(), 0);
    }
}
