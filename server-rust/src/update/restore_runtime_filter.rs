//! Allowlist for one non-daemonizing native SSH syntax-check process.

use super::SandboxError;
use nix::libc;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

pub(super) fn compile() -> Result<BpfProgram, SandboxError> {
    let mut rules = BTreeMap::new();
    for syscall in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_ppoll,
        libc::SYS_close,
        libc::SYS_lseek,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getgroups,
        libc::SYS_capget,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_getrandom,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrusage,
        // Needed for the one initial native exec. This is not an executable-
        // pathname filter: a compromised process can re-exec within its same
        // closed root, but cannot fork or acquire any host/network authority.
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
    ] {
        rules.insert(syscall, Vec::new());
    }
    // Redirection is limited to standard streams. Do not permit native code to
    // manufacture a high-numbered descriptor outside the bounded fd table.
    rules.insert(
        libc::SYS_dup3,
        (0..=2).map(|fd| equals(1, fd)).collect::<Result<_, _>>()?,
    );
    // OpenSSH raises its /dev/null descriptor to REEXEC_MIN_FREE_FD (5) with
    // dup() before the syntax check. Restrict the source descriptor to the
    // standard streams and that reserved range; no arbitrary inherited fd can
    // be duplicated.
    rules.insert(
        libc::SYS_dup,
        (0..=5).map(|fd| equals(0, fd)).collect::<Result<_, _>>()?,
    );
    #[cfg(target_arch = "x86_64")]
    rules.insert(
        libc::SYS_dup2,
        (0..=2).map(|fd| equals(1, fd)).collect::<Result<_, _>>()?,
    );
    #[cfg(target_arch = "x86_64")]
    for syscall in [
        libc::SYS_open,
        libc::SYS_poll,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_readlink,
        libc::SYS_arch_prctl,
        libc::SYS_getrlimit,
        libc::SYS_time,
    ] {
        rules.insert(syscall, Vec::new());
    }
    // Only harmless tty queries, not arbitrary device or terminal control.
    rules.insert(
        libc::SYS_ioctl,
        [libc::TCGETS, libc::TIOCGWINSZ, libc::FIONREAD]
            .into_iter()
            // libc exposes these positive 32-bit requests as u64 on x86_64
            // and i32 on RV64; normalize without a platform-specific cast lint.
            .map(|value| equals(1, u64::from(value as u32)))
            .collect::<Result<Vec<_>, _>>()?,
    );
    rules.insert(libc::SYS_prlimit64, vec![equals(0, 0)?]);
    // No F_SETOWN/F_SETSIG, leases, dnotify or locking side channels. The native
    // syntax checker needs descriptor/status queries and close-on-exec flags.
    rules.insert(
        libc::SYS_fcntl,
        [libc::F_GETFD, libc::F_SETFD, libc::F_GETFL]
            .into_iter()
            .map(|value| equals(1, value as u64))
            .collect::<Result<Vec<_>, _>>()?,
    );
    rules.insert(
        libc::SYS_prctl,
        [
            libc::PR_GET_DUMPABLE,
            libc::PR_GET_NO_NEW_PRIVS,
            libc::PR_GET_PDEATHSIG,
            libc::PR_GET_SECUREBITS,
            libc::PR_CAPBSET_READ,
        ]
        .into_iter()
        .map(|value| equals(0, value as u64))
        .collect::<Result<Vec<_>, _>>()?,
    );
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| SandboxError::Filter)?,
    )
    .map_err(|_| SandboxError::Filter)?;
    filter.try_into().map_err(|_| SandboxError::Filter)
}

fn equals(argument: u8, value: u64) -> Result<SeccompRule, SandboxError> {
    SeccompRule::new(vec![
        SeccompCondition::new(argument, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, value)
            .map_err(|_| SandboxError::Filter)?,
    ])
    .map_err(|_| SandboxError::Filter)
}
