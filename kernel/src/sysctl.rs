//! Writable kernel tunables surfaced under /proc/sys (Linux sysctl).
//! Values live here so every consumer reads the live knob, not a const.

use core::sync::atomic::{AtomicU64, Ordering};

static PID_MAX: AtomicU64 = AtomicU64::new(32768);
static THREADS_MAX: AtomicU64 = AtomicU64::new(1024);
static YAMA_SCOPE: AtomicU64 = AtomicU64::new(0);
static FS_NR_OPEN: AtomicU64 = AtomicU64::new(1_048_576);
static FS_PIPE_MAX: AtomicU64 = AtomicU64::new(64 * 1024);
static INOTIFY_MAX_WATCHES: AtomicU64 = AtomicU64::new(128);
static FS_FILE_MAX: AtomicU64 = AtomicU64::new(1_048_576);
static PTY_MAX: AtomicU64 = AtomicU64::new(4096);
static VM_MAX_MAP_COUNT: AtomicU64 = AtomicU64::new(65530);
static SHMMAX: AtomicU64 = AtomicU64::new(32 * 1024 * 1024);
static SHMALL: AtomicU64 = AtomicU64::new(262144);
static SHMMNI: AtomicU64 = AtomicU64::new(4096);
static MQ_MSG_MAX: AtomicU64 = AtomicU64::new(10);
static MQ_MSGSIZE_MAX: AtomicU64 = AtomicU64::new(8192);
static MQ_QUEUES_MAX: AtomicU64 = AtomicU64::new(256);
static INOTIFY_MAX_QUEUED: AtomicU64 = AtomicU64::new(16384);
static EPOLL_MAX_WATCHES: AtomicU64 = AtomicU64::new(131072);
static UNPRIV_PORT_START: AtomicU64 = AtomicU64::new(1024);
static NGROUPS_MAX: AtomicU64 = AtomicU64::new(65536);
static OVERCOMMIT_MEMORY: AtomicU64 = AtomicU64::new(0);
static OVERCOMMIT_RATIO: AtomicU64 = AtomicU64::new(50);
static KPTR_RESTRICT: AtomicU64 = AtomicU64::new(0);
static PROTECTED_SYMLINKS: AtomicU64 = AtomicU64::new(1);
static LOCAL_PORT_LO: AtomicU64 = AtomicU64::new(49152);
static LOCAL_PORT_HI: AtomicU64 = AtomicU64::new(65535);
static UNPRIV_USERNS: AtomicU64 = AtomicU64::new(1);
static MMAP_MIN_ADDR: AtomicU64 = AtomicU64::new(0x10000);
static MIN_FREE_KB: AtomicU64 = AtomicU64::new(8192);
static PROTECTED_FIFOS: AtomicU64 = AtomicU64::new(1);
static PROTECTED_REGULAR: AtomicU64 = AtomicU64::new(0);
static UNIX_MAX_QLEN: AtomicU64 = AtomicU64::new(64);
static SOMAXCONN: AtomicU64 = AtomicU64::new(4096);
static USER_NS_MAX: AtomicU64 = AtomicU64::new(0);
static MNT_NS_MAX: AtomicU64 = AtomicU64::new(0);
static UTS_NS_MAX: AtomicU64 = AtomicU64::new(0);
static PID_NS_MAX: AtomicU64 = AtomicU64::new(0);
static IPC_NS_MAX: AtomicU64 = AtomicU64::new(0);
static TIME_NS_MAX: AtomicU64 = AtomicU64::new(0);
static ICMP_ECHO_IGNORE_BCAST: AtomicU64 = AtomicU64::new(1);
static IP_FORWARD: AtomicU64 = AtomicU64::new(0);
static KERNEL_SYSRQ: AtomicU64 = AtomicU64::new(1);
static DMESG_RESTRICT: AtomicU64 = AtomicU64::new(0);
static RANDOMIZE_VA: AtomicU64 = AtomicU64::new(2);

pub fn pid_max() -> u64 {
    PID_MAX.load(Ordering::Relaxed).clamp(1, 4_194_304)
}
pub fn threads_max() -> u64 {
    THREADS_MAX.load(Ordering::Relaxed).clamp(1, 1_048_576)
}
pub fn yama_scope() -> u64 {
    YAMA_SCOPE.load(Ordering::Relaxed)
}
pub fn fs_nr_open() -> u64 {
    FS_NR_OPEN.load(Ordering::Relaxed).clamp(1, 4_194_304)
}
pub fn fs_pipe_max() -> usize {
    (FS_PIPE_MAX.load(Ordering::Relaxed).clamp(4096, 1 << 20)) as usize
}
pub fn inotify_max_watches() -> u64 {
    INOTIFY_MAX_WATCHES.load(Ordering::Relaxed).clamp(1, 1 << 20)
}
pub fn fs_file_max() -> u64 {
    FS_FILE_MAX.load(Ordering::Relaxed).clamp(0, u64::MAX / 2)
}
pub fn pty_max() -> u64 {
    PTY_MAX.load(Ordering::Relaxed).clamp(0, 1 << 20)
}
pub fn vm_max_map_count() -> u64 {
    VM_MAX_MAP_COUNT.load(Ordering::Relaxed).clamp(1, u64::MAX / 2)
}
pub fn shmmax() -> u64 {
    SHMMAX.load(Ordering::Relaxed)
}
pub fn shmall() -> u64 {
    SHMALL.load(Ordering::Relaxed)
}
pub fn shmmni() -> u64 {
    SHMMNI.load(Ordering::Relaxed)
}
pub fn mq_msg_max() -> u64 {
    MQ_MSG_MAX.load(Ordering::Relaxed)
}
pub fn mq_msgsize_max() -> u64 {
    MQ_MSGSIZE_MAX.load(Ordering::Relaxed)
}
pub fn mq_queues_max() -> u64 {
    MQ_QUEUES_MAX.load(Ordering::Relaxed)
}
pub fn inotify_max_queued() -> usize {
    INOTIFY_MAX_QUEUED.load(Ordering::Relaxed) as usize
}
pub fn epoll_max_watches() -> u64 {
    EPOLL_MAX_WATCHES.load(Ordering::Relaxed)
}
pub fn unpriv_port_start() -> u64 {
    UNPRIV_PORT_START.load(Ordering::Relaxed).min(65535)
}
pub fn ngroups_max() -> u64 {
    NGROUPS_MAX.load(Ordering::Relaxed)
}
pub fn icmp_echo_ignore_bcast() -> u64 {
    ICMP_ECHO_IGNORE_BCAST.load(Ordering::Relaxed)
}
pub fn ip_forward() -> u64 {
    IP_FORWARD.load(Ordering::Relaxed)
}
pub fn kernel_sysrq() -> u64 {
    KERNEL_SYSRQ.load(Ordering::Relaxed)
}
pub fn dmesg_restrict() -> u64 {
    DMESG_RESTRICT.load(Ordering::Relaxed)
}
pub fn randomize_va_space() -> u64 {
    RANDOMIZE_VA.load(Ordering::Relaxed)
}
pub fn vm_overcommit_memory() -> u64 {
    OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}
pub fn vm_overcommit_ratio() -> u64 {
    OVERCOMMIT_RATIO.load(Ordering::Relaxed)
}
pub fn kptr_restrict() -> u64 {
    KPTR_RESTRICT.load(Ordering::Relaxed)
}
pub fn protected_symlinks() -> u64 {
    PROTECTED_SYMLINKS.load(Ordering::Relaxed)
}
pub fn local_port_range() -> (u64, u64) {
    (
        LOCAL_PORT_LO.load(Ordering::Relaxed),
        LOCAL_PORT_HI.load(Ordering::Relaxed),
    )
}
pub fn set_local_port_range(lo: u64, hi: u64) -> bool {
    if lo == 0 || hi == 0 || lo > hi || hi > 65535 {
        return false;
    }
    LOCAL_PORT_LO.store(lo, Ordering::Relaxed);
    LOCAL_PORT_HI.store(hi, Ordering::Relaxed);
    true
}
/// kernel.unprivileged_userns_clone (default 1): allow CLONE_NEWUSER
/// unshare() from tasks without CAP_SYS_ADMIN.
pub fn unpriv_userns_clone() -> u64 {
    UNPRIV_USERNS.load(Ordering::Relaxed)
}
/// vm.mmap_min_addr (default 64KiB): floor for MAP_FIXED placements —
/// CAP_SYS_RAWIO bypasses it like on Linux.
pub fn mmap_min_addr() -> u64 {
    MMAP_MIN_ADDR.load(Ordering::Relaxed)
}
/// vm.min_free_kbytes: userspace reservations must leave this much RAM
/// free — a zone-watermark style deny in the reserve path.
pub fn min_free_kbytes() -> u64 {
    MIN_FREE_KB.load(Ordering::Relaxed)
}
/// fs.protected_fifos: 1 = block O_WRONLY opens of foreign fifos in
/// sticky world-writable dirs, 2 = also gate read opens.
pub fn protected_fifos() -> u64 {
    PROTECTED_FIFOS.load(Ordering::Relaxed)
}
/// fs.protected_regular: O_CREAT open-for-write of an existing regular
/// file in a sticky+world-writable dir requires owning the file or the
/// dir (CAP_FOWNER exempts) — the regular-file arm of may_open.
pub fn protected_regular() -> u64 {
    PROTECTED_REGULAR.load(Ordering::Relaxed)
}
/// net.unix.max_dgram_qlen: per-mailbox datagram queue bound for
/// AF_UNIX SOCK_DGRAM — a full mailbox fails sends EAGAIN.
pub fn unix_max_dgram_qlen() -> u64 {
    UNIX_MAX_QLEN.load(Ordering::Relaxed)
}
/// net.core.somaxconn: per-listener accept-queue bound — the cap on
/// queued completed handshakes is min(listen backlog, this value).
pub fn somaxconn() -> u64 {
    SOMAXCONN.load(Ordering::Relaxed)
}
/// user.max_user_namespaces: per-creator userns cap (Linux ucounts).
/// 0 = unlimited, matching kernels that ship the knob unbounded.
pub fn max_user_namespaces() -> u64 {
    USER_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_mnt_namespaces — per-creator live mount-ns cap (0 = no cap).
pub fn max_mnt_namespaces() -> u64 {
    MNT_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_uts_namespaces — per-creator live uts-ns cap (0 = no cap).
pub fn max_uts_namespaces() -> u64 {
    UTS_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_pid_namespaces — per-creator live pid-ns cap (0 = no cap).
pub fn max_pid_namespaces() -> u64 {
    PID_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_ipc_namespaces — per-creator live ipc-ns cap (0 = no cap).
pub fn max_ipc_namespaces() -> u64 {
    IPC_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_time_namespaces — per-creator live time-ns cap (0 = no cap).
pub fn max_time_namespaces() -> u64 {
    TIME_NS_MAX.load(Ordering::Relaxed)
}

/// sysctl name under /proc/sys → current value, or None when unknown.
/// Names are given relative, e.g. "kernel/pid_max", "fs/nr_open".
/// file-nr/pty-nr are computed live like the Linux file-table stats.
pub fn get(name: &str) -> Option<u64> {
    Some(match name {
        "kernel/pid_max" => PID_MAX.load(Ordering::Relaxed),
        "kernel/threads-max" => THREADS_MAX.load(Ordering::Relaxed),
        "kernel/yama/ptrace_scope" => YAMA_SCOPE.load(Ordering::Relaxed),
        "kernel/pty/max" => PTY_MAX.load(Ordering::Relaxed),
        "kernel/pty/nr" => crate::pty::count(),
        "fs/nr_open" => FS_NR_OPEN.load(Ordering::Relaxed),
        "fs/pipe-max-size" => FS_PIPE_MAX.load(Ordering::Relaxed),
        "fs/inotify/max_user_watches" => INOTIFY_MAX_WATCHES.load(Ordering::Relaxed),
        "fs/file-max" => FS_FILE_MAX.load(Ordering::Relaxed),
        "fs/file-nr" => crate::task::live_fd_count(),
        "vm/max_map_count" => VM_MAX_MAP_COUNT.load(Ordering::Relaxed),
        "kernel/shmmax" => SHMMAX.load(Ordering::Relaxed),
        "kernel/shmall" => SHMALL.load(Ordering::Relaxed),
        "kernel/shmmni" => SHMMNI.load(Ordering::Relaxed),
        "kernel/ngroups_max" => NGROUPS_MAX.load(Ordering::Relaxed),
        "fs/mqueue/msg_max" => MQ_MSG_MAX.load(Ordering::Relaxed),
        "fs/mqueue/msgsize_max" => MQ_MSGSIZE_MAX.load(Ordering::Relaxed),
        "fs/mqueue/queues_max" => MQ_QUEUES_MAX.load(Ordering::Relaxed),
        "fs/inotify/max_queued_events" => INOTIFY_MAX_QUEUED.load(Ordering::Relaxed),
        "fs/epoll/max_user_watches" => EPOLL_MAX_WATCHES.load(Ordering::Relaxed),
        "net/ipv4/ip_unprivileged_port_start" => {
            UNPRIV_PORT_START.load(Ordering::Relaxed).min(65535)
        }
        "net/ipv4/icmp_echo_ignore_broadcasts" => ICMP_ECHO_IGNORE_BCAST.load(Ordering::Relaxed),
        "net/ipv4/ip_forward" => IP_FORWARD.load(Ordering::Relaxed),
        "kernel/sysrq" => KERNEL_SYSRQ.load(Ordering::Relaxed),
        "kernel/dmesg_restrict" => DMESG_RESTRICT.load(Ordering::Relaxed),
        "kernel/randomize_va_space" => RANDOMIZE_VA.load(Ordering::Relaxed),
        "vm/overcommit_memory" => OVERCOMMIT_MEMORY.load(Ordering::Relaxed),
        "vm/overcommit_ratio" => OVERCOMMIT_RATIO.load(Ordering::Relaxed),
        "kernel/kptr_restrict" => KPTR_RESTRICT.load(Ordering::Relaxed),
        "fs/protected_symlinks" => PROTECTED_SYMLINKS.load(Ordering::Relaxed),

            "kernel/unprivileged_userns_clone" => UNPRIV_USERNS.load(Ordering::Relaxed),
        "vm/mmap_min_addr" => MMAP_MIN_ADDR.load(Ordering::Relaxed),
        "vm/min_free_kbytes" => MIN_FREE_KB.load(Ordering::Relaxed),
        "fs/protected_fifos" => PROTECTED_FIFOS.load(Ordering::Relaxed),
        "fs/protected_regular" => PROTECTED_REGULAR.load(Ordering::Relaxed),
        "net/unix/max_dgram_qlen" => UNIX_MAX_QLEN.load(Ordering::Relaxed),
        "net/core/somaxconn" => SOMAXCONN.load(Ordering::Relaxed),
        "user/max_user_namespaces" => USER_NS_MAX.load(Ordering::Relaxed),
        "user/max_mnt_namespaces" => MNT_NS_MAX.load(Ordering::Relaxed),
        "user/max_uts_namespaces" => UTS_NS_MAX.load(Ordering::Relaxed),
        "user/max_pid_namespaces" => PID_NS_MAX.load(Ordering::Relaxed),
        "user/max_ipc_namespaces" => IPC_NS_MAX.load(Ordering::Relaxed),
        "user/max_time_namespaces" => TIME_NS_MAX.load(Ordering::Relaxed),

        _ => return None,
    })
}

/// Write a sysctl value — Linux rejects out-of-range/non-numeric input.
pub fn set(name: &str, v: u64) -> bool {
    match name {
        "kernel/pid_max" if (301..=4_194_304).contains(&v) => PID_MAX.store(v, Ordering::Relaxed),
        "kernel/threads-max" if v >= 1 => THREADS_MAX.store(v, Ordering::Relaxed),
        "kernel/yama/ptrace_scope" if v <= 3 => YAMA_SCOPE.store(v, Ordering::Relaxed),
        "kernel/pty/max" if v <= 1 << 20 => PTY_MAX.store(v, Ordering::Relaxed),
        "fs/nr_open" if (1..=4_194_304).contains(&v) => FS_NR_OPEN.store(v, Ordering::Relaxed),
        "fs/pipe-max-size" if (4096..=1 << 20).contains(&v) => FS_PIPE_MAX.store(v, Ordering::Relaxed),
        "fs/inotify/max_user_watches" if v > 0 => INOTIFY_MAX_WATCHES.store(v, Ordering::Relaxed),
        "fs/file-max" if v <= 1 << 30 => FS_FILE_MAX.store(v, Ordering::Relaxed),
        "vm/max_map_count" if v > 0 => VM_MAX_MAP_COUNT.store(v, Ordering::Relaxed),
        "kernel/shmmax" if v <= 1 << 40 => SHMMAX.store(v, Ordering::Relaxed),
        "kernel/shmall" if v <= 1 << 40 => SHMALL.store(v, Ordering::Relaxed),
        "kernel/shmmni" if v <= 1 << 20 => SHMMNI.store(v, Ordering::Relaxed),
        "kernel/ngroups_max" if v <= 1 << 20 => NGROUPS_MAX.store(v, Ordering::Relaxed),
        "fs/mqueue/msg_max" if (1..=1 << 16).contains(&v) => {
            MQ_MSG_MAX.store(v, Ordering::Relaxed)
        }
        "fs/mqueue/msgsize_max" if (1..=1 << 24).contains(&v) => {
            MQ_MSGSIZE_MAX.store(v, Ordering::Relaxed)
        }
        "fs/mqueue/queues_max" if v <= 1 << 16 => MQ_QUEUES_MAX.store(v, Ordering::Relaxed),
        "fs/inotify/max_queued_events" if v > 0 => {
            INOTIFY_MAX_QUEUED.store(v, Ordering::Relaxed)
        }
        "fs/epoll/max_user_watches" if v > 0 => {
            EPOLL_MAX_WATCHES.store(v, Ordering::Relaxed)
        }
        "net/ipv4/ip_unprivileged_port_start" if v <= 65535 => {
            UNPRIV_PORT_START.store(v, Ordering::Relaxed)
        }
        "net/ipv4/icmp_echo_ignore_broadcasts" if v <= 1 => {
            ICMP_ECHO_IGNORE_BCAST.store(v, Ordering::Relaxed)
        }
        "net/ipv4/ip_forward" if v <= 1 => IP_FORWARD.store(v, Ordering::Relaxed),
        "kernel/sysrq" if v <= 1 << 16 => KERNEL_SYSRQ.store(v, Ordering::Relaxed),
        "kernel/dmesg_restrict" if v <= 1 => DMESG_RESTRICT.store(v, Ordering::Relaxed),
        "kernel/randomize_va_space" if v <= 2 => RANDOMIZE_VA.store(v, Ordering::Relaxed),
        "vm/overcommit_memory" if v <= 2 => OVERCOMMIT_MEMORY.store(v, Ordering::Relaxed),
        "vm/overcommit_ratio" if v <= 100 => OVERCOMMIT_RATIO.store(v, Ordering::Relaxed),
        "kernel/kptr_restrict" if v <= 2 => KPTR_RESTRICT.store(v, Ordering::Relaxed),
        "fs/protected_symlinks" if v <= 1 => PROTECTED_SYMLINKS.store(v, Ordering::Relaxed),
        "kernel/unprivileged_userns_clone" if v <= 1 => {
            UNPRIV_USERNS.store(v, Ordering::Relaxed)
        }
        "vm/mmap_min_addr" if v <= 0x7e00_0000 => {
            MMAP_MIN_ADDR.store(v, Ordering::Relaxed)
        }
        "vm/min_free_kbytes" if v <= 4_194_304 => MIN_FREE_KB.store(v, Ordering::Relaxed),
        "fs/protected_fifos" if v <= 2 => PROTECTED_FIFOS.store(v, Ordering::Relaxed),
        "fs/protected_regular" if v <= 1 => {
            PROTECTED_REGULAR.store(v, Ordering::Relaxed)
        }
        "net/unix/max_dgram_qlen" if (1..=1024).contains(&v) => {
            UNIX_MAX_QLEN.store(v, Ordering::Relaxed)
        }
        "net/core/somaxconn" if (1..=65535).contains(&v) => {
            SOMAXCONN.store(v, Ordering::Relaxed)
        }
        "user/max_user_namespaces" if v <= 65535 => {
            USER_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_mnt_namespaces" if v <= 65535 => {
            MNT_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_uts_namespaces" if v <= 65535 => {
            UTS_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_pid_namespaces" if v <= 65535 => {
            PID_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_ipc_namespaces" if v <= 65535 => {
            IPC_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_time_namespaces" if v <= 65535 => {
            TIME_NS_MAX.store(v, Ordering::Relaxed)
        }

        _ => return false,
    }
    true
}
