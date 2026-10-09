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
        _ => return false,
    }
    true
}
