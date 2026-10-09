//! Writable kernel tunables surfaced under /proc/sys (Linux sysctl).
//! Values live here so every consumer reads the live knob, not a const.

use core::sync::atomic::{AtomicU64, Ordering};

static PID_MAX: AtomicU64 = AtomicU64::new(32768);
static THREADS_MAX: AtomicU64 = AtomicU64::new(1024);
static YAMA_SCOPE: AtomicU64 = AtomicU64::new(0);
static FS_NR_OPEN: AtomicU64 = AtomicU64::new(1_048_576);
static FS_PIPE_MAX: AtomicU64 = AtomicU64::new(64 * 1024);
static INOTIFY_MAX_WATCHES: AtomicU64 = AtomicU64::new(128);

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

/// sysctl name under /proc/sys → current value, or None when unknown.
/// Names are given relative, e.g. "kernel/pid_max", "fs/nr_open".
pub fn get(name: &str) -> Option<u64> {
    Some(match name {
        "kernel/pid_max" => PID_MAX.load(Ordering::Relaxed),
        "kernel/threads-max" => THREADS_MAX.load(Ordering::Relaxed),
        "kernel/yama/ptrace_scope" => YAMA_SCOPE.load(Ordering::Relaxed),
        "fs/nr_open" => FS_NR_OPEN.load(Ordering::Relaxed),
        "fs/pipe-max-size" => FS_PIPE_MAX.load(Ordering::Relaxed),
        "fs/inotify/max_user_watches" => INOTIFY_MAX_WATCHES.load(Ordering::Relaxed),
        _ => return None,
    })
}

/// Write a sysctl value — Linux rejects out-of-range/non-numeric input.
pub fn set(name: &str, v: u64) -> bool {
    match name {
        "kernel/pid_max" if (301..=4_194_304).contains(&v) => PID_MAX.store(v, Ordering::Relaxed),
        "kernel/threads-max" if v >= 1 => THREADS_MAX.store(v, Ordering::Relaxed),
        "kernel/yama/ptrace_scope" if v <= 3 => YAMA_SCOPE.store(v, Ordering::Relaxed),
        "fs/nr_open" if (1..=4_194_304).contains(&v) => FS_NR_OPEN.store(v, Ordering::Relaxed),
        "fs/pipe-max-size" if (4096..=1 << 20).contains(&v) => FS_PIPE_MAX.store(v, Ordering::Relaxed),
        "fs/inotify/max_user_watches" if v > 0 => INOTIFY_MAX_WATCHES.store(v, Ordering::Relaxed),
        _ => return false,
    }
    true
}
