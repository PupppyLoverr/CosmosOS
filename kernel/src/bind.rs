//! Bind mounts — `mount --bind /src /dst` aliases the source subtree
//! onto the target. Unlike tmpfs mounts, binds carry no storage: the
//! target path is REWRITTEN to the source path at resolve time, so the
//! file can live on any filesystem (FAT or tmpfs). Chained binds
//! (b->a, c->b) resolve iteratively.
//!
//! #PF contract (same as tmpfs::read_range_pf): `resolve_pf` must be
//! try_lock/wait_irq only — the fault handler can run while a preempted
//! task holds this lock or the heap lock, so it must never spin or alloc.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// (target, source) pairs, longest-target-prefix first.
static BINDS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
/// Non-zero while any bind is registered — lets the #PF path skip the
/// MUTEX probe entirely in the common case (no binds).
static ANY: AtomicUsize = AtomicUsize::new(0);

fn under(m: &str, path: &str) -> bool {
    path == m || (path.len() > m.len() && path.starts_with(m) && path.as_bytes()[m.len()] == b'/')
}

fn resolve_inner(g: &Vec<(String, String)>, path: &str) -> String {
    // Iterative so a bind chain (c -> b -> a) fully collapses; real
    // kernels compose mounts the same way. Bound the walk to keep a
    // self-referential entry from looping forever.
    let mut cur = String::from(path);
    for _ in 0..8 {
        match g.iter().find(|b| under(&b.0, &cur)) {
            Some(b) => {
                let rest = &cur[b.0.len()..];
                let mut n = b.1.clone();
                n.push_str(rest);
                cur = n;
            }
            None => break,
        }
    }
    cur
}

/// Rewrite `path` through the bind table (no-op when no bind matches).
/// Locks BINDS — never call under the scheduler or from #PF; use
/// `resolve_pf` there instead.
pub fn resolve(path: &str) -> String {
    if ANY.load(Ordering::Acquire) == 0 {
        return String::from(path);
    }
    resolve_inner(&BINDS.lock(), path)
}

/// #PF-safe resolve: try_lock + IRQ-backed wait on contention. Returns
/// `Some(path)` resolved, or `None` when nothing is registered.
pub fn resolve_pf(path: &str) -> Option<String> {
    if ANY.load(Ordering::Acquire) == 0 {
        return None;
    }
    loop {
        if let Some(g) = BINDS.try_lock() {
            return Some(resolve_inner(&g, path));
        }
        crate::task::wait_irq();
    }
}

/// mount --bind source target. Both must already exist on their fs.
/// EINVAL on self-bind, EEXIST on a duplicate target.
pub fn mount(source: &str, target: &str) -> Result<(), i64> {
    if source == target {
        return Err(-22);
    }
    let mut g = BINDS.lock();
    if g.iter().any(|b| b.0 == target) {
        return Err(-16);
    }
    g.push((String::from(target), String::from(source)));
    g.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    ANY.store(g.len(), Ordering::Release);
    Ok(())
}

/// Remove the bind on `target`. EINVAL when it isn't a bind mount.
pub fn umount(target: &str) -> Result<(), i64> {
    let mut g = BINDS.lock();
    let Some(i) = g.iter().position(|b| b.0 == target) else {
        return Err(-22);
    };
    g.remove(i);
    ANY.store(g.len(), Ordering::Release);
    Ok(())
}

/// (target, source) list for /proc output.
pub fn mounts() -> Vec<(String, String)> {
    BINDS.lock().clone()
}

/// Is `target` a bind mount point?
pub fn is_bound(target: &str) -> bool {
    BINDS.lock().iter().any(|b| b.0 == target)
}
