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

/// The alias table lives per-task in task::MountNs.binds (mount
/// namespaces); this global counter is >0 while ANY namespace has a
/// bind, so the #PF path skips the namespace probe in the common case.
static ANY: AtomicUsize = AtomicUsize::new(0);

fn under(m: &str, path: &str) -> bool {
    path == m || (path.len() > m.len() && path.starts_with(m) && path.as_bytes()[m.len()] == b'/')
}

fn resolve_inner(g: &[(String, String, u64)], path: &str) -> String {
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
    let ns = crate::task::ns_of();
    let g = ns.lock();
    resolve_inner(&g.binds, path)
}

/// #PF-safe resolve: try_lock + IRQ-backed wait on contention. Returns
/// `Some(path)` resolved, or `None` when nothing is registered.
pub fn resolve_pf(path: &str) -> Option<String> {
    if ANY.load(Ordering::Acquire) == 0 {
        return None;
    }
    loop {
        let ns = crate::task::ns_of();
        if let Some(g) = ns.try_lock() {
            return Some(resolve_inner(&g.binds, path));
        }
        crate::task::wait_irq();
    }
}

/// mount --bind source target. Both must already exist on their fs.
/// EINVAL on self-bind, EEXIST on a duplicate target. `opts` carries
/// MS_NODEV/MS_NOEXEC for accesses through the alias.
pub fn mount(source: &str, target: &str, opts: u64) -> Result<(), i64> {
    if source == target {
        return Err(-22);
    }
    let ns = crate::task::ns_of();
    let mut g = ns.lock();
    if g.binds.iter().any(|b| b.0 == target) {
        return Err(-16);
    }
    g.binds.push((String::from(target), String::from(source), opts));
    g.binds.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    ANY.fetch_add(1, Ordering::Release);
    Ok(())
}

/// Remove the bind on `target`. EINVAL when it isn't a bind mount.
pub fn umount(target: &str) -> Result<(), i64> {
    let ns = crate::task::ns_of();
    let mut g = ns.lock();
    let Some(i) = g.binds.iter().position(|b| b.0 == target) else {
        return Err(-22);
    };
    g.binds.remove(i);
    ANY.fetch_sub(1, Ordering::Release);
    Ok(())
}

/// MS_MOVE: relocate an existing bind target onto `new`. The bind's
/// alias semantics are unchanged; only its mount point moves.
/// EINVAL when `old` isn't a bind, EBUSY if `new` is covered.
pub fn move_mount(old: &str, new: &str) -> Result<(), i64> {
    let ns = crate::task::ns_of();
    let mut g = ns.lock();
    let Some(i) = g.binds.iter().position(|b| b.0 == old) else {
        return Err(-22);
    };
    if g.binds.iter().any(|b| b.0 == new) {
        return Err(-16);
    }
    g.binds[i].0 = String::from(new);
    g.binds.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    Ok(())
}

/// mount_setattr on an attached mount-fd: fold set/clr into the bind's
/// opts. EINVAL when `target` isn't a bind mount.
pub fn set_opts(target: &str, set: u64, clr: u64) -> Result<(), i64> {
    let ns = crate::task::ns_of();
    let mut g = ns.lock();
    let Some(b) = g.binds.iter_mut().find(|b| b.0 == target) else {
        return Err(-22);
    };
    b.2 |= set;
    b.2 &= !clr;
    Ok(())
}

/// (target, source) list in the current namespace — /proc output.
pub fn mounts() -> Vec<(String, String)> {
    let ns = crate::task::ns_of();
    let g = ns.lock();
    g.binds.iter().map(|b| (b.0.clone(), b.1.clone())).collect()
}

/// Is `target` a bind mount point in the current namespace?
pub fn is_bound(target: &str) -> bool {
    let ns = crate::task::ns_of();
    let g = ns.lock();
    g.binds.iter().any(|b| b.0 == target)
}
