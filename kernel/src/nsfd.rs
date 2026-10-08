//! Namespace-object fds — the backing for setns(2).
//!
//! Opening `/proc/<pid>/ns/mntns` yields an object fd whose stored path
//! is `/nsfd/{n}` and which pins the target's MountNs object itself —
//! Linux `mnt:[inum]` semantics. The fd keeps referring to that SAME
//! namespace even if the task afterwards unshares or setns's into
//! another one (that's what makes setns-back work).
//!
//! The fd is path-only: reads/writes on it fail (Linux treats ns fds
//! as ioctl-only handles).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::task::MountNs;

static NEXT: AtomicU64 = AtomicU64::new(1);
static REG: Mutex<BTreeMap<u64, Arc<Mutex<MountNs>>>> = Mutex::new(BTreeMap::new());

/// Is `path` an ns-object fd?
pub fn handles(path: &str) -> bool {
    path.starts_with("/nsfd/")
}

fn seq(path: &str) -> Option<u64> {
    path.strip_prefix("/nsfd/")?.parse().ok()
}

/// Register `arc` as a new ns object; returns the fd path to store.
fn register(arc: Arc<Mutex<MountNs>>) -> String {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    REG.lock().insert(id, arc);
    alloc::format!("/nsfd/{}", id)
}

/// Open `/proc/<pid>/ns/mntns`: pin that task's CURRENT namespace as an
/// object fd. `None` when the path isn't an mntns link or the pid is
/// dead — caller falls through to the generic proc path (or fails).
pub fn open(path: &str) -> Option<String> {
    let rest = path
        .strip_prefix("/proc/")?
        .strip_suffix("/ns/mntns")?;
    let pid = if rest == "self" {
        crate::task::current_id()
    } else if rest.bytes().all(|b| b.is_ascii_digit()) {
        rest.parse().ok()?
    } else {
        return None;
    };
    let arc = crate::task::ns_arc_of(pid)?;
    Some(register(arc))
}

/// The namespace object behind an ns fd — setns's adopt source.
pub fn arc(path: &str) -> Option<Arc<Mutex<MountNs>>> {
    REG.lock().get(&seq(path)?).cloned()
}

/// fd died — drop the pinned reference.
pub fn release(path: &str) {
    if let Some(id) = seq(path) {
        REG.lock().remove(&id);
    }
}
