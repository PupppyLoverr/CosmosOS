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

use crate::task::{IpcNs, MountNs, PidNs, TimeNs, UtsNs};

/// Which namespace object an fd pins — setns adopts the matching field.
#[derive(Clone)]
pub enum NsObj {
    Mount(Arc<Mutex<MountNs>>),
    Uts(Arc<Mutex<UtsNs>>),
    Pid(Arc<Mutex<PidNs>>),
    Time(Arc<Mutex<TimeNs>>),
    Ipc(Arc<Mutex<IpcNs>>),
}

static NEXT: AtomicU64 = AtomicU64::new(1);
static REG: Mutex<BTreeMap<u64, NsObj>> = Mutex::new(BTreeMap::new());

/// Is `path` an ns-object fd?
pub fn handles(path: &str) -> bool {
    path.starts_with("/nsfd/")
}

fn seq(path: &str) -> Option<u64> {
    path.strip_prefix("/nsfd/")?.parse().ok()
}

/// Register `arc` as a new ns object; returns the fd path to store.
fn register(obj: NsObj) -> String {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    REG.lock().insert(id, obj);
    alloc::format!("/nsfd/{}", id)
}

/// Open `/proc/<pid>/ns/mntns`: pin that task's CURRENT namespace as an
/// object fd. `None` when the path isn't an mntns link or the pid is
/// dead — caller falls through to the generic proc path (or fails).
pub fn open(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/proc/")?;
    let (rest, kind) = rest
        .strip_suffix("/ns/mntns")
        .map(|r| (r, 0u8))
        .or_else(|| rest.strip_suffix("/ns/uts").map(|r| (r, 1u8)))
        .or_else(|| rest.strip_suffix("/ns/pid").map(|r| (r, 2u8)))
        // time_for_children must be tried before the /ns/time suffix
        .or_else(|| rest.strip_suffix("/ns/time_for_children").map(|r| (r, 4u8)))
        .or_else(|| rest.strip_suffix("/ns/time").map(|r| (r, 3u8)))
        .or_else(|| rest.strip_suffix("/ns/ipc").map(|r| (r, 5u8)))?;
    let pid = if rest == "self" {
        crate::task::current_id()
    } else if rest.bytes().all(|b| b.is_ascii_digit()) {
        rest.parse().ok()?
    } else {
        return None;
    };
    match kind {
        0 => crate::task::ns_arc_of(pid).map(|a| register(NsObj::Mount(a))),
        1 => crate::task::uts_arc_of(pid).map(|a| register(NsObj::Uts(a))),
        3 => crate::task::timens_arc_of(pid).map(|a| register(NsObj::Time(a))),
        4 => crate::task::timens_children_arc(pid).map(|a| register(NsObj::Time(a))),
        5 => crate::task::ipcns_arc_of(pid).map(|a| register(NsObj::Ipc(a))),
        _ => crate::task::pidns_arc_of(pid).map(|a| register(NsObj::Pid(a))),
    }
}

/// The namespace object behind an ns fd — setns's adopt source.
pub fn obj(path: &str) -> Option<NsObj> {
    REG.lock().get(&seq(path)?).cloned()
}

/// fd died — drop the pinned reference.
pub fn release(path: &str) {
    if let Some(id) = seq(path) {
        REG.lock().remove(&id);
    }
}
