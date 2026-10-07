//! Advisory file locks (flock): a kernel-global table of per-path lock
//! state. Each successful request is a distinct open-file description —
//! like POSIX flock, a pid re-locking the same path still conflicts with
//! itself. Held locks release automatically when the owner task exits
//! (reaper calls release_pid), so a crashed locker can never wedge a path.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub const LOCK_SH: u64 = 1;
pub const LOCK_EX: u64 = 2;
pub const LOCK_NB: u64 = 4;
pub const LOCK_UN: u64 = 8;

struct Held {
    pid: u32,
    excl: bool,
}

static LOCKS: Mutex<BTreeMap<String, Vec<Held>>> = Mutex::new(BTreeMap::new());

/// apply `op` on `path` for `pid`.
///   Ok(())      acquired (or released, for UN)
///   Err(-11)    contended — caller re-blocks and retries (blocking mode)
///   Err(-35)    EWOULDBLOCK — contended and LOCK_NB was set
///   Err(-2)     invalid op
pub fn lock(path: &str, pid: u32, op: u64) -> Result<(), i64> {
    let mut g = LOCKS.lock();
    if op & LOCK_UN != 0 {
        if let Some(l) = g.get_mut(path) {
            l.retain(|h| h.pid != pid);
            if l.is_empty() {
                g.remove(path);
            }
        }
        return Ok(());
    }
    if op & (LOCK_SH | LOCK_EX) == 0 || op & (LOCK_SH | LOCK_EX) == (LOCK_SH | LOCK_EX) {
        return Err(-2);
    }
    let excl = op & LOCK_EX != 0;
    let conflict = g
        .get(path)
        .map(|l| l.iter().any(|h| h.excl || excl))
        .unwrap_or(false);
    if conflict {
        return if op & LOCK_NB != 0 { Err(-35) } else { Err(-11) };
    }
    g.entry(String::from(path))
        .or_default()
        .push(Held { pid, excl });
    Ok(())
}

/// query state for /proc/locks-style inspection: (excl?, owners) per path
pub fn snapshot() -> Vec<(String, bool, Vec<u32>)> {
    LOCKS
        .lock()
        .iter()
        .map(|(p, l)| {
            (
                p.clone(),
                l.iter().any(|h| h.excl),
                l.iter().map(|h| h.pid).collect(),
            )
        })
        .collect()
}

/// drop every lock held by `pid` (called from the task reaper)
pub fn release_pid(pid: u32) {
    let mut g = LOCKS.lock();
    let empty: Vec<String> = g
        .iter_mut()
        .filter_map(|(p, l)| {
            l.retain(|h| h.pid != pid);
            if l.is_empty() {
                Some(p.clone())
            } else {
                None
            }
        })
        .collect();
    for p in empty {
        g.remove(&p);
    }
}
