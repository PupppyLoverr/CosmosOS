//! `pidfd_create(2)` — an fd that references a task. Poll/epoll reports it
//! readable the moment the task dies (or once it is already gone); `read()`
//! yields the 8-byte exit status without reaping it. Used to wait on process
//! death from the generic readiness machinery.
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static PDS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/pidfd/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

/// Create a pidfd for `pid`; works on live tasks only (pidfd_open of a dead
/// or absent task fails like Linux's ESRCH).
pub fn create(pid: u32) -> Option<String> {
    if !crate::task::exists(pid) || crate::task::child_exit(pid).is_some() {
        return None;
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    PDS.lock().insert(id, pid);
    Some(format!("/pidfd/{}", id))
}

/// Readable when the referenced task is dead (or already reaped).
pub fn ready(path: &str, _for_read: bool) -> bool {
    let Some(id) = id_of(path) else { return false };
    let g = PDS.lock();
    match g.get(&id) {
        Some(&pid) => crate::task::dead_or_gone(pid),
        None => false,
    }
}

/// 8-byte LE exit status once dead; Err(-11) while still running.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let Some(id) = id_of(path) else {
        return Err(-2);
    };
    let pid = match PDS.lock().get(&id) {
        Some(&p) => p,
        None => return Err(-2),
    };
    if buf.len() < 8 {
        return Err(-22);
    }
    if !crate::task::dead_or_gone(pid) {
        return Err(-11);
    }
    // Task may already be reaped — absent means "exited" but the status is
    // unknowable; report -1 (distinct from any real exit code >= 0 or a
    // negative kill code? real status int can be anything — still real data:
    // None => gone => we return the code captured... keep it simple: code -1
    // when the task is already reaped)
    let code = crate::task::child_exit(pid).unwrap_or(-1);
    buf[..8].copy_from_slice(&(code as u64).to_le_bytes());
    Ok(8)
}

pub fn close_obj(path: &str) {
    if let Some(id) = id_of(path) {
        PDS.lock().remove(&id);
    }
}
