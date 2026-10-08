//! eventfd objects: each `SYS_EVENTFD` mints a kernel counter reachable
//! through a `/eventfd/{id}` fd. Writes add a u64; reads return the count
//! and reset it to zero — or decrement by one and return 1 when the fd was
//! created in semaphore mode (`flags & EFD_SEMAPHORE`). Empty reads and
//! overflowing reads both report EAGAIN so `sys_read`/`sys_write` re-block.

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub const EFD_SEMAPHORE: u32 = 0x1;
/// kernel-side write cap, mirroring the real EFD_MAX (2^64-2)
const MAX: u64 = u64::MAX - 1;

struct Efd {
    count: u64,
    sem: bool,
}

static EFDS: Mutex<BTreeMap<u64, Efd>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/eventfd/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

pub fn exists(path: &str) -> bool {
    match id_of(path) {
        Some(id) => EFDS.lock().contains_key(&id),
        None => false,
    }
}

/// eventfd(initval, flags): returns the fd path of a new counter.
pub fn create(initval: u64, flags: u32) -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    EFDS.lock().insert(
        id,
        Efd { count: initval.min(MAX), sem: flags & EFD_SEMAPHORE != 0 },
    );
    Ok(alloc::format!("/eventfd/{}", id))
}

/// readable while count > 0; writable while count < MAX
pub fn ready(path: &str, for_read: bool) -> bool {
    match id_of(path) {
        Some(id) => EFDS
            .lock()
            .get(&id)
            .map(|e| if for_read { e.count > 0 } else { e.count < MAX })
            .unwrap_or(false),
        None => false,
    }
}

/// read: 8-byte LE count. nonsem drains to zero; sem mode yields 1 per
/// count. Err(-11) when empty, Err(-22) when buf < 8.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-3i64)?;
    if buf.len() < 8 {
        return Err(-22);
    }
    let mut g = EFDS.lock();
    let e = g.get_mut(&id).ok_or(-3i64)?;
    if e.count == 0 {
        return Err(-11);
    }
    let v = if e.sem {
        e.count -= 1;
        1
    } else {
        core::mem::replace(&mut e.count, 0)
    };
    buf[..8].copy_from_slice(&v.to_le_bytes());
    Ok(8)
}

/// write: buffer must be an 8-byte LE u64, added to the counter unless the
/// sum would exceed MAX. 0xffffffffffffffff is EINVAL. Err(-11) when the
/// add would overflow (poll-then-write protocol).
pub fn try_write(path: &str, buf: &[u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-3i64)?;
    if buf.len() < 8 {
        return Err(-22);
    }
    let v = u64::from_le_bytes(buf[..8].try_into().map_err(|_| -22i64)?);
    if v == u64::MAX {
        return Err(-22);
    }
    let mut g = EFDS.lock();
    let e = g.get_mut(&id).ok_or(-3i64)?;
    if e.count > MAX - v {
        return Err(-11);
    }
    e.count += v;
    Ok(8)
}

/// last close of the fd drops the counter
pub fn close_obj(path: &str) {
    if let Some(id) = id_of(path) {
        EFDS.lock().remove(&id);
    }
}
