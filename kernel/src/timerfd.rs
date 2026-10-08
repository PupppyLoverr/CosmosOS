//! timerfd-style timers: `SYS_TIMERFD` mints a `/timerfd/{id}` fd; arming sets
//! an initial deadline (ms) and optional interval. Each PIT tick decrements
//! live timers; expiry accumulates a count. `read` drains an 8-byte LE count
//! (and returns 0 bytes' worth of "would block" as Err(-11) when 0);
//! `SYS_POLL` reports readable while count > 0.

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

struct Tfd {
    /// ticks until next expiry; u64::MAX = disarmed
    left: u64,
    interval_ticks: u64,
    count: u64,
}

static TFDS: Mutex<BTreeMap<u64, Tfd>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/timerfd/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

pub fn exists(path: &str) -> bool {
    match id_of(path) {
        Some(id) => TFDS.lock().contains_key(&id),
        None => false,
    }
}

pub fn create() -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    TFDS.lock().insert(id, Tfd { left: u64::MAX, interval_ticks: 0, count: 0 });
    Ok(alloc::format!("/timerfd/{}", id))
}

/// timerfd_gettime: (remaining_ms, interval_ms) — 0 remaining = disarmed
/// or expired-awaiting-read, matching Linux's it_value.it_sec==0.
pub fn gettime(path: &str) -> Option<(u64, u64)> {
    let id = id_of(path)?;
    let g = TFDS.lock();
    let t = g.get(&id)?;
    let rem = if t.left == u64::MAX { 0 } else { t.left * 10 };
    Some((rem, t.interval_ticks * 10))
}

/// timerfd_settime: initial ms + periodic interval ms (0 = one-shot)
pub fn settime(path: &str, init_ms: u64, interval_ms: u64) -> Result<(), i64> {
    let id = id_of(path).ok_or(-3i64)?;
    let mut g = TFDS.lock();
    let t = g.get_mut(&id).ok_or(-3i64)?;
    // init_ms==0 disarms — matches Linux's it_value==0
    t.left = if init_ms == 0 {
        u64::MAX
    } else {
        init_ms.div_ceil(10).max(1)
    };
    t.interval_ticks = interval_ms / 10;
    Ok(())
}

/// PIT tick hook (~10ms): expire armed timers, bump counts.
pub fn tick() {
    let mut g = TFDS.lock();
    for t in g.values_mut() {
        if t.left == u64::MAX {
            continue;
        }
        match t.left.checked_sub(1) {
            Some(l) if l > 0 => t.left = l,
            _ => {
                t.count = t.count.saturating_add(1);
                t.left = if t.interval_ticks > 0 { t.interval_ticks } else { u64::MAX };
            }
        }
    }
}

pub fn ready(path: &str) -> bool {
    match id_of(path) {
        Some(id) => TFDS.lock().get(&id).map(|t| t.count > 0).unwrap_or(false),
        None => false,
    }
}

/// read: 8-byte little-endian expiration count (resets to 0); Err(-11) when 0
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-3i64)?;
    let mut g = TFDS.lock();
    let t = g.get_mut(&id).ok_or(-3i64)?;
    if t.count == 0 {
        return Err(-11);
    }
    if buf.len() < 8 {
        return Err(-22);
    }
    buf[..8].copy_from_slice(&t.count.to_le_bytes());
    t.count = 0;
    Ok(8)
}

pub fn close_obj(path: &str) {
    if let Some(id) = id_of(path) {
        TFDS.lock().remove(&id);
    }
}
