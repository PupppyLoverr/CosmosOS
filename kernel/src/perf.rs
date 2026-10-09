//! perf_event_open: real per-task hardware/software counters behind an fd.
//!
//! An event is a /perf/{id} object fd; read() returns the u64 count
//! accumulated SINCE the open (the counter basis is snapshotted at create).
//! Supported counters are all live kernel data — nothing is sampled:
//!   hw   cycles            : TSC credited to the task while on-cpu
//!   sw   cpu_clock/task    : cpu_ticks * 10ms in ns
//!   sw   page_faults       : min_flt + maj_flt (minor/major separately too)
//!   sw   context_switches  : times the task was scheduled in
//! Reads on a dead target return the last observed count (Linux semantics).

use alloc::{collections::BTreeMap, format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

struct PerfEv {
    target: u32,
    typ: u8,
    cfg: u8,
    base: u64,
    last: u64,
}

static EVS: Mutex<BTreeMap<u64, PerfEv>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// /perf/... path check for fd dispatch.
pub fn handles(path: &str) -> bool {
    path.starts_with("/perf/")
}

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/perf/")?.parse().ok()
}

/// SYS_PERF_EVENT_OPEN body: validate config against the live target and
/// snapshot the counter basis. `pid`==0 means the caller.
pub fn create(pid: u32, typ: u8, cfg: u8) -> Result<String, i64> {
    let target = if pid == 0 {
        crate::task::current_id()
    } else {
        pid
    };
    let Some(base) = crate::task::perf_counter(target, typ, cfg) else {
        return Err(-3); // ESRCH / EINVAL: dead target or unsupported config
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    EVS.lock().insert(
        id,
        PerfEv { target, typ, cfg, base, last: base },
    );
    Ok(format!("/perf/{id}"))
}

/// Read = the event's count since open, as an 8-byte LE record.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let Some(id) = id_of(path) else { return Err(-2) };
    let mut g = EVS.lock();
    let Some(ev) = g.get_mut(&id) else { return Err(-2) };
    match crate::task::perf_counter(ev.target, ev.typ, ev.cfg) {
        Some(c) => ev.last = c,
        None => {} // dead target: serve the last observed count
    }
    if buf.len() < 8 {
        return Err(-22); // EINVAL: perf reads are full records
    }
    buf[..8].copy_from_slice(&ev.last.saturating_sub(ev.base).to_le_bytes());
    Ok(8)
}

/// Event fds are always readable (the count is instantaneous).
pub fn ready(_path: &str, _read: bool) -> bool {
    true
}

/// fd-release hook — drop the event.
pub fn release(path: &str) {
    if let Some(id) = id_of(path) {
        EVS.lock().remove(&id);
    }
}
