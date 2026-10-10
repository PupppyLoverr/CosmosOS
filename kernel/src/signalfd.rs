//! signalfd-style signal fds: `SYS_SIGNALFD` mints a `/signalfd/{id}` fd
//! bound to the creating task and a signal mask. `read` drains one pending
//! signal visible through the mask as a 128-byte `signalfd_siginfo`-shaped
//! record (`ssi_signo` = first u32, rest zeroed). Nothing pending → Err(-11)
//! so the shared read path blocks/EAGAINs like every other event fd.
//! `SYS_POLL` reports readable while a masked signal is pending.

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

struct Sfd {
    /// task that owns this queue — signalfds are per-process
    owner: u32,
    /// signals of interest for this fd (NOT the task's sigprocmask mask —
    /// Linux semantics: you block via sigprocmask, then read them here)
    mask: u64,
}

static SFDS: Mutex<BTreeMap<u64, Sfd>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/signalfd/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

/// Create a signalfd for `owner` watching `mask`. Returns the fd path.
pub fn create(owner: u32, mask: u64) -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    SFDS.lock().insert(id, Sfd { owner, mask });
    Ok(alloc::format!("/signalfd/{}", id))
}

/// Read: one pending masked signal per 128-byte record. -11 while empty.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-3i64)?;
    if buf.len() < 128 {
        return Err(-22); // EINVAL: a signalfd_siginfo is 128 bytes
    }
    let (owner, mask) = {
        let g = SFDS.lock();
        let Some(s) = g.get(&id) else { return Err(-3) };
        (s.owner, s.mask)
    };
    match crate::task::take_siginfo(owner, mask) {
        Some((sig, code, val)) => {
            for b in buf[..128].iter_mut() {
                *b = 0;
            }
            buf[..4].copy_from_slice(&sig.to_le_bytes());
            buf[8..12].copy_from_slice(&code.to_le_bytes());   // ssi_code
            buf[44..48].copy_from_slice(&val.to_le_bytes());   // ssi_int
            Ok(128)
        }
        None => {
            // orphaned fd (owner died): real EOF, not "would block"
            if owner == u32::MAX { Ok(0) } else { Err(-11) }
        }
    }
}

/// poll-ready: a masked signal is pending on the owner.
pub fn ready(path: &str) -> bool {
    let Some(id) = id_of(path) else { return false };
    let g = SFDS.lock();
    let Some(s) = g.get(&id) else { return false };
    let (owner, mask) = (s.owner, s.mask);
    drop(g);
    crate::task::has_pending_sig(owner, mask)
}

/// Task exited: its queued signals die with it (the fd stays but reads -11).
pub fn drop_owner(pid: u32) {
    let mut g = SFDS.lock();
    for s in g.values_mut() {
        if s.owner == pid {
            s.owner = u32::MAX;
        }
    }
}
