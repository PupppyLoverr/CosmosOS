//! `socketpair(2)` — bidirectional anonymous sockets as `/sockpair/{id}/{0,1}`
//! pseudo-fds. Two queues: side 0 reads what side 1 wrote and vice versa.
//! Closing one side makes the peer's reads see EOF and its writes EPIPE.
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

const CAP: usize = 1 << 16;

struct Spair {
    a2b: VecDeque<u8>, // side 0 -> side 1
    b2a: VecDeque<u8>, // side 1 -> side 0
    open_a: bool,
    open_b: bool,
}

static SP: Mutex<BTreeMap<u64, Spair>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

/// (id, side) for "/sockpair/{id}/{0|1}".
fn parse(path: &str) -> Option<(u64, u8)> {
    let s = path.strip_prefix("/sockpair/")?;
    let (id, side) = s.split_once('/')?;
    Some((id.parse().ok()?, if side == "1" { 1 } else { 0 }))
}

pub fn handles(path: &str) -> bool {
    parse(path).is_some()
}

/// Mint a connected pair; returns the two fd paths.
pub fn create() -> Option<(String, String)> {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    SP.lock().insert(
        id,
        Spair {
            a2b: VecDeque::new(),
            b2a: VecDeque::new(),
            open_a: true,
            open_b: true,
        },
    );
    Some((
        format!("/sockpair/{}/0", id),
        format!("/sockpair/{}/1", id),
    ))
}

/// Readiness for `sys_poll`/`epoll`: readable when own inbox has data or the
/// peer is gone (EOF); writable while the peer side is still open.
pub fn ready(path: &str, for_read: bool) -> bool {
    let Some((id, side)) = parse(path) else {
        return false;
    };
    let g = SP.lock();
    let Some(s) = g.get(&id) else { return false };
    let peer_open = if side == 0 { s.open_b } else { s.open_a };
    if for_read {
        let inbox = if side == 0 { &s.b2a } else { &s.a2b };
        !inbox.is_empty() || !peer_open
    } else {
        peer_open
    }
}

/// Ok(0) = EOF (peer closed, inbox drained); Err(-11) = would block.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let Some((id, side)) = parse(path) else {
        return Err(-2);
    };
    let mut g = SP.lock();
    let Some(s) = g.get_mut(&id) else {
        return Err(-2);
    };
    let inbox = if side == 0 { &mut s.b2a } else { &mut s.a2b };
    if inbox.is_empty() {
        let peer_open = if side == 0 { s.open_b } else { s.open_a };
        return if peer_open { Err(-11) } else { Ok(0) };
    }
    let n = inbox.len().min(buf.len());
    for b in buf.iter_mut().take(n) {
        *b = inbox.pop_front().unwrap();
    }
    Ok(n)
}

/// Err(-32) = EPIPE (peer closed); Err(-11) = buffer full.
pub fn try_write(path: &str, buf: &[u8]) -> Result<usize, i64> {
    let Some((id, side)) = parse(path) else {
        return Err(-2);
    };
    let mut g = SP.lock();
    let Some(s) = g.get_mut(&id) else {
        return Err(-2);
    };
    let peer_open = if side == 0 { s.open_b } else { s.open_a };
    if !peer_open {
        return Err(-32);
    }
    let out = if side == 0 { &mut s.a2b } else { &mut s.b2a };
    if out.len() + buf.len() > CAP {
        if out.len() >= CAP {
            return Err(-11);
        }
    }
    let n = buf.len().min(CAP - out.len());
    for b in buf.iter().take(n) {
        out.push_back(*b);
    }
    Ok(n)
}

/// One side's fd closed: mark it so the peer sees EOF/EPIPE. The object is
/// dropped when both sides are closed.
pub fn close_obj(path: &str) {
    let Some((id, side)) = parse(path) else {
        return;
    };
    let mut g = SP.lock();
    let drop_it = match g.get_mut(&id) {
        Some(s) => {
            if side == 0 {
                s.open_a = false;
            } else {
                s.open_b = false;
            }
            !s.open_a && !s.open_b
        }
        None => false,
    };
    if drop_it {
        g.remove(&id);
    }
}
