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
    ca2b: VecDeque<String>, // side 0 -> side 1 ancillary (passed fd paths)
    cb2a: VecDeque<String>, // side 1 -> side 0 ancillary
    open_a: bool,
    open_b: bool,
    wr_a: bool, // side 0 shutdown(SHUT_WR): its writes stopped
    wr_b: bool,
    rd_a: bool, // side 0 shutdown(SHUT_RD): its reads return EOF
    rd_b: bool,
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
            ca2b: VecDeque::new(),
            cb2a: VecDeque::new(),
            open_a: true,
            open_b: true,
            wr_a: false,
            wr_b: false,
            rd_a: false,
            rd_b: false,
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
    let peer_wr = if side == 0 { s.wr_b } else { s.wr_a };
    let my_rd = if side == 0 { s.rd_a } else { s.rd_b };
    let my_wr = if side == 0 { s.wr_a } else { s.wr_b };
    if for_read {
        if my_rd {
            return true; // shutdown(RD) -> reads see EOF
        }
        let inbox = if side == 0 { &s.b2a } else { &s.a2b };
        let cin = if side == 0 { &s.cb2a } else { &s.ca2b };
        !inbox.is_empty() || !cin.is_empty() || !peer_open || peer_wr
    } else {
        peer_open && !my_wr
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
    let my_rd = if side == 0 { s.rd_a } else { s.rd_b };
    if my_rd {
        return Ok(0);
    }
    let inbox = if side == 0 { &mut s.b2a } else { &mut s.a2b };
    if inbox.is_empty() {
        let peer_open = if side == 0 { s.open_b } else { s.open_a };
        let peer_wr = if side == 0 { s.wr_b } else { s.wr_a };
        return if peer_open && !peer_wr { Err(-11) } else { Ok(0) };
    }
    let n = inbox.len().min(buf.len());
    for b in buf.iter_mut().take(n) {
        *b = inbox.pop_front().unwrap();
    }
    Ok(n)
}

/// MSG_PEEK: copy the front bytes WITHOUT draining — same error contract
/// as try_read (Ok(0) EOF, Err(-11) would block).
pub fn peek_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let Some((id, side)) = parse(path) else {
        return Err(-2);
    };
    let g = SP.lock();
    let Some(s) = g.get(&id) else {
        return Err(-2);
    };
    let my_rd = if side == 0 { s.rd_a } else { s.rd_b };
    if my_rd {
        return Ok(0);
    }
    let inbox = if side == 0 { &s.b2a } else { &s.a2b };
    if inbox.is_empty() {
        let peer_open = if side == 0 { s.open_b } else { s.open_a };
        let peer_wr = if side == 0 { s.wr_b } else { s.wr_a };
        return if peer_open && !peer_wr { Err(-11) } else { Ok(0) };
    }
    let n = inbox.len().min(buf.len());
    for (i, b) in inbox.iter().take(n).enumerate() {
        buf[i] = *b;
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
    let my_wr = if side == 0 { s.wr_a } else { s.wr_b };
    if !peer_open || my_wr {
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

/// sendmsg(2) with SCM_RIGHTS: write the data, then queue an optional
/// passed object path for the peer to adopt as a fresh fd. Works on a
/// zero-length payload so an fd can be sent on its own — the peer still
/// becomes readable via the ctrl queue.
pub fn send_msg(path: &str, data: &[u8], pass: Option<String>) -> Result<usize, i64> {
    let Some((id, side)) = parse(path) else {
        return Err(-2);
    };
    let mut g = SP.lock();
    let Some(s) = g.get_mut(&id) else {
        return Err(-2);
    };
    let peer_open = if side == 0 { s.open_b } else { s.open_a };
    let my_wr = if side == 0 { s.wr_a } else { s.wr_b };
    if !peer_open || my_wr {
        return Err(-32);
    }
    let out = if side == 0 { &mut s.a2b } else { &mut s.b2a };
    if out.len() >= CAP {
        return Err(-11);
    }
    let n = data.len().min(CAP - out.len());
    for b in data.iter().take(n) {
        out.push_back(*b);
    }
    if let Some(p) = pass {
        let cq = if side == 0 { &mut s.ca2b } else { &mut s.cb2a };
        cq.push_back(p);
    }
    Ok(n)
}

/// recvmsg(2): read data, and pop the next queued passed-object path
/// (SCM_RIGHTS). An fd-only message (empty data + ctrl) still returns —
/// Ok((0, Some(path))) — never leaves the receiver blocked on its fd.
pub fn recv_msg(path: &str, buf: &mut [u8]) -> Result<(usize, Option<String>), i64> {
    let Some((id, side)) = parse(path) else {
        return Err(-2);
    };
    let ctrl = {
        let mut g = SP.lock();
        let Some(s) = g.get_mut(&id) else {
            return Err(-2);
        };
        let cq = if side == 0 { &mut s.cb2a } else { &mut s.ca2b };
        cq.pop_front()
    };
    match try_read(path, buf) {
        Ok(n) => Ok((n, ctrl)),
        Err(-11) if ctrl.is_some() => Ok((0, ctrl)),
        Err(e) => Err(e),
    }
}

/// shutdown(2) on a pair side: how=0 stops our reads (peer sees nothing),
/// how=1 stops our writes (peer reads EOF after draining), how=2 both.
/// Returns -1 when the object or side is already gone.
pub fn shutdown(path: &str, how: u64) -> i64 {
    let Some((id, side)) = parse(path) else { return -1 };
    let mut g = SP.lock();
    let Some(s) = g.get_mut(&id) else { return -1 };
    let rd = how == 0 || how == 2;
    let wr = how == 1 || how == 2;
    if side == 0 {
        if rd {
            s.rd_a = true;
        }
        if wr {
            s.wr_a = true;
        }
    } else {
        if rd {
            s.rd_b = true;
        }
        if wr {
            s.wr_b = true;
        }
    }
    0
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
