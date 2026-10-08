//! AF_UNIX SOCK_DGRAM: named packet mailboxes. `bind` registers a path
//! name; `sendto` queues one bounded datagram for a bound name (message
//! boundaries preserved — unlike the stream sockpair); `recvfrom` pops
//! one packet and reports the sender's name. Unbound senders auto-bind
//! to `/tmp/udg-{sockid}` on first send, like Linux's unix autobind.
use alloc::{
    collections::{BTreeMap, VecDeque},
    string::String,
    vec::Vec,
};
use spin::Mutex;

const MAXQ: usize = 64; // queued packets per mailbox
const MAXPKT: usize = 16 * 1024; // max datagram payload

struct Dbox {
    packets: VecDeque<(Vec<u8>, String)>, // (data, sender name)
}

static BOXES: Mutex<BTreeMap<String, Dbox>> = Mutex::new(BTreeMap::new());

/// Claim a mailbox name; false = already taken.
pub fn register(name: &str) -> bool {
    let mut g = BOXES.lock();
    if g.contains_key(name) {
        return false;
    }
    g.insert(
        String::from(name),
        Dbox {
            packets: VecDeque::new(),
        },
    );
    true
}

/// Drop a mailbox and any queued packets (owner closed/bound elsewhere).
pub fn unregister(name: &str) {
    BOXES.lock().remove(name);
}

/// Mailbox exists?
pub fn exists(name: &str) -> bool {
    BOXES.lock().contains_key(name)
}

/// Queue one datagram for `dst` from `src`. Err(-2) no mailbox,
/// Err(-11) queue full, Err(-90) oversized datagram.
pub fn send(dst: &str, src: &str, data: &[u8]) -> i64 {
    if data.len() > MAXPKT {
        return -90; // EMSGSIZE
    }
    let mut g = BOXES.lock();
    let Some(b) = g.get_mut(dst) else {
        return -2; // ENOENT: nobody bound there
    };
    if b.packets.len() >= MAXQ {
        return -11; // EAGAIN
    }
    b.packets.push_back((Vec::from(data), String::from(src)));
    0
}

/// Pop one datagram for `name`: Ok((bytes copied, sender name)).
/// A packet larger than `buf` is truncated, the rest dropped (POSIX).
/// Err(-11) empty queue, Err(-2) mailbox gone.
pub fn recv(name: &str, buf: &mut [u8]) -> Result<(usize, String), i64> {
    let mut g = BOXES.lock();
    let Some(b) = g.get_mut(name) else {
        return Err(-2);
    };
    match b.packets.pop_front() {
        Some((d, s)) => {
            let n = d.len().min(buf.len());
            buf[..n].copy_from_slice(&d[..n]);
            Ok((n, s))
        }
        None => Err(-11),
    }
}

/// MSG_PEEK: copy the front datagram + sender WITHOUT popping it.
/// Err(-11) empty queue, Err(-2) mailbox gone — same contract as recv.
pub fn peek(name: &str, buf: &mut [u8]) -> Result<(usize, String), i64> {
    let g = BOXES.lock();
    let Some(b) = g.get(name) else {
        return Err(-2);
    };
    match b.packets.front() {
        Some((d, s)) => {
            let n = d.len().min(buf.len());
            buf[..n].copy_from_slice(&d[..n]);
            Ok((n, s.clone()))
        }
        None => Err(-11),
    }
}

/// Poll/epoll readiness: a queued packet (or a gone mailbox — let the
/// read surface the error instead of blocking forever).
pub fn ready(name: &str) -> bool {
    BOXES
        .lock()
        .get(name)
        .map(|b| !b.packets.is_empty())
        .unwrap_or(true)
}
