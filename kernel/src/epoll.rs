//! epoll objects: `SYS_EPOLL_CREATE` mints a kernel interest set reachable
//! through an `/epoll/{id}` fd; `SYS_EPOLL_CTL` registers a monitored fd by
//! resolving its path; `SYS_EPOLL_WAIT` evaluates each interest through the
//! same readiness dispatch `SYS_POLL` uses and copies `{fd, revents}` pairs
//! to userspace, blocking (re-entered syscall) until one fires or the
//! timeout expires.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub const EPOLL_CTL_ADD: u64 = 1;
pub const EPOLL_CTL_DEL: u64 = 2;
pub const EPOLL_CTL_MOD: u64 = 3;

pub const EPOLLIN: u32 = 0x1;
pub const EPOLLOUT: u32 = 0x2;

struct Interest {
    path: String,
    events: u32,
}

struct Ep {
    /// fd-number (as registered) -> interest
    interests: BTreeMap<u32, Interest>,
}

static EPOLLS: Mutex<BTreeMap<u64, Ep>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/epoll/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

pub fn exists(path: &str) -> bool {
    match id_of(path) {
        Some(id) => EPOLLS.lock().contains_key(&id),
        None => false,
    }
}

pub fn create() -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    EPOLLS.lock().insert(id, Ep { interests: BTreeMap::new() });
    Ok(alloc::format!("/epoll/{}", id))
}

/// ctl(epfd_path, op, fdnum, fd_path, events):
/// ADD registers (fails EEXIST-style -17 when the fdnum is already in the
/// set), DEL removes, MOD replaces the event mask + path.
pub fn ctl(epfd_path: &str, op: u64, fdnum: u32, fd_path: &str, events: u32) -> i64 {
    let Some(id) = id_of(epfd_path) else { return -9 };
    let mut g = EPOLLS.lock();
    let Some(e) = g.get_mut(&id) else { return -9 };
    match op {
        EPOLL_CTL_ADD => {
            if e.interests.contains_key(&fdnum) {
                return -17;
            }
            e.interests.insert(
                fdnum,
                Interest { path: String::from(fd_path), events },
            );
            0
        }
        EPOLL_CTL_DEL => {
            if e.interests.remove(&fdnum).is_some() {
                0
            } else {
                -2
            }
        }
        EPOLL_CTL_MOD => match e.interests.get_mut(&fdnum) {
            Some(i) => {
                i.path = String::from(fd_path);
                i.events = events;
                0
            }
            None => -2,
        },
        _ => -22,
    }
}

/// collect currently-ready interests as (fdnum, revents) pairs. The caller
/// (sys_epoll_wait) writes them out or blocks and re-asks.
pub fn collect(epfd_path: &str, max: usize) -> Vec<(u32, u32)> {
    let Some(id) = id_of(epfd_path) else { return Vec::new() };
    let g = EPOLLS.lock();
    let Some(e) = g.get(&id) else { return Vec::new() };
    let mut out = Vec::new();
    for (fdnum, i) in e.interests.iter() {
        if out.len() >= max {
            break;
        }
        let mut re = 0u32;
        if i.events & EPOLLIN != 0 && crate::syscall::fd_ready(&i.path, 1) {
            re |= EPOLLIN;
        }
        if i.events & EPOLLOUT != 0 && crate::syscall::fd_ready(&i.path, 2) {
            re |= EPOLLOUT;
        }
        if re != 0 {
            out.push((*fdnum, re));
        }
    }
    out
}

/// last close of the fd drops the interest set
pub fn close_obj(path: &str) {
    if let Some(id) = id_of(path) {
        EPOLLS.lock().remove(&id);
    }
}
