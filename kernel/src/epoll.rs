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
pub const EPOLLERR: u32 = 0x8;
pub const EPOLLHUP: u32 = 0x10;
pub const EPOLLET: u32 = 0x8000_0000;
pub const EPOLLONESHOT: u32 = 0x4000_0000;

struct Interest {
    path: String,
    events: u32,
    /// EPOLLET: report only on a not-ready -> ready transition (edge).
    /// Set once reported at this level; cleared when readiness falls.
    seen_ready: bool,
    /// object's readiness epoch at the last report (pipes::rise_gen; 0
    /// for kinds without epochs) — detects a drain+refill that happened
    /// entirely between two wait calls.
    seen_gen: u64,
    /// EPOLLONESHOT: reported once, silent until CTL_MOD re-arms.
    disabled: bool,
}

struct Ep {
    /// creator's uid — fs.epoll.max_user_watches charges per user
    owner: u32,
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

pub fn create(owner: u32) -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    EPOLLS.lock().insert(
        id,
        Ep {
            owner,
            interests: BTreeMap::new(),
        },

    );
    Ok(alloc::format!("/epoll/{}", id))
}

/// ctl(epfd_path, op, fdnum, fd_path, events):
/// ADD registers (fails EEXIST-style -17 when the fdnum is already in the
/// set), DEL removes, MOD replaces the event mask + path.
pub fn ctl(epfd_path: &str, op: u64, fdnum: u32, fd_path: &str, events: u32, uid: u32) -> i64 {
    let Some(id) = id_of(epfd_path) else { return -9 };
    let mut g = EPOLLS.lock();
    // fs.epoll.max_user_watches: total interests across every
    // epoll instance this user owns (Linux per-user accounting).
    let watched: u64 = g
        .values()
        .filter(|x| x.owner == uid)
        .map(|x| x.interests.len() as u64)
        .sum();
    let Some(e) = g.get_mut(&id) else { return -9 };
    match op {
        EPOLL_CTL_ADD => {
            if e.interests.contains_key(&fdnum) {
                return -17;
            }
            if watched >= crate::sysctl::epoll_max_watches() {
                return -28; // ENOSPC
            }
            e.interests.insert(
                fdnum,
                Interest {
                    path: String::from(fd_path),
                    events,
                    seen_ready: false,
                    seen_gen: 0,
                    disabled: false,
                },
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
                // Linux: MOD re-arms a consumed ONESHOT and re-bases
                // the ET edge.
                i.disabled = false;
                i.seen_ready = false;
                i.seen_gen = 0;
                0
            }
            None => -2,
        },
        _ => -22,
    }
}

/// Probe one interest's revents: requested-masked IN/OUT plus
/// unconditional ERR/HUP (same bit values as poll revents — poll_revents
/// is the shared dispatcher, so EPOLLERR/EPOLLHUP surface for free).
fn probe(path: &str, events: u32) -> u32 {
    crate::syscall::poll_revents(path, events & (EPOLLIN | EPOLLOUT))
}

/// Would this interest report right now (read-only — for `fd_ready` so a
/// poll()/nested epoll on THIS epoll fd works)?
fn fires(i: &Interest, raw: u32, gen: u64) -> bool {
    raw != 0
        && !i.disabled
        && !(i.events & EPOLLET != 0 && i.seen_ready && i.seen_gen == gen)
}

/// Snapshot interests, probe OUTSIDE the EPOLLS lock (member probes can
/// recurse into this lock for nested epoll — never hold it while
/// probing), then apply EPOLLET/EPOLLONESHOT bookkeeping under the lock.
pub fn ready(path: &str) -> bool {
    let Some(id) = id_of(path) else { return false };
    let snap: Vec<Interest> = {
        let g = EPOLLS.lock();
        match g.get(&id) {
            Some(e) => e
                .interests
                .values()
                .map(|i| Interest {
                    path: i.path.clone(),
                    events: i.events,
                    seen_ready: i.seen_ready,
                    seen_gen: i.seen_gen,
                    disabled: i.disabled,
                })
                .collect(),
            None => return false,
        }
    };
    snap.iter()
        .any(|i| fires(i, probe(&i.path, i.events), epoch(&i.path)))
}

/// collect currently-ready interests as (fdnum, revents) pairs. The caller
/// (sys_epoll_wait) writes them out or blocks and re-asks.
pub fn collect(epfd_path: &str, max: usize) -> Vec<(u32, u32)> {
    let Some(id) = id_of(epfd_path) else { return Vec::new() };
    // phase 1: snapshot (fdnum, path, events, seen_ready, disabled)
    let snap: Vec<(u32, Interest)> = {
        let g = EPOLLS.lock();
        match g.get(&id) {
            Some(e) => e
                .interests
                .iter()
                .map(|(fdn, i)| {
                    (
                        *fdn,
                        Interest {
                            path: i.path.clone(),
                            events: i.events,
                            seen_ready: i.seen_ready,
                            seen_gen: i.seen_gen,
                            disabled: i.disabled,
                        },
                    )
                })
                .collect(),
            None => return Vec::new(),
        }
    };
    // phase 2: probe each member path outside the lock
    let raws: Vec<(u32, u32, u32)> = snap
        .iter()
        .map(|(fdn, i)| (*fdn, i.events, probe(&i.path, i.events)))
        .collect();
    let gens: alloc::collections::BTreeMap<u32, u64> = snap
        .iter()
        .map(|(fdn, i)| (*fdn, epoch(&i.path)))
        .collect();
    // phase 3: under the lock, gate on ET/ONESHOT state and mutate it.
    let mut g = EPOLLS.lock();
    let Some(e) = g.get_mut(&id) else { return Vec::new() };
    let mut out = Vec::new();
    for (fdn, _ev, raw) in raws {
        let gen = gens.get(&fdn).copied().unwrap_or(0);
        let Some(i) = e.interests.get_mut(&fdn) else { continue };
        if raw == 0 {
            // level fell: an ET interest re-arms for the next rise
            i.seen_ready = false;
            continue;
        }
        if !fires(i, raw, gen) {
            continue;
        }
        if i.events & EPOLLET != 0 {
            i.seen_ready = true;
            i.seen_gen = gen;
        }
        if i.events & EPOLLONESHOT != 0 {
            i.disabled = true;
        }
        if out.len() < max {
            out.push((fdn, raw));
        }
    }
    out
}

/// readiness-transition epoch per object kind — only pipes track edges
/// for now; other kinds return 0 so ET degrades to the seen-once level
/// model for them.
fn epoch(path: &str) -> u64 {
    if crate::pipes::handles(path) {
        crate::pipes::rise_gen(path)
    } else if crate::sockfd::handles(path) {
        crate::sockfd::rise_gen(path)
    } else if crate::sockpair::handles(path) {
        crate::sockpair::rise_gen(path)
    } else {
        0
    }
}

/// last close of the fd drops the interest set
pub fn close_obj(path: &str) {
    if let Some(id) = id_of(path) {
        EPOLLS.lock().remove(&id);
    }
}
