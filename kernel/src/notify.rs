//! inotify-style filesystem watches: each `SYS_INOTIFY_INIT` mints a kernel
//! object reachable through a `/inotify/{id}` fd; vfs mutation hooks push
//! events into matching watchers' queues. Read returns text records
//! `"{wd} {mask} {name}\n"`; `SYS_POLL` reports the fd readable while the
//! queue is non-empty.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub const IN_ACCESS: u32 = 0x1;
pub const IN_MODIFY: u32 = 0x2;
pub const IN_ATTRIB: u32 = 0x4;
pub const IN_CLOSE_WRITE: u32 = 0x8;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO: u32 = 0x80;
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
pub const IN_DELETE_SELF: u32 = 0x400;
pub const IN_MOVE_SELF: u32 = 0x800;
pub const IN_ISDIR: u32 = 0x4000_0000;
pub const IN_Q_OVERFLOW: u32 = 0x8000;
/// convenience: everything vfs can report
pub const IN_ALL: u32 = 0x0fff;

struct Watch {
    wd: u32,
    path: String,
    mask: u32,
}

struct Inotif {
    watches: Vec<Watch>,
    queue: VecDeque<(u32, u32, String)>, // (wd, mask, name)
    next_wd: u32,
}

static INOTIF: Mutex<BTreeMap<u64, Inotif>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);
const QUEUE_CAP: usize = 128;

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/inotify/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

pub fn exists(path: &str) -> bool {
    match id_of(path) {
        Some(id) => INOTIF.lock().contains_key(&id),
        None => false,
    }
}

/// inotify_init: returns the fd path of a new empty watch instance.
pub fn create() -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    INOTIF.lock().insert(
        id,
        Inotif { watches: Vec::new(), queue: VecDeque::new(), next_wd: 1 },
    );
    Ok(alloc::format!("/inotify/{}", id))
}

/// inotify_add_watch(fd_path, fs_path, mask) -> wd | Err
pub fn add_watch(fd_path: &str, path: &str, mask: u32) -> Result<u32, i64> {
    let id = id_of(fd_path).ok_or(-3i64)?;
    let mut g = INOTIF.lock();
    let i = g.get_mut(&id).ok_or(-3i64)?;
    // re-adding the same path just ORs the mask (real inotify semantics)
    if let Some(w) = i.watches.iter_mut().find(|w| w.path == path) {
        w.mask |= mask;
        return Ok(w.wd);
    }
    let wd = i.next_wd;
    i.next_wd += 1;
    i.watches.push(Watch { wd, path: String::from(path), mask });
    Ok(wd)
}

/// inotify_rm_watch
pub fn rm_watch(fd_path: &str, wd: u32) -> bool {
    let Some(id) = id_of(fd_path) else { return false };
    let mut g = INOTIF.lock();
    match g.get_mut(&id) {
        Some(i) => i.watches.iter().position(|w| w.wd == wd).map(|p| i.watches.remove(p)).is_some(),
        None => false,
    }
}

/// readable while events are queued
pub fn ready(path: &str) -> bool {
    match id_of(path) {
        Some(id) => INOTIF.lock().get(&id).map(|i| !i.queue.is_empty()).unwrap_or(false),
        None => false,
    }
}

/// drain pending events into `buf` as text lines; Err(-11) when empty
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-3i64)?;
    let mut g = INOTIF.lock();
    let i = g.get_mut(&id).ok_or(-3i64)?;
    if i.queue.is_empty() {
        return Err(-11); // EAGAIN
    }
    let mut n = 0usize;
    while let Some((wd, mask, name)) = i.queue.pop_front() {
        let line = alloc::format!("{} {} {}\n", wd, mask, name);
        if n + line.len() > buf.len() {
            i.queue.push_front((wd, mask, name));
            break;
        }
        buf[n..n + line.len()].copy_from_slice(line.as_bytes());
        n += line.len();
    }
    Ok(n)
}

/// last close of the fd drops the instance
pub fn close_obj(path: &str) {
    if let Some(id) = id_of(path) {
        INOTIF.lock().remove(&id);
    }
}

/// vfs mutation hook: `touched` is a canonical path, `mask` the event bits.
/// A watch on the touched path itself, or on its parent directory (direct
/// children only), receives the event.
pub fn fire(touched: &str, mask: u32) {
    let (dir, name) = match touched.rfind('/') {
        Some(0) => ("/", &touched[1..]),
        Some(i) => (&touched[..i], &touched[i + 1..]),
        None => ("/", touched),
    };
    let mut g = INOTIF.lock();
    for i in g.values_mut() {
        for w in i.watches.iter() {
            let (ev_mask, want) = if w.path == touched {
                // self-watch: the event comes through as the *_SELF bit
                let selfbit = match mask & !IN_ISDIR {
                    IN_DELETE => IN_DELETE_SELF,
                    IN_MOVED_FROM => IN_MOVE_SELF,
                    m => m,
                };
                (selfbit | (mask & IN_ISDIR), selfbit)
            } else if w.path == dir {
                (mask, mask & !IN_ISDIR)
            } else {
                continue;
            };
            if w.mask & want == 0 {
                continue;
            }
            if i.queue.len() >= QUEUE_CAP {
                i.queue.pop_front();
                i.queue.push_back((0, IN_Q_OVERFLOW, String::new()));
            }
            i.queue.push_back((w.wd, ev_mask, String::from(name)));
        }
    }
}
