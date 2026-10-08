//! tmpfs — a real in-memory filesystem mountable via SYS_MOUNT.
//!
//! `MOUNTS` holds mounted target paths (longest-first); `NODES` is the
//! store, keyed by the absolute normalized path so mount prefixes are
//! part of the key. Dirs track entry names in `children`. Writes are
//! quota-bounded — tmpfs returns real ENOSPC past QUOTA.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

pub struct Node {
    pub is_dir: bool,
    /// File contents as 4KiB page boxes — never a big contiguous heap
    /// alloc (a single Vec would OOM the 4MiB kernel heap / panic it).
    pub pages: Vec<Box<[u8; 4096]>>,
    pub size: u64,
    pub mtime: u64,
    pub attr: u8,
    pub children: Vec<String>, // entry names (dirs only)
}

static NODES: Mutex<BTreeMap<String, Node>> = Mutex::new(BTreeMap::new());
/// (mount path, read-only) — longest-prefix-first on insert.
static MOUNTS: Mutex<Vec<(String, bool)>> = Mutex::new(Vec::new());
/// Lock-free "anything mounted?" flag — lets `handles` short-circuit
/// without taking MOUNTS, which matters on the page-fault read path.
static ANY: AtomicUsize = AtomicUsize::new(0);

/// Per-instance storage cap — ENOSPC is real when it's exceeded.
const QUOTA: u64 = 4 * 1024 * 1024;

pub fn any() -> bool {
    ANY.load(Ordering::Relaxed) > 0
}

/// `path` at or under mount `m` — allocation-free: `handles` runs on the
/// page-fault read path where heap allocation can deadlock (a preempted
/// task may hold the heap lock).
fn under(m: &str, path: &str) -> bool {
    path == m || (path.len() > m.len() && path.starts_with(m) && path.as_bytes()[m.len()] == b'/')
}

fn mounted(g: &Vec<(String, bool)>, path: &str) -> bool {
    g.iter().any(|m| under(&m.0, path))
}

/// Is `path` under a READ-ONLY mount? EROFS gate for all mutators.
fn ro_of(g: &Vec<(String, bool)>, path: &str) -> bool {
    g.iter().any(|m| m.1 && under(&m.0, path))
}

/// Is `path` at or under a tmpfs mount point?
pub fn handles(path: &str) -> bool {
    if !any() {
        return false;
    }
    mounted(&MOUNTS.lock(), path)
}

/// Registered mount points with ro flag (for /proc/mounts).
pub fn mounts() -> Vec<(String, bool)> {
    MOUNTS.lock().clone()
}

/// MS_REMOUNT: update the existing mount's ro flag. EINVAL if not mounted.
pub fn remount(target: &str, ro: bool) -> Result<(), i64> {
    let mut mg = MOUNTS.lock();
    match mg.iter_mut().find(|m| m.0 == target) {
        Some(m) => {
            m.1 = ro;
            Ok(())
        }
        None => Err(-22),
    }
}

fn parent_of(path: &str) -> Option<String> {
    path.rfind('/').map(|i| {
        if i == 0 {
            String::from("/")
        } else {
            String::from(&path[..i])
        }
    })
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn used_bytes(g: &BTreeMap<String, Node>) -> u64 {
    g.values()
        .map(|n| n.size + n.pages.len() as u64 * 64 + 128)
        .sum()
}

/// Read `size`-bounded bytes from page-boxed file data.
fn read_pages(n: &Node, off: u64, buf: &mut [u8]) -> usize {
    let mut done = 0usize;
    while done < buf.len() {
        let pos = off + done as u64;
        if pos >= n.size {
            break;
        }
        let pi = (pos / 4096) as usize;
        let Some(p) = n.pages.get(pi) else { break };
        let in_off = (pos % 4096) as usize;
        let want = (4096 - in_off).min(buf.len() - done);
        let avail = ((n.size - pos) as usize).min(want);
        buf[done..done + avail].copy_from_slice(&p[in_off..in_off + avail]);
        done += avail;
    }
    done
}

/// Write into page-boxed data, allocating page boxes as needed.
/// Caller has already done the quota check.
fn write_pages(n: &mut Node, off: u64, buf: &[u8]) {
    let end = off + buf.len() as u64;
    let need = (end as usize + 4095) / 4096;
    while n.pages.len() < need {
        n.pages.push(Box::new([0u8; 4096]));
    }
    let mut done = 0usize;
    while done < buf.len() {
        let pos = off + done as u64;
        let pi = (pos / 4096) as usize;
        let in_off = (pos % 4096) as usize;
        let n2 = (4096 - in_off).min(buf.len() - done);
        n.pages[pi][in_off..in_off + n2].copy_from_slice(&buf[done..done + n2]);
        done += n2;
    }
    if end > n.size {
        n.size = end;
    }
}

/// Mount a fresh tmpfs at `target` (already normalized, verified to be an
/// existing directory by the caller). EBUSY(-16) if already a mount,
/// EINVAL(-22) for "/".
pub fn mount(target: &str, ro: bool) -> Result<(), i64> {
    if target == "/" {
        return Err(-22);
    }
    let mut mg = MOUNTS.lock();
    if mg.iter().any(|m| m.0 == target) {
        return Err(-16);
    }
    let mut ng = NODES.lock();
    ng.insert(
        String::from(target),
        Node {
            is_dir: true,
            pages: Vec::new(),
            size: 0,
            mtime: crate::vfs::now_unix(),
            attr: 0,
            children: Vec::new(),
        },
    );
    mg.push((String::from(target), ro));
    mg.sort_by(|a, b| b.0.len().cmp(&a.0.len())); // longest prefix wins
    ANY.store(mg.len(), Ordering::Relaxed);
    Ok(())
}

/// Unmount: EBUSY when any live fd or cwd sits under the mount, or a
/// nested tmpfs mount lives inside it. Drops every node under the prefix.
pub fn umount(target: &str) -> Result<(), i64> {
    let mut mg = MOUNTS.lock();
    let Some(i) = mg.iter().position(|m| m.0 == target) else {
        return Err(-22); // EINVAL: not a mount
    };
    // busy: a nested mount, or an open fd / cwd below it
    let under = alloc::format!("{}/", target);
    if mg.iter().any(|m| m.0.starts_with(&under)) {
        return Err(-16);
    }
    if crate::task::fd_path_prefix_in_use(&under) || crate::task::cwd_under(&under) {
        return Err(-16);
    }
    mg.remove(i);
    ANY.store(mg.len(), Ordering::Relaxed);
    let mut ng = NODES.lock();
    ng.retain(|k, _| k.as_str() != target && !k.starts_with(&under));
    Ok(())
}

/// open(2) semantics for a tmpfs path. Returns ((), append_pos).
pub fn open(path: &str, flags: u64) -> Result<u64, i64> {
    let wants_write = flags
        & (shared::O_WRONLY | shared::O_RDWR | shared::O_CREATE | shared::O_TRUNC | shared::O_APPEND)
        != 0;
    if wants_write && ro_of(&MOUNTS.lock(), path) {
        return Err(-30); // EROFS
    }
    let mut ng = NODES.lock();
    match ng.get(path) {
        Some(n) if n.is_dir => return Err(-4), // EISDIR
        Some(n) => {
            if flags & shared::O_CREATE != 0 && flags & shared::O_EXCL != 0 {
                return Err(-17); // EEXIST
            }
            let app = if flags & shared::O_APPEND != 0 {
                n.size
            } else {
                0
            };
            if flags & shared::O_TRUNC != 0 {
                let n = ng.get_mut(path).unwrap();
                n.pages.clear();
                n.size = 0;
                n.mtime = crate::vfs::now_unix();
            }
            Ok(app)
        }
        None => {
            if flags & shared::O_CREATE == 0 {
                return Err(-2);
            }
            let par = parent_of(path).unwrap_or_else(|| String::from("/"));
            let Some(p) = ng.get_mut(&par) else {
                return Err(-2); // parent dir must exist
            };
            if !p.is_dir {
                return Err(-20); // ENOTDIR
            }
            let name = String::from(name_of(path));
            p.children.push(name);
            ng.insert(
                String::from(path),
                Node {
                    is_dir: false,
                    pages: Vec::new(),
                    size: 0,
                    mtime: crate::vfs::now_unix(),
                    attr: 0x20,
                    children: Vec::new(),
                },
            );
            Ok(0)
        }
    }
}

pub fn read_range(path: &str, off: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let ng = NODES.lock();
    let Some(n) = ng.get(path) else { return Err(-2) };
    if n.is_dir {
        return Err(-21);
    }
    Ok(read_pages(n, off, buf))
}

/// #PF-safe read for demand-paged tmpfs files. `None` = not a tmpfs
/// path (caller falls through to FAT). Lock order matches the FAT path's
/// try_lock+wait_irq: a preempted holder is rescheduled, never spun on.
pub fn read_range_pf(path: &str, off: u64, buf: &mut [u8]) -> Option<Result<usize, i64>> {
    if !any() {
        return None;
    }
    loop {
        {
            let Some(mg) = MOUNTS.try_lock() else {
                crate::task::wait_irq();
                continue;
            };
            if !mounted(&mg, path) {
                return None;
            }
        }
        if let Some(ng) = NODES.try_lock() {
            let Some(n) = ng.get(path) else {
                return Some(Err(-2));
            };
            if n.is_dir {
                return Some(Err(-21));
            }
            return Some(Ok(read_pages(n, off, buf)));
        }
        crate::task::wait_irq();
    }
}

pub fn read_all(path: &str) -> Result<Vec<u8>, i64> {
    let ng = NODES.lock();
    let Some(n) = ng.get(path) else { return Err(-2) };
    if n.is_dir {
        return Err(-21);
    }
    let mut out = Vec::with_capacity(n.size as usize);
    out.resize(n.size as usize, 0);
    read_pages(n, 0, &mut out);
    Ok(out)
}

/// Write `buf` at `off` (caller handles O_APPEND by passing off=len).
/// ENOSPC past QUOTA.
pub fn write_range(path: &str, off: u64, buf: &[u8]) -> Result<usize, i64> {
    if ro_of(&MOUNTS.lock(), path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    if !ng.contains_key(path) {
        return Err(-2);
    }
    if ng.get(path).map(|n| n.is_dir).unwrap_or(false) {
        return Err(-21);
    }
    let end = off + buf.len() as u64;
    let grow = end.saturating_sub(ng.get(path).map(|n| n.size).unwrap_or(0));
    if used_bytes(&ng) + grow > QUOTA {
        return Err(-28); // ENOSPC
    }
    let n = ng.get_mut(path).unwrap();
    write_pages(n, off, buf);
    n.mtime = crate::vfs::now_unix();
    Ok(buf.len())
}

pub fn truncate(path: &str, len: u64) -> Result<(), i64> {
    if ro_of(&MOUNTS.lock(), path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    let Some(n) = ng.get_mut(path) else { return Err(-2) };
    if n.is_dir {
        return Err(-21);
    }
    let need = (len as usize + 4095) / 4096;
    while n.pages.len() < need {
        n.pages.push(Box::new([0u8; 4096]));
    }
    n.pages.truncate(need);
    n.size = len;
    n.mtime = crate::vfs::now_unix();
    Ok(())
}

pub fn exists(path: &str) -> bool {
    NODES.lock().contains_key(path)
}

pub fn stat(path: &str) -> Option<(u64, bool, u64, u8)> {
    let ng = NODES.lock();
    ng.get(path)
        .map(|n| (n.size, n.is_dir, n.mtime, n.attr))
}

pub fn mkdir(path: &str) -> Result<(), i64> {
    if ro_of(&MOUNTS.lock(), path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    if ng.contains_key(path) {
        return Err(-17);
    }
    let par = parent_of(path).unwrap_or_else(|| String::from("/"));
    let Some(p) = ng.get_mut(&par) else {
        return Err(-2);
    };
    if !p.is_dir {
        return Err(-20);
    }
    p.children.push(String::from(name_of(path)));
    ng.insert(
        String::from(path),
        Node {
            is_dir: true,
            pages: Vec::new(),
            size: 0,
            mtime: crate::vfs::now_unix(),
            attr: 0,
            children: Vec::new(),
        },
    );
    Ok(())
}

/// unlink/rmdir: files drop on unlink; dirs only when empty (-39 ENOTEMPTY).
pub fn remove(path: &str) -> Result<(), i64> {
    if ro_of(&MOUNTS.lock(), path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    let Some(n) = ng.get(path) else { return Err(-2) };
    if n.is_dir && !n.children.is_empty() {
        return Err(-39);
    }
    let node = ng.remove(path).unwrap();
    let par = parent_of(path).unwrap_or_else(|| String::from("/"));
    let nm = String::from(name_of(path));
    if let Some(p) = ng.get_mut(&par) {
        p.children.retain(|c| *c != nm);
    }
    drop(node);
    Ok(())
}

/// Same-mount rename (dirs or files); cross-mount is EXDEV(-18).
pub fn rename(from: &str, to: &str) -> Result<(), i64> {
    {
        let mg = MOUNTS.lock();
        if ro_of(&mg, from) || ro_of(&mg, to) {
            return Err(-30);
        }
    }
    let mut ng = NODES.lock();
    let par_to = parent_of(to).unwrap_or_else(|| String::from("/"));
    {
        let Some(p) = ng.get(&par_to) else { return Err(-2) };
        if !p.is_dir {
            return Err(-20);
        }
    }
    let mut node = ng.remove(from).ok_or(-2i64)?;
    // overwrite target if present: detach its old children entry
    if ng.contains_key(to) {
        ng.remove(to);
    }
    node.mtime = crate::vfs::now_unix();
    ng.insert(String::from(to), node);
    let par_from = parent_of(from).unwrap_or_else(|| String::from("/"));
    let nm_from = String::from(name_of(from));
    if let Some(p) = ng.get_mut(&par_from) {
        p.children.retain(|c| *c != nm_from);
    }
    if let Some(p) = ng.get_mut(&par_to) {
        p.children.push(String::from(name_of(to)));
    }
    Ok(())
}

/// Directory listing as DirEntry records.
pub fn listdir(path: &str) -> Result<Vec<shared::DirEntry>, i64> {
    let ng = NODES.lock();
    let Some(n) = ng.get(path) else { return Err(-2) };
    if !n.is_dir {
        return Err(-20);
    }
    let mut out = Vec::new();
    for c in &n.children {
        let full = if path == "/" {
            alloc::format!("/{}", c)
        } else {
            alloc::format!("{}/{}", path, c)
        };
        let Some(m) = ng.get(&full) else { continue };
        let mut de = shared::DirEntry::default();
        let nb = c.as_bytes();
        let l = nb.len().min(95);
        de.name[..l].copy_from_slice(&nb[..l]);
        de.name_len = l as u8;
        de.is_dir = m.is_dir as u8;
        de.size = m.size;
        de.mtime = m.mtime;
        de.attr = m.attr;
        out.push(de);
    }
    Ok(out)
}

pub fn utime(path: &str, secs: u64) -> Result<(), i64> {
    if ro_of(&MOUNTS.lock(), path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    let Some(n) = ng.get_mut(path) else { return Err(-2) };
    n.mtime = secs;
    Ok(())
}

pub fn setattr(path: &str, attr: u8) -> Result<(), i64> {
    if ro_of(&MOUNTS.lock(), path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    let Some(n) = ng.get_mut(path) else { return Err(-2) };
    n.attr = attr;
    Ok(())
}

/// (total, free) for statfs/df on tmpfs paths.
pub fn df() -> (u64, u64) {
    let ng = NODES.lock();
    let u = used_bytes(&ng);
    (QUOTA, QUOTA.saturating_sub(u))
}
