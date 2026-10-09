//! tmpfs — a real in-memory filesystem mountable via SYS_MOUNT.
//!
//! `MOUNTS` holds mounted target paths (longest-first); `NODES` is the
//! store, keyed by the absolute normalized path so mount prefixes are
//! part of the key. Dirs track entry names in `children`. Writes are
//! quota-bounded — tmpfs returns real ENOSPC past QUOTA.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
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
    /// inode change/birth time (unix secs) — statx ctime/btime.
    pub ctime: u64,
    pub attr: u8,
    /// Owner ids + unix perm bits — the real DAC fields statx reports
    /// and the open/mutate paths check. Defaults: creator's euid/egid,
    /// 0755 dir / 0644 file minus umask.
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub children: Vec<String>, // entry names (dirs only)
}

/// (uid, gid, mode) for a fresh node: creator creds + umask-masked mode.
fn fresh(is_dir: bool) -> (u32, u32, u16) {
    let (eu, eg) = crate::task::cred();
    let um = crate::task::with_current(|t| t.umask as u16);
    (
        eu,
        eg,
        (if is_dir { 0o755 } else { 0o644 }) & !um,
    )
}

/// Owner/group/other perm check: `want` is one owner-position bit
/// (0o400 read / 0o200 write / 0o100 exec). Root (euid 0) passes all.
pub fn allows(n: &Node, want: u16) -> bool {
    let (eu, _eg) = crate::task::cred();
    // root is not magic here: the bypass is CAP_DAC_OVERRIDE on writes /
    // CAP_DAC_READ_SEARCH on reads, so a bounding-set drop really bites.
    crate::task::capable_ns_dac(if want == 0o200 {
        crate::task::CAP_DAC_OVERRIDE
    } else {
        crate::task::CAP_DAC_READ_SEARCH
    })
        || (eu == n.uid && n.mode & want != 0)
        || (crate::task::in_group(n.gid) && n.mode & (want >> 3) != 0)
        || n.mode & (want >> 6) != 0
}

/// Write-permission on the node at `path` (or, for creates, its parent).
pub fn may_write(path: &str) -> bool {
    if !any() {
        return true;
    }
    let g = NODES.lock();
    match g.get(path) {
        Some(n) => allows(n, 0o200),
        None => match g.get(parent_of(path).as_deref().unwrap_or("")) {
            Some(p) => allows(p, 0o200),
            None => true,
        },
    }
}

/// Read-permission on the node at `path` (exec shares it: our tmpfs has
/// no noexec-per-file distinction beyond mount flags).
pub fn may_read(path: &str) -> bool {
    if !any() {
        return true;
    }
    let g = NODES.lock();
    match g.get(path) {
        Some(n) => allows(n, 0o400),
        None => true,
    }
}

/// owner_of -> (uid, gid, perm bits) for statx; missing = root:root 0.
pub fn owner(path: &str) -> (u32, u32, u16) {
    if !any() {
        return (0, 0, 0);
    }
    let g = NODES.lock();
    g.get(path).map(|n| (n.uid, n.gid, n.mode)).unwrap_or((0, 0, 0))
}

/// chmod: set perm bits; EPERM unless root or the owner.
pub fn chmod(path: &str, mode: u16) -> Result<(), i64> {
    let mut g = NODES.lock();
    let n = g.get_mut(path).ok_or(-2i64)?;
    let (eu, _) = crate::task::cred();
    if eu != n.uid && !crate::task::capable_ns_dac(crate::task::CAP_FOWNER) {
        return Err(-1);
    }
    n.mode = mode & 0o7777;
    n.ctime = crate::vfs::now_unix();
    Ok(())
}

/// chown: root only, like Linux; gid u32::MAX keeps the current one.
pub fn chown(path: &str, uid: u32, gid: u32) -> Result<(), i64> {
    if !crate::task::capable_ns_dac(crate::task::CAP_CHOWN) {
        return Err(-1);
    }
    let mut g = NODES.lock();
    let n = g.get_mut(path).ok_or(-2i64)?;
    if uid != u32::MAX {
        n.uid = uid;
    }
    if gid != u32::MAX {
        n.gid = gid;
    }
    n.ctime = crate::vfs::now_unix();
    Ok(())
}

static NODES: Mutex<BTreeMap<String, Node>> = Mutex::new(BTreeMap::new());
/// (mount path, read-only) — longest-prefix-first on insert.
/// Mount tables live per-task in task::MountNs (mount namespaces); the
/// only tmpfs global is this counter — >0 while ANY namespace has a
/// tmpfs mount, so the #PF path can skip the namespace probe entirely
/// (mount()/umount() fetch_add/fetch_sub it).
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
pub fn under(m: &str, path: &str) -> bool {
    path == m || (path.len() > m.len() && path.starts_with(m) && path.as_bytes()[m.len()] == b'/')
}

fn mounted(g: &[(String, u64)], path: &str) -> bool {
    g.iter().any(|m| under(&m.0, path))
}

/// Is `path` under a READ-ONLY mount? EROFS gate for all mutators.
fn ro_of(g: &[(String, u64)], path: &str) -> bool {
    g.iter().any(|m| m.1 & shared::MS_RDONLY != 0 && under(&m.0, path))
}

/// Convenience: ro check against the current task's namespace.
fn ro(path: &str) -> bool {
    if !any() {
        return false;
    }
    let ns = crate::task::ns_of();
    let g = ns.lock();
    ro_of(&g.tmpfs, path)
}

/// Is `path` at or under a tmpfs mount point (or a lazily-detached
/// tree that must keep serving resolved paths)? Namespace-aware.
pub fn handles(path: &str) -> bool {
    if !any() {
        return false;
    }
    let ns = crate::task::ns_of();
    let g = ns.lock();
    mounted(&g.tmpfs, path) || g.detached.iter().any(|p| under(p, path))
}

/// Mount points with option flags in the current task's namespace.
pub fn mounts() -> Vec<(String, u64)> {
    let ns = crate::task::ns_of();
    let g = ns.lock();
    g.tmpfs.clone()
}

/// MS_REMOUNT: update the existing mount's ro flag. EINVAL if not mounted.
pub fn remount(target: &str, ro: bool) -> Result<(), i64> {
    let ns = crate::task::ns_of();
    let mut mg = ns.lock();
    match mg.tmpfs.iter_mut().find(|m| m.0 == target) {
        Some(m) => {
            // remount flips ro; other option bits persist
            m.1 = (m.1 & !shared::MS_RDONLY) | if ro { shared::MS_RDONLY } else { 0 };
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
pub fn mount(target: &str, opts: u64) -> Result<(), i64> {
    if target == "/" {
        return Err(-22);
    }
    let ns = crate::task::ns_of();
    let mut mg = ns.lock();
    if mg.tmpfs.iter().any(|m| m.0 == target) {
        return Err(-16);
    }
    let mut ng = NODES.lock();
    // a fresh mount is a fresh superblock: purge any stale node tree a
    // dead namespace left under this prefix (nodes are path-keyed
    // globally, so the purge belongs in the mount itself)
    let under = alloc::format!("{}/", target);
    ng.retain(|k, _| !k.starts_with(&under));
    let (cu, cg, cm) = fresh(true);
    ng.insert(
        String::from(target),
        Node {
            is_dir: true,
            pages: Vec::new(),
            size: 0,
            mtime: crate::vfs::now_unix(),
            ctime: crate::vfs::now_unix(),
            attr: 0,
            uid: cu,
            gid: cg,
            mode: cm,
            children: Vec::new(),
        },
    );
    mg.tmpfs.push((String::from(target), opts));
    mg.tmpfs.sort_by(|a, b| b.0.len().cmp(&a.0.len())); // longest prefix wins
    ANY.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// MS_MOVE: relocate a mounted tmpfs onto `new`. The whole node tree
/// is path-keyed, so the move re-keys every node under the prefix —
/// open descriptors into the old path resolve through the same nodes
/// only if the mount's entry moved with them (it does — same super).
/// EINVAL when `old` isn't mounted here; EBUSY when `new` is taken.
pub fn move_mount(old: &str, new: &str) -> Result<(), i64> {
    let ns = crate::task::ns_of();
    let mut mg = ns.lock();
    let Some(i) = mg.tmpfs.iter().position(|m| m.0 == old) else {
        return Err(-22);
    };
    if mg.tmpfs.iter().any(|m| m.0 == new) {
        return Err(-16);
    }
    let under = alloc::format!("{}/", old);
    let under_new = alloc::format!("{}/", new);
    let mut ng = NODES.lock();
    let old_nodes = core::mem::take(&mut *ng);
    let moved: Vec<(String, Node)> = old_nodes
        .into_iter()
        .map(|(k, v)| {
            if k == old {
                (String::from(new), v)
            } else if let Some(rest) = k.strip_prefix(&under) {
                (alloc::format!("{}{}", under_new, rest), v)
            } else {
                (k, v)
            }
        })
        .collect();
    *ng = moved.into_iter().collect();
    mg.tmpfs[i].0 = String::from(new);
    mg.tmpfs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    Ok(())
}

/// Unmount: EBUSY when any live fd or cwd sits under the mount, or a
/// nested tmpfs mount lives inside it. Drops every node under the prefix.
/// umount2(target, flags): MNT_FORCE(1) skips the busy checks and
/// purges; MNT_DETACH(2) drops the mount point but keeps the node tree
/// alive for already-resolved paths (lazy umount).
pub fn umount(target: &str, flags: u64) -> Result<(), i64> {
    let ns = crate::task::ns_of();
    let mut mg = ns.lock();
    let Some(i) = mg.tmpfs.iter().position(|m| m.0 == target) else {
        return Err(-22); // EINVAL: not a mount
    };
    let under = alloc::format!("{}/", target);
    let force = flags & shared::MNT_FORCE != 0;
    // MNT_DETACH (lazy) also skips busy checks — it detaches regardless.
    if !force && flags & shared::MNT_DETACH == 0 {
        // busy: a nested mount, or an open fd / cwd below it
        if mg.tmpfs.iter().any(|m| m.0.starts_with(&under)) {
            return Err(-16);
        }
        if crate::task::fd_path_prefix_in_use(&under) || crate::task::cwd_under(&under) {
            return Err(-16);
        }
    }
    mg.tmpfs.remove(i);
    ANY.fetch_sub(1, Ordering::Relaxed);
    if flags & shared::MNT_DETACH != 0 {
        // lazy: keep the node tree serving resolved paths
        mg.detached.push(String::from(target));
        return Ok(());
    }
    let mut ng = NODES.lock();
    ng.retain(|k, _| k.as_str() != target && !k.starts_with(&under));
    mg.detached.retain(|p| p.as_str() != target);
    Ok(())
}

/// open(2) semantics for a tmpfs path. Returns ((), append_pos).
pub fn open(path: &str, flags: u64) -> Result<u64, i64> {
    // FS_IMMUTABLE_FL / FS_APPEND_FL: write-intent opens on an `i`-marked
    // node fail EPERM; `a`-marked nodes accept only O_APPEND opens.
    if flags
        & (shared::O_WRONLY | shared::O_RDWR | shared::O_TRUNC | shared::O_APPEND)
        != 0
    {
        if let Some((_, _, _, _, attr)) = stat(path) {
            if attr & 0x80 != 0 || (attr & 0x08 != 0 && flags & shared::O_APPEND == 0) {
                return Err(-1);
            }
        }
    }
    let wants_write = flags
        & (shared::O_WRONLY | shared::O_RDWR | shared::O_CREATE | shared::O_TRUNC | shared::O_APPEND)
        != 0;
    if wants_write && ro(path) {
        return Err(-30); // EROFS
    }
    // fs.protected_regular: O_CREAT open-for-write of an existing
    // regular file inside a sticky+world-writable dir is denied unless
    // the opener owns the file or the dir (CAP_FOWNER exempts) — the
    // regular-file arm of Linux may_open.
    if flags & shared::O_CREATE != 0
        && flags & (shared::O_WRONLY | shared::O_RDWR | shared::O_TRUNC) != 0
        && crate::sysctl::protected_regular() != 0
    {
        let (eu, _eg) = crate::task::cred();
        if eu != 0 && !crate::task::capable_ns_dac(crate::task::CAP_FOWNER) {
            let ng = NODES.lock();
            if let Some(n) = ng.get(path) {
                if !n.is_dir {
                    let par = parent_of(path).unwrap_or_else(|| String::from("/"));
                    let denied = ng
                        .get(&par)
                        .map(|p| {
                            p.is_dir
                                && p.mode & 0o1002 == 0o1002
                                && eu != n.uid
                                && eu != p.uid
                        })
                        .unwrap_or(false);
                    if denied {
                        return Err(-1); // EPERM
                    }
                }
            }
        }
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
            let (cu, cg, cm) = fresh(false);
            ng.insert(
                String::from(path),
                Node {
                    is_dir: false,
                    pages: Vec::new(),
                    size: 0,
                    mtime: crate::vfs::now_unix(),
                    ctime: crate::vfs::now_unix(),
                    attr: 0x20,
                    uid: cu,
                    gid: cg,
                    mode: cm,
                    children: Vec::new(),
                },
            );
            Ok(0)
        }
    }
}

pub fn read_range(path: &str, off: u64, buf: &mut [u8]) -> Result<usize, i64> {
    if !may_read(path) {
        return Err(-13);
    }
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
            let ns = crate::task::ns_of();
            let Some(mg) = ns.try_lock() else {
                crate::task::wait_irq();
                continue;
            };
            if !mounted(&mg.tmpfs, path) && !mg.detached.iter().any(|p| under(p, path)) {
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
    if !may_read(path) {
        return Err(-13);
    }
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
    // DAC: the node (or its parent on create) must grant the caller write
    if !may_write(path) {
        return Err(-13);
    }
    if ro(path) {
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
    if ro(path) {
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

/// fs.protected_symlinks: a link in a sticky, world-writable dir may
/// only be followed by its owner, the dir's owner, or CAP_FOWNER.
/// readlink(2) stays ungated — this is for the follow path only.
pub fn link_follow_denied(path: &str) -> bool {
    if crate::sysctl::protected_symlinks() == 0 {
        return false;
    }
    let (eu, _eg) = crate::task::cred();
    if eu == 0 || crate::task::capable_ns_dac(crate::task::CAP_FOWNER) {
        return false;
    }
    let ng = NODES.lock();
    let Some(n) = ng.get(path) else {
        return false;
    };
    if n.is_dir || n.attr & 0x40 == 0 {
        return false;
    }
    let parent = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => return false,
    };
    let Some(dir) = ng.get(parent) else {
        return false;
    };
    dir.is_dir && dir.mode & 0o1000 != 0 && dir.mode & 0o002 != 0
        && eu != n.uid
        && eu != dir.uid
}

/// (is_dir, mode, owner-uid) of a tmpfs node — fs.protected_fifos reads
/// the containing dir's sticky/world-writable bits through this.
pub fn dir_meta(path: &str) -> Option<(bool, u16, u32)> {
    let ng = NODES.lock();
    ng.get(path).map(|n| (n.is_dir, n.mode, n.uid))
}

/// Raw symlink target — mirrors the FAT32 "LNK>" convention: a node
/// with attr bit 0x40 whose body starts with "LNK>" names its target.
/// None when the node isn't a link (also what dangling means).
pub fn readlink(path: &str) -> Option<String> {
    let ng = NODES.lock();
    let n = ng.get(path)?;
    if n.is_dir || n.attr & 0x40 == 0 || n.size > 4096 || n.size < 4 {
        return None;
    }
    let mut b = [0u8; 4096];
    let got = read_pages(n, 0, &mut b);
    if !b[..got].starts_with(b"LNK>") {
        return None;
    }
    let t = String::from_utf8_lossy(&b[4..got]).trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub fn exists(path: &str) -> bool {
    NODES.lock().contains_key(path)
}

pub fn stat(path: &str) -> Option<(u64, bool, u64, u64, u8)> {
    let ng = NODES.lock();
    ng.get(path)
        .map(|n| (n.size, n.is_dir, n.mtime, n.ctime, n.attr))
}

pub fn mkdir(path: &str) -> Result<(), i64> {
    if !may_write(path) {
        return Err(-13);
    }
    if ro(path) {
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
    let (cu, cg, cm) = fresh(true);
    ng.insert(
        String::from(path),
        Node {
            is_dir: true,
            pages: Vec::new(),
            size: 0,
            mtime: crate::vfs::now_unix(),
            ctime: crate::vfs::now_unix(),
            attr: 0,
            uid: cu,
            gid: cg,
            mode: cm,
            children: Vec::new(),
        },
    );
    Ok(())
}

/// unlink/rmdir: files drop on unlink; dirs only when empty (-39 ENOTEMPTY).
pub fn remove(path: &str) -> Result<(), i64> {
    if !may_write(path) {
        return Err(-13);
    }
    if ro(path) {
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
    if !may_write(from) || !may_write(to) {
        return Err(-13);
    }
    {
        let ns = crate::task::ns_of();
        let mg = ns.lock();
        if ro_of(&mg.tmpfs, from) || ro_of(&mg.tmpfs, to) {
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
    if ro(path) {
        return Err(-30);
    }
    let mut ng = NODES.lock();
    let Some(n) = ng.get_mut(path) else { return Err(-2) };
    n.mtime = secs;
    Ok(())
}

pub fn setattr(path: &str, attr: u8) -> Result<(), i64> {
    // attribute flips are owner/root only — same bar as chmod
    let (eu, _) = crate::task::cred();
    if eu != 0 {
        let g = NODES.lock();
        if g.get(path).map(|n| n.uid != eu).unwrap_or(false) {
            return Err(-1);
        }
    }
    if ro(path) {
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

/// (files, ffree) for statfs/df -i: every node (dirs included) is a real
/// inode; free inodes are bound by the quota — one inode per minimal node.
pub fn ifree() -> (u64, u64) {
    let ng = NODES.lock();
    let used = ng.len() as u64;
    let free = QUOTA.saturating_sub(used_bytes(&ng)) / 64;
    (used, free.max(used))
}
