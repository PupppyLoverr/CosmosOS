//! VFS: single mounted FAT32 volume on the virtio-blk data disk.
//! Per-task fd tables live in task.rs; this module owns the FS and path logic.
use crate::sprintln;
use crate::task::{self, FileDesc};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fat32::Fat32;
use spin::Mutex;

pub static FS: Mutex<Option<Fat32<crate::virtio::BlkDev>>> = Mutex::new(None);

// ---- file-IO accounting for /proc/iostat ----
// Counts user-visible read()/write() calls and requested byte counts,
// not device sectors (that's the layer a real OS reports at /proc/diskstats).

use core::sync::atomic::{AtomicU64, Ordering};

static RD_OPS: AtomicU64 = AtomicU64::new(0);
static RD_BYTES: AtomicU64 = AtomicU64::new(0);
static WR_OPS: AtomicU64 = AtomicU64::new(0);
static WR_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn io_stats() -> (u64, u64, u64, u64) {
    (
        RD_OPS.load(Ordering::Relaxed),
        RD_BYTES.load(Ordering::Relaxed),
        WR_OPS.load(Ordering::Relaxed),
        WR_BYTES.load(Ordering::Relaxed),
    )
}

pub fn init() -> bool {
    let Some(dev) = crate::virtio::block_device() else {
        sprintln!("[vfs] no block device");
        return false;
    };
    match Fat32::mount(dev) {
        Ok(mut fs) => {
            fs.set_time_fn(current_unix);
            match fs.readdir("/") {
                Ok(ents) => {
                    for e in &ents {
                        sprintln!("[vfs] root: {:?} dir={} size={}", e.name, e.is_dir, e.size);
                    }
                }
                Err(e) => sprintln!("[vfs] root scan failed: {:?}", e),
            }
            *FS.lock() = Some(fs);
            sprintln!("[vfs] data disk mounted (FAT32)");
            true
        }
        Err(e) => {
            sprintln!("[vfs] mount failed: {:?}", e);
            false
        }
    }
}

pub fn now_unix() -> u64 {
    current_unix()
}

fn current_unix() -> u64 {
    let d = crate::timer::datetime();
    dos_dt_to_unix(d.year, d.month, d.day, d.hour, d.minute, d.second)
}

fn dos_dt_to_unix(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> u64 {
    // days since epoch via civil algorithm
    let y = y as i64;
    let m = mo as i64;
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days.max(0) as u64) * 86400 + h as u64 * 3600 + mi as u64 * 60 + s as u64
}

/// Join `cwd` + `path`, resolve `.`/`..`, return canonical absolute
/// (physical) path. When the calling task is chrooted (`t.root != "/"`),
/// absolute paths resolve under the jail root and `..` can't pop above
/// it — cwd/root are always stored as physical paths.
fn normalize_inner(cwd: &str, path: &str) -> String {
    let root = task::with_current(|t| t.root.clone());
    let root_depth = root.split('/').filter(|c| !c.is_empty()).count();
    let mut out: Vec<&str> = Vec::new();
    let joined: String = if path.starts_with('/') {
        // virtual absolute -> physical under the jail root
        if root == "/" {
            String::from(path)
        } else {
            alloc::format!("{}{}", root.trim_end_matches('/'), path)
        }
    } else {
        alloc::format!("{}/{}", cwd.trim_end_matches('/'), path)
    };
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if out.len() > root_depth {
                    out.pop();
                }
            }
            c => out.push(c),
        }
    }
    let mut s = String::from("/");
    s.push_str(&out.join("/"));
    s
}

pub fn normalize(cwd: &str, path: &str) -> String {
    // Bind mounts apply on the canonical path — AFTER `..` resolution,
    // so `bind/../x` escapes to the real parent exactly like Linux.
    crate::bind::resolve(&normalize_inner(cwd, path))
}

/// Canonical path BEFORE bind aliasing — what the user actually named.
/// Mount-option checks (MS_NODEV/MS_NOEXEC) look up the covering mount
/// on this path; resolution funnels through normalize() for the rest.
pub fn normalize_prebind(cwd: &str, path: &str) -> String {
    normalize_inner(cwd, path)
}

pub fn read_all(path: &str) -> Result<Vec<u8>, i64> {
    if crate::pipes::handles(path) {
        return if crate::pipes::is_dir(path) {
            Err(-4) // EISDIR
        } else {
            let mut out = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match crate::pipes::try_read(path, &mut tmp) {
                    crate::pipes::TryRead::Data(n) => out.extend_from_slice(&tmp[..n]),
                    _ => break,
                }
            }
            Ok(out)
        };
    }
    if crate::dev::handles(path) {
        return if crate::dev::is_dir(path) {
            Err(-4) // EISDIR
        } else {
            crate::dev::read_file(path).ok_or(-2)
        };
    }
    if crate::proc::handles(path) {
        return if crate::proc::is_dir(path) {
            Err(-4) // EISDIR
        } else {
            crate::proc::read_file(path).ok_or(-2)
        };
    }
    if crate::cgroup::handles(path) {
        return if crate::cgroup::is_dir(path) {
            Err(-4) // EISDIR
        } else {
            crate::cgroup::read_file(path).ok_or(-2)
        };
    }
    if crate::tmpfs::handles(path) {
        return crate::tmpfs::read_all(path);
    }
    let mut g = FS.lock();
    match g.as_mut() {
        Some(fs) => fs.read_file(path).map_err(err_to_i64),
        None => Err(-1),
    }
}

/// Read `buf.len()` bytes at `offset` of a real file (normal callers).
pub fn read_range(path: &str, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    if crate::memfd::handles(path) {
        return crate::memfd::read_at(path, offset, buf);
    }
    if crate::tmpfs::handles(path) {
        return crate::tmpfs::read_range(path, offset, buf);
    }
    if crate::pipes::handles(path) || crate::dev::handles(path) || crate::proc::handles(path) || crate::cgroup::handles(path) {
        return Err(-22);
    }
    let mut g = FS.lock();
    match g.as_mut() {
        Some(fs) => fs.read_file_range(path, offset, buf).map_err(err_to_i64),
        None => Err(-1),
    }
}

/// Demand-paging read for the #PF path. Same read, but the FS lock is
/// taken with try_lock+wait_irq: the holder may be a preempted task, and
/// spinning here would deadlock the fault handler — rescheduling it
/// lets it finish and release.
pub fn read_range_pf(path: &str, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    // paths here arrive normalized at map time, but fold any bind too
    // (try_lock + wait_irq: the #PF contract forbids spinning/allocs).
    let owned;
    let path = match crate::bind::resolve_pf(path) {
        Some(p) => {
            owned = p;
            owned.as_str()
        }
        None => path,
    };
    if crate::memfd::handles(path) {
        // RAM store — no FS lock needed, safe inside the fault handler
        return crate::memfd::read_at(path, offset, buf);
    }
    if let Some(r) = crate::tmpfs::read_range_pf(path, offset, buf) {
        // RAM store — try_lock+wait_irq inside keeps the fault handler safe
        return r;
    }
    loop {
        if let Some(mut g) = FS.try_lock() {
            return match g.as_mut() {
                Some(fs) => fs.read_file_range(path, offset, buf).map_err(err_to_i64),
                None => Err(-1),
            };
        }
        crate::task::wait_irq();
    }
}

fn err_to_i64(e: fat32::Error) -> i64 {
    -(e as i64) - 100
}

// ---- fd ops on the current task ----

/// First free fd index below RLIMIT_NOFILE; None = EMFILE. POSIX bounds
/// the fd INDEX — slots at or above the limit are never handed out,
/// even when the vec has holes there.
fn alloc_fd() -> Option<usize> {
    task::with_current(|t| {
        for (i, f) in t.fds.iter().enumerate() {
            if f.is_none() && (i as u64) < t.rlim_nofile {
                return Some(i);
            }
        }
        if t.fds.len() as u64 >= t.rlim_nofile {
            return None;
        }
        t.fds.push(None);
        Some(t.fds.len() - 1)
    })
}

/// Transparent symlinks: a regular file carrying FAT attr bit 0x40 whose
/// body starts with "LNK>" is a symlink; the rest of the body is the target
/// (relative targets resolve against the link's directory, POSIX-style).
/// `full` is rewritten to the final target path. ELOOP after 8 hops.
fn resolve_links(
    fs: &mut Fat32<crate::virtio::BlkDev>,
    full: &mut String,
) -> Result<(), i64> {
    for _ in 0..8 {
        // tmpfs mounts share the LNK> convention — a link under a
        // tmpfs-covered dir (e.g. /tmp) resolves here too, and its
        // target may point back at FAT
        if crate::tmpfs::handles(full) {
            match crate::tmpfs::readlink(full) {
                Some(tgt) => {
                    let base = match full.rfind('/') {
                        Some(i) => String::from(&full[..i + 1]),
                        None => String::from("/"),
                    };
                    *full = normalize(&base, &tgt);
                    continue;
                }
                None => return Ok(()),
            }
        }
        let st = match fs.stat(full) {
            Ok(s) => s,
            Err(_) => return Ok(()), // dangling: open/stat report ENOENT on the link itself
        };
        if st.is_dir || st.attr & 0x40 == 0 || st.size > 4096 {
            return Ok(());
        }
        let data = fs.read_file(full).unwrap_or_default();
        if !data.starts_with(b"LNK>") {
            return Ok(());
        }
        let tgt = String::from_utf8_lossy(&data[4..]).trim().to_string();
        if tgt.is_empty() {
            return Ok(());
        }
        let base = match full.rfind('/') {
            Some(i) => String::from(&full[..i + 1]),
            None => String::from("/"),
        };
        *full = normalize(&base, &tgt);
    }
    Err(-40) // ELOOP
}

/// Raw read of a symlink body: target string iff `path` is a 0x40 attr file
/// with a "LNK>" body, else Err(-22) EINVAL (not a symlink).
pub fn readlink(path: &str) -> Result<String, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::readlink(&full).ok_or(-22);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let st = fs.stat(&full).map_err(err_to_i64)?;
    if st.attr & 0x40 == 0 {
        return Err(-22);
    }
    let data = fs.read_file(&full).map_err(err_to_i64)?;
    if !data.starts_with(b"LNK>") {
        return Err(-22);
    }
    Ok(String::from_utf8_lossy(&data[4..]).trim().to_string())
}

pub fn open(path: &str, flags: u64) -> Result<i64, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let mut full = normalize(&cwd, path);
    // O_PATH: descriptor for pathname operations only — never creates,
    // truncates, or appends; read/write/seek on it return EBADF.
    let flags = if flags & shared::O_PATH != 0 {
        (flags | shared::O_PATH) & !(shared::O_CREATE | shared::O_TRUNC | shared::O_APPEND)
    } else {
        flags
    };
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    // links are fully transparent: resolve first, then classify the target
    resolve_links(fs, &mut full)?;
    let is_proc = crate::proc::handles(&full);
    let is_dev = crate::dev::handles(&full);
    let is_pipe = crate::pipes::handles(&full);
    let is_cg = crate::cgroup::handles(&full);
    // MS_NODEV on the covering mount (typically a bind alias) bars
    // device-file access through it — EACCES like Linux.
    if is_dev {
        let pre = normalize_prebind(&cwd, path);
        if task::mount_opts(&pre) & shared::MS_NODEV != 0 {
            return Err(-13);
        }
        // Raw hardware exposure is capability-gated: /dev/mem (physical
        // RAM) and /dev/port (PIO space) need CAP_SYS_RAWIO.
        if (full == "/dev/mem" || full == "/dev/port")
            && !task::capable(task::CAP_SYS_RAWIO)
        {
            return Err(-1);
        }
    }
    if crate::tmpfs::handles(&full) {
        let pos = crate::tmpfs::open(&full, flags)?;
        crate::notify::fire(&full, crate::notify::IN_ACCESS);
        let Some(fdi) = alloc_fd() else { return Err(-24) };
        let fd = fdi as i64;
        task::with_current(|t| {
            t.fds[fd as usize] = Some(FileDesc { path: full, pos, flags });
        });
        return Ok(fd);
    }
    // PTY slave nodes (/dev/pts/{id}) and direct /ptym/{id} opens: real
    // objects with refcounted descs; the pair must exist already
    if crate::pty::handles(&full) {
        if !crate::pty::exists(&full) {
            return Err(-2);
        }
        crate::pty::acquire(&full);
        let Some(fdi) = alloc_fd() else { return Err(-24) };
        let fd = fdi as i64;
        task::with_current(|t| {
            t.fds[fd as usize] = Some(FileDesc {
                path: full,
                pos: 0,
                flags,
            });
        });
        return Ok(fd);
    }
    if is_pipe {
        if crate::pipes::is_dir(&full) {
            return Err(-4);
        }
        // mkfifo-style create: O_CREATE on a missing /pipes path makes a
        // pipe object, not a FAT file
        if !crate::pipes::exists(&full) {
            if flags & shared::O_CREATE == 0 {
                return Err(-2);
            }
            crate::pipes::create(&full)?;
        }
        // writer = an fd opened for write (O_WRONLY|O_TRUNC|O_APPEND), i.e.
        // `>` / `>>` opens; plain readers take the reader slot
        let writer = flags & (shared::O_WRONLY | shared::O_TRUNC | shared::O_APPEND) != 0;
        crate::pipes::open_role(&full, writer);
        let Some(fdi) = alloc_fd() else { return Err(-24) }; // EMFILE
        let fd = fdi as i64;
        task::with_current(|t| {
            t.fds[fd as usize] = Some(FileDesc { path: full, pos: 0, flags });
        });
        return Ok(fd);
    }
    if is_dev && crate::dev::is_dir(&full) {
        return Err(-4);
    }
    let is_fat = !is_dev && !is_proc && !is_pipe && !crate::pty::handles(&full);
    // vfat ownership model: every file is root:root — a non-root caller
    // gets the "other" bits only, so nothing on the volume is writable.
    if is_fat
        && task::cred().0 != 0
        && flags
            & (shared::O_WRONLY
                | shared::O_RDWR
                | shared::O_CREATE
                | shared::O_TRUNC
                | shared::O_APPEND)
            != 0
    {
        return Err(-13);
    }
    let exists = if is_dev {
        true
    } else if is_proc {
        // procfs is read-only: dirs are rejected; O_CREATE only fails when
        // the proc file is genuinely absent (no proc files can be created)
        if crate::proc::is_dir(&full) {
            return Err(-4);
        }
        // /proc/<pid>/ns/{mntns,uts} opens as a namespace OBJECT fd pinning
        // the task's MountNs/UtsNs — the fd survives the task swapping
        // namespaces (setns's adopt source), not just its current entry.
        if let Some(obj) = crate::nsfd::open(&full) {
            let Some(fdi) = alloc_fd() else { return Err(-24) };
            let fd = fdi as i64;
            task::with_current(|t| {
                t.fds[fd as usize] = Some(FileDesc {
                    path: obj,
                    pos: 0,
                    flags,
                });
            });
            return Ok(fd);
        }
        let ex = crate::proc::exists(&full);
        if !ex && flags & shared::O_CREATE != 0 {
            return Err(-4);
        }
        ex
    } else if is_cg {
        // cgroupfs is read-computed/write-routed: O_CREATE only works
        // through mkdir; a missing control file fails
        if crate::cgroup::is_dir(&full) {
            return Err(-4);
        }
        let ex = crate::cgroup::exists(&full);
        if !ex && flags & shared::O_CREATE != 0 {
            return Err(-4);
        }
        ex
    } else {
        fs.exists(&full)
    };
    const O_CREAT: u64 = shared::O_CREATE;
    const O_TRUNC: u64 = shared::O_TRUNC;
    const O_APPEND: u64 = shared::O_APPEND;
    if exists && flags & O_CREAT != 0 && flags & shared::O_EXCL != 0 {
        return Err(-17); // EEXIST
    }
    if !exists {
        if flags & O_CREAT == 0 || is_cg {
            return Err(-2); // no O_CREATE under cgroupfs — use mkdir
        }
        fs.create_file(&full).map_err(err_to_i64)?;
        crate::notify::fire(&full, crate::notify::IN_CREATE);
        // POSIX umask: FAT has no mode bits; the one meaningful mapping is
        // owner-write masked out -> the readonly attribute. Other bits are
        // ignored (fat32 has nothing to map them onto).
        let um = task::with_current(|t| t.umask);
        if um & 0o200 != 0 {
            let cur = fs.stat(&full).map(|s| s.attr).unwrap_or(0);
            let _ = fs.set_meta(&full, None, Some(cur | 0x01));
        }
    }
    if exists && flags & O_TRUNC != 0 && !is_dev && !is_proc && !is_cg {
        fs.write_file(&full, &[]).map_err(err_to_i64)?;
        crate::notify::fire(&full, crate::notify::IN_MODIFY);
    }
    // procfs files stream live data; their size is per-read, not on disk
    let pos = if flags & O_APPEND != 0 && !is_proc && !is_cg {
        fs.stat(&full).map_err(err_to_i64)?.size
    } else {
        0
    };
    let Some(fdi) = alloc_fd() else { return Err(-24) }; // EMFILE
    let fd = fdi as i64;
    task::with_current(|t| {
        t.fds[fd as usize] = Some(FileDesc { path: full, pos, flags });
    });
    Ok(fd)
}

/// read up to buf.len() bytes at the fd's current position
pub fn read(fd: i64, buf: &mut [u8]) -> Result<i64, i64> {
    RD_OPS.fetch_add(1, Ordering::Relaxed);
    RD_BYTES.fetch_add(buf.len() as u64, Ordering::Relaxed);
    let (path, pos) = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => (f.path.clone(), f.pos),
        _ => (String::new(), u64::MAX),
    });
    if pos == u64::MAX {
        return Err(-3);
    }
    if crate::pipes::handles(&path) {
        return match crate::pipes::try_read(&path, buf) {
            crate::pipes::TryRead::Data(n) => Ok(n as i64),
            crate::pipes::TryRead::Eof => Ok(0),
            crate::pipes::TryRead::WouldBlock => Ok(0), // nonblocking caller sees EOF
        };
    }
    if crate::memfd::handles(&path) {
        let n = crate::memfd::read_at(&path, pos, buf)? as u64;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n;
            }
        });
        task::io_charge(true, n);
        return Ok(n as i64);
    }
    if crate::dev::handles(&path) {
        let n = crate::dev::read_at(&path, pos, buf)? as u64;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n;
            }
        });
        task::io_charge(true, n);
        return Ok(n as i64);
    }
    if crate::cgroup::handles(&path) {
        let data = crate::cgroup::read_file(&path).ok_or(-3i64)?;
        let avail = if pos as usize >= data.len() { 0 } else { data.len() - pos as usize };
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&data[pos as usize..pos as usize + n]);
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n as u64;
            }
        });
        task::io_charge(true, n as u64);
        return Ok(n as i64);
    }
    if crate::proc::handles(&path) {
        let data = crate::proc::read_file(&path).ok_or(-3i64)?;
        let avail = if pos as usize >= data.len() { 0 } else { data.len() - pos as usize };
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&data[pos as usize..pos as usize + n]);
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n as u64;
            }
        });
        task::io_charge(true, n as u64);
        return Ok(n as i64);
    }
    if crate::tmpfs::handles(&path) {
        let n = crate::tmpfs::read_range(&path, pos, buf)? as u64;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n;
            }
        });
        task::io_charge(true, n);
        return Ok(n as i64);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let data = fs.read_file(&path).map_err(err_to_i64)?;
    let avail = if pos as usize >= data.len() { 0 } else { data.len() - pos as usize };
    let n = avail.min(buf.len());
    buf[..n].copy_from_slice(&data[pos as usize..pos as usize + n]);
    task::with_current(|t| {
        if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
            f.pos += n as u64;
        }
    });
    task::io_charge(true, n as u64);
    Ok(n as i64)
}

/// Read a symlink target. FAT32 links are handled by resolve_links; proc
/// files like `/proc/<pid>/exe` resolve to the recorded spawn path.
pub fn readlink_path(path: &str) -> Result<String, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::proc::handles(&full) {
        if let Some(target) = crate::proc::readlink(&full) {
            return Ok(target);
        }
        return Err(-22);
    }
    readlink(path)
}

/// write buf.len() bytes at the fd's current position
pub fn write(fd: i64, buf: &[u8]) -> Result<i64, i64> {
    WR_OPS.fetch_add(1, Ordering::Relaxed);
    WR_BYTES.fetch_add(buf.len() as u64, Ordering::Relaxed);
    let (path, pos, flags) = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => (f.path.clone(), f.pos, f.flags),
        _ => (String::new(), u64::MAX, 0u64),
    });
    if pos == u64::MAX {
        return Err(-3);
    }
    if crate::pipes::handles(&path) {
        return crate::pipes::try_write(&path, buf);
    }
    if crate::memfd::handles(&path) {
        let n = crate::memfd::write_at(&path, pos, buf)? as u64;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n as u64;
            }
        });
        task::io_charge(false, n as u64);
        return Ok(n as i64);
    }
    if crate::dev::handles(&path) {
        let n = crate::dev::write(&path, pos, buf)?;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n as u64;
            }
        });
        task::io_charge(false, n as u64);
        return Ok(n as i64);
    }
    if crate::cgroup::handles(&path) {
        match crate::cgroup::write_file(&path, buf) {
            Some(n) => {
                task::with_current(|t| {
                    if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                        f.pos += n as u64;
                    }
                });
                task::io_charge(false, n as u64);
                return Ok(n as i64);
            }
            None => return Err(-1),
        }
    }
    if crate::proc::handles(&path) {
        // procfs is read-only except whitelisted sysctl files
        match crate::proc::write_file(&path, buf) {
            Some(n) => {
                task::with_current(|t| {
                    if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                        f.pos += n as u64;
                    }
                });
                task::io_charge(false, n as u64);
                return Ok(n as i64);
            }
            None => return Err(-4),
        }
    }
    if crate::tmpfs::handles(&path) {
        let sz = if flags & shared::O_APPEND != 0 {
            crate::tmpfs::stat(&path).map(|s| s.0).unwrap_or(pos)
        } else {
            pos
        };
        let n = crate::tmpfs::write_range(&path, sz, buf)? as u64;
        crate::notify::fire(&path, crate::notify::IN_MODIFY);
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos = sz + n;
            }
        });
        task::io_charge(false, n);
        return Ok(n as i64);
    }
    const O_APPEND: u64 = shared::O_APPEND;
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let mut data = fs.read_file(&path).map_err(err_to_i64)?;
    let write_pos = if flags & O_APPEND != 0 { data.len() as u64 } else { pos };
    let end = write_pos as usize + buf.len();
    if end > data.len() {
        data.resize(end, 0);
    }
    data[write_pos as usize..end].copy_from_slice(buf);
    fs.write_file(&path, &data).map_err(err_to_i64)?;
    crate::notify::fire(&path, crate::notify::IN_MODIFY);
    task::with_current(|t| {
        if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
            f.pos = end as u64;
        }
    });
    task::io_charge(false, buf.len() as u64);
    Ok(buf.len() as i64)
}

/// Release the kernel-side object a descriptor holds: pipe reader/writer
/// role, inotify watch instance, timerfd, eventfd, epoll set. Called from
/// close() and from the
/// task-exit reaper so dead tasks can't pin objects (e.g. a dead writer
/// would otherwise keep a pipe's `writers` count elevated forever).
/// A new desc now references `f`'s kernel object (the fd table was dup'd
/// or a clone() copied it). Per-desc registrations acquire one hold each
/// so the matching release stays balanced.
pub fn acquire_desc(f: &task::FileDesc) {
    if crate::pipes::handles(&f.path) {
        let writer = f.flags & (shared::O_WRONLY | shared::O_TRUNC | shared::O_APPEND) != 0;
        crate::pipes::open_role(&f.path, writer);
    }
    crate::sockpair::acquire(&f.path);
    crate::mqueue::acquire(&f.path);
    crate::memfd::acquire(&f.path);
    crate::pty::acquire(&f.path);
}

/// Release one desc's hold on its kernel object. Pipe roles and socketpair
/// sides are per-desc registrations — they release unconditionally (the
/// counters were acquired at open/dup/clone). Destructive objects
/// (notify/timerfd/eventfd/epoll/socket/pidfd) die only when `still_open`
/// says no other live desc references the path.
fn release_desc_obj(f: &task::FileDesc, still_open: bool) {
    if crate::pipes::handles(&f.path) {
        let writer = f.flags & (shared::O_WRONLY | shared::O_TRUNC | shared::O_APPEND) != 0;
        crate::pipes::close_role(&f.path, writer);
    }
    // sockpair sides are counted — close decrements, drops at zero
    crate::sockpair::close_obj(&f.path);
    // mqueue fds are refcounted too — a named queue survives until
    // unlink + last close, so release runs on every desc
    crate::mqueue::release(&f.path);
    // memfd stores die at last close
    crate::memfd::release(&f.path);
    // pty pairs: last master desc destroys the pair
    crate::pty::release(&f.path);
    if still_open {
        return;
    }
    crate::notify::close_obj(&f.path);
    crate::timerfd::close_obj(&f.path);
    crate::eventfd::close_obj(&f.path);
    crate::epoll::close_obj(&f.path);
    crate::sockfd::close_obj(&f.path);
    crate::pidfd::close_obj(&f.path);
    crate::nsfd::release(&f.path);
}

pub fn release_desc(f: &task::FileDesc) {
    release_desc_obj(f, task::fd_path_in_use(&f.path));
}

/// Exit-path variant used while the caller already holds SCHED (spin mutex
/// is not recursive): `still_open` was computed against the live task list
/// AND the dying task's own remaining slots inline.
pub fn release_desc_locked(f: &task::FileDesc, still_open: bool) {
    release_desc_obj(f, still_open);
}

pub fn close(fd: i64) {
    let gone = task::with_current(|t| match t.fds.get_mut(fd as usize) {
        Some(slot) => slot.take(),
        None => None,
    });
    if let Some(f) = gone {
        release_desc(&f);
    }
}

pub fn seek(fd: i64, pos: u64) -> Result<i64, i64> {
    task::with_current(|t| match t.fds.get_mut(fd as usize) {
        Some(Some(f)) => {
            f.pos = pos;
            Ok(pos as i64)
        }
        _ => Err(-3),
    })
}

pub fn stat_path(path: &str) -> Result<shared::Stat, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::memfd::handles(&full) {
        return match crate::memfd::stat(&full) {
            Some((sz, at)) => Ok(shared::Stat { size: sz, is_dir: 0, mtime: 0, attr: at as u32 }),
            None => Err(-2),
        };
    }
    if crate::pipes::handles(&full) {
        if crate::pipes::is_dir(&full) {
            return Ok(shared::Stat { size: 0, is_dir: 1, mtime: 0, attr: 0 });
        }
        return match crate::pipes::stat(&full) {
            Some((sz, mt)) => Ok(shared::Stat { size: sz, is_dir: 0, mtime: mt, attr: 0x20 }),
            None => Err(-2),
        };
    }
    if crate::dev::handles(&full) {
        return Ok(shared::Stat {
            size: 0,
            is_dir: crate::dev::is_dir(&full) as u32,
            mtime: 0,
            attr: 0,
        });
    }
    if crate::proc::handles(&full) {
        if crate::proc::is_dir(&full) {
            return Ok(shared::Stat { size: 0, is_dir: 1, mtime: 0, attr: 0 });
        }
        return crate::proc::read_file(&full)
            .map(|d| shared::Stat { size: d.len() as u64, is_dir: 0, mtime: 0, attr: 0 })
            .ok_or(-2);
    }
    if crate::cgroup::handles(&full) {
        if crate::cgroup::is_dir(&full) {
            return Ok(shared::Stat { size: 0, is_dir: 1, mtime: 0, attr: 0 });
        }
        return crate::cgroup::read_file(&full)
            .map(|d| shared::Stat { size: d.len() as u64, is_dir: 0, mtime: 0, attr: 0 })
            .ok_or(-2);
    }
    if crate::tmpfs::handles(&full) {
        return match crate::tmpfs::stat(&full) {
            Some((sz, dir, mt, _ct, at)) => Ok(shared::Stat {
                size: sz,
                is_dir: dir as u32,
                mtime: mt,
                attr: at as u32,
            }),
            None => Err(-2),
        };
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let mut full = full;
    resolve_links(fs, &mut full)?;
    let e = fs.stat(&full).map_err(err_to_i64)?;
    Ok(shared::Stat { size: e.size, is_dir: e.is_dir as u32, mtime: e.mtime, attr: e.attr as u32 })
}

/// Set a file's modify time (unix seconds) — the FAT dir entry is patched
/// in place. Pseudo-filesystems are read-only: always an error.
/// stat without following a trailing symlink (lstat): links report the
/// link's own Stat, everything else falls through to stat_path.
pub fn stat_path_nofollow(path: &str) -> Result<shared::Stat, i64> {
    let path = &crate::bind::resolve(path);
    match readlink_path(path) {
        Ok(_) => {
            let mut g = FS.lock();
            match g.as_mut().and_then(|fs| fs.stat(path).ok()) {
                Some(s) => Ok(shared::Stat {
                    size: s.size,
                    is_dir: if s.is_dir { 1 } else { 0 },
                    mtime: s.mtime,
                    attr: s.attr as u32,
                }),
                None => Err(-2),
            }
        }
        Err(_) => stat_path(path),
    }
}

/// Which mount domain owns `path`: 0 = root fs, n>0 = the nth tmpfs
/// mount or bind (the resolved canonical path is already folded).
fn mount_domain(path: &str) -> usize {
    if crate::tmpfs::handles(path) || !crate::bind::mounts().is_empty()
        && crate::bind::mounts().iter().any(|(t, _)| {
            path == t || (path.len() > t.len()
                && path.starts_with(t)
                && path.as_bytes()[t.len()] == b'/')
        })
    {
        return 1;
    }
    0
}

/// openat2 RESOLVE_* enforcement on the already-canonical path.
/// `base` = the dirfd's own canonical path for BENEATH ("/" for IN_ROOT).
/// Walks each component prefix so symlink and mount-crossing checks see
/// intermediate dirs too. Returns () or a negative errno.
pub fn resolve_flags(path: &str, base: &str, mode: u64) -> Result<(), i64> {
    if mode & shared::RESOLVE_BENEATH != 0 {
        // every prefix of path must stay at/under base
        let b = base.trim_end_matches('/');
        let under = path == b
            || (path.len() > b.len()
                && path.starts_with(b)
                && path.as_bytes()[b.len()] == b'/');
        if !under {
            return Err(-18); // EXDEV-ish: escaped the dirfd subtree
        }
    }
    if mode & (shared::RESOLVE_NO_XDEV | shared::RESOLVE_NO_SYMLINKS) != 0 {
        let base_dom = if mode & shared::RESOLVE_NO_XDEV != 0 {
            Some(mount_domain(base))
        } else {
            None
        };
        // component walk: "", "/a", "/a/b", ...
        let mut pref = String::from("/");
        for (i, comp) in path.split('/').enumerate() {
            if comp.is_empty() {
                continue;
            }
            if i > 1 {
                pref.push('/');
            }
            pref.push_str(comp);
            if mode & shared::RESOLVE_NO_SYMLINKS != 0 {
                if readlink_path(&pref).is_ok() {
                    return Err(-40); // ELOOP: symlink inside a no-symlink resolve
                }
            }
            if let Some(bd) = base_dom {
                if mount_domain(&pref) != bd {
                    return Err(-18); // EXDEV: crossed a mount boundary
                }
            }
        }
    }
    Ok(())
}

/// Birth time (unix secs) for statx — tmpfs ctime, FAT mtime, 0 elsewhere.
pub fn btime(path: &str) -> u64 {
    if crate::tmpfs::handles(path) {
        return crate::tmpfs::stat(path).map(|s| s.3).unwrap_or(0);
    }
    if let Ok(st) = stat_path(path) {
        return st.mtime;
    }
    0
}

pub fn utime(path: &str, secs: u64) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::utime(&full, secs);
    }
    if crate::proc::handles(&full) || crate::dev::handles(&full) || crate::pipes::handles(&full) || crate::cgroup::handles(&full) {
        return Err(-4);
    }
    // vfat ownership: files are root:root, so a non-root caller gets
    // the "other" bits only — writes are EPERM across the volume.
    if task::cred().0 != 0 {
        return Err(-1);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.set_meta(&full, Some(secs), None).map_err(err_to_i64)?;
    crate::notify::fire(&full, crate::notify::IN_ATTRIB);
    Ok(())
}

/// Set the user-settable FAT attribute bits (0x01 ro, 0x02 hidden, 0x04 sys)
/// on a path. Pseudo-filesystems are read-only: always an error.
pub fn setattr(path: &str, attr: u8) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::setattr(&full, attr);
    }
    if crate::proc::handles(&full) || crate::dev::handles(&full) || crate::pipes::handles(&full) || crate::cgroup::handles(&full) {
        return Err(-4);
    }
    // vfat ownership: files are root:root, so a non-root caller gets
    // the "other" bits only — writes are EPERM across the volume.
    if task::cred().0 != 0 {
        return Err(-1);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.set_meta(&full, None, Some(attr)).map_err(err_to_i64)?;
    crate::notify::fire(&full, crate::notify::IN_ATTRIB);
    Ok(())
}

pub fn listdir(path: &str) -> Result<Vec<shared::DirEntry>, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::pipes::handles(&full) {
        return if crate::pipes::is_dir(&full) {
            Ok(crate::pipes::entries())
        } else {
            Err(-4) // ENOTDIR
        };
    }
    if crate::dev::handles(&full) {
        return if crate::dev::is_dir(&full) {
            Ok(crate::dev::entries())
        } else {
            Err(-4) // ENOTDIR
        };
    }
    if crate::proc::handles(&full) {
        return if crate::proc::is_dir(&full) {
            Ok(crate::proc::entries(&full))
        } else {
            Err(-4) // ENOTDIR
        };
    }
    if crate::cgroup::handles(&full) {
        return if crate::cgroup::is_dir(&full) {
            Ok(crate::cgroup::entries(&full))
        } else {
            Err(-4) // ENOTDIR
        };
    }
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::listdir(&full);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let ents = fs.readdir(&full).map_err(err_to_i64)?;
    let mut out = Vec::new();
    for e in ents {
        if e.name == "." || e.name == ".." {
            continue;
        }
        let mut de = shared::DirEntry::default();
        let nb = e.name.as_bytes();
        let l = nb.len().min(95);
        de.name[..l].copy_from_slice(&nb[..l]);
        de.name_len = l as u8;
        de.is_dir = e.is_dir as u8;
        de.size = e.size;
        de.mtime = e.mtime;
        de.attr = e.attr;
        out.push(de);
    }
    Ok(out)
}

pub fn mkdir(path: &str) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::mkdir(&full);
    }
    if crate::cgroup::handles(&full) {
        return crate::cgroup::mkdir(&full);
    }
    if crate::proc::handles(&full) || crate::dev::handles(&full) || crate::pipes::handles(&full) {
        return Err(-4);
    }
    // vfat ownership: files are root:root, so a non-root caller gets
    // the "other" bits only — writes are EPERM across the volume.
    if task::cred().0 != 0 {
        return Err(-1);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.mkdir(&full).map_err(err_to_i64)?;
    crate::notify::fire(&full, crate::notify::IN_CREATE | crate::notify::IN_ISDIR);
    Ok(())
}

pub fn remove(path: &str) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::pipes::handles(&full) && !crate::pipes::is_dir(&full) {
        let r = crate::pipes::remove(&full);
        if r.is_ok() {
            crate::notify::fire(&full, crate::notify::IN_DELETE);
        }
        return r;
    }
    if crate::tmpfs::handles(&full) {
        let r = crate::tmpfs::remove(&full);
        if r.is_ok() {
            crate::notify::fire(&full, crate::notify::IN_DELETE);
        }
        return r;
    }
    if crate::cgroup::handles(&full) {
        return crate::cgroup::remove(&full);
    }
    if crate::proc::handles(&full) || crate::dev::handles(&full) || crate::pipes::handles(&full) {
        return Err(-4);
    }
    // vfat ownership: files are root:root, so a non-root caller gets
    // the "other" bits only — writes are EPERM across the volume.
    if task::cred().0 != 0 {
        return Err(-1);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.remove(&full).map_err(err_to_i64)?;
    crate::notify::fire(&full, crate::notify::IN_DELETE);
    Ok(())
}

pub fn rename(from: &str, to: &str) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let f = normalize(&cwd, from);
    let t2 = normalize(&cwd, to);
    let ft = crate::tmpfs::handles(&f);
    let tt = crate::tmpfs::handles(&t2);
    if ft && tt {
        return crate::tmpfs::rename(&f, &t2);
    }
    if ft != tt {
        return Err(-18); // EXDEV: across mounts is never a plain rename
    }
    if crate::proc::handles(&f)
        || crate::proc::handles(&t2)
        || crate::dev::handles(&f)
        || crate::dev::handles(&t2)
        || crate::pipes::handles(&f)
        || crate::pipes::handles(&t2)
        || crate::cgroup::handles(&f)
        || crate::cgroup::handles(&t2)
    {
        return Err(-4);
    }
    // vfat ownership: files are root:root, so a non-root caller gets
    // the "other" bits only — writes are EPERM across the volume.
    if task::cred().0 != 0 {
        return Err(-1);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.rename(&f, &t2).map_err(err_to_i64)?;
    crate::notify::fire(&f, crate::notify::IN_MOVED_FROM);
    crate::notify::fire(&t2, crate::notify::IN_MOVED_TO);
    Ok(())
}

/// renameat2(2): `flags` = RENAME_NOREPLACE (fail -17 if `to` exists) or
/// RENAME_EXCHANGE (swap two live names). The exchange is done through a
/// per-pid scratch name — FAT rename preserves the directory entry, so both
/// files' data and metadata survive the swap.
pub fn rename2(from: &str, to: &str, flags: u64) -> Result<(), i64> {
    match flags {
        0 => rename(from, to),
        shared::RENAME_NOREPLACE => {
            let cwd = task::with_current(|t| t.cwd.clone());
            if stat_path(&normalize(&cwd, to)).is_ok() {
                return Err(-17); // EEXIST
            }
            rename(from, to)
        }
        shared::RENAME_EXCHANGE => {
            let cwd = task::with_current(|t| t.cwd.clone());
            let f = normalize(&cwd, from);
            let t2 = normalize(&cwd, to);
            if stat_path(&f).is_err() || stat_path(&t2).is_err() {
                return Err(-2); // ENOENT: both names must exist
            }
            let tmp = alloc::format!("/.rn2-swap-{}", task::current_id());
            rename(&f, &tmp)?;
            rename(&t2, &f)?;
            rename(&tmp, &t2)?;
            Ok(())
        }
        _ => Err(-22), // EINVAL
    }
}

/// Resize a filesystem file to `len` (pad zeros or cut) — backs ftruncate(2).
/// Pseudo-fs objects and pipes reject with -22 like a real fd-based truncate.
pub fn truncate_path(path: &str, len: u64) -> Result<(), i64> {
    if crate::memfd::handles(path) {
        return crate::memfd::truncate(path, len);
    }
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::truncate(&full, len);
    }
    if crate::pipes::handles(&full)
        || crate::dev::handles(&full)
        || crate::proc::handles(&full)
        || crate::notify::handles(&full)
        || crate::timerfd::handles(&full)
        || crate::eventfd::handles(&full)
        || crate::epoll::handles(&full)
        || crate::sockpair::handles(&full)
        || crate::sockfd::handles(&full)
        || crate::pidfd::handles(&full)
    {
        return Err(-22); // EINVAL on non-regular fds
    }
    if len > 1 << 28 {
        return Err(-22);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let mut full = full;
    resolve_links(fs, &mut full)?;
    let mut data = fs.read_file(&full).map_err(err_to_i64)?;
    data.resize(len as usize, 0);
    fs.write_file(&full, &data).map_err(err_to_i64)?;
    crate::notify::fire(&full, crate::notify::IN_MODIFY);
    Ok(())
}

/// Whole-file write without the fd table — for kernel-side producers
/// (screenshots). Path is normalized against the caller's cwd.
pub fn write_all_path(path: &str, data: &[u8]) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::tmpfs::handles(&full) {
        crate::tmpfs::open(&full, shared::O_CREATE | shared::O_TRUNC | shared::O_WRONLY)?;
        crate::tmpfs::write_range(&full, 0, data)?;
        return Ok(());
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    if !fs.exists(&full) {
        fs.create_file(&full).map_err(err_to_i64)?;
        crate::notify::fire(&full, crate::notify::IN_CREATE);
    }
    fs.write_file(&full, data).map_err(err_to_i64)?;
    crate::notify::fire(&full, crate::notify::IN_MODIFY);
    Ok(())
}

/// (total_bytes, free_bytes) for the mounted volume.
pub fn df() -> Option<(u64, u64)> {
    let mut g = FS.lock();
    let fs = g.as_mut()?;
    let cb = fs.cluster_bytes();
    let total = fs.total_clusters() * cb;
    let free = fs.free_clusters().ok()? * cb;
    Some((total, free))
}

/// Append a spawn record to /utmp: "pid path unix_secs\n" per user task.
/// Read-modify-write is fine here — the file stays small (one line per spawn).
pub fn utmp_log(pid: u32, path: &str) {
    let line = alloc::format!("{} {} {}\n", pid, path, now_unix());
    let mut cur = read_all("/utmp").unwrap_or_default();
    cur.extend_from_slice(line.as_bytes());
    let _ = write_all_path("/utmp", &cur);
}
