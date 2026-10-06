//! VFS: single mounted FAT32 volume on the virtio-blk data disk.
//! Per-task fd tables live in task.rs; this module owns the FS and path logic.
use crate::sprintln;
use crate::task::{self, FileDesc};
use alloc::string::String;
use alloc::vec::Vec;
use fat32::Fat32;
use spin::Mutex;

pub static FS: Mutex<Option<Fat32<crate::virtio::BlkDev>>> = Mutex::new(None);

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

/// Join `cwd` + `path`, resolve `.`/`..`, return canonical absolute path.
pub fn normalize(cwd: &str, path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let joined: String = if path.starts_with('/') {
        String::from(path)
    } else {
        alloc::format!("{}/{}", cwd.trim_end_matches('/'), path)
    };
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    let mut s = String::from("/");
    s.push_str(&out.join("/"));
    s
}

pub fn read_all(path: &str) -> Result<Vec<u8>, i64> {
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
    let mut g = FS.lock();
    match g.as_mut() {
        Some(fs) => fs.read_file(path).map_err(err_to_i64),
        None => Err(-1),
    }
}

fn err_to_i64(e: fat32::Error) -> i64 {
    -(e as i64) - 100
}

// ---- fd ops on the current task ----

fn alloc_fd() -> usize {
    task::with_current(|t| {
        for (i, f) in t.fds.iter().enumerate() {
            if f.is_none() {
                return i;
            }
        }
        t.fds.push(None);
        t.fds.len() - 1
    })
}

pub fn open(path: &str, flags: u64) -> Result<i64, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let is_proc = crate::proc::handles(&full);
    let is_dev = crate::dev::handles(&full);
    if is_dev && crate::dev::is_dir(&full) {
        return Err(-4);
    }
    let exists = if is_dev {
        true
    } else if is_proc {
        // procfs is read-only: opening a dir or creating is rejected
        if crate::proc::is_dir(&full) || flags & shared::O_CREATE != 0 {
            return Err(-4);
        }
        crate::proc::exists(&full)
    } else {
        fs.exists(&full)
    };
    const O_CREAT: u64 = shared::O_CREATE;
    const O_TRUNC: u64 = shared::O_TRUNC;
    const O_APPEND: u64 = shared::O_APPEND;
    if !exists {
        if flags & O_CREAT == 0 {
            return Err(-2);
        }
        fs.create_file(&full).map_err(err_to_i64)?;
    }
    if exists && flags & O_TRUNC != 0 && !is_dev {
        fs.write_file(&full, &[]).map_err(err_to_i64)?;
    }
    // procfs files stream live data; their size is per-read, not on disk
    let pos = if flags & O_APPEND != 0 && !is_proc {
        fs.stat(&full).map_err(err_to_i64)?.size
    } else {
        0
    };
    let fd = alloc_fd() as i64;
    task::with_current(|t| {
        t.fds[fd as usize] = Some(FileDesc { path: full, pos, flags });
    });
    Ok(fd)
}

/// read up to buf.len() bytes at the fd's current position
pub fn read(fd: i64, buf: &mut [u8]) -> Result<i64, i64> {
    let (path, pos) = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => (f.path.clone(), f.pos),
        _ => (String::new(), u64::MAX),
    });
    if pos == u64::MAX {
        return Err(-3);
    }
    if crate::dev::handles(&path) {
        let n = crate::dev::read_at(&path, pos, buf)? as u64;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n;
            }
        });
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
    Ok(n as i64)
}

pub fn write(fd: i64, buf: &[u8]) -> Result<i64, i64> {
    let (path, pos, flags) = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => (f.path.clone(), f.pos, f.flags),
        _ => (String::new(), u64::MAX, 0u64),
    });
    if pos == u64::MAX {
        return Err(-3);
    }
    if crate::dev::handles(&path) {
        let n = crate::dev::write(&path, buf.len())?;
        task::with_current(|t| {
            if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
                f.pos += n as u64;
            }
        });
        return Ok(n as i64);
    }
    if crate::proc::handles(&path) {
        return Err(-4); // procfs is read-only
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
    task::with_current(|t| {
        if let Some(Some(f)) = t.fds.get_mut(fd as usize) {
            f.pos = end as u64;
        }
    });
    Ok(buf.len() as i64)
}

pub fn close(fd: i64) {
    task::with_current(|t| {
        if let Some(slot) = t.fds.get_mut(fd as usize) {
            *slot = None;
        }
    });
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
    if crate::dev::handles(&full) {
        return Ok(shared::Stat {
            size: 0,
            is_dir: crate::dev::is_dir(&full) as u32,
            mtime: 0,
        });
    }
    if crate::proc::handles(&full) {
        if crate::proc::is_dir(&full) {
            return Ok(shared::Stat { size: 0, is_dir: 1, mtime: 0 });
        }
        return crate::proc::read_file(&full)
            .map(|d| shared::Stat { size: d.len() as u64, is_dir: 0, mtime: 0 })
            .ok_or(-2);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    let e = fs.stat(&full).map_err(err_to_i64)?;
    Ok(shared::Stat { size: e.size, is_dir: e.is_dir as u32, mtime: e.mtime })
}

pub fn listdir(path: &str) -> Result<Vec<shared::DirEntry>, i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::dev::handles(&full) {
        return if crate::dev::is_dir(&full) {
            Ok(crate::dev::entries())
        } else {
            Err(-4) // ENOTDIR
        };
    }
    if crate::proc::handles(&full) {
        return if crate::proc::is_dir(&full) {
            Ok(crate::proc::entries())
        } else {
            Err(-4) // ENOTDIR
        };
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
        out.push(de);
    }
    Ok(out)
}

pub fn mkdir(path: &str) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::proc::handles(&full) || crate::dev::handles(&full) {
        return Err(-4);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.mkdir(&full).map_err(err_to_i64)
}

pub fn remove(path: &str) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    if crate::proc::handles(&full) || crate::dev::handles(&full) {
        return Err(-4);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.remove(&full).map_err(err_to_i64)
}

pub fn rename(from: &str, to: &str) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let f = normalize(&cwd, from);
    let t2 = normalize(&cwd, to);
    if crate::proc::handles(&f)
        || crate::proc::handles(&t2)
        || crate::dev::handles(&f)
        || crate::dev::handles(&t2)
    {
        return Err(-4);
    }
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    fs.rename(&f, &t2).map_err(err_to_i64)
}

/// Whole-file write without the fd table — for kernel-side producers
/// (screenshots). Path is normalized against the caller's cwd.
pub fn write_all_path(path: &str, data: &[u8]) -> Result<(), i64> {
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = normalize(&cwd, path);
    let mut g = FS.lock();
    let fs = g.as_mut().ok_or(-1i64)?;
    if !fs.exists(&full) {
        fs.create_file(&full).map_err(err_to_i64)?;
    }
    fs.write_file(&full, data).map_err(err_to_i64)
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
