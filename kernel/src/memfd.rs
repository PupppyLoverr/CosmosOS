//! memfd: `SYS_MEMFD_CREATE` mints an anonymous RAM-backed "file" fd
//! (`/memfd/{id}`) — read/write/seek/truncate/stat like a real file,
//! mmap'able through SYS_MMAP_FILE (its pages fault in from the RAM
//! store), and passable across tasks like any fd (SCM_RIGHTS, dup,
//! fork). Storage lives in the kernel store until the last fd closes.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

struct Memfd {
    name: String,
    data: Vec<u8>,
    open_ct: u64,
}

static MFS: Mutex<BTreeMap<u64, Memfd>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn id_of(path: &str) -> Option<u64> {
    path.strip_prefix("/memfd/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    id_of(path).is_some()
}

pub fn exists(path: &str) -> bool {
    match id_of(path) {
        Some(id) => MFS.lock().contains_key(&id),
        None => false,
    }
}

pub fn create(name: &str) -> Result<String, i64> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    MFS.lock().insert(
        id,
        Memfd {
            name: String::from(name),
            data: Vec::new(),
            open_ct: 1, // the fd we're about to hand back
        },
    );
    Ok(alloc::format!("/memfd/{}", id))
}

/// read at `off` — past EOF returns a short/zero count like a file
pub fn read_at(path: &str, off: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-9i64)?;
    let g = MFS.lock();
    let m = g.get(&id).ok_or(-9i64)?;
    let avail = if off as usize >= m.data.len() {
        0
    } else {
        m.data.len() - off as usize
    };
    let n = avail.min(buf.len());
    buf[..n].copy_from_slice(&m.data[off as usize..off as usize + n]);
    Ok(n)
}

/// write at `off` — extends the store (sparse gap zero-filled)
pub fn write_at(path: &str, off: u64, data: &[u8]) -> Result<usize, i64> {
    let id = id_of(path).ok_or(-9i64)?;
    if off > (16 << 20) || data.len() > 1 << 20 {
        return Err(-28); // ENOSPC cap: memfds live in RAM
    }
    let mut g = MFS.lock();
    let m = g.get_mut(&id).ok_or(-9i64)?;
    let end = off as usize + data.len();
    if end > (16 << 20) {
        return Err(-28);
    }
    if m.data.len() < off as usize {
        m.data.resize(off as usize, 0);
    }
    if m.data.len() < end {
        m.data.resize(end, 0);
    }
    m.data[off as usize..end].copy_from_slice(data);
    Ok(data.len())
}

pub fn truncate(path: &str, size: u64) -> Result<(), i64> {
    let id = id_of(path).ok_or(-9i64)?;
    if size > (16 << 20) {
        return Err(-28);
    }
    let mut g = MFS.lock();
    let m = g.get_mut(&id).ok_or(-9i64)?;
    m.data.resize(size as usize, 0);
    Ok(())
}

pub fn stat(path: &str) -> Option<(u64, u64)> {
    let id = id_of(path)?;
    let g = MFS.lock();
    g.get(&id).map(|m| (m.data.len() as u64, 0x20))
}

pub fn name_of(path: &str) -> Option<String> {
    let id = id_of(path)?;
    let g = MFS.lock();
    g.get(&id).map(|m| m.name.clone())
}

/// Another desc references this memfd (dup/fork/clone/SCM_RIGHTS)
pub fn acquire(path: &str) {
    if let Some(id) = id_of(path) {
        if let Some(m) = MFS.lock().get_mut(&id) {
            m.open_ct += 1;
        }
    }
}

/// fd released: last close frees the RAM store (memfd dies with its
/// last descriptor — unlike mqueue there's no persistent name)
pub fn release(path: &str) {
    let Some(id) = id_of(path) else { return };
    let mut g = MFS.lock();
    let dead = match g.get_mut(&id) {
        Some(m) => {
            m.open_ct = m.open_ct.saturating_sub(1);
            m.open_ct == 0
        }
        None => false,
    };
    if dead {
        g.remove(&id);
    }
}
