//! Named pipes: a kernel-global registry of buffered byte FIFOs under
//! `/pipes/`. mkfifo creates an entry; open-for-write (O_TRUNC|O_APPEND)
//! counts as a writer, plain opens as readers. The buffer is kernel heap
//! memory (cap PIPE_CAP), so a writer may run before any reader exists --
//! data stays queued until drained. Readers block (via the syscall layer)
//! while the queue is empty AND a writer is still open; they see EOF once
//! the last writer closes. Writers block when the queue is full and a
//! reader exists, or fail with EPIPE when full and readers == 0.
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub const PIPE_CAP: usize = 64 * 1024;

/// fs.pipe-max-size tunes the live cap downward (never above the const).
fn pipe_cap() -> usize {
    PIPE_CAP.min(crate::sysctl::fs_pipe_max())
}

pub struct Pipe {
    pub buf: VecDeque<u8>,
    pub writers: u32,
    pub readers: u32,
    /// A reader has been attached at least once — writes may only EPIPE
    /// after this is true (a fifo writer opened before any reader buffers
    /// instead, since our open doesn't rendezvous like POSIX).
    pub readers_seen: bool,
    pub mtime: u64,
    /// user-settable attribute bits (same layout as FAT: 0x01 = readonly);
    /// readonly fifos reject open-for-write, like a file's r-bit
    pub attr: u8,
    /// euid at create — fs.protected_fifos compares openers against it
    pub uid: u32,
    /// readiness-transition epoch: bumped on empty->non-empty writes and
    /// on 0<->non0 reader/writer transitions — epoll ET edges key off it
    /// (a drain+refill between polls is a real edge Linux hooks via wait
    /// queues; a monotonically-advanced epoch detects the same thing).
    pub rise_gen: u64,
}

static PIPES: Mutex<BTreeMap<String, Pipe>> = Mutex::new(BTreeMap::new());

pub fn handles(path: &str) -> bool {
    if path == "/pipes" || path.starts_with("/pipes/") {
        return true;
    }
    PIPES.lock().contains_key(path) // mkfifo'd pipes at arbitrary paths
}

pub fn is_dir(path: &str) -> bool {
    path == "/pipes"
}

/// mkfifo: create a pipe object at an arbitrary canonical path.
pub fn mkfifo(path: &str) -> Result<(), i64> {
    create(path)
}

static ANON_NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// pipe(2): mint an unnamed pipe under a hidden /pipes/ name. The entry
/// exists (handles() claims it) but is filtered out of /pipes listings.
pub fn create_anon() -> Result<String, i64> {
    let n = ANON_NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let path = alloc::format!("/pipes/.anon{}", n);
    create(&path)?;
    Ok(path)
}

/// readiness-transition epoch for epoll ET (0 when the pipe is gone —
/// never equal to a live pipe's gen, which starts at 1 after its first
/// transition... it starts at 0 too but a dead pipe answers Eof anyway).
pub fn rise_gen(path: &str) -> u64 {
    PIPES.lock().get(path).map(|p| p.rise_gen).unwrap_or(0)
}

/// poll(2) readiness: read is ready when data is queued OR all writers are
/// gone (EOF counts as readable); write is ready while space remains OR no
/// readers remain (a write would EPIPE — still "ready").
pub fn ready(path: &str, for_read: bool) -> bool {
    let g = PIPES.lock();
    match g.get(path) {
        Some(p) => {
            if for_read {
                !p.buf.is_empty() || p.writers == 0
            } else {
                p.buf.len() < pipe_cap() || p.readers == 0
            }
        }
        // missing pipe: reads hit EOF, writes hit EPIPE — both "ready"
        None => true,
    }
}

/// poll()-style revents for a pipe/fifo: bit0=read-ready, bit1=write-
/// ready, 0x8=POLLERR (EPIPE — no readers), 0x10=POLLHUP (no writers ->
/// EOF on the read end).
pub fn poll_revents(path: &str) -> u32 {
    let g = PIPES.lock();
    match g.get(path) {
        Some(p) => {
            let mut rv = 0u32;
            if !p.buf.is_empty() {
                rv |= 1;
            }
            if p.writers == 0 {
                rv |= 1 | 0x10; // EOF: read end is "ready" + HUP (Linux POLLPRI? no: POLLIN|POLLHUP)
            }
            if p.readers == 0 && p.readers_seen {
                rv |= 0x8; // write end -> EPIPE -> POLLERR
            } else if p.buf.len() < pipe_cap() {
                rv |= 2;
            }
            rv
        }
        // missing pipe object: read end would hit EOF
        None => 1 | 0x10,
    }
}

pub fn exists(path: &str) -> bool {
    path != "/pipes" && PIPES.lock().contains_key(path)
}

/// create a new pipe (mkfifo or O_CREATE on a /pipes/ name); fails if one
/// already exists or the path isn't absolute
pub fn create(path: &str) -> Result<(), i64> {
    if path == "/pipes" || !path.starts_with('/') {
        return Err(-4);
    }
    let mut g = PIPES.lock();
    if g.contains_key(path) {
        return Err(-5); // EEXIST
    }
    g.insert(
        String::from(path),
        Pipe { buf: VecDeque::new(), writers: 0, readers: 0, readers_seen: false, mtime: crate::vfs::now_unix(), attr: 0, uid: crate::task::cred().0, rise_gen: 0 },
    );
    Ok(())
}

/// fs.protected_fifos: an open of a fifo in a sticky, world-writable dir
/// is denied unless the opener owns the fifo, owns the dir, is root, or
/// holds CAP_FOWNER. v=1 gates O_WRONLY opens only, v=2 reads too.
pub fn open_denied(path: &str, writer: bool) -> bool {
    let v = crate::sysctl::protected_fifos();
    if v == 0 || (v == 1 && !writer) {
        return false;
    }
    let (eu, _eg) = crate::task::cred();
    if eu == 0 || crate::task::capable_ns_dac(crate::task::CAP_FOWNER) {
        return false;
    }
    let Some(owner) = PIPES.lock().get(path).map(|p| p.uid) else {
        return false;
    };
    let parent = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => return false,
    };
    let Some((is_dir, mode, duid)) = crate::tmpfs::dir_meta(parent) else {
        return false;
    };
    is_dir && mode & 0o1000 != 0 && mode & 0o002 != 0 && eu != owner && eu != duid
}

/// current attribute bits on a named pipe (mkfifo -m / chattr on a fifo)
pub fn attr(path: &str) -> u8 {
    PIPES.lock().get(path).map(|p| p.attr).unwrap_or(0)
}

/// setattr on a named pipe — ENOENT when the path isn't a live pipe object
pub fn set_attr(path: &str, attr: u8) -> Result<(), i64> {
    match PIPES.lock().get_mut(path) {
        Some(p) => {
            p.attr = attr;
            Ok(())
        }
        None => Err(-2),
    }
}

/// open-role accounting: writer iff O_TRUNC|O_APPEND was requested
pub fn open_role(path: &str, writer: bool) {
    if let Some(p) = PIPES.lock().get_mut(path) {
        if writer {
            p.writers += 1;
            if p.writers == 1 {
                p.rise_gen += 1; // first writer: EOF -> blocked transition
            }
        } else {
            p.readers += 1;
            p.readers_seen = true;
            if p.readers == 1 {
                p.rise_gen += 1; // first reader: EPIPE -> writable
            }
        }
    }
}

/// close-role accounting; drops the pipe when fully unreferenced AND empty
pub fn close_role(path: &str, writer: bool) {
    let mut g = PIPES.lock();
    let drop_it = match g.get_mut(path) {
        Some(p) => {
            if writer && p.writers > 0 {
                p.writers -= 1;
                if p.writers == 0 {
                    p.rise_gen += 1; // EOF edge
                }
            } else if !writer && p.readers > 0 {
                p.readers -= 1;
                if p.readers == 0 {
                    p.rise_gen += 1; // EPIPE edge for writers
                }
            }
            // only anonymous pipe() objects self-destruct on last close; a
            // mkfifo'd name is a persistent fs object until unlinked
            let anon = path.rsplit('/').next().map(|b| b.starts_with('.')).unwrap_or(false);
            anon && p.writers == 0 && p.readers == 0 && p.buf.is_empty()
        }
        None => false,
    };
    if drop_it {
        g.remove(path);
    }
}

pub enum TryRead {
    Data(usize),
    Eof,
    WouldBlock,
}

/// nonblocking pop: Data when bytes were available, Eof when the last
/// writer is gone and the queue drained, WouldBlock while a writer is
/// still attached but hasn't produced yet.
pub fn try_read(path: &str, buf: &mut [u8]) -> TryRead {
    let mut g = PIPES.lock();
    let Some(p) = g.get_mut(path) else { return TryRead::Eof };
    if !p.buf.is_empty() {
        let n = buf.len().min(p.buf.len());
        for i in 0..n {
            buf[i] = p.buf.pop_front().unwrap_or(0);
        }
        p.mtime = crate::vfs::now_unix();
        return TryRead::Data(n);
    }
    if p.writers == 0 {
        return TryRead::Eof;
    }
    TryRead::WouldBlock
}

/// nonblocking push: Err(-32)=EPIPE (no read end anywhere — POSIX also
/// raises SIGPIPE in the writer), Err(-11)=EAGAIN (full, a reader may
/// drain it -- caller re-blocks).
pub fn try_write(path: &str, data: &[u8]) -> Result<i64, i64> {
    let mut g = PIPES.lock();
    let Some(p) = g.get_mut(path) else { return Err(-2) };
    if p.readers == 0 && p.readers_seen {
        return Err(-32);
    }
    let space = pipe_cap().saturating_sub(p.buf.len());
    if space == 0 {
        return Err(-11);
    }
    let n = space.min(data.len());
    let was_empty = p.buf.is_empty();
    p.buf.extend(&data[..n]);
    if was_empty {
        p.rise_gen += 1; // not-ready -> readable edge
    }
    p.mtime = crate::vfs::now_unix();
    Ok(n as i64)
}

pub fn remove(path: &str) -> Result<(), i64> {
    if PIPES.lock().remove(path).is_some() {
        Ok(())
    } else {
        Err(-2)
    }
}

/// tee: duplicate up to `len` queued bytes from `from` into `to`
/// without consuming the source (POSIX tee()). Returns the moved count.
pub fn tee(from: &str, to: &str, len: usize) -> Result<u64, i64> {
    let mut g = PIPES.lock();
    let Some(src) = g.get(from) else { return Err(-22) };
    let take = src.buf.iter().take(len).copied().collect::<Vec<u8>>();
    let Some(dst) = g.get_mut(to) else { return Err(-22) };
    let space = pipe_cap().saturating_sub(dst.buf.len());
    let n = take.len().min(space);
    let was_empty = dst.buf.is_empty();
    dst.buf.extend(&take[..n]);
    if was_empty {
        dst.rise_gen += 1;
    }
    dst.mtime = crate::vfs::now_unix();
    Ok(n as u64)
}

/// (size=queued bytes, mtime)
pub fn stat(path: &str) -> Option<(u64, u64)> {
    PIPES.lock().get(path).map(|p| (p.buf.len() as u64, p.mtime))
}

/// live pipe listing for `ls /pipes`
pub fn entries() -> Vec<shared::DirEntry> {
    let g = PIPES.lock();
    let mut out = Vec::new();
    for (name, p) in g.iter() {
        let base = name.rsplit('/').next().unwrap_or(name);
        if base.starts_with('.') {
            continue; // hidden anonymous pipes
        }
        let mut de = shared::DirEntry::default();
        let nb = base.as_bytes();
        let l = nb.len().min(95);
        de.name[..l].copy_from_slice(&nb[..l]);
        de.name_len = l as u8;
        de.is_dir = 0;
        de.size = p.buf.len() as u64;
        de.mtime = p.mtime;
        de.attr = 0x20; // archive bit: visible-but-transient object
        out.push(de);
    }
    out
}
