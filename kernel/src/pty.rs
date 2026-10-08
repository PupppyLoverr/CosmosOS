//! Kernel pseudo-terminal pairs. `SYS_OPENPT` makes a `/ptym/{id}` master
//! fd plus a `/dev/pts/{id}` slave node anyone may `open()`. Master writes
//! feed the slave's input queue through a minimal line discipline
//! (canonical mode: line buffering + erase + echo; raw mode: bytes
//! straight through). Slave writes are readable on the master. Master
//! close destroys the pair (slave reads see EIO); slave fds are
//! refcounted so the master sees EIO once the last slave is gone — the
//! real Linux semantics, not an EOF sugar.
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

const CAP: usize = 8192;

#[derive(Default)]
struct Pty {
    /// number of live master-side descs (openpt fd + dups)
    master_open: u32,
    slave_open: u32,
    canon: bool,
    echo: bool,
    /// foreground process group for job control (0 = unset)
    fg_pgid: u32,
    /// TOSTOP: background slave writes raise SIGTTOU
    tostop: bool,
    /// canonical line being assembled from master input
    partial: Vec<u8>,
    /// master->slave cooked input, readable by the slave
    m2s: VecDeque<u8>,
    /// slave->master output, readable by the master
    s2m: VecDeque<u8>,
}

static PTS: Mutex<BTreeMap<u64, Pty>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

fn id_of(path: &str) -> Option<u64> {
    if let Some(s) = path.strip_prefix("/ptym/") {
        return s.parse().ok();
    }
    path.strip_prefix("/dev/pts/")?.parse().ok()
}

fn is_slave(path: &str) -> bool {
    path.strip_prefix("/dev/pts/")
        .map(|s| s.parse::<u64>().is_ok())
        .unwrap_or(false)
}

fn is_master(path: &str) -> bool {
    path.strip_prefix("/ptym/")
        .map(|s| s.parse::<u64>().is_ok())
        .unwrap_or(false)
}

pub fn handles(path: &str) -> bool {
    is_slave(path) || is_master(path)
}

/// `posix_openpt`: create a pair, return the master path. The slave node is
/// `/dev/pts/{id}` — named in the Pty as created and openable at once
/// (grantpt+unlockpt semantics folded in, matching the rest of our flat fs).
pub fn create() -> String {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    PTS.lock().insert(
        id,
        Pty {
            master_open: 1,
            canon: true,
            echo: true,
            ..Default::default()
        },
    );
    format!("/ptym/{}", id)
}

/// Slave node name for a master path (or the path itself if already slave).
pub fn slave_path(master: &str) -> Option<String> {
    let id = master.strip_prefix("/ptym/")?.parse::<u64>().ok()?;
    PTS.lock().contains_key(&id).then(|| format!("/dev/pts/{}", id))
}

pub fn exists(path: &str) -> bool {
    id_of(path)
        .map(|id| PTS.lock().contains_key(&id))
        .unwrap_or(false)
}

/// Every new desc bumps its side's count — dup'd masters keep the pair
/// alive like Linux's inode refcount.
pub fn acquire(path: &str) {
    if let Some(id) = id_of(path) {
        if let Some(p) = PTS.lock().get_mut(&id) {
            if is_master(path) {
                p.master_open += 1;
            } else {
                p.slave_open += 1;
            }
        }
    }
}

/// Per-desc release: the last master desc destroys the pair outright
/// (POSIX: slave then gets EIO, not EOF). Destruction also queues a
/// hangup — SIGHUP goes to the session that had this pty as its
/// controlling terminal, delivered by drain_hups on the next syscall
/// (release can run under SCHED during task teardown, so signaling
/// here could self-deadlock).
pub fn release(path: &str) {
    let Some(id) = id_of(path) else { return };
    let mut g = PTS.lock();
    let destroy = g.get_mut(&id).map(|p| {
        if is_master(path) {
            p.master_open = p.master_open.saturating_sub(1);
            p.master_open == 0
        } else {
            p.slave_open = p.slave_open.saturating_sub(1);
            false
        }
    });
    if destroy.unwrap_or(false) {
        g.remove(&id);
        HUP_PENDING.lock().push(id);
    }
}

static HUP_PENDING: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// Deliver queued terminal hangups: SIGHUP to every live task holding
/// the destroyed pty as its controlling terminal. Called at the top of
/// syscall dispatch where the scheduler lock is not held.
pub fn drain_hups() {
    let ids: Vec<u64> = {
        let mut g = HUP_PENDING.lock();
        core::mem::take(&mut *g)
    };
    for id in ids {
        crate::task::signal_ctty(id, 1);
    }
}

/// termios-lite flags: bit0 canonical, bit1 echo.
pub fn tcget(path: &str) -> i64 {
    let Some(id) = id_of(path) else { return -1 };
    let g = PTS.lock();
    g.get(&id)
        .map(|p| {
            (p.canon as i64) | ((p.echo as i64) << 1) | ((p.tostop as i64) << 2)
        })
        .unwrap_or(-19) // ENODEV
}

pub fn tcset(path: &str, flags: u64) -> i64 {
    let Some(id) = id_of(path) else { return -1 };
    let mut g = PTS.lock();
    match g.get_mut(&id) {
        Some(p) => {
            p.canon = flags & 1 != 0;
            p.echo = flags & 2 != 0;
            p.tostop = flags & 4 != 0;
            if !p.canon {
                // leftover cooked line becomes readable input in raw mode
                while let Some(b) = p.partial.pop() {
                    p.m2s.push_front(b);
                }
            }
            0
        }
        None => -19,
    }
}

/// Foreground pgid reported by `tcgetpgrp`; 0 when unset.
pub fn fg_pgid_of(path: &str) -> i64 {
    let Some(id) = id_of(path) else { return -1 };
    let g = PTS.lock();
    g.get(&id).map(|p| p.fg_pgid as i64).unwrap_or(-19)
}

/// tcsetpgrp: make `pgid` the pty's foreground group. 0 clears.
pub fn set_fg_pgid(path: &str, pgid: u32) -> i64 {
    let Some(id) = id_of(path) else { return -1 };
    let mut g = PTS.lock();
    match g.get_mut(&id) {
        Some(p) => {
            p.fg_pgid = pgid;
            0
        }
        None => -19,
    }
}

/// TIOCSTI: push one byte into the pty's input queue — it arrives at slave
/// readers as if it had been typed on the master. Returns -19 unknown fd,
/// -11 when the input queue is full.
pub fn tiocsti(path: &str, byte: u8) -> i64 {
    let Some(id) = id_of(path) else { return -1 };
    let mut g = PTS.lock();
    match g.get_mut(&id) {
        Some(p) => {
            if p.m2s.len() >= CAP {
                -11
            } else {
                p.m2s.push_back(byte);
                0
            }
        }
        None => -19,
    }
}

/// `(caller ctty, caller pgid, caller pid)` for job-control checks, or None
/// for kernel callers.
fn tty_cred() -> Option<(u64, u32, u32)> {
    let c = crate::task::with_current(|t| (t.ctty, t.pgid, t.id));
    if c.2 == 0 {
        None
    } else {
        Some(c)
    }
}

/// True when `id` is the caller's controlling tty and the caller is NOT in
/// the pty's foreground group — reads must stop it with SIGTTIN (and writes
/// with SIGTTOU when TOSTOP is on).
fn background(caller_pgid: u32, fg: u32) -> bool {
    fg != 0 && caller_pgid != 0 && caller_pgid != fg
}

/// Non-blocking read. Err(-11) would-block, Err(-5) EIO (peer gone),
/// Err(-19) unknown.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let Some(id) = id_of(path) else { return Err(-19) };
    let mut g = PTS.lock();
    let Some(p) = g.get_mut(&id) else { return Err(-5) }; // pair destroyed
    if is_master(path) {
        if p.s2m.is_empty() {
            return if p.slave_open == 0 { Err(-5) } else { Err(-11) };
        }
        let mut n = 0;
        while n < buf.len() {
            match p.s2m.pop_front() {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        return Ok(n);
    }
    // slave read: cooked input only — but a background job that reads its
    // controlling tty gets SIGTTIN first (POSIX job control).
    let stop = if let Some((ctty, cpid_pgid, me)) = tty_cred() {
        if ctty == id && background(cpid_pgid, p.fg_pgid) {
            Some(me)
        } else {
            None
        }
    } else {
        None
    };
    if let Some(me) = stop {
        drop(g);
        crate::task::signal(me, 21); // SIGTTIN
        return Err(-11);
    }
    if p.m2s.is_empty() {
        return if p.master_open == 0 { Err(-5) } else { Err(-11) };
    }
    let mut n = 0;
    // canonical: at most one cooked line per read
    if p.canon {
        while n < buf.len() {
            match p.m2s.pop_front() {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                    if b == b'\n' {
                        break;
                    }
                }
                None => break,
            }
        }
    } else {
        while n < buf.len() {
            match p.m2s.pop_front() {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
    }
    Ok(n)
}

/// Non-blocking write. Err(-5) EIO, Err(-11) queue full.
pub fn try_write(path: &str, data: &[u8]) -> Result<usize, i64> {
    let Some(id) = id_of(path) else { return Err(-19) };
    let mut g = PTS.lock();
    let Some(p) = g.get_mut(&id) else { return Err(-5) };
    if is_master(path) {
        // input side: cook through the line discipline
        let mut n = 0;
        for &b in data {
            if p.m2s.len() + p.partial.len() >= CAP {
                break; // short write under backpressure
            }
            n += 1;
            if !p.canon {
                p.m2s.push_back(b);
                continue;
            }
            match b {
                b'\n' => {
                    p.partial.push(b'\n');
                    for &c in &p.partial.clone() {
                        p.m2s.push_back(c);
                    }
                    p.partial.clear();
                    if p.echo {
                        p.s2m.push_back(b'\n');
                    }
                }
                0x7f | 0x08 => {
                    if p.partial.pop().is_some() && p.echo {
                        // erase visually: BS SP BS
                        for &c in &[0x08u8, b' ', 0x08] {
                            if p.s2m.len() < CAP {
                                p.s2m.push_back(c);
                            }
                        }
                    }
                }
                _ => {
                    p.partial.push(b);
                    if p.echo && p.s2m.len() < CAP {
                        p.s2m.push_back(b);
                    }
                }
            }
        }
        return Ok(n);
    }
    // slave write: output straight to the master — TOSTOP mode stops a
    // background writer with SIGTTOU.
    if p.tostop {
        let stop = if let Some((ctty, cpid_pgid, me)) = tty_cred() {
            if ctty == id && background(cpid_pgid, p.fg_pgid) {
                Some(me)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(me) = stop {
            drop(g);
            crate::task::signal(me, 22); // SIGTTOU
            return Err(-11);
        }
    }
    if p.master_open == 0 {
        return Err(-5);
    }
    let mut n = 0;
    for &b in data {
        if p.s2m.len() >= CAP {
            break;
        }
        p.s2m.push_back(b);
        n += 1;
    }
    if n == 0 && !data.is_empty() {
        return Err(-11);
    }
    Ok(n)
}

/// Poll readiness: master read = output pending or slave gone; slave read =
/// cooked input pending or master gone. Write side reports ready unless the
/// matching queue is full or the peer is gone.
pub fn ready(path: &str, for_read: bool) -> bool {
    let Some(id) = id_of(path) else { return false };
    let g = PTS.lock();
    let Some(p) = g.get(&id) else { return false };
    if for_read {
        if is_master(path) {
            !p.s2m.is_empty() || p.slave_open == 0
        } else {
            !p.m2s.is_empty() || p.master_open == 0
        }
    } else if is_master(path) {
        p.m2s.len() + p.partial.len() < CAP
    } else {
        p.master_open > 0 && p.s2m.len() < CAP
    }
}
