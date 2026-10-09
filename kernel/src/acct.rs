//! BSD-style process accounting (acct(2)): SYS_ACCT arms a file and every
//! task exit appends one fixed-size record to it. Records are buffered
//! while SCHED is held and flushed at the head of the next syscall
//! dispatch — the FS lock is never taken inside the scheduler lock.

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

/// 64-byte acct record (acct_v3-flavoured):
/// [0..16)  comm, NUL-padded
/// [16..20) exit code (u32 LE)
/// [20..24) uid, [24..28) gid
/// [28..36) cpu ticks used (PIT)
/// [36..44) wall-clock tick at exit
/// [44..64) reserved
pub const REC_LEN: usize = 64;
const PENDING_MAX: usize = 256;

struct Acct {
    path: Option<String>,
    pending: Vec<[u8; REC_LEN]>,
}

static ACCT: Mutex<Acct> = Mutex::new(Acct {
    path: None,
    pending: Vec::new(),
});

/// SYS_ACCT(path | NULL): arm or disarm accounting. CAP_SYS_ADMIN.
/// Returns 0 or -1 EPERM.
pub fn sys_acct(path: Option<String>) -> i64 {
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return -1;
    }
    ACCT.lock().path = path;
    0
}

/// Whether accounting is armed (for /proc or tests).
pub fn armed() -> Option<String> {
    ACCT.lock().path.clone()
}

/// Called from task::kill_at with SCHED already held — only buffers,
/// never touches the FS. Oldest records drop past PENDING_MAX rather
/// than ever blocking the exit path.
pub fn on_exit(name: &str, code: i64, cpu_ticks: u64, uid: u32, gid: u32) {
    let mut a = ACCT.lock();
    if a.path.is_none() {
        return;
    }
    let mut r = [0u8; REC_LEN];
    let nb = name.as_bytes();
    r[..nb.len().min(16)].copy_from_slice(&nb[..nb.len().min(16)]);
    r[16..20].copy_from_slice(&(code as u32).to_le_bytes());
    r[20..24].copy_from_slice(&uid.to_le_bytes());
    r[24..28].copy_from_slice(&gid.to_le_bytes());
    r[28..36].copy_from_slice(&cpu_ticks.to_le_bytes());
    r[36..44].copy_from_slice(&crate::timer::ticks().to_le_bytes());
    if a.pending.len() >= PENDING_MAX {
        a.pending.remove(0);
    }
    a.pending.push(r);
}

/// Drain pending records to the armed file. Called at the head of
/// syscall dispatch where no kernel lock is held.
pub fn flush() {
    let (path, recs) = {
        let mut a = ACCT.lock();
        if a.pending.is_empty() {
            return;
        }
        match &a.path {
            Some(p) => (p.clone(), core::mem::take(&mut a.pending)),
            None => return,
        }
    };
    let mut buf = Vec::with_capacity(recs.len() * REC_LEN);
    for r in &recs {
        buf.extend_from_slice(r);
    }
    let off = crate::vfs::stat_path(&path)
        .map(|st| st.size)
        .unwrap_or(0);
    let _ = crate::vfs::write_range_path(&path, off, &buf);
}
