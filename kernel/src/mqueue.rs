//! POSIX message queues: `SYS_MQ_OPEN` names a queue (`mq_open`), mints a
//! `/mqueue/{id}` fd; `SYS_MQ_SEND`/`SYS_MQ_RECV` move whole messages with a
//! priority (highest first, FIFO within a priority — POSIX ordering).
//! Queues are named kernel objects: they persist across task death and
//! survive until `SYS_MQ_UNLINK`, matching POSIX mqueue lifetime.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub struct Mq {
    pub maxmsg: usize,
    pub msgsize: usize,
    /// messages sorted by (prio desc, seq asc): front = next to deliver
    msgs: Vec<Msg>,
    open_ct: u64,
}

struct Msg {
    prio: u32,
    seq: u64,
    data: Vec<u8>,
}

static MQS: Mutex<BTreeMap<u64, Mq>> = Mutex::new(BTreeMap::new());
/// queue name -> id (POSIX names persist independently of the id)
static NAMES: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static SEQ: AtomicU64 = AtomicU64::new(1);

pub fn qid_of(path: &str) -> Option<u64> {
    path.strip_prefix("/mqueue/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    qid_of(path).is_some()
}

/// mq_open(name, maxmsg, msgsize): returns the fd path, or EEXIST-ish err.
/// maxmsg/msgsize apply on creation; reopening shares the existing queue.
pub fn open(name: &str, maxmsg: usize, msgsize: usize) -> Result<String, i64> {
    // fs.mqueue.msg_max / fs.mqueue.msgsize_max bound queue geometry.
    if name.is_empty() || name.len() > 64 || maxmsg == 0 || msgsize == 0
        || maxmsg as u64 > crate::sysctl::mq_msg_max()
        || msgsize as u64 > crate::sysctl::mq_msgsize_max()
    {
        return Err(-22); // EINVAL
    }
    // IPC namespacing: the same name in two namespaces maps to
    // different queues — the registry key is (ipc_ns, name).
    let key = alloc::format!("{}:{}", crate::task::cur_ipc_ns(), name);
    let mut names = NAMES.lock();
    let id = match names.get(&key) {
        Some(&id) => id,
        None => {
            // fs.mqueue.queues_max bounds the global queue count.
            if MQS.lock().len() as u64 >= crate::sysctl::mq_queues_max() {
                return Err(-28); // ENOSPC
            }
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            MQS.lock().insert(
                id,
                Mq { maxmsg, msgsize, msgs: Vec::new(), open_ct: 0 },
            );
            names.insert(key, id);
            id
        }
    };
    if let Some(q) = MQS.lock().get_mut(&id) {
        q.open_ct += 1;
    }
    Ok(alloc::format!("/mqueue/{}", id))
}

/// mq_unlink(name): detach the name; the queue dies when its last fd
/// closes (POSIX) — implemented by marking it unlinked.
pub fn unlink(name: &str) -> i64 {
    let key = alloc::format!("{}:{}", crate::task::cur_ipc_ns(), name);
    match NAMES.lock().remove(&key) {
        Some(_) => 0,
        None => -2, // ENOENT
    }
}

/// mq_notify registrations: qid -> (pid, sig). One-shot per POSIX.
static NOTIFY: spin::Mutex<alloc::collections::BTreeMap<u64, (u32, u64)>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());

/// Register (sig>0) or clear (sig==0) the queue's empty->nonempty signal.
pub fn notify_set(qid: u64, pid: u32, sig: u64) {
    let mut g = NOTIFY.lock();
    if sig == 0 {
        g.remove(&qid);
    } else {
        g.insert(qid, (pid, sig));
    }
}

/// mq_send: enqueue (prio,msg) honoring the queue's msgsize cap.
/// Err(-11) = full (blockable); Err(-28) = EMSGSIZE.
/// An empty->nonempty transition fires the registered mq_notify signal.
pub fn send(path: &str, data: &[u8], prio: u32) -> Result<usize, i64> {
    let id = qid_of(path).ok_or(-9i64)?; // EBADF
    let mut g = MQS.lock();
    let q = g.get_mut(&id).ok_or(-9i64)?;
    if data.len() > q.msgsize {
        return Err(-28);
    }
    if q.msgs.len() >= q.maxmsg {
        return Err(-11);
    }
    let m = Msg {
        prio,
        seq: SEQ.fetch_add(1, Ordering::Relaxed),
        data: Vec::from(data),
    };
    // highest prio first; within prio, earlier seq first (FIFO)
    let pos = q
        .msgs
        .iter()
        .position(|o| o.prio < prio || (o.prio == prio && o.seq > m.seq))
        .unwrap_or(q.msgs.len());
    let was_empty = q.msgs.is_empty();
    q.msgs.insert(pos, m);
    if was_empty {
        if let Some((pid, sig)) = NOTIFY.lock().remove(&id) {
            crate::task::signal(pid, sig);
        }
    }
    Ok(data.len())
}

/// mq_receive: pop the front message; *prio_out (if written) gets its
/// priority. Err(-11) = empty (blockable); Err(-28) = buf < msgsize
/// (POSIX requires the buffer to hold a whole message).
pub fn recv(path: &str, buf: &mut [u8]) -> Result<(usize, u32), i64> {
    let id = qid_of(path).ok_or(-9i64)?;
    let mut g = MQS.lock();
    let q = g.get_mut(&id).ok_or(-9i64)?;
    let msgsize = q.msgsize;
    if buf.len() < msgsize {
        return Err(-28);
    }
    match q.msgs.first().map(|m| (m.prio, m.seq)) {
        None => Err(-11),
        Some((prio, _)) => {
            let m = q.msgs.remove(0);
            let n = m.data.len().min(buf.len());
            buf[..n].copy_from_slice(&m.data[..n]);
            Ok((n, prio))
        }
    }
}

/// Whether a queue exists for this fd path (a live, non-closed fd still
/// resolves even after mq_unlink — POSIX keeps the queue alive on the
/// open description; ours keeps it until the last fd releases).
pub fn exists(path: &str) -> bool {
    match qid_of(path) {
        Some(id) => MQS.lock().contains_key(&id),
        None => false,
    }
}

/// poll-readability: nonempty queue
pub fn ready(path: &str) -> bool {
    match qid_of(path) {
        Some(id) => MQS.lock().get(&id).map(|q| !q.msgs.is_empty()).unwrap_or(false),
        None => false,
    }
}

/// Another desc now references this queue (dup/fork/clone) — POSIX
/// open-file-description sharing: the queue lives while any fd is open.
pub fn acquire(path: &str) {
    if let Some(id) = qid_of(path) {
        if let Some(q) = MQS.lock().get_mut(&id) {
            q.open_ct += 1;
        }
    }
}

/// fd released: decrement open count; a queue whose name was unlinked
/// AND whose last fd closed is destroyed (POSIX lifetime).
pub fn release(path: &str) {
    let Some(id) = qid_of(path) else { return };
    let mut names = NAMES.lock();
    let mut g = MQS.lock();
    let Some(q) = g.get_mut(&id) else { return };
    q.open_ct = q.open_ct.saturating_sub(1);
    let named = names.values().any(|&v| v == id);
    if q.open_ct == 0 && !named {
        g.remove(&id);
    }
}
