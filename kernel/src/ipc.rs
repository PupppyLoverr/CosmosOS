//! Named IPC ports: unidirectional message queues between tasks.
//! A task listens on a name ("cosmos:win"); clients connect by name and send
//! messages; replies go to a reply-port id passed inside the message.
use crate::task::{State, Task, SCHED};
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub const MAX_MSG: usize = 8192;
pub const MAX_QUEUE: usize = 128;

pub struct Port {
    pub id: u32,
    pub owner: u32, // task id
    pub queue: VecDeque<Vec<u8>>,
}

pub struct Ipc {
    pub ports: BTreeMap<u32, Port>,
    pub names: BTreeMap<String, u32>,
    pub next_id: u32,
}

pub static IPC: Mutex<Option<Ipc>> = Mutex::new(None);

pub fn init() {
    *IPC.lock() = Some(Ipc { ports: BTreeMap::new(), names: BTreeMap::new(), next_id: 1 });
}

fn with<R>(f: impl FnOnce(&mut Ipc) -> R) -> Option<R> {
    IPC.lock().as_mut().map(f)
}

/// Listen on `name` ("" for anonymous). Returns port id.
pub fn listen(name: &str, owner: u32) -> u32 {
    with(|i| {
        let id = i.next_id;
        i.next_id += 1;
        i.ports.insert(id, Port { id, owner, queue: VecDeque::new() });
        if !name.is_empty() {
            i.names.insert(String::from(name), id);
        }
        id
    })
    .unwrap_or(0)
}

/// Resolve a name to a port id.
pub fn connect(name: &str) -> Option<u32> {
    with(|i| i.names.get(name).copied()).flatten()
}

/// Who owns a port (for permission checks).
pub fn owner_of(port: u32) -> Option<u32> {
    with(|i| i.ports.get(&port).map(|p| p.owner)).flatten()
}

/// Push a message onto `port`'s queue and wake a blocked owner.
pub fn send(port: u32, bytes: &[u8]) -> Result<(), i64> {
    if bytes.len() > MAX_MSG {
        return Err(-2);
    }
    let owner = with(|i| match i.ports.get_mut(&port) {
        Some(p) => {
            if p.queue.len() >= MAX_QUEUE {
                return Err(-3);
            }
            p.queue.push_back(Vec::from(bytes));
            Ok(p.owner)
        }
        None => Err(-1),
    })
    .unwrap_or(Err(-1))?;
    // wake owner if it's blocked on this port (best-effort; avoid deadlock with try_lock)
    if let Some(g) = SCHED.try_lock().as_mut().and_then(|s| s.as_mut()) {
        for t in g.tasks.iter_mut() {
            if t.id == owner && t.state == State::Blocked && t.wait_port == port {
                t.state = State::Running;
                t.wait_port = 0;
            }
        }
    }
    Ok(())
}

/// Non-blocking pop from own port queue.
pub fn try_recv(port: u32, owner: u32) -> Option<Vec<u8>> {
    with(|i| match i.ports.get_mut(&port) {
        Some(p) if p.owner == owner => p.queue.pop_front(),
        _ => None,
    })
    .flatten()
}

/// Does `port` have a message queued (and is owned by `owner`)?
pub fn has_msg(port: u32, owner: u32) -> bool {
    with(|i| i.ports.get(&port).map(|p| p.owner == owner && !p.queue.is_empty()).unwrap_or(false))
        .unwrap_or(false)
}

/// Close a single port (must be owner).
pub fn close(port: u32, owner: u32) {
    with(|i| {
        if let Some(p) = i.ports.get(&port) {
            if p.owner == owner {
                i.ports.remove(&port);
                i.names.retain(|_, &mut v| v != port);
            }
        }
    });
}

/// Called at task teardown: drop every port it owns.
pub fn close_task_ports(t: &mut Task) {
    for p in core::mem::take(&mut t.ports) {
        close(p, t.id);
    }
}

/// Timer-tick helper: a blocked receiver wakes when its port has a message.
/// Called with SCHED already held — uses try_lock to avoid deadlock.
pub fn wake_receivers(s: &mut crate::task::Sched) {
    let mut guard = IPC.try_lock();
    let Some(i) = guard.as_mut().and_then(|x| x.as_mut()) else {
        return;
    };
    for t in s.tasks.iter_mut() {
        if t.state == State::Blocked && t.wait_port != 0 {
            if let Some(p) = i.ports.get(&t.wait_port) {
                if p.owner == t.id && !p.queue.is_empty() {
                    t.state = State::Running;
                    t.wait_port = 0;
                }
            } else {
                // port gone
                t.state = State::Running;
                t.wait_port = 0;
            }
        }
    }
}

/// Push to a named service if it exists (used by kernel input pump).
pub fn push_named(name: &str, bytes: &[u8]) -> Result<(), i64> {
    match connect(name) {
        Some(pid) => send(pid, bytes),
        None => Err(-4),
    }
}
