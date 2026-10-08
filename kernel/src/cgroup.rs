//! cgroups-lite: a real control-group filesystem at /sys/fs/cgroup.
//!
//! Each `mkdir` under the root creates a real named group. Tasks join
//! by writing a pid to `cgroup.procs` (fork inherits membership, like
//! Linux). `cpu.stat` and `memory.current` are live views over member
//! tasks; `cpu.max` is enforced in the scheduler's pick loop: a group
//! whose members consumed their quota in the current 1s window is
//! simply not picked until the window rolls.

use crate::task;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub const ROOT: &str = "/sys/fs/cgroup";

/// One control group. `quota` is allowed runnable ticks per 100-tick
/// window (1 second); u64::MAX means `max` (uncapped).
pub struct CGroup {
    pub id: u64,
    pub name: String,
    pub members: Vec<u32>,
    pub quota: u64,
    /// ticks charged inside the current window
    pub used: u64,
    /// window serial (ticks()/100) the charge belongs to
    pub win: u64,
    /// windows where the group ran out of quota — nr_throttled
    pub throttled_windows: u64,
    /// ticks spent past the quota boundary — throttled_usec/10ms
    pub throttled_ticks: u64,
}

static CG: Mutex<BTreeMap<u64, CGroup>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Window length in PIT ticks: 100 ticks = 1s.
const WIN_TICKS: u64 = 100;

fn win_now() -> u64 {
    task::ticks() / WIN_TICKS
}

// ---- scheduler hooks (called with SCHED held; only ever take CG) ----

/// Charge one runnable tick to the outgoing task's cgroup.
pub fn charge(cg: u64) {
    if cg == 0 {
        return;
    }
    let mut g = CG.lock();
    let Some(c) = g.get_mut(&cg) else { return };
    let w = win_now();
    if c.win != w {
        c.win = w;
        c.used = 0;
    }
    c.used += 1;
    if c.used == c.quota + 1 {
        c.throttled_windows += 1;
    }
    if c.used > c.quota {
        c.throttled_ticks += 1;
    }
}

/// Whether the cgroup burned its quota this window — pick() skips
/// throttled members, so they can never exceed cpu.max.
pub fn throttled(cg: u64) -> bool {
    if cg == 0 {
        return false;
    }
    CG.lock()
        .get(&cg)
        .map(|c| c.win == win_now() && c.used > c.quota)
        .unwrap_or(false)
}

// ---- membership ----

/// Move `pid` into cgroup `id` (0 = root). Returns errno on failure.
pub fn move_task(pid: u32, id: u64) -> i64 {
    if !task::pids().contains(&pid) {
        return -3; // ESRCH
    }
    if id != 0 && !CG.lock().contains_key(&id) {
        return -2; // ENOENT
    }
    let old = task::with_pid_mut(pid, |t| {
        let o = t.cgroup;
        t.cgroup = id;
        o as i64
    });
    if old < 0 {
        return old;
    }
    let old = old as u64;
    if old == id {
        return 0;
    }
    if old != 0 {
        if let Some(c) = CG.lock().get_mut(&old) {
            c.members.retain(|&m| m != pid);
        }
    }
    if id != 0 {
        if let Some(c) = CG.lock().get_mut(&id) {
            if !c.members.contains(&pid) {
                c.members.push(pid);
            }
        }
    }
    0
}

/// Remove `pid` from whatever group it is in (called on task death).
pub fn drop_task(pid: u32, cg: u64) {
    if cg == 0 {
        return;
    }
    if let Some(c) = CG.lock().get_mut(&cg) {
        c.members.retain(|&m| m != pid);
    }
}

// ---- the virtual filesystem ----

pub fn handles(path: &str) -> bool {
    path == ROOT || path.starts_with("/sys/fs/cgroup/")
}

/// files present in every cgroup dir (and the root)
const FILES: &[&str] = &[
    "cgroup.procs",
    "cgroup.controllers",
    "cgroup.events",
    "cgroup.type",
    "cpu.stat",
    "cpu.max",
    "memory.current",
];

pub fn is_dir(path: &str) -> bool {
    if path == ROOT {
        return true;
    }
    let rest = match path.strip_prefix("/sys/fs/cgroup/") {
        Some(r) => r,
        None => return false,
    };
    let mut it = rest.split('/');
    let gname = it.next().unwrap_or("");
    match it.next() {
        // /sys/fs/cgroup/<name>
        None => CG.lock().values().any(|c| c.name == gname),
        // /sys/fs/cgroup/<name>/<file> — never a dir
        Some(_) => false,
    }
}

pub fn exists(path: &str) -> bool {
    if path == ROOT || is_dir(path) {
        return true;
    }
    let rest = match path.strip_prefix("/sys/fs/cgroup/") {
        Some(r) => r,
        None => return false,
    };
    // root-level files: /sys/fs/cgroup/<file>
    if !rest.contains('/') {
        return FILES.contains(&rest);
    }
    // /sys/fs/cgroup/<group>/<file>
    let mut it = rest.split('/');
    let (gname, file) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    it.next().is_none() && FILES.contains(&file)
        && CG.lock().values().any(|c| c.name == gname)
}

pub fn entries(path: &str) -> Vec<shared::DirEntry> {
    let mut out = Vec::new();
    let is_root = path == ROOT;
    let names: Vec<String> = if is_root {
        let mut v: Vec<String> = FILES.iter().map(|s| String::from(*s)).collect();
        for c in CG.lock().values() {
            v.push(c.name.clone());
        }
        v
    } else if is_dir(path) {
        FILES.iter().map(|s| String::from(*s)).collect()
    } else {
        Vec::new()
    };
    let group_names: Vec<String> = if is_root {
        CG.lock().values().map(|c| c.name.clone()).collect()
    } else {
        Vec::new()
    };
    for n in names {
        let mut de = shared::DirEntry::default();
        let b = n.as_bytes();
        let l = b.len().min(95);
        de.name[..l].copy_from_slice(&b[..l]);
        de.is_dir = group_names.contains(&n) as u8;
        de.size = if de.is_dir == 1 {
            0
        } else {
            read_file(&alloc::format!("{}/{}", path, n))
                .map(|d| d.len() as u64)
                .unwrap_or(0)
        };
        out.push(de);
    }
    out
}

fn group_id_by_name(name: &str) -> Option<u64> {
    CG.lock()
        .values()
        .find(|c| c.name == name)
        .map(|c| c.id)
}

/// File contents. Root's cgroup.procs lists every live pid; a group's
/// lists its members. cpu.stat is real: usage_usec derives from member
/// cpu_ticks; nr_throttled/throttled_usec count quota exhaustions.
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    if is_dir(path) || !exists(path) {
        return None;
    }
    let rest = path.strip_prefix("/sys/fs/cgroup/")?;
    let (gname, file) = if rest.contains('/') {
        let mut it = rest.splitn(2, '/');
        (Some(it.next().unwrap_or("")), it.next().unwrap_or(""))
    } else {
        (None, rest)
    };
    let gid = gname.and_then(group_id_by_name).unwrap_or(0);
    let members: Vec<u32> = if gid == 0 {
        task::pids()
    } else {
        CG.lock().get(&gid).map(|c| c.members.clone()).unwrap_or_default()
    };
    let text = match file {
        "cgroup.procs" => members
            .iter()
            .map(|p| alloc::format!("{}\n", p))
            .collect::<String>(),
        "cgroup.controllers" => String::from("cpu memory\n"),
        "cgroup.events" => alloc::format!("populated {}\n", !members.is_empty() as u32),
        "cgroup.type" => String::from("domain\n"),
        "cpu.stat" => {
            let (usage, nrt, thrt) = if gid == 0 {
                let t = task::total_cpu_ticks();
                (t * 10_000, 0, 0)
            } else {
                let g = CG.lock();
                let c = g.get(&gid)?;
                let ticks: u64 = c
                    .members
                    .iter()
                    .map(|&p| task::cpu_ticks_of(p).unwrap_or(0))
                    .sum();
                (ticks * 10_000, c.throttled_windows, c.throttled_ticks * 10_000)
            };
            alloc::format!(
                "usage_usec {}\nnr_periods {}\nnr_throttled {}\nthrottled_usec {}\n",
                usage,
                task::ticks() / WIN_TICKS,
                nrt,
                thrt
            )
        }
        "cpu.max" => {
            let q = if gid == 0 {
                u64::MAX
            } else {
                CG.lock().get(&gid).map(|c| c.quota).unwrap_or(u64::MAX)
            };
            if q == u64::MAX {
                String::from("max 1000000\n")
            } else {
                // usecs over a 1s period (1 tick = 10ms = 10000us)
                alloc::format!("{} 1000000\n", q * 10_000)
            }
        }
        "memory.current" => {
            let bytes: u64 = members
                .iter()
                .map(|&p| task::pid_faults(p).map(|f| f.2 * 4096).unwrap_or(0))
                .sum();
            alloc::format!("{}\n", bytes)
        }
        _ => return None,
    };
    Some(text.into_bytes())
}

/// Writes: `echo <pid> > cgroup.procs` moves a task (real);
/// `echo "<quota_us> <period_us>"` or `max` > cpu.max sets the throttle.
pub fn write_file(path: &str, buf: &[u8]) -> Option<usize> {
    if !exists(path) || is_dir(path) {
        return None;
    }
    let rest = path.strip_prefix("/sys/fs/cgroup/")?;
    let (gname, file) = if rest.contains('/') {
        let mut it = rest.splitn(2, '/');
        (Some(it.next().unwrap_or("")), it.next().unwrap_or(""))
    } else {
        (None, rest)
    };
    let gid = gname.and_then(group_id_by_name).unwrap_or(0);
    if gname.is_some() && gid == 0 {
        return None; // group gone
    }
    let text = String::from(String::from_utf8_lossy(buf).trim());
    match file {
        "cgroup.procs" => {
            let pid: u32 = text.parse().ok()?;
            (move_task(pid, gid) == 0).then_some(buf.len())
        }
        "cpu.max" => {
            if gid == 0 {
                return None; // root has no quota
            }
            let q = if text == "max" {
                u64::MAX
            } else {
                // "<quota_us> <period_us>" → ticks per 100-tick window
                // (1 tick = 10ms = 10000us)
                let first = text.split_whitespace().next()?;
                first.parse::<u64>().ok()? / 10_000
            };
            CG.lock().get_mut(&gid).map(|c| c.quota = q)?;
            Some(buf.len())
        }
        _ => None,
    }
}

/// mkdir /sys/fs/cgroup/<name> — a real group (flat layout: only the
/// root may hold groups, a single-level v2 tree).
pub fn mkdir(path: &str) -> Result<(), i64> {
    let rest = path.strip_prefix("/sys/fs/cgroup/").ok_or(-4i64)?;
    if rest.is_empty() || rest.contains('/') {
        return Err(-4);
    }
    if CG.lock().values().any(|c| c.name == rest) {
        return Err(-17); // EEXIST
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    CG.lock().insert(
        id,
        CGroup {
            id,
            name: String::from(rest),
            members: Vec::new(),
            quota: u64::MAX,
            used: 0,
            win: win_now(),
            throttled_windows: 0,
            throttled_ticks: 0,
        },
    );
    Ok(())
}

/// rmdir /sys/fs/cgroup/<name>: members fall back to the root group.
pub fn remove(path: &str) -> Result<(), i64> {
    let rest = path.strip_prefix("/sys/fs/cgroup/").ok_or(-4i64)?;
    if rest.contains('/') || rest.is_empty() {
        return Err(-4);
    }
    let Some(id) = group_id_by_name(rest) else {
        return Err(-2); // ENOENT
    };
    let members = CG.lock().remove(&id).map(|c| c.members).unwrap_or_default();
    for pid in members {
        task::with_pid_mut(pid, |t| {
            t.cgroup = 0;
            0
        });
    }
    Ok(())
}
