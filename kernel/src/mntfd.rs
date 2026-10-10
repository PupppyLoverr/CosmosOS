//! Mount-file-descriptor API (the new mount API): `open_tree` clones a
//! subtree into a detached mount record addressed by an fd;
//! `mount_setattr` toggles its MS_* flags; `move_mount` attaches it at
//! a path (a real bind alias). `statmount`/`listmount` introspect the
//! caller namespace's mount set with stable fnv1a ids.

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Clone)]
pub struct MntRec {
    pub id: u64,
    pub source: String,
    pub opts: u64,
    /// Some(target) once move_mount has attached the record.
    pub attached: Option<String>,
}

static REG: Mutex<Vec<MntRec>> = Mutex::new(Vec::new());
static NEXT: Mutex<u64> = Mutex::new(1);

/// Stable mount id for a path — fnv1a-64 over the canonical target.
/// The same function is exposed to userspace via ustd::mnt_id.
pub fn mnt_id(path: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in path.as_bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    if h == 0 {
        1
    } else {
        h
    }
}

pub fn clone_tree(source: &str, opts: u64) -> u64 {
    let mut n = NEXT.lock();
    let id = *n;
    *n += 1;
    REG.lock().push(MntRec {
        id,
        source: String::from(source),
        opts,
        attached: None,
    });
    id
}

/// Look up a mount-fd's record id from its fd path (/mntfd/{id}).
pub fn fd_id(path: &str) -> Option<u64> {
    path.strip_prefix("/mntfd/")?.parse().ok()
}

pub fn get(id: u64) -> Option<MntRec> {
    REG.lock().iter().find(|r| r.id == id).cloned()
}

/// mount_setattr: fold set/clr into the record's opts — a detached
/// record updates itself; an attached one mutates the live bind entry.
pub fn set_opts(id: u64, set: u64, clr: u64) -> Result<(), i64> {
    let mut g = REG.lock();
    let Some(r) = g.iter_mut().find(|r| r.id == id) else {
        return Err(-9); // EBADF
    };
    match &r.attached {
        None => {
            r.opts |= set;
            r.opts &= !clr;
            Ok(())
        }
        Some(t) => {
            let t = t.clone();
            crate::bind::set_opts(&t, set, clr).map(|_| {
                r.opts |= set;
                r.opts &= !clr;
            })
        }
    }
}

/// move_mount attach: the record must be detached; installs it as a
/// bind at `target`, then marks it attached. EBUSY/EINVAL propagate.
pub fn attach(id: u64, target: &str) -> Result<(), i64> {
    let (source, opts) = {
        let g = REG.lock();
        let Some(r) = g.iter().find(|r| r.id == id) else {
            return Err(-9);
        };
        if r.attached.is_some() {
            return Err(-16); // EBUSY: already attached
        }
        (r.source.clone(), r.opts)
    };
    crate::bind::mount(&source, target, opts)?;
    if let Some(r) = REG.lock().iter_mut().find(|r| r.id == id) {
        r.attached = Some(String::from(target));
    }
    Ok(())
}

/// The namespace's live mount set for statmount/listmount:
/// root + tmpfs mounts + binds, each with id/parent/opts/kind.
/// kind: 0 root, 1 tmpfs, 2 bind.
pub fn mount_set() -> Vec<(u64, u64, String, u64, u8)> {
    let mut v: Vec<(u64, u64, String, u64, u8)> = Vec::new();
    let root_id = mnt_id("/");
    v.push((root_id, 0, String::from("/"), 0, 0));
    for (t, opts) in crate::tmpfs::mounts() {
        v.push((mnt_id(&t), parent_of(&t), t, opts, 1));
    }
    for (t, _s, opts) in {
        let ns = crate::task::ns_of();
        let g = ns.lock();
        g.binds.clone()
    } {
        v.push((mnt_id(&t), parent_of(&t), t, opts, 2));
    }
    let _ = root_id;
    v
}

/// Mount id of the mount containing `path`'s strict parent — the
/// longest other mount-target prefix, else the root mount.
fn parent_of(path: &str) -> u64 {
    let ns = crate::task::ns_of();
    let g = ns.lock();
    let mut best = "/";
    for m in g.tmpfs.iter().map(|m| &m.0).chain(g.binds.iter().map(|b| &b.0)) {
        if crate::tmpfs::under(m, path) && *m != path && m.len() > best.len() {
            best = m;
        }
    }
    mnt_id(best)
}
