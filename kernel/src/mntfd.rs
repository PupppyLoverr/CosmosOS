//! Mount-file-descriptor API (the new mount API): `open_tree` clones a
//! subtree into a detached mount record addressed by an fd;
//! `mount_setattr` toggles its MS_* flags; `move_mount` attaches it at
//! a path (a real bind alias). `statmount`/`listmount` introspect the
//! caller namespace's mount set with stable fnv1a ids.

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub const KIND_SUBTREE: u8 = 0; // open_tree clone → attaches as a bind alias
pub const KIND_TMPFS: u8 = 1; // fsmount product → attaches as a real tmpfs super

#[derive(Clone)]
pub struct MntRec {
    pub id: u64,
    pub source: String,
    pub opts: u64,
    /// Some(target) once move_mount has attached the record.
    pub attached: Option<String>,
    /// KIND_SUBTREE | KIND_TMPFS
    pub kind: u8,
    /// Per-instance byte cap for KIND_TMPFS (0 = tmpfs default).
    pub quota: u64,
}

/// Filesystem-context record created by fsopen (tmpfs only). fsconfig
/// mutates it; fsmount materializes it into a detached MntRec.
#[derive(Clone)]
pub struct FsCtx {
    pub id: u64,
    pub opts: u64,
    /// `size=` byte cap, 0 = default.
    pub size: u64,
}

static FSCTX: Mutex<Vec<FsCtx>> = Mutex::new(Vec::new());
static FCNEXT: Mutex<u64> = Mutex::new(1);

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
        kind: KIND_SUBTREE,
        quota: 0,
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
    let (source, opts, kind, quota) = {
        let g = REG.lock();
        let Some(r) = g.iter().find(|r| r.id == id) else {
            return Err(-9);
        };
        if r.attached.is_some() {
            return Err(-16); // EBUSY: already attached
        }
        (r.source.clone(), r.opts, r.kind, r.quota)
    };
    match kind {
        KIND_TMPFS => crate::tmpfs::mount_sized(target, opts, quota)?,
        _ => crate::bind::mount(&source, target, opts)?,
    }
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

// ---------------------------------------------------------------------------
// fsopen/fsconfig/fsmount — a mutable filesystem context that fsmount
// materializes into a detached mount record. tmpfs is the only fstype.

/// fsopen("tmpfs") → context id. ENODEV for anything else.
pub fn ctx_create(fstype: &str) -> Result<u64, i64> {
    if fstype != "tmpfs" {
        return Err(-19);
    }
    let mut n = FCNEXT.lock();
    let id = *n;
    *n += 1;
    FSCTX.lock().push(FsCtx {
        id,
        opts: 0,
        size: 0,
    });
    Ok(id)
}

/// Parse "/fsctx/{id}" fd paths.
pub fn fd_ctx(path: &str) -> Option<u64> {
    path.strip_prefix("/fsctx/")?.parse().ok()
}

fn ctx_mut(id: u64, f: impl Fn(&mut FsCtx) -> Result<(), i64>) -> Result<(), i64> {
    let mut g = FSCTX.lock();
    let Some(c) = g.iter_mut().find(|c| c.id == id) else {
        return Err(-9);
    };
    f(c)
}

fn flag_of(key: &str) -> Option<u64> {
    match key {
        "ro" | "rdonly" => Some(shared::MS_RDONLY),
        "nosuid" => Some(shared::MS_NOSUID),
        "nodev" => Some(shared::MS_NODEV),
        "noexec" => Some(shared::MS_NOEXEC),
        _ => None,
    }
}

/// "96K"/"4M"/"1G" or plain digits → bytes.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (d, mul) = match s.as_bytes().last() {
        Some(b'K') | Some(b'k') => (&s[..s.len() - 1], 1024u64),
        Some(b'M') | Some(b'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G') | Some(b'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };
    d.parse::<u64>().ok().map(|v| v.saturating_mul(mul))
}

/// FSCONFIG_SET_FLAG — a boolean mount flag by name.
pub fn ctx_flag(id: u64, key: &str) -> Result<(), i64> {
    let Some(bit) = flag_of(key) else { return Err(-22) };
    ctx_mut(id, |c| {
        c.opts |= bit;
        Ok(())
    })
}

/// FSCONFIG_UNSET — clear a flag by name.
pub fn ctx_unset(id: u64, key: &str) -> Result<(), i64> {
    let Some(bit) = flag_of(key) else { return Err(-22) };
    ctx_mut(id, |c| {
        c.opts &= !bit;
        Ok(())
    })
}

/// FSCONFIG_SET_STRING — "size=96K" (real per-mount quota) or a flag
/// name carried as a string ("ro"/"nosuid"/...).
pub fn ctx_string(id: u64, key: &str, val: &str) -> Result<(), i64> {
    if key == "size" {
        let Some(q) = parse_size(val) else { return Err(-22) };
        return ctx_mut(id, |c| {
            c.size = q;
            Ok(())
        });
    }
    if let Some(bit) = flag_of(key) {
        return ctx_mut(id, |c| {
            c.opts |= bit;
            Ok(())
        });
    }
    Err(-22)
}

/// fsmount(ctx) → a detached mount-fd record carrying the ctx's opts
/// and size; attach materializes a real tmpfs superblock.
pub fn fsmount(ctx_id: u64) -> Result<u64, i64> {
    let (opts, quota) = {
        let g = FSCTX.lock();
        let Some(c) = g.iter().find(|c| c.id == ctx_id) else {
            return Err(-9);
        };
        (c.opts, c.size)
    };
    let mut n = NEXT.lock();
    let id = *n;
    *n += 1;
    REG.lock().push(MntRec {
        id,
        source: String::from("tmpfs"),
        opts,
        attached: None,
        kind: KIND_TMPFS,
        quota,
    });
    Ok(id)
}
