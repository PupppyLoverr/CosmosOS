//! Shared-memory surfaces: pages one task allocates, maps into its own
//! address space, then hands to another task (winserver) which maps the same
//! frames. Ownership: the Shm object owns the frames; each mapper's leaf
//! entries are marked "borrowed" so teardown doesn't double-free.
use crate::task::Task;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub struct Shm {
    pub id: u32,
    pub owner: u32,
    pub frames: Vec<u64>,
    pub refs: u32, // number of tasks currently mapping it
}

pub struct ShmReg {
    pub map: BTreeMap<u32, Shm>,
    pub next_id: u32,
}

pub static SHM: Mutex<Option<ShmReg>> = Mutex::new(None);

pub fn init() {
    *SHM.lock() = Some(ShmReg { map: BTreeMap::new(), next_id: 1 });
}

/// Create a shm region of `size` bytes owned by `owner`. Returns id.
pub fn create(size: u64, owner: u32) -> Option<u32> {
    let pages = size.div_ceil(0x1000);
    if pages == 0 || pages > 4096 {
        return None;
    }
    let mut frames = Vec::new();
    for _ in 0..pages {
        let f = crate::mem::alloc_frame()?;
        let pa = f.start_address().as_u64();
        unsafe { core::ptr::write_bytes(crate::mem::phys_to_virt(pa) as *mut u8, 0, 0x1000) };
        frames.push(pa);
    }
    let mut g = SHM.lock();
    let r = g.as_mut()?;
    let id = r.next_id;
    r.next_id += 1;
    r.map.insert(id, Shm { id, owner, frames, refs: 1 });
    Some(id)
}

/// Map shm `id` into task `t`'s address space at `vaddr` (page-aligned).
/// Returns the number of bytes mapped.
pub fn map_into(t: &mut Task, id: u32, vaddr: u64) -> u64 {
    let frames = {
        let g = SHM.lock();
        match g.as_ref().and_then(|r| r.map.get(&id)) {
            Some(s) => s.frames.clone(),
            None => return 0,
        }
    };
    let Some(pml4) = t.pml4 else { return 0 };
    for (i, &pa) in frames.iter().enumerate() {
        if !crate::elf::map_phys_user(pml4, vaddr + (i as u64) * 0x1000, pa, true) {
            return 0;
        }
        t.borrowed.push(pa);
    }
    let mut g = SHM.lock();
    if let Some(s) = g.as_mut().and_then(|r| r.map.get_mut(&id)) {
        s.refs += 1;
    }
    t.shm.push(id);
    (frames.len() as u64) * 0x1000
}

/// Get the size (mapped byte count) of a shm region.
pub fn size_of(id: u32) -> u64 {
    let g = SHM.lock();
    g.as_ref()
        .and_then(|r| r.map.get(&id))
        .map(|s| (s.frames.len() as u64) * 0x1000)
        .unwrap_or(0)
}

/// Register one more mapper of `id` (clone/thread inherits the shared mm):
/// balances a later `release` so the frames outlive every sharer.
pub fn acquire(id: u32) {
    let mut g = SHM.lock();
    if let Some(r) = g.as_mut() {
        if let Some(s) = r.map.get_mut(&id) {
            s.refs = s.refs.saturating_add(1);
        }
    }
}

/// Process `t` releases its mapping of `id` (frames owned by shm stay alive).
pub fn release(t: &mut Task, id: u32) {
    let mut g = SHM.lock();
    if let Some(r) = g.as_mut() {
        let mut dead = false;
        if let Some(s) = r.map.get_mut(&id) {
            s.refs = s.refs.saturating_sub(1);
            if s.refs == 0 {
                dead = true;
            }
        }
        if dead {
            if let Some(s) = r.map.remove(&id) {
                for f in s.frames {
                    crate::mem::free_frame(f);
                }
            }
        }
    }
    t.shm.retain(|&x| x != id);
    // remove the borrowed markings so a future remap is clean (we can't
    // easily unmap; teardown handles wholesale unmap anyway)
}

/// At task teardown: drop every shm it maps.
pub fn drop_task_shm(t: &mut Task) {
    let ids = core::mem::take(&mut t.shm);
    for id in ids {
        release(t, id);
    }
}

/// Text dump of the shm registry for SYS_IPCS:
/// "id owner size refs" per line — rendered Linux-style by `ipcs -m`.
pub fn ipcs_text() -> String {
    let g = SHM.lock();
    let mut s = String::new();
    if let Some(r) = g.as_ref() {
        for (id, seg) in r.map.iter() {
            s.push_str(&alloc::format!(
                "{} {} {} {}\n",
                id,
                seg.owner,
                seg.frames.len() as u64 * 0x1000,
                seg.refs
            ));
        }
    }
    s
}
