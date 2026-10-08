//! ELF64 loading into user page tables + user mapping helpers.
use crate::mem;
use alloc::string::String;
use alloc::vec::Vec;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame};
use x86_64::PhysAddr;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

fn user_l4(pml4: PhysFrame) -> &'static mut PageTable {
    unsafe { &mut *(mem::phys_to_virt(pml4.start_address().as_u64()) as *mut PageTable) }
}

fn next_table<'a>(entry: &'a mut PageTableEntry, frames: &mut Vec<u64>) -> Option<&'a mut PageTable> {
    use x86_64::structures::paging::PageTableFlags as F;
    if entry.is_unused() {
        let f = mem::alloc_frame()?;
        frames.push(f.start_address().as_u64());
        let t = unsafe { &mut *(mem::phys_to_virt(f.start_address().as_u64()) as *mut PageTable) };
        t.zero();
        entry.set_addr(f.start_address(), F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE);
    }
    Some(unsafe { &mut *(mem::phys_to_virt(entry.addr().as_u64()) as *mut PageTable) })
}

/// Map one 4KiB user page (fresh frame, zeroed, USER|RW).
pub fn map_user_page(pml4: PhysFrame, vaddr: u64, frames: &mut Vec<u64>) -> Option<u64> {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = user_l4(pml4);
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt = next_table(&mut l4[i4], frames)?;
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    let pd = next_table(&mut pdpt[i3], frames)?;
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    let pt = next_table(&mut pd[i2], frames)?;
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if !pt[i1].is_unused() {
        return Some(pt[i1].addr().as_u64()); // already mapped
    }
    let f = mem::alloc_frame()?;
    unsafe { core::ptr::write_bytes(mem::phys_to_virt(f.start_address().as_u64()) as *mut u8, 0, 0x1000) };
    frames.push(f.start_address().as_u64());
    pt[i1].set_addr(
        f.start_address(),
        F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE | F::NO_EXECUTE,
    );
    Some(f.start_address().as_u64())
}

/// Map an executable (no WRITE, has USER) user page.
pub fn map_user_page_flags(pml4: PhysFrame, vaddr: u64, writable: bool, exec: bool, frames: &mut Vec<u64>) -> Option<u64> {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = user_l4(pml4);
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt = next_table(&mut l4[i4], frames)?;
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    let pd = next_table(&mut pdpt[i3], frames)?;
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    let pt = next_table(&mut pd[i2], frames)?;
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if !pt[i1].is_unused() {
        return Some(pt[i1].addr().as_u64());
    }
    let f = mem::alloc_frame()?;
    unsafe { core::ptr::write_bytes(mem::phys_to_virt(f.start_address().as_u64()) as *mut u8, 0, 0x1000) };
    frames.push(f.start_address().as_u64());
    let mut fl = F::PRESENT | F::USER_ACCESSIBLE;
    if writable {
        fl |= F::WRITABLE;
    }
    if !exec {
        fl |= F::NO_EXECUTE;
    }
    pt[i1].set_addr(f.start_address(), fl);
    Some(f.start_address().as_u64())
}

/// Map `size` bytes of zeroed, user-accessible memory. Returns mapped phys frames.
pub fn map_user_range(pml4: PhysFrame, vaddr: u64, size: u64, frames: &mut Vec<u64>) -> Option<Vec<u64>> {
    let mut out = Vec::new();
    let pages = size.div_ceil(0x1000);
    for i in 0..pages {
        let phys = map_user_page(pml4, vaddr + i * 0x1000, frames)?;
        out.push(phys);
    }
    Some(out)
}

/// Map an existing physical frame into user space (shm surfaces, framebuffer).
pub fn map_phys_user(pml4: PhysFrame, vaddr: u64, phys: u64, writable: bool) -> bool {
    use x86_64::structures::paging::PageTableFlags as F;
    let mut scratch = Vec::new();
    let l4 = user_l4(pml4);
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    let Some(pdpt) = next_table(&mut l4[i4], &mut scratch) else { return false };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    let Some(pd) = next_table(&mut pdpt[i3], &mut scratch) else { return false };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    let Some(pt) = next_table(&mut pd[i2], &mut scratch) else { return false };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if !pt[i1].is_unused() {
        return false;
    }
    let mut fl = F::PRESENT | F::USER_ACCESSIBLE | F::NO_EXECUTE;
    if writable {
        fl |= F::WRITABLE;
    }
    pt[i1].set_addr(PhysAddr::new(phys), fl);
    // scratch holds intermediate PT frames we created — they are owned by the
    // user table and reclaimed by free_user_space at process teardown.
    let _ = scratch;
    true
}

/// map_phys_user with an exec flag — fork/exec need to recreate shared
/// or copied mappings with the source page's real permissions.
pub fn map_phys_user_flags(
    pml4: PhysFrame,
    vaddr: u64,
    phys: u64,
    writable: bool,
    exec: bool,
    frames: &mut Vec<u64>,
) -> bool {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = user_l4(pml4);
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    let Some(pdpt) = next_table(&mut l4[i4], frames) else { return false };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    let Some(pd) = next_table(&mut pdpt[i3], frames) else { return false };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    let Some(pt) = next_table(&mut pd[i2], frames) else { return false };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if !pt[i1].is_unused() {
        return false;
    }
    let mut fl = F::PRESENT | F::USER_ACCESSIBLE;
    if writable {
        fl |= F::WRITABLE;
    }
    if !exec {
        fl |= F::NO_EXECUTE;
    }
    pt[i1].set_addr(PhysAddr::new(phys), fl);
    true
}

/// Load ELF64 segments from `data` into the user table `pml4`.
/// Returns entry point.
/// Load an ELF image. Every PT_LOAD is also recorded in `maps` as a
/// `MapEnt` so `/proc/<pid>/maps` reflects the real segment layout.
pub fn load_into(
    pml4: PhysFrame,
    data: &[u8],
    frames: &mut Vec<u64>,
    maps: &mut Vec<crate::task::MapEnt>,
) -> Result<u64, ()> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(());
    }
    if data[4] != 2 || data[5] != 1 {
        return Err(()); // need 64-bit LE
    }
    let machine = u16::from_le_bytes([data[18], data[19]]);
    if machine != 0x3E {
        return Err(()); // x86_64
    }
    let entry = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
    if phoff + phnum * phentsize > data.len() || phentsize < 56 {
        return Err(());
    }
    // pass 1: lowest PT_LOAD vaddr -> load bias (PIE binaries link at ~0)
    const USER_LOAD_BASE: u64 = 0x40_0000; // 4 MiB
    let mut min_vaddr = u64::MAX;
    for i in 0..phnum {
        let ph = &data[phoff + i * phentsize..phoff + i * phentsize + 56];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != PT_LOAD {
            continue;
        }
        let pv = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        if u64::from_le_bytes(ph[40..48].try_into().unwrap()) > 0 {
            min_vaddr = min_vaddr.min(pv & !0xFFF);
        }
    }
    if min_vaddr == u64::MAX {
        return Err(());
    }
    let bias = USER_LOAD_BASE.saturating_sub(min_vaddr);
    for i in 0..phnum {
        let ph = &data[phoff + i * phentsize..phoff + i * phentsize + 56];
        let ptype = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        if ptype != PT_LOAD {
            continue;
        }
        let pflags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        let poffset = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let pvaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap()) + bias;
        let pfilesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        let pmemsz = u64::from_le_bytes(ph[40..48].try_into().unwrap()) as usize;
        if pmemsz == 0 {
            continue;
        }
        if pvaddr < 0x1000 || pvaddr + pmemsz as u64 > 0x7EFF_F000 {
            return Err(()); // keep user layout tidy
        }
        let writable = pflags & PF_W != 0;
        // map pages covering [vaddr, vaddr+memsz)
        let page_lo = pvaddr & !0xFFF;
        let page_hi = (pvaddr + pmemsz as u64 + 0xFFF) & !0xFFF;
        for page in (page_lo..page_hi).step_by(0x1000) {
            map_user_page_flags(pml4, page, writable, true, frames).ok_or(())?;
        }
        let perm = (if pflags & PF_R != 0 { 1u8 } else { 0 })
            | (if writable { 2u8 } else { 0 })
            | (if pflags & PF_X != 0 { 4u8 } else { 0 });
        maps.push(crate::task::MapEnt {
            start: page_lo,
            end: page_hi,
            perm,
            name: String::new(), // filled with the image path by the caller
        });
        // copy file bytes via the phys map (works regardless of active CR3)
        if pfilesz > 0 {
            let mut off = 0usize;
            while off < pfilesz {
                let va = pvaddr + off as u64;
                let phys = translate(pml4, va).ok_or(())?;
                let chunk = (0x1000 - (va as usize & 0xFFF)).min(pfilesz - off);
                unsafe {
                    // translate() already includes the in-page offset
                    let dst = mem::phys_to_virt(phys) as *mut u8;
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(poffset + off), dst, chunk);
                }
                off += chunk;
            }
        }
        // zero bss tail
        if pmemsz > pfilesz {
            let mut off = pfilesz;
            while off < pmemsz {
                let va = pvaddr + off as u64;
                let phys = translate(pml4, va).ok_or(())?;
                let chunk = (0x1000 - (va as usize & 0xFFF)).min(pmemsz - off);
                unsafe {
                    core::ptr::write_bytes(mem::phys_to_virt(phys) as *mut u8, 0, chunk);
                }
                off += chunk;
            }
        }
    }

    // pass 3: apply R_X86_64_RELATIVE relocations (PIE binaries carry GOT
    // slots/function pointers that must be rebased by the load bias)
    for i in 0..phnum {
        let ph = &data[phoff + i * phentsize..phoff + i * phentsize + 56];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 2 {
            continue; // PT_DYNAMIC
        }
        let dyn_va = u64::from_le_bytes(ph[16..24].try_into().unwrap()) + bias;
        let dyn_sz = u64::from_le_bytes(ph[40..48].try_into().unwrap()) as usize;
        let Some(dyn_phys) = translate(pml4, dyn_va) else { continue };
        let dynp = unsafe {
            core::slice::from_raw_parts(mem::phys_to_virt(dyn_phys) as *const u8, dyn_sz)
        };
        let (mut rela, mut relasz, mut relaent) = (0u64, 0u64, 24u64);
        for e in dynp.chunks_exact(16) {
            let tag = i64::from_le_bytes(e[0..8].try_into().unwrap());
            let val = u64::from_le_bytes(e[8..16].try_into().unwrap());
            match tag {
                7 => rela = val,      // DT_RELA
                8 => relasz = val,    // DT_RELASZ
                9 => relaent = val,   // DT_RELAENT
                _ => {}
            }
        }
        if rela == 0 || relasz == 0 || relaent < 24 {
            break;
        }
        let n = relasz / relaent;
        for j in 0..n {
            let rva = rela + bias + j * relaent;
            let Some(rphys) = translate(pml4, rva) else { continue };
            let e = unsafe {
                core::slice::from_raw_parts(mem::phys_to_virt(rphys) as *const u8, 24)
            };
            let r_offset = u64::from_le_bytes(e[0..8].try_into().unwrap());
            let r_info = u64::from_le_bytes(e[8..16].try_into().unwrap());
            let r_addend = i64::from_le_bytes(e[16..24].try_into().unwrap());
            if r_info & 0xFFFF_FFFF != 8 {
                continue; // only R_X86_64_RELATIVE
            }
            let Some(wphys) = translate(pml4, r_offset + bias) else { continue };
            unsafe {
                *(mem::phys_to_virt(wphys) as *mut u64) = (r_addend as u64).wrapping_add(bias);
            }
        }
    }
    Ok(entry + bias)
}

/// Translate a user vaddr to a physical address under `pml4`.
/// Like `translate`, but only resolves pages userspace may actually access:
/// USER_ACCESSIBLE must be set at every level (hardware ANDs it). Kernel
/// mappings shared into a user pml4 fail here — the syscall boundary uses
/// this so copy_in/copy_out can never be aimed at kernel memory.
pub fn translate_user(pml4: PhysFrame, vaddr: u64) -> Option<u64> {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = unsafe { &*(mem::phys_to_virt(pml4.start_address().as_u64()) as *const PageTable) };
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    if l4[i4].is_unused() || !l4[i4].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    let pdpt = unsafe { &*(mem::phys_to_virt(l4[i4].addr().as_u64()) as *const PageTable) };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    if pdpt[i3].is_unused() || !pdpt[i3].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    let pd = unsafe { &*(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *const PageTable) };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    if pd[i2].is_unused() || !pd[i2].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    let pt = unsafe { &*(mem::phys_to_virt(pd[i2].addr().as_u64()) as *const PageTable) };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if pt[i1].is_unused() || !pt[i1].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    Some(pt[i1].addr().as_u64() + (vaddr & 0xFFF))
}

pub fn translate(pml4: PhysFrame, vaddr: u64) -> Option<u64> {
    let l4 = unsafe { &*(mem::phys_to_virt(pml4.start_address().as_u64()) as *const PageTable) };
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    if l4[i4].is_unused() {
        return None;
    }
    let pdpt = unsafe { &*(mem::phys_to_virt(l4[i4].addr().as_u64()) as *const PageTable) };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    if pdpt[i3].is_unused() {
        return None;
    }
    let pd = unsafe { &*(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *const PageTable) };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    if pd[i2].is_unused() {
        return None;
    }
    let pt = unsafe { &*(mem::phys_to_virt(pd[i2].addr().as_u64()) as *const PageTable) };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if pt[i1].is_unused() {
        return None;
    }
    Some(pt[i1].addr().as_u64() + (vaddr & 0xFFF))
}

/// translate() but enforces USER_ACCESSIBLE at every level — the syscall
/// boundary must never resolve a supervisor mapping for a user pointer.
/// Also refuses anything outside PML4[0]: user tables share the kernel's
/// upper entries by value, so i4 > 0 would name a shared kernel mapping.
pub fn translate_user(pml4: PhysFrame, vaddr: u64) -> Option<u64> {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = unsafe { &*(mem::phys_to_virt(pml4.start_address().as_u64()) as *const PageTable) };
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    if i4 != 0 || l4[i4].is_unused() || !l4[i4].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    let pdpt = unsafe { &*(mem::phys_to_virt(l4[i4].addr().as_u64()) as *const PageTable) };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    if pdpt[i3].is_unused() || !pdpt[i3].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    let pd = unsafe { &*(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *const PageTable) };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    if pd[i2].is_unused() || !pd[i2].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    let pt = unsafe { &*(mem::phys_to_virt(pd[i2].addr().as_u64()) as *const PageTable) };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if pt[i1].is_unused() || !pt[i1].flags().contains(F::USER_ACCESSIBLE) {
        return None;
    }
    Some(pt[i1].addr().as_u64() + (vaddr & 0xFFF))
}

/// Enumerate every present 4KiB user leaf: (vaddr, phys, writable, exec).
/// fork() copies the address space by walking this and rebuilding each
/// page in the child's own table.
pub fn collect_user_pages(pml4: PhysFrame) -> Vec<(u64, u64, bool, bool)> {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = unsafe { &*(mem::phys_to_virt(pml4.start_address().as_u64()) as *const PageTable) };
    let mut out = Vec::new();
    if l4[0].is_unused() {
        return out;
    }
    let pdpt = unsafe { &*(mem::phys_to_virt(l4[0].addr().as_u64()) as *const PageTable) };
    for i3 in 0..512usize {
        if pdpt[i3].is_unused() {
            continue;
        }
        let pd = unsafe { &*(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *const PageTable) };
        for i2 in 0..512usize {
            if pd[i2].is_unused() || pd[i2].flags().contains(F::HUGE_PAGE) {
                continue;
            }
            let pt = unsafe { &*(mem::phys_to_virt(pd[i2].addr().as_u64()) as *const PageTable) };
            for i1 in 0..512usize {
                if pt[i1].is_unused() {
                    continue;
                }
                let va = ((i3 as u64) << 30) | ((i2 as u64) << 21) | ((i1 as u64) << 12);
                let fl = pt[i1].flags();
                out.push((va, pt[i1].addr().as_u64(), fl.contains(F::WRITABLE), !fl.contains(F::NO_EXECUTE)));
            }
        }
    }
    out
}

/// Count present 4KiB leaf mappings in the user half (PML4[0] only — the
/// shared kernel upper-half entries are not the task's own pages).
pub fn count_mapped(pml4: PhysFrame) -> u64 {
    let l4 = unsafe { &*(mem::phys_to_virt(pml4.start_address().as_u64()) as *const PageTable) };
    let mut n = 0u64;
    for i4 in 0..1usize {
        if l4[i4].is_unused() {
            continue;
        }
        let pdpt = unsafe { &*(mem::phys_to_virt(l4[i4].addr().as_u64()) as *const PageTable) };
        for i3 in 0..512usize {
            if pdpt[i3].is_unused() {
                continue;
            }
            let pd = unsafe { &*(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *const PageTable) };
            for i2 in 0..512usize {
                if pd[i2].is_unused() {
                    continue;
                }
                let pt = unsafe { &*(mem::phys_to_virt(pd[i2].addr().as_u64()) as *const PageTable) };
                n += pt.iter().filter(|e| !e.is_unused()).count() as u64;
            }
        }
    }
    n
}

/// Unmap one user page in `pml4`; returns its physical frame address when it
/// was mapped (the caller decides whether the frame is owned or borrowed).
pub fn unmap_user_page(pml4: PhysFrame, vaddr: u64) -> Option<u64> {
    let l4 = user_l4(pml4);
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    if i4 != 0 {
        return None; // never reach into the shared kernel-half tables
    }
    if l4[i4].is_unused() {
        return None;
    }
    let pdpt = unsafe { &mut *(mem::phys_to_virt(l4[i4].addr().as_u64()) as *mut PageTable) };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    if pdpt[i3].is_unused() {
        return None;
    }
    let pd = unsafe { &mut *(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *mut PageTable) };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    if pd[i2].is_unused() {
        return None;
    }
    let pt = unsafe { &mut *(mem::phys_to_virt(pd[i2].addr().as_u64()) as *mut PageTable) };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if pt[i1].is_unused() {
        return None;
    }
    let phys = pt[i1].addr().as_u64();
    pt[i1].set_unused();
    Some(phys)
}

/// Unmap every page in `[lo, hi)`; returns the physical frames that were
/// removed (caller decides ownership — e.g. borrowed shm frames stay).
/// Used to reclaim a dead thread's private stack slot while the shared
/// address space lives on.
pub fn unmap_user_range(pml4: PhysFrame, lo: u64, hi: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut a = lo;
    while a < hi {
        if let Some(p) = unmap_user_page(pml4, a) {
            out.push(p);
        }
        a += 0x1000;
    }
    out
}

/// Rewrite the WRITABLE/NO_EXECUTE bits of a mapped user page (mprotect).
/// Returns Some(()) when the page was mapped.
pub fn protect_user_page(pml4: PhysFrame, vaddr: u64, writable: bool, executable: bool) -> Option<()> {
    use x86_64::structures::paging::PageTableFlags as F;
    let l4 = user_l4(pml4);
    let i4 = ((vaddr >> 39) & 0x1FF) as usize;
    if i4 != 0 {
        return None; // never reach into the shared kernel-half tables
    }
    if l4[i4].is_unused() {
        return None;
    }
    let pdpt = unsafe { &mut *(mem::phys_to_virt(l4[i4].addr().as_u64()) as *mut PageTable) };
    let i3 = ((vaddr >> 30) & 0x1FF) as usize;
    if pdpt[i3].is_unused() {
        return None;
    }
    let pd = unsafe { &mut *(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *mut PageTable) };
    let i2 = ((vaddr >> 21) & 0x1FF) as usize;
    if pd[i2].is_unused() {
        return None;
    }
    let pt = unsafe { &mut *(mem::phys_to_virt(pd[i2].addr().as_u64()) as *mut PageTable) };
    let i1 = ((vaddr >> 12) & 0x1FF) as usize;
    if pt[i1].is_unused() {
        return None;
    }
    let mut fl = F::PRESENT | F::USER_ACCESSIBLE;
    if writable {
        fl |= F::WRITABLE;
    }
    if !executable {
        fl |= F::NO_EXECUTE;
    }
    pt[i1].set_flags(fl);
    Some(())
}

/// Free every user-mapped page + page-table frame under `pml4` (indices < 512
/// except shared kernel slots). Returns all freed frame addresses.
pub fn free_user_space(pml4: PhysFrame) -> Vec<u64> {
    let mut freed = Vec::new();
    unsafe {
        let l4 = &mut *(mem::phys_to_virt(pml4.start_address().as_u64()) as *mut PageTable);
        let i4 = 0usize; // slot 0 is the user-owned tree; shared kernel slots stay
        if !l4[i4].is_unused() {
            let pdpt = &mut *(mem::phys_to_virt(l4[i4].addr().as_u64()) as *mut PageTable);
            for i3 in 0..512 {
                if pdpt[i3].is_unused() {
                    continue;
                }
                let pd = &mut *(mem::phys_to_virt(pdpt[i3].addr().as_u64()) as *mut PageTable);
                for i2 in 0..512 {
                    if pd[i2].is_unused() {
                        continue;
                    }
                    if pd[i2].flags().contains(PageTableFlags::HUGE_PAGE) {
                        continue;
                    }
                    let pt = &mut *(mem::phys_to_virt(pd[i2].addr().as_u64()) as *mut PageTable);
                    for i1 in 0..512 {
                        if !pt[i1].is_unused() {
                            freed.push(pt[i1].addr().as_u64());
                        }
                    }
                    freed.push(pd[i2].addr().as_u64());
                }
                freed.push(pdpt[i3].addr().as_u64());
            }
            freed.push(l4[i4].addr().as_u64());
        }
    }
    freed
}

/// Demand-paged ELF load: PT_LOAD segments register task::FileMap
/// regions instead of copying file bytes eagerly — each page faults in
/// from the image on first touch. `hdr` must contain the ELF header +
/// program headers (caller reads enough of the file to cover them).
/// `file_size` is the whole file's size for bounds. Falls back for
/// segments whose (vaddr,offset) aren't page-aligned.
pub fn load_into_lazy(
    pml4: PhysFrame,
    path: &str,
    hdr: &[u8],
    file_size: u64,
    frames: &mut Vec<u64>,
    maps: &mut Vec<crate::task::MapEnt>,
    filemaps: &mut Vec<crate::task::FileMap>,
) -> Result<u64, ()> {
    if hdr.len() < 64 || &hdr[0..4] != b"\x7fELF" || hdr[4] != 2 || hdr[5] != 1 {
        return Err(());
    }
    if u16::from_le_bytes([hdr[18], hdr[19]]) != 0x3E {
        return Err(());
    }
    let entry = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(hdr[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(hdr[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(hdr[56..58].try_into().unwrap()) as usize;
    if phoff + phnum * phentsize > hdr.len() || phentsize < 56 {
        return Err(()); // phdrs beyond the header window -> caller falls back
    }
    const USER_LOAD_BASE: u64 = 0x40_0000;
    let mut min_vaddr = u64::MAX;
    for i in 0..phnum {
        let ph = &hdr[phoff + i * phentsize..phoff + i * phentsize + 56];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != PT_LOAD {
            continue;
        }
        let pv = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        if u64::from_le_bytes(ph[40..48].try_into().unwrap()) > 0 {
            min_vaddr = min_vaddr.min(pv & !0xFFF);
        }
    }
    if min_vaddr == u64::MAX {
        return Err(());
    }
    let bias = USER_LOAD_BASE.saturating_sub(min_vaddr);
    // (va_lo, va_hi, delta): va->file 1:1 for the file-backed part of
    // every segment — used to read rela entries that live in eagerly
    // mapped pages, outside any filemap
    let mut vadeltas: Vec<(u64, u64, u64)> = Vec::new();
    for i in 0..phnum {
        let ph = &hdr[phoff + i * phentsize..phoff + i * phentsize + 56];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != PT_LOAD {
            continue;
        }
        let pflags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        let poffset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
        let pvaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap()) + bias;
        let pfilesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
        let pmemsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
        if pmemsz == 0 {
            continue;
        }
        if pvaddr < 0x1000 || pvaddr + pmemsz > 0x7EFF_F000 {
            return Err(());
        }
        if poffset + pfilesz > file_size {
            return Err(());
        }
        if pfilesz > 0 {
            vadeltas.push((pvaddr, pvaddr + pfilesz, pvaddr - poffset));
        }
        let writable = pflags & PF_W != 0;
        let perm = (if pflags & PF_R != 0 { 1u8 } else { 0 })
            | (if writable { 2u8 } else { 0 })
            | (if pflags & PF_X != 0 { 4u8 } else { 0 });
        let page_lo = pvaddr & !0xFFF;
        let page_hi = (pvaddr + pmemsz + 0xFFF) & !0xFFF;
        let file_end = pvaddr + pfilesz;
        maps.push(crate::task::MapEnt {
            start: page_lo,
            end: page_hi,
            perm,
            name: String::new(),
        });
        // misaligned (vaddr,offset) can't be paged in 1:1 — eager that seg
        if (pvaddr & 0xFFF) != (poffset & 0xFFF) {
            let mut scratch: Vec<u64> = Vec::new();
            for page in (page_lo..page_hi).step_by(0x1000) {
                map_user_page_flags(pml4, page, writable, true, &mut scratch).ok_or(())?;
            }
            frames.extend(scratch);
            let mut tmp = [0u8; 0x1000];
            let mut off = 0usize;
            while off < pfilesz as usize {
                let va = pvaddr + off as u64;
                let want = (0x1000 - (va as usize & 0xFFF)).min(pfilesz as usize - off);
                let n = crate::vfs::read_range(
                    path,
                    poffset + off as u64,
                    &mut tmp[..want],
                )
                .map_err(|_| ())?;
                let phys = translate(pml4, va).ok_or(())?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        tmp.as_ptr(),
                        mem::phys_to_virt(phys) as *mut u8,
                        n,
                    );
                }
                off += n;
                if n < want {
                    break;
                }
            }
            continue;
        }
        // file-backed zone: [page_lo, file_end&!0xFFF)
        let fm_end = file_end & !0xFFF;
        if fm_end > page_lo {
            filemaps.push(crate::task::FileMap {
                start: page_lo,
                end: fm_end,
                path: String::from(path),
                off: poffset - (pvaddr - page_lo),
                perm,
            });
        }
        // overlap page (file tail + bss head): fill eagerly, zero the tail.
        // The page maps file bytes 1:1 from `poffset - (pvaddr - page)`;
        // only bytes up to file_end are real — everything past is .bss
        // and stays zero (fresh frames are pre-zeroed).
        if pfilesz > 0 && (file_end & 0xFFF) != 0 {
            let mut scratch: Vec<u64> = Vec::new();
            let page = file_end & !0xFFF;
            map_user_page_flags(pml4, page, writable, true, &mut scratch).ok_or(())?;
            frames.extend(scratch);
            let file_off = (poffset as i64 + page as i64 - pvaddr as i64) as u64;
            let copy_len = (file_end - page).min(0x1000) as usize;
            let mut tmp = [0u8; 0x1000];
            let n = crate::vfs::read_range(path, file_off, &mut tmp[..copy_len])
                .map_err(|_| ())?;
            let phys = translate(pml4, page).ok_or(())?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tmp.as_ptr(),
                    mem::phys_to_virt(phys) as *mut u8,
                    n,
                );
            }
        }
        // pure-bss zone: demand-zero pages (sentinel path = "")
        let bss_lo = if pfilesz > 0 {
            (file_end + 0xFFF) & !0xFFF
        } else {
            page_lo
        };
        if bss_lo < page_hi {
            filemaps.push(crate::task::FileMap {
                start: bss_lo,
                end: page_hi,
                path: String::new(), // "" = zero-fill
                off: 0,
                perm,
            });
        }
    }
    // pass 3: R_X86_64_RELATIVE — PIE GOT slots/function pointers get
    // addend+bias. A target on a demand page faults that page in NOW
    // (eager fill) so the slot can be written.
    for i in 0..phnum {
        let ph = &hdr[phoff + i * phentsize..phoff + i * phentsize + 56];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 2 {
            continue; // PT_DYNAMIC
        }
        let dyn_off = u64::from_le_bytes(ph[8..16].try_into().unwrap());
        let dyn_sz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        let mut dynbuf = alloc::vec![0u8; dyn_sz.min(0x1000)];
        let _ = crate::vfs::read_range(path, dyn_off, &mut dynbuf);
        let (mut rela, mut relasz, mut relaent) = (0u64, 0u64, 24u64);
        for e in dynbuf.chunks_exact(16) {
            let tag = i64::from_le_bytes(e[0..8].try_into().unwrap());
            let val = u64::from_le_bytes(e[8..16].try_into().unwrap());
            match tag {
                7 => rela = val,
                8 => relasz = val,
                9 => relaent = val,
                _ => {}
            }
        }
        if rela == 0 || relasz == 0 || relaent < 24 {
            break;
        }
        // the RELA table is file data — find its file offset through the
        // filemap that covers it (or fall back to va==file-offset region
        // inside an eagerly-mapped page, which translate() will find)
        for j in 0..(relasz / relaent) {
            let rva = rela + bias + j * relaent;
            // read the 24-byte rela entry — it lives in a file-backed
            // page; translate() works only if that page is mapped, so
            // read via the file offset using the 1:1 va<->file delta
            let mut eb = [0u8; 24];
            let Some(rf_off) = file_offset_of(&vadeltas, rva) else { continue };
            if crate::vfs::read_range(path, rf_off, &mut eb).is_err() {
                continue;
            }
            let r_offset = u64::from_le_bytes(eb[0..8].try_into().unwrap());
            let r_info = u64::from_le_bytes(eb[8..16].try_into().unwrap());
            let r_addend = i64::from_le_bytes(eb[16..24].try_into().unwrap());
            if r_info & 0xFFFF_FFFF != 8 {
                continue; // only R_X86_64_RELATIVE
            }
            let wva = r_offset + bias;
            if translate(pml4, wva).is_none() {
                // the reloc target page is still demand-only — fault it
                // in eagerly so the slot can be written
                let wpage = wva & !0xFFF;
                if let Some((wpath, woff, wperm)) = filemaps
                    .iter()
                    .find(|f| wpage >= f.start && wpage < f.end)
                    .map(|f| (f.path.clone(), f.off + (wpage - f.start), f.perm))
                {
                    let mut scratch: Vec<u64> = Vec::new();
                    if let Some(wphys) = map_user_page_flags(
                        pml4,
                        wpage,
                        wperm & 2 != 0,
                        wperm & 4 != 0,
                        &mut scratch,
                    ) {
                        frames.extend(scratch);
                        let mut pb = [0u8; 0x1000];
                        if !wpath.is_empty() {
                            let _ = crate::vfs::read_range(path, woff, &mut pb);
                        }
                        unsafe {
                            // pb is zero-initialized — a full-page copy
                            // zeroes the tail past the file data
                            core::ptr::copy_nonoverlapping(
                                pb.as_ptr(),
                                mem::phys_to_virt(wphys) as *mut u8,
                                0x1000,
                            );
                        }
                    }
                }
            }
            let Some(wphys) = translate(pml4, wva) else { continue };
            unsafe {
                *(mem::phys_to_virt(wphys) as *mut u64) = (r_addend as u64).wrapping_add(bias);
            }
        }
    }
    Ok(entry + bias)
}

/// File offset for a VA inside a file-backed span (delta = va - file_off).
fn file_offset_of(spans: &[(u64, u64, u64)], va: u64) -> Option<u64> {
    spans
        .iter()
        .find(|(lo, hi, _)| va >= *lo && va < *hi)
        .map(|(_, _, d)| va - *d)
}
