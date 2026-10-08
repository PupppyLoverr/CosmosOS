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
    frames.push(f.start_address().as_u64());
    pt[i1].set_addr(
        f.start_address(),
        F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE | F::NO_EXECUTE,
    );
    Some(f.start_address().as_u64())
}

/// Map an executable (no WRITE, has USER) user page.
fn map_user_page_flags(pml4: PhysFrame, vaddr: u64, writable: bool, frames: &mut Vec<u64>) -> Option<u64> {
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
    frames.push(f.start_address().as_u64());
    let mut fl = F::PRESENT | F::USER_ACCESSIBLE;
    if writable {
        fl |= F::WRITABLE;
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
            map_user_page_flags(pml4, page, writable, frames).ok_or(())?;
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
