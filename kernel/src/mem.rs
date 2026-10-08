//! Physical frame allocation, paging helpers, kernel heap.
use crate::sprintln;
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use core::sync::atomic::{AtomicU64, Ordering};
use linked_list_allocator::LockedHeap;
use spin::{Mutex, Once};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    Translate,
};
use x86_64::{PhysAddr, VirtAddr};

pub static PHYS_OFFSET: Once<u64> = Once::new();
pub static FRAME_ALLOC: Mutex<Option<RegionFrameAlloc>> = Mutex::new(None);
pub static MAPPER: Mutex<Option<OffsetPageTable<'static>>> = Mutex::new(None);

#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

pub static HEAP_SIZE: AtomicU64 = AtomicU64::new(0);

pub const HEAP_START: u64 = 0x4444_4444_0000;
pub const HEAP_PAGES: u64 = 2048; // 8 MiB kernel heap (tmpfs data lives here)

/// Bump allocator over the UEFI memory map's Usable regions.
/// Used frames are never reclaimed (kernel structures are long-lived);
/// process-owned frames are tracked separately for teardown.
pub struct RegionFrameAlloc {
    regions: &'static MemoryRegions,
    idx: usize,       // region index
    next_frame: u64,  // next frame addr within region
    total: u64,
    used: u64,
    free_list: Option<alloc::vec::Vec<u64>>, // frames returned by teardowns
}

impl RegionFrameAlloc {
    pub fn new(regions: &'static MemoryRegions) -> Self {
        let mut total = 0u64;
        for r in regions.iter() {
            if r.kind == MemoryRegionKind::Usable {
                total += r.end - r.start;
            }
        }
        let mut a = RegionFrameAlloc { regions, idx: 0, next_frame: 0, total, used: 0, free_list: None };
        a.advance();
        a
    }

    fn advance(&mut self) {
        while self.idx < self.regions.len() {
            let r = &self.regions[self.idx];
            if r.kind == MemoryRegionKind::Usable {
                let start = self.next_frame.max(r.start);
                if start + 0x1000 <= r.end {
                    self.next_frame = start;
                    return;
                }
            }
            self.idx += 1;
            self.next_frame = 0;
        }
    }

    pub fn alloc_frame(&mut self) -> Option<PhysFrame> {
        if let Some(fl) = &mut self.free_list {
            if let Some(a) = fl.pop() {
                self.used += 0x1000;
                return PhysFrame::from_start_address(PhysAddr::new(a)).ok();
            }
        }
        loop {
            if self.idx >= self.regions.len() {
                return None;
            }
            let r = &self.regions[self.idx];
            let frame = self.next_frame;
            self.next_frame += 0x1000;
            if frame + 0x1000 <= r.end {
                self.used += 0x1000;
                return PhysFrame::from_start_address(PhysAddr::new(frame)).ok();
            }
            self.advance();
        }
    }

    pub fn free(&mut self, addr: u64) {
        self.free_list.get_or_insert_with(alloc::vec::Vec::new).push(addr);
        self.used = self.used.saturating_sub(0x1000);
    }

    pub fn total_bytes(&self) -> u64 {
        self.total
    }
    pub fn used_bytes(&self) -> u64 {
        self.used
    }
}

unsafe impl FrameAllocator<Size4KiB> for RegionFrameAlloc {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        self.alloc_frame()
    }
}

/// Allocate one frame globally (for ad-hoc kernel use).
pub fn alloc_frame() -> Option<PhysFrame> {
    FRAME_ALLOC.lock().as_mut().as_mut().and_then(|a| a.alloc_frame())
}

/// Allocate `pages` physically-contiguous frames (bump region only — DMA).
pub fn alloc_contig(pages: usize) -> Option<u64> {
    let mut g = FRAME_ALLOC.lock();
    let a = g.as_mut()?;
    // steal from the current region only — contiguous run
    loop {
        if a.idx >= a.regions.len() {
            return None;
        }
        let r = &a.regions[a.idx];
        if a.next_frame + (pages as u64) * 0x1000 <= r.end {
            let base = a.next_frame;
            a.next_frame += (pages as u64) * 0x1000;
            a.used += (pages as u64) * 0x1000;
            return Some(base);
        }
        a.advance();
    }
}

/// Return a frame to the free list. COW-shared frames decrement their
/// sharer count instead — the last sharer's free actually reclaims it.
pub fn free_frame(addr: u64) {
    if !cow_release(addr) {
        return;
    }
    let mut g = FRAME_ALLOC.lock();
    if let Some(a) = g.as_mut() {
        a.free(addr);
    }
}

/// Copy-on-write shared frames: phys -> number of address spaces that
/// map it. fork() registers every private frame it shares; free_frame
/// decrements; a count-1 entry means exactly one mm still maps it —
/// that mm may claim it outright (cow_claim) instead of copying.
static COW_REFS: Mutex<alloc::collections::BTreeMap<u64, u32>> =
    Mutex::new(alloc::collections::BTreeMap::new());

/// Register one more mapper of `phys` (called by fork per shared frame).
/// A first share records 2 — the parent's existing mapping + the new
/// child's — so the count always equals live mappers.
pub fn cow_share(phys: u64) {
    *COW_REFS.lock().entry(phys).or_insert(1) += 1;
}

/// How many address spaces currently map `phys` (1 = untracked/sole).
pub fn cow_count(phys: u64) -> u32 {
    COW_REFS.lock().get(&phys).copied().unwrap_or(1)
}

/// Drop the bookkeeping entry — the sole remaining mapper takes full
/// ownership. The frame stays mapped; nothing is freed.
pub fn cow_claim(phys: u64) {
    COW_REFS.lock().remove(&phys);
}

/// Total frames currently COW-shared — surfaced via /proc/sys/kernel.
pub fn cow_shared_total() -> u64 {
    COW_REFS.lock().len() as u64
}

/// One sharer dropped `phys`. true = really free it now.
fn cow_release(phys: u64) -> bool {
    let mut m = COW_REFS.lock();
    match m.get_mut(&phys) {
        None => true,
        Some(c) if *c > 1 => {
            *c -= 1;
            false
        }
        Some(_) => {
            m.remove(&phys);
            true
        }
    }
}

/// Kernel virtual stack region: each kernel stack maps its own frames here.
static KSTACK_VIRT: AtomicU64 = AtomicU64::new(0x5555_0000_0000);

/// Map `pages` fresh frames at a fresh virtual range in kernel space; returns
/// (virt_base, phys_frames) — used for kernel stacks (no contiguity needed).
pub fn alloc_kstack(pages: u64) -> Option<(u64, alloc::vec::Vec<u64>)> {
    let base = KSTACK_VIRT.fetch_add(pages * 0x1000, Ordering::Relaxed);
    let mut frames = alloc::vec::Vec::new();
    let mut m = MAPPER.lock();
    let mapper = m.as_mut()?;
    let mut a = FRAME_ALLOC.lock();
    let alloc = a.as_mut()?;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    for i in 0..pages {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + i * 0x1000));
        let frame = alloc.alloc_frame()?;
        frames.push(frame.start_address().as_u64());
        unsafe {
            mapper.map_to(page, frame, flags, alloc).ok()?.flush();
        }
    }
    Some((base, frames))
}

pub fn phys_to_virt(phys: u64) -> u64 {
    *PHYS_OFFSET.get().unwrap() + phys
}

/// Translate a kernel-mapped virtual address to its physical address.
pub fn translate(vaddr: u64) -> Option<u64> {
    let mut g = MAPPER.lock();
    let m = g.as_mut()?;
    m.translate_addr(x86_64::VirtAddr::new(vaddr)).map(|p| p.as_u64())
}

pub fn meminfo() -> (u64, u64, u64) {
    let g = FRAME_ALLOC.lock();
    match g.as_ref() {
        Some(a) => (a.total_bytes(), a.used_bytes(), HEAP_SIZE.load(Ordering::Relaxed)),
        None => (0, 0, 0),
    }
}

unsafe fn active_l4(_phys_offset: u64) -> &'static mut PageTable {
    let (frame, _) = Cr3::read();
    let virt = phys_to_virt(frame.start_address().as_u64());
    &mut *(virt as *mut PageTable)
}

/// Initialize frame allocator, mapper, kernel heap.
pub fn init(regions: &'static MemoryRegions, phys_offset: u64) {
    PHYS_OFFSET.call_once(|| phys_offset);
    let alloc = RegionFrameAlloc::new(regions);
    *FRAME_ALLOC.lock() = Some(alloc);
    let l4 = unsafe { active_l4(phys_offset) };
    let mapper = unsafe { OffsetPageTable::new(l4, VirtAddr::new(phys_offset)) };
    *MAPPER.lock() = Some(mapper);

    // map kernel heap
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    {
        let mut m = MAPPER.lock();
        let mapper = m.as_mut().unwrap();
        let mut a = FRAME_ALLOC.lock();
        let alloc = a.as_mut().unwrap();
        for i in 0..HEAP_PAGES {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(HEAP_START + i * 0x1000));
            let frame = alloc.alloc_frame().expect("heap frame");
            unsafe {
                mapper.map_to(page, frame, flags, alloc).expect("map heap").flush();
            }
        }
    }
    unsafe { HEAP.lock().init(HEAP_START as *mut u8, (HEAP_PAGES * 0x1000) as usize) };
    HEAP_SIZE.store(HEAP_PAGES * 0x1000, Ordering::Relaxed);
    sprintln!("[mem] phys_offset={:#x} heap={} pages", phys_offset, HEAP_PAGES);
}
