//! Framebuffer bookkeeping: stored at boot, claimed+mapped into the first
//! user task that asks (the winserver).
use crate::sprintln;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::PhysFrame;

pub struct Fb {
    pub phys: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32, // pixels/row
    pub format: u8,  // 0=Bgr 1=Rgb
}

pub static FB: Mutex<Option<Fb>> = Mutex::new(None);
/// task id that claimed the framebuffer (0 = unclaimed)
pub static FB_OWNER: AtomicU64 = AtomicU64::new(0);
/// user vaddr where the fb gets mapped (fixed slot)
pub const FB_USER_VA: u64 = 0x4000_0000;

pub fn set(phys: u64, w: u32, h: u32, stride: u32, format: u8) {
    *FB.lock() = Some(Fb { phys, width: w, height: h, stride, format });
}

/// Map the framebuffer into `pml4`'s user space at FB_USER_VA.
/// Returns FbInfo with user addr, or Err if already claimed by another task.
pub fn claim_and_map(pml4: PhysFrame, owner: u32) -> Result<shared::FbInfo, ()> {
    let prev = FB_OWNER.compare_exchange(0, owner as u64, Ordering::SeqCst, Ordering::SeqCst);
    match prev {
        Ok(_) => {}
        Err(x) if x == owner as u64 => {}
        Err(_) => return Err(()),
    }
    let g = FB.lock();
    let Some(f) = g.as_ref() else { return Err(()) };
    let bytes = (f.stride as u64) * (f.height as u64) * 4;
    let pages = bytes.div_ceil(0x1000);
    let mut vaddr = FB_USER_VA;
    let mut borrowed: Vec<u64> = Vec::new();
    for _ in 0..pages {
        if !crate::elf::map_phys_user(pml4, vaddr, f.phys + (vaddr - FB_USER_VA), true) {
            sprintln!("[fb] map failed at {:#x}", vaddr);
            return Err(());
        }
        borrowed.push(f.phys + (vaddr - FB_USER_VA));
        vaddr += 0x1000;
    }
    // track borrowed frames on the task so teardown skips them
    crate::task::with_current(|t| t.borrowed.extend(borrowed));
    sprintln!("[fb] claimed by pid={} -> {:#x} ({}x{})", owner, FB_USER_VA, f.width, f.height);
    Ok(shared::FbInfo {
        addr: FB_USER_VA,
        width: f.width,
        height: f.height,
        stride: f.stride,
        bpp: 32,
        format: f.format,
    })
}
