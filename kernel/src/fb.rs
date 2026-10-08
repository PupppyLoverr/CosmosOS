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
    // Atomics mirror for the panic path (takes no locks, allocates nothing).
    PFB_PHYS.store(phys, Ordering::SeqCst);
    PFB_WH.store(((w as u64) << 32) | h as u64, Ordering::SeqCst);
    PFB_STRIDE.store(stride as u64, Ordering::SeqCst);
    PFB_FORMAT.store(format as u64, Ordering::SeqCst);
}

static PFB_PHYS: AtomicU64 = AtomicU64::new(0);
static PFB_WH: AtomicU64 = AtomicU64::new(0); // w << 32 | h
static PFB_STRIDE: AtomicU64 = AtomicU64::new(0);
static PFB_FORMAT: AtomicU64 = AtomicU64::new(0);

/// Render `msg` as 8x16 text straight to the framebuffer. Used by the panic
/// handler — no locks, no allocation, safe to run with the heap corrupted.
pub fn panic_screen(msg: &str) {
    let phys = PFB_PHYS.load(Ordering::SeqCst);
    if phys == 0 {
        return;
    }
    let wh = PFB_WH.load(Ordering::SeqCst);
    let (w, h) = ((wh >> 32) as usize, wh as u32 as usize);
    let stride = PFB_STRIDE.load(Ordering::SeqCst) as usize;
    let fmt = PFB_FORMAT.load(Ordering::SeqCst) as u8;
    let px = |c: u32| -> u32 {
        if fmt == 0 { // Bgr: swap R/B
            (c & 0xFF00FF00) | ((c >> 16) & 0xFF) | ((c & 0xFF) << 16)
        } else {
            c
        }
    };
    let base = crate::mem::phys_to_virt(phys) as *mut u32;
    unsafe {
        // dark red wipe
        for y in 0..h {
            for x in 0..w.min(stride) {
                *base.add(y * stride + x) = px(0xFF200A0A);
            }
        }
        let mut cx = 8usize;
        let mut cy = 8usize;
        for b in msg.bytes() {
            if b == b'\n' || cx + 8 > w {
                cx = 8;
                cy += 16;
                if cy + 16 > h {
                    return;
                }
                if b == b'\n' {
                    continue;
                }
            }
            let g = &shared::font16::FONT16[b as usize];
            for (row, bits) in g.iter().enumerate() {
                for col in 0..8 {
                    if bits & (0x80 >> col) != 0 {
                        *base.add((cy + row) * stride + cx + col) = px(0xFFF0F0F0);
                    }
                }
            }
            cx += 8;
        }
    }
}

/// Snapshot the live framebuffer as a binary PPM (P6), top-down rows.
/// Kernel-side read via the HHDM map — captures whatever is on screen.
pub fn snapshot_ppm() -> Option<Vec<u8>> {
    let f = FB.lock();
    let f = f.as_ref()?;
    let (w, h, stride) = (f.width as usize, f.height as usize, f.stride as usize);
    let bgr = f.format == 0;
    let base = crate::mem::phys_to_virt(f.phys) as *const u32;
    let mut out = Vec::with_capacity(16 + w * h * 3);
    out.extend_from_slice(alloc::format!("P6\n{} {}\n255\n", w, h).as_bytes());
    for y in 0..h {
        for x in 0..w.min(stride) {
            let p = unsafe { core::ptr::read_volatile(base.add(y * stride + x)) };
            // u32 holds byte-order [b0,b1,b2,x]; Bgr has B in byte0
            let (r, g, b) = if bgr {
                ((p >> 16) & 0xFF, (p >> 8) & 0xFF, p & 0xFF)
            } else {
                (p & 0xFF, (p >> 8) & 0xFF, (p >> 16) & 0xFF)
            };
            out.extend_from_slice(&[r as u8, g as u8, b as u8]);
        }
    }
    Some(out)
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
