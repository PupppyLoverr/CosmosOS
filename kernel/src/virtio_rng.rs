//! virtio-rng (legacy, PCI) hardware entropy device driver.
//! One request queue; the device fills device-writable buffers with
//! backend entropy (host /dev/urandom via rng-random object in run.sh).
use crate::mem;
use crate::pci;
use crate::sprintln;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

// legacy virtio io-port offsets (same map as virtio-blk)
const R_GUEST_FEATURES: u16 = 0x04;
const R_QADDR: u16 = 0x08;
const R_QSIZE: u16 = 0x0C;
const R_QSEL: u16 = 0x0E;
const R_QNOTIFY: u16 = 0x10;
const R_STATUS: u16 = 0x12;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRVOK: u8 = 4;
const S_RESET: u8 = 0;

const DESC_F_WRITE: u16 = 2;

const QSZ: usize = 4;
const CHUNK: usize = 512;

pub struct VirtioRng {
    iobase: u16,
    dma_base: u64,
    dma_virt: u64,
    desc0: u64,
    avail: u64,
    used: u64,
    data: u64,
    last_used: AtomicU16,
}

static RNG: Mutex<Option<Arc<VirtioRng>>> = Mutex::new(None);

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

pub fn init() -> bool {
    let Some(d) = pci::find_virtio(0x1005, 0x1044) else {
        sprintln!("[virtio] no rng device");
        return false;
    };
    sprintln!(
        "[virtio] rng dev {:02x}:{:02x} ven {:04x} dev {:04x}",
        d.bus, d.dev, d.vendor, d.device
    );
    d.enable();
    let iobase = d.iobar(0);
    if iobase == 0 {
        sprintln!("[virtio] rng bad iobar");
        return false;
    }
    let mut status_port: Port<u8> = Port::new(iobase + R_STATUS);
    unsafe {
        status_port.write(S_RESET);
        for _ in 0..1_000_000 {
            if status_port.read() == 0 {
                break;
            }
        }
        status_port.write(S_ACK);
        status_port.write(S_ACK | S_DRIVER);
        let mut guest: Port<u32> = Port::new(iobase + R_GUEST_FEATURES);
        guest.write(0);

        let mut qsel: Port<u16> = Port::new(iobase + R_QSEL);
        qsel.write(0);
        let mut qsize_port: Port<u16> = Port::new(iobase + R_QSIZE);
        let qsz = qsize_port.read() as usize;
        if qsz < QSZ {
            sprintln!("[virtio] rng queue too small: {}", qsz);
            return false;
        }

        let page = 0x1000u64;
        let desc_sz = qsz as u64 * 16;
        let avail_sz = 4 + qsz as u64 * 2;
        let used_sz = 4 + qsz as u64 * 8;
        let desc_off = 0u64;
        let avail_off = desc_off + desc_sz;
        let used_off = align_up(avail_off + avail_sz, page);
        let data_off = used_off + used_sz; // inside page 2
        let total = align_up(data_off + (QSZ * CHUNK) as u64, page);
        let pages = (total / page) as usize;

        let Some(base_phys) = mem::alloc_contig(pages) else {
            sprintln!("[virtio] rng no contiguous dma region");
            return false;
        };
        let virt = mem::phys_to_virt(base_phys);
        core::ptr::write_bytes(virt as *mut u8, 0, total as usize);

        let mut qaddr: Port<u32> = Port::new(iobase + R_QADDR);
        qaddr.write((base_phys >> 12) as u32);
        status_port.write(S_ACK | S_DRIVER | S_DRVOK);
        sprintln!("[virtio] rng ready iobase={:#x}", iobase);
        *RNG.lock() = Some(Arc::new(VirtioRng {
            iobase,
            dma_base: base_phys,
            dma_virt: virt,
            desc0: desc_off,
            avail: avail_off,
            used: used_off,
            data: data_off,
            last_used: AtomicU16::new(0),
        }));
        true
    }
}

impl VirtioRng {
    fn rd<T: Copy>(&self, off: u64) -> T {
        unsafe { (self.dma_virt as *const u8).add(off as usize).cast::<T>().read_volatile() }
    }
    fn wr<T: Copy>(&self, off: u64, v: T) {
        unsafe { (self.dma_virt as *mut u8).add(off as usize).cast::<T>().write_volatile(v) }
    }
    fn used_idx(&self) -> u16 {
        self.rd(self.used + 2)
    }
    fn used_elem_len(&self, i: usize) -> u32 {
        self.rd(self.used + 8 + (i as u64) * 8)
    }

    /// Post `n` writeable descriptors (one CHUNK each), notify, and spin
    /// on the used ring until the device has filled them. Returns total
    /// bytes the device wrote into the data area.
    fn request(&self, n: usize, out: &mut [u8]) -> usize {
        // ring slots follow the running avail index, not a fresh 0..n —
        // the ring wraps at QSZ so writes must land on (idx+i) % QSZ
        let start: u16 = self.rd(self.avail + 2);
        for i in 0..n {
            let pa = self.dma_base + self.data + (i * CHUNK) as u64;
            self.wr(self.desc0 + (i * 16) as u64, pa);
            self.wr(self.desc0 + (i * 16) as u64 + 8, CHUNK as u32);
            self.wr(self.desc0 + (i * 16) as u64 + 12, DESC_F_WRITE);
            self.wr(self.desc0 + (i * 16) as u64 + 14, 0u16);
            let slot = (start as usize + i) % QSZ;
            self.wr(self.avail + 4 + (slot as u64) * 2, i as u16);
        }
        self.wr(self.avail + 2, start.wrapping_add(n as u16));
        unsafe {
            Port::<u16>::new(self.iobase + R_QNOTIFY).write(0);
        }
        let want = self.last_used.load(Ordering::Relaxed).wrapping_add(n as u16);
        for _ in 0..50_000_000 {
            if self.used_idx() == want {
                break;
            }
            core::hint::spin_loop();
        }
        if self.used_idx() != want {
            return 0;
        }
        let mut got = 0usize;
        for i in 0..n {
            let li = self.last_used.load(Ordering::Relaxed) as usize % QSZ;
            let len = self.used_elem_len(li) as usize;
            let len = len.min(CHUNK).min(out.len() - got);
            let src = self.dma_virt + self.data + (i * CHUNK) as u64;
            unsafe {
                core::ptr::copy_nonoverlapping(src as *const u8, out.as_mut_ptr().add(got), len);
            }
            got += len;
            self.last_used.fetch_add(1, Ordering::Relaxed);
        }
        got
    }
}

/// Fill `out` with hardware entropy. Returns bytes written (0 when the
/// device is absent or didn't answer).
pub fn fill(out: &mut [u8]) -> usize {
    let g = RNG.lock();
    let Some(r) = g.as_ref() else { return 0 };
    let r = r.clone();
    drop(g);
    let mut done = 0;
    while done < out.len() {
        let want = ((out.len() - done) / CHUNK).clamp(1, QSZ);
        let n = r.request(want, &mut out[done..]);
        if n == 0 {
            break;
        }
        done += n;
    }
    done
}

pub fn ready() -> bool {
    RNG.lock().is_some()
}
