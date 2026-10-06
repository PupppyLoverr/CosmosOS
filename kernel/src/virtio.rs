//! virtio-blk (legacy, PCI) block device driver.
//! Single queue, polled + IRQ for wakeups. Standard legacy init sequence.
use crate::mem;
use crate::pci;
use crate::sprintln;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use fat32::BlockDevice;
use spin::Mutex;
use x86_64::instructions::port::Port;

// legacy virtio-blk io-port offsets (bar0)
const R_FEATURES: u16 = 0x00;
const R_GUEST_FEATURES: u16 = 0x04;
const R_QADDR: u16 = 0x08;
const R_QSIZE: u16 = 0x0C;
const R_QSEL: u16 = 0x0E;
const R_QNOTIFY: u16 = 0x10;
const R_STATUS: u16 = 0x12;
const R_ISR: u16 = 0x13;
const R_CONFIG: u16 = 0x14;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRVOK: u8 = 4;
const S_RESET: u8 = 0;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const QSIZE: usize = 16;

/// Layout within one physically-contiguous region:
/// [desc QSIZE*16][avail 4+QSIZE*2][pad to page][used 4+QSIZE*8][pad][blk hdr 16][status 1]
pub struct VirtioBlk {
    iobase: u16,
    dma_base: u64,
    dma_virt: u64,
    desc0: u64,
    avail: u64,
    used: u64,
    hdr: u64,
    data: u64,
    status: u64,
    last_used: AtomicU16,
    sectors: u64,
    pending: AtomicBool,
}

pub static BLK: Mutex<Option<Arc<VirtioBlk>>> = Mutex::new(None);

pub fn init() -> bool {
    let Some(d) = pci::find_virtio(0x1001, 0x1042) else {
        sprintln!("[virtio] no blk device");
        return false;
    };
    sprintln!(
        "[virtio] blk dev {:02x}:{:02x} ven {:04x} dev {:04x}",
        d.bus, d.dev, d.vendor, d.device
    );
    d.enable();
    let iobase = d.iobar(0);
    if iobase == 0 {
        sprintln!("[virtio] bad iobar");
        return false;
    }
    let mut status_port: Port<u8> = Port::new(iobase + R_STATUS);
    unsafe {
        status_port.write(S_RESET);
        // wait for reset to complete (status reads 0)
        for _ in 0..1_000_000 {
            if status_port.read() == 0 {
                break;
            }
        }
        status_port.write(S_ACK);
        status_port.write(S_ACK | S_DRIVER);

        // legacy protocol: no FEATURES_OK bit (modern-only). Accept no features.
        let mut guest: Port<u32> = Port::new(iobase + R_GUEST_FEATURES);
        guest.write(0);

        // queue select
        let mut qsel: Port<u16> = Port::new(iobase + R_QSEL);
        qsel.write(0);
        let mut qsize_port: Port<u16> = Port::new(iobase + R_QSIZE);
        let qsz = qsize_port.read() as usize;
        if qsz < QSIZE {
            sprintln!("[virtio] queue too small: {}", qsz);
            return false;
        }

        // allocate a physically contiguous DMA region:
        // desc = QSIZE*16 = 256B; avail = 4 + QSIZE*2 = 36B; pad to page;
        // used = 4 + QSIZE*8 = 132B pad to page; blk hdr 16 + data 512 + status 1 = 529 pad to page
        let desc_sz = qsz * 16;
        let avail_sz = 4 + qsz * 2;
        let used_sz = 4 + qsz * 8;
        let page = 0x1000u64;
        let desc_off = 0u64;
        let avail_off = desc_off + desc_sz as u64; // 256
        let used_off = align_up(avail_off + avail_sz as u64, page); // 0x1000
        let io_off = used_off + used_sz as u64; // inside second page
        let hdr_off = align_up(io_off + 0x10, 16);
        let data_off = hdr_off + 0x10;   // 512B sector payload, right after the 16B header
        let status_off = data_off + 0x200;
        let total = align_up(status_off + 0x10, page); // ~2 pages + slack
        let pages = (total / page) as usize;

        // need contiguous phys frames — use the bump allocator's next_frame peek
        let Some(base_phys) = mem::alloc_contig(pages) else {
            sprintln!("[virtio] no contiguous dma region");
            return false;
        };
        let virt = mem::phys_to_virt(base_phys);
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, total as usize) };

        let mut qaddr: Port<u32> = Port::new(iobase + R_QADDR);
        qaddr.write((base_phys >> 12) as u32); // PFN

        // capacity
        let mut cfg: Port<u32> = Port::new(iobase + R_CONFIG);
        let lo = cfg.read() as u64;
        let mut cfg2: Port<u32> = Port::new(iobase + R_CONFIG + 4);
        let hi = cfg2.read() as u64;
        let sectors = lo | (hi << 32);

        status_port.write(S_ACK | S_DRIVER | S_DRVOK);

        sprintln!("[virtio] blk ready: {} sectors ({} MiB) iobase={:#x}", sectors, sectors / 2048, iobase);
        *BLK.lock() = Some(Arc::new(VirtioBlk {
            iobase,
            dma_base: base_phys,
            dma_virt: virt,
            desc0: desc_off,
            avail: avail_off,
            used: used_off,
            hdr: hdr_off,
            data: data_off,
            status: status_off,
            last_used: AtomicU16::new(0),
            sectors,
            pending: AtomicBool::new(false),
        }));
        true
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

impl VirtioBlk {
    fn rd<T: Copy>(&self, off: u64) -> T {
        unsafe { (self.dma_virt as *const u8).add(off as usize).cast::<T>().read_volatile() }
    }
    fn wr<T: Copy>(&self, off: u64, v: T) {
        unsafe { (self.dma_virt as *mut u8).add(off as usize).cast::<T>().write_volatile(v) }
    }
    fn desc(&self, i: usize) -> VringDesc {
        self.rd(self.desc0 + (i * 16) as u64)
    }
    fn set_desc(&self, i: usize, d: VringDesc) {
        self.wr(self.desc0 + (i * 16) as u64, d);
    }
    fn avail_idx(&self) -> u16 {
        self.rd(self.avail + 2)
    }
    fn set_avail_idx(&self, v: u16) {
        self.wr(self.avail + 2, v);
    }
    fn set_avail_ring(&self, i: usize, v: u16) {
        self.wr(self.avail + 4 + (i as u64) * 2, v);
    }
    fn used_idx(&self) -> u16 {
        self.rd(self.used + 2)
    }
    fn used_elem_id(&self, i: usize) -> u32 {
        self.rd(self.used + 4 + (i as u64) * 8)
    }
    fn used_elem_len(&self, i: usize) -> u32 {
        self.rd(self.used + 8 + (i as u64) * 8)
    }
    /// io header (in DMA): {type u32, reserved u32, sector u64}
    fn set_hdr(&self, typ: u32, sector: u64) {
        self.wr(self.hdr, typ);
        self.wr(self.hdr + 4, 0u32);
        self.wr(self.hdr + 8, sector);
    }
    fn data_phys(&self) -> u64 {
        self.dma_base + self.data
    }
    fn data_virt(&self) -> u64 {
        self.dma_virt + self.data
    }
    fn status_phys(&self) -> u64 {
        self.dma_base + self.status
    }

    /// one 512-byte-sector request; write=false → read into `buf`.
    pub fn rw_sector(&self, sector: u64, buf: &mut [u8], write: bool) -> Result<(), ()> {
        if buf.len() < 512 || sector >= self.sectors {
            return Err(());
        }
        let _g = BLK_IO_LOCK.lock();
        unsafe {
            self.set_hdr(if write { 1 } else { 0 }, sector);
            if write {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), self.data_virt() as *mut u8, 512);
            }
            // desc 0: hdr (read)
            self.set_desc(
                0,
                VringDesc {
                    addr: self.dma_base + self.hdr,
                    len: 16,
                    flags: DESC_F_NEXT,
                    next: 1,
                },
            );
            // desc 1: data
            self.set_desc(
                1,
                VringDesc {
                    addr: self.data_phys(),
                    len: 512,
                    flags: DESC_F_NEXT | if write { 0 } else { DESC_F_WRITE },
                    next: 2,
                },
            );
            // desc 2: status (write)
            self.set_desc(
                2,
                VringDesc {
                    addr: self.status_phys(),
                    len: 1,
                    flags: DESC_F_WRITE,
                    next: 0,
                },
            );
            let ai = self.avail_idx();
            self.set_avail_ring((ai as usize) % QSIZE, 0);
            core::sync::atomic::fence(Ordering::SeqCst);
            self.set_avail_idx(ai.wrapping_add(1));
            core::sync::atomic::fence(Ordering::SeqCst);
            let mut notify: Port<u16> = Port::new(self.iobase + R_QNOTIFY);
            notify.write(0);

            self.pending.store(true, Ordering::SeqCst);
            // poll for the used element
            let start = self.last_used.load(Ordering::SeqCst);
            for _ in 0..50_000_000u64 {
                if self.used_idx() != start {
                    let idx = (start as usize) % QSIZE;
                    let _id = self.used_elem_id(idx);
                    let _len = self.used_elem_len(idx);
                    self.last_used.store(self.used_idx(), Ordering::SeqCst);
                    break;
                }
                core::hint::spin_loop();
            }
            self.pending.store(false, Ordering::SeqCst);
            // read ISR to clear interrupt
            let mut isr: Port<u8> = Port::new(self.iobase + R_ISR);
            let _ = isr.read();

            let st: u8 = self.rd(self.status);
            if st != 0 {
                return Err(());
            }
            if !write {
                core::ptr::copy_nonoverlapping(self.data_virt() as *const u8, buf.as_mut_ptr(), 512);
            }
        }
        Ok(())
    }
}

static BLK_IO_LOCK: Mutex<()> = Mutex::new(());

pub fn on_irq() {
    if let Some(b) = BLK.lock().clone() {
        unsafe {
            let mut isr: Port<u8> = Port::new(b.iobase + R_ISR);
            let _ = isr.read();
        }
        b.pending.store(false, Ordering::SeqCst);
    }
}

/// Block device impl for fat32
pub struct BlkDev {
    inner: Arc<VirtioBlk>,
}

impl BlkDev {
    pub fn new(inner: Arc<VirtioBlk>) -> Self {
        Self { inner }
    }
}

impl BlockDevice for BlkDev {
    fn read_sector(&mut self, lba: u64, buf: &mut [u8]) -> fat32::Result<()> {
        self.inner.rw_sector(lba, buf, false).map_err(|_| fat32::Error::Io)
    }
    fn write_sector(&mut self, lba: u64, buf: &[u8]) -> fat32::Result<()> {
        let mut tmp = [0u8; 512];
        tmp[..512].copy_from_slice(&buf[..512]);
        self.inner.rw_sector(lba, &mut tmp, true).map_err(|_| fat32::Error::Io)
    }
}

/// Get a block device handle for the mounted data disk, if present.
pub fn block_device() -> Option<BlkDev> {
    BLK.lock().as_ref().map(|b| BlkDev::new(b.clone()))
}
