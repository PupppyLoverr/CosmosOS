//! virtio-net (legacy, PCI) network device driver.
//! Two vrings (rx=0, tx=1), legacy io-port init like virtio-blk.
//! RX buffers are pre-posted packet frames; the IRQ path only acks+drains.
use crate::mem;
use crate::pci;
use crate::sprintln;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

// legacy virtio io-port offsets (shared with virtio-blk)
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

const DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const RX_BUFS: usize = 8;
const PKT_SZ: usize = 2048; // 10B virtio-net hdr + up to 1514B frame + slack
const VNET_HDR: usize = 10; // legacy virtio-net header (no features negotiated)

/// virtio-net legacy queue layout: each queue's PFN points at the start of
/// its own [desc][avail][pad page][used] block. We allocate one contiguous
/// DMA region holding both queue blocks plus the packet buffers.
pub struct VirtioNet {
    iobase: u16,
    dma_base: u64,
    dma_virt: u64,
    rx_avail: u64, // rx-queue-relative offsets (rx block base = dma_virt)
    rx_used: u64,
    tx_off: u64,   // absolute offset of the tx queue block
    tx_avail: u64, // tx-queue-relative offsets
    tx_used: u64,
    rx_bufs: u64,  // absolute region offset of RX_BUFS*PKT_SZ packet space
    tx_frame: u64, // absolute region offset of the single tx staging buffer
    rxq: u16, // device-advertised rx queue size (avail-ring wrap modulus)
    rx_last: AtomicU16,
    tx_last: AtomicU16,
    pub mac: [u8; 6],
}

pub static NET: Mutex<Option<Arc<VirtioNet>>> = Mutex::new(None);
/// Packets drained by IRQ outside of an explicit wait, for the net stack.
pub static RX_QUEUE: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

pub fn init() -> bool {
    // legacy transitional id 0x1000 (net), modern 0x1041
    let Some(d) = pci::find_virtio(0x1000, 0x1041) else {
        sprintln!("[virtio-net] no net device");
        return false;
    };
    sprintln!(
        "[virtio-net] dev {:02x}:{:02x} ven {:04x} dev {:04x}",
        d.bus, d.dev, d.vendor, d.device
    );
    d.enable();
    let iobase = d.iobar(0);
    if iobase == 0 {
        sprintln!("[virtio-net] bad iobar");
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

        // accept no features: 10B legacy header, no mergeable buffers/csum
        let mut guest: Port<u32> = Port::new(iobase + R_GUEST_FEATURES);
        guest.write(0);

        let mut qsel: Port<u16> = Port::new(iobase + R_QSEL);
        let mut qsize_port: Port<u16> = Port::new(iobase + R_QSIZE);
        qsel.write(0);
        let rxq = qsize_port.read() as usize;
        qsel.write(1);
        let txq = qsize_port.read() as usize;
        if rxq < RX_BUFS || txq < 2 {
            sprintln!("[virtio-net] queues too small rx={} tx={}", rxq, txq);
            return false;
        }

        // ---- DMA layout ----
        let page = 0x1000u64;
        let rx_avail_sz = 4 + rxq * 2;
        let rx_used_sz = 4 + rxq * 8;
        let tx_avail_sz = 4 + txq * 2;
        let tx_used_sz = 4 + txq * 8;

        let rx_avail_off = (rxq * 16) as u64;                     // after rx desc
        let rx_used_off = align_up(rx_avail_off + rx_avail_sz as u64, page);
        let tx_off = align_up(rx_used_off + rx_used_sz as u64, page); // tx block
        let tx_avail_off = (txq * 16) as u64;                     // tx-block-relative
        let tx_used_off = align_up(tx_avail_off + tx_avail_sz as u64, page);
        let rx_bufs_off = tx_off + align_up(tx_used_off + tx_used_sz as u64, page);
        let tx_frame_off = rx_bufs_off + (RX_BUFS * PKT_SZ) as u64;
        let total = align_up(tx_frame_off + PKT_SZ as u64, page);
        let pages = (total / page) as usize;

        let Some(base_phys) = mem::alloc_contig(pages) else {
            sprintln!("[virtio-net] no contiguous dma region");
            return false;
        };
        let virt = mem::phys_to_virt(base_phys);
        core::ptr::write_bytes(virt as *mut u8, 0, total as usize);

        let mut qaddr: Port<u32> = Port::new(iobase + R_QADDR);
        qsel.write(0);
        qaddr.write((base_phys >> 12) as u32);                    // rx block at +0
        qsel.write(1);
        qaddr.write(((base_phys + tx_off) >> 12) as u32);         // tx block at +tx_off

        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            let mut p: Port<u8> = Port::new(iobase + R_CONFIG + i as u16);
            *b = p.read();
        }

        status_port.write(S_ACK | S_DRIVER | S_DRVOK);

        let dev = Arc::new(VirtioNet {
            iobase,
            dma_base: base_phys,
            dma_virt: virt,
            rx_avail: rx_avail_off,
            rx_used: rx_used_off,
            tx_off,
            tx_avail: tx_avail_off,
            tx_used: tx_used_off,
            rx_bufs: rx_bufs_off,
            tx_frame: tx_frame_off,
            rxq: rxq as u16,
            rx_last: AtomicU16::new(0),
            tx_last: AtomicU16::new(0),
            mac,
        });
        dev.post_rx_all();
        *NET.lock() = Some(dev.clone());
        sprintln!(
            "[virtio-net] ready: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} iobase={:#x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], iobase
        );
        true
    }
}

impl VirtioNet {
    fn rx_base(&self) -> u64 {
        self.dma_virt
    }
    fn tx_base(&self) -> u64 {
        self.dma_virt + self.tx_off
    }
    fn rdq<T: Copy>(&self, qbase: u64, off: u64) -> T {
        unsafe { (qbase as *const u8).add(off as usize).cast::<T>().read_volatile() }
    }
    fn wrq<T: Copy>(&self, qbase: u64, off: u64, v: T) {
        unsafe { (qbase as *mut u8).add(off as usize).cast::<T>().write_volatile(v) }
    }

    fn rx_avail_idx(&self) -> u16 {
        self.rdq(self.rx_base(), self.rx_avail + 2)
    }
    fn set_rx_avail_idx(&self, v: u16) {
        self.wrq(self.rx_base(), self.rx_avail + 2, v);
    }
    fn rx_used_idx(&self) -> u16 {
        self.rdq(self.rx_base(), self.rx_used + 2)
    }
    fn rx_used_id(&self, i: usize) -> u32 {
        self.rdq(self.rx_base(), self.rx_used + 4 + (i as u64) * 8)
    }
    fn rx_used_len(&self, i: usize) -> u32 {
        self.rdq(self.rx_base(), self.rx_used + 8 + (i as u64) * 8)
    }
    fn tx_avail_idx(&self) -> u16 {
        self.rdq(self.tx_base(), self.tx_avail + 2)
    }
    fn set_tx_avail_idx(&self, v: u16) {
        self.wrq(self.tx_base(), self.tx_avail + 2, v);
    }
    fn tx_used_idx(&self) -> u16 {
        self.rdq(self.tx_base(), self.tx_used + 2)
    }

    fn set_rx_desc(&self, i: usize, d: VringDesc) {
        self.wrq(self.rx_base(), (i * 16) as u64, d);
    }
    fn set_tx_desc(&self, i: usize, d: VringDesc) {
        self.wrq(self.tx_base(), (i * 16) as u64, d);
    }
    fn notify(&self, q: u16) {
        unsafe {
            let mut p: Port<u16> = Port::new(self.iobase + R_QNOTIFY);
            p.write(q);
        }
    }

    /// Fill the rx avail ring with buffers 0..RX_BUFS (one desc each).
    fn post_rx_all(&self) {
        let ai = self.rx_avail_idx();
        for i in 0..RX_BUFS {
            self.set_rx_desc(
                i,
                VringDesc {
                    addr: self.dma_base + self.rx_bufs + (i * PKT_SZ) as u64,
                    len: PKT_SZ as u32,
                    flags: DESC_F_WRITE,
                    next: 0,
                },
            );
            self.wrq(
                self.rx_base(),
                self.rx_avail + 4 + (((ai + i as u16) % self.rxq) as u64) * 2,
                i as u16,
            );
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        self.set_rx_avail_idx(ai.wrapping_add(RX_BUFS as u16));
        core::sync::atomic::fence(Ordering::SeqCst);
        self.notify(0);
    }

    /// Drain received frames into `out`. Returns count drained.
    pub fn drain_rx(&self, out: &mut Vec<Vec<u8>>) -> usize {
        let mut n = 0;
        loop {
            let used = self.rx_used_idx();
            let last = self.rx_last.load(Ordering::SeqCst);
            if used == last {
                break;
            }
            let i = (last % self.rxq) as usize;
            let id = self.rx_used_id(i) as usize;
            let len = self.rx_used_len(i) as usize;
            self.rx_last.store(last.wrapping_add(1), Ordering::SeqCst);
            if id < RX_BUFS && len > VNET_HDR && len <= PKT_SZ {
                let src = self.dma_virt + self.rx_bufs + (id * PKT_SZ) as u64 + VNET_HDR as u64;
                let frame =
                    unsafe { core::slice::from_raw_parts(src as *const u8, len - VNET_HDR) };
                out.push(frame.to_vec());
            }
            // repost the buffer
            let ai = self.rx_avail_idx();
            self.wrq(
                self.rx_base(),
                self.rx_avail + 4 + ((ai % self.rxq) as u64) * 2,
                id as u16,
            );
            core::sync::atomic::fence(Ordering::SeqCst);
            self.set_rx_avail_idx(ai.wrapping_add(1));
            core::sync::atomic::fence(Ordering::SeqCst);
            self.notify(0);
            n += 1;
        }
        n
    }

    /// Send one ethernet frame (caller supplies the full frame incl. eth hdr).
    pub fn send(&self, frame: &[u8]) -> Result<(), ()> {
        if frame.len() > PKT_SZ - VNET_HDR {
            return Err(());
        }
        unsafe {
            let dst = self.dma_virt + self.tx_frame;
            core::ptr::write_bytes(dst as *mut u8, 0, VNET_HDR);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                (dst + VNET_HDR as u64) as *mut u8,
                frame.len(),
            );
            self.set_tx_desc(
                0,
                VringDesc {
                    addr: self.dma_base + self.tx_frame,
                    len: (VNET_HDR + frame.len()) as u32,
                    flags: 0,
                    next: 0,
                },
            );
            let ai = self.tx_avail_idx();
            self.wrq(
                self.tx_base(),
                self.tx_avail + 4 + ((ai as usize) % 2) as u64 * 2,
                0u16,
            );
            core::sync::atomic::fence(Ordering::SeqCst);
            self.set_tx_avail_idx(ai.wrapping_add(1));
            core::sync::atomic::fence(Ordering::SeqCst);
            self.notify(1);
            // poll for the used element (device consumes immediately)
            let start = self.tx_last.load(Ordering::SeqCst);
            for _ in 0..10_000_000u64 {
                if self.tx_used_idx() != start {
                    self.tx_last.store(self.tx_used_idx(), Ordering::SeqCst);
                    break;
                }
                core::hint::spin_loop();
            }
        }
        Ok(())
    }
}

pub fn on_irq() {
    if let Some(n) = NET.lock().clone() {
        unsafe {
            let mut isr: Port<u8> = Port::new(n.iobase + R_ISR);
            let _ = isr.read();
        }
        let mut q = RX_QUEUE.lock();
        n.drain_rx(&mut q);
    }
}

/// Net stack drains this: frames received via IRQ.
pub fn take_rx() -> Vec<Vec<u8>> {
    let mut q = RX_QUEUE.lock();
    core::mem::take(&mut *q)
}
