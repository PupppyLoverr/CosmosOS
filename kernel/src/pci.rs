//! Minimal PCI config-space scan (legacy, port 0xCF8/0xCFC).
use x86_64::instructions::port::Port;

fn cfg_addr(bus: u8, dev: u8, fun: u8, off: u8) -> u32 {
    0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((fun as u32) << 8)
        | (off as u32 & 0xFC)
}

pub fn cfg_read32(bus: u8, dev: u8, fun: u8, off: u8) -> u32 {
    unsafe {
        let mut a: Port<u32> = Port::new(0xCF8);
        a.write(cfg_addr(bus, dev, fun, off));
        let mut d: Port<u32> = Port::new(0xCFC);
        d.read()
    }
}

pub fn cfg_read16(bus: u8, dev: u8, fun: u8, off: u8) -> u16 {
    let v = cfg_read32(bus, dev, fun, off & 0xFC);
    ((v >> ((off & 3) * 8)) & 0xFFFF) as u16
}

pub fn cfg_read8(bus: u8, dev: u8, fun: u8, off: u8) -> u8 {
    let v = cfg_read32(bus, dev, fun, off & 0xFC);
    ((v >> ((off & 3) * 8)) & 0xFF) as u8
}

pub fn cfg_write32(bus: u8, dev: u8, fun: u8, off: u8, v: u32) {
    unsafe {
        let mut a: Port<u32> = Port::new(0xCF8);
        a.write(cfg_addr(bus, dev, fun, off));
        let mut d: Port<u32> = Port::new(0xCFC);
        d.write(v);
    }
}

pub fn cfg_write16(bus: u8, dev: u8, fun: u8, off: u8, v: u16) {
    let base = cfg_read32(bus, dev, fun, off & 0xFC);
    let shift = (off & 3) * 8;
    let mask = !(0xFFFFu32 << shift);
    let newv = (base & mask) | ((v as u32) << shift);
    cfg_write32(bus, dev, fun, off & 0xFC, newv);
}

#[derive(Clone, Copy)]
pub struct PciDev {
    pub bus: u8,
    pub dev: u8,
    pub fun: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
}

impl PciDev {
    pub fn bar(&self, i: u8) -> u32 {
        cfg_read32(self.bus, self.dev, self.fun, 0x10 + i * 4)
    }
    /// BAR as an ioport base (bits[1:0] == 01 means IO space).
    pub fn iobar(&self, i: u8) -> u16 {
        (self.bar(i) & !3) as u16
    }
    /// Enable IO-space, memory-space and bus-master DMA.
    pub fn enable(&self) {
        let cmd = cfg_read16(self.bus, self.dev, self.fun, 0x04) | 0x7;
        cfg_write16(self.bus, self.dev, self.fun, 0x04, cmd);
    }
}

/// Enumerate every PCI function on the first 16 buses (the same range the
/// virtio probe uses) into `out`. Returns the number written.
pub fn scan(out: &mut [PciDev]) -> usize {
    let mut n = 0;
    for bus in 0..16u8 {
        for dev in 0..32u8 {
            for fun in 0..8u8 {
                let vendor = cfg_read16(bus, dev, fun, 0x00);
                if vendor == 0xFFFF {
                    continue;
                }
                if n >= out.len() {
                    return n;
                }
                out[n] = PciDev {
                    bus,
                    dev,
                    fun,
                    vendor,
                    device: cfg_read16(bus, dev, fun, 0x02),
                    class: cfg_read8(bus, dev, fun, 0x0B),
                    subclass: cfg_read8(bus, dev, fun, 0x0A),
                };
                n += 1;
                // a non-multifunction device only answers at function 0
                if fun == 0 && cfg_read8(bus, dev, 0, 0x0E) & 0x80 == 0 {
                    break;
                }
            }
        }
    }
    n
}

/// Scan bus 0..=0xFF for a virtio device (vendor 0x1AF4) with the given
/// device-id range (transitional or modern-pci).
pub fn find_virtio(legacy_id: u16, modern_id: u16) -> Option<PciDev> {
    for bus in 0..16u16 {
        for dev in 0..32u8 {
            let vendor = cfg_read16(bus as u8, dev, 0, 0x00);
            if vendor == 0xFFFF {
                continue;
            }
            let device = cfg_read16(bus as u8, dev, 0, 0x02);
            if vendor == 0x1AF4 && (device == legacy_id || device == modern_id) {
                let class = cfg_read8(bus as u8, dev, 0, 0x0B);
                let subclass = cfg_read8(bus as u8, dev, 0, 0x0A);
                return Some(PciDev {
                    bus: bus as u8,
                    dev,
                    fun: 0,
                    vendor,
                    device,
                    class,
                    subclass,
                });
            }
        }
    }
    None
}
