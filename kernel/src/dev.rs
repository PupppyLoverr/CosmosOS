//! /dev pseudo-filesystem — classic Unix device semantics, kernel-side.
//!
//!   /dev/null      reads EOF, writes discarded
//!   /dev/zero      reads zeros (unbounded via fd; bounded via read_all)
//!   /dev/full      reads zeros, writes fail with ENOSPC
//!   /dev/random    reads random bytes (RDRAND when present, else PRNG)
//!   /dev/urandom   same source here — no entropy-pool blocking in this OS
//!   /dev/rtc       reads the current RTC wall-clock (one line of text)
//!   /dev/vda       raw virtio-blk data disk, sector-granular, read-only
//!   /dev/fb0       raw framebuffer pixels (32bpp), read/write at byte offset
//!   /dev/kmsg      kernel log ring: read = tail, write = userspace printk
//!   /dev/console   write = serial + klog (the system console sink)
//!   /dev/mem       raw physical memory via the HHDM map (read-only)
//!   /dev/nvram     128 bytes of CMOS NVRAM, read-only
//!   /dev/smbios    raw SMBIOS table bytes if firmware exports one
//!   /dev/dsp       write u16-LE Hz values -> PC speaker tones (60ms each)
//!
//! fd-granularity reads always produce fresh data (streams never EOF);
//! read_all/stat return a bounded 4KiB snapshot so `cat`/`hex` terminate.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::instructions::port::Port;

const SNAPSHOT: usize = 4096;
const NAMES: [&str; 21] = [
    "null", "zero", "full", "random", "urandom", "rtc", "vda",
    "fb0", "kmsg", "console", "mem", "nvram", "smbios", "dsp",
    "smbios-tables", "port", "loopctl", "loop0", "loop1", "loop2", "loop3",
];

pub fn handles(path: &str) -> bool {
    path == "/dev" || NAMES.iter().any(|n| {
        path.len() == n.len() + 5 && path.starts_with("/dev/") && &path[5..] == *n
    })
}

pub fn is_dir(path: &str) -> bool {
    path == "/dev"
}

pub fn exists(path: &str) -> bool {
    handles(path)
}

pub fn entries() -> Vec<shared::DirEntry> {
    NAMES
        .iter()
        .map(|n| {
            let mut e = shared::DirEntry::default();
            let b = n.as_bytes();
            e.name[..b.len()].copy_from_slice(b);
            e.name_len = b.len() as u8;
            e
        })
        .collect()
}

/// fd-granularity read at byte offset `pos`.
pub fn read_at(path: &str, pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    match &path[5..] {
        "vda" => return vda_read(pos, buf),
        "fb0" => return fb0_read(pos, buf),
        "mem" => return mem_read(pos, buf),
        "nvram" => return nvram_read(pos, buf),
        "smbios" => return smbios_read(pos, buf),
        "smbios-tables" => return smbios_tables_read(pos, buf),
        "port" => return port_read(pos, buf),
        "kmsg" => {
            // stream of the ring tail: pos 0 emits the whole tail, then EOF
            if pos != 0 {
                return Ok(0);
            }
            return Ok(crate::klog::read_tail(buf));
        }
        "rtc" => {
            let d = crate::timer::datetime();
            let s = alloc::format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC\n",
                d.year, d.month, d.day, d.hour, d.minute, d.second
            );
            let b = s.as_bytes();
            let rem = (b.len() as u64).saturating_sub(pos) as usize;
            let n = buf.len().min(rem);
            buf[..n].copy_from_slice(&b[pos as usize..pos as usize + n]);
            return Ok(n);
        }
        _ => {}
    }
    match &path[5..] {
        "null" => Ok(0),
        // zero/full/random are infinite sources — they never EOF and
        // ignore the read offset, matching Linux character devices.
        "zero" | "full" => {
            buf.iter_mut().for_each(|b| *b = 0);
            Ok(buf.len())
        }
        "random" | "urandom" => {
            crate::syscall::rand_fill(buf);
            Ok(buf.len())
        }
        "console" | "dsp" => Ok(0), // write-only sinks; reads EOF
        "loopctl" => loopctl_read(pos, buf),
        p => match p.strip_prefix("loop").and_then(|v| v.parse::<u32>().ok()) {
            Some(n) if n < 4 => loop_read(n, pos, buf),
            _ => Err(-2),
        },
    }
}

/// Byte-level loop devices: /dev/loopN is a byte window over a bound
/// backing file on any real filesystem. /dev/loopctl is the control
/// node — write "bind <n> <path>" or "clear <n>"; read for the table
/// "<n> <size> <path>" per bound loop (newest to oldest sorted by n).
/// (backing path, byte offset, size limit) — offset/limit shrink the
/// loop's window into the file, matching `losetup -o/--sizelimit`.
static LOOPS: Mutex<BTreeMap<u32, (String, u64, u64)>> =
    Mutex::new(BTreeMap::new());

fn loop_read(n: u32, pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let (file, off, lim) = LOOPS.lock().get(&n).cloned().ok_or(-2i64)?;
    if lim != 0 {
        if pos >= lim {
            return Ok(0);
        }
        let take = buf.len().min((lim - pos) as usize);
        return crate::vfs::read_range(&file, off + pos, &mut buf[..take]);
    }
    crate::vfs::read_range(&file, off + pos, buf)
}

fn loop_write_data(n: u32, pos: u64, buf: &[u8]) -> Result<usize, i64> {
    let (file, off, lim) = LOOPS.lock().get(&n).cloned().ok_or(-2i64)?;
    let take = if lim != 0 && pos + buf.len() as u64 > lim {
        lim.saturating_sub(pos) as usize
    } else {
        buf.len()
    };
    if take == 0 {
        return Ok(0);
    }
    let r = crate::vfs::write_range_path(&file, off + pos, &buf[..take])?;
    crate::notify::fire(&file, crate::notify::IN_MODIFY);
    Ok(r)
}

fn loopctl_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let rows: Vec<(u32, String, u64, u64)> = LOOPS
        .lock()
        .iter()
        .map(|(n, (f, o, l))| (*n, f.clone(), *o, *l))
        .collect();
    let mut s = String::new();
    for (n, file, off, lim) in rows {
        let sz = crate::vfs::stat_path(&file).map(|st| st.size).unwrap_or(0);
        s.push_str(&alloc::format!(
            "{} {} {} {} {}\n",
            n, sz, off, lim, file
        ));
    }
    let b = s.as_bytes();
    if pos >= b.len() as u64 {
        return Ok(0);
    }
    let n = buf.len().min(b.len() - pos as usize);
    buf[..n].copy_from_slice(&b[pos as usize..pos as usize + n]);
    Ok(n)
}

fn loopctl_write(buf: &[u8]) -> Result<usize, i64> {
    let s = core::str::from_utf8(buf).map_err(|_| -22i64)?;
    for line in s.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        match it.next() {
            Some("bind") => {
                let n: u32 =
                    it.next().and_then(|v| v.parse().ok()).ok_or(-22i64)?;
                if n >= 4 {
                    return Err(-22);
                }
                let file = it.next().ok_or(-22i64)?;
                // backing must be a real file — not a device/proc/pipe/cgroup
                if handles(file)
                    || crate::proc::handles(file)
                    || crate::pipes::handles(file)
                    || crate::cgroup::handles(file)
                    || crate::memfd::handles(file)
                {
                    return Err(-22);
                }
                let st = crate::vfs::stat_path(file).map_err(|_| -2i64)?;
                if st.size == 0 {
                    return Err(-22);
                }
                // optional trailing fields: "off <u64>" "size <u64>"
                let mut off = 0u64;
                let mut lim = 0u64;
                while let Some(k) = it.next() {
                    match k {
                        "off" => {
                            off = it
                                .next()
                                .and_then(|v| v.parse().ok())
                                .ok_or(-22i64)?
                        }
                        "size" => {
                            lim = it
                                .next()
                                .and_then(|v| v.parse().ok())
                                .ok_or(-22i64)?
                        }
                        _ => return Err(-22),
                    }
                }
                if off >= st.size || (lim != 0 && off + lim > st.size) {
                    return Err(-22);
                }
                LOOPS.lock().insert(n, (String::from(file), off, lim));
            }
            Some("clear") => {
                let n: u32 =
                    it.next().and_then(|v| v.parse().ok()).ok_or(-22i64)?;
                LOOPS.lock().remove(&n);
            }
            _ => return Err(-22),
        }
    }
    Ok(buf.len())
}

/// /dev/smbios-tables: the SMBIOS structure table exactly as QEMU exports
/// it through fw_cfg "etc/smbios/smbios-tables" (what dmidecode parses).
fn smbios_tables_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let data = smbios_tables().ok_or(-2i64)?;
    let rem = (data.len() as u64).saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    if n == 0 {
        return Ok(0);
    }
    buf[..n].copy_from_slice(&data[pos as usize..pos as usize + n]);
    Ok(n)
}

static SMBIOS_TABLES: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// The whole SMBIOS structure table, fetched once and cached.
/// Two real sources, tried in order:
///   1. fw_cfg "etc/smbios/smbios-tables" (newer QEMU exports it whole)
///   2. the anchor's table address/length — the actual dmidecode mechanism —
///      read straight out of physical memory.
fn smbios_tables() -> Option<Vec<u8>> {
    let mut g = SMBIOS_TABLES.lock();
    if let Some(d) = g.as_ref() {
        return Some(d.clone());
    }
    if let Some((sel, size)) = fw_cfg_find("etc/smbios/smbios-tables") {
        if size > 0 && size <= 1 << 20 {
            let mut v = alloc::vec![0u8; size as usize];
            let n = fw_cfg_read(sel, size as usize, 0, &mut v);
            v.truncate(n);
            if n > 0 {
                *g = Some(v.clone());
                return Some(v);
            }
        }
    }
    let (addr, len) = smbios_table_loc()?;
    if len == 0 || len > 1 << 20 {
        return None;
    }
    let mut v = alloc::vec![0u8; len];
    unsafe {
        let src = crate::mem::phys_to_virt(addr) as *const u8;
        core::ptr::copy_nonoverlapping(src, v.as_mut_ptr(), len);
    }
    *g = Some(v.clone());
    Some(v)
}

/// Parse the SMBIOS entry point for (table_addr, table_len) — 2.x anchor
/// carries them in its "_DMI_" intermediate area; 3.x anchor carries a
/// max size and 64-bit address.
fn smbios_table_loc() -> Option<(u64, usize)> {
    // fetch the anchor exactly like smbios_read does
    let mut ep = alloc::vec![0u8; 64];
    let n = if let Some((sel, size)) = fw_cfg_find("etc/smbios/smbios-anchor") {
        fw_cfg_read(sel, size as usize, 0, &mut ep[..(size as usize).min(64)])
    } else if let Some((ep_addr, ep_len)) = smbios_scan() {
        let n = ep_len.min(64);
        unsafe {
            let src = crate::mem::phys_to_virt(ep_addr) as *const u8;
            core::ptr::copy_nonoverlapping(src, ep.as_mut_ptr(), n);
        }
        n
    } else {
        return None;
    };
    let ep = &ep[..n];
    if ep.starts_with(b"_SM3_") && ep.len() >= 24 {
        let len = u32::from_le_bytes(ep[12..16].try_into().ok()?) as usize;
        let addr = u64::from_le_bytes(ep[16..24].try_into().ok()?);
        return Some((addr, len));
    }
    if ep.starts_with(b"_SM_") && ep.len() >= 0x20 {
        // intermediate "_DMI_" section at byte 16: checksum @21,
        // table len @22-23 (u16 LE), table addr @24-27 (u32 LE)
        let len = u16::from_le_bytes(ep[22..24].try_into().ok()?) as usize;
        let addr = u32::from_le_bytes(ep[24..28].try_into().ok()?) as u64;
        return Some((addr, len));
    }
    None
}

/// /dev/port: raw x86 I/O port space — offset is the port number,
/// one byte per `in`/`out` (like Linux /dev/port).
fn port_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    if pos > 0xFFFF {
        return Ok(0);
    }
    let n = buf.len().min((0x10000 - pos) as usize);
    for i in 0..n {
        buf[i] = unsafe {
            x86_64::instructions::port::Port::<u8>::new((pos + i as u64) as u16).read()
        };
    }
    Ok(n)
}

fn port_write(pos: u64, buf: &[u8]) -> Result<usize, i64> {
    if pos > 0xFFFF {
        return Err(-9);
    }
    let n = buf.len().min((0x10000 - pos) as usize);
    for i in 0..n {
        unsafe {
            x86_64::instructions::port::Port::<u8>::new((pos + i as u64) as u16).write(buf[i])
        };
    }
    Ok(n)
}

/// /dev/fb0: raw framebuffer bytes at file offset `pos` (32bpp pixels,
/// row-major over `stride*height*4` bytes).
fn fb0_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let g = crate::fb::FB.lock();
    let f = g.as_ref().ok_or(-2i64)?;
    let size = (f.stride as u64) * (f.height as u64) * 4;
    let rem = size.saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    if n == 0 {
        return Ok(0);
    }
    unsafe {
        let src = crate::mem::phys_to_virt(f.phys + pos) as *const u8;
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
    }
    Ok(n)
}

fn fb0_write(pos: u64, buf: &[u8]) -> Result<usize, i64> {
    let g = crate::fb::FB.lock();
    let f = g.as_ref().ok_or(-2i64)?;
    let size = (f.stride as u64) * (f.height as u64) * 4;
    let rem = size.saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    if n == 0 {
        return Ok(0);
    }
    unsafe {
        let dst = crate::mem::phys_to_virt(f.phys + pos) as *mut u8;
        core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, n);
    }
    Ok(n)
}

/// /dev/mem: raw physical memory at address `pos`, capped at total RAM
/// (the allocator knows the real bound; beyond it is unmapped/ballast).
fn mem_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let (total, _, _) = crate::mem::meminfo();
    let rem = total.saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    if n == 0 {
        return Ok(0);
    }
    unsafe {
        let src = crate::mem::phys_to_virt(pos) as *const u8;
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
    }
    Ok(n)
}

/// /dev/nvram: the 128 bytes of CMOS RAM behind ports 0x70/0x71.
fn nvram_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let rem = (128u64).saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    for i in 0..n {
        let reg = (pos as u8) + i as u8;
        unsafe {
            let mut addr: Port<u8> = Port::new(0x70);
            let mut data: Port<u8> = Port::new(0x71);
            addr.write(reg);
            buf[i] = data.read();
        }
    }
    Ok(n)
}

/// QEMU fw_cfg (ports 0x510 selector / 0x511 data): the real mechanism QEMU
/// uses to hand firmware blobs (SMBIOS, ACPI, etc.) to the guest — OVMF and
/// SeaBIOS both consume it. Returns (selector, size) for a named file.
fn fw_cfg_find(name: &str) -> Option<(u16, u32)> {
    use x86_64::instructions::port::Port;
    unsafe {
        let mut sel: Port<u16> = Port::new(0x510);
        let mut data: Port<u8> = Port::new(0x511);
        sel.write(0x0000); // signature selector
        let mut sig = [0u8; 4];
        for b in &mut sig {
            *b = data.read();
        }
        if &sig != b"QEMU" {
            return None;
        }
        sel.write(0x0019); // FW_CFG_FILE_DIR
        let mut cnt = [0u8; 4];
        for b in &mut cnt {
            *b = data.read();
        }
        let n = u32::from_be_bytes(cnt);
        for _ in 0..n.min(2048) {
            // FWCfgFile: u32 size BE, u16 select BE, u16 reserved, name[56]
            let mut ent = [0u8; 64];
            for b in &mut ent {
                *b = data.read();
            }
            let size = u32::from_be_bytes(ent[0..4].try_into().unwrap());
            let select = u16::from_be_bytes(ent[4..6].try_into().unwrap());
            let end = ent[8..64].iter().position(|&c| c == 0).unwrap_or(56) + 8;
            let nm = core::str::from_utf8(&ent[8..end]).unwrap_or("");
            if nm == name {
                return Some((select, size));
            }
        }
        None
    }
}

/// Read `buf.len()` bytes from fw_cfg file `select` starting at `pos`.
fn fw_cfg_read(select: u16, size: usize, pos: u64, buf: &mut [u8]) -> usize {
    use x86_64::instructions::port::Port;
    unsafe {
        let mut sel: Port<u16> = Port::new(0x510);
        let mut data: Port<u8> = Port::new(0x511);
        sel.write(select);
        let mut skip = pos;
        while skip > 0 {
            let _ = data.read();
            skip -= 1;
        }
        let mut n = 0usize;
        while n < buf.len() && pos as usize + n < size {
            buf[n] = data.read();
            n += 1;
        }
        n
    }
}

/// /dev/smbios: locate the SMBIOS entry point ("_SM3_" 3.x or "_SM_" 2.x
/// anchor) in the legacy F-segment 0xF0000..0x100000 and expose its raw
/// entry-point bytes — the real firmware artifact. The structure table it
/// points at is readable through /dev/mem. ENOENT when absent.
fn smbios_scan() -> Option<(u64, usize)> {
    let base = crate::mem::phys_to_virt(0xF0000) as *const u8;
    let mut i = 0usize;
    while i + 0x20 <= 0x10000 {
        unsafe {
            let p = base.add(i);
            let ep_len = if *p == b'_'
                && *p.add(1) == b'S'
                && *p.add(2) == b'M'
                && *p.add(3) == b'3'
                && *p.add(4) == b'_'
            {
                // 3.x anchor: "_SM3_", checksum@0x05, ep_len@0x06
                *p.add(6) as usize
            } else if *p == b'_'
                && *p.add(1) == b'S'
                && *p.add(2) == b'M'
                && *p.add(3) == b'_'
            {
                // 2.x anchor: "_SM_", ep_len@0x05
                *p.add(5) as usize
            } else {
                i += 0x10;
                continue;
            };
            if ep_len < 0x10 || ep_len > 0x40 {
                i += 0x10;
                continue;
            }
            let mut sum = 0u8;
            for j in 0..ep_len {
                sum = sum.wrapping_add(*p.add(j));
            }
            if sum == 0 {
                return Some((0xF0000 + i as u64, ep_len));
            }
        }
        i += 0x10;
    }
    None
}

fn smbios_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    // QEMU hands the entry point to the guest through fw_cfg first
    // ("etc/smbios/smbios-anchor"); fall back to the legacy F-segment scan
    // for boots where the firmware installs the anchor there.
    if let Some((sel, size)) = fw_cfg_find("etc/smbios/smbios-anchor") {
        let rem = (size as u64).saturating_sub(pos) as usize;
        let n = buf.len().min(rem);
        return Ok(fw_cfg_read(sel, size as usize, pos, &mut buf[..n]));
    }
    let (ep_addr, ep_len) = smbios_scan().ok_or(-2i64)?;
    let rem = (ep_len as u64).saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    unsafe {
        let src = crate::mem::phys_to_virt(ep_addr + pos) as *const u8;
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
    }
    Ok(n)
}

/// Raw disk read at byte offset `pos` (512B-granular). Read-only: writes
/// return EROFS below. EOF is the real end of the disk — no artificial cap.
fn vda_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    use fat32::BlockDevice;
    let mut d = match crate::virtio::block_device() {
        Some(d) => d,
        None => return Err(-2),
    };
    let cap = d.capacity_sectors() * 512;
    let rem = cap.saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    if n == 0 {
        return Ok(0);
    }
    // sector-window copy: read each covered sector wholesale
    let mut off = 0usize;
    while off < n {
        let sec = (pos + off as u64) / 512;
        let s_off = (pos + off as u64) % 512;
        let mut tmp = [0u8; 512];
        d.read_sector(sec, &mut tmp).map_err(|_| -1i64)?;
        let take = (n - off).min((512 - s_off) as usize);
        buf[off..off + take].copy_from_slice(&tmp[s_off as usize..s_off as usize + take]);
        off += take;
    }
    Ok(n)
}

/// Bounded snapshot for whole-file readers (read_all/stat) — caps
/// `cat /dev/urandom`-style consumers at 4KiB so they terminate.
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    match &path[5..] {
        "null" => Some(Vec::new()),
        _ => {
            let mut v = alloc::vec![0u8; SNAPSHOT];
            read_at(path, 0, &mut v).ok()?;
            Some(v)
        }
    }
}

/// Write: null/zero discard and report success; full -> ENOSPC;
/// vda/rtc/mem/nvram/smbios are read-only (EROFS).
/// kmsg/console append to the kernel log (userspace printk);
/// fb0 writes raw pixels at `pos`; dsp turns u16-LE Hz values into tones.
pub fn write(path: &str, pos: u64, buf: &[u8]) -> Result<usize, i64> {
    let len = buf.len();
    match &path[5..] {
        "null" | "zero" => Ok(len),
        "full" => Err(-28), // ENOSPC
        "vda" | "rtc" | "mem" | "nvram" | "smbios" => Err(-30), // EROFS
        "random" | "urandom" => Ok(len), // accepted, ignored (like a seed write)
        "loopctl" => loopctl_write(buf),
        "fb0" => fb0_write(pos, buf),
        "port" => port_write(pos, buf),
        "kmsg" | "console" => {
            // userspace printk: into the klog ring and out the serial port
            let s = String::from_utf8_lossy(buf);
            crate::klog::append(&alloc::format!("[user] {}", s.trim_end()));
            for &b in buf {
                crate::serial::write_byte(b);
            }
            Ok(len)
        }
        "dsp" => {
            // pairs of little-endian u16 = Hz; each tone plays 60ms.
            // Odd trailing byte is ignored (a tone needs a full u16).
            // Bounded: a write may consume at most 64 tones (~4 s) — a
            // partial write is POSIX-legal and keeps a huge `cat > dsp`
            // from monopolising the syscall.
            let mut i = 0usize;
            while i + 1 < buf.len() && i < 128 {
                let freq = u16::from_le_bytes([buf[i], buf[i + 1]]) as u32;
                if freq > 0 {
                    crate::timer::beep(freq, 60);
                    let deadline = crate::task::ticks() + 7;
                    while crate::task::ticks() < deadline {
                        // syscall gate runs with interrupts off: sti+hlt so
                        // the PIT tick can actually fire and advance time
                        x86_64::instructions::interrupts::enable_and_hlt();
                    }
                }
                i += 2;
            }
            Ok(if i == 0 { len } else { i })
        }
        p => match p.strip_prefix("loop").and_then(|v| v.parse::<u32>().ok()) {
            Some(n) if n < 4 => loop_write_data(n, pos, buf),
            _ => Err(-4),
        },
    }
}
