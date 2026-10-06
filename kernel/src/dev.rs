//! /dev pseudo-filesystem — classic Unix device semantics, kernel-side.
//!
//!   /dev/null      reads EOF, writes discarded
//!   /dev/zero      reads zeros (unbounded via fd; bounded via read_all)
//!   /dev/full      reads zeros, writes fail with ENOSPC
//!   /dev/random    reads random bytes (RDRAND when present, else PRNG)
//!   /dev/urandom   same source here — no entropy-pool blocking in this OS
//!   /dev/rtc       reads the current RTC wall-clock (one line of text)
//!   /dev/vda       raw virtio-blk data disk, sector-granular, read-only
//!
//! fd-granularity reads always produce fresh data (streams never EOF);
//! read_all/stat return a bounded 4KiB snapshot so `cat`/`hex` terminate.

use alloc::vec::Vec;

const SNAPSHOT: usize = 4096;
/// /dev/vda caps a single open at 1 MiB (cat-style readers terminate).
const VDA_SNAPSHOT: usize = 1 << 20;
const NAMES: [&str; 7] = ["null", "zero", "full", "random", "urandom", "rtc", "vda"];

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

/// fd-granularity read: each open fd yields a bounded SNAPSHOT-byte
/// virtual stream (EOF at pos >= 4KiB) so consumers terminate.
/// /dev/null always EOFs.
pub fn read_at(path: &str, pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    if &path[5..] == "vda" {
        return vda_read(pos, buf);
    }
    if &path[5..] == "rtc" {
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
    let rem = (SNAPSHOT as u64).saturating_sub(pos) as usize;
    let n = buf.len().min(rem);
    match &path[5..] {
        "null" => Ok(0),
        "zero" | "full" => {
            buf[..n].iter_mut().for_each(|b| *b = 0);
            Ok(n)
        }
        "random" | "urandom" => {
            crate::syscall::rand_fill(&mut buf[..n]);
            Ok(n)
        }
        _ => Err(-2),
    }
}

/// Raw disk read at byte offset `pos` (512B-granular), capped at 1 MiB
/// per open. Read-only: writes return EROFS below.
fn vda_read(pos: u64, buf: &mut [u8]) -> Result<usize, i64> {
    use fat32::BlockDevice;
    let mut d = match crate::virtio::block_device() {
        Some(d) => d,
        None => return Err(-2),
    };
    let cap = (d.capacity_sectors() * 512).min(VDA_SNAPSHOT as u64);
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

/// Write: null/zero discard and report success; full -> ENOSPC,
/// vda/rtc are read-only (EROFS).
pub fn write(path: &str, len: usize) -> Result<usize, i64> {
    match &path[5..] {
        "null" | "zero" => Ok(len),
        "full" => Err(-28), // ENOSPC
        "vda" | "rtc" => Err(-30), // EROFS
        "random" | "urandom" => Ok(len), // accepted, ignored (like a seed write)
        _ => Err(-4),
    }
}
