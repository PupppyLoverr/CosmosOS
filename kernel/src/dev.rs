//! /dev pseudo-filesystem — classic Unix device semantics, kernel-side.
//!
//!   /dev/null      reads EOF, writes discarded
//!   /dev/zero      reads zeros (unbounded via fd; bounded via read_all)
//!   /dev/full      reads zeros, writes fail with ENOSPC
//!   /dev/random    reads random bytes (RDRAND when present, else PRNG)
//!   /dev/urandom   same source here — no entropy-pool blocking in this OS
//!
//! fd-granularity reads always produce fresh data (streams never EOF);
//! read_all/stat return a bounded 4KiB snapshot so `cat`/`hex` terminate.

use alloc::vec::Vec;

const SNAPSHOT: usize = 4096;
const NAMES: [&str; 5] = ["null", "zero", "full", "random", "urandom"];

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

/// Write: null/zero discard and report success; full -> ENOSPC.
pub fn write(path: &str, len: usize) -> Result<usize, i64> {
    match &path[5..] {
        "null" | "zero" => Ok(len),
        "full" => Err(-28), // ENOSPC
        "random" | "urandom" => Ok(len), // accepted, ignored (like a seed write)
        _ => Err(-4),
    }
}
