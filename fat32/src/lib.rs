//! cosmos-fat32: a compact FAT32 implementation with read/write support.
//! no_std + alloc; drives any `BlockDevice` (sector size 512).
//!
//! Supports: mount, path resolve ("." / ".."), readdir, stat, read file,
//! write file (grow/truncate), create, mkdir, remove file, rmdir, rename,
//! LFN names, timestamps via a caller-provided clock.
#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

pub const SECTOR: usize = 512;
const EOC: u32 = 0x0FFF_FFF8; // end-of-chain threshold
const FREE: u32 = 0;
const ATTR_DIR: u8 = 0x10;
const ATTR_LFN: u8 = 0x0F;
const MAX_NAME: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    NotFound,
    NotDir,
    Exists,
    NoSpace,
    NotEmpty,
    InvalidFs,
    BadPath,
    NameTooLong,
}

pub type Result<T> = core::result::Result<T, Error>;

/// A 512-byte-sector block device.
pub trait BlockDevice {
    fn read_sector(&mut self, lba: u64, buf: &mut [u8]) -> Result<()>;
    fn write_sector(&mut self, lba: u64, buf: &[u8]) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u64, // unix seconds
    pub attr: u8,   // FAT attribute byte (0x01 ro, 0x02 hidden, 0x04 sys, 0x10 dir)
}

#[derive(Clone, Copy)]
struct Bpb {
    sec_per_clus: u8,
    reserved: u16,
    num_fats: u8,
    fat_secs: u32,
    root_clus: u32,
    total_secs: u32,
}

#[derive(Clone)]
struct RawEntry {
    name: String,
    attr: u8,
    first_cluster: u32,
    size: u32,
    mtime: u64,
    slot_cluster: u32, // cluster containing the primary dir entry
    slot_offset: usize, // byte offset of primary entry within that cluster
    lfn_start: usize,   // entry index within its dir block where LFN chain begins
    lfn_count: usize,
}

pub struct Fat32<D: BlockDevice> {
    dev: D,
    bpb: Bpb,
    clus_bytes: usize,
    next_free: u32,
    time_fn: fn() -> u64,
    /// Whole File Allocation Table held in RAM — sector reads for every
    /// FAT entry made large-file reads quadratic (a full chain re-walk per
    /// clustered read). `fat_read` becomes an index; `fat_write` updates
    /// both the cache and both on-disk copies. None until first use.
    fat_ram: Option<Vec<u32>>,
}

impl<D: BlockDevice> Fat32<D> {
    pub fn mount(mut dev: D) -> Result<Self> {
        let mut s0 = [0u8; SECTOR];
        dev.read_sector(0, &mut s0)?;
        if s0[510] != 0x55 || s0[511] != 0xAA {
            return Err(Error::InvalidFs);
        }
        let bytes_per_sec = u16::from_le_bytes([s0[11], s0[12]]);
        if bytes_per_sec as usize != SECTOR {
            return Err(Error::InvalidFs);
        }
        let bpb = Bpb {
            sec_per_clus: s0[13],
            reserved: u16::from_le_bytes([s0[14], s0[15]]),
            num_fats: s0[16],
            fat_secs: u32::from_le_bytes([s0[36], s0[37], s0[38], s0[39]]),
            root_clus: u32::from_le_bytes([s0[44], s0[45], s0[46], s0[47]]),
            total_secs: u32::from_le_bytes([s0[32], s0[33], s0[34], s0[35]]),
        };
        if bpb.sec_per_clus == 0 || bpb.fat_secs == 0 || bpb.root_clus < 2 {
            return Err(Error::InvalidFs);
        }
        Ok(Fat32 {
            clus_bytes: bpb.sec_per_clus as usize * SECTOR,
            bpb,
            dev,
            next_free: 2,
            time_fn: || 0,
            fat_ram: None,
        })
    }

    /// Bytes per cluster on this volume.
    pub fn cluster_bytes(&self) -> u64 {
        self.clus_bytes as u64
    }

    /// Total data clusters: sectors after reserved+FAT, floored to clusters.
    pub fn total_clusters(&self) -> u64 {
        let data_secs = self
            .bpb
            .total_secs
            .saturating_sub(self.bpb.reserved as u32 + self.bpb.num_fats as u32 * self.bpb.fat_secs);
        (data_secs / self.bpb.sec_per_clus as u32) as u64
    }

    /// Real free-cluster count: one sequential sector-walk of the FAT.
    pub fn free_clusters(&mut self) -> Result<u64> {
        let mut free = 0u64;
        let mut sec = [0u8; SECTOR];
        let nclusters = self.total_clusters();
        for s in 0..self.bpb.fat_secs as u64 {
            let lba = self.bpb.reserved as u64 + s;
            self.dev.read_sector(lba, &mut sec)?;
            for i in 0..SECTOR / 4 {
                let idx = s * (SECTOR / 4) as u64 + i as u64;
                if idx < 2 || idx >= 2 + nclusters {
                    continue;
                }
                let v = u32::from_le_bytes([sec[i * 4], sec[i * 4 + 1], sec[i * 4 + 2], sec[i * 4 + 3]])
                    & 0x0FFF_FFFF;
                if v == FREE {
                    free += 1;
                }
            }
        }
        Ok(free)
    }

    pub fn set_time_fn(&mut self, f: fn() -> u64) {
        self.time_fn = f;
    }

    fn now(&self) -> u64 {
        (self.time_fn)()
    }

    // ---- low level -------------------------------------------------------
    fn cluster_lba(&self, c: u32) -> u64 {
        let first_data = self.bpb.reserved as u64 + self.bpb.num_fats as u64 * self.bpb.fat_secs as u64;
        first_data + (c as u64 - 2) * self.bpb.sec_per_clus as u64
    }

    fn read_cluster(&mut self, c: u32, buf: &mut [u8]) -> Result<()> {
        let lba = self.cluster_lba(c);
        for i in 0..self.bpb.sec_per_clus as u64 {
            self.dev.read_sector(lba + i, &mut buf[i as usize * SECTOR..(i as usize + 1) * SECTOR])?;
        }
        Ok(())
    }

    fn write_cluster(&mut self, c: u32, buf: &[u8]) -> Result<()> {
        let lba = self.cluster_lba(c);
        for i in 0..self.bpb.sec_per_clus as u64 {
            self.dev.write_sector(lba + i, &buf[i as usize * SECTOR..(i as usize + 1) * SECTOR])?;
        }
        Ok(())
    }

    /// Load FAT1 into `fat_ram` on first use (~`fat_secs`*512B).
    fn ensure_fat_ram(&mut self) -> Result<()> {
        if self.fat_ram.is_some() {
            return Ok(());
        }
        let n = self.bpb.fat_secs as usize * (SECTOR / 4);
        let mut fat = Vec::with_capacity(n);
        let mut sec = [0u8; SECTOR];
        for s in 0..self.bpb.fat_secs {
            self.dev.read_sector(self.bpb.reserved as u64 + s as u64, &mut sec)?;
            for w in sec.chunks_exact(4) {
                fat.push(u32::from_le_bytes([w[0], w[1], w[2], w[3]]) & 0x0FFF_FFFF);
            }
        }
        self.fat_ram = Some(fat);
        Ok(())
    }

    fn fat_read(&mut self, cluster: u32) -> Result<u32> {
        self.ensure_fat_ram()?;
        Ok(self
            .fat_ram
            .as_ref()
            .and_then(|f| f.get(cluster as usize).copied())
            .unwrap_or(0x0FFF_FFFF))
    }

    fn fat_write(&mut self, cluster: u32, val: u32) -> Result<()> {
        let fat_off = cluster as u64 * 4;
        if let Some(fat) = self.fat_ram.as_mut() {
            if let Some(e) = fat.get_mut(cluster as usize) {
                *e = val & 0x0FFF_FFFF;
            }
        }
        for f in 0..self.bpb.num_fats {
            let lba = self.bpb.reserved as u64 + f as u64 * self.bpb.fat_secs as u64 + fat_off / SECTOR as u64;
            let mut sec = [0u8; SECTOR];
            self.dev.read_sector(lba, &mut sec)?;
            let off = (fat_off % SECTOR as u64) as usize;
            let cur = u32::from_le_bytes([sec[off], sec[off + 1], sec[off + 2], sec[off + 3]]);
            let nv = (cur & 0xF000_0000) | (val & 0x0FFF_FFFF);
            sec[off..off + 4].copy_from_slice(&nv.to_le_bytes());
            self.dev.write_sector(lba, &sec)?;
        }
        Ok(())
    }

    fn chain(&mut self, start: u32) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut c = start;
        let mut guard = 0u32;
        while c >= 2 && c < EOC {
            out.push(c);
            guard += 1;
            if guard > (self.bpb.total_secs / self.bpb.sec_per_clus as u32) + 8 {
                return Err(Error::InvalidFs); // corrupt loop
            }
            c = self.fat_read(c)?;
        }
        Ok(out)
    }

    fn alloc_cluster(&mut self) -> Result<u32> {
        // scan FAT for a FREE entry starting at next_free hint
        let max = 2 + self.bpb.total_secs / self.bpb.sec_per_clus as u32;
        let mut c = self.next_free.max(2);
        let mut scanned = 0u32;
        loop {
            if self.fat_read(c)? == FREE {
                self.fat_write(c, EOC)?;
                self.next_free = c + 1;
                return Ok(c);
            }
            c += 1;
            if c >= max {
                c = 2;
            }
            scanned += 1;
            if scanned >= max {
                return Err(Error::NoSpace);
            }
        }
    }

    fn free_chain(&mut self, start: u32) -> Result<()> {
        if start < 2 {
            return Ok(());
        }
        let ch = self.chain(start)?;
        for c in ch {
            self.fat_write(c, FREE)?;
        }
        Ok(())
    }

    /// Ensure `chain_start`'s file has capacity for `size` bytes; returns chain.
    fn ensure_capacity(&mut self, chain_start: u32, size: u64) -> Result<Vec<u32>> {
        let need = size.div_ceil(self.clus_bytes as u64).max(1) as usize;
        let mut ch = if chain_start >= 2 { self.chain(chain_start)? } else { Vec::new() };
        while ch.len() < need {
            let c = self.alloc_cluster()?;
            let zeros = vec![0u8; self.clus_bytes];
            self.write_cluster(c, &zeros)?;
            if let Some(&prev) = ch.last() {
                self.fat_write(prev, c)?;
            }
            ch.push(c);
        }
        Ok(ch)
    }

    fn truncate_chain(&mut self, chain_start: u32, size: u64) -> Result<u32> {
        // returns new first cluster (0 if empty)
        let keep = size.div_ceil(self.clus_bytes as u64) as usize;
        let ch = self.chain(chain_start)?;
        if keep == 0 {
            self.free_chain(chain_start)?;
            return Ok(0);
        }
        if ch.len() > keep {
            let tail = ch[keep];
            self.fat_write(ch[keep - 1], EOC)?;
            self.free_chain(tail)?;
        }
        Ok(chain_start)
    }

    // ---- directory layer -------------------------------------------------
    fn read_dir_block(&mut self, dir_cluster: u32) -> Result<Vec<u8>> {
        let ch = self.chain(dir_cluster)?;
        let mut data = Vec::with_capacity(ch.len() * self.clus_bytes);
        let mut buf = vec![0u8; self.clus_bytes];
        for c in ch {
            self.read_cluster(c, &mut buf)?;
            data.extend_from_slice(&buf);
        }
        Ok(data)
    }

    fn write_dir_entry(&mut self, cluster: u32, offset: usize, entry: &[u8; 32]) -> Result<()> {
        let mut buf = vec![0u8; self.clus_bytes];
        self.read_cluster(cluster, &mut buf)?;
        buf[offset..offset + 32].copy_from_slice(entry);
        self.write_cluster(cluster, &buf)
    }

    fn read_dir_entry(&mut self, cluster: u32, offset: usize) -> Result<[u8; 32]> {
        let mut buf = vec![0u8; self.clus_bytes];
        self.read_cluster(cluster, &mut buf)?;
        let mut e = [0u8; 32];
        e.copy_from_slice(&buf[offset..offset + 32]);
        Ok(e)
    }

    /// List a directory's raw entries (skips . .. deleted, decodes LFN).
    fn scan_dir(&mut self, dir_cluster: u32) -> Result<Vec<RawEntry>> {
        let data = self.read_dir_block(dir_cluster)?;
        let mut out = Vec::new();
        let mut lfn: Vec<u16> = Vec::new(); // accumulated UCS-2 units
        let mut lfn_start = 0usize;
        let mut lfn_count = 0usize;
        let mut idx = 0usize;
        let chain = self.chain(dir_cluster)?;
        let clus_size = self.clus_bytes;
        while idx + 32 <= data.len() {
            let e = &data[idx..idx + 32];
            if e[0] == 0x00 {
                break; // end of dir
            }
            if e[0] == 0xE5 {
                idx += 32;
                continue;
            }
            let attr = e[11];
            if attr == ATTR_LFN {
                if lfn.is_empty() {
                    lfn_start = idx / 32;
                }
                lfn_count += 1;
                // collect 13 u16 units in order 1..10,14..25,28..31
                for &off in &[1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
                    lfn.push(u16::from_le_bytes([e[off], e[off + 1]]));
                }
                idx += 32;
                continue;
            }
            if attr & 0x08 != 0 {
                // volume label
                idx += 32;
                lfn.clear();
                lfn_count = 0;
                continue;
            }
            let name = if !lfn.is_empty() {
                // LFN entries are stored last-chunk-first on disk: each 32B
                // entry holds 13 UCS-2 units, and the entry physically first
                // contains the name's tail. Reverse at 13-unit granularity.
                let mut units: Vec<u16> = Vec::with_capacity(lfn.len());
                for chunk in lfn.chunks(13).rev() {
                    units.extend_from_slice(chunk);
                }
                decode_lfn(&units)
            } else {
                decode_short(&e[0..11])
            };
            lfn.clear();
            lfn_count = 0;
            if name == "." || name == ".." {
                idx += 32;
                continue;
            }
            let first_cluster = (u16::from_le_bytes([e[20], e[21]]) as u32) << 16
                | u16::from_le_bytes([e[26], e[27]]) as u32;
            let mtime = dos_to_unix(
                u16::from_le_bytes([e[24], e[25]]),
                u16::from_le_bytes([e[22], e[23]]),
            );
            // Append-only (chattr +a / FS_APPEND_FL): persisted as bit 0x20
            // of the NT-reserved dirent byte 12, surfaced as attr bit 0x08
            // (0x08 in the FAT attr byte itself is the volume-label mark —
            // setting it would hide the entry from dir scans above).
            let attr = attr | if e[12] & 0x20 != 0 { 0x08 } else { 0 };
            out.push(RawEntry {
                name,
                attr,
                first_cluster,
                size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
                mtime,
                slot_cluster: chain[(idx / 32 * 32) / clus_size],
                slot_offset: (idx / 32 * 32) % clus_size,
                lfn_start,
                lfn_count: 0,
            });
            idx += 32;
        }
        Ok(out)
    }

    /// Resolve a path. Returns (parent_dir_cluster, entry) — entry None for "/".
    fn resolve(&mut self, path: &str) -> Result<(u32, Option<RawEntry>)> {
        let mut cur = self.bpb.root_clus;
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return Ok((cur, None));
        }
        let mut stack: Vec<&str> = Vec::new();
        for s in segs {
            match s {
                "." => {}
                ".." => {
                    stack.pop();
                }
                _ => stack.push(s),
            }
        }
        if stack.is_empty() {
            return Ok((cur, None));
        }
        for (i, seg) in stack.iter().enumerate() {
            if seg.len() > MAX_NAME {
                return Err(Error::NameTooLong);
            }
            let entries = self.scan_dir(cur)?;
            let hit = entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(seg));
            match hit {
                Some(e) => {
                    if i == stack.len() - 1 {
                        return Ok((cur, Some(e)));
                    }
                    if e.attr & ATTR_DIR == 0 {
                        return Err(Error::NotDir);
                    }
                    cur = e.first_cluster;
                }
                None => return Err(Error::NotFound),
            }
        }
        unreachable!()
    }

    fn parent_of(&mut self, path: &str) -> Result<(u32, String)> {
        let path = path.trim_end_matches('/');
        let (dir_part, name) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        };
        if name.is_empty() || name == "." || name == ".." {
            return Err(Error::BadPath);
        }
        // resolve(dir_part) yields (container_cluster, entry): when dir_part
        // itself names a directory we must descend into it — its own cluster
        // is the dirent's first_cluster, not the container's.
        let (container, entry) = self.resolve(dir_part)?;
        let dir_clus = match entry {
            None => container,
            Some(e) => {
                if e.attr & ATTR_DIR == 0 {
                    return Err(Error::NotDir);
                }
                e.first_cluster
            }
        };
        Ok((dir_clus, String::from(name)))
    }

    // ---- public API ------------------------------------------------------
    pub fn readdir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let (dir, entry) = self.resolve(path)?;
        let target = match entry {
            None => dir,
            Some(e) => {
                if e.attr & ATTR_DIR == 0 {
                    return Err(Error::NotDir);
                }
                e.first_cluster
            }
        };
        Ok(self
            .scan_dir(target)?
            .into_iter()
            .map(|e| DirEntry {
                name: e.name,
                is_dir: e.attr & ATTR_DIR != 0,
                size: e.size as u64,
                mtime: e.mtime,
                attr: e.attr,
            })
            .collect())
    }

    pub fn stat(&mut self, path: &str) -> Result<DirEntry> {
        let (_, entry) = self.resolve(path)?;
        match entry {
            None => Ok(DirEntry { name: String::from("/"), is_dir: true, size: 0, mtime: 0, attr: ATTR_DIR }),
            Some(e) => Ok(DirEntry {
                name: e.name,
                is_dir: e.attr & ATTR_DIR != 0,
                size: e.size as u64,
                mtime: e.mtime,
                attr: e.attr,
            }),
        }
    }

    /// Patch a dir entry's modify-time and/or attribute byte in place.
    /// `mtime` is unix seconds (FAT stores DOS date/time, 2s granularity).
    /// `attr` replaces only the user-settable bits (0x01 read-only,
    /// 0x02 hidden, 0x04 system); volume/dir/archive bits are preserved.
    pub fn set_meta(&mut self, path: &str, mtime: Option<u64>, attr: Option<u8>) -> Result<()> {
        let (_, entry) = self.resolve(path)?;
        let e = entry.ok_or(Error::NotFound)?;
        let mut raw = self.read_dir_entry(e.slot_cluster, e.slot_offset)?;
        if let Some(unix) = mtime {
            let (d, t) = unix_to_dos(unix);
            raw[22..24].copy_from_slice(&t.to_le_bytes());
            raw[24..26].copy_from_slice(&d.to_le_bytes());
        }
        if let Some(a) = attr {
            // user-settable: 0x01 ro, 0x02 hidden, 0x04 sys + 0x40 symlink
            // + 0x80 immutable (chattr +i; enforced in kernel vfs)
            raw[11] = (raw[11] & 0x38) | (a & 0xC7);
            // attr 0x08 append-only lives in NT-reserved byte 12 bit 0x20
            // (see the read side — 0x08 in byte 11 is FAT volume-label)
            raw[12] = (raw[12] & !0x20) | ((a & 0x08) << 2);
        }
        self.write_dir_entry(e.slot_cluster, e.slot_offset, &raw)
    }

    pub fn exists(&mut self, path: &str) -> bool {
        matches!(self.resolve(path), Ok(_))
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let (_, entry) = self.resolve(path)?;
        let e = entry.ok_or(Error::NotFound)?;
        if e.attr & ATTR_DIR != 0 {
            return Err(Error::NotDir);
        }
        self.read_entry(&e)
    }

    fn read_entry(&mut self, e: &RawEntry) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(e.size as usize);
        if e.first_cluster < 2 || e.size == 0 {
            return Ok(out);
        }
        let ch = self.chain(e.first_cluster)?;
        let mut buf = vec![0u8; self.clus_bytes];
        let mut left = e.size as usize;
        for c in ch {
            self.read_cluster(c, &mut buf)?;
            let n = left.min(self.clus_bytes);
            out.extend_from_slice(&buf[..n]);
            left -= n;
            if left == 0 {
                break;
            }
        }
        Ok(out)
    }

    /// Read `buf.len()` bytes starting at `offset` — walks the cluster
    /// chain skipping whole clusters; short read at EOF. This is the
    /// demand-pager's backend (no whole-file Vec).
    pub fn read_file_range(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (_, entry) = self.resolve(path)?;
        let e = entry.ok_or(Error::NotFound)?;
        if e.attr & ATTR_DIR != 0 {
            return Err(Error::NotDir);
        }
        if e.first_cluster < 2 || offset >= e.size as u64 {
            return Ok(0);
        }
        let want = ((e.size as u64 - offset).min(buf.len() as u64)) as usize;
        let cb = self.clus_bytes;
        let mut tmp = vec![0u8; cb];
        let mut skip = offset / cb as u64;
        let mut inner = (offset % cb as u64) as usize;
        let mut done = 0usize;
        for c in self.chain(e.first_cluster)? {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if done >= want {
                break;
            }
            self.read_cluster(c, &mut tmp)?;
            let take = (want - done).min(cb - inner);
            buf[done..done + take].copy_from_slice(&tmp[inner..inner + take]);
            done += take;
            inner = 0;
        }
        Ok(done)
    }

    /// Write a whole file: create if missing, grow/truncate as needed.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let (parent_clus, name) = self.parent_of(path)?;
        let (dir, existing) = self.resolve(path)?;
        let _ = dir;
        let e = match existing {
            Some(e) => {
                if e.attr & ATTR_DIR != 0 {
                    return Err(Error::NotDir);
                }
                e
            }
            None => self.create_entry(parent_clus, &name, 0x20)?,
        };
        let first = self.ensure_capacity(e.first_cluster, data.len() as u64)?;
        let first_clus = first.first().copied().unwrap_or(0);
        // write data
        let mut buf = vec![0u8; self.clus_bytes];
        let mut off = 0usize;
        for &c in &first {
            let n = (data.len() - off).min(self.clus_bytes);
            buf[..n].copy_from_slice(&data[off..off + n]);
            if n < self.clus_bytes {
                for b in &mut buf[n..] {
                    *b = 0;
                }
            }
            self.write_cluster(c, &buf)?;
            off += n;
        }
        let first_clus = self.truncate_chain(first_clus, data.len() as u64)?;
        self.update_entry(&e, first_clus, data.len() as u32)
    }

    pub fn append_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let mut cur = match self.read_file(path) {
            Ok(v) => v,
            Err(Error::NotFound) => Vec::new(),
            Err(e) => return Err(e),
        };
        cur.extend_from_slice(data);
        self.write_file(path, &cur)
    }

    /// Ranged write: `data` at byte offset `off`, creating the file if
    /// missing and extending the cluster chain only as far as `end`.
    /// Never materializes the whole file — one cluster buffer only.
    pub fn write_at(&mut self, path: &str, off: u64, data: &[u8]) -> Result<()> {
        let (parent_clus, name) = self.parent_of(path)?;
        let (_, existing) = self.resolve(path)?;
        let e = match existing {
            Some(e) => {
                if e.attr & ATTR_DIR != 0 {
                    return Err(Error::NotDir);
                }
                e
            }
            None => self.create_entry(parent_clus, &name, 0x20)?,
        };
        let end = off + data.len() as u64;
        let ch = self.ensure_capacity(e.first_cluster, end)?;
        let first_clus = ch.first().copied().unwrap_or(0);
        let cb = self.clus_bytes as u64;
        let mut buf = vec![0u8; self.clus_bytes];
        let mut written = 0usize;
        let mut pos = off;
        while written < data.len() {
            let idx = (pos / cb) as usize;
            let inner = (pos % cb) as usize;
            let c = ch[idx];
            let take = (data.len() - written).min(self.clus_bytes - inner);
            if take == self.clus_bytes {
                self.write_cluster(c, &data[written..written + take])?;
            } else {
                self.read_cluster(c, &mut buf)?;
                buf[inner..inner + take]
                    .copy_from_slice(&data[written..written + take]);
                self.write_cluster(c, &buf)?;
            }
            written += take;
            pos += take as u64;
        }
        let new_size = (e.size as u64).max(end) as u32;
        self.update_entry(&e, first_clus, new_size)
    }

    pub fn create_file(&mut self, path: &str) -> Result<()> {
        let (p, name) = self.parent_of(path)?;
        if let Ok(_) = self.resolve(path) {
            return Err(Error::Exists);
        }
        self.create_entry(p, &name, 0x20)?;
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let (p, name) = self.parent_of(path)?;
        if self.exists(path) {
            return Err(Error::Exists);
        }
        let e = self.create_entry(p, &name, ATTR_DIR | 0x20)?;
        let c = self.alloc_cluster()?;
        let mut buf = vec![0u8; self.clus_bytes];
        // "." and ".." entries
        write_short_entry(&mut buf[0..32], b".          ", ATTR_DIR, c, 0, self.now());
        write_short_entry(&mut buf[32..64], b"..         ", ATTR_DIR, if p == self.bpb.root_clus && self.is_root(p) { 0 } else { p }, 0, self.now());
        self.write_cluster(c, &buf)?;
        self.update_entry(&e, c, 0)
    }

    fn is_root(&self, c: u32) -> bool {
        c == self.bpb.root_clus
    }

    /// Remove a file or empty directory.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let (parent, entry) = self.resolve(path)?;
        let e = entry.ok_or(Error::NotFound)?;
        if e.attr & ATTR_DIR != 0 {
            // must be empty
            let kids = self.scan_dir(e.first_cluster)?;
            if !kids.is_empty() {
                return Err(Error::NotEmpty);
            }
        }
        self.free_chain(e.first_cluster)?;
        // mark the entry + its LFN entries deleted inside the dir block
        let mut buf = self.read_dir_block(parent)?;
        let start = e.lfn_start * 32;
        let end = ((e.slot_offset + 32 - 1) / 32 + 1) * 32; // careful: e.slot_offset is byte offset within cluster
        // recompute: entries occupy [lfn_start*32 .. slot_idx*32+32]. Find slot idx:
        let slot_idx = (self.chain(parent)?.iter().position(|&c| c == e.slot_cluster).unwrap_or(0) * self.clus_bytes + e.slot_offset) / 32;
        let start = start.min(slot_idx * 32);
        for i in (start..slot_idx * 32 + 32).step_by(32) {
            if i < buf.len() {
                buf[i] = 0xE5;
            }
        }
        let _ = end;
        self.write_dir_block(parent, &buf)
    }

    fn write_dir_block(&mut self, dir_cluster: u32, data: &[u8]) -> Result<()> {
        let ch = self.chain(dir_cluster)?;
        let mut off = 0;
        for c in ch {
            let n = (data.len() - off).min(self.clus_bytes);
            let mut buf = vec![0u8; self.clus_bytes];
            buf[..n].copy_from_slice(&data[off..off + n]);
            // preserve anything beyond n? no — the whole block was read then modified in-place; n covers it
            self.write_cluster(c, &buf)?;
            off += n;
            if off >= data.len() {
                break;
            }
        }
        Ok(())
    }

    /// Move/rename. Only same-filesystem rename supported (dirs move whole subtree by pointer).
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let (fp, fe) = self.resolve(from)?;
        let e = fe.ok_or(Error::NotFound)?;
        if self.exists(to) {
            return Err(Error::Exists);
        }
        let (tp, tname) = self.parent_of(to)?;
        // create destination entry with same cluster/size/attr
        let ne = self.create_entry(tp, &tname, e.attr)?;
        self.update_entry(&ne, e.first_cluster, e.size)?;
        // now remove only the source's dir entries (do NOT free the chain!)
        let mut buf = self.read_dir_block(fp)?;
        let chain = self.chain(fp)?;
        let slot_idx = (chain.iter().position(|&c| c == e.slot_cluster).unwrap_or(0) * self.clus_bytes + e.slot_offset) / 32;
        let start = (e.lfn_start * 32).min(slot_idx * 32);
        for i in (start..slot_idx * 32 + 32).step_by(32) {
            if i < buf.len() {
                buf[i] = 0xE5;
            }
        }
        self.write_dir_block(fp, &buf)
    }

    // ---- creation helpers ------------------------------------------------
    fn create_entry(&mut self, dir_cluster: u32, name: &str, attr: u8) -> Result<RawEntry> {
        if name.len() > MAX_NAME {
            return Err(Error::NameTooLong);
        }
        let short = self.make_short_name(dir_cluster, name)?;
        let lfn_units: Vec<u16> = name.encode_utf16().collect();
        let lfn_entries = lfn_units.len().div_ceil(13);
        let need = lfn_entries + 1;
        // find `need` consecutive free entries in dir block
        let mut data = self.read_dir_block(dir_cluster)?;
        let mut free_start: Option<usize> = None;
        let mut run = 0usize;
        let mut i = 0usize;
        loop {
            if i + 32 > data.len() {
                // dir block exhausted: extend the chain by one cluster
                let ch = self.chain(dir_cluster)?;
                let c = self.alloc_cluster()?;
                let zeros = vec![0u8; self.clus_bytes];
                self.write_cluster(c, &zeros)?;
                if let Some(&last) = ch.last() {
                    self.fat_write(last, c)?;
                } else {
                    // empty dir chain shouldn't happen (dirs get a cluster at mkdir)
                    self.update_entry_cluster(dir_cluster, c)?;
                }
                data.extend_from_slice(&zeros);
                continue;
            }
            if data[i] == 0x00 || data[i] == 0xE5 {
                if free_start.is_none() {
                    free_start = Some(i);
                }
                run += 1;
                if run >= need {
                    break;
                }
                // a 0x00 marker means everything after is free — enough
                // space, but the dir block may not be materialized that far:
                // grow the chain so `need` entries fit from free_start.
                if data[i] == 0x00 {
                    let required = free_start.unwrap_or(i) + need * 32;
                    let mut ch = self.chain(dir_cluster)?;
                    while ch.len() * self.clus_bytes < required {
                        let c = self.alloc_cluster()?;
                        let zeros = vec![0u8; self.clus_bytes];
                        self.write_cluster(c, &zeros)?;
                        self.fat_write(*ch.last().unwrap(), c)?;
                        ch.push(c);
                    }
                    if data.len() < required {
                        data.resize(required, 0);
                    }
                    break;
                }
            } else {
                free_start = None;
                run = 0;
            }
            i += 32;
        }
        let start = free_start.ok_or(Error::NoSpace)?;
        // write LFN entries then the short entry
        let checksum = lfn_checksum(&short);
        for k in 0..lfn_entries {
            let seq = lfn_entries - k; // written last-first
            let mut e = [0xFFu8; 32];
            e[0] = if k == 0 { 0x40 | seq as u8 } else { seq as u8 };
            e[11] = ATTR_LFN;
            e[13] = checksum;
            let base = (seq - 1) * 13;
            let mut units = [0xFFFFu16; 13];
            for j in 0..13 {
                if base + j < lfn_units.len() {
                    units[j] = lfn_units[base + j];
                } else if base + j == lfn_units.len() {
                    units[j] = 0;
                }
            }
            let offs = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for (j, &o) in offs.iter().enumerate() {
                e[o] = (units[j] & 0xFF) as u8;
                e[o + 1] = (units[j] >> 8) as u8;
            }
            data[start + k * 32..start + k * 32 + 32].copy_from_slice(&e);
        }
        let se = start + lfn_entries * 32;
        write_short_entry(&mut data[se..se + 32], &short, attr, 0, 0, self.now());
        self.write_dir_block(dir_cluster, &data)?;
        let chain = self.chain(dir_cluster)?;
        Ok(RawEntry {
            name: String::from(name),
            attr,
            first_cluster: 0,
            size: 0,
            mtime: self.now(),
            slot_cluster: chain[se / self.clus_bytes],
            slot_offset: se % self.clus_bytes,
            lfn_start: start / 32,
            lfn_count: lfn_entries,
        })
    }

    fn update_entry(&mut self, e: &RawEntry, first_cluster: u32, size: u32) -> Result<()> {
        let mut raw = self.read_dir_entry(e.slot_cluster, e.slot_offset)?;
        raw[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        raw[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        let (d, t) = unix_to_dos(self.now());
        raw[24..26].copy_from_slice(&d.to_le_bytes());
        raw[22..24].copy_from_slice(&t.to_le_bytes());
        raw[28..32].copy_from_slice(&size.to_le_bytes());
        self.write_dir_entry(e.slot_cluster, e.slot_offset, &raw)
    }

    fn update_entry_cluster(&mut self, _dir: u32, _c: u32) -> Result<()> {
        Ok(())
    }

    fn make_short_name(&mut self, dir_cluster: u32, name: &str) -> Result<[u8; 11]> {
        let existing = self.scan_dir(dir_cluster)?;
        let lowname = name.to_uppercase();
        let (stem, ext) = match lowname.rfind('.') {
            Some(i) if i > 0 => (&lowname[..i], &lowname[i + 1..]),
            _ => (lowname.as_str(), ""),
        };
        let clean: String = stem.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
        let cext: String = ext.chars().filter(|c| c.is_ascii_alphanumeric()).take(3).collect();
        for n in 1..1000u32 {
            let stem_part = if n == 1 && clean.len() <= 8 && !clean.is_empty() {
                clean.clone()
            } else {
                let suffix = alloc::format!("~{}", n);
                let keep = (8 - suffix.len()).min(clean.len());
                alloc::format!("{}{}", &clean[..keep], suffix)
            };
            let mut sn = [b' '; 11];
            for (i, b) in stem_part.as_bytes().iter().take(8).enumerate() {
                sn[i] = *b;
            }
            for (i, b) in cext.as_bytes().iter().take(3).enumerate() {
                sn[8 + i] = *b;
            }
            let candidate = decode_short(&sn);
            let collides = existing
                .iter()
                .any(|e| decode_short_str(e).eq_ignore_ascii_case(&candidate));
            if !collides {
                return Ok(sn);
            }
        }
        Err(Error::NoSpace)
    }
}

// ---- helpers -------------------------------------------------------------
fn decode_short(raw: &[u8]) -> String {
    let mut stem = String::new();
    for i in 0..8 {
        if raw[i] == b' ' {
            break;
        }
        stem.push(raw[i] as char);
    }
    let mut ext = String::new();
    for i in 8..11 {
        if raw[i] == b' ' {
            break;
        }
        ext.push(raw[i] as char);
    }
    if ext.is_empty() {
        stem
    } else {
        alloc::format!("{}.{}", stem, ext)
    }
}

fn decode_short_str(e: &RawEntry) -> String {
    // reconstruct the 8.3 name stored on disk isn't kept; compare via stored name stem
    e.name.clone()
}

fn decode_lfn(units: &[u16]) -> String {
    let mut s = String::new();
    for &u in units {
        if u == 0 || u == 0xFFFF {
            break;
        }
        // ASCII fast path; fallback for non-ASCII
        if let Some(c) = char::from_u32(u as u32) {
            s.push(c);
        }
    }
    s
}

fn lfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for i in 0..11 {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(short[i]);
    }
    sum
}

fn write_short_entry(dst: &mut [u8], short: &[u8; 11], attr: u8, cluster: u32, size: u32, now: u64) {
    for b in dst.iter_mut() {
        *b = 0;
    }
    dst[0..11].copy_from_slice(short);
    dst[11] = attr;
    let (d, t) = unix_to_dos(now);
    dst[14..16].copy_from_slice(&t.to_le_bytes());
    dst[16..18].copy_from_slice(&d.to_le_bytes());
    dst[18..20].copy_from_slice(&d.to_le_bytes());
    dst[22..24].copy_from_slice(&t.to_le_bytes());
    dst[24..26].copy_from_slice(&d.to_le_bytes());
    dst[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    dst[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    dst[28..32].copy_from_slice(&size.to_le_bytes());
}

// DOS date: (y-1980)<<9 | m<<5 | d ; DOS time: h<<11 | m<<5 | s/2
pub fn unix_to_dos(unix: u64) -> (u16, u16) {
    let secs = unix % 86400;
    let days = (unix / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    let yy = if y < 1980 { 0 } else { (y - 1980) as u16 };
    let date = (yy << 9) | ((m as u16) << 5) | d as u16;
    let h = (secs / 3600) as u16;
    let mi = ((secs % 3600) / 60) as u16;
    let s = ((secs % 60) / 2) as u16;
    (date, (h << 11) | (mi << 5) | s)
}

pub fn dos_to_unix(date: u16, time: u16) -> u64 {
    let y = ((date >> 9) & 0x7F) as i64 + 1980;
    let m = ((date >> 5) & 0xF) as i64;
    let d = (date & 0x1F) as i64;
    if m < 1 || m > 12 || d < 1 || d > 31 {
        return 0;
    }
    let days = days_from_civil(y, m, d);
    let h = ((time >> 11) & 0x1F) as u64;
    let mi = ((time >> 5) & 0x3F) as u64;
    let s = ((time & 0x1F) * 2) as u64;
    (days.max(0) as u64) * 86400 + h * 3600 + mi * 60 + s
}

// Howard Hinnant's civil calendar algorithms (public domain)
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
