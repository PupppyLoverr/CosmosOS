//! procfs: read-only pseudo-files under `/proc`, generated live from kernel
//! state. Intercepted by vfs.rs before the FAT32 driver sees the path.
use crate::{mem, net, task, timer};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// `/proc` itself plus the flat file list it serves.
const FILES: &[&str] = &[
    "meminfo",
    "uptime",
    "cpuinfo",
    "version",
    "mounts",
    "filesystems",
    "cmdline",
    "tasks",
    "netstat",
    "partitions",
];

pub fn handles(path: &str) -> bool {
    path == "/proc" || path.starts_with("/proc/")
}

pub fn is_dir(path: &str) -> bool {
    path == "/proc"
}

pub fn exists(path: &str) -> bool {
    is_dir(path) || FILES.contains(&path.trim_start_matches("/proc/"))
}

/// Directory entries of `/proc` (flat: the directory has no subdirs).
pub fn entries() -> Vec<shared::DirEntry> {
    let mut out = Vec::new();
    for name in FILES {
        let mut de = shared::DirEntry::default();
        let nb = name.as_bytes();
        de.name[..nb.len()].copy_from_slice(nb);
        de.name_len = nb.len() as u8;
        de.is_dir = 0;
        de.size = read_file(&alloc::format!("/proc/{}", name))
            .map(|d| d.len() as u64)
            .unwrap_or(0);
        de.mtime = 0;
        out.push(de);
    }
    out
}

fn cpu_brand() -> String {
    let mut vendor = [0u8; 12];
    let r = unsafe { core::arch::x86_64::__cpuid(0) };
    vendor[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&r.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&r.ecx.to_le_bytes());
    let vendor = String::from_utf8_lossy(&vendor).trim_end().to_string();
    let max_ext = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    let mut brand = String::new();
    if max_ext >= 0x8000_0004 {
        let mut b = [0u8; 48];
        for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            let r = unsafe { core::arch::x86_64::__cpuid(leaf) };
            for (j, v) in [r.eax, r.ebx, r.ecx, r.edx].iter().enumerate() {
                b[i * 16 + j * 4..i * 16 + j * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        brand = String::from_utf8_lossy(&b)
            .trim_end_matches('\0')
            .trim()
            .to_string();
    }
    if brand.is_empty() {
        vendor
    } else {
        brand
    }
}

/// Render a /proc file's current contents. Generated fresh on every read so
/// values like uptime and the task list are live.
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    let s = match path {
        "/proc/meminfo" => {
            let (total, used, heap) = mem::meminfo();
            alloc::format!(
                "MemTotal:       {} kB\nMemUsed:        {} kB\nKernelHeap:     {} kB\nTasks:          {}\n",
                total / 1024,
                used / 1024,
                heap / 1024,
                task::task_count()
            )
        }
        "/proc/uptime" => {
            let ms = timer::uptime_ms();
            alloc::format!("{}.{}00 0.00\n", ms / 1000, ms % 1000 / 10)
        }
        "/proc/cpuinfo" => {
            let r = unsafe { core::arch::x86_64::__cpuid(1) };
            let model = (r.eax >> 4) & 0xF;
            let family = (r.eax >> 8) & 0xF;
            let stepping = r.eax & 0xF;
            let mut f = String::from("fpu ");
            for (bit, name) in [
                (23u32, "mmx"), (25u32, "sse"), (26u32, "sse2"), (0u32, "sse3"),
                (9u32, "ssse3"), (19u32, "sse4_1"), (20u32, "sse4_2"),
                (30u32, "rdrand"), (28u32, "avx"),
            ] {
                if r.ecx & (1 << bit) != 0 {
                    f.push_str(name);
                    f.push(' ');
                }
            }
            alloc::format!(
                "vendor_id   : {}\nmodel name  : {}\nfamily      : {}\nmodel       : {}\nstepping    : {}\nflags       :{}\n",
                {
                    let r = unsafe { core::arch::x86_64::__cpuid(0) };
                    let mut v = [0u8; 12];
                    v[0..4].copy_from_slice(&r.ebx.to_le_bytes());
                    v[4..8].copy_from_slice(&r.edx.to_le_bytes());
                    v[8..12].copy_from_slice(&r.ecx.to_le_bytes());
                    String::from_utf8_lossy(&v).into_owned()
                },
                cpu_brand(),
                family,
                model,
                stepping,
                f.trim_end()
            )
        }
        "/proc/version" => alloc::format!("CosmosOS 0.1 rust-kernel x86_64\n"),
        "/proc/mounts" => alloc::format!("virtio-blk / fat32 rw 0 0\nproc /proc proc ro 0 0\n"),
        "/proc/filesystems" => alloc::format!("fat32\nproc\n"),
        "/proc/cmdline" => alloc::format!("BOOT=uefi\n"),
        "/proc/tasks" => {
            let mut buf = [shared::ProcInfo::default(); 64];
            let n = task::proclist(&mut buf);
            let mut s = String::from("  pid  mem_kb  cpu_ms  name\n");
            for p in buf.iter().take(n) {
                let name = core::str::from_utf8(&p.name)
                    .unwrap_or("?")
                    .trim_end_matches('\0');
                s.push_str(&alloc::format!(
                    "{:5} {:7} {:7}  {}\n",
                    p.pid,
                    p.mem_kb,
                    p.cpu_ticks * 10,
                    name
                ));
            }
            s
        }
        "/proc/netstat" => {
            let mut s = net::sockstat();
            if s.is_empty() {
                s.push_str("no sockets open\n");
            }
            s
        }
        "/proc/partitions" => {
            let secs = crate::virtio::block_device().map(|d| d.capacity_sectors()).unwrap_or(0);
            alloc::format!("major minor  #blocks  name\n   8     0  {} virtio-blk\n", secs / 2)
        }
        _ => return None,
    };
    Some(s.into_bytes())
}
