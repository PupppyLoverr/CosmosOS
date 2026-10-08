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
    "iostat",
    "netstat",
    "partitions",
    "stat",
];

/// files under /proc/net
const NET_FILES: &[&str] = &["tcp", "udp"];

/// files under /proc/sys/kernel
const SYS_FILES: &[&str] = &["hostname"];

pub fn handles(path: &str) -> bool {
    path == "/proc" || path.starts_with("/proc/")
}

/// `/proc/<pid>` when `pid` names an alive task (digits only).
fn pid_of(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/proc/")?;
    let p = rest.split('/').next()?;
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse().ok()
}

const PID_FILES: &[&str] = &["status", "cmdline", "stat", "fds", "cwd"];

pub fn is_dir(path: &str) -> bool {
    path == "/proc"
        || path == "/proc/net"
        || path == "/proc/sys"
        || path == "/proc/sys/kernel"
        || pid_of(path)
            .map(|p| task::pids().contains(&p) && path.matches('/').count() == 2)
            .unwrap_or(false)
}

pub fn exists(path: &str) -> bool {
    if is_dir(path) {
        return true;
    }
    if let Some(p) = pid_of(path) {
        // /proc/<pid>/<file>
        if path.matches('/').count() == 3 {
            let f = path.rsplit('/').next().unwrap_or("");
            return task::pids().contains(&p) && PID_FILES.contains(&f);
        }
        return false;
    }
    if let Some(f) = path.strip_prefix("/proc/net/") {
        return NET_FILES.contains(&f);
    }
    if let Some(f) = path.strip_prefix("/proc/sys/kernel/") {
        return SYS_FILES.contains(&f);
    }
    FILES.contains(&path.trim_start_matches("/proc/"))
}

/// Directory entries of a /proc dir (`/proc` or `/proc/<pid>`).
pub fn entries(path: &str) -> Vec<shared::DirEntry> {
    let mut out = Vec::new();
    if let Some(p) = pid_of(path) {
        if is_dir(path) {
            for name in PID_FILES {
                let mut de = shared::DirEntry::default();
                let nb = name.as_bytes();
                de.name[..nb.len()].copy_from_slice(nb);
                de.name_len = nb.len() as u8;
                out.push(de);
            }
            return out;
        }
        let _ = p;
    }
    if path == "/proc/net" {
        for name in NET_FILES {
            let mut de = shared::DirEntry::default();
            let nb = name.as_bytes();
            de.name[..nb.len()].copy_from_slice(nb);
            de.name_len = nb.len() as u8;
            out.push(de);
        }
        return out;
    }
    if path == "/proc/sys/kernel" {
        for name in SYS_FILES {
            let mut de = shared::DirEntry::default();
            let nb = name.as_bytes();
            de.name[..nb.len()].copy_from_slice(nb);
            de.name_len = nb.len() as u8;
            de.size = read_file(&alloc::format!("/proc/sys/kernel/{}", name))
                .map(|d| d.len() as u64)
                .unwrap_or(0);
            out.push(de);
        }
        return out;
    }
    if path == "/proc/sys" {
        let mut de = shared::DirEntry::default();
        de.name[..6].copy_from_slice(b"kernel");
        de.name_len = 6;
        de.is_dir = 1;
        out.push(de);
        return out;
    }
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
    // numeric pid dirs alongside the flat files, plus /proc/net and /proc/sys
    for name in ["net", "sys"] {
        let mut de = shared::DirEntry::default();
        let nb = name.as_bytes();
        de.name[..nb.len()].copy_from_slice(nb);
        de.name_len = nb.len() as u8;
        de.is_dir = 1;
        out.push(de);
    }
    for pid in task::pids() {
        let name = alloc::format!("{}", pid);
        let mut de = shared::DirEntry::default();
        let nb = name.as_bytes();
        de.name[..nb.len()].copy_from_slice(nb);
        de.name_len = nb.len() as u8;
        de.is_dir = 1;
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
    if let Some(p) = pid_of(path) {
        let file = path.rsplit('/').next().unwrap_or("");
        if path.matches('/').count() == 3 && PID_FILES.contains(&file) {
            return pid_file(p, file);
        }
        return None;
    }
    let s = match path {
        "/proc/net/tcp" => net::net_tcp(),
        "/proc/net/udp" => net::net_udp(),
        "/proc/sys/kernel/hostname" => alloc::format!("{}\n", crate::syscall::hostname()),
        "/proc/stat" => {
            let (user, all) = task::cpu_sums();
            let ticks = timer::ticks();
            let idle = ticks.saturating_sub(all);
            alloc::format!(
                "cpu  {} 0 {} {} 0 0 0\nintr {}\nprocs_running {}\n",
                user,
                all.saturating_sub(user),
                idle,
                ticks,
                task::task_count()
            )
        }
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
        "/proc/iostat" => {
            let (ro, rb, wo, wb) = crate::vfs::io_stats();
            alloc::format!("reads {} {}\nwrites {} {}\n", ro, rb, wo, wb)
        }
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

/// Writable proc files: `/proc/sys/kernel/hostname` accepts a new nodename
/// (trimmed, non-empty, capped at 64 bytes). Returns bytes consumed.
pub fn write_file(path: &str, buf: &[u8]) -> Option<usize> {
    if path != "/proc/sys/kernel/hostname" {
        return None;
    }
    let s = String::from(String::from_utf8_lossy(buf).trim());
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    crate::syscall::set_hostname(s);
    Some(buf.len())
}

/// Render a `/proc/<pid>/<file>` — live task state each read.
fn pid_file(pid: u32, file: &str) -> Option<Vec<u8>> {
    let (name, argv, mem, ticks, is_user, state, nice, vrun) = task::pid_info(pid)?;
    let s = match file {
        "status" => alloc::format!(
            "Name:\t{}\nPid:\t{}\nState:\t{}\nUser:\t{}\nVmSize:\t{} kB\nCpuTicks:\t{}\nNice:\t{}\nVrun:\t{}\n",
            name, pid, state, is_user, mem / 1024, ticks, nice, vrun
        ),
        "cmdline" => alloc::format!("{} {}\n", name, argv).trim_end().to_string() + "\n",
        "stat" => alloc::format!(
            "{} ({}) {} {} {} {} 0 0 0 {} {} {}\n",
            pid,
            name,
            state.chars().next().unwrap_or('?'),
            is_user as u8,
            mem / 1024,
            ticks,
            ticks,
            nice,
            vrun
        ),
        "fds" => task::fd_list(pid).unwrap_or_default(),
        "cwd" => alloc::format!("{}\n", task::pid_cwd(pid).unwrap_or_default()),
        _ => return None,
    };
    Some(s.into_bytes())
}
