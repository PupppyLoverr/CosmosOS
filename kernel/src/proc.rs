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
    "locks",
    "loadavg",
    "diskstats",
    "interrupts",
    "modules",
    "sysrq-trigger",
    "swaps",
];

/// files under /proc/net
const NET_FILES: &[&str] = &[
    "tcp", "udp", "unix", "dev", "operstate", "owners", "route", "iptables", "nat", "natsave",
    "ipt_recent",
    "snmp", "nf_conntrack", "arp", "fib_trie", "tc", "dns", "neigh", "mtu",
    "tcpinfo", "iptsave",
];

/// files under /proc/sys/kernel
const SYS_FILES: &[&str] = &["hostname", "cow_pages"];

/// files under /proc/sys/net/ipv4
const NET_SYS_FILES: &[&str] = &["icmp_echo_ignore_all", "ip_default_ttl"];

pub fn handles(path: &str) -> bool {
    path == "/proc" || path.starts_with("/proc/")
}

/// `/proc/<pid>` when `pid` names an alive task (digits only, or `self`
/// which always resolves to the reading task — real POSIX self magic).
fn pid_of(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/proc/")?;
    let p = rest.split('/').next()?;
    if p == "self" {
        return Some(task::current_id());
    }
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // namespaced readers resolve the number against THEIR namespace —
    // a global pid that isn't a member is invisible inside.
    let v: u64 = p.parse().ok()?;
    match task::visible_pid(v as i64) {
        u32::MAX => None,
        id => Some(id),
    }
}

const PID_FILES: &[&str] = &[
    "status", "cmdline", "stat", "fds", "fdinfo", "cwd", "maps", "io",
    "statm", "exe", "smaps", "wchan", "children", "task", "syscall",
    "sig", "mountinfo", "timens_offsets", "uid_map", "gid_map",
    "limits",
];

pub fn is_dir(path: &str) -> bool {
    path == "/proc"
        || path == "/proc/net"
        || path == "/proc/sys"
        || path == "/proc/sys/kernel"
        || path == "/proc/sys/net"
        || path == "/proc/sys/net/ipv4"
        || pid_of(path)
            .map(|p| task::pids().contains(&p) && path.matches('/').count() == 2)
            .unwrap_or(false)
        || pid_of(path)
            .map(|p| {
                task::pids().contains(&p)
                    && path.matches('/').count() == 3
                    && path.ends_with("/ns")
            })
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
        // /proc/<pid>/ns/<nsfile> — the setns fd targets
        if path.matches('/').count() == 4 {
            let n = path.rsplit('/').next().unwrap_or("");
            if ["mntns", "uts", "pid", "ipc", "time", "time_for_children", "user"]
                .contains(&n)
            {
                return task::pids().contains(&p);
            }
        }
        return false;
    }
    if let Some(f) = path.strip_prefix("/proc/net/") {
        // /proc/net/iptables/<chain> — the selective -L dump
        if let Some(c) = f.strip_prefix("iptables/") {
            return net::net_iptables_chain_exists(c);
        }
        return NET_FILES.contains(&f);
    }
    if let Some(f) = path.strip_prefix("/proc/sys/kernel/") {
        return SYS_FILES.contains(&f);
    }
    if let Some(f) = path.strip_prefix("/proc/sys/net/ipv4/") {
        return NET_SYS_FILES.contains(&f);
    }
    FILES.contains(&path.trim_start_matches("/proc/"))
}

/// Directory entries of a /proc dir (`/proc` or `/proc/<pid>`).
pub fn entries(path: &str) -> Vec<shared::DirEntry> {
    let mut out = Vec::new();
    if let Some(p) = pid_of(path) {
        if is_dir(path) {
            if path.ends_with("/ns") {
                for n in ["mntns", "uts", "pid", "ipc", "time", "time_for_children", "user"] {
                    let mut de = shared::DirEntry::default();
                    de.name[..n.len()].copy_from_slice(n.as_bytes());
                    de.name_len = n.len() as u8;
                    out.push(de);
                }
                return out;
            }
            for name in PID_FILES {
                let mut de = shared::DirEntry::default();
                let nb = name.as_bytes();
                de.name[..nb.len()].copy_from_slice(nb);
                de.name_len = nb.len() as u8;
                out.push(de);
            }
            // the ns/ subdirectory holding namespace link-files
            let mut nsde = shared::DirEntry::default();
            nsde.name[..2].copy_from_slice(b"ns");
            nsde.name_len = 2;
            out.push(nsde);
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
        for name in ["kernel", "net"] {
            let mut de = shared::DirEntry::default();
            let nb = name.as_bytes();
            de.name[..nb.len()].copy_from_slice(nb);
            de.name_len = nb.len() as u8;
            de.is_dir = 1;
            out.push(de);
        }
        return out;
    }
    if path == "/proc/sys/net" {
        let mut de = shared::DirEntry::default();
        de.name[..4].copy_from_slice(b"ipv4");
        de.name_len = 4;
        de.is_dir = 1;
        out.push(de);
        return out;
    }
    if path == "/proc/sys/net/ipv4" {
        for name in NET_SYS_FILES {
            let mut de = shared::DirEntry::default();
            let nb = name.as_bytes();
            de.name[..nb.len()].copy_from_slice(nb);
            de.name_len = nb.len() as u8;
            out.push(de);
        }
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
        // /proc/<pid>/ns/<name> — content is the namespace's own id,
        // like Linux's mnt:[inum] / uts:[inum] link targets
        if path.matches('/').count() == 4 && path.ends_with("/ns/mntns") {
            return task::ns_arc_of(p)
                .map(|ns| alloc::format!("mntns:[{}]
", ns.lock().id).into_bytes());
        }
        if path.matches('/').count() == 4 && path.ends_with("/ns/uts") {
            return task::uts_arc_of(p)
                .map(|ns| alloc::format!("uts:[{}]
", ns.lock().id).into_bytes());
        }
        if path.matches('/').count() == 4 && path.ends_with("/ns/pid") {
            // global-ns tasks report their own ns id (0 = the initial
            // namespace — Linux uses a fixed inode; we report the
            // registry id or 0 for the initial space)
            return Some(
                alloc::format!("pid:[{}]
", task::pid_ns_of(p)).into_bytes(),
            );
        }
        if path.matches('/').count() == 4 && path.ends_with("/ns/ipc") {
            return Some(
                alloc::format!("ipc:[{}]
", task::ipc_ns_of(p)).into_bytes(),
            );
        }
        if path.matches('/').count() == 4 && path.ends_with("/ns/time_for_children") {
            let c = task::child_tns_of(p);
            return Some(
                alloc::format!("time_for_children:[{}]
", if c != 0 { c } else { task::time_ns_of(p) })
                    .into_bytes(),
            );
        }
        if path.matches('/').count() == 4 && path.ends_with("/ns/user") {
            return Some(
                alloc::format!("user:[{}]
", task::user_ns_of(p)).into_bytes(),
            );
        }
        if path.matches('/').count() == 4 && path.ends_with("/ns/time") {
            return Some(
                alloc::format!("time:[{}]
", task::time_ns_of(p)).into_bytes(),
            );
        }
        return None;
    }
    let s = match path {
        "/proc/net/tcp" => net::net_tcp(),
        "/proc/net/udp" => net::net_udp(),
        "/proc/net/unix" => crate::sockfd::net_unix(),
        "/proc/net/dev" => net::net_dev(),
        "/proc/net/route" => net::net_route(),
        "/proc/net/iptables" => net::net_iptables(),
        // `/proc/net/iptables/<chain>` — selective single-chain dump
        p if p.starts_with("/proc/net/iptables/") => {
            match net::net_iptables_chain(&p[19..]) {
                Some(t) => t,
                None => return None,
            }
        }
        "/proc/net/nat" => net::net_nat(),
        "/proc/net/natsave" => net::net_natsave(),
        "/proc/net/snmp" => net::net_snmp(),
        "/proc/net/nf_conntrack" => net::net_conntrack(),
        "/proc/net/arp" => net::net_arp(),
        "/proc/net/fib_trie" => net::net_fib_trie(),
        "/proc/net/tc" => net::tc_show(),
        "/proc/net/dns" => net::net_dns_stats(),
        "/proc/net/neigh" => net::net_neigh(),
        "/proc/net/mtu" => net::net_mtu(),
        "/proc/net/tcpinfo" => net::net_tcpinfo(),
        "/proc/net/iptsave" => net::net_iptsave(),
        "/proc/net/ipt_recent" => net::net_ipt_recent(),
        "/proc/net/operstate" => alloc::format!(
            "{}\n",
            if net::is_up() { "up" } else { "down" }
        ),
        "/proc/net/owners" => net::net_owners(),
        "/proc/sys/kernel/hostname" => alloc::format!("{}\n", crate::syscall::hostname()),
        "/proc/sys/net/ipv4/icmp_echo_ignore_all" => net::net_icmp_ignore_all(),
        "/proc/sys/net/ipv4/ip_default_ttl" => net::net_def_ttl(),
        "/proc/swaps" => {
            // no swap devices in this kernel — header only, like an
            // enabled-but-empty swap table on Linux
            String::from("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")
        }
        "/proc/sys/kernel/cow_pages" => {
            alloc::format!("{}\n", crate::mem::cow_shared_total())
        }
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
        "/proc/mounts" => {
            let mut s = String::from("virtio-blk / fat32 rw 0 0\nproc /proc proc ro 0 0\ndevfs /dev devfs ro 0 0\n");
            for (m, ro) in crate::tmpfs::mounts() {
                s.push_str(&alloc::format!(
                    "tmpfs {} tmpfs {} 0 0\n",
                    m,
                    if ro & shared::MS_RDONLY != 0 { "ro" } else { "rw" }
                ));
            }
            for (tgt, src) in crate::bind::mounts() {
                s.push_str(&alloc::format!("none {} none rw,bind:{} 0 0\n", tgt, src));
            }
            s
        }
        "/proc/filesystems" => alloc::format!("fat32\nproc\ntmpfs\n"),
        "/proc/mountinfo" | "/proc/self/mountinfo" => mountinfo(),
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
        "/proc/loadavg" => {
            // no float formatting in this kernel (SSE is off); the three
            // fields are the instant runnable count repeated — a real
            // sample, just not a decaying average (no history kept)
            let (run, total, last) = task::loadavg();
            alloc::format!("{}.00 {}.00 {}.00 {}/{} {}\n", run, run, run, run, total, last)
        }
        "/proc/diskstats" => {
            let (r, w) = (
                crate::virtio::BLK_RD_SECTORS.load(core::sync::atomic::Ordering::Relaxed),
                crate::virtio::BLK_WR_SECTORS.load(core::sync::atomic::Ordering::Relaxed),
            );
            alloc::format!(
                "   8       0 vda {} {} {} 0 {} {} {} 0 0 0 0\n",
                r, r, r * 512, w, w, w * 512
            )
        }
        "/proc/interrupts" => alloc::format!(
            "            CPU0\n   0:{:>8}   PIT    timer\n   1:{:>8}   i8042  keyboard\n  12:{:>8}   i8042  mouse\n",
            task::ticks(),
            crate::input::KBD_IRQS.load(core::sync::atomic::Ordering::Relaxed),
            crate::input::MOUSE_IRQS.load(core::sync::atomic::Ordering::Relaxed),
        ),
        // monolithic kernel: no LKM subsystem — the honest answer is an
        // empty module list, not a fake one
        "/proc/modules" => String::from(""),
        "/proc/locks" => {
            // flock table snapshot: index, mode, owner pid, path
            let mut s = String::new();
            for (i, (p, ex, owners)) in crate::locks::snapshot().iter().enumerate() {
                for pid in owners {
                    s.push_str(&alloc::format!(
                        "{}: {} {} {}\n",
                        i + 1,
                        if *ex { "EXCLUSIVE" } else { "SHARED" },
                        pid,
                        p
                    ));
                }
            }
            s
        }
        _ => return None,
    };
    Some(s.into_bytes())
}

/// Writable proc files: `/proc/sys/kernel/hostname` accepts a new nodename
/// (trimmed, non-empty, capped at 64 bytes). `/proc/sysrq-trigger` takes a
/// single command letter. Returns bytes consumed.
pub fn write_file(path: &str, buf: &[u8]) -> Option<usize> {
    if path.ends_with("/timens_offsets") {
        let text = String::from(String::from_utf8_lossy(buf));
        return (crate::task::timens_offsets_write(&text) == 0).then_some(buf.len());
    }
    if path.ends_with("/uid_map") || path.ends_with("/gid_map") {
        let text = String::from(String::from_utf8_lossy(buf));
        return (crate::task::userns_map_write(
            &text,
            path.ends_with("/gid_map"),
            pid_of(path).unwrap_or(0),
        ) == 0)
        .then_some(buf.len());
    }
    if path == "/proc/sysrq-trigger" {
        // sysrq reboot/poweroff are privileged — CAP_SYS_ADMIN.
        if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return None;
        }
        match buf.first().copied().unwrap_or(0) {
            b'b' => crate::syscall::reboot(),
            b'o' => crate::syscall::power_off(),
            b's' => crate::klog::append("[sysrq] sync (writes are write-through — nothing pending)"),
            _ => return None,
        }
        return Some(buf.len());
    }
    if path == "/proc/net/operstate" {
        let s = String::from(String::from_utf8_lossy(buf).trim());
        match s.as_str() {
            "up" => net::set_up(true),
            "down" => net::set_up(false),
            _ => return None,
        }
        return Some(buf.len());
    }
    if path == "/proc/net/mtu" {
        // `ip link set eth0 mtu N` — one integer; 68..=65535 like a real nic
        let s = String::from(String::from_utf8_lossy(buf));
        let ok = s
            .trim()
            .parse::<u64>()
            .map(|n| net::set_mtu(n))
            .unwrap_or(false);
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/route" {
        // 'add <dest>/<plen> <gw|*>' / 'del <dest>[/<plen>]' per line
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::route_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/arp" {
        // 'add <ip> <mac>' / 'del <ip>' / 'flush' per line
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::arp_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/ipt_recent" {
        // 'F'/'/' flush the table; '-a.b.c.d' removes a source.
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            ok &= net::ipt_recent_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/iptables" {
        // 'A <proto> [dport N] [src ip/plen]' / 'D <n>' / 'F' / 'P <verdict>'
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::iptables_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/nat" {
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::nat_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/nf_conntrack" {
        // 'F' flush / 'D <proto> <src> <dst> <sport> <dport>' delete —
        // the `conntrack` tool's real ops on the kernel flow table.
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::ct_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/tc" {
        // 'add qdisc tbf rate <bps[k|m]>' / 'del' — the tc tool's ops.
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::tc_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/net/dns" {
        // 'F' flushes the cache (resolvectl flush-caches).
        let text = String::from(String::from_utf8_lossy(buf));
        let mut ok = true;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            ok &= net::dns_ctl(line);
        }
        return ok.then_some(buf.len());
    }
    if path == "/proc/sys/net/ipv4/icmp_echo_ignore_all" {
        let s = String::from(String::from_utf8_lossy(buf).trim());
        match s.as_str() {
            "0" => net::set_icmp_ignore_all(0),
            "1" => net::set_icmp_ignore_all(1),
            _ => return None,
        }
        return Some(buf.len());
    }
    if path == "/proc/sys/net/ipv4/ip_default_ttl" {
        let s = String::from(String::from_utf8_lossy(buf).trim());
        let Ok(v) = s.parse::<u64>() else { return None };
        if v == 0 || v > 255 {
            return None;
        }
        net::set_def_ttl(v);
        return Some(buf.len());
    }
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

/// Symlink targets inside procfs (readlink): `/proc/<pid>/exe` plus the
/// namespace links `/proc/<pid>/ns/{mntns,uts,pid}` — Linux renders them
/// as `mnt:[inum]` / `uts:[inum]` / `pid:[inum]`.
pub fn readlink(path: &str) -> Option<String> {
    if let Some(p) = pid_of(path) {
        if path.ends_with("/exe") && task::pids().contains(&p) {
            return task::pid_exe(p);
        }
        if path.ends_with("/ns/mntns") {
            return task::ns_arc_of(p).map(|ns| alloc::format!("mnt:[{}]", ns.lock().id));
        }
        if path.ends_with("/ns/uts") {
            return task::uts_arc_of(p).map(|ns| alloc::format!("uts:[{}]", ns.lock().id));
        }
        if path.ends_with("/ns/pid") {
            return Some(alloc::format!("pid:[{}]", task::pid_ns_of(p)));
        }
        if path.ends_with("/ns/ipc") {
            return Some(alloc::format!("ipc:[{}]", task::ipc_ns_of(p)));
        }
        if path.ends_with("/ns/time") {
            return Some(alloc::format!("time:[{}]", task::time_ns_of(p)));
        }
        if path.ends_with("/ns/time_for_children") {
            let c = task::child_tns_of(p);
            return Some(alloc::format!(
                "time_for_children:[{}]",
                if c != 0 { c } else { task::time_ns_of(p) }
            ));
        }
        if path.ends_with("/ns/user") {
            return Some(alloc::format!("user:[{}]", task::user_ns_of(p)));
        }
    }
    None
}

/// Render a `/proc/<pid>/<file>` — live task state each read.
/// Linux mountinfo body: id parent major:minor root mnt opts - fs src
/// opts. tmpfs entries plus bind mounts (root shown as the source path).
fn mountinfo() -> String {
    let mut s = String::from("1 0 8:0 / / rw,relatime - fat32 virtio-blk rw\n");
    let mut id = 30u32;
    for (m, ro) in crate::tmpfs::mounts() {
        s.push_str(&alloc::format!(
            "{} 1 0:{} / {} {} - tmpfs tmpfs {}\n",
            id,
            id,
            m,
            if ro & shared::MS_RDONLY != 0 { "ro" } else { "rw" },
            if ro & shared::MS_RDONLY != 0 { "ro" } else { "rw" },
        ));
        id += 1;
    }
    for (tgt, src) in crate::bind::mounts() {
        s.push_str(&alloc::format!(
            "{} 1 0:{} {} {} rw - bind none rw\n",
            id, id, src, tgt,
        ));
        id += 1;
    }
    s
}

fn pid_file(pid: u32, file: &str) -> Option<Vec<u8>> {
    let (name, argv, mem, ticks, is_user, state, nice, vrun, ppid) = task::pid_info(pid)?;
    let (min_flt, maj_flt, rss) = task::pid_faults(pid).unwrap_or((0, 0, 0));
    let s = match file {
        "status" => {
            let c = task::pid_creds6(pid).unwrap_or((0, 0, 0, 0, 0, 0, Vec::new()));
            let glist = c
                .6
                .iter()
                .map(|g| g.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let (ce, cp, cb) = task::pid_caps(pid).unwrap_or((0, 0, 0));
            alloc::format!(
                "Name:\t{}\nPid:\t{}\nPPid:\t{}\nState:\t{}\nUser:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nGroups:\t{}\nCapEff:\t{:016x}\nCapPrm:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nMinFlt:\t{}\nMajFlt:\t{}\nCpuTicks:\t{}\nNice:\t{}\nRt:\t{}\nVrun:\t{}\n",
                name, pid, ppid, state, is_user, c.0, c.1, c.2, c.0, c.3, c.4, c.5, c.3,
                glist, ce, cp, cb, 0u64, mem / 1024, rss * 4,
                min_flt, maj_flt, ticks, nice,
                task::pid_rt(pid).unwrap_or(false) as u8, vrun
            )
        }
        "cmdline" => alloc::format!("{} {}\n", name, argv).trim_end().to_string() + "\n",
        "stat" => alloc::format!(
            "{} ({}) {} {} {} {} 0 {} 0 {} {} {} {} {}\n",
            pid,
            name,
            state.chars().next().unwrap_or('?'),
            is_user as u8,
            mem / 1024,
            ticks,
            min_flt,
            ticks,
            maj_flt,
            nice,
            vrun,
            rss
        ),
        "task" => alloc::format!(
            "{}\n",
            task::pid_threads(pid)
                .unwrap_or_default()
                .iter()
                .map(|t| alloc::format!("{}", t))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        "fds" => task::fd_list(pid).unwrap_or_default(),
        "fdinfo" => task::fd_info(pid).unwrap_or_default(),
        "cwd" => alloc::format!("{}\n", task::pid_cwd(pid).unwrap_or_default()),
        "maps" => task::pid_maps(pid).unwrap_or_default(),
        "io" => {
            let (r, w) = task::pid_io(pid).unwrap_or((0, 0));
            alloc::format!("rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\nread_bytes: 0\nwrite_bytes: 0\n", r, w, r, w)
        }
        "statm" => task::pid_statm(pid).unwrap_or_default(),
        "smaps" => task::pid_smaps(pid).unwrap_or_default(),
        "wchan" => task::pid_wchan(pid).unwrap_or_default(),
        "children" => alloc::format!(
            "{}\n",
            task::children_of(pid)
                .iter()
                .map(|c| alloc::format!("{}", c))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        // exe is a symlink; opening it directly yields the path text
        "exe" => alloc::format!("{}\n", task::pid_exe(pid).unwrap_or_default()),
        "syscall" => task::pid_syscall(pid).unwrap_or_else(|| alloc::format!("-1\n")),
        "mountinfo" => mountinfo(),
        "sig" => task::pid_sig(pid).unwrap_or_default(),
        "limits" => task::pid_limits(pid).unwrap_or_default(),
        // Linux timens_offsets: monotonic + boottime offsets, in
        // seconds + nanoseconds — ours fold into one tick offset.
        "timens_offsets" => {
            let off = task::timens_offsets_read(pid).unwrap_or(0);
            let sec = off.div_euclid(100);
            let ns = off.rem_euclid(100) * 10_000_000;
            alloc::format!("monotonic {} {}\nboottime {} {}\n", sec, ns, sec, ns)
        }
        "uid_map" => task::userns_map_read(task::user_ns_of(pid), false),
        "gid_map" => task::userns_map_read(task::user_ns_of(pid), true),
        _ => return None,
    };
    Some(s.into_bytes())
}
