//! int 0x80 syscall dispatch. nr=rax, args rdi,rsi,rdx,r8,r9 → ret rax.
//! Runs on the faulting task's kernel stack; may block via task::yield_ctx.
use crate::idt::CpuContext;
use crate::{elf, fb, ipc, mem, net, pci, shm, task, timer, vfs};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use x86_64::structures::paging::PhysFrame;

const ERR: u64 = u64::MAX;

/// Cross-app clipboard (Ctrl+C/X/V) — kernel-held so it survives app exit.
static CLIPBOARD: spin::Mutex<Vec<u8>> = spin::Mutex::new(Vec::new());

/// Copy `len` bytes from user buffer `ptr` (current task's address space).
fn copy_in(ptr: u64, len: u64) -> Option<Vec<u8>> {
    if len > 1 << 20 {
        return None;
    }
    let pml4 = current_pml4()?;
    let mut out = Vec::with_capacity(len as usize);
    let mut off = 0u64;
    while off < len {
        let va = ptr + off;
        let phys = elf::translate(pml4, va)?;
        let chunk = (0x1000 - (va & 0xFFF)).min(len - off);
        unsafe {
            let src = (mem::phys_to_virt(phys)) as *const u8;
            out.extend_from_slice(core::slice::from_raw_parts(src, chunk as usize));
        }
        off += chunk;
    }
    Some(out)
}

/// Copy bytes to user buffer `ptr`.
fn copy_out(ptr: u64, data: &[u8]) -> Option<()> {
    let pml4 = current_pml4()?;
    let mut off = 0u64;
    while off < data.len() as u64 {
        let va = ptr + off;
        let phys = elf::translate(pml4, va)?;
        let chunk = ((0x1000 - (va & 0xFFF)) as usize).min(data.len() - off as usize);
        unsafe {
            let dst = (mem::phys_to_virt(phys)) as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr().add(off as usize), dst, chunk);
        }
        off += chunk as u64;
    }
    Some(())
}

fn copy_str(ptr: u64, len: u64) -> Option<String> {
    let bytes = copy_in(ptr, len)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn current_pml4() -> Option<PhysFrame> {
    task::with_current(|t| t.pml4)
}

fn cur_id() -> u32 {
    task::current_id()
}

pub fn dispatch(ctx: &mut CpuContext) {
    // Bottom-half for input IRQs: drain the lock-free event rings into IPC
    // queues. Runs in syscall context where taking locks is safe; the IRQ
    // handler itself never locks. Also gives blocked tasks a wake path: when
    // this syscall is a restarted ipc_recv, the freshly-pushed port message
    // is picked up by the try_recv below.
    crate::input::pump();
    let nr = ctx.rax;
    let (a1, a2, a3, a4, a5) = (ctx.rdi, ctx.rsi, ctx.rdx, ctx.r8, ctx.r9);
    let ret: u64 = match nr {
        shared::SYS_EXIT => {
            task::exit_current(ctx.rdi as i64);
        }
        shared::SYS_YIELD => {
            ctx.rax = 0;
            task::yield_ctx(ctx);
        }
        shared::SYS_SPAWN => sys_spawn(a1, a2, a3, a4),
        shared::SYS_SLEEP_MS => sys_sleep(ctx, a1),
        shared::SYS_MMAP => sys_mmap(a1),
        shared::SYS_DEBUG => sys_debug(a1, a2),
        shared::SYS_OPEN => sys_open(a1, a2, a3),
        shared::SYS_CLOSE => {
            vfs::close(a1 as i64);
            0
        }
        shared::SYS_READ => sys_read(a1, a2, a3),
        shared::SYS_WRITE => sys_write(a1, a2, a3),
        shared::SYS_SEEK => sys_seek(a1, a2, a3),
        shared::SYS_STAT => sys_stat(a1, a2, a3),
        shared::SYS_READDIR => sys_readdir(a1, a2, a3, a4),
        shared::SYS_MKDIR => sys_mkdir(a1, a2),
        shared::SYS_REMOVE => sys_remove(a1, a2),
        shared::SYS_RENAME => sys_rename(a1, a2, a3, a4),
        shared::SYS_SHM_CREATE => shm::create(a1, cur_id()).map(|i| i as u64).unwrap_or(ERR),
        shared::SYS_SHM_MAP => sys_shm_map(a1),
        shared::SYS_SHM_DROP => {
            task::with_current(|t| shm::release(t, a1 as u32));
            0
        }
        shared::SYS_IPC_LISTEN => sys_ipc_listen(a1, a2),
        shared::SYS_IPC_CONNECT => sys_ipc_connect(a1, a2),
        shared::SYS_IPC_SEND => sys_ipc_send(a1, a2, a3),
        shared::SYS_IPC_RECV => sys_ipc_recv(ctx, a1, a2, a3, a4),
        shared::SYS_IPC_OWNER => ipc::owner_of(a1 as u32).map(|o| o as u64).unwrap_or(0),
        shared::SYS_IPC_CLOSE => {
            ipc::close(a1 as u32, cur_id());
            task::with_current(|t| t.ports.retain(|&p| p != a1 as u32));
            0
        }
        shared::SYS_MEMINFO => {
            let (total, used, heap) = mem::meminfo();
            let tasks = task::task_count() as u64;
            let mi = shared::MemInfo {
                total_kb: total / 1024,
                used_kb: used / 1024,
                kernel_heap_kb: heap / 1024,
                tasks,
            };
            let bytes = unsafe {
                core::slice::from_raw_parts(&mi as *const _ as *const u8, core::mem::size_of::<shared::MemInfo>())
            };
            match copy_out(a1, bytes) {
                Some(_) => 0,
                None => ERR,
            }
        }
        shared::SYS_TIME => {
            let dt = timer::datetime();
            let bytes = unsafe {
                core::slice::from_raw_parts(&dt as *const _ as *const u8, core::mem::size_of::<shared::DateTime>())
            };
            match copy_out(a1, bytes) {
                Some(_) => 0,
                None => ERR,
            }
        }
        shared::SYS_UPTIME_MS => task::uptime_ms(),
        shared::SYS_PROCLIST => sys_proclist(a1, a2),
        shared::SYS_POWEROFF => {
            crate::sprint!("poweroff\n");
            power_off();
        }
        shared::SYS_REBOOT => {
            crate::sprint!("reboot\n");
            reboot();
        }
        shared::SYS_FB_INFO => sys_fb_info(a1),
        shared::SYS_CHDIR => sys_chdir(a1, a2),
        shared::SYS_GETCWD => sys_getcwd(a1, a2),
        shared::SYS_WAITPID => sys_waitpid(ctx, a1, a2),
        shared::SYS_KILL => sys_kill(a1),
        shared::SYS_NET_PING => {
            let ip = [
                (a1 >> 24) as u8,
                (a1 >> 16) as u8,
                (a1 >> 8) as u8,
                a1 as u8,
            ];
            net::ping(ip, a2.min(10_000)).unwrap_or(ERR)
        }
        shared::SYS_NET_DNS => {
            let Some(name) = copy_str(a1, a2.min(253)) else {
                ctx.rax = ERR;
                return;
            };
            match net::dns_query(&name, 3000) {
                Some(ip) => match copy_out(a3, &ip) {
                    Some(_) => 0,
                    None => ERR,
                },
                None => ERR,
            }
        }
        shared::SYS_NET_HTTP => {
            let Some(url) = copy_str(a1, a2.min(253)) else {
                ctx.rax = ERR;
                return;
            };
            // url = "host[:port][/path]" — port defaults to 80, path to "/"
            let (authority, path) = match url.find('/') {
                Some(i) => (&url[..i], &url[i..]),
                None => (url.as_str(), "/"),
            };
            let (host, port) = match authority.find(':') {
                Some(i) => (
                    &authority[..i],
                    authority[i + 1..].parse::<u16>().unwrap_or(80),
                ),
                None => (authority, 80u16),
            };
            let Some(ip) = net::dns_query(host, 3000) else {
                ctx.rax = ERR;
                return;
            };
            match net::http_get(ip, host, port, path) {
                Some(body) => {
                    let n = body.len().min(a4 as usize);
                    match copy_out(a3, &body[..n]) {
                        Some(_) => n as u64,
                        None => ERR,
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_NET_UDP_OPEN => net::udp_open(a1 as u16).map(|_| 0).unwrap_or(ERR),
        shared::SYS_NET_UDP_SEND => {
            let ip = [
                (a2 >> 24) as u8,
                (a2 >> 16) as u8,
                (a2 >> 8) as u8,
                a2 as u8,
            ];
            match copy_in(a4, a5.min(1400)) {
                Some(payload) => net::udp_send(a1 as u16, ip, a3 as u16, &payload)
                    .map(|_| 0)
                    .unwrap_or(ERR),
                None => ERR,
            }
        }
        shared::SYS_NET_UDP_RECV => {
            match net::udp_recv(a1 as u16, a4.min(10_000)) {
                Some((src_ip, sport, payload)) => {
                    let n = (6 + payload.len()).min(a3 as usize);
                    let mut buf = Vec::with_capacity(n);
                    buf.extend_from_slice(&src_ip);
                    buf.extend_from_slice(&sport.to_be_bytes());
                    buf.extend_from_slice(&payload[..n.saturating_sub(6)]);
                    match copy_out(a2, &buf) {
                        Some(_) => buf.len() as u64,
                        None => ERR,
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_NET_UDP_CLOSE => {
            net::udp_close(a1 as u16);
            0
        }
        shared::SYS_NET_DHCP => net::dhcp().map(|ip| u32::from_be_bytes(ip) as u64).unwrap_or(ERR),
        shared::SYS_NET_TCP_OPEN => {
            let ip = [(a2>>24) as u8,(a2>>16) as u8,(a2>>8) as u8,a2 as u8];
            net::tcp_open(a1 as u16, ip, a3 as u16, 4000).map(|_|0).unwrap_or(ERR)
        }
        shared::SYS_NET_TCP_SEND => match copy_in(a2, a3.min(1400)) {
            Some(d) => net::tcp_send(a1 as u16, &d, 5000).map(|_|0).unwrap_or(ERR),
            None => ERR,
        },
        shared::SYS_NET_TCP_RECV => match net::tcp_recv(a1 as u16, a4.min(10_000)) {
            Some(d) => {
                let n = d.len().min(a3 as usize);
                match copy_out(a2, &d[..n]) {
                    Some(()) => n as u64,
                    None => ERR,
                }
            }
            None => ERR,
        },
        shared::SYS_NET_TCP_CLOSE => {
            net::tcp_close(a1 as u16);
            0
        }
        shared::SYS_NET_TCP_LISTEN => match net::tcp_listen(a1 as u16) {
            Ok(()) => 0,
            Err(_) => ERR,
        },
        shared::SYS_NET_TCP_ACCEPT => {
            match net::tcp_accept(a1 as u16, a3.min(60_000)) {
                Some((cid, rip, rport)) => {
                    let mut out = [0u8; 8];
                    out[..4].copy_from_slice(&rip);
                    out[4..6].copy_from_slice(&rport.to_be_bytes());
                    match copy_out(a2, &out) {
                        Some(()) => cid as u64,
                        None => ERR,
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_NET_TCP_UNLISTEN => {
            net::tcp_unlisten(a1 as u16);
            0
        }
        shared::SYS_SHOT => match copy_in(a1, a2.min(256)) {
            Some(p) => match core::str::from_utf8(&p) {
                Ok(path) => match fb::snapshot_ppm() {
                    Some(ppm) => match vfs::write_all_path(path, &ppm) {
                        Ok(()) => 0,
                        Err(_) => ERR,
                    },
                    None => ERR,
                },
                Err(_) => ERR,
            },
            None => ERR,
        },
        shared::SYS_CLIP_SET => match copy_in(a1, a2.min(1 << 16)) {
            Some(d) => {
                *CLIPBOARD.lock() = d;
                0
            }
            None => ERR,
        },
        shared::SYS_NET_STAT => {
            let s = net::sockstat();
            let n = s.len().min(a2 as usize);
            match copy_out(a1, &s.as_bytes()[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_ARP => {
            let s = net::arp_stat();
            let n = s.len().min(a2 as usize);
            match copy_out(a1, &s.as_bytes()[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_KLOG => {
            let mut v = alloc::vec![0u8; (a2 as usize).min(32 * 1024)];
            let n = crate::klog::read_tail(&mut v);
            match copy_out(a1, &v[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_DF => match vfs::df() {
            Some((total, free)) => {
                let out = [total, free];
                match copy_out(a1, unsafe {
                    core::slice::from_raw_parts(out.as_ptr() as *const u8, 16)
                }) {
                    Some(()) => 0,
                    None => ERR,
                }
            }
            None => ERR,
        }
        shared::SYS_CLIP_GET => {
            let c = CLIPBOARD.lock();
            let n = c.len().min(a2 as usize);
            match copy_out(a1, &c[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_NET_INFO => match net::info() {
            Some((mac, ip)) => {
                let mut b = [0u8; 10];
                b[..6].copy_from_slice(&mac);
                b[6..].copy_from_slice(&ip);
                match copy_out(a1, &b) {
                    Some(_) => 0,
                    None => ERR,
                }
            }
            None => ERR,
        },
        shared::SYS_RAND => {
            let mut v = alloc::vec![0u8; (a2 as usize).min(4096)];
            rand_fill(&mut v);
            match copy_out(a1, &v) {
                Some(()) => v.len() as u64,
                None => ERR,
            }
        }
        shared::SYS_BEEP => {
            crate::timer::beep(a1 as u32, a2);
            0
        }
        shared::SYS_PCI_SCAN => {
            let max = (a2 as usize).min(64);
            let mut devs = alloc::vec![pci::PciDev {
                bus: 0, dev: 0, fun: 0, vendor: 0, device: 0, class: 0, subclass: 0,
            }; max];
            let n = pci::scan(&mut devs);
            let mut out = alloc::vec![shared::PciEnt::default(); n];
            for (i, d) in devs.iter().enumerate().take(n) {
                out[i] = shared::PciEnt {
                    bus: d.bus,
                    dev: d.dev,
                    fun: d.fun,
                    class: d.class,
                    subclass: d.subclass,
                    _pad: 0,
                    vendor: d.vendor,
                    device: d.device,
                };
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    out.as_ptr() as *const u8,
                    n * core::mem::size_of::<shared::PciEnt>(),
                )
            };
            match copy_out(a1, bytes) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        _ => {
            crate::sprint!("[syscall] unknown nr\n");
            ERR
        }
    };
    ctx.rax = ret;
}

fn sys_spawn(pptr: u64, plen: u64, aptr: u64, alen: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    let args = if aptr == 0 { String::new() } else {
        match copy_str(aptr, alen) {
            Some(a) => a,
            None => return ERR,
        }
    };
    let full = vfs::normalize(&task::with_current(|t| t.cwd.clone()), &path);
    match task::spawn_user(&full, &args, cur_id()) {
        Ok(pid) => pid as u64,
        Err(_) => ERR,
    }
}

fn sys_mmap(size: u64) -> u64 {
    if size == 0 || size > 64 << 20 {
        return 0;
    }
    task::with_current(|t| {
        let Some(pml4) = t.pml4 else { return 0 };
        let base = t.mmap_next;
        if base == 0 {
            return 0;
        }
        let pages = size.div_ceil(0x1000);
        let mut scratch = Vec::new();
        for i in 0..pages {
            if elf::map_user_page(pml4, base + i * 0x1000, &mut scratch).is_none() {
                return 0;
            }
        }
        t.mem_bytes += pages * 0x1000;
        t.mmap_next += pages * 0x1000 + 0x1000; // guard page
        base
    })
}

fn sys_debug(ptr: u64, len: u64) -> u64 {
    let Some(bytes) = copy_in(ptr, len.min(4096)) else { return ERR };
    // write raw bytes to serial — apps' stderr
    for &b in &bytes {
        crate::serial::write_byte(b);
    }
    bytes.len() as u64
}

fn sys_open(pptr: u64, plen: u64, flags: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    match vfs::open(&path, flags) {
        Ok(fd) => fd as u64,
        Err(e) => e as u64,
    }
}

fn sys_read(fd: u64, buf: u64, len: u64) -> u64 {
    if len > 1 << 20 {
        return ERR;
    }
    let mut tmp = vec![0u8; len as usize];
    match vfs::read(fd as i64, &mut tmp) {
        Ok(n) => match copy_out(buf, &tmp[..n as usize]) {
            Some(_) => n as u64,
            None => ERR,
        },
        Err(e) => e as u64,
    }
}

fn sys_write(fd: u64, buf: u64, len: u64) -> u64 {
    let Some(data) = copy_in(buf, len.min(1 << 20)) else { return ERR };
    match vfs::write(fd as i64, &data) {
        Ok(n) => n as u64,
        Err(e) => e as u64,
    }
}

fn sys_seek(fd: u64, off: u64, whence: u64) -> u64 {
    let pos = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => f.pos,
        _ => return ERR,
    });
    let size = match task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => f.path.clone(),
        _ => String::new(),
    }) {
        p if p.is_empty() => return ERR,
        p => {
            let mut g = vfs::FS.lock();
            match g.as_mut().and_then(|fs| fs.stat(&p).ok()) {
                Some(s) => s.size,
                None => return ERR,
            }
        }
    };
    let new = match whence {
        shared::SEEK_SET => off,
        shared::SEEK_CUR => pos + off,
        shared::SEEK_END => size + off,
        _ => return ERR,
    };
    match vfs::seek(fd as i64, new) {
        Ok(v) => v as u64,
        Err(e) => e as u64,
    }
}

fn sys_stat(pptr: u64, plen: u64, out: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    match vfs::stat_path(&path) {
        Ok(st) => {
            let bytes = unsafe {
                core::slice::from_raw_parts(&st as *const _ as *const u8, core::mem::size_of::<shared::Stat>())
            };
            match copy_out(out, bytes) {
                Some(_) => 0,
                None => ERR,
            }
        }
        Err(e) => e as u64,
    }
}

fn sys_readdir(pptr: u64, plen: u64, buf: u64, max: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    match vfs::listdir(&path) {
        Ok(mut ents) => {
            ents.truncate(max as usize);
            let n = ents.len();
            let bytes = unsafe {
                core::slice::from_raw_parts(ents.as_ptr() as *const u8, n * core::mem::size_of::<shared::DirEntry>())
            };
            match copy_out(buf, bytes) {
                Some(_) => n as u64,
                None => ERR,
            }
        }
        Err(e) => e as u64,
    }
}

fn sys_mkdir(pptr: u64, plen: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    vfs::mkdir(&path).map(|_| 0).unwrap_or_else(|e| e as u64)
}

fn sys_remove(pptr: u64, plen: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    vfs::remove(&path).map(|_| 0).unwrap_or_else(|e| e as u64)
}

fn sys_rename(optr: u64, olen: u64, nptr: u64, nlen: u64) -> u64 {
    let (Some(o), Some(n)) = (copy_str(optr, olen), copy_str(nptr, nlen)) else { return ERR };
    vfs::rename(&o, &n).map(|_| 0).unwrap_or_else(|e| e as u64)
}

fn sys_shm_map(id: u64) -> u64 {
    task::with_current(|t| {
        let vaddr = t.mmap_next;
        let n = shm::map_into(t, id as u32, vaddr);
        if n == 0 {
            return 0;
        }
        t.mmap_next += n + 0x1000;
        t.mem_bytes += n;
        vaddr
    })
}

fn sys_ipc_listen(nptr: u64, nlen: u64) -> u64 {
    let Some(name) = copy_str(nptr, nlen) else { return ERR };
    let me = cur_id();
    let id = ipc::listen(&name, me);
    if id != 0 {
        task::with_current(|t| t.ports.push(id));
    }
    id as u64
}

fn sys_ipc_connect(nptr: u64, nlen: u64) -> u64 {
    let Some(name) = copy_str(nptr, nlen) else { return ERR };
    match ipc::connect(&name) {
        Some(id) => id as u64,
        None => ERR,
    }
}

fn sys_ipc_send(port: u64, buf: u64, len: u64) -> u64 {
    let Some(data) = copy_in(buf, len) else { return ERR };
    match ipc::send(port as u32, &data) {
        Ok(_) => 0,
        Err(e) => e as u64,
    }
}

fn sys_ipc_recv(ctx: &mut CpuContext, port: u64, buf: u64, buflen: u64, timeout_ms: u64) -> u64 {
    let me = cur_id();
    // verify ownership
    if ipc::owner_of(port as u32) != Some(me) {
        return ERR;
    }
    // Deadline is fixed on FIRST entry and kept in wait_timeout so the
    // int-0x80 restart doesn't push it forward forever.
    let now = task::ticks();
    let deadline = task::with_current(|t| {
        if t.wait_timeout == 0 {
            t.wait_timeout = if timeout_ms == u64::MAX { u64::MAX } else { now + timeout_ms.div_ceil(10) + 1 };
        }
        t.wait_timeout
    });
    if let Some(msg) = ipc::try_recv(port as u32, me) {
        task::with_current(|t| {
            t.wait_timeout = 0;
            t.wait_port = 0;
        });
        let n = msg.len().min(buflen as usize);
        if copy_out(buf, &msg[..n]).is_none() {
            return ERR;
        }
        return n as u64;
    }
    if now >= deadline {
        task::with_current(|t| {
            t.wait_timeout = 0;
            t.wait_port = 0;
        });
        return 0;
    }
    // block: rewind to re-execute int 0x80 on wake (rax still holds nr)
    task::with_current(|t| {
        t.state = task::State::Blocked;
        t.wait_port = port as u32;
        t.wake_at = deadline;
    });
    ctx.rip -= 2;
    task::yield_ctx(ctx);
}

fn sys_sleep(ctx: &mut CpuContext, ms: u64) -> u64 {
    let now = task::ticks();
    let (dl, sleeping) = task::with_current(|t| (t.sleep_deadline, t.sleep_deadline != 0));
    if !sleeping {
        let dl = now + ms.div_ceil(10) + 1;
        task::with_current(|t| t.sleep_deadline = dl);
        if now < dl {
            block_reenter(ctx, dl, 0);
        }
        task::with_current(|t| t.sleep_deadline = 0);
        return 0;
    }
    if now < dl {
        block_reenter(ctx, dl, 0);
    }
    task::with_current(|t| t.sleep_deadline = 0);
    0
}

fn sys_waitpid(ctx: &mut CpuContext, pid: u64, timeout_ms: u64) -> u64 {
    if !task::exists(pid as u32) {
        return ERR;
    }
    let now = task::ticks();
    if let Some(code) = task::child_exit(pid as u32) {
        task::with_current(|t| t.wait_timeout = 0);
        return code as u64;
    }
    let dl = task::with_current(|t| {
        if t.wait_timeout == 0 {
            t.wait_timeout = if timeout_ms == u64::MAX { u64::MAX } else { now + timeout_ms.div_ceil(10) + 1 };
        }
        t.wait_timeout
    });
    if now >= dl {
        task::with_current(|t| {
            t.wait_timeout = 0;
            t.waiting_on = 0;
        });
        return ERR;
    }
    task::with_current(|t| {
        t.state = task::State::Blocked;
        t.waiting_on = pid as u32;
        t.wake_at = dl;
    });
    ctx.rip -= 2;
    task::yield_ctx(ctx);
}

fn sys_kill(pid: u64) -> u64 {
    match task::kill_pid(pid as u32) {
        true => 0,
        false => ERR,
    }
}

/// Mark current task blocked until `deadline` ticks, rewind rip so the syscall
/// re-executes on wake, and yield to the scheduler.
fn block_reenter(ctx: &mut CpuContext, deadline: u64, wait_port: u32) -> ! {
    task::with_current(|t| {
        t.state = task::State::Blocked;
        t.wake_at = deadline;
        t.wait_port = wait_port;
    });
    ctx.rip -= 2;
    task::yield_ctx(ctx);
}

fn sys_proclist(buf: u64, max: u64) -> u64 {
    let max = max.min(256);
    let mut list = vec![shared::ProcInfo::default(); max as usize];
    let n = task::proclist(&mut list);
    let bytes = unsafe {
        core::slice::from_raw_parts(list.as_ptr() as *const u8, n * core::mem::size_of::<shared::ProcInfo>())
    };
    match copy_out(buf, bytes) {
        Some(_) => n as u64,
        None => ERR,
    }
}

fn sys_fb_info(out: u64) -> u64 {
    let Some(pml4) = current_pml4() else { return ERR };
    let me = cur_id();
    match fb::claim_and_map(pml4, me) {
        Ok(info) => {
            let bytes = unsafe {
                core::slice::from_raw_parts(&info as *const _ as *const u8, core::mem::size_of::<shared::FbInfo>())
            };
            match copy_out(out, bytes) {
                Some(_) => 0,
                None => ERR,
            }
        }
        Err(_) => ERR,
    }
}

fn sys_chdir(pptr: u64, plen: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = vfs::normalize(&cwd, &path);
    // verify it's a dir (procfs/dev roots are dirs too, though not on the fs)
    if crate::proc::is_dir(&full) || crate::dev::is_dir(&full) {
        task::with_current(|t| t.cwd = full);
        return 0;
    }
    let mut g = vfs::FS.lock();
    let ok = match g.as_mut() {
        Some(fs) => fs.stat(&full).map(|e| e.is_dir).unwrap_or(false),
        None => false,
    };
    drop(g);
    if !ok {
        return ERR;
    }
    task::with_current(|t| t.cwd = full);
    0
}

fn sys_getcwd(buf: u64, len: u64) -> u64 {
    let cwd = task::with_current(|t| t.cwd.clone());
    let bytes = cwd.as_bytes();
    let n = bytes.len().min(len as usize);
    match copy_out(buf, &bytes[..n]) {
        Some(_) => n as u64,
        None => ERR,
    }
}

fn power_off() -> ! {
    // QEMU q35 ACPI shutdown
    unsafe {
        use x86_64::instructions::port::Port;
        let mut p: Port<u16> = Port::new(0x604);
        p.write(0x2000u16);
        let mut p2: Port<u16> = Port::new(0xB004); // piix4 fallback
        p2.write(0x2000u16);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

/// Random bytes for SYS_RAND: RDRAND when the CPU advertises it
/// (CPUID.1:ECX bit 30), otherwise a xorshift64* PRNG seeded once from
/// rdtsc — a real PRNG, not presented as CSPRNG in the docs.
pub(crate) fn rand_fill(out: &mut [u8]) {
    let has_rdrand = unsafe { core::arch::x86_64::__cpuid(1).ecx } & (1 << 30) != 0;
    let mut i = 0;
    while i < out.len() {
        let n = if has_rdrand {
            let mut v: u64 = 0;
            let mut cf: u64;
            // rdrand can legally fail (CF=0) — retry a bounded number of times
            let mut ok = false;
            for _ in 0..16 {
                unsafe {
                    core::arch::asm!(
                        "xor {0}, {0}",
                        "rdrand {1}",
                        "setc {0:l}",
                        out(reg) cf,
                        out(reg) v,
                        options(nostack)
                    );
                }
                if cf != 0 {
                    ok = true;
                    break;
                }
            }
            if ok { v } else { next_seed() }
        } else {
            next_seed()
        };
        let b = n.to_le_bytes();
        let take = (out.len() - i).min(8);
        out[i..i + take].copy_from_slice(&b[..take]);
        i += take;
    }
}

/// xorshift64* fallback stream, seeded once from rdtsc.
fn next_seed() -> u64 {
    static S: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    use core::sync::atomic::Ordering::Relaxed;
    let mut s = S.load(Relaxed);
    if s == 0 {
        s = unsafe { core::arch::x86_64::_rdtsc() } | 1;
        S.store(s, Relaxed);
    }
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    S.store(s, Relaxed);
    s.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn reboot() -> ! {
    unsafe {
        use x86_64::instructions::port::Port;
        let mut p: Port<u8> = Port::new(0x64);
        p.write(0xFEu8);
    }
    loop {
        x86_64::instructions::hlt();
    }
}
