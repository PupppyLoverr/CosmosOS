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

/// System nodename — read via SYS_HOSTNAME_GET, /proc/sys/kernel/hostname and
/// `uname -n`; set via SYS_HOSTNAME_SET / `hostname <name>`.
static HOSTNAME: spin::Mutex<String> = spin::Mutex::new(String::new());

pub fn hostname() -> String {
    let g = HOSTNAME.lock();
    if g.is_empty() {
        String::from("cosmos")
    } else {
        g.clone()
    }
}

/// Set the nodename (also writable via /proc/sys/kernel/hostname).
pub fn set_hostname(s: String) {
    let mut g = HOSTNAME.lock();
    *g = s.chars().take(64).collect();
}

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
        // demand-page file-backed/bss pages on first touch — a syscall
        // can legitimately hit a not-yet-faulted user page
        let phys = match elf::translate_user(pml4, va) {
            Some(p) => p,
            None if task::demand_page(va) => elf::translate_user(pml4, va)?,
            None => return None,
        };
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
    copy_out_pub(ptr, data)
}

/// task.rs needs copy_out for prlimit's old-value; keep the real one here
pub fn copy_out_pub(ptr: u64, data: &[u8]) -> Option<()> {
    let pml4 = current_pml4()?;
    let mut off = 0u64;
    while off < data.len() as u64 {
        let va = ptr + off;
        let phys = match elf::translate_user(pml4, va) {
            Some(p) => {
                if task::cow_resolve(va) {
                    elf::translate_user(pml4, va)?
                } else {
                    p
                }
            }
            None if task::demand_page(va) => elf::translate_user(pml4, va)?,
            None => return None,
        };
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
        shared::SYS_MMAP_FILE => sys_mmap_file(a1, a2, a3),
        shared::SYS_CLONE => match task::clone_user(a1, a2, a3) {
            Some(pid) => pid as u64,
            None => ERR,
        },
        shared::SYS_FUTEX => sys_futex(ctx, a1, a2, a3, a4),
        shared::SYS_FORK => task::fork_current(ctx).map(|p| p as u64).unwrap_or(ERR),
        shared::SYS_EXECVE => sys_execve(ctx, a1, a2, a3, a4),
        shared::SYS_SIGACTION => sys_sigaction(a1, a2, a3),
        shared::SYS_SIGALTSTACK => sys_sigaltstack(a1, a2, a3, a4),
        shared::SYS_SIGRETURN => sys_sigreturn(ctx),
        shared::SYS_SIGPROCMASK => sys_sigprocmask(a1, a2),
        shared::SYS_SIGNALFD => {
            let owner = task::with_current(|t| t.id);
            let Ok(path) = crate::signalfd::create(owner, a1) else {
                ctx.rax = ERR;
                return;
            };
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR; };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: shared::O_RDONLY,
                });
                fd as u64
            })
        }
        shared::SYS_SETSID => task::sys_setsid() as u64,
        shared::SYS_SETPGID => task::sys_setpgid(a1 as u32, a2 as u32) as u64,
        shared::SYS_GETPGID => task::sys_getpgid(a1 as u32) as u64,
        shared::SYS_GETSID => task::sys_getsid(a1 as u32) as u64,
        shared::SYS_PRCTL => {
            if a1 == 15 {
                // PR_SET_NAME: copy up to 16 bytes into the task name
                match copy_in(a2, 16) {
                    Some(b) => {
                        let n = String::from(
                            String::from_utf8_lossy(&b).trim_matches('\0'),
                        );
                        task::with_current(|t| {
                            t.name = n;
                            0u64
                        })
                    }
                    None => ERR,
                }
            } else {
                task::sys_prctl(a1, a2) as u64
            }
        }
        shared::SYS_GETPPID => task::with_current(|t| t.parent as u64),
        shared::SYS_SIGPENDING => task::with_current(|t| t.sigpending),
        shared::SYS_SIGSUSPEND => sys_sigsuspend(ctx, a1),
        shared::SYS_ARCH_PRCTL => task::sys_arch_prctl(a1, a2) as u64,
        shared::SYS_PRLIMIT => task::sys_prlimit(a1 as u32, a2, a3, a4) as u64,
        shared::SYS_ALARM => task::with_current(|t| {
            let left = if t.alarm_at == 0 {
                0
            } else {
                // alarm_at is in PIT ticks (~10ms each); a1 is seconds
            t.alarm_at.saturating_sub(task::ticks()) / 100
            };
            t.alarm_at = if a1 == 0 { 0 } else { task::ticks() + a1 * 100 };
            left
        }),
        shared::SYS_DEBUG => sys_debug(a1, a2),
        shared::SYS_OPEN => sys_open(a1, a2, a3),
        shared::SYS_CLOSE => {
            vfs::close(a1 as i64);
            0
        }
        shared::SYS_READ => sys_read(ctx, a1, a2, a3),
        shared::SYS_WRITE => sys_write(ctx, a1, a2, a3),
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
        shared::SYS_WAITPID => sys_waitpid(ctx, a1, a2, a3),
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
        shared::SYS_ARP_DEL => {
            let ip = [
                (a1 >> 24) as u8,
                (a1 >> 16) as u8,
                (a1 >> 8) as u8,
                a1 as u8,
            ];
            net::arp_del(ip) as u64
        }
        shared::SYS_UTIME => {
            let Some(path) = copy_str(a1, a2.min(4096)) else {
                ctx.rax = ERR;
                return;
            };
            vfs::utime(&path, a3).map(|_| 0).unwrap_or_else(|e| e as u64)
        }
        shared::SYS_SETATTR => {
            let Some(path) = copy_str(a1, a2.min(4096)) else {
                ctx.rax = ERR;
                return;
            };
            vfs::setattr(&path, a3 as u8)
                .map(|_| 0)
                .unwrap_or_else(|e| e as u64)
        }
        shared::SYS_RTC_SET => {
            crate::timer::set_unix(a1);
            0
        }
        shared::SYS_UMASK => task::with_current(|t| {
            let old = t.umask as u64;
            if a1 != u64::MAX {
                t.umask = (a1 as u32) & 0o777;
            }
            old
        }),
        shared::SYS_READLINK => {
            // (path_ptr,len,out,cap): raw symlink target (no resolution);
            // -22 when the path isn't a 0x40/LNK> link
            match copy_in(a1, a2.min(4096)) {
                Some(b) => {
                    let path = String::from_utf8_lossy(&b).into_owned();
                    match crate::vfs::readlink_path(&path) {
                        Ok(t) => {
                            let n = (t.len() as u64).min(a4);
                            match copy_out(a3, &t.as_bytes()[..n as usize]) {
                                Some(_) => n,
                                None => ERR,
                            }
                        }
                        Err(e) => e as u64,
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_FLOCK => {
            // (path_ptr,len,op): advisory file lock — SH/EX (+NB for
            // nonblocking), UN releases. Contended blocking requests
            // re-block and retry like the pipe wait path; locks release
            // automatically when the owner task exits (reaper).
            match copy_in(a1, a2.min(4096)) {
                Some(b) => {
                    let path = String::from_utf8_lossy(&b).into_owned();
                    if !path.starts_with('/') {
                        ERR
                    } else {
                        match crate::locks::lock(&path, cur_id(), a3) {
                            Ok(()) => 0,
                            Err(-11) => block_reenter(ctx, task::ticks() + 2, 0),
                            Err(e) => e as u64,
                        }
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_MKFIFO => {
            // (ptr,len): mkfifo — create a named pipe at any canonical path
            match copy_in(a1, a2.min(4096)) {
                Some(b) => {
                    let path = String::from_utf8_lossy(&b).into_owned();
                    if !path.starts_with('/') {
                        -3i64 as u64 // must be absolute
                    } else {
                        match crate::pipes::mkfifo(&path) {
                            Ok(()) => 0,
                            Err(e) => e as u64,
                        }
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_KLOG_CLEAR => {
            crate::klog::clear();
            0
        }
        shared::SYS_MUNMAP => sys_munmap(a1, a2),
        shared::SYS_MPROTECT => sys_mprotect(a1, a2, a3),
        shared::SYS_CHRT => match task::set_rt(a1 as u32, a2 == shared::SCHED_RT) {
            true => 0,
            false => ERR,
        },
        shared::SYS_IPCS => {
            let s = shm::ipcs_text();
            let n = s.len().min(a2 as usize);
            match copy_out(a1, &s.as_bytes()[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_PIPE => sys_pipe(),
        shared::SYS_DUP2 => sys_dup2(a1, a2),
        shared::SYS_POLL => sys_poll(ctx, a1, a2, a3, a4),
        shared::SYS_RUSAGE => match task::rusage(a1 as u32) {
            Some((utime, maxrss)) => {
                let out = [utime, 0u64, maxrss];
                match copy_out(
                    a2,
                    unsafe {
                        core::slice::from_raw_parts(
                            out.as_ptr() as *const u8,
                            core::mem::size_of_val(&out),
                        )
                    },
                ) {
                    Some(()) => 0,
                    None => ERR,
                }
            }
            None => ERR,
        },
        shared::SYS_FSYNC => {
            // fd == u64::MAX: sync() — commit the whole device. Otherwise the
            // fd must be open; fsync on a pipe object is EINVAL. Writes are
            // already synchronous per-sector, so the flush op is best-effort
            // confirmation on top of a trivially-clean invariant.
            if a1 == u64::MAX {
                if crate::virtio::flush_disk() { 0 } else { ERR }
            } else {
                let ok = task::with_current(|t| match t.fds.get(a1 as usize) {
                    Some(Some(f)) => !crate::pipes::handles(&f.path),
                    _ => false,
                });
                if ok && crate::virtio::flush_disk() { 0 } else { ERR }
            }
        }
        shared::SYS_INOTIFY_INIT => {
            let Ok(path) = crate::notify::create() else {
                ctx.rax = ERR;
                return;
            };
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR; };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: shared::O_RDONLY,
                });
                fd as u64
            })
        }
        shared::SYS_INOTIFY_ADD => {
            let fd_path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) if crate::notify::handles(&f.path) => Some(f.path.clone()),
                _ => None,
            });
            let Some(fd_path) = fd_path else {
                ctx.rax = ERR;
                return;
            };
            let Some(b) = copy_in(a2, a3.min(4096)) else {
                ctx.rax = ERR;
                return;
            };
            let path = String::from_utf8_lossy(&b).into_owned();
            let cwd = task::with_current(|t| t.cwd.clone());
            let full = vfs::normalize(&cwd, &path);
            match crate::notify::add_watch(&fd_path, &full, a4 as u32) {
                Ok(wd) => wd as u64,
                Err(e) => e as u64,
            }
        }
        shared::SYS_INOTIFY_RM => {
            let fd_path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) if crate::notify::handles(&f.path) => Some(f.path.clone()),
                _ => None,
            });
            match fd_path {
                Some(p) if crate::notify::rm_watch(&p, a2 as u32) => 0,
                _ => ERR,
            }
        }
        shared::SYS_TIMERFD => {
            let Ok(path) = crate::timerfd::create() else {
                ctx.rax = ERR;
                return;
            };
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR; };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: shared::O_RDONLY,
                });
                fd as u64
            })
        }
        shared::SYS_TFD_SET => {
            let fd_path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) if crate::timerfd::handles(&f.path) => Some(f.path.clone()),
                _ => None,
            });
            match fd_path {
                Some(p) => match crate::timerfd::settime(&p, a2, a3) {
                    Ok(()) => 0,
                    Err(e) => e as u64,
                },
                None => ERR,
            }
        }
        shared::SYS_EVENTFD => {
            let Ok(path) = crate::eventfd::create(a1, a2 as u32) else {
                ctx.rax = ERR;
                return;
            };
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR; };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: 0, // read+write
                });
                fd as u64
            })
        }
        shared::SYS_EPOLL_CREATE => {
            let Ok(path) = crate::epoll::create() else {
                ctx.rax = ERR;
                return;
            };
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR; };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: shared::O_RDONLY,
                });
                fd as u64
            })
        }
        shared::SYS_EPOLL_CTL => {
            // (epfd, op, fd, events): resolve both fds through the task table
            let both = task::with_current(|t| {
                let ep = match t.fds.get(a1 as usize) {
                    Some(Some(f)) if crate::epoll::handles(&f.path) => Some(f.path.clone()),
                    _ => None,
                };
                let mp = match t.fds.get(a3 as usize) {
                    Some(Some(f)) => Some(f.path.clone()),
                    _ => None,
                };
                (ep, mp)
            });
            let (Some(ep_path), Some(m_path)) = both else {
                ctx.rax = ERR;
                return;
            };
            crate::epoll::ctl(&ep_path, a2, a3 as u32, &m_path, a4 as u32) as u64
        }
        shared::SYS_EPOLL_WAIT => sys_epoll_wait(ctx, a1, a2, a3, a4),
        shared::SYS_SOCKETPAIR => {
            // (type) -> fdA | fdB<<32: two ends of one bidirectional
            // socket. type=SOCK_DGRAM(2) makes an AF_UNIX datagram pair.
            match if a1 == shared::SOCK_DGRAM {
                crate::sockfd::socketpair_dgram()
            } else {
                crate::sockpair::create()
            } {
                Some((pa, pb)) => task::with_current(|t| {
                    let Some(sa) = alloc_slot(t) else { return ERR; };
                    t.fds[sa] = Some(task::FileDesc { path: pa, pos: 0, flags: shared::O_RDWR });
                    let Some(sb) = alloc_slot(t) else { return ERR; };
                    t.fds[sb] = Some(task::FileDesc { path: pb, pos: 0, flags: shared::O_RDWR });
                    sa as u64 | (sb as u64) << 32
                }),
                None => ERR,
            }
        }
        shared::SYS_PIDFD => {
            // (pid) -> fd readable when the task dies; read = 8B status
            match crate::pidfd::create(a1 as u32) {
                Some(p) => task::with_current(|t| {
                    let Some(s) = alloc_slot(t) else { return ERR; };
                    t.fds[s] = Some(task::FileDesc { path: p, pos: 0, flags: shared::O_RDONLY });
                    s as u64
                }),
                None => ERR,
            }
        }
        shared::SYS_FCNTL => task::with_current(|t| {
            // (fd,cmd,arg): F_DUPFD dups into the first slot >= arg (shares
            // pos like POSIX); F_GETFL/F_SETFL read/write status bits
            let i = a1 as usize;
            match a2 {
                shared::F_DUPFD => {
                    let Some(Some(src)) = t.fds.get(i) else { return ERR };
                    let nf = task::FileDesc { path: src.path.clone(), pos: src.pos, flags: src.flags };
                    let mut s = a3 as usize;
                    while s < t.fds.len() && t.fds[s].is_some() {
                        s += 1;
                    }
                    // POSIX: result must be >= arg AND below RLIMIT_NOFILE;
                    // grow the vec with None holes when arg is past the end
                    if s as u64 >= t.rlim_nofile || s > 4096 {
                        return ERR;
                    }
                    vfs::acquire_desc(&nf);
                    while t.fds.len() <= s {
                        t.fds.push(None);
                    }
                    t.fds[s] = Some(nf);
                    s as u64
                }
                shared::F_GETFL => match t.fds.get(i) {
                    Some(Some(f)) => f.flags,
                    _ => ERR,
                },
                shared::F_SETFL => {
                    const SETTABLE: u64 = shared::O_APPEND | shared::O_NONBLOCK;
                    match t.fds.get_mut(i) {
                        Some(Some(f)) => {
                            f.flags = (f.flags & !SETTABLE) | (a3 & SETTABLE);
                            0
                        }
                        _ => ERR,
                    }
                }
                _ => ERR,
            }
        }),
        shared::SYS_FSTAT => {
            // (fd,&mut Stat): stat via the descriptor — real files, pseudo-fs
            // and object fds alike (objects report a zeroed stat)
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => Some(f.path.clone()),
                _ => None,
            });
            let Some(path) = path else {
                ctx.rax = ERR;
                return;
            };
            let st = vfs::stat_path(&path).unwrap_or(shared::Stat {
                size: 0,
                is_dir: 0,
                mtime: 0,
                attr: 0,
            });
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &st as *const _ as *const u8,
                    core::mem::size_of::<shared::Stat>(),
                )
            };
            match copy_out(a2, bytes) {
                Some(_) => 0,
                None => ERR,
            }
        }
        shared::SYS_FTRUNCATE => {
            // (fd,len): resize through the descriptor's path; clamps fd.pos
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => Some(f.path.clone()),
                _ => None,
            });
            let Some(path) = path else {
                ctx.rax = ERR;
                return;
            };
            match vfs::truncate_path(&path, a2) {
                Ok(()) => {
                    task::with_current(|t| {
                        if let Some(Some(f)) = t.fds.get_mut(a1 as usize) {
                            if f.pos > a2 {
                                f.pos = a2;
                            }
                        }
                    });
                    0
                }
                Err(e) => e as u64,
            }
        }
        shared::SYS_SENDFILE => sys_sendfile(ctx, a1, a2, a3, a4),
        shared::SYS_READV => sys_iov(ctx, a1, a2, a3, true),
        shared::SYS_WRITEV => sys_iov(ctx, a1, a2, a3, false),
        shared::SYS_SOCKET => {
            // (SOCK_STREAM|SOCK_DGRAM, domain=AF_INET|AF_UNIX) -> fd
            if a1 != shared::SOCK_STREAM && a1 != shared::SOCK_DGRAM {
                ctx.rax = ERR;
                return;
            }
            match crate::sockfd::create(a1 == shared::SOCK_STREAM, a2) {
                Err(e) => {
                    ctx.rax = e as u64;
                    return;
                }
                Ok(path) => task::with_current(|t| {
                    let Some(s) = alloc_slot(t) else { return ERR; };
                    t.fds[s] = Some(task::FileDesc { path, pos: 0, flags: shared::O_RDWR });
                    s as u64
                }),
            }
        }
        shared::SYS_BIND => {
            // (fd, port|name_ptr, name_len) — unix sockets take a path
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = ERR;
                return;
            };
            if crate::sockfd::is_unix(id) {
                let Some(name) = copy_in(a2, a3.min(108)) else {
                    ctx.rax = ERR;
                    return;
                };
                crate::sockfd::bind(id, 0, &name) as u64
            } else {
                crate::sockfd::bind(id, a2 as u16, &[]) as u64
            }
        }
        shared::SYS_CONNECT => {
            // (fd, ip|name_ptr, port|name_len)
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = ERR;
                return;
            };
            if crate::sockfd::is_unix(id) {
                let Some(name) = copy_in(a2, a3.min(108)) else {
                    ctx.rax = ERR;
                    return;
                };
                crate::sockfd::connect(id, 0, 0, &name) as u64
            } else {
                crate::sockfd::connect(id, a2 as u32, a3 as u16, &[]) as u64
            }
        }
        shared::SYS_LISTEN => {
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            match id {
                Some(id) => crate::sockfd::listen(id, a2 as usize) as u64,
                None => ERR,
            }
        }
        shared::SYS_ACCEPT => {
            // (fd, peer_out[8]|0) -> conn fd; -11 reblocks unless O_NONBLOCK
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = ERR;
                return;
            };
            match crate::sockfd::accept(id) {
                Err(-11) => {
                    if fd_nonblock(a1 as usize) {
                        ctx.rax = (-11i64) as u64;
                    } else {
                        block_reenter(ctx, task::ticks() + 2, 0);
                    }
                    return;
                }
                Err(e) => ctx.rax = e as u64,
                Ok((cpath, rip, rport)) => {
                    if a2 != 0 {
                        let mut peer = [0u8; 8];
                        peer[..4].copy_from_slice(&rip);
                        peer[4..6].copy_from_slice(&rport.to_be_bytes());
                        let _ = copy_out(a2, &peer);
                    }
                    ctx.rax = task::with_current(|t| {
                        let Some(s) = alloc_slot(t) else { return ERR; };
                        t.fds[s] = Some(task::FileDesc {
                            path: cpath,
                            pos: 0,
                            flags: shared::O_RDWR,
                        });
                        s as u64
                    });
                }
            }
            return;
        }
        shared::SYS_SENDTO => {
            // (fd, buf, len, ip u32 BE, port) -> n
            let Some(data) = copy_in(a2, a3.min(65507)) else {
                ctx.rax = ERR;
                return;
            };
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            });
            match crate::sockfd::sendto(&path, &data, a4 as u32, a5 as u16) {
                Ok(n) => n as u64,
                Err(e) => e as u64,
            }
        }
        shared::SYS_RECVFROM => {
            // (fd, buf, cap, src_out[8]|0) -> n; -11 reblocks unless nonblock
            let mut tmp = vec![0u8; a3.min(1 << 16) as usize];
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            });
            match crate::sockfd::recvfrom(&path, &mut tmp, a5 & 1 != 0) {
                Err(-11) => {
                    if crate::sockfd::wait_expired(&path) || fd_nonblock(a1 as usize) {
                        ctx.rax = (-11i64) as u64;
                    } else {
                        block_reenter(ctx, task::ticks() + 2, 0);
                    }
                    return;
                }
                Err(e) => ctx.rax = e as u64,
                Ok((n, ip, port)) => {
                    if a4 != 0 {
                        let mut src = [0u8; 8];
                        src[..4].copy_from_slice(&ip);
                        src[4..6].copy_from_slice(&port.to_be_bytes());
                        let _ = copy_out(a4, &src);
                    }
                    ctx.rax = match copy_out(a2, &tmp[..n]) {
                        Some(_) => n as u64,
                        None => ERR,
                    };
                }
            }
            return;
        }
        shared::SYS_SHUTDOWN => {
            // (fd, how) -> 0 — half-close: rd->EOF, wr->FIN/EPIPE + peer EOF
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            });
            if let Some(id) = crate::sockfd::parse(&path) {
                crate::sockfd::shutdown(id, a2) as u64
            } else if crate::sockpair::handles(&path) {
                crate::sockpair::shutdown(&path, a2) as u64
            } else {
                (-88i64) as u64 // ENOTSOCK
            }
        }
        shared::SYS_GETSOCKNAME | shared::SYS_GETPEERNAME => {
            // (fd, out, cap) -> n written: [fam u16le][inet: ip4|port2be]
            // [unix: name bytes + NUL]. non-sockets -> -88 ENOTSOCK.
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            });
            let named = |fam: u16, ip: [u8; 4], port: u16, name: Option<String>| -> u64 {
                let mut b: Vec<u8> = Vec::new();
                b.extend_from_slice(&fam.to_le_bytes());
                match fam {
                    2 => {
                        b.extend_from_slice(&ip);
                        b.extend_from_slice(&port.to_be_bytes());
                    }
                    1 => {
                        if let Some(n) = name {
                            b.extend_from_slice(n.as_bytes());
                        }
                        b.push(0);
                    }
                    _ => {}
                }
                let n = b.len().min(a3 as usize);
                match copy_out(a2, &b[..n]) {
                    Some(_) => n as u64,
                    None => ERR,
                }
            };
            let getpeer = nr == shared::SYS_GETPEERNAME;
            let r: Result<u64, i64> = if let Some(id) = crate::sockfd::parse(&path) {
                let g = if getpeer {
                    crate::sockfd::peername(id)
                } else {
                    crate::sockfd::sockname(id).ok_or(-9i64)
                };
                g.map(|(d, ip, port, name)| {
                    let fam: u16 = match d {
                        crate::sockfd::Dom::Inet => 2,
                        crate::sockfd::Dom::Unix => 1,
                    };
                    named(fam, ip, port, name)
                })
            } else if crate::sockpair::handles(&path) {
                Ok(named(1, [0; 4], 0, None))
            } else {
                Err(-88)
            };
            match r {
                Ok(v) => v,
                Err(e) => e as u64,
            }
        }
        shared::SYS_SENDMSG => {
            // (fd, buf, len, passfd|usize::MAX) -> n — SCM_RIGHTS: the
            // passed fd's object path is queued for the peer to adopt.
            let Some(data) = copy_in(a2, a3.min(1 << 16)) else {
                ctx.rax = ERR;
                return;
            };
            let (path, pass) = task::with_current(|t| {
                let p = match t.fds.get(a1 as usize) {
                    Some(Some(f)) => f.path.clone(),
                    _ => String::new(),
                };
                let pass = if a4 == u64::MAX {
                    None
                } else {
                    match t.fds.get(a4 as usize) {
                        Some(Some(f)) => Some(f.path.clone()),
                        _ => Some(String::new()), // bad fd marker
                    }
                };
                (p, pass)
            });
            if pass.as_deref() == Some("") {
                ctx.rax = (-9i64) as u64; // EBADF: passfd isn't an open fd
                return;
            }
            let r = if crate::sockfd::handles(&path) {
                crate::sockfd::sendmsg(&path, &data, pass)
            } else if crate::sockpair::handles(&path) {
                crate::sockpair::send_msg(&path, &data, pass)
            } else {
                Err(-88) // ENOTSOCK
            };
            match r {
                Ok(n) => n as u64,
                Err(e) => e as u64,
            }
        }
        shared::SYS_RECVMSG => {
            // (fd, buf, cap, fd_out|0) -> n; fd_out gets the adopted fd
            // for a passed object path (SCM_RIGHTS), or -1. -11 reblocks.
            let mut tmp = vec![0u8; a3.min(1 << 16) as usize];
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            });
            let r = if crate::sockfd::handles(&path) {
                crate::sockfd::recvmsg(&path, &mut tmp)
            } else if crate::sockpair::handles(&path) {
                crate::sockpair::recv_msg(&path, &mut tmp)
            } else {
                Err(-88)
            };
            match r {
                Err(-11) => {
                    if fd_nonblock(a1 as usize) {
                        ctx.rax = (-11i64) as u64;
                    } else {
                        block_reenter(ctx, task::ticks() + 2, 0);
                    }
                    return;
                }
                Err(e) => e as u64,
                Ok((n, got)) => {
                    let newfd: i64 = match got {
                        Some(p) if a4 != 0 => task::with_current(|t| {
                            let Some(s) = alloc_slot(t) else { return -1; };
                            let nf = task::FileDesc {
                                path: p,
                                pos: 0,
                                flags: shared::O_RDWR,
                            };
                            vfs::acquire_desc(&nf);
                            t.fds[s] = Some(nf);
                            s as i64
                        }),
                        _ => -1,
                    };
                    if a4 != 0 {
                        let _ = copy_out(a4, &newfd.to_le_bytes());
                    }
                    match copy_out(a2, &tmp[..n]) {
                        Some(()) => ctx.rax = n as u64,
                        None => ctx.rax = ERR,
                    }
                    return;
                }
            }
        }
        shared::SYS_SENDTO_PATH => {
            // (fd, buf, len, name_ptr, name_len) -> n — AF_UNIX datagram
            // destination is a path string, not an (ip,port).
            let Some(data) = copy_in(a2, a3.min(16 * 1024)) else {
                ctx.rax = ERR;
                return;
            };
            let Some(name) = copy_in(a4, a5.min(128)) else {
                ctx.rax = ERR;
                return;
            };
            let Ok(name) = core::str::from_utf8(&name) else {
                ctx.rax = (-22i64) as u64;
                return;
            };
            let name = String::from(name);
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = (-9i64) as u64;
                return;
            };
            match crate::sockfd::sendto_path(id, &name, &data) {
                Ok(n) => n as u64,
                Err(e) => e as u64,
            }
        }
        shared::SYS_RECVFROM_PATH => {
            // (fd, buf, cap, name_out|0, name_cap) -> n | fills the
            // sender's unix path; -11 reblocks unless O_NONBLOCK.
            let mut tmp = vec![0u8; a3.min(16 * 1024) as usize];
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = (-9i64) as u64;
                return;
            };
            match crate::sockfd::recvfrom_path(id, &mut tmp) {
                Err(-11) => {
                    if fd_nonblock(a1 as usize) {
                        ctx.rax = (-11i64) as u64;
                    } else {
                        block_reenter(ctx, task::ticks() + 2, 0);
                    }
                    return;
                }
                Err(e) => e as u64,
                Ok((n, src)) => {
                    if a4 != 0 {
                        let nb = src.as_bytes();
                        let m = nb.len().min((a5 as usize).saturating_sub(1));
                        let mut out = nb[..m].to_vec();
                        out.push(0);
                        let _ = copy_out(a4, &out);
                    }
                    match copy_out(a2, &tmp[..n]) {
                        Some(()) => ctx.rax = n as u64,
                        None => ctx.rax = ERR,
                    }
                    return;
                }
            }
        }
        shared::SYS_GETSOCKOPT => {
            // (fd, level, opt, out, cap) -> n — SOL_SOCKET queries write a
            // u32-le value; read-only (no setsockopt yet — nothing we
            // export is mutable).
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = (-9i64) as u64;
                return;
            };
            match crate::sockfd::getsockopt(id, a2, a3) {
                Ok(v) => {
                    let b = v.to_le_bytes();
                    let n = (a5 as usize).min(4);
                    match copy_out(a4, &b[..n]) {
                        Some(()) => n as u64,
                        None => ERR,
                    }
                }
                Err(e) => e as u64,
            }
        }
        shared::SYS_NET_TRACE => {
            // (ip u32 BE, max_hops, out, cap) -> n bytes written | ERR.
            // out gets 16-byte entries: ttl u8 | flags u8 (bit0 hop,
            // bit1 reached) | pad u16 | hop_ip[4] | rtt u64 BE.
            let ip = [
                (a1 >> 24) as u8,
                (a1 >> 16) as u8,
                (a1 >> 8) as u8,
                a1 as u8,
            ];
            let hops = net::net_trace(ip, (a2 as u8).max(1).min(30), 900);
            let mut buf = alloc::vec::Vec::with_capacity(hops.len() * 16);
            for (ttl, hop, reached) in hops {
                buf.push(ttl);
                buf.push(
                    (hop.is_some() as u8) | ((reached as u8) << 1),
                );
                buf.extend_from_slice(&[0u8; 2]);
                buf.extend_from_slice(&hop.map(|h| h.0).unwrap_or([0; 4]));
                buf.extend_from_slice(&hop.map(|h| h.1).unwrap_or(0).to_be_bytes());
            }
            let n = buf.len().min(a4 as usize);
            match copy_out(a3, &buf[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_SETSOCKOPT => {
            // (fd, level, opt, val) -> 0 | errno
            let id = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::sockfd::parse(&f.path),
                _ => None,
            });
            let Some(id) = id else {
                ctx.rax = (-9i64) as u64;
                return;
            };
            crate::sockfd::setsockopt(id, a2, a3, a4) as u64
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
        shared::SYS_GETPID => task::current_id() as u64,
        shared::SYS_PCAP => {
            // a1 op, a2 buf ptr, a3 cap
            if a1 == 4 {
                match a3 {
                    0..=262_144 => match copy_out_pcap(a2, a3 as usize) {
                        Ok(n) => n as u64,
                        Err(e) => e as u64,
                    },
                    _ => ERR,
                }
            } else {
                crate::pcap::sys_pcap(a1, &mut []) as u64
            }
        }
        shared::SYS_NICE => task::set_nice(a1 as u32, a2 as i64) as u64,
        shared::SYS_KILL2 => task::signal(a1 as u32, a2) as u64,
        shared::SYS_HOSTNAME_GET => {
            let h = hostname();
            let n = h.len().min(a2 as usize);
            match copy_out(a1, &h.as_bytes()[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_HOSTNAME_SET => match copy_in(a1, a2.min(64)) {
            Some(b) => {
                let h = String::from(String::from_utf8_lossy(&b).trim());
                if h.is_empty() {
                    ERR
                } else {
                    set_hostname(h);
                    0
                }
            }
            None => ERR,
        },
        shared::SYS_STRACE => match a1 {
            // (op, pid, out, cap): 0 start, 1 stop, 2 drain packed 7*u64 recs
            0 => task::trace_start(a2 as u32) as u64,
            1 => task::trace_stop(a2 as u32) as u64,
            2 => {
                let mut v: Vec<u8> = Vec::new();
                if task::trace_drain(a2 as u32, &mut v) < 0 {
                    ERR
                } else {
                    let n = v.len().min(a4 as usize);
                    match copy_out(a3, &v[..n]) {
                        Some(()) => n as u64,
                        None => ERR,
                    }
                }
            }
            _ => ERR,
        },
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
    if nr != shared::SYS_STRACE {
        task::trace_rec(nr, a1, a2, a3, a4, a5, ret);
    }
    ctx.rax = ret;
    // a normal return to user code means no interrupted-block remains —
    // except SYS_SIGRETURN, whose restored wake_eintr must survive for
    // the re-executed syscall's block_reenter to consume
    if nr != shared::SYS_SIGRETURN {
        task::with_current(|t| t.sig.wake_eintr = false);
    }
    // a pending userspace signal delivers right here — the saved frame
    // captures rax=ret so the handler's sigreturn resumes correctly
    let mut g = task::SCHED.lock();
    if let Some(s) = g.as_mut() {
        task::maybe_deliver(s, s.cur, ctx);
        if s.tasks[s.cur].state == task::State::Dead
            || s.tasks[s.cur].state == task::State::Stopped
        {
            // uncaught signal killed or stopped us — never resume it
            drop(g);
            task::yield_ctx(ctx);
        }
    }
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
        Ok(pid) => {
            vfs::utmp_log(pid, &full);
            pid as u64
        }
        Err(_) => ERR,
    }
}

fn sys_mmap(size: u64) -> u64 {
    if size == 0 || size > 64 << 20 {
        return 0;
    }
    // (real anon mmap — see SYS_MUNMAP/SYS_MPROTECT for the full lifecycle)
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
        t.maps.push(task::MapEnt {
            start: base,
            end: base + pages * 0x1000,
            perm: 1 | 2,
            name: alloc::string::String::from("[anon]"),
        });
        t.mmap_next += pages * 0x1000 + 0x1000; // guard page
        base
    })
}

/// SYS_MMAP_FILE(fd,size,offset): real demand-paged file mapping — the
/// VA range is reserved NOW but no pages exist; the first touch of each
/// 4KiB page faults, and the #PF handler fills it from the file (zero
/// past EOF). Pseudo-fs fds are rejected: only real files page in.
fn sys_mmap_file(fd: u64, size: u64, offset: u64) -> u64 {
    if size == 0 || size > 64 << 20 {
        return 0;
    }
    let path = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => Some(f.path.clone()),
        _ => None,
    });
    let Some(path) = path else {
        return 0;
    };
    if crate::pipes::handles(&path)
        || crate::dev::handles(&path)
        || crate::proc::handles(&path)
    {
        return 0;
    }
    let Ok(st) = vfs::stat_path(&path) else {
        return 0;
    };
    if st.is_dir != 0 {
        return 0;
    }
    task::with_current(|t| {
        if t.pml4.is_none() {
            return 0;
        }
        let base = t.mmap_next;
        if base == 0 {
            return 0;
        }
        let pages = size.div_ceil(0x1000);
        t.mem_bytes += pages * 0x1000;
        t.maps.push(task::MapEnt {
            start: base,
            end: base + pages * 0x1000,
            perm: 1 | 2,
            name: path.clone(),
        });
        t.filemaps.push(task::FileMap {
            start: base,
            end: base + pages * 0x1000,
            path,
            off: offset,
            perm: 1 | 2,
        });
        t.mmap_next += pages * 0x1000 + 0x1000; // guard page
        base
    })
}

/// SYS_MUNMAP(addr,len): real unmap — PTEs cleared, owned frames freed,
/// borrowed (shm/fb) frames just detached, tracked entries shrunk/split.
fn sys_munmap(addr: u64, len: u64) -> u64 {
    if len == 0 || addr & 0xFFF != 0 {
        return ERR;
    }
    let end = addr.saturating_add(len.div_ceil(0x1000) * 0x1000);
    let mut pml4_phys = None;
    let ret: Option<u64> = task::with_current(|t| {
        let pml4 = t.pml4?;
        let mut unmapped = 0u64;
        let mut a = addr;
        while a < end {
            if let Some(phys) = elf::unmap_user_page(pml4, a) {
                if !t.borrowed.contains(&phys) {
                    mem::free_frame(phys);
                }
                unmapped += 1;
            }
            task::cow_unmap(pml4.start_address().as_u64(), a);
            a += 0x1000;
        }
        if unmapped == 0 {
            return None;
        }
        // release shm segments whose region is fully covered
        let mut releases: Vec<u32> = Vec::new();
        for m in t.maps.iter() {
            if m.start >= addr && m.end <= end && m.name.starts_with("shm#") {
                if let Ok(id) = m.name[4..].parse::<u32>() {
                    releases.push(id);
                }
            }
        }
        for id in releases {
            shm::release(t, id);
            t.shm.retain(|&s| s != id);
        }
        trim_map_lists(t, addr, end);
        t.mem_bytes = t.mem_bytes.saturating_sub(unmapped * 0x1000);
        unsafe { x86_64::instructions::tlb::flush_all() };
        pml4_phys = t.pml4.map(|p| p.start_address().as_u64());
        pml4_phys
    });
    // cloned threads share this mm — every sharer's bookkeeping must see
    // the same trim or a stale filemap would resurrect unmapped pages on
    // the next fault. (for_mm_peers re-trims ours too: idempotent.)
    if let Some(pp) = pml4_phys {
        task::for_mm_peers(pp, |o| trim_map_lists(o, addr, end));
    }
    match ret {
        Some(_) => 0,
        None => ERR,
    }
}

/// Split/shrink/drop one task's maps+filemaps bookkeeping over [addr,end).
fn trim_map_lists(t: &mut task::Task, addr: u64, end: u64) {
    let mut out: Vec<task::MapEnt> = Vec::new();
    for m in core::mem::take(&mut t.maps) {
        if m.end <= addr || m.start >= end {
            out.push(m);
            continue;
        }
        if m.start < addr {
            out.push(task::MapEnt {
                start: m.start,
                end: addr,
                perm: m.perm,
                name: m.name.clone(),
            });
        }
        if m.end > end {
            out.push(task::MapEnt {
                start: end,
                end: m.end,
                perm: m.perm,
                name: m.name,
            });
        }
    }
    t.maps = out;
    // filemap bookkeeping tracks the same split
    let mut fout: Vec<task::FileMap> = Vec::new();
    for f in core::mem::take(&mut t.filemaps) {
        if f.end <= addr || f.start >= end {
            fout.push(f);
            continue;
        }
        if f.start < addr {
            fout.push(task::FileMap {
                start: f.start,
                end: addr,
                path: f.path.clone(),
                off: f.off,
                perm: f.perm,
            });
        }
        if f.end > end {
            fout.push(task::FileMap {
                start: end,
                end: f.end,
                path: f.path,
                off: f.off + (end - f.start),
                perm: f.perm,
            });
        }
    }
    t.filemaps = fout;
}

/// SYS_MPROTECT(addr,len,prot R1W2X4): rewrites real PTE flags on the
/// task's own mappings — a subsequent violating access page-faults for real.
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    if len == 0 || prot > 7 || addr & 0xFFF != 0 {
        return ERR;
    }
    let w = prot & shared::PROT_WRITE != 0;
    let x = prot & shared::PROT_EXEC != 0;
    let end = addr.saturating_add(len.div_ceil(0x1000) * 0x1000);
    task::with_current(|t| {
        let Some(pml4) = t.pml4 else { return ERR };
        let mut a = addr;
        let mut changed = 0u64;
        while a < end {
            if w {
                // break COW sharing before granting write — the frame
                // may be mapped read-only into a fork sibling
                if let Some(phys) = elf::translate(pml4, a) {
                    task::cow_split(pml4, a & !0xFFF, phys & !0xFFF);
                }
            }
            if elf::protect_user_page(pml4, a, w, x).is_some() {
                changed += 1;
            }
            a += 0x1000;
        }
        if changed == 0 {
            return ERR;
        }
        for m in t.maps.iter_mut() {
            if m.end <= addr || m.start >= end {
                continue;
            }
            m.perm = (prot & 7) as u8;
        }
        unsafe { x86_64::instructions::tlb::flush_all() };
        0
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

/// One non-blocking read attempt against `fd`'s backend — the shared read
/// path used by sys_read/readv/sendfile. Err(-11) = would block.
fn fd_read_once(fd: usize, buf: &mut [u8]) -> Result<usize, i64> {
    let path = task::with_current(|t| match t.fds.get(fd) {
        Some(Some(f)) => Some(f.path.clone()),
        _ => None,
    })
    .ok_or(-3i64)?;
    if crate::pipes::handles(&path) {
        return match crate::pipes::try_read(&path, buf) {
            crate::pipes::TryRead::WouldBlock => Err(-11),
            crate::pipes::TryRead::Eof => Ok(0),
            crate::pipes::TryRead::Data(n) => Ok(n),
        };
    }
    if crate::notify::handles(&path) {
        return crate::notify::try_read(&path, buf);
    }
    if crate::eventfd::handles(&path) {
        return crate::eventfd::try_read(&path, buf);
    }
    if crate::sockpair::handles(&path) {
        return crate::sockpair::try_read(&path, buf);
    }
    if crate::pidfd::handles(&path) {
        return crate::pidfd::try_read(&path, buf);
    }
    if crate::timerfd::handles(&path) {
        return crate::timerfd::try_read(&path, buf);
    }
    if crate::signalfd::handles(&path) {
        return crate::signalfd::try_read(&path, buf);
    }
    if crate::sockfd::handles(&path) {
        return crate::sockfd::try_read(&path, buf);
    }
    match vfs::read(fd as i64, buf) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// One non-blocking write attempt against `fd`'s backend. Err(-11) = would
/// block; Err(-32) = EPIPE.
fn fd_write_once(fd: usize, data: &[u8]) -> Result<usize, i64> {
    let path = task::with_current(|t| match t.fds.get(fd) {
        Some(Some(f)) => Some(f.path.clone()),
        _ => None,
    })
    .ok_or(-3i64)?;
    if crate::eventfd::handles(&path) {
        return crate::eventfd::try_write(&path, data);
    }
    if crate::sockpair::handles(&path) {
        return crate::sockpair::try_write(&path, data);
    }
    if crate::sockfd::handles(&path) {
        let nb = fd_nonblock(fd);
        return crate::sockfd::try_write(&path, data, nb);
    }
    // pipes are dispatched inside vfs::write (try_write -> -11 full / -32
    // no-readers); real files and dev/proc go the normal route
    match vfs::write(fd as i64, data) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// Whether `fd` was opened (or fcntl'd) O_NONBLOCK.
fn fd_nonblock(fd: usize) -> bool {
    task::with_current(|t| match t.fds.get(fd) {
        Some(Some(f)) => f.flags & shared::O_NONBLOCK != 0,
        _ => false,
    })
}

fn sys_read(ctx: &mut CpuContext, fd: u64, buf: u64, len: u64) -> u64 {
    if len > 1 << 20 {
        return ERR;
    }
    let mut tmp = vec![0u8; len as usize];
    match fd_read_once(fd as usize, &mut tmp) {
        Err(-11) => {
            let path = task::with_current(|t| match t.fds.get(fd as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            });
            // SO_RCVTIMEO expiry: the socket already waited its budget —
            // the -11 is a real EAGAIN for userspace, not "retry"
            if crate::sockfd::wait_expired(&path) || fd_nonblock(fd as usize) {
                (-11i64) as u64 // EAGAIN instead of blocking
            } else {
                block_reenter(ctx, task::ticks() + 2, 0) // poll every ~20ms
            }
        }
        Err(e) => e as u64,
        Ok(n) => match copy_out(buf, &tmp[..n]) {
            Some(_) => n as u64,
            None => ERR,
        },
    }
}

fn sys_write(ctx: &mut CpuContext, fd: u64, buf: u64, len: u64) -> u64 {
    let Some(data) = copy_in(buf, len.min(1 << 20)) else { return ERR };
    match fd_write_once(fd as usize, &data) {
        Err(-11) => {
            if fd_nonblock(fd as usize) {
                (-11i64) as u64
            } else {
                block_reenter(ctx, task::ticks() + 2, 0)
            }
        }
        Err(e) => e as u64,
        Ok(n) => n as u64,
    }
}

/// enable interrupts only for the hlt window — the syscall gate runs with
/// interrupts OFF, so waiting for readiness means sti;hlt;cli around a tick.
fn wait_irq() {
    unsafe { core::arch::asm!("sti; hlt; cli", options(nomem, nostack)) };
}

/// SYS_READV/SYS_WRITEV: scatter/gather I/O. iov entries are {ptr,len} u64
/// pairs; per-vec ops go through the same fd backend as sys_read/sys_write,
/// blocking (via wait_irq retry) only until the first vec makes progress —
/// partial results return the short count like POSIX.
fn sys_iov(ctx: &mut CpuContext, fd: u64, iov_ptr: u64, iovcnt: u64, rd: bool) -> u64 {
    let _ = ctx;
    let fd = fd as usize;
    let n = iovcnt.min(16) as usize;
    if fd > 4096 || iov_ptr == 0 {
        return ERR;
    }
    let mut total = 0usize;
    let nonblock = fd_nonblock(fd);
    for i in 0..n {
        let Some(ent) = copy_in(iov_ptr + i as u64 * 16, 16) else {
            return if total > 0 { total as u64 } else { ERR };
        };
        let (ptr, len) = (
            u64::from_le_bytes(ent[..8].try_into().unwrap()) as usize,
            u64::from_le_bytes(ent[8..].try_into().unwrap()) as usize,
        );
        if len == 0 {
            continue;
        }
        if len > 1 << 20 {
            return ERR;
        }
        if rd {
            let mut tmp = vec![0u8; len];
            loop {
                match fd_read_once(fd, &mut tmp) {
                    Ok(cnt) => {
                        match copy_out(ptr as u64, &tmp[..cnt]) {
                            Some(_) => total += cnt,
                            None => return ERR,
                        }
                        break;
                    }
                    Err(-11) if total > 0 => return total as u64,
                    Err(-11) if nonblock => return (-11i64) as u64,
                    Err(-11) => wait_irq(), // nothing read yet: block for ready
                    Err(e) => return e as u64,
                }
            }
        } else {
            let Some(data) = copy_in(ptr as u64, len as u64) else {
                return if total > 0 { total as u64 } else { ERR };
            };
            loop {
                match fd_write_once(fd, &data) {
                    Ok(cnt) => {
                        total += cnt;
                        // a partial write ends the writev (POSIX)
                        return if cnt < data.len() { total as u64 } else { break };
                    }
                    Err(-11) if total > 0 => return total as u64,
                    Err(-11) if nonblock => return (-11i64) as u64,
                    Err(-11) => wait_irq(),
                    Err(e) => return e as u64,
                }
            }
        }
    }
    total as u64
}

/// SYS_SENDFILE(out_fd, in_fd, off_ptr|0, count): kernel-side copy — data
/// never crosses userspace. With an offset, the input fd's position is
/// preserved (POSIX: *offset updated, fd pos untouched). Blocks via wait_irq
/// when a blocking fd isn't ready; short count on EOF/EAGAIN-partial.
fn sys_sendfile(ctx: &mut CpuContext, out_fd: u64, in_fd: u64, off_ptr: u64, count: u64) -> u64 {
    let _ = ctx;
    let (out, inp) = (out_fd as usize, in_fd as usize);
    if out > 4096 || inp > 4096 {
        return ERR;
    }
    // count is a maximum, not a contract — clamp to one call's work budget;
    // callers (sendfile_all) loop for the rest
    let count = count.min(1 << 24);
    // optional explicit offset: save the fd pos, seek to *offset, restore
    // after; the new position is reported back through off_ptr
    let saved_pos = if off_ptr != 0 {
        let Some(offb) = copy_in(off_ptr, 8) else { return ERR };
        let off = u64::from_le_bytes(offb.try_into().unwrap());
        let old = task::with_current(|t| match t.fds.get(inp) {
            Some(Some(f)) => Some(f.pos),
            _ => None,
        });
        let _ = vfs::seek(inp as i64, off);
        old
    } else {
        None
    };
    let mut buf = vec![0u8; 4096];
    let mut done = 0u64;
    let nonblock = fd_nonblock(inp) && fd_nonblock(out);
    let res = loop {
        if done >= count {
            break done;
        }
        let want = ((count - done) as usize).min(buf.len());
        match fd_read_once(inp, &mut buf[..want]) {
            Ok(0) => break done, // EOF
            Ok(n) => {
                let mut w = 0usize;
                while w < n {
                    match fd_write_once(out, &buf[w..n]) {
                        Ok(m) => {
                            w += m;
                            done += m as u64;
                        }
                        Err(-11) if done > 0 => break,
                        Err(-11) if nonblock => {
                            restore_pos(inp, saved_pos, off_ptr);
                            return (-11i64) as u64;
                        }
                        Err(-11) => wait_irq(),
                        Err(e) => {
                            restore_pos(inp, saved_pos, off_ptr);
                            return e as u64;
                        }
                    }
                    if done >= count {
                        break;
                    }
                }
                if w < n {
                    break done;
                }
            }
            Err(-11) if done > 0 => break done,
            Err(-11) if nonblock => {
                restore_pos(inp, saved_pos, off_ptr);
                return (-11i64) as u64;
            }
            Err(-11) => wait_irq(),
            Err(e) => {
                restore_pos(inp, saved_pos, off_ptr);
                return e as u64;
            }
        }
    };
    restore_pos(inp, saved_pos, off_ptr);
    res
}

/// POSIX sendfile offset semantics: write the final offset back to *off_ptr
/// and restore the input fd's own position.
fn restore_pos(inp: usize, saved: Option<u64>, off_ptr: u64) {
    if let Some(old) = saved {
        let end = task::with_current(|t| match t.fds.get(inp) {
            Some(Some(f)) => Some(f.pos),
            _ => None,
        });
        if let Some(end) = end {
            let _ = copy_out(off_ptr, &end.to_le_bytes());
        }
        let _ = vfs::seek(inp as i64, old);
    }
}

fn sys_seek(fd: u64, off: u64, whence: u64) -> u64 {
    let Some((pos, path)) = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => Some((f.pos, f.path.clone())),
        _ => None,
    }) else {
        return ERR;
    };
    let new = match whence {
        shared::SEEK_SET => off,
        shared::SEEK_CUR => pos + off,
        shared::SEEK_END => {
            // only real filesystem files have a stat-able size; dev/proc/pipe
            // fds support SET/CUR (the offset is the device byte address —
            // /dev/port's port number, /dev/mem's physical address)
            if path.is_empty()
                || crate::dev::handles(&path)
                || crate::proc::handles(&path)
                || crate::pipes::handles(&path)
            {
                return ERR;
            }
            let mut g = vfs::FS.lock();
            let size = match g.as_mut().and_then(|fs| fs.stat(&path).ok()) {
                Some(s) => s.size,
                None => return ERR,
            };
            size + off
        }
        _ => return ERR,
    };
    match vfs::seek(fd as i64, new) {
        Ok(v) => v as u64,
        Err(e) => e as u64,
    }
}

/// First free fd slot below RLIMIT_NOFILE; None = EMFILE. POSIX bounds
/// the fd INDEX — slots at or above the limit are never handed out,
/// even when the vec has holes there.
fn alloc_slot(t: &mut task::Task) -> Option<usize> {
    for (i, f) in t.fds.iter().enumerate() {
        if f.is_none() && (i as u64) < t.rlim_nofile {
            return Some(i);
        }
    }
    if t.fds.len() as u64 >= t.rlim_nofile {
        return None;
    }
    t.fds.push(None);
    Some(t.fds.len() - 1)
}

/// SYS_PIPE: an anonymous pipe bound to two fresh fds in the caller's
/// table — read end + write end. Returns rfd | wfd<<32.
fn sys_pipe() -> u64 {
    let Ok(path) = crate::pipes::create_anon() else {
        return ERR;
    };
    let packed = task::with_current(|t| {
        let Some(rfd) = alloc_slot(t) else { return ERR; };
        t.fds[rfd] = Some(task::FileDesc {
            path: path.clone(),
            pos: 0,
            flags: shared::O_RDONLY,
        });
        let Some(wfd) = alloc_slot(t) else { return ERR; };
        t.fds[wfd] = Some(task::FileDesc {
            path: path.clone(),
            pos: 0,
            flags: shared::O_TRUNC, // pipes count TRUNC|APPEND|WRONLY as writer
        });
        rfd as u64 | ((wfd as u64) << 32)
    });
    crate::pipes::open_role(&path, false);
    crate::pipes::open_role(&path, true);
    packed
}

/// SYS_DUP2: clone the open description at `oldfd` into slot `newfd`
/// (closing whatever sat there, like POSIX dup2).
fn sys_dup2(oldfd: u64, newfd: u64) -> u64 {
    if newfd > 4096 {
        return ERR;
    }
    if oldfd == newfd {
        let held = task::with_current(|t| {
            matches!(t.fds.get(oldfd as usize), Some(Some(_)))
        });
        return if held { newfd } else { ERR };
    }
    let f = match task::with_current(|t| match t.fds.get(oldfd as usize) {
        Some(Some(f)) => Some(f.clone()),
        _ => None,
    }) {
        Some(f) => f,
        None => return ERR,
    };
    // close the occupying fd first so pipe roles stay honest
    vfs::close(newfd as i64);
    vfs::acquire_desc(&f);
    task::with_current(|t| {
        while t.fds.len() <= newfd as usize {
            t.fds.push(None);
        }
        t.fds[newfd as usize] = Some(f);
    });
    newfd
}

/// Single-fd readiness, shared by `SYS_POLL` and `SYS_EPOLL_WAIT`.
/// `ev` bit0 = read, bit1 = write. fs/proc/dev fds are always ready both ways.
pub fn fd_ready(path: &str, ev: u32) -> bool {
    if crate::pipes::handles(path) {
        (ev & 1 != 0 && crate::pipes::ready(path, true))
            || (ev & 2 != 0 && crate::pipes::ready(path, false))
    } else if crate::notify::handles(path) {
        // events queued = readable; never writable
        ev & 1 != 0 && crate::notify::ready(path)
    } else if crate::timerfd::handles(path) {
        ev & 1 != 0 && crate::timerfd::ready(path)
    } else if crate::signalfd::handles(path) {
        ev & 1 != 0 && crate::signalfd::ready(path)
    } else if crate::eventfd::handles(path) {
        (ev & 1 != 0 && crate::eventfd::ready(path, true))
            || (ev & 2 != 0 && crate::eventfd::ready(path, false))
    } else if crate::sockpair::handles(path) {
        (ev & 1 != 0 && crate::sockpair::ready(path, true))
            || (ev & 2 != 0 && crate::sockpair::ready(path, false))
    } else if crate::pidfd::handles(path) {
        ev & 1 != 0 && crate::pidfd::ready(path, true)
    } else if crate::epoll::handles(path) {
        false // epoll fds are wait targets, not readable/writable streams
    } else if crate::sockfd::handles(path) {
        (ev & 1 != 0 && crate::sockfd::ready(path, true))
            || (ev & 2 != 0 && crate::sockfd::ready(path, false))
    } else {
        true
    }
}

/// SYS_POLL: wait until any listed fd is ready or `timeout_ms` elapses.
/// `fds`/`evs` are parallel user arrays of u32: events bit0=read bit1=write.
/// Returns the count of ready fds.
fn sys_poll(ctx: &mut CpuContext, fds: u64, evs: u64, nfds: u64, timeout_ms: u64) -> u64 {
    let nfds = nfds.min(64);
    let fdv = match copy_in(fds, nfds * 4) {
        Some(d) => d,
        None => return ERR,
    };
    let evv = match copy_in(evs, nfds * 4) {
        Some(d) => d,
        None => return ERR,
    };
    let rd32 = |v: &[u8], i: usize| u32::from_le_bytes(v[i * 4..i * 4 + 4].try_into().unwrap());
    let paths: Vec<String> = task::with_current(|t| {
        (0..nfds as usize)
            .map(|i| match t.fds.get(rd32(&fdv, i) as usize) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            })
            .collect()
    });
    let mut ready = 0u64;
    for (i, path) in paths.iter().enumerate() {
        if path.is_empty() {
            continue;
        }
        let ev = rd32(&evv, i);
        if fd_ready(path, ev) {
            ready += 1;
        }
    }
    if ready > 0 || timeout_ms == 0 {
        return ready;
    }
    // block: re-enter the syscall until something is ready or deadline hits
    // (u64::MAX = wait forever, same sentinel as waitpid)
    let dl = if timeout_ms == u64::MAX {
        u64::MAX
    } else {
        task::ticks() + timeout_ms.div_ceil(10) + 1
    };
    if task::ticks() >= dl {
        return 0;
    }
    block_reenter(ctx, dl, 0)
}

/// SYS_EPOLL_WAIT: copy {u32 fd, u32 revents} pairs for ready interests to
/// `out` (up to `max`), blocking until at least one is ready or `timeout_ms`
/// elapses (u64::MAX waits forever, like poll).
fn sys_epoll_wait(ctx: &mut CpuContext, epfd: u64, out: u64, max: u64, timeout_ms: u64) -> u64 {
    let ep_path = match task::with_current(|t| match t.fds.get(epfd as usize) {
        Some(Some(f)) if crate::epoll::handles(&f.path) => Some(f.path.clone()),
        _ => None,
    }) {
        Some(p) => p,
        _ => return ERR,
    };
    let max = (max as usize).min(64);
    let hits = crate::epoll::collect(&ep_path, max);
    if !hits.is_empty() {
        let mut buf = alloc::vec![0u8; hits.len() * 8];
        for (i, (fdn, re)) in hits.iter().enumerate() {
            buf[i * 8..i * 8 + 4].copy_from_slice(&fdn.to_le_bytes());
            buf[i * 8 + 4..i * 8 + 8].copy_from_slice(&re.to_le_bytes());
        }
        return match copy_out(out, &buf) {
            Some(()) => hits.len() as u64,
            None => ERR,
        };
    }
    if timeout_ms == 0 {
        return 0;
    }
    let dl = if timeout_ms == u64::MAX {
        u64::MAX
    } else {
        task::ticks() + timeout_ms.div_ceil(10) + 1
    };
    if task::ticks() >= dl {
        return 0;
    }
    block_reenter(ctx, dl, 0)
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
        t.maps.push(task::MapEnt {
            start: vaddr,
            end: vaddr + n,
            perm: 1 | 2,
            name: alloc::format!("shm#{}", id),
        });
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

/// SYS_FUTEX(uaddr, op, val, timeout_ms) — real futex wait/wake.
/// op 0 = FUTEX_WAIT: sleep while *uaddr == val; op 1 = FUTEX_WAKE: wake
/// `val` waiters. The wait key is the word's PHYSICAL page (shared-mm
/// threads and any mapping of the same frame collide; unrelated
/// processes' identical VAs can't). wait_timeout doubles as the
/// re-entry marker; wait_futex is the claimed key a waker clears.
fn sys_futex(ctx: &mut CpuContext, uaddr: u64, op: u64, val: u64, timeout_ms: u64) -> u64 {
    if uaddr & 7 != 0 {
        return ERR;
    }
    let pml4 = task::with_current(|t| t.pml4);
    let Some(pml4) = pml4 else { return ERR };
    // touch the word first: a demand-paged page must be present to key on
    let Some(bytes) = copy_in(uaddr, 8) else {
        return (u64::MAX - 13) as u64; // -EFAULT
    };
    let Some(phys) = elf::translate_user(pml4, uaddr & !0xfff) else {
        return (u64::MAX - 13) as u64;
    };
    let key = phys | (uaddr & 0xfff);
    if op == 1 {
        // FUTEX_WAKE(val = max waiters)
        return task::futex_wake(key, val);
    }
    if op != 0 {
        return (u64::MAX - 21) as u64; // -EINVAL
    }
    let now = task::ticks();
    let was_waiting = task::with_current(|t| t.wait_timeout != 0);
    if !was_waiting {
        // fresh wait: semantics require *uaddr == val at call time
        let cur = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
        if cur != val {
            return (u64::MAX - 10) as u64; // -EAGAIN
        }
        let dl = if timeout_ms == u64::MAX {
            u64::MAX
        } else {
            now + timeout_ms.div_ceil(10) + 1
        };
        task::with_current(|t| {
            t.wait_timeout = dl;
            t.wait_futex = key; // claim — makes us visible to wakers
        });
    } else {
        // re-entry after a scheduler wake
        let (flag, dl) = task::with_current(|t| (t.wait_futex, t.wait_timeout));
        if flag == 0 {
            // a waker cleared our key while we slept
            task::with_current(|t| t.wait_timeout = 0);
            return 0;
        }
        if now >= dl {
            task::with_current(|t| {
                t.wait_timeout = 0;
                t.wait_futex = 0;
            });
            return (u64::MAX - 109) as u64; // -ETIMEDOUT
        }
    }
    // commit to blocking — the waker may have fired between claim and
    // here; it clears wait_futex, so only sleep if the flag still stands
    let (still_wait, dl) = task::with_current(|t| {
        if t.wait_futex == key {
            t.state = task::State::Blocked;
            t.wake_at = t.wait_timeout; // generic tick wake doubles as timeout
            (true, t.wait_timeout)
        } else {
            t.wait_timeout = 0; // claimed-then-woken: count as a wake
            (false, 0)
        }
    });
    let _ = dl;
    if !still_wait {
        return 0;
    }
    ctx.rip -= 2;
    task::yield_ctx(ctx)
}

/// SYS_EXECVE(path_ptr,path_len,args_ptr,args_len): replace the current
/// image — on success the task irets into the new program's entry.
fn sys_execve(ctx: &mut CpuContext, pptr: u64, plen: u64, aptr: u64, alen: u64) -> u64 {
    let Some(pb) = copy_in(pptr, plen.min(4096)) else {
        return ERR;
    };
    let Some(ab) = copy_in(aptr, alen.min(4096)) else {
        return ERR;
    };
    let path = String::from(
        String::from_utf8_lossy(&pb).trim_matches('\0'),
    );
    let args = String::from(
        String::from_utf8_lossy(&ab).trim_matches('\0'),
    );
    if task::exec_current(ctx, &path, &args) {
        0 // unreachable in practice — the frame is already the new image's
    } else {
        ERR
    }
}

/// SYS_SIGACTION(sig, handler): handler 0=SIG_DFL, 1=SIG_IGN, else a
/// userspace handler address. SIGKILL/SIGSTOP are uncatchable.
/// Returns the previous handler value.
/// SYS_SIGALTSTACK(sp, size, flags, old_ptr): register the alternate
/// signal stack handlers run on when installed SA_ONSTACK. flags=SS_DISABLE
/// clears it; old_ptr (24B) receives the previous {sp,size,flags}.
fn sys_sigaltstack(sp: u64, size: u64, flags: u64, old_ptr: u64) -> u64 {
    let old = task::with_current(|t| {
        [
            t.sig.sigstack_sp,
            t.sig.sigstack_size,
            t.sig.sigstack_flags,
        ]
    });
    if old_ptr != 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(old.as_ptr() as *const u8, 24)
        };
        if copy_out_pub(old_ptr, bytes).is_none() {
            return ERR;
        }
    }
    if sp != 0 || size != 0 || flags != 0 {
        task::with_current(|t| {
            if flags & shared::SS_DISABLE != 0 {
                t.sig.sigstack_flags = shared::SS_DISABLE;
            } else {
                t.sig.sigstack_sp = sp;
                t.sig.sigstack_size = size;
                t.sig.sigstack_flags = flags;
            }
        });
    }
    0
}

fn sys_sigaction(sig: u64, handler: u64, flags: u64) -> u64 {
    if sig == 0 || sig >= 32 || sig == 9 || sig == 19 {
        return ERR;
    }
    if handler > 1 && (handler < 0x1000 || handler >= 0x8000_0000_0000) {
        return ERR;
    }
    task::with_current(|t| {
        let old = t.sighandlers[sig as usize];
        t.sighandlers[sig as usize] = handler;
        t.sig.sa_flags[sig as usize] = flags as u8;
        old
    })
}

/// SYS_SIGRETURN: invoked by the restorer trampoline when a signal
/// handler returns — restores the CpuContext pushed by maybe_deliver.
/// Segments/rflags are forced safe: the frame lives on the user stack
/// and could have been tampered with.
/// SYS_SIGPROCMASK(how, mask): 0=SIG_BLOCK(or), 1=SIG_UNBLOCK(and-not),
/// 2=SIG_SETMASK(replace). SIGKILL/SIGSTOP can't be masked — POSIX strips
/// them silently. Returns the previous mask.
fn sys_sigprocmask(how: u64, mask: u64) -> u64 {
    if how > 2 {
        return ERR;
    }
    let mask = mask & !((1u64 << 9) | (1u64 << 19));
    task::with_current(|t| {
        let old = t.sigmask;
        t.sigmask = match how {
            0 => t.sigmask | mask,
            1 => t.sigmask & !mask,
            _ => mask,
        };
        old
    })
}

fn sys_sigreturn(ctx: &mut CpuContext) -> u64 {
    let fbase = ctx.rsp.wrapping_sub(168);
    // restore the mask saved when the handler frame was pushed, and the
    // EINTR marker carried in the byte below the frame
    task::with_current(|t| {
        if t.sig.sigmask_depth > 0 {
            t.sig.sigmask_depth -= 1;
            t.sigmask = t.sig.sigmask_stack[t.sig.sigmask_depth as usize];
        }
    });
    if let Some(e) = copy_in(fbase - 8, 8) {
        if e.len() >= 8 && u64::from_le_bytes(e[..8].try_into().unwrap()) != 0 {
            task::with_current(|t| t.sig.wake_eintr = true);
        }
    }
    let Some(bytes) = copy_in(fbase, 160) else {
        return ERR;
    };
    if bytes.len() < 160 {
        return ERR;
    }
    let mut saved: CpuContext =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const CpuContext) };
    saved.cs = unsafe { crate::gdt::USER_CS.0 as u64 };
    saved.ss = unsafe { crate::gdt::USER_DS.0 as u64 };
    saved.rflags = (saved.rflags & !0x0003_7000) | 0x202;
    let rax = saved.rax;
    *ctx = saved;
    rax // dispatch writes ctx.rax=ret — keeps the restored value
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

/// SYS_SIGSUSPEND(mask): atomically swap the blocked mask and sleep until
/// a signal is deliverable, then restore the old mask and return EINTR.
/// Re-entrant through block_reenter: the pre-suspend mask lives in the
/// task (`sigsuspend_saved`), so every re-entry after a spurious or
/// masked-signal wake re-checks deliverability and re-blocks.
fn sys_sigsuspend(ctx: &mut CpuContext, mask: u64) -> u64 {
    let done = task::with_current(|t| {
        if t.sigsuspend_saved == u64::MAX {
            t.sigsuspend_saved = t.sigmask;
            t.sigsuspend_seq = t.sig_seq;
            t.sigmask = mask & !(1 << 9 | 1 << 19);
        }
        // suspended until a signal is DELIVERED — the handler runs at
        // pick time and consumes the pending bit (bumping sig_seq), so
        // the re-executed int80 lands here after sigreturn and sees the
        // bump; a pending-but-deliverable bit also ends it directly
        (t.sigpending & !t.sigmask != 0) || (t.sig_seq != t.sigsuspend_seq)
    });
    if done {
        task::with_current(|t| {
            t.sigmask = t.sigsuspend_saved;
            t.sigsuspend_saved = u64::MAX;
            0u64
        });
        return (-4i64) as u64; // EINTR
    }
    block_reenter(ctx, task::ticks() + 86_400_000, 0);
}

fn sys_waitpid(ctx: &mut CpuContext, pid: u64, timeout_ms: u64, opts: u64) -> u64 {
    let me = cur_id();
    let any = pid as u32 == u32::MAX;
    // WUNTRACED (bit0 of opts): report a stopped child before blocking —
    // status is the POSIX encoding 0x7f | (sig << 8), once per transition
    if opts & 1 != 0 {
        let got = if any {
            task::child_stopped_any(me)
        } else {
            task::child_stopped_one(me, pid as u32)
        };
        if let Some((cpid, st)) = got {
            return if any {
                ((cpid as u64) << 32) | (st as u64 & 0xffff_ffff)
            } else {
                st as u64
            };
        }
    }
    if any {
        // wait(-1): returns pid<<32 | exit_code of the first dead child
        if let Some((cpid, code)) = task::child_exit_any(me) {
            task::with_current(|t| t.wait_timeout = 0);
            return ((cpid as u64) << 32) | (code as u64 & 0xffff_ffff);
        }
        if !task::has_children(me) {
            return ERR;
        }
    } else {
        if !task::exists(pid as u32) {
            return ERR;
        }
        if let Some(code) = task::child_exit(pid as u32) {
            task::with_current(|t| t.wait_timeout = 0);
            return code as u64;
        }
    }
    let now = task::ticks();
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
    // POSIX EINTR: if a signal woke this blocked syscall and its handler
    // ran without SA_RESTART, the syscall returns EINTR to user code
    // instead of re-blocking. signal() sets wake_eintr; a normal syscall
    // return clears it, so it can never fire stale.
    let intr = task::with_current(|t| {
        if t.sig.wake_eintr {
            t.sig.wake_eintr = false;
            t.sleep_deadline = 0;
            t.wake_at = 0;
            t.wait_port = 0;
            t.waiting_on = 0;
            t.wait_futex = 0;
            true
        } else {
            t.state = task::State::Blocked;
            t.wake_at = deadline;
            t.wait_port = wait_port;
            false
        }
    });
    if intr {
        ctx.rax = (-4i64) as u64; // EINTR — ctx resumes past the int80
        task::yield_ctx(ctx);
    }
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
            task::record_map(
                me,
                info.addr,
                info.addr + (info.stride as u64) * (info.height as u64) * 4,
                1 | 2,
                "[fb]",
            );
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

pub fn power_off() -> ! {
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

pub fn reboot() -> ! {
    unsafe {
        use x86_64::instructions::port::Port;
        let mut p: Port<u8> = Port::new(0x64);
        p.write(0xFEu8);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

/// SYS_PCAP op 4: bounds-check + copy the capture image to userspace.
fn copy_out_pcap(ptr: u64, cap: usize) -> Result<i64, i64> {
    let mut tmp = alloc::vec![0u8; cap];
    let n = crate::pcap::sys_pcap(4, &mut tmp);
    if n < 0 {
        return Err(n);
    }
    match copy_out(ptr, &tmp[..n as usize]) {
        Some(()) => Ok(n),
        None => Err(-2),
    }
}
