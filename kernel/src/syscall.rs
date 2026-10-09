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
/// `uname -n`; set via SYS_HOSTNAME_SET / `hostname <name>`. Lives in the
/// task's UTS namespace so unshare(CLONE_NEWUTS) privatizes it.
pub fn hostname() -> String {
    let g = task::uts_of().lock().hostname.clone();
    if g.is_empty() {
        return String::from("cosmos");
    }
    g
}

/// Set the nodename (also writable via /proc/sys/kernel/hostname).
pub fn set_hostname(s: String) {
    task::uts_of().lock().hostname = s.chars().take(64).collect();
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
    // PTRACE_SYSCALL entry-stop: a tracer armed sc_phase=1, so the tracee
    // halts BEFORE the syscall body runs (rax/rdi/rsi/rdx still hold the
    // args). rip rewinds so CONT re-executes the int80; the re-dispatch
    // then sees sc_phase==2 and falls through to real dispatch.
    task::with_current(|t| {
        t.cur_syscall = nr;
        t.sc_args = [a1, a2, a3, a4, a5];
    });
    // pending pty hangups: master closes queue them (pty::release may run
    // under SCHED during task teardown) — dispatch is a lock-free spot.
    crate::pty::drain_hups();
    // seccomp enforcement: strict kills with SIGKILL on anything outside
    // the POSIX strict allowlist (read/write/exit/sigreturn/exit_group);
    // filter mode returns ENOSYS on any nr outside the installed bitmap.
    let (sc_mode, sc_allow) = task::with_current(|t| (t.seccomp_mode, t.seccomp_allow));
    if sc_mode == 1 {
        let ok = nr == shared::SYS_READ
            || nr == shared::SYS_WRITE
            || nr == shared::SYS_EXIT
            || nr == shared::SYS_SIGRETURN
            || nr == shared::SYS_EXIT_GROUP;
        if !ok {
            task::signal(cur_id(), 9);
            ctx.rax = ERR;
            return;
        }
    } else if sc_mode == 2 {
        let ok = nr < 256 && (sc_allow[(nr / 64) as usize] >> (nr % 64)) & 1 == 1;
        if !ok {
            ctx.rax = (-38i64) as u64; // ENOSYS
            return;
        }
    }
    let entry_stop = task::with_current(|t| {
        // phase 2 = mid-syscall (entry-stop already happened, resume
        // re-executed this int80) — anything else armed is a real entry
        t.sig.syscall_trace && t.sig.sc_phase != 2 && nr != shared::SYS_SIGRETURN
    });
    if entry_stop {
        ctx.rip -= 2;
        {
            let mut g = task::SCHED.lock();
            if let Some(s) = g.as_mut() {
                s.tasks[s.cur].sig.sc_phase = 2;
                s.tasks[s.cur].state = task::State::Stopped;
                s.tasks[s.cur].stop_sig = 5; // SIGTRAP
                s.tasks[s.cur].stop_notified = false;
            }
        }
        task::yield_ctx(ctx);
    }
    let ret: u64 = match nr {
        shared::SYS_EXIT => {
            // POSIX ptrace: a traced task must stop for pending signals
            // before it dies — the tracer sees the exit boundary stop
            let traced = task::with_current(|t| t.sig.traced && t.sigpending != 0);
            if traced {
                let mut g = task::SCHED.lock();
                if let Some(s) = g.as_mut() {
                    task::maybe_deliver(s, s.cur, ctx);
                    if s.tasks[s.cur].state != task::State::Running {
                        drop(g);
                        ctx.rip -= 2; // re-enter SYS_EXIT once CONTed
                        task::yield_ctx(ctx);
                    }
                }
            }
            task::exit_current(ctx.rdi as i64);
        }
        shared::SYS_YIELD => {
            ctx.rax = 0;
            task::yield_ctx(ctx);
        }
        shared::SYS_SPAWN => sys_spawn(a1, a2, a3, a4),
        shared::SYS_RDMSR => sys_rdmsr(a1),
        shared::SYS_SLEEP_MS => sys_sleep(ctx, a1),
        shared::SYS_MMAP => sys_mmap(a1, a2, a3),
        shared::SYS_MMAP_FILE => sys_mmap_file(a1, a2, a3),
        shared::SYS_CLONE => match task::clone_user(a1, a2, a3, a4) {
            Some(pid) => task::reported_child_pid(pid) as u64,
            None => ERR,
        },
        shared::SYS_FUTEX => sys_futex(ctx, a1, a2, a3, a4),
        shared::SYS_FORK => task::fork_current(ctx)
            .map(|p| task::reported_child_pid(p) as u64)
            .unwrap_or(ERR),
        shared::SYS_EXECVE => sys_execve(ctx, a1, a2, a3, a4),
        shared::SYS_SIGACTION => sys_sigaction(a1, a2, a3),
        shared::SYS_SIGALTSTACK => sys_sigaltstack(a1, a2, a3, a4),
        shared::SYS_PTRACE => sys_ptrace(a1, a2 as u32, a3, a4),
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
        shared::SYS_GETPGID => {
            task::sys_getpgid(task::visible_pid(a1 as i64) as u32) as u64
        }
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
        shared::SYS_GETPPID => task::parent_pid_view(),
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
        shared::SYS_UPTIME_MS => task::uptime_ms_ns(),
        shared::SYS_PROCLIST => sys_proclist(a1, a2),
        shared::SYS_POWEROFF => {
            crate::sprint!("poweroff\n");
            power_off();
        }
        shared::SYS_REBOOT => sys_reboot_call(a1, a2, a3),
        shared::SYS_FB_INFO => sys_fb_info(a1),
        shared::SYS_CHDIR => sys_chdir(a1, a2),
        shared::SYS_GETCWD => sys_getcwd(a1, a2),
        shared::SYS_WAITPID => {
            sys_waitpid(ctx, task::visible_pid(a1 as i64) as u64, a2, a3)
        }
        shared::SYS_WAITID => sys_waitid(ctx, a1, a2, a3),
        shared::SYS_EXIT_GROUP => task::exit_group(ctx.rdi as i64),
        shared::SYS_GETTID => task::with_current(|t| t.id as u64),
        shared::SYS_TGKILL => task::sys_tgkill(
            task::visible_pid(a1 as i64) as u32,
            task::visible_pid(a2 as i64) as u32,
            a3,
        ) as u64,
        shared::SYS_SETITIMER => {
            // (which 0..3, init_ms, interval_ms) -> 0 | err
            if a1 > 2 {
                ERR
            } else {
                task::with_current(|t| {
                    t.itimers[a1 as usize] =
                        [a2.div_ceil(10).min(u64::MAX / 2), a3 / 10];
                });
                0
            }
        }
        shared::SYS_GETITIMER => {
            if a1 > 2 {
                ERR
            } else {
                let it = task::with_current(|t| t.itimers[a1 as usize]);
                ((it[0] * 10) << 32) | (it[1] * 10)
            }
        }
        shared::SYS_MQ_OPEN => {
            let Some(nb) = copy_in(a1, a2.min(64)) else {
                ctx.rax = ERR;
                return;
            };
            let name = String::from_utf8_lossy(&nb).into_owned();
            let Ok(path) = crate::mqueue::open(&name, a3 as usize, a4 as usize) else {
                ctx.rax = ERR;
                return;
            };
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR; };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: 0,
                });
                fd as u64
            })
        }
        shared::SYS_MQ_SEND => {
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) if crate::mqueue::handles(&f.path) => Some(f.path.clone()),
                _ => None,
            });
            let Some(path) = path else {
                ctx.rax = ERR;
                return;
            };
            let Some(data) = copy_in(a2, a3.min(1 << 16)) else {
                ctx.rax = ERR;
                return;
            };
            match crate::mqueue::send(&path, &data, a4 as u32) {
                Ok(_) => 0, // POSIX mq_send returns 0
                Err(-11) => {
                    if fd_nonblock(a1 as usize) {
                        (-11i64) as u64
                    } else {
                        block_reenter(ctx, task::ticks() + 2, 0)
                    }
                }
                Err(e) => e as u64,
            }
        }
        shared::SYS_MQ_RECV => {
            let path = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) if crate::mqueue::handles(&f.path) => Some(f.path.clone()),
                _ => None,
            });
            let Some(path) = path else {
                ctx.rax = ERR;
                return;
            };
            let mut buf = vec![0u8; a3.min(1 << 16) as usize];
            match crate::mqueue::recv(&path, &mut buf) {
                Ok((n, prio)) => match copy_out(a2, &buf[..n]) {
                    Some(_) => ((prio as u64) << 32) | (n as u64),
                    None => ERR,
                },
                Err(-11) => {
                    if fd_nonblock(a1 as usize) {
                        (-11i64) as u64
                    } else {
                        block_reenter(ctx, task::ticks() + 2, 0)
                    }
                }
                Err(e) => e as u64,
            }
        }
        shared::SYS_MEMFD_CREATE => {
            let Some(nb) = copy_in(a1, a2.min(64)) else {
                ctx.rax = ERR;
                return;
            };
            let name = String::from_utf8_lossy(&nb).into_owned();
            let Ok(path) = crate::memfd::create(&name) else {
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
        shared::SYS_TIMER_CREATE => {
            // (sig) -> timer id: per-task POSIX timer slot
            task::with_current(|t| {
                let id = (t.ptimers.iter().map(|p| p.id).max().unwrap_or(0)) + 1;
                t.ptimers.push(task::PTimer {
                    id,
                    cur: 0,
                    int: 0,
                    sig: a1,
                });
                id
            })
        }
        shared::SYS_TIMER_SETTIME => {
            // (id, init_ms, interval_ms) -> 0|err
            task::with_current(|t| match t.ptimers.iter_mut().find(|p| p.id == a1) {
                Some(pt) => {
                    pt.cur = a2.div_ceil(10).min(u64::MAX / 2);
                    pt.int = a3 / 10;
                    0
                }
                None => ERR,
            })
        }
        shared::SYS_TIMER_DELETE => {
            task::with_current(|t| {
                let n = t.ptimers.len();
                t.ptimers.retain(|p| p.id != a1);
                if t.ptimers.len() < n { 0 } else { ERR }
            })
        }
        shared::SYS_CLOCK_GETTIME => {
            // (clkid, out_ptr): clk 0 = realtime (rtc epoch ms), 1 = monotonic
            let ms = if a1 == 1 {
                task::ticks_ns() * 10
            } else if a1 == 0 {
                crate::timer::rtc_ms()
            } else {
                ctx.rax = ERR;
                return;
            };
            let v = [ms / 1000, (ms % 1000) * 1_000_000];
            match copy_out(a2, unsafe {
                core::slice::from_raw_parts(v.as_ptr() as *const u8, 16)
            }) {
                Some(_) => 0,
                None => ERR,
            }
        }
        shared::SYS_SPLICE => sys_splice(a1, a2, a3),
        shared::SYS_PROCESS_VM => sys_process_vm(a1, a2, a3, a4, a5),
        shared::SYS_PPOLL => sys_ppoll(ctx, a1, a2, a3, a4, a5),
        shared::SYS_SYSINFO => sys_sysinfo(a1),
        shared::SYS_CLOSE_RANGE => sys_close_range(a1, a2),
        shared::SYS_PIDFD_SIGNAL => sys_pidfd_signal(a1, a2),
        shared::SYS_OPENPT => {
            // posix_openpt folded: master fd; slave lives at /dev/pts/{id}
            let path = crate::pty::create();
            task::with_current(|t| {
                let Some(s) = alloc_slot(t) else { return ERR; };
                t.fds[s] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: shared::O_RDWR,
                });
                s as u64
            })
        }
        shared::SYS_TCSETS => task::with_current(|t| match t.fds.get(a1 as usize) {
            Some(Some(f)) if crate::pty::handles(&f.path) => {
                crate::pty::tcset(&f.path, a2) as u64
            }
            _ => ERR,
        }),
        shared::SYS_TCGETS => task::with_current(|t| match t.fds.get(a1 as usize) {
            Some(Some(f)) if crate::pty::handles(&f.path) => {
                crate::pty::tcget(&f.path) as u64
            }
            _ => ERR,
        }),
        shared::SYS_TCGETPGRP => task::with_current(|t| match t.fds.get(a1 as usize) {
            Some(Some(f)) if crate::pty::handles(&f.path) => {
                crate::pty::fg_pgid_of(&f.path) as u64
            }
            _ => ERR,
        }),
        shared::SYS_TCSETPGRP => task::with_current(|t| match t.fds.get(a1 as usize) {
            Some(Some(f)) if crate::pty::handles(&f.path) => {
                crate::pty::set_fg_pgid(&f.path, a2 as u32) as u64
            }
            _ => ERR,
        }),
        shared::SYS_CAPGET => sys_capget(a1, a2),
        shared::SYS_CAPSET => sys_capset(a1, a2),
        shared::SYS_TIOCSTI => {
            // Linux gates TIOCSTI on CAP_SYS_ADMIN.
            if !task::capable(task::CAP_SYS_ADMIN) {
                ERR
            } else {
                task::with_current(|t| match t.fds.get(a1 as usize) {
                    Some(Some(f)) if crate::pty::handles(&f.path) => {
                        crate::pty::tiocsti(&f.path, a2 as u8) as u64
                    }
                    _ => ERR,
                })
            }
        }
        shared::SYS_PTSNAME => {
            let sp = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => crate::pty::slave_path(&f.path),
                _ => None,
            });

            match sp {
                Some(name) => {
                    let want = (a3 as usize).min(64);
                    let bytes = &name.as_bytes()[..name.len().min(want)];
                    match copy_out(a2, bytes) {
                        Some(_) => bytes.len() as u64,
                        None => ERR,
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_OPENAT => match resolve_at(a1 as i64, a2, a3) {
            Some(p) => match vfs::open(&p, a4) {
                Ok(fd) => fd as u64,
                Err(e) => e as u64,
            },
            None => ERR,
        },
        shared::SYS_FSTATAT => sys_fstatat(a1 as i64, a2, a3, a4, a5),
        shared::SYS_FACCESSAT => sys_access_at(a1 as i64, a2, a3, a4),
        shared::SYS_ACCESS => sys_access_at(shared::AT_FDCWD, a1, a2, a3),
        shared::SYS_UNLINKAT => match resolve_at(a1 as i64, a2, a3) {
            Some(p) => {
                // POSIX split: unlink() on a dir is EISDIR, rmdir() on a
                // non-dir is ENOTDIR.
                match vfs::stat_path(&p) {
                    Ok(st) if st.is_dir != 0 && a4 & shared::AT_REMOVEDIR == 0 => {
                        (-21i64) as u64
                    }
                    Ok(st) if st.is_dir == 0 && a4 & shared::AT_REMOVEDIR != 0 => {
                        (-20i64) as u64
                    }
                    Ok(_) => vfs::remove(&p).map(|_| 0).unwrap_or_else(|e| e as u64),
                    Err(e) => e as u64,
                }
            }
            None => ERR,
        },
        shared::SYS_RENAMEAT => {
            // 6-arg shape doesn't fit the 5-register ABI: a1 packs the two
            // dirfds (old low 32, new high 32), then opath,olen,npath,nlen.
            let (o, n) = (
                resolve_at(a1 as u32 as i32 as i64, a2, a3),
                resolve_at((a1 >> 32) as u32 as i32 as i64, a4, a5),
            );
            match (o, n) {
                (Some(o), Some(n)) => vfs::rename(&o, &n).map(|_| 0).unwrap_or_else(|e| e as u64),
                _ => ERR,
            }
        }
        shared::SYS_MKDIRAT => match resolve_at(a1 as i64, a2, a3) {
            Some(p) => vfs::mkdir(&p).map(|_| 0).unwrap_or_else(|e| e as u64),
            None => ERR,
        },
        shared::SYS_LINKAT => ERR, // -38 ENOSYS: FAT32 has no hard links
        shared::SYS_SYMLINKAT => {
            let (t, n) = (copy_str(a1, a2), resolve_at(a3 as i64, a4, a5));
            match (t, n) {
                (Some(t), Some(n)) => sys_symlink_impl(&t, &n),
                _ => ERR,
            }
        }
        shared::SYS_READLINKAT => match resolve_at(a1 as i64, a2, a3) {
            Some(p) => match vfs::readlink_path(&p) {
                Ok(t) => {
                    let bytes = t.as_bytes();
                    let n = bytes.len().min(a5 as usize);
                    match copy_out(a4, &bytes[..n]) {
                        Some(_) => n as u64,
                        None => ERR,
                    }
                }
                Err(e) => e as u64,
            },
            None => ERR,
        },
        shared::SYS_FCHDIR => {
            let p = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => Some(f.path.clone()),
                _ => None,
            });
            match p {
                Some(p) => {
                    let is_dir = crate::proc::is_dir(&p)
                        || crate::dev::is_dir(&p)
                        || {
                            let mut g = vfs::FS.lock();
                            g.as_mut().and_then(|fs| fs.stat(&p).ok()).map(|s| s.is_dir).unwrap_or(false)
                        };
                    if is_dir {
                        task::with_current(|t| t.cwd = p);
                        0
                    } else {
                        (-20i64) as u64 // ENOTDIR
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_FCHMOD => {
            let p = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => Some(f.path.clone()),
                _ => None,
            });
            match p {
                Some(p) => {
                    // FAT has no mode bits; the one meaningful mapping is
                    // owner-write masked out -> readonly attribute.
                    let cur = {
                        let mut g = vfs::FS.lock();
                        g.as_mut().and_then(|fs| fs.stat(&p).ok()).map(|s| s.attr)
                    };
                    match cur {
                        Some(attr) => {
                            let attr = if a2 & 0o200 != 0 { attr & !0x01 } else { attr | 0x01 };
                            vfs::setattr(&p, attr).map(|_| 0).unwrap_or_else(|e| e as u64)
                        }
                        None => (-2i64) as u64,
                    }
                }
                None => ERR,
            }
        }
        shared::SYS_GETDENTS => {
            let p = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => Some(f.path.clone()),
                _ => None,
            });
            match p {
                Some(p) => match vfs::listdir(&p) {
                    Ok(mut ents) => {
                        ents.truncate(a3 as usize);
                        let n = ents.len();
                        let bytes = unsafe {
                            core::slice::from_raw_parts(
                                ents.as_ptr() as *const u8,
                                n * core::mem::size_of::<shared::DirEntry>(),
                            )
                        };
                        match copy_out(a2, bytes) {
                            Some(_) => n as u64,
                            None => ERR,
                        }
                    }
                    Err(e) => e as u64,
                },
                None => ERR,
            }
        }
        shared::SYS_WAIT4 => {
            sys_wait4(ctx, task::visible_pid(a1 as i64) as u64, a2, a3, a4)
        }
        shared::SYS_SECCOMP => {
            // one-way door: once set, the filter can only tighten (POSIX
            // seccomp rules — there is no unset).
            let already = task::with_current(|t| t.seccomp_mode);
            if already == 1 {
                ERR
            } else if a1 == shared::SECCOMP_MODE_STRICT {
                task::with_current(|t| t.seccomp_mode = 1);
                0
            } else if a1 == shared::SECCOMP_MODE_FILTER {
                match copy_in(a2, a3.min(32)) {
                    Some(d) if d.len() == 32 => {
                        let mut w = [0u64; 4];
                        for i in 0..4 {
                            w[i] = u64::from_le_bytes(d[i * 8..i * 8 + 8].try_into().unwrap());
                        }
                        task::with_current(|t| {
                            t.seccomp_allow = w;
                            t.seccomp_mode = 2;
                        });
                        0
                    }
                    _ => ERR,
                }
            } else {
                ERR
            }
        }
        shared::SYS_SET_ROBUST_LIST => {
            task::with_current(|t| t.robust_list = a1);
            0
        }
        shared::SYS_STATFS => match copy_str(a1, a2) {
            Some(p) => sys_statfs_out(&p, a3),
            None => ERR,
        },
        shared::SYS_FSTATFS => {
            let ok = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(_)) => true,
                _ => false,
            });
            if ok {
                sys_statfs_out("/", a2)
            } else {
                ERR
            }
        }
        shared::SYS_SYNCFS => {
            let ok = task::with_current(|t| match t.fds.get(a1 as usize) {
                Some(Some(f)) => !crate::pipes::handles(&f.path),
                _ => false,
            });
            if ok && crate::virtio::flush_disk() { 0 } else { ERR }
        }
        shared::SYS_FALLOCATE => sys_fallocate(a1, a2, a3),
        shared::SYS_COPY_FILE_RANGE => {
            // (in_fd, out_fd, len): kernel-side file->file copy using each
            // fd's own position (POSIX null-offset semantics — positions
            // advance by what was moved).
            let mut v = vec![0u8; a3.min(1 << 20) as usize];
            match vfs::read(a1 as i64, &mut v) {
                Ok(n) => {
                    v.truncate(n as usize);
                    match vfs::write(a2 as i64, &v) {
                        Ok(w) => w as u64,
                        Err(e) => e as u64,
                    }
                }
                Err(e) => e as u64,
            }
        }
        shared::SYS_TEE => {
            let (i, o) = task::with_current(|t| {
                (
                    t.fds.get(a1 as usize).and_then(|s| s.as_ref()).map(|f| f.path.clone()),
                    t.fds.get(a2 as usize).and_then(|s| s.as_ref()).map(|f| f.path.clone()),
                )
            });
            match (i, o) {
                (Some(i), Some(o)) => match crate::pipes::tee(&i, &o, a3 as usize) {
                    Ok(n) => n,
                    Err(e) => e as u64,
                },
                _ => ERR,
            }
        }
        shared::SYS_PSELECT => sys_pselect(ctx, a1, a2, a3, a4, a5),
        shared::SYS_DUP3 => {
            if a3 & !shared::O_CLOEXEC != 0 {
                (-22i64) as u64 // EINVAL: dup3 only accepts O_CLOEXEC
            } else {
                let r = sys_dup2(a1, a2);
                if r != ERR && a3 != 0 {
                    task::with_current(|t| {
                        if let Some(Some(f)) = t.fds.get_mut(a2 as usize) {
                            f.flags |= shared::O_CLOEXEC;
                        }
                    });
                }
                r
            }
        }
        shared::SYS_SCHED_YIELD => {
            ctx.rax = 0;
            task::yield_ctx(ctx);
        }
        shared::SYS_CLOCK_NANOSLEEP => {
            // absolute deadline in ms; ticks run 10ms each. A past deadline
            // returns immediately (POSIX TIMER_ABSTIME).
            let dl = a2.div_ceil(10);
            if task::ticks() < dl {
                block_reenter(ctx, dl, 0)
            } else {
                0
            }
        }
        shared::SYS_SET_TID_ADDRESS => task::with_current(|t| {
            t.ctid_va = a1;
            t.id as u64
        }),
        shared::SYS_PIPE2 => sys_pipe_flags(a1 & (shared::O_NONBLOCK | shared::O_CLOEXEC)),
        shared::SYS_EVENTFD2 => {
            // a2: EFD_SEMAPHORE|EFD_NONBLOCK|EFD_CLOEXEC
            let sem = if a2 & 1 != 0 { 1u32 } else { 0u32 };
            let Ok(path) = crate::eventfd::create(a1, sem) else {
                ctx.rax = ERR;
                return;
            };
            let fl = a2 & (shared::EFD_NONBLOCK | shared::EFD_CLOEXEC);
            task::with_current(|t| {
                let Some(fd) = alloc_slot(t) else { return ERR };
                t.fds[fd] = Some(task::FileDesc {
                    path,
                    pos: 0,
                    flags: fl,
                });
                fd as u64
            })
        }
        shared::SYS_RENAMEAT2 => {
            // 7 args don't fit the register ABI: a1 points at a u64[7]
            // {odfd, optr, olen, ndfd, nptr, nlen, flags}
            let Some(args) = copy_in(a1, 56) else {
                ctx.rax = ERR;
                return;
            };
            let rd = |i: usize| u64::from_le_bytes(args[i * 8..i * 8 + 8].try_into().unwrap());
            let (o, n) = (
                resolve_at(rd(0) as u32 as i32 as i64, rd(1), rd(2)),
                resolve_at(rd(3) as u32 as i32 as i64, rd(4), rd(5)),
            );
            match (o, n) {
                (Some(o), Some(n)) => vfs::rename2(&o, &n, rd(6))
                    .map(|_| 0)
                    .unwrap_or_else(|e| e as u64),
                _ => ERR,
            }
        }
        shared::SYS_UTIMENSAT => {
            // (dirfd, path, plen, times[4u64]|0, flags); times = {atime, mtime}
            // each {sec, nsec}. FAT32 stores mtime at 2s granularity — atime
            // is accepted and discarded like other coarse-fs fields.
            let p = if a3 == 0 && a5 & shared::AT_EMPTY_PATH != 0 {
                task::with_current(|t| match t.fds.get(a1 as usize) {
                    Some(Some(f)) => Some(f.path.clone()),
                    _ => None,
                })
            } else {
                resolve_at(a1 as i64, a2, a3)
            };
            let secs = if a4 == 0 {
                vfs::now_unix()
            } else {
                match copy_in(a4, 32) {
                    Some(t) => u64::from_le_bytes(t[16..24].try_into().unwrap()),
                    None => {
                        ctx.rax = ERR;
                        return;
                    }
                }
            };
            match p {
                Some(p) => vfs::utime(&p, secs).map(|_| 0).unwrap_or_else(|e| e as u64),
                None => ERR,
            }
        }
        shared::SYS_MOUNT => sys_mount(a1),
        shared::SYS_UMOUNT => sys_umount(a1, a2, a3),
        shared::SYS_STATX => sys_statx(a1),
        shared::SYS_PIVOT_ROOT => sys_pivot_root(a1),
        shared::SYS_OPENAT2 => sys_openat2(a1),
        shared::SYS_GETRANDOM => sys_getrandom(a1, a2, a3),
        shared::SYS_MINCORE => sys_mincore(a1, a2, a3),
        shared::SYS_MADVISE => sys_madvise(a1, a2, a3),
        shared::SYS_UNSHARE => sys_unshare(a1),
        shared::SYS_SETNS => sys_setns(a1),
        shared::SYS_PIDFD_GETFD => sys_pidfd_getfd(a1, a2, a3),
        shared::SYS_SYSLOG => sys_syslog(a1, a2, a3),
        shared::SYS_TFD_GET => sys_tfd_gettime(a1, a2),
        shared::SYS_GETUID => {
            task::with_current(|t| task::map_uid_in(t.user_ns, t.uid, false) as u64)
        }
        shared::SYS_GETGID => {
            task::with_current(|t| task::map_uid_in(t.user_ns, t.gid, true) as u64)
        }
        shared::SYS_GETEUID => {
            task::with_current(|t| task::map_uid_in(t.user_ns, t.euid, false) as u64)
        }
        shared::SYS_GETEGID => {
            task::with_current(|t| task::map_uid_in(t.user_ns, t.egid, true) as u64)
        }
        shared::SYS_SETUID => sys_setid(a1, false),
        shared::SYS_SETGID => sys_setid(a1, true),
        shared::SYS_GETGROUPS => sys_getgroups(a1, a2),
        shared::SYS_SETGROUPS => sys_setgroups(a1, a2),
        shared::SYS_SETRESUID => sys_setresid(a1, a2, a3, false),
        shared::SYS_SETRESGID => sys_setresid(a1, a2, a3, true),
        shared::SYS_GETRESUID => sys_getresid(a1, false),
        shared::SYS_GETRESGID => sys_getresid(a1, true),
        shared::SYS_CHOWN => sys_chown(a1, a2, a3, a4),
        shared::SYS_FCHOWN => sys_fchown(a1, a2, a3),
        shared::SYS_CHMOD => sys_chmod(a1, a2, a3),
        shared::SYS_CHROOT => sys_chroot(a1, a2),
        shared::SYS_GETTIMEOFDAY => {
            let sec = vfs::now_unix();
            let usec = (task::ticks() % 100) * 10_000; // 10ms tick granularity
            let b = [sec.to_le_bytes(), usec.to_le_bytes()].concat();
            match copy_out(a1, &b) {
                Some(_) => 0,
                None => ERR,
            }
        }
        shared::SYS_MQ_UNLINK => {
            let Some(nb) = copy_in(a1, a2.min(64)) else {
                ctx.rax = ERR;
                return;
            };
            let name = String::from_utf8_lossy(&nb).into_owned();
            crate::mqueue::unlink(&name) as u64
        }
        shared::SYS_KILL => {
            let p = task::visible_pid(a1 as i64) as u32;
            if !task::signal_perm(p) {
                (-1i64) as u64 // EPERM
            } else {
                sys_kill(p as u64)
            }
        }
        shared::SYS_NET_PING => {
            let ip = [
                (a1 >> 24) as u8,
                (a1 >> 16) as u8,
                (a1 >> 8) as u8,
                a1 as u8,
            ];
            net::ping_ttl(ip, a2.min(10_000), a3 as u8).unwrap_or(ERR)
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
            if !task::capable(task::CAP_SYS_TIME) {
                ERR
            } else {
                crate::timer::set_unix(a1);
                0
            }
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
                    // POSIX: dup clears CLOEXEC on the new descriptor
                    let nf = task::FileDesc {
                        path: src.path.clone(),
                        pos: src.pos,
                        flags: src.flags & !shared::O_CLOEXEC,
                    };
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
                shared::F_GETFD => match t.fds.get(i) {
                    Some(Some(f)) => (f.flags & shared::O_CLOEXEC != 0) as u64,
                    _ => ERR,
                },
                shared::F_SETFD => match t.fds.get_mut(i) {
                    Some(Some(f)) => {
                        if a3 & 1 != 0 {
                            f.flags |= shared::O_CLOEXEC;
                        } else {
                            f.flags &= !shared::O_CLOEXEC;
                        }
                        0
                    }
                    _ => ERR,
                },
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
        shared::SYS_GETPID => task::current_pid() as u64,
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
        shared::SYS_KILL2 => {
            let p = task::visible_pid(a1 as i64) as u32;
            if !task::signal_perm(p) {
                (-1i64) as u64 // EPERM
            } else {
                task::signal(p, a2) as u64
            }
        }
        shared::SYS_HOSTNAME_GET => {
            let h = hostname();
            let n = h.len().min(a2 as usize);
            match copy_out(a1, &h.as_bytes()[..n]) {
                Some(()) => n as u64,
                None => ERR,
            }
        }
        shared::SYS_HOSTNAME_SET => {
            if !task::capable(task::CAP_SYS_ADMIN) {
                ERR
            } else {
                match copy_in(a1, a2.min(64)) {
                    Some(b) => {
                        let h = String::from(
                            String::from_utf8_lossy(&b).trim(),
                        );
                        if h.is_empty() {
                            ERR
                        } else {
                            set_hostname(h);
                            0
                        }
                    }
                    None => ERR,
                }
            }
        }
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
        s.tasks[s.cur].cur_syscall = u64::MAX;
        task::maybe_deliver(s, s.cur, ctx);
        // PTRACE_SYSCALL exit-stop: the syscall's result is already in
        // ctx.rax; mark the tracee Stopped so the repick below switches
        // away instead of resuming it. The next PTRACE_SYSCALL re-arms
        // sc_phase=1. This MUST use the live Sched borrow — a nested
        // SCHED.lock() here deadlocks the non-reentrant spin mutex.
        if nr != shared::SYS_SIGRETURN
            && s.tasks[s.cur].state == task::State::Running
            && s.tasks[s.cur].sig.syscall_trace
            && s.tasks[s.cur].sig.sc_phase == 2
        {
            // phase 1 = next boundary is the NEXT syscall's entry
            s.tasks[s.cur].sig.sc_phase = 1;
            s.tasks[s.cur].state = task::State::Stopped;
            s.tasks[s.cur].stop_sig = 5;
            s.tasks[s.cur].stop_notified = false;
        }
        if s.tasks[s.cur].state == task::State::Dead
            || s.tasks[s.cur].state == task::State::Stopped
        {
            // uncaught signal killed or stopped us — never resume it
            drop(g);
            task::yield_ctx(ctx);
        }
    }
}

/// rdmsr — read an architecturally safe model-specific register.
/// Whitelist only: an unimplemented MSR #GPs inside the kernel, which
/// would panic — out-of-set indexes get -ENOSYS instead.
fn sys_rdmsr(msr: u64) -> u64 {
    const OK: &[u32] = &[
        0x10,          // IA32_TSC
        0x1b,          // IA32_APIC_BASE
        0x174, 0x175, 0x176, // SYSENTER CS/ESP/EIP
        0x1a0,         // IA32_MISC_ENABLE
        0x277,         // IA32_PAT
        0xc000_0080,   // EFER
        0xc000_0081, 0xc000_0082, 0xc000_0084, // STAR/LSTAR/SFMASK
        0xc000_0100, 0xc000_0101, 0xc000_0102, // FS/GS/KernelGS base
    ];
    if !OK.contains(&(msr as u32)) {
        return (-38i64) as u64;
    }
    unsafe { x86_64::registers::model_specific::Msr::new(msr as u32).read() }
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
            task::reported_child_pid(pid) as u64
        }
        Err(_) => ERR,
    }
}

/// SYS_MMAP(size, flags, addr): anonymous demand map. flags bit0 =
/// MAP_FIXED: place at `addr` (4k-aligned, user range), evicting any
/// overlapping maps first — POSIX MAP_FIXED replace semantics.
fn sys_mmap(size: u64, flags: u64, addr: u64) -> u64 {
    if size == 0 || size > 64 << 20 {
        return 0;
    }
    let fixed = flags & 1 != 0;
    // MAP_FIXED bound: inside the user mmap region — below the stack/argv
    // zone (USER_STACK region sits at ~0x7e00_0000+)
    if fixed && (addr & 0xfff != 0 || addr >= 0x7e00_0000 || addr < 0x10_0000) {
        return 0;
    }
    // RLIMIT_AS (res 9): the new range must fit the task's total mapped
    // bytes bound — checked against the live maps table
    let over = task::with_current(|t| {
        let used: u64 = t.maps.iter().map(|m| m.end - m.start).sum();
        used.saturating_add(size) > t.rlim_as
    });
    if over {
        return 0;
    }
    let pages = size.div_ceil(0x1000);
    if fixed {
        // POSIX MAP_FIXED: evict overlapping maps first (real munmap —
        // unmaps frames, releases COW/shm bookkeeping, propagates to
        // thread peers) before the fresh map lands on the range
        let end = addr + pages * 0x1000;
        let overlaps: Vec<(u64, u64)> = task::with_current(|t| {
            t.maps
                .iter()
                .filter(|m| m.start < end && m.end > addr)
                .map(|m| (m.start, m.end))
                .collect()
        });
        for (s0, e0) in overlaps {
            sys_munmap(s0, e0 - s0);
        }
    }
    // (real anon mmap — see SYS_MUNMAP/SYS_MPROTECT for the full lifecycle)
    let pp = task::with_current(|t| t.pml4.map(|p| p.start_address().as_u64()));
    let Some(pp) = pp else { return 0 };
    // reserve across ALL peers of the mm — two threads can't collide
    let base = if fixed { addr } else { task::mm_reserve(pp, pages) };
    if base == 0 {
        return 0;
    }
    task::with_current(|t| {
        let Some(pml4) = t.pml4 else { return 0 };
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
    // RLIMIT_AS: same bound as sys_mmap
    let over = task::with_current(|t| {
        let used: u64 = t.maps.iter().map(|m| m.end - m.start).sum();
        used.saturating_add(size) > t.rlim_as
    });
    if over {
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
    let pages = size.div_ceil(0x1000);
    let pp = task::with_current(|t| t.pml4.map(|p| p.start_address().as_u64()));
    let Some(pp) = pp else { return 0 };
    let base = task::mm_reserve(pp, pages);
    if base == 0 {
        return 0;
    }
    task::with_current(|t| {
        if t.pml4.is_none() {
            return 0;
        }
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
    let changed = task::with_current(|t| {
        let Some(pml4) = t.pml4 else { return 0 };
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
        changed
    });
    if changed == 0 {
        return ERR;
    }
    // perm bookkeeping propagates to every thread of the mm — peers
    // share the page tables, so their maps must agree
    let pp = task::with_current(|t| t.pml4.map(|p| p.start_address().as_u64()));
    if let Some(pp) = pp {
        task::for_mm_peers(pp, |o| {
            for m in o.maps.iter_mut() {
                if m.end <= addr || m.start >= end {
                    continue;
                }
                m.perm = (prot & 7) as u8;
            }
        });
    }
    unsafe { x86_64::instructions::tlb::flush_all() };
    0
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
        Ok(fd) => {
            // POSIX ctty acquisition: a session leader with no controlling
            // terminal takes the tty it just opened (unless O_NOCTTY).
            if flags & shared::O_NOCTTY == 0 {
                if let Some(id) = path
                    .strip_prefix("/dev/pts/")
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    task::with_current(|t| {
                        if t.sid == t.id && t.ctty == 0 {
                            t.ctty = id;
                        }
                    });
                }
            }
            fd as u64
        }
        Err(e) => e as u64,
    }
}

/// One non-blocking read attempt against `fd`'s backend — the shared read
/// path used by sys_read/readv/sendfile. Err(-11) = would block.
fn fd_read_once(fd: usize, buf: &mut [u8]) -> Result<usize, i64> {
    let (path, oflags) = task::with_current(|t| match t.fds.get(fd) {
        Some(Some(f)) => Some((f.path.clone(), f.flags)),
        _ => None,
    })
    .ok_or(-3i64)?;
    if oflags & shared::O_PATH != 0 {
        return Err(-9); // EBADF: O_PATH fds are pathname-only
    }
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
    if crate::pty::handles(&path) {
        return crate::pty::try_read(&path, buf);
    }
    match vfs::read(fd as i64, buf) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// One non-blocking write attempt against `fd`'s backend. Err(-11) = would
/// block; Err(-32) = EPIPE.
fn fd_write_once(fd: usize, data: &[u8]) -> Result<usize, i64> {
    let (path, oflags) = task::with_current(|t| match t.fds.get(fd) {
        Some(Some(f)) => Some((f.path.clone(), f.flags)),
        _ => None,
    })
    .ok_or(-3i64)?;
    if oflags & shared::O_PATH != 0 {
        return Err(-9); // EBADF: O_PATH fds are pathname-only
    }
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
    if crate::pty::handles(&path) {
        return crate::pty::try_write(&path, data);
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
    // Chunked: the whole write never sits in one kernel allocation — a
    // single 1MiB Vec can OOM the 4MiB heap under fragmentation, which
    // made write(fd, buf, 1<<20) a userspace-triggerable kernel panic.
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(1 << 17); // 128KiB
        let Some(data) = copy_in(buf + done, n) else {
            return if done > 0 { done } else { ERR };
        };
        match fd_write_once(fd as usize, &data) {
            Err(-11) => {
                if done > 0 {
                    return done;
                }
                if fd_nonblock(fd as usize) {
                    return (-11i64) as u64;
                }
                return block_reenter(ctx, task::ticks() + 2, 0);
            }
            Err(-32) => {
                // POSIX: a write that fails with EPIPE also raises SIGPIPE.
                task::signal(cur_id(), 13);
                return if done > 0 { done } else { (-32i64) as u64 };
            }
            Err(e) => return if done > 0 { done } else { e as u64 },
            Ok(n) => {
                done += n as u64;
                if n < data.len() {
                    return done; // short write — caller retries
                }
            }
        }
    }
    done
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
                    Err(-32) => {
                        task::signal(cur_id(), 13);
                        return if total > 0 { total as u64 } else { (-32i64) as u64 };
                    }
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
    let Some((pos, path, oflags)) = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => Some((f.pos, f.path.clone(), f.flags)),
        _ => None,
    }) else {
        return ERR;
    };
    if oflags & shared::O_PATH != 0 {
        return (-9i64) as u64;
    }
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

/// SYS_PIPE/SYS_PIPE2: an anonymous pipe bound to two fresh fds in the
/// caller's table — read end + write end. Returns rfd | wfd<<32.
/// `flags` = O_NONBLOCK|O_CLOEXEC applied to both ends (pipe2).
fn sys_pipe() -> u64 {
    sys_pipe_flags(0)
}

fn sys_pipe_flags(fl: u64) -> u64 {
    let Ok(path) = crate::pipes::create_anon() else {
        return ERR;
    };
    let packed = task::with_current(|t| {
        let Some(rfd) = alloc_slot(t) else { return ERR; };
        t.fds[rfd] = Some(task::FileDesc {
            path: path.clone(),
            pos: 0,
            flags: shared::O_RDONLY | fl,
        });
        let Some(wfd) = alloc_slot(t) else { return ERR; };
        t.fds[wfd] = Some(task::FileDesc {
            path: path.clone(),
            pos: 0,
            // pipes count TRUNC|APPEND|WRONLY as writer
            flags: shared::O_TRUNC | fl,
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
    let mut f = match task::with_current(|t| match t.fds.get(oldfd as usize) {
        Some(Some(f)) => Some(f.clone()),
        _ => None,
    }) {
        Some(f) => f,
        None => return ERR,
    };
    f.flags &= !shared::O_CLOEXEC; // a dup'ed descriptor is never cloexec
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
    } else if crate::memfd::handles(path) {
        crate::memfd::exists(path) // real file semantics: always ready
    } else if crate::mqueue::handles(path) {
        // readable while a message is queued; writable while under maxmsg
        (ev & 1 != 0 && crate::mqueue::ready(path))
            || (ev & 2 != 0 && crate::mqueue::exists(path))
    } else if crate::pty::handles(path) {
        (ev & 1 != 0 && crate::pty::ready(path, true))
            || (ev & 2 != 0 && crate::pty::ready(path, false))
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
        task::with_current(|t| t.poll_dl = 0);
        return ready;
    }
    // block: re-enter the syscall until something is ready or deadline hits.
    // The deadline is persisted on the task — recomputing it on each
    // re-entry would push it forward forever and the poll would never
    // time out (u64::MAX = wait forever, same sentinel as waitpid).
    let dl = task::with_current(|t| {
        if t.poll_dl == 0 {
            t.poll_dl = if timeout_ms == u64::MAX {
                u64::MAX
            } else {
                task::ticks() + timeout_ms.div_ceil(10) + 1
            };
        }
        t.poll_dl
    });
    if task::ticks() >= dl {
        task::with_current(|t| t.poll_dl = 0);
        return 0;
    }
    block_reenter(ctx, dl, 0)
}

/// SYS_SPLICE: move up to `len` bytes from `in_fd` to `out_fd`; one end
/// must be a pipe (POSIX). We move through a single kernel buffer — the
/// pipe's real packet queue drains/fills without touching user memory.
fn sys_splice(in_fd: u64, out_fd: u64, len: u64) -> u64 {
    let (ip, op) = task::with_current(|t| {
        let a = t
            .fds
            .get(in_fd as usize)
            .and_then(|f| f.as_ref())
            .map(|f| f.path.clone());
        let b = t
            .fds
            .get(out_fd as usize)
            .and_then(|f| f.as_ref())
            .map(|f| f.path.clone());
        (a.unwrap_or_default(), b.unwrap_or_default())
    });
    if ip.is_empty() || op.is_empty() {
        return ERR;
    }
    let in_pipe = crate::pipes::handles(&ip);
    let out_pipe = crate::pipes::handles(&op);
    if !in_pipe && !out_pipe {
        return ERR; // EINVAL — one end must be a pipe
    }
    let len = len.min(1 << 20);
    let mut tmp = alloc::vec![0u8; len.min(65536) as usize];
    let mut done = 0u64;
    while done < len {
        let want = ((len - done) as usize).min(tmp.len());
        let n = if in_pipe {
            match crate::pipes::try_read(&ip, &mut tmp[..want]) {
                crate::pipes::TryRead::Data(n) => n,
                _ => break,
            }
        } else {
            match fd_read_once(in_fd as usize, &mut tmp[..want]) {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        if n == 0 {
            break;
        }
        let m = if out_pipe {
            match crate::pipes::try_write(&op, &tmp[..n]) {
                Ok(m) if m >= 0 => m as usize,
                _ => break,
            }
        } else {
            match fd_write_once(out_fd as usize, &tmp[..n]) {
                Ok(m) => m,
                Err(_) => break,
            }
        };
        done += m as u64;
        if m < n {
            break;
        }
    }
    done
}

/// SYS_PROCESS_VM: copy bytes between the caller's buffer and another
/// task's user memory (a live, demand-paged VA range on their pml4).
/// wr=0 reads theirs → ours; wr=1 writes ours → theirs.
fn sys_process_vm(pid: u64, addr: u64, buf: u64, len: u64, wr: u64) -> u64 {
    let r = task::with_pid_mut(pid as u32, |t| {
        t.pml4
            .map(|p| p.start_address().as_u64() as i64)
            .unwrap_or(0)
    });
    if r <= 0 || len == 0 {
        return ERR;
    }
    let Some(pml4) =
        x86_64::structures::paging::PhysFrame::from_start_address(x86_64::PhysAddr::new(r as u64))
            .ok()
    else {
        return ERR;
    };
    let len = len.min(1 << 20);
    let mut done = 0u64;
    while done < len {
        let va = addr + done;
        let Some(pa) = elf::translate_user(pml4, va) else {
            break;
        };
        let n = (len - done).min(0x1000 - (va & 0xfff)) as usize;
        // translate_user returns phys INCLUDING the page offset
        let kv = mem::phys_to_virt(pa);
        if wr != 0 {
            let Some(data) = copy_in(buf + done, n as u64) else {
                break;
            };
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), kv as *mut u8, n);
            }
        } else {
            let chunk = unsafe { core::slice::from_raw_parts(kv as *const u8, n) };
            if copy_out_pub(buf + done, chunk).is_none() {
                break;
            }
        }
        done += n as u64;
    }
    if done == 0 {
        ERR
    } else {
        done
    }
}

/// SYS_PPOLL: poll under a temporary signal mask (mask = u64::MAX means
/// "no swap", i.e. plain poll). The swap persists across the blocked
/// wait via poll_saved_mask; the dispatch tail restores it at return.
fn sys_ppoll(ctx: &mut CpuContext, fds: u64, evs: u64, nfds: u64, timeout: u64, mask: u64) -> u64 {
    if mask != u64::MAX {
        task::with_current(|t| {
            if t.poll_saved_mask == u64::MAX {
                t.poll_saved_mask = t.sigmask;
                t.sigmask = mask;
            }
        });
    }
    // POSIX: a pending signal the new mask unblocks interrupts ppoll
    // immediately — the dispatch tail runs the handler right after.
    let eintr = task::with_current(|t| {
        let pend = t.sigpending & !t.sigmask;
        (0..32).any(|i| pend & (1u64 << i) != 0 && t.sighandlers[i] > 1)
    });
    if eintr {
        return (-4i64) as u64;
    }
    sys_poll(ctx, fds, evs, nfds, timeout)
}

/// SYS_SYSINFO: { uptime_sec, totalram_kb, freeram_kb, procs } out 32B.
fn sys_sysinfo(out: u64) -> u64 {
    let (total, used) = mem::FRAME_ALLOC
        .lock()
        .as_ref()
        .map(|a| (a.total_bytes(), a.used_bytes()))
        .unwrap_or((0, 0));
    let procs = task::SCHED
        .lock()
        .as_ref()
        .map(|s| s.tasks.iter().filter(|t| t.state != task::State::Dead).count() as u64)
        .unwrap_or(0);
    let mut b = alloc::vec![0u8; 32];
    b[0..8].copy_from_slice(&(task::ticks() / 100).to_le_bytes());
    b[8..16].copy_from_slice(&(total / 1024).to_le_bytes());
    b[16..24].copy_from_slice(&(total.saturating_sub(used) / 1024).to_le_bytes());
    b[24..32].copy_from_slice(&procs.to_le_bytes());
    if copy_out_pub(out, &b).is_some() {
        0
    } else {
        ERR
    }
}

/// SYS_CLOSE_RANGE: close every fd in [first, last] (releasing objects).
fn sys_close_range(first: u64, last: u64) -> u64 {
    if last < first {
        return ERR;
    }
    let last = last.min(1023);
    let rel: alloc::vec::Vec<task::FileDesc> = task::with_current(|t| {
        let mut v = alloc::vec::Vec::new();
        for i in first..=last {
            if let Some(f) = t.fds.get_mut(i as usize).and_then(|s| s.take()) {
                v.push(f);
            }
        }
        v
    });
    for f in &rel {
        crate::vfs::release_desc(f);
    }
    0
}

/// SYS_PIDFD_SIGNAL: signal the task behind a pidfd (/pidfd/{pid}).
fn sys_pidfd_signal(pidfd: u64, sig: u64) -> u64 {
    let path = task::with_current(|t| match t.fds.get(pidfd as usize) {
        Some(Some(f)) => f.path.clone(),
        _ => String::new(),
    });
    let Some(pid) = crate::pidfd::target(&path) else {
        return ERR;
    };
    if sig == 0 {
        // permission-style probe: 0 = target exists
        return if task::with_pid_mut(pid, |_| 0) == 0 { 0 } else { ERR };
    }
    if !task::signal_perm(pid) {
        return (-1i64) as u64;
    }
    if task::signal(pid, sig) == 0 {
        0
    } else {
        ERR
    }
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
        task::with_current(|t| t.poll_dl = 0);
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
        task::with_current(|t| t.poll_dl = 0);
        return 0;
    }
    // Same persisted deadline as sys_poll (see its comment) — a recomputed
    // deadline on re-entry would slide forward and never fire.
    let dl = task::with_current(|t| {
        if t.poll_dl == 0 {
            t.poll_dl = if timeout_ms == u64::MAX {
                u64::MAX
            } else {
                task::ticks() + timeout_ms.div_ceil(10) + 1
            };
        }
        t.poll_dl
    });
    if task::ticks() >= dl {
        task::with_current(|t| t.poll_dl = 0);
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

/// Resolve a possibly dirfd-relative path to an absolute one.
/// `dirfd` may be AT_FDCWD (-100, use the task's cwd), a real fd whose
/// desc's path is the base directory, or ignored for absolute paths.
/// Returns None on a bad fd or bad string.
fn resolve_at(dirfd: i64, pptr: u64, plen: u64) -> Option<String> {
    let path = copy_str(pptr, plen)?;
    if path.is_empty() {
        // AT_EMPTY_PATH callers pass the dirfd's own path.
        return task::with_current(|t| {
            t.fds
                .get(dirfd as usize)
                .and_then(|s| s.as_ref())
                .map(|f| f.path.clone())
        });
    }
    if path.starts_with('/') {
        return Some(path);
    }
    if dirfd == shared::AT_FDCWD {
        return task::with_current(|t| {
            Some(alloc::format!("{}/{}", t.cwd.trim_end_matches('/'), path))
        });
    }
    let base = task::with_current(|t| {
        t.fds
            .get(dirfd as usize)
            .and_then(|s| s.as_ref())
            .map(|f| f.path.clone())
    })?;
    Some(alloc::format!("{}/{}", base.trim_end_matches('/'), path))
}

/// SYS_FSTATAT(dirfd, path, len, flags, out): stat relative to dirfd;
/// AT_SYMLINK_NOFOLLOW reports the link itself, AT_EMPTY_PATH stats the fd.
fn sys_fstatat(dirfd: i64, pptr: u64, plen: u64, flags: u64, out: u64) -> u64 {
    let Some(path) = resolve_at(dirfd, pptr, plen) else { return ERR };
    if path.is_empty() && flags & shared::AT_EMPTY_PATH == 0 {
        return ERR;
    }
    let st = if flags & shared::AT_SYMLINK_NOFOLLOW != 0 {
        // readlink_path distinguishes "is a symlink" from stat errors: a
        // link reports its own Stat (LNK> body), anything else falls back
        // to the normal stat.
        match vfs::readlink_path(&path) {
            Ok(_) => {
                let mut g = vfs::FS.lock();
                match g.as_mut().and_then(|fs| fs.stat(&path).ok()) {
                    Some(s) => shared::Stat {
                        size: s.size,
                        is_dir: if s.is_dir { 1 } else { 0 },
                        mtime: s.mtime,
                        attr: s.attr as u32,
                    },
                    None => return (-2i64) as u64,
                }
            }
            Err(_) => match vfs::stat_path(&path) {
                Ok(st) => st,
                Err(e) => return e as u64,
            },
        }
    } else {
        match vfs::stat_path(&path) {
            Ok(st) => st,
            Err(e) => return e as u64,
        }
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(&st as *const _ as *const u8, core::mem::size_of::<shared::Stat>())
    };
    match copy_out(out, bytes) {
        Some(_) => 0,
        None => ERR,
    }
}

/// SYS_ACCESS/SYS_FACCESSAT: does the path exist and permit `mode`?
/// FAT32 has no owner/permission model, so the honest checks are: the file
/// must exist (F_OK), and W_OK fails on the readonly FAT attribute and on
/// the read-only pseudo filesystems. X_OK follows the same rule (every
/// readable file is considered executable, like vfat mounts on Linux).
fn sys_access_at(dirfd: i64, pptr: u64, plen: u64, mode: u64) -> u64 {
    let Some(path) = resolve_at(dirfd, pptr, plen) else { return ERR };
    if mode == 0 {
        // F_OK
        return match vfs::stat_path(&path) {
            Ok(_) => 0,
            Err(e) => e as u64,
        };
    }
    match vfs::stat_path(&path) {
        Ok(st) => {
            if mode & 2 != 0 && (st.attr & 0x01 != 0 || !on_real_fs(&path)) {
                return (-13i64) as u64; // EACCES
            }
            0
        }
        Err(e) => e as u64,
    }
}

fn on_real_fs(path: &str) -> bool {
    !(crate::proc::handles(path)
        || crate::dev::handles(path)
        || crate::pipes::handles(path)
        || crate::pty::handles(path))
}

/// Write the `LNK>target` file + symlink attribute — what `ln -s` does
/// in userspace, callable kernel-side for symlinkat.
fn sys_symlink_impl(target: &str, link: &str) -> u64 {
    if vfs::stat_path(link).is_ok() || vfs::readlink_path(link).is_ok() {
        return (-17i64) as u64; // EEXIST
    }
    let body = alloc::format!("LNK>{}", target);
    if vfs::write_all_path(link, body.as_bytes()).is_err() {
        return ERR;
    }
    let cur = {
        let mut g = vfs::FS.lock();
        g.as_mut().and_then(|fs| fs.stat(link).ok()).map(|s| s.attr)
    };
    let attr = cur.unwrap_or(0x20) | 0x40;
    let _ = vfs::setattr(link, attr);
    0
}

/// statfs record out: {type=0x4d44 FAT, bsize=cluster, blocks, bfree}.
/// SYS_MOUNT(&[u64;8]{sptr,slen,tptr,tlen,fptr,flen,flags,unused}):
/// mount a filesystem. Only "tmpfs" exists — a real in-RAM fs over the
/// target dir; source is ignored like Linux tmpfs. Flags: MS_RDONLY(1),
/// MS_REMOUNT(32) — remount flips ro on the existing mount.
fn sys_mount(argp: u64) -> u64 {
    if !task::capable(task::CAP_SYS_ADMIN) {
        return (-1i64) as u64; // EPERM
    }
    let Some(a) = copy_in(argp, 64) else { return ERR };
    let rd = |i: usize| u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
    let (Some(tgt), Some(fst)) = (copy_str(rd(2) as u64, rd(3) as u64), copy_str(rd(4) as u64, rd(5) as u64))
    else {
        return ERR;
    };
    let flags = rd(6);
    let cwd = task::with_current(|t| t.cwd.clone());
    let t = vfs::normalize(&cwd, tgt.trim_matches('\0'));
    if flags & shared::MS_MOVE != 0 {
        // mount --move old new: relocate an existing mount. Tries bind
        // aliases first, then a real tmpfs mount (which re-keys its
        // whole node tree). Source arg carries the OLD mount path.
        // Both names are mount-point NAMES: resolve without the bind
        // tail (a bind target is the mount itself, not what it covers).
        let Some(src_raw) = copy_str(rd(0), rd(1)) else { return ERR };
        let s = vfs::normalize_prebind(&cwd, src_raw.trim_matches('\0'));
        let tn = vfs::normalize_prebind(&cwd, tgt.trim_matches('\0'));
        if vfs::stat_path(&s).is_err() || vfs::stat_path(&tn).is_err() {
            return (-2i64) as u64;
        }
        return match crate::bind::move_mount(&s, &tn) {
            Ok(()) => 0,
            Err(_) => crate::tmpfs::move_mount(&s, &tn)
                .map(|_| 0)
                .unwrap_or_else(|e| e as u64),
        };
    }
    if flags & shared::MS_BIND != 0 {
        // mount --bind: source must exist (dir or file); the target is
        // an alias resolved at path time, so it only needs to exist too.
        let Some(src_raw) = copy_str(rd(0), rd(1)) else { return ERR };
        let s = vfs::normalize(&cwd, src_raw.trim_matches('\0'));
        if vfs::stat_path(&s).is_err() || vfs::stat_path(&t).is_err() {
            return (-2i64) as u64;
        }
        let opts = flags
            & (shared::MS_RDONLY | shared::MS_NOSUID | shared::MS_NODEV | shared::MS_NOEXEC);
        return crate::bind::mount(&s, &t, opts)
            .map(|_| 0)
            .unwrap_or_else(|e| e as u64);
    }
    if fst.trim_matches('\0') != "tmpfs" {
        return (-19i64) as u64; // ENODEV: unknown fstype
    }
    let ro = flags & shared::MS_RDONLY != 0;
    if flags & shared::MS_REMOUNT != 0 {
        return crate::tmpfs::remount(&t, ro)
            .map(|_| 0)
            .unwrap_or_else(|e| e as u64);
    }
    // target must be an existing directory on whatever fs it lands on
    match vfs::stat_path(&t) {
        Ok(s) if s.is_dir != 0 => {}
        Ok(_) => return (-20i64) as u64, // ENOTDIR
        Err(e) => return e as u64,
    }
    let opts = flags
        & (shared::MS_RDONLY | shared::MS_NOSUID | shared::MS_NODEV | shared::MS_NOEXEC);
    crate::tmpfs::mount(&t, opts)
        .map(|_| 0)
        .unwrap_or_else(|e| e as u64)
}

/// SYS_CHROOT(path): jail the task under `path` — must be a directory.
/// Absolute paths resolve under it via vfs::normalize; `..` can't escape.
fn sys_chroot(pptr: u64, plen: u64) -> u64 {
    if !task::capable(task::CAP_SYS_CHROOT) {
        return (-1i64) as u64; // EPERM
    }
    let Some(p) = copy_str(pptr, plen) else { return ERR };
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = vfs::normalize(&cwd, p.trim_matches('\0'));
    match vfs::stat_path(&full) {
        Ok(s) if s.is_dir != 0 => {
            task::with_current(|t| {
                t.root = full;
                0u64
            })
        }
        Ok(_) => (-20i64) as u64, // ENOTDIR
        Err(e) => e as u64,
    }
}

/// SYS_UMOUNT(target): EBUSY on open fds/cwd/nested mounts under it.
fn sys_umount(ptr: u64, len: u64, flags: u64) -> u64 {
    if !task::capable(task::CAP_SYS_ADMIN) {
        return (-1i64) as u64; // EPERM
    }
    let Some(tgt) = copy_str(ptr, len) else { return ERR };
    let cwd = task::with_current(|t| t.cwd.clone());
    let t = vfs::normalize(&cwd, tgt.trim_matches('\0'));
    match crate::tmpfs::umount(&t, flags) {
        Err(-22) => crate::bind::umount(&t)
            .map(|_| 0)
            .unwrap_or_else(|e| e as u64),
        r => r.map(|_| 0).unwrap_or_else(|e| e as u64),
    }
}

/// SYS_PIVOT_ROOT(&[u64;4]{new_ptr,new_len,old_ptr,old_len}): move the
/// task's root to new_root, keeping the old root reachable at
/// new_root/put_old via a real bind entry. Pivoting is per-task.
fn sys_pivot_root(argp: u64) -> u64 {
    if !task::capable(task::CAP_SYS_ADMIN) {
        return (-1i64) as u64; // EPERM
    }
    let Some(a) = copy_in(argp, 32) else { return ERR };
    let rd = |i: usize| u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
    let (Some(newp), Some(oldp)) = (copy_str(rd(0), rd(1)), copy_str(rd(2), rd(3))) else {
        return ERR;
    };
    let cwd = task::with_current(|t| t.cwd.clone());
    let newr = vfs::normalize(&cwd, newp.trim_matches('\0'));
    let oldr = vfs::normalize(&cwd, oldp.trim_matches('\0'));
    // new root must be a dir; put_old must be under the new root
    match vfs::stat_path(&newr) {
        Ok(s) if s.is_dir != 0 => {}
        Ok(_) => return (-20i64) as u64,
        Err(e) => return e as u64,
    }
    match vfs::stat_path(&oldr) {
        Ok(s) if s.is_dir != 0 => {}
        Ok(_) => return (-20i64) as u64,
        Err(e) => return e as u64,
    }
    let under_new = oldr == newr
        || (oldr.len() > newr.len()
            && oldr.starts_with(&newr)
            && oldr.as_bytes()[newr.len()] == b'/');
    if !under_new {
        return (-22i64) as u64; // EINVAL: put_old outside new root
    }
    // register the old root as a bind on put_old BEFORE switching roots —
    // resolve rewrites /new/put_old/x -> /x of the old tree.
    if oldr != newr {
        if let Err(e) = crate::bind::mount("/", &oldr, 0) {
            return e as u64;
        }
    }
    task::with_current(|t| {
        t.root = newr;
        0u64
    })
}

/// SYS_OPENAT2(&[u64;6]{dirfd,path,len,flags,mode,resolve}): openat plus
/// RESOLVE_* path-walk policy (NO_SYMLINKS / BENEATH / IN_ROOT / NO_XDEV).
fn sys_openat2(argp: u64) -> u64 {
    let Some(a) = copy_in(argp, 48) else { return ERR };
    let rd = |i: usize| u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
    let Some(path) = resolve_at(rd(0) as u32 as i32 as i64, rd(1), rd(2)) else {
        return ERR;
    };
    let (flags, resolve) = (rd(3), rd(5));
    if resolve != 0 {
        // canonical path first (normalize folds `..` and binds)
        let cwd = task::with_current(|t| t.cwd.clone());
        let full = vfs::normalize(&cwd, &path);
        // BENEATH/IN_ROOT use the dirfd's own canonical base
        let base = if resolve & shared::RESOLVE_BENEATH != 0 {
            resolve_at(rd(0) as u32 as i32 as i64, 0, 0).unwrap_or_else(|| String::from("/"))
        } else {
            String::from("/")
        };
        if let Err(e) = vfs::resolve_flags(&full, &base, resolve) {
            return e as u64;
        }
        // open the already-canonical path directly
        return match vfs::open(&full, flags) {
            Ok(fd) => fd as u64,
            Err(e) => e as u64,
        };
    }
    match vfs::open(&path, flags) {
        Ok(fd) => fd as u64,
        Err(e) => e as u64,
    }
}

/// SYS_GETRANDOM(buf,len,flags): fill user buf from the kernel RNG.
fn sys_getrandom(buf: u64, len: u64, _flags: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    if len > 256 * 1024 {
        return (-22i64) as u64;
    }
    let mut tmp = alloc::vec![0u8; len as usize];
    rand_fill(&mut tmp);
    match copy_out(buf, &tmp) {
        Some(_) => len,
        None => ERR,
    }
}

/// SYS_MINCORE(addr,len,vec): per-page residency bits for the task's own
/// address space — real page-table walk, not a stub.
fn sys_mincore(addr: u64, len: u64, outp: u64) -> u64 {
    if addr & 0xFFF != 0 {
        return ERR;
    }
    let pages = len.div_ceil(0x1000);
    if pages == 0 || pages > 65536 {
        return (-22i64) as u64;
    }
    let mut vec = alloc::vec![0u8; pages as usize];
    let ok = task::with_current(|t| {
        let Some(pml4) = t.pml4 else { return false };
        let mut a = addr;
        for i in 0..pages as usize {
            if elf::translate(pml4, a).is_some() {
                vec[i] = 1;
            }
            a += 0x1000;
        }
        true
    });
    if !ok {
        return ERR;
    }
    match copy_out(outp, &vec) {
        Some(_) => 0,
        None => ERR,
    }
}

/// SYS_MADVISE(addr,len,advice): DONTNEED drops the mapped pages (they
/// refault from the file/zero-fill on next touch); WILLNEED prefaults
/// them; other advice is a legal no-op.
fn sys_madvise(addr: u64, len: u64, advice: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let end = addr.saturating_add(len.div_ceil(0x1000) * 0x1000);
    match advice {
        a if a == shared::MADV_DONTNEED => {
            let freed = task::with_current(|t| {
                let Some(pml4) = t.pml4 else { return 0u64 };
                let mut a = addr;
                let mut n = 0u64;
                while a < end {
                    if let Some(phys) = elf::unmap_user_page(pml4, a) {
                        if !t.borrowed.contains(&phys) {
                            mem::free_frame(phys);
                        }
                        task::cow_unmap(pml4.start_address().as_u64(), a);
                        n += 1;
                    }
                    a += 0x1000;
                }
                t.mem_bytes = t.mem_bytes.saturating_sub(n * 0x1000);
                n
            });
            unsafe { x86_64::instructions::tlb::flush_all() };
            let _ = freed;
            0
        }
        a if a == shared::MADV_WILLNEED => {
            // touch each page so demand paging pulls it in now
            task::with_current(|t| {
                if let Some(pml4) = t.pml4 {
                    let mut a = addr;
                    while a < end {
                        if elf::translate(pml4, a).is_none() {
                            // read one byte through the fault path —
                            // copy_in demand-pages without touching data
                            let _ = copy_in(a, 1);
                        }
                        a += 0x1000;
                    }
                }
            });
            0
        }
        _ => 0, // other advice is advisory — legal no-op
    }
}

/// SYS_UNSHARE(flags): CLONE_NEWNS gives the task a private mount
/// namespace — mounts/binds/unmounts stop propagating to the parent.
fn sys_unshare(flags: u64) -> u64 {
    if !task::capable(task::CAP_SYS_ADMIN) {
        return (-1i64) as u64; // EPERM
    }
    let want = shared::CLONE_NEWNS
        | shared::CLONE_NEWUTS
        | shared::CLONE_NEWPID
        | shared::CLONE_NEWIPC
        | shared::CLONE_NEWTIME
        | shared::CLONE_NEWUSER;
    if flags & !want != 0 {
        return (-22i64) as u64; // EINVAL: unsupported share bits
    }
    if flags & shared::CLONE_NEWNS != 0 {
        task::unshare_ns();
    }
    if flags & shared::CLONE_NEWUTS != 0 {
        task::unshare_uts();
    }
    if flags & shared::CLONE_NEWPID != 0 {
        task::unshare_pidns();
    }
    if flags & shared::CLONE_NEWIPC != 0 {
        task::unshare_ipcns();
    }
    if flags & shared::CLONE_NEWTIME != 0 {
        task::unshare_timens();
    }
    if flags & shared::CLONE_NEWUSER != 0 {
        task::unshare_userns();
    }
    0
}

/// SYS_SYSLOG(action, buf, len): kernel log ring access. Actions: 0/1
/// open-close (noop), 2 read-new (shared unread cursor), 3 read-all,
/// 4 read-all+clear, 5 clear, 9 unread-bytes, 10 buffer-capacity.
fn sys_syslog(action: u64, ptr: u64, len: u64) -> u64 {
    if !task::capable(task::CAP_SYS_ADMIN) {
        return (-1i64) as u64; // EPERM
    }
    match action {
        0 | 1 => 0,
        2 => {
            let mut b = vec![0u8; len.min(32 * 1024) as usize];
            let n = crate::klog::read_unread(&mut b);
            b.truncate(n);
            if n > 0 && copy_out(ptr, &b).is_none() {
                return (-14i64) as u64;
            }
            n as u64
        }
        3 => {
            let mut b = vec![0u8; len.min(32 * 1024) as usize];
            let n = crate::klog::read_tail(&mut b);
            b.truncate(n);
            if n > 0 && copy_out(ptr, &b).is_none() {
                return (-14i64) as u64;
            }
            n as u64
        }
        4 => {
            let mut b = vec![0u8; len.min(32 * 1024) as usize];
            let n = crate::klog::read_tail(&mut b);
            crate::klog::clear();
            b.truncate(n);
            if n > 0 && copy_out(ptr, &b).is_none() {
                return (-14i64) as u64;
            }
            n as u64
        }
        5 => {
            crate::klog::clear();
            0
        }
        9 => crate::klog::unread_len() as u64,
        10 => crate::klog::buffer_size() as u64,
        _ => (-22i64) as u64,
    }
}

/// SYS_TFD_GET(fd, &mut [u64;2]{init_ms,interval_ms}): remaining time on
/// the armed timer (0 = disarmed) plus its interval.
fn sys_tfd_gettime(fd: u64, ptr: u64) -> u64 {
    let path = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) if crate::timerfd::handles(&f.path) => Some(f.path.clone()),
        _ => None,
    });
    let Some(p) = path else { return (-9i64) as u64 };
    let Some((init, iv)) = crate::timerfd::gettime(&p) else {
        return (-9i64) as u64;
    };
    let a = [init, iv];
    match copy_out(ptr, &a.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()) {
        Some(_) => 0,
        None => (-14i64) as u64,
    }
}

/// SYS_REBOOT(magic1, magic2, cmd): RB_RESTART / RB_HALT / RB_POWER_OFF.
/// Bad magic is EINVAL before anything destructive can run.
fn sys_reboot_call(m1: u64, m2: u64, cmd: u64) -> u64 {
    if !task::capable(task::CAP_SYS_BOOT) {
        return (-1i64) as u64; // EPERM
    }
    if m1 != shared::RB_MAGIC1 || m2 != shared::RB_MAGIC2 {
        return (-22i64) as u64;
    }
    match cmd {
        shared::RB_RESTART => reboot(),
        shared::RB_HALT | shared::RB_POWER_OFF => power_off(),
        _ => (-22i64) as u64,
    }
}

/// SYS_SETUID/SYS_SETGID: root swaps both ids to `v`; a non-root task may
/// only restore its effective id to its real one — EPERM otherwise.
fn sys_setid(v: u64, group: bool) -> u64 {
    let u = v as u32;
    let cap = if group { task::CAP_SETGID } else { task::CAP_SETUID };
    task::with_current(|t| {
        if task::capable_in_ns(t, cap) {
            if group {
                t.gid = u;
                t.egid = u;
                t.sgid = u;
            } else {
                t.uid = u;
                t.euid = u;
                t.suid = u;
            }
            0
        } else if group && u == t.gid {
            t.egid = u;
            0
        } else if !group && u == t.uid {
            t.euid = u;
            0
        } else {
            (-1i64) as u64 // EPERM
        }
    })
}

/// SYS_GETGROUPS(out u32[], cap): copy the supplementary list (up to cap).
fn sys_getgroups(out: u64, cap: u64) -> u64 {
    let gs = task::groups_of();
    let n = gs.len() as u64;
    if cap == 0 {
        return n; // size query, Linux-style
    }
    let want = cap.min(n) as usize;
    let mut buf = alloc::vec![0u8; want * 4];
    for (i, g) in gs.iter().take(want).enumerate() {
        buf[i * 4..i * 4 + 4].copy_from_slice(&g.to_le_bytes());
    }
    match copy_out(out, &buf) {
        Some(_) => want as u64,
        None => ERR,
    }
}

/// SYS_SETGROUPS(u32[], count): replace the supplementary list (root only).
fn sys_setgroups(ptr: u64, count: u64) -> u64 {
    if count > 256 {
        return ERR;
    }
    let Some(raw) = copy_in(ptr, count * 4) else { return ERR };
    let mut gs = alloc::vec::Vec::new();
    for i in 0..count as usize {
        gs.push(u32::from_le_bytes([
            raw[i * 4],
            raw[i * 4 + 1],
            raw[i * 4 + 2],
            raw[i * 4 + 3],
        ]));
    }
    task::with_current(|t| {
        if !task::capable_in_ns(t, task::CAP_SETGID) {
            (-1i64) as u64 // EPERM
        } else {
            t.groups = gs;
            0
        }
    })
}

/// setresuid/setresgid semantics: u32::MAX keeps a field; root may set any
/// value; non-root may only shuffle among its current real/effective/saved.
fn sys_setresid(r: u64, e: u64, s: u64, group: bool) -> u64 {
    let (r, e, s) = (r as u32, e as u32, s as u32);
    task::with_current(|t| {
        let (cr, ce, cs) = if group {
            (t.gid, t.egid, t.sgid)
        } else {
            (t.uid, t.euid, t.suid)
        };
        let keep = u32::MAX;
        let cap = if group { task::CAP_SETGID } else { task::CAP_SETUID };
        let allowed =
            |v: u32| task::capable_in_ns(t, cap) || v == cr || v == ce || v == cs;
        for v in [r, e, s] {
            if v != keep && !allowed(v) {
                return (-1i64) as u64; // EPERM
            }
        }
        if group {
            if r != keep {
                t.gid = r;
            }
            if e != keep {
                t.egid = e;
            }
            if s != keep {
                t.sgid = s;
            }
        } else {
            if r != keep {
                t.uid = r;
            }
            if e != keep {
                t.euid = e;
            }
            if s != keep {
                t.suid = s;
            }
        }
        0
    })
}

/// getresuid/getresgid: copy out (real, effective, saved) as u32[3].
fn sys_getresid(out: u64, group: bool) -> u64 {
    let c = task::creds6();
    let ids = if group { (c.3, c.4, c.5) } else { (c.0, c.1, c.2) };
    let mut buf = alloc::vec![0u8; 12];
    for (i, v) in [ids.0, ids.1, ids.2].iter().enumerate() {
        buf[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    match copy_out(out, &buf) {
        Some(_) => 0,
        None => ERR,
    }
}

/// SYS_CHOWN(path_ptr, len, uid, gid; u64::MAX keeps a field): real
/// ownership on tmpfs; EPERM on FAT (vfat has no owners) and for
/// non-root callers anywhere.
fn sys_chown(pptr: u64, plen: u64, uid: u64, gid: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = vfs::normalize(&cwd, path.trim_matches('\0'));
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::chown(&full, uid as u32, gid as u32)
            .map(|_| 0)
            .unwrap_or_else(|e| e as u64);
    }
    if !task::capable(task::CAP_CHOWN) {
        return (-1i64) as u64; // EPERM — no CAP_CHOWN, any filesystem
    }
    (-1i64) as u64 // EPERM — vfat has no owners
}

/// SYS_FCHOWN(fd, uid, gid): same policy, fd's stored path resolves it.
fn sys_fchown(fd: u64, uid: u64, gid: u64) -> u64 {
    let path = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => f.path.clone(),
        _ => String::new(),
    });
    if path.is_empty() {
        return (-9i64) as u64;
    }
    if crate::tmpfs::handles(&path) {
        return crate::tmpfs::chown(&path, uid as u32, gid as u32)
            .map(|_| 0)
            .unwrap_or_else(|e| e as u64);
    }
    (-1i64) as u64
}

/// SYS_CHMOD(path_ptr, len, mode): tmpfs stores real perm bits (owner or
/// root only); FAT maps the owner-write bit onto the readonly attr,
/// root only, matching vfat's chmod.
fn sys_chmod(pptr: u64, plen: u64, mode: u64) -> u64 {
    let Some(path) = copy_str(pptr, plen) else { return ERR };
    let cwd = task::with_current(|t| t.cwd.clone());
    let full = vfs::normalize(&cwd, path.trim_matches('\0'));
    if crate::tmpfs::handles(&full) {
        return crate::tmpfs::chmod(&full, mode as u16)
            .map(|_| 0)
            .unwrap_or_else(|e| e as u64);
    }
    if !task::capable(task::CAP_FOWNER) {
        return (-1i64) as u64;
    }
    // FAT: owner-write masked -> readonly attr; other bits unmapped
    let ro = mode & 0o222 == 0;
    let cur = vfs::stat_path(&full).map(|s| s.attr).unwrap_or(0) as u8;
    let attr = if ro { cur | 0x01 } else { cur & !0x01 };
    vfs::setattr(&full, attr).map(|_| 0).unwrap_or_else(|e| e as u64)
}

/// SYS_SETNS(fd): the fd must be an ns-object fd — an open
/// /proc/<pid>/ns/{mntns,uts} whose stored path is /nsfd/{n} pinning a
/// MountNs or UtsNs object. EINVAL on a non-ns fd.
fn sys_setns(fd: u64) -> u64 {
    if !task::capable(task::CAP_SYS_ADMIN) {
        return (-1i64) as u64; // EPERM
    }
    let path = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => f.path.clone(),
        _ => String::new(),
    });
    // only namespace-object fds (/nsfd/{n} from an open
    // /proc/<pid>/ns/mntns) are legal adopt sources — EINVAL otherwise.
    if !crate::nsfd::handles(&path) {
        return (-22i64) as u64;
    }
    match crate::nsfd::obj(&path) {
        Some(crate::nsfd::NsObj::Mount(arc)) => {
            task::set_ns(arc);
            0
        }
        Some(crate::nsfd::NsObj::Uts(arc)) => {
            task::set_uts(arc);
            0
        }
        Some(crate::nsfd::NsObj::Pid(arc)) => {
            task::set_pidns_for_children(arc);
            0
        }
        Some(crate::nsfd::NsObj::Time(arc)) => {
            task::set_timens_for_children(arc);
            0
        }
        Some(crate::nsfd::NsObj::Ipc(arc)) => {
            task::set_ipcns(arc);
            0
        }
        Some(crate::nsfd::NsObj::User(arc)) => {
            task::set_userns(arc);
            0
        }
        None => (-9i64) as u64,
    }
}

/// SYS_PIDFD_GETFD(pidfd, fd, flags): duplicate descriptor `fd` out of the
/// pidfd's task into ours. Access needs ptrace authority over the target
/// (PTRACE_MODE_ATTACH equivalents: the task itself or its tracer).
fn sys_pidfd_getfd(pidfd: u64, tfd: u64, _flags: u64) -> u64 {
    let path = task::with_current(|t| match t.fds.get(pidfd as usize) {
        Some(Some(f)) => f.path.clone(),
        _ => String::new(),
    });
    let Some(pid) = crate::pidfd::target(&path) else {
        return (-9i64) as u64;
    };
    let me = task::current_id();
    let desc = task::fd_clone_from(pid, tfd as usize, me);
    let Some(desc) = desc else {
        return (-9i64) as u64;
    };
    vfs::acquire_desc(&desc); // refcounted objects get a second owner
    match task::adopt_fd(desc) {
        Some(i) => i as u64,
        None => (-24i64) as u64, // EMFILE
    }
}

/// SYS_STATX(&[u64;6]{dirfd,pathptr,pathlen,flags,mask,bufp}): extended
/// stat — btime/ctime/ino/mode/blocks that plain stat can't express.
fn sys_statx(argp: u64) -> u64 {
    let Some(a) = copy_in(argp, 48) else { return ERR };
    let rd = |i: usize| u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
    let Some(path) = resolve_at(rd(0) as u32 as i32 as i64, rd(1), rd(2)) else {
        return ERR;
    };
    let flags = rd(3);
    if path.is_empty() && flags & shared::AT_EMPTY_PATH == 0 {
        return ERR;
    }
    let st = if flags & shared::AT_STATX_SYMLINK_NOFOLLOW != 0 {
        match vfs::stat_path_nofollow(&path) {
            Ok(st) => st,
            Err(e) => return e as u64,
        }
    } else {
        match vfs::stat_path(&path) {
            Ok(st) => st,
            Err(e) => return e as u64,
        }
    };
    // stable inode-ish id: FNV-1a of the canonical path
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.as_bytes() {
        h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
    }
    let sx = shared::Statx {
        mask: shared::STATX_ALL as u32,
        blksize: 512,
        attr: st.attr as u64,
        nlink: 1,
        mode: {
            // tmpfs nodes carry real perm bits; FAT/pseudo keep the
            // uniform 0755/0644 vfat-style answer.
            let (ou, _og, om) = crate::tmpfs::owner(&path);
            let _ = ou;
            if om != 0 {
                (if st.is_dir != 0 { 0o40000 } else { 0o100000 }) | om as u32
            } else if st.is_dir != 0 {
                0o40755
            } else {
                0o100644
            }
        },
        _pad: 0,
        ino: h,
        size: st.size,
        blocks: (st.size + 511) / 512,
        mtime: st.mtime,
        ctime: vfs::btime(&path),
        btime: vfs::btime(&path),
        // owner ids are stored real; callers in a userns see the
        // mapped (inner) ids — Linux's kuid→uid translation.
        uid: task::map_uid_in(
            task::with_current(|t| t.user_ns),
            crate::tmpfs::owner(&path).0,
            false,
        ),
        gid: task::map_uid_in(
            task::with_current(|t| t.user_ns),
            crate::tmpfs::owner(&path).1,
            true,
        ),
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &sx as *const _ as *const u8,
            core::mem::size_of::<shared::Statx>(),
        )
    };
    match copy_out(rd(5), bytes) {
        Some(_) => 0,
        None => ERR,
    }
}

fn sys_statfs_out(path: &str, out: u64) -> u64 {
    if crate::tmpfs::handles(path) {
        let (total, free) = crate::tmpfs::df();
        let (files, ffree) = crate::tmpfs::ifree();
        let cb = 4096u64;
        let b = [
            0x1021_994u64.to_le_bytes(), // TMPFS_MAGIC
            cb.to_le_bytes(),
            (total / cb).to_le_bytes(),
            (free / cb).to_le_bytes(),
            files.to_le_bytes(),
            ffree.to_le_bytes(),
        ]
        .concat();
        return match copy_out(out, &b) {
            Some(_) => 0,
            None => ERR,
        };
    }
    let Some((total, free)) = vfs::df() else {
        return ERR;
    };
    let cb = {
        let mut g = vfs::FS.lock();
        g.as_mut().map(|fs| fs.cluster_bytes()).unwrap_or(512)
    };
    let blocks = if cb > 0 { total / cb } else { 0 };
    let bfree = if cb > 0 { free / cb } else { 0 };
    let b = [
        0x4d44u64.to_le_bytes(), // MSDOS_SUPER_MAGIC
        cb.to_le_bytes(),
        blocks.to_le_bytes(),
        bfree.to_le_bytes(),
        0u64.to_le_bytes(), // files: FAT has no inode table (GNU prints 0)
        0u64.to_le_bytes(), // ffree
    ]
    .concat();
    match copy_out(out, &b) {
        Some(_) => 0,
        None => ERR,
    }
}

/// SYS_FALLOCATE(fd, off, len): guarantee [off, off+len) exists — extends
/// the file with zeros when it's shorter (FAT has no unwritten extents,
/// so real allocation = real zero bytes).
fn sys_fallocate(fd: u64, off: u64, len: u64) -> u64 {
    let path = task::with_current(|t| match t.fds.get(fd as usize) {
        Some(Some(f)) => Some(f.path.clone()),
        _ => None,
    });
    let Some(path) = path else { return ERR };
    if crate::pipes::handles(&path) || crate::dev::handles(&path) || crate::proc::handles(&path) {
        return (-25i64) as u64; // ENOTTY-ish: not a real file
    }
    let cur = match vfs::stat_path(&path) {
        Ok(s) => s.size,
        Err(e) => return e as u64,
    };
    let want = off.saturating_add(len);
    if want <= cur {
        return 0; // already allocated
    }
    let mut data = match vfs::read_all(&path) {
        Ok(d) => d,
        Err(e) => return e as u64,
    };
    data.resize(want as usize, 0);
    match vfs::write_all_path(&path, &data) {
        Ok(()) => 0,
        Err(e) => e as u64,
    }
}

/// SYS_PSELECT(nfds, rmask_ptr, wmask_ptr, timeout_ms, mask): fd-set select
/// (bitmask form, nfds <= 64) + optional signal-mask swap like ppoll.
/// Returns the count of ready fds; the masks are rewritten in place with
/// only the ready bits left set (POSIX select semantics).
fn sys_pselect(ctx: &mut CpuContext, nfds: u64, rptr: u64, wptr: u64, timeout: u64, mask: u64) -> u64 {
    if mask != u64::MAX {
        task::with_current(|t| {
            if t.poll_saved_mask == u64::MAX {
                t.poll_saved_mask = t.sigmask;
                t.sigmask = mask;
            }
        });
    }
    let eintr = task::with_current(|t| {
        let pend = t.sigpending & !t.sigmask;
        (0..32).any(|i| pend & (1u64 << i) != 0 && t.sighandlers[i] > 1)
    });
    if eintr {
        return (-4i64) as u64;
    }
    let nfds = nfds.min(64) as usize;
    let rset = if rptr != 0 {
        match copy_in(rptr, 8) {
            Some(d) => u64::from_le_bytes(d[..8].try_into().unwrap()),
            None => return ERR,
        }
    } else {
        0
    };
    let wset = if wptr != 0 {
        match copy_in(wptr, 8) {
            Some(d) => u64::from_le_bytes(d[..8].try_into().unwrap()),
            None => return ERR,
        }
    } else {
        0
    };
    let paths: Vec<String> = task::with_current(|t| {
        (0..nfds)
            .map(|i| match t.fds.get(i) {
                Some(Some(f)) => f.path.clone(),
                _ => String::new(),
            })
            .collect()
    });
    let (mut r_out, mut w_out) = (0u64, 0u64);
    for i in 0..nfds {
        if paths[i].is_empty() {
            continue;
        }
        if rset & (1u64 << i) != 0 && fd_ready(&paths[i], 1) {
            r_out |= 1u64 << i;
        }
        if wset & (1u64 << i) != 0 && fd_ready(&paths[i], 2) {
            w_out |= 1u64 << i;
        }
    }
    let n = (r_out | w_out).count_ones() as u64;
    if n > 0 || timeout == 0 {
        if rptr != 0 {
            let _ = copy_out(rptr, &r_out.to_le_bytes());
        }
        if wptr != 0 {
            let _ = copy_out(wptr, &w_out.to_le_bytes());
        }
        task::with_current(|t| t.poll_dl = 0);
        return n;
    }
    let dl = task::with_current(|t| {
        if t.poll_dl == 0 {
            t.poll_dl = if timeout == u64::MAX { u64::MAX } else { task::ticks() + timeout.div_ceil(10) + 1 };
        }
        t.poll_dl
    });
    if dl != u64::MAX && task::ticks() >= dl {
        task::with_current(|t| t.poll_dl = 0);
        if rptr != 0 {
            let _ = copy_out(rptr, &0u64.to_le_bytes());
        }
        if wptr != 0 {
            let _ = copy_out(wptr, &0u64.to_le_bytes());
        }
        return 0;
    }
    block_reenter(ctx, dl, 0)
}

/// SYS_WAIT4(pid, opts, timeout, rusage_ptr): waitpid + rusage copy-out.
/// Delegates the wait itself to sys_waitpid (which handles WUNTRACED /
/// WCONTINUED encodings and the blocking re-entry), then copies the dead
/// child's {utime_ticks, rtime?} pair when a result lands.
fn sys_wait4(ctx: &mut CpuContext, pid: u64, opts: u64, timeout: u64, rusage_ptr: u64) -> u64 {
    let r = sys_waitpid(ctx, pid, timeout, opts);
    if r != ERR && rusage_ptr != 0 {
        let cpid = if pid as u32 == u32::MAX {
            (r >> 32) as u32
        } else {
            pid as u32
        };
        if let Some((a, b)) = task::rusage(cpid) {
            let bytes = [a.to_le_bytes(), b.to_le_bytes()].concat();
            let _ = copy_out(rusage_ptr, &bytes);
        }
    }
    r
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
    // MS_NOEXEC on the covering mount (tmpfs or bind alias) bars exec
    // through it — EACCES like Linux.
    {
        let cwd = task::with_current(|t| t.cwd.clone());
        let pre = vfs::normalize_prebind(&cwd, &path);
        if task::mount_opts(&pre) & shared::MS_NOEXEC != 0 {
            return (-13i64) as u64;
        }
    }
    // snapshot CLOEXEC descriptors first: on success they must not reach
    // the new image (POSIX exec closes them); on failure nothing changes
    let clo: Vec<usize> = task::with_current(|t| {
        t.fds
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                f.as_ref()
                    .map(|f| f.flags & shared::O_CLOEXEC != 0)
                    .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect()
    });
    if task::exec_current(ctx, &path, &args) {
        for i in clo {
            vfs::close(i as i64);
        }
        0 // unreachable in practice — the frame is already the new image's
    } else {
        ERR
    }
}

/// SYS_SIGACTION(sig, handler): handler 0=SIG_DFL, 1=SIG_IGN, else a
/// userspace handler address. SIGKILL/SIGSTOP are uncatchable.
/// Returns the previous handler value.
/// SYS_PTRACE(op, pid, addr, data): real process tracing.
/// - TRACEME: mark self traced by parent (traced+tracer set)
/// - ATTACH/DETACH: claim/release a tracee; attach pends a SIGTRAP stop
/// - PEEK/POKE: 8B at addr through the tracee's pml4 (POKE splits COW)
/// - GETREGS/SETREGS: the tracee's parked CpuContext on its kstack
/// - CONT: resume from the stop; data>0 injects that signal, data==0
///   suppresses the signal that caused the stop (POSIX semantics)
/// - STEP: TF-bit single-step — resumes, #DB fires after one insn,
///   SIGTRAP pends and the traced-stop lands on the next delivery
/// - KILL: unconditional 128+9
fn sys_ptrace(op: u64, pid: u32, addr: u64, data: u64) -> u64 {
    let me = cur_id();
    match op {
        shared::PT_TRACEME => {
            let parent = task::with_current(|t| t.parent);
            task::with_current(|t| {
                t.sig.traced = true;
                t.sig.tracer = parent;
            });
            0
        }
        shared::PT_ATTACH => {
            // Linux: same-uid tracing is free; anything else needs
            // CAP_SYS_PTRACE.
            let (ru, _, eu, _) = task::creds();
            let privd = task::capable(task::CAP_SYS_PTRACE);
            let ok = task::with_pid_mut(pid, |t| {
                if !privd && ru != t.uid && eu != t.uid && ru != t.suid && eu != t.suid {
                    return -1;
                }
                if !t.is_user
                    || t.state == task::State::Dead
                    || t.id == 1
                    || t.name == "cosmos-winserver"
                    || t.sig.traced
                    || pid == me
                {
                    return -1;
                }
                t.sig.traced = true;
                t.sig.tracer = me;
                t.sigpending |= 1 << 5; // SIGTRAP -> traced-stop
                task::wake_for_signal(t, 5);
                0
            });
            if ok == 0 { 0 } else { ERR }
        }
        shared::PT_DETACH => {
            let ok = task::with_pid_mut(pid, |t| {
                if !t.sig.traced || t.sig.tracer != me {
                    return -1;
                }
                t.sig.traced = false;
                t.sig.tracer = 0;
                t.sig.syscall_trace = false;
                t.sig.sc_phase = 0;
                t.stop_notified = false;
                if t.state == task::State::Stopped {
                    t.state = task::State::Running;
                }
                0
            });
            if ok == 0 { 0 } else { ERR }
        }
        shared::PT_PEEK => {
            // read 8B at addr via the tracee's page tables
            let (pml4, ok) = tracee_for(me, pid);
            if !ok {
                return ERR;
            }
            let Some(pml4) = pml4 else { return ERR };
            if addr & 7 != 0 {
                return ERR;
            }
            match crate::elf::translate_user(pml4, addr) {
                Some(p) => unsafe { *(crate::mem::phys_to_virt(p) as *const u64) },
                None => ERR,
            }
        }
        shared::PT_POKE => {
            let (pml4, ok) = tracee_for(me, pid);
            if !ok {
                return ERR;
            }
            let Some(pml4) = pml4 else { return ERR };
            if addr & 7 != 0 {
                return ERR;
            }
            let Some(p) = crate::elf::translate_user(pml4, addr) else {
                return ERR;
            };
            // a write on a COW-shared page must split it first
            let phys = task::cow_split(pml4, addr & !0xFFF, p & !0xFFF)
                .then(|| crate::elf::translate_user(pml4, addr))
                .flatten()
                .unwrap_or(p);
            unsafe {
                *(crate::mem::phys_to_virt(phys) as *mut u64) = data;
            }
            0
        }
        shared::PT_GETREGS | shared::PT_SETREGS => {
            // the stopped tracee's ctx lives at saved_rsp on its kstack
            let rsp = task::with_pid_mut(pid, |t| {
                if !t.sig.traced || t.sig.tracer != me
                    || t.state != task::State::Stopped
                    || t.saved_rsp == 0
                {
                    return 0;
                }
                t.saved_rsp as i64
            });
            if rsp <= 0 {
                return ERR; // guards with_pid_mut's not-found/-3 error codes
            }
            let rsp = rsp as u64;
            if op == shared::PT_GETREGS {
                let bytes = unsafe {
                    core::slice::from_raw_parts(rsp as *const u8, 160)
                };
                match copy_out_pub(data, bytes) {
                    Some(_) => 0,
                    None => ERR,
                }
            } else {
                let Some(bytes) = copy_in(data, 160) else { return ERR };
                if bytes.len() < 160 {
                    return ERR;
                }
                let mut saved: CpuContext = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const CpuContext)
                };
                saved.cs = unsafe { crate::gdt::USER_CS.0 as u64 };
                saved.ss = unsafe { crate::gdt::USER_DS.0 as u64 };
                saved.rflags = (saved.rflags & !0x0003_7000) | 0x202;
                unsafe { *(rsp as *mut CpuContext) = saved };
                0
            }
        }
        shared::PT_CONT | shared::PT_STEP => {
            let ok = task::with_pid_mut(pid, |t| {
                if !t.sig.traced || t.sig.tracer != me
                    || t.state != task::State::Stopped
                {
                    return -1;
                }
                if data > 0 && data < 32 {
                    t.sigpending |= 1 << data; // inject this signal
                } else if data == 0 {
                    // POSIX CONT(0): suppress the signal that caused the stop
                    t.sigpending &= !(1 << (t.stop_sig as u64));
                }
                if op == shared::PT_STEP {
                    if t.saved_rsp == 0 {
                        return -1;
                    }
                    unsafe {
                        (*(t.saved_rsp as *mut CpuContext)).rflags |= 0x100;
                    }
                }
                t.sig.sc_phase = 0; // CONT/STEP runs without syscall stops
                t.stop_notified = false;
                t.state = task::State::Running;
                0
            });
            if ok == 0 { 0 } else { ERR }
        }
        shared::PT_PEEKUSER | shared::PT_POKEUSER => {
            // access the tracee's saved register area (its CpuContext at
            // saved_rsp on the kstack) — addr is a byte offset, 8-aligned
            if addr & 7 != 0 || addr >= 160 {
                return ERR;
            }
            let rsp = task::with_pid_mut(pid, |t| {
                if !t.sig.traced || t.sig.tracer != me
                    || t.state != task::State::Stopped
                    || t.saved_rsp == 0
                {
                    return 0;
                }
                t.saved_rsp as i64
            });
            if rsp <= 0 {
                return ERR;
            }
            let cell = (rsp as u64 + addr) as *mut u64;
            if op == shared::PT_PEEKUSER {
                unsafe { *cell }
            } else {
                // don't let the tracer corrupt cs/ss/rflags through the
                // byte-level door — same invariants SETREGS enforces
                if addr == 152 || addr == 168 {
                    return ERR; // cs, ss (CpuContext field offsets)
                }
                if addr == 136 {
                    // rflags: force IF + reserved bit, drop IOPL/TF/NT
                    let v = (data & !0x0003_7100) | 0x202;
                    unsafe { *cell = v };
                    return 0;
                }
                unsafe { *cell = data };
                0
            }
        }
        shared::PT_SYSCALL => {
            // resume the stopped tracee and arm syscall-boundary stops:
            // it halts at the next dispatch entry (sc_phase=1->2) and
            // again at each syscall exit (sc_phase=2->0)
            let ok = task::with_pid_mut(pid, |t| {
                if !t.sig.traced || t.sig.tracer != me
                    || t.state != task::State::Stopped
                {
                    return -1;
                }
                if data > 0 && data < 32 {
                    t.sigpending |= 1 << data;
                }
                t.sig.syscall_trace = true;
                // sc_phase stays: it encodes where the tracee sits —
                // a signal-stop mid-syscall (0) entry-stops next int80,
                // an entry-stop rewind (2) must NOT re-stop on re-dispatch
                t.stop_notified = false;
                t.state = task::State::Running;
                0
            });
            if ok == 0 { 0 } else { ERR }
        }
        shared::PT_GETSIGINFO => {
            // si_signo/si_errno/si_code of the last stop, 12 bytes
            let sig = task::with_pid_mut(pid, |t| {
                if !t.sig.traced || t.sig.tracer != me
                    || t.state != task::State::Stopped
                {
                    return -1;
                }
                t.stop_sig as i64
            });
            if sig < 0 {
                return ERR;
            }
            let buf = [sig as u32, 0u32, 0u32];
            let bytes = unsafe {
                core::slice::from_raw_parts(buf.as_ptr() as *const u8, 12)
            };
            match copy_out_pub(data, bytes) {
                Some(_) => 0,
                None => ERR,
            }
        }
        shared::PT_KILL => {
            if task::kill_pid_code(pid, 128 + 9) { 0 } else { ERR }
        }
        _ => ERR,
    }
}

/// Is `pid` a tracee of `me` that is stopped and inspectable?
fn tracee_for(me: u32, pid: u32) -> (Option<PhysFrame>, bool) {
    let pml4 = task::with_pid_mut(pid, |t| {
        if !t.sig.traced || t.sig.tracer != me
            || t.state != task::State::Stopped
        {
            return 0;
        }
        t.pml4.map(|p| p.start_address().as_u64() as i64).unwrap_or(-1)
    });
    if pml4 <= 0 {
        return (None, false);
    }
    (
        Some(unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(pml4 as u64)) }),
        true,
    )
}

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
            task::with_current(|t| t.wait_timeout = 0);
            return if any {
                ((cpid as u64) << 32) | (st as u64 & 0xffff_ffff)
            } else {
                st as u64
            };
        }
    }
    // WCONTINUED (bit1): report a child continued since its last report —
    // status is the POSIX WIFCONTINUED encoding 0xffff
    if opts & 2 != 0 {
        let got = if any {
            task::child_cont_any(me)
        } else {
            task::child_cont_one(me, pid as u32)
        };
        if let Some((cpid, st)) = got {
            task::with_current(|t| t.wait_timeout = 0);
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

/// SYS_WAITID(idtype, id, flags): wait report returning
/// (pid<<32)|(kind<<24)|status — kind 1=exit, 2=stopped, 3=continued.
/// idtype 0 = this child pid, 2 (or id=MAX) = any child.
/// flags: bit0 WNOHANG, bit1 WSTOPPED, bit2 WCONTINUED.
fn sys_waitid(ctx: &mut CpuContext, idtype: u64, id: u64, flags: u64) -> u64 {
    let me = cur_id();
    let any = idtype == 2 || id as u32 == u32::MAX;
    if flags & 2 != 0 {
        let got = if any {
            task::child_stopped_any(me)
        } else {
            task::child_stopped_one(me, id as u32)
        };
        if let Some((cpid, st)) = got {
            return ((cpid as u64) << 32) | (2 << 24) | (st as u64 & 0xffff);
        }
    }
    if flags & 4 != 0 {
        let got = if any {
            task::child_cont_any(me)
        } else {
            task::child_cont_one(me, id as u32)
        };
        if let Some((cpid, st)) = got {
            return ((cpid as u64) << 32) | (3 << 24) | (st as u64 & 0xffff);
        }
    }
    if any {
        if let Some((cpid, code)) = task::child_exit_any(me) {
            return ((cpid as u64) << 32) | (1 << 24) | (code as u64 & 0xffff);
        }
        if !task::has_children(me) {
            return ERR;
        }
    } else {
        if !task::exists(id as u32) {
            return ERR;
        }
        if let Some(code) = task::child_exit(id as u32) {
            return ((id as u64) << 32) | (1 << 24) | (code as u64 & 0xffff);
        }
    }
    if flags & 1 != 0 {
        return 0; // WNOHANG: nothing reportable
    }
    // block until a child changes state; wake re-executes this syscall
    // (rip rewind is REQUIRED — without it the resumed frame abandons
    // the wait entirely)
    task::with_current(|t| {
        t.state = task::State::Blocked;
        t.waiting_on = if any { u32::MAX } else { id as u32 };
        t.wake_at = task::ticks() + 50; // recheck window
    });
    ctx.rip -= 2;
    task::yield_ctx(ctx);
}

/// SYS_CAPGET(pid, out u64[3]): (effective, permitted, bounding) of
/// `pid` — 0 = caller. The effective set is derived: euid 0 wields
/// permitted; a non-root task shows its stored cap_eff.
fn sys_capget(pid: u64, out: u64) -> u64 {
    let v = if pid == 0 {
        Some(task::capset3())
    } else {
        task::pid_caps(pid as u32)
    };
    match v {
        Some((e, p, b)) => {
            let mut buf = alloc::vec![0u8; 24];
            for (i, v) in [e, p, b].iter().enumerate() {
                buf[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            match copy_out(out, &buf) {
                Some(()) => 0,
                None => ERR,
            }
        }
        None => (-3i64) as u64, // ESRCH
    }
}

/// SYS_CAPSET(pid, in u64[2]{eff,prm}): self only (pid 0 or own id) —
/// Linux requires CAP_SETPCAP to touch another task's set and our
/// tasks never hand it out, so cross-task sets stay EPERM.
fn sys_capset(pid: u64, inp: u64) -> u64 {
    let me = task::current_id();
    if pid != 0 && pid as u32 != me {
        return (-1i64) as u64; // EPERM
    }
    let Some(a) = copy_in(inp, 16) else { return ERR };
    let eff = u64::from_le_bytes(a[..8].try_into().unwrap());
    let prm = u64::from_le_bytes(a[8..].try_into().unwrap());
    task::capset_self(eff, prm) as u64
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
    // One critical section: if a deliverable signal is already pending,
    // re-enter instead of blocking. Without this, a signal landing
    // between the syscall's readiness check and this block is LOST —
    // wake_for_signal no-ops on a still-Running task, and the task then
    // sleeps forever with the pending bit set (a whole-machine hang:
    // no runnable tasks, idle hlt loop).
    let intr = task::with_current(|t| {
        if t.sig.wake_eintr {
            t.sig.wake_eintr = false;
            t.sleep_deadline = 0;
            t.wake_at = 0;
            t.wait_port = 0;
            t.waiting_on = 0;
            t.wait_futex = 0;
            t.poll_dl = 0;
            if t.poll_saved_mask != u64::MAX {
                t.sigmask = t.poll_saved_mask;
                t.poll_saved_mask = u64::MAX;
            }
            1
        } else if t.sigpending & !t.sigmask != 0 {
            2 // pending deliverable: re-enter so maybe_deliver runs it
        } else {
            t.state = task::State::Blocked;
            t.wake_at = deadline;
            t.wait_port = wait_port;
            0
        }
    });
    if intr == 1 {
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
    if crate::proc::is_dir(&full)
        || crate::dev::is_dir(&full)
        || crate::tmpfs::stat(&full).map(|s| s.1).unwrap_or(false)
    {
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
