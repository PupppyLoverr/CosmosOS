//! CosmosOS userspace runtime ("ustd"): _start, syscalls, heap, printing,
//! file system, IPC, shm, windows. Everything is a thin, real syscall —
//! no stubs, no simulation.
#![no_std]
#![no_main]
#![feature(allocator_api)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use linked_list_allocator::LockedHeap;

pub mod draw;
pub mod img;
pub mod deflate;
pub mod inflate;
// FONT16 moved to `shared` so the kernel can render its panic screen.
pub mod font16 {
    pub use shared::font16::FONT16;
}
pub mod wm;

// ---------------------------------------------------------------------------
// syscall raw wrappers (int 0x80; nr=rax, args rdi,rsi,rdx,r8,r9)
// ---------------------------------------------------------------------------
#[inline(always)]
pub fn sc0(nr: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("int 0x80", inout("rax") nr => r, options(nostack, preserves_flags)) };
    r
}
#[inline(always)]
pub fn sc1(nr: u64, a: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("int 0x80", inout("rax") nr => r, in("rdi") a, options(nostack, preserves_flags)) };
    r
}
#[inline(always)]
pub fn sc2(nr: u64, a: u64, b: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("int 0x80", inout("rax") nr => r, in("rdi") a, in("rsi") b, options(nostack, preserves_flags)) };
    r
}
#[inline(always)]
pub fn sc3(nr: u64, a: u64, b: u64, c: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("int 0x80", inout("rax") nr => r, in("rdi") a, in("rsi") b, in("rdx") c, options(nostack, preserves_flags)) };
    r
}
#[inline(always)]
pub fn sc4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("int 0x80", inout("rax") nr => r, in("rdi") a, in("rsi") b, in("rdx") c, in("r8") d, options(nostack, preserves_flags)) };
    r
}
#[inline(always)]
pub fn sc5(nr: u64, a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("int 0x80", inout("rax") nr => r, in("rdi") a, in("rsi") b, in("rdx") c, in("r8") d, in("r9") e, options(nostack, preserves_flags)) };
    r
}

const ERR: u64 = shared::SYS_ERR;
pub fn is_err(v: u64) -> bool {
    v >= u64::MAX - 4096
}

// ---------------------------------------------------------------------------
// process / time
// ---------------------------------------------------------------------------
pub fn exit(code: i64) -> ! {
    sc1(shared::SYS_EXIT, code as u64);
    loop {
        core::hint::spin_loop();
    }
}
pub fn yield_now() {
    sc0(shared::SYS_YIELD);
}
pub fn sleep_ms(ms: u64) {
    sc1(shared::SYS_SLEEP_MS, ms);
}
pub fn uptime_ms() -> u64 {
    sc0(shared::SYS_UPTIME_MS)
}
pub fn spawn(path: &str, args: &str) -> Result<u32, ()> {
    let pid = sc4(
        shared::SYS_SPAWN,
        path.as_ptr() as u64,
        path.len() as u64,
        if args.is_empty() { 0 } else { args.as_ptr() as u64 },
        args.len() as u64,
    );
    if is_err(pid) {
        Err(())
    } else {
        Ok(pid as u32)
    }
}
pub fn waitpid(pid: u32, timeout_ms: u64) -> Result<i64, ()> {
    // opts must be explicit — a stale 3rd register reads as garbage flags
    let r = sc3(shared::SYS_WAITPID, pid as u64, timeout_ms, 0);
    if is_err(r) {
        Err(())
    } else {
        Ok(r as i64)
    }
}

pub const WUNTRACED: u64 = 1;

/// waitpid with POSIX option flags (WUNTRACED reports stopped children,
/// returned status is 0x7f | (sig << 8)).
pub fn waitpid_opt(pid: u32, flags: u64, timeout_ms: u64) -> Result<i64, ()> {
    let r = sc3(shared::SYS_WAITPID, pid as u64, timeout_ms, flags);
    if is_err(r) {
        Err(())
    } else {
        Ok(r as i64)
    }
}

/// Parent pid of the calling process.
pub fn getppid() -> i64 {
    sc1(shared::SYS_GETPPID, 0) as i64
}

/// PR_SET_NAME: rename this task (visible in /proc and ps).
pub fn set_name(name: &str) -> i64 {
    sc2(shared::SYS_PRCTL, 15, name.as_ptr() as u64) as i64
}

/// Pending-signal bitmask for this process.
pub fn sigpending() -> u64 {
    sc1(shared::SYS_SIGPENDING, 0)
}

/// Atomically swap the signal mask and sleep until a signal is
/// deliverable; the old mask is restored before the handler runs.
/// Returns -4 (EINTR) when it wakes.
pub fn sigsuspend(mask: u64) -> i64 {
    sc1(shared::SYS_SIGSUSPEND, mask) as i64
}

/// ARCH_SET_FS: install this thread's TLS base (fs segment).
pub fn set_fs_base(addr: u64) -> i64 {
    sc2(shared::SYS_ARCH_PRCTL, 2, addr) as i64
}

/// ARCH_GET_FS.
pub fn get_fs_base() -> u64 {
    sc2(shared::SYS_ARCH_PRCTL, 3, 0)
}

/// Read the thread id the kernel stored in the TCB (fs:8).
pub fn thread_id() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:8", out(reg) v, options(nostack, preserves_flags));
    }
    v
}

/// Read the TCB self pointer (fs:0).
pub fn tls_self() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:0", out(reg) v, options(nostack, preserves_flags));
    }
    v
}

pub const RLIMIT_STACK: u64 = 3;
pub const RLIMIT_NPROC: u64 = 6;
pub const RLIMIT_NOFILE: u64 = 7;

/// getrlimit: returns the current limit for `res` (self).
pub fn getrlimit(res: u64) -> Option<u64> {
    let mut old = 0u64;
    let r = sc4(
        shared::SYS_PRLIMIT,
        0,
        res,
        u64::MAX,
        &mut old as *mut u64 as u64,
    );
    if is_err(r) { None } else { Some(old) }
}

/// setrlimit: set `res` on self. Returns true on success.
pub fn setrlimit(res: u64, lim: u64) -> bool {
    !is_err(sc4(shared::SYS_PRLIMIT, 0, res, lim, 0))
}

/// pthread-style thread: `f(arg)` runs in the caller's address space on a
/// private 256KiB stack; the thread exits with `f`'s return code (reap
/// with `waitpid`, same as a process). Err = no stack slot / bad entry.
pub fn thread_spawn(f: extern "C" fn(u64) -> i64, arg: u64) -> Result<u32, ()> {
    extern "C" fn entry(raw: u64) -> ! {
        // the (f,arg) pair is a heap cell in our shared address space —
        // free it after reading (leaks nothing on either side)
        let pair = unsafe { *alloc::boxed::Box::from_raw(raw as *mut (extern "C" fn(u64) -> i64, u64)) };
        let code = (pair.0)(pair.1);
        exit(code)
    }
    let b = alloc::boxed::Box::new((f, arg));
    let raw = alloc::boxed::Box::into_raw(b) as u64;
    // CLONE_SETTLS: hand the thread a real TCB — [0]=self ptr, [8]=tid
    // (the kernel fills [8] once the child exists)
    let tcb = alloc::boxed::Box::leak(alloc::boxed::Box::new([0u64; 2]));
    tcb[0] = tcb.as_ptr() as u64;
    let pid = sc3(
        shared::SYS_CLONE,
        entry as u64,
        raw,
        tcb.as_ptr() as u64,
    );
    if is_err(pid) {
        unsafe {
            drop(alloc::boxed::Box::from_raw(raw as *mut (extern "C" fn(u64) -> i64, u64)));
        }
        Err(())
    } else {
        Ok(pid as u32)
    }
}

// ---- futex: real kernel wait/wake on a userspace atomic word ----

pub const FUTEX_WAIT: u64 = 0;
pub const FUTEX_WAKE: u64 = 1;

/// Raw futex syscall. WAIT returns 0 woken, -11 EAGAIN (value differs),
/// -110 ETIMEDOUT. WAKE returns the number of waiters woken.
pub fn futex(uaddr: &core::sync::atomic::AtomicU64, op: u64, val: u64, timeout_ms: u64) -> i64 {
    sc4(
        shared::SYS_FUTEX,
        uaddr as *const _ as u64,
        op,
        val,
        timeout_ms,
    ) as i64
}

/// Sleep while `*uaddr == val` (spurious wakes possible — callers loop).
pub fn futex_wait(uaddr: &core::sync::atomic::AtomicU64, val: u64) {
    let _ = futex(uaddr, FUTEX_WAIT, val, u64::MAX);
}

/// Wake up to `n` waiters blocked on `uaddr`.
pub fn futex_wake(uaddr: &core::sync::atomic::AtomicU64, n: u64) -> i64 {
    futex(uaddr, FUTEX_WAKE, n, 0)
}

/// A real three-state futex mutex (glibc-style): 0 = free, 1 = locked
/// without waiters, 2 = locked with sleepers queued in the kernel.
pub struct Mutex {
    pub state: core::sync::atomic::AtomicU64,
}

impl Mutex {
    pub const fn new() -> Self {
        Mutex { state: core::sync::atomic::AtomicU64::new(0) }
    }
    pub fn lock(&self) {
        use core::sync::atomic::Ordering;
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        // contested: mark waiters and sleep while the word stays != 0
        while self.state.swap(2, Ordering::Acquire) != 0 {
            futex_wait(&self.state, 2);
        }
    }
    pub fn unlock(&self) {
        use core::sync::atomic::Ordering;
        if self.state.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.state, 1);
        }
    }
}

/// Signal dispositions.
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// Register a userspace handler for `sig` (0=DFL 1=IGN else fn addr).
/// Returns the previous disposition. SIGKILL/SIGSTOP can't be caught.
pub const SA_RESTART: u64 = 1;
pub const SA_ONSTACK: u64 = 2;
pub const SA_NODEFER: u64 = 4;
pub const SS_DISABLE: u64 = 2;

pub fn sigaction(sig: u64, handler: u64) -> i64 {
    sigaction_fl(sig, handler, 0)
}

/// sigaction with sa_flags: SA_RESTART restarts interrupted slow
/// syscalls instead of EINTR; SA_ONSTACK runs the handler on the
/// stack registered with sigaltstack; SA_NODEFER leaves the signal
/// unmasked inside its own handler.
pub fn sigaction_fl(sig: u64, handler: u64, flags: u64) -> i64 {
    sc3(shared::SYS_SIGACTION, sig, handler, flags) as i64
}

pub const PT_TRACEME: u64 = 0;
pub const PT_PEEK: u64 = 1;
pub const PT_POKE: u64 = 4;
pub const PT_CONT: u64 = 7;
pub const PT_KILL: u64 = 8;
pub const PT_STEP: u64 = 9;
pub const PT_GETREGS: u64 = 12;
pub const PT_SETREGS: u64 = 13;
pub const PT_ATTACH: u64 = 16;
pub const PT_DETACH: u64 = 17;

pub use shared::PtRegs;

/// ptrace(op, pid, addr, data): process tracing. Returns -1 on error;
/// PEEK returns the read word directly.
pub fn ptrace(op: u64, pid: u32, addr: u64, data: u64) -> i64 {
    sc4(shared::SYS_PTRACE, op, pid as u64, addr, data) as i64
}

pub const PT_PEEKUSER: u64 = 3;
pub const PT_POKEUSER: u64 = 6;
pub const PT_SYSCALL: u64 = 24;
pub const PT_GETSIGINFO: u64 = 0x4202;

/// waitid(idtype, id, flags): idtype 0=P_ALL, 1=P_PID; flags bit0
/// WNOHANG, bit1 WSTOPPED, bit2 WCONTINUED. Returns packed
/// (pid << 32) | (kind << 24) | status — kind 1=exit, 2=stop, 3=cont.
pub fn waitid(idtype: u64, id: u32, flags: u64) -> i64 {
    sc3(shared::SYS_WAITID, idtype, id as u64, flags) as i64
}

/// PTRACE_GETREGS into a shared::PtRegs.
pub fn ptrace_getregs(pid: u32) -> Option<PtRegs> {
    let mut r = PtRegs::default();
    let p = &mut r as *mut PtRegs as u64;
    if ptrace(PT_GETREGS, pid, 0, p) == 0 {
        Some(r)
    } else {
        None
    }
}

/// exit_group(code): POSIX exit_group — kills every thread of the mm.
pub fn exit_group(code: i64) -> ! {
    sc1(shared::SYS_EXIT_GROUP, code as u64);
    unreachable!()
}

/// gettid(): this thread's id (main thread's tid == getpid).
pub fn gettid() -> u32 {
    sc0(shared::SYS_GETTID) as u32
}

/// tgkill(tgid, tid, sig): signal a specific thread; tgid 0 skips the
/// same-address-space check.
pub fn tgkill(tgid: u32, tid: u32, sig: u64) -> i64 {
    sc3(shared::SYS_TGKILL, tgid as u64, tid as u64, sig) as i64
}

// POSIX wait-status decoders on the kernel's packed statuses
// (exit code | stopped 0x7f|(sig<<8) | continued 0xffff)
pub fn wifexited(st: i64) -> bool {
    st & 0x7f == 0
}
pub fn wexitstatus(st: i64) -> i64 {
    (st >> 8) & 0xff
}
pub fn wifstopped(st: i64) -> bool {
    st & 0xff == 0x7f
}
pub fn wstopsig(st: i64) -> i64 {
    (st >> 8) & 0xff
}
pub fn wifcontinued(st: i64) -> bool {
    st == 0xffff
}

/// PTRACE_GETSIGINFO: writes si_signo/errno/code (12 bytes) for the
/// tracee's last stop. Returns the signal number for convenience.
pub fn ptrace_siginfo(pid: u32) -> Option<u32> {
    let mut buf = [0u32; 3];
    if ptrace(PT_GETSIGINFO, pid, 0, buf.as_mut_ptr() as u64) == 0 {
        Some(buf[0])
    } else {
        None
    }
}

/// setitimer(which, init_ms, interval_ms): which 0=REAL(wall),1=VIRTUAL
/// (cpu),2=PROF — arms a real kernel timer that pends SIGALRM/SIGVTALRM/
/// SIGPROF. init_ms 0 disarms.
pub fn setitimer(which: u64, init_ms: u64, interval_ms: u64) -> i64 {
    sc3(shared::SYS_SETITIMER, which, init_ms, interval_ms) as i64
}

/// getitimer(which) -> (cur_ms, interval_ms)
pub fn getitimer(which: u64) -> (u64, u64) {
    let v = sc1(shared::SYS_GETITIMER, which);
    (v >> 32, v & 0xffff_ffff)
}

/// POSIX mq_open: name/caps -> queue fd (use send/recv, not read/write)
pub fn mq_open(name: &str, maxmsg: u64, msgsize: u64) -> i64 {
    sc4(shared::SYS_MQ_OPEN, name.as_ptr() as u64, name.len() as u64,
        maxmsg, msgsize) as i64
}

/// mq_send(fd, data, prio) -> 0 | err (prio orders delivery, highest first)
pub fn mq_send(fd: i64, data: &[u8], prio: u32) -> i64 {
    sc4(shared::SYS_MQ_SEND, fd as u64, data.as_ptr() as u64,
        data.len() as u64, prio as u64) as i64
}

/// mq_receive(fd, buf) -> Ok((n, prio)) | err
pub fn mq_recv(fd: i64, buf: &mut [u8]) -> Result<(usize, u32), i64> {
    let v = sc3(shared::SYS_MQ_RECV, fd as u64, buf.as_mut_ptr() as u64,
                buf.len() as u64);
    if (v as i64) < 0 {
        Err(v as i64)
    } else {
        Ok(((v & 0xffff_ffff) as usize, (v >> 32) as u32))
    }
}

/// mq_unlink(name): detach a named queue (POSIX lifetime: dies at last
/// close once unlinked)
pub fn mq_unlink(name: &str) -> i64 {
    sc2(shared::SYS_MQ_UNLINK, name.as_ptr() as u64, name.len() as u64) as i64
}

/// memfd_create(name): an anonymous RAM-backed file fd — read/write/
/// seek/truncate/mmap like a real file; dies with its last fd.
pub fn memfd_create(name: &str) -> i64 {
    sc2(shared::SYS_MEMFD_CREATE, name.as_ptr() as u64, name.len() as u64) as i64
}

/// POSIX timer_create(sig) -> timer id | err
pub fn timer_create(sig: u64) -> i64 {
    sc1(shared::SYS_TIMER_CREATE, sig) as i64
}

/// timer_settime(id, init_ms, interval_ms) -> 0 | err
pub fn timer_settime(id: u64, init_ms: u64, interval_ms: u64) -> i64 {
    sc3(shared::SYS_TIMER_SETTIME, id, init_ms, interval_ms) as i64
}

/// timer_delete(id) -> 0 | err
pub fn timer_delete(id: u64) -> i64 {
    sc1(shared::SYS_TIMER_DELETE, id) as i64
}

/// clock_gettime(clkid) -> (sec, nsec); clk 0=REALTIME(rtc), 1=MONOTONIC
pub fn clock_gettime(clkid: u64) -> Option<(u64, u64)> {
    let mut v = [0u64; 2];
    if sc2(shared::SYS_CLOCK_GETTIME, clkid, v.as_mut_ptr() as u64) == 0 {
        Some((v[0], v[1]))
    } else {
        None
    }
}

/// mmap at a fixed address (MAP_FIXED semantics — evicts overlaps)
pub fn mmap_fixed(addr: u64, size: u64) -> Option<*mut u8> {
    let p = sc3(shared::SYS_MMAP, size, 1, addr);
    if p == 0 || p == ERR { None } else { Some(p as *mut u8) }
}

/// Register an alternate signal stack (sa_flags=SA_ONSTACK handlers run
/// on it). Pass SS_DISABLE as flags to unregister.
pub fn sigaltstack(sp: u64, size: u64) -> i64 {
    sc4(shared::SYS_SIGALTSTACK, sp, size, 0, 0) as i64
}



/// C-friendly alias — pass the function's address.
pub fn signal(sig: u64, handler: extern "C" fn(u64)) -> i64 {
    sigaction(sig, handler as usize as u64)
}

/// Send `sig` to the calling process.
pub fn raise(sig: u64) -> i64 {
    kill2(getpid(), sig)
}

pub const SIG_BLOCK: u64 = 0;
pub const SIG_UNBLOCK: u64 = 1;
pub const SIG_SETMASK: u64 = 2;

/// sigprocmask: adjust the blocked-signal mask; returns the old mask.
pub fn sigprocmask(how: u64, mask: u64) -> i64 {
    sc2(shared::SYS_SIGPROCMASK, how, mask) as i64
}

/// A signalfd: read pending signals in `mask` as 128B records (first u32 =
/// signo). Poll-able, O_NONBLOCK-able like any fd.
pub fn signalfd(mask: u64) -> i64 {
    sc1(shared::SYS_SIGNALFD, mask) as i64
}

/// Arm a one-shot SIGALRM in `secs`; returns the previous seconds left.
pub fn alarm(secs: u64) -> i64 {
    sc1(shared::SYS_ALARM, secs) as i64
}

/// setsid: leave the session/group and lead a new one (fails if already
/// a group leader — fork first like POSIX daemons do).
pub fn setsid() -> i64 {
    sc1(shared::SYS_SETSID, 0) as i64
}

/// setpgid(pid, pgid): 0 = self / same-as-pid.
pub fn setpgid(pid: u32, pgid: u32) -> i64 {
    sc2(shared::SYS_SETPGID, pid as u64, pgid as u64) as i64
}
pub fn getpgid(pid: u32) -> i64 {
    sc1(shared::SYS_GETPGID, pid as u64) as i64
}
pub fn getsid(pid: u32) -> i64 {
    sc1(shared::SYS_GETSID, pid as u64) as i64
}

/// Signal the whole process group (POSIX kill(-pgid)).
pub fn killpg(pgid: u32, sig: u64) -> i64 {
    kill2((pgid as i32).wrapping_neg() as u32, sig)
}

/// PR_SET_PDEATHSIG: deliver `sig` to this task when its parent dies.
pub fn set_pdeathsig(sig: u64) -> i64 {
    sc2(shared::SYS_PRCTL, 1, sig) as i64
}

/// Real fork(): the child resumes here with 0, in a private copy of the
/// parent's whole address space; the parent gets the child pid.
pub fn fork() -> i64 {
    sc0(shared::SYS_FORK) as i64
}

/// execve: replace this task's image with `path` (args string) — returns
/// only on failure; open fds carry over.
pub fn execve(path: &str, args: &str) -> i64 {
    sc4(
        shared::SYS_EXECVE,
        path.as_ptr() as u64,
        path.len() as u64,
        args.as_ptr() as u64,
        args.len() as u64,
    ) as i64
}

/// posix_spawn-style: fork + exec in one call — the child execs `path`
/// and the parent gets its pid. Err = fork failed.
pub fn spawnv(path: &str, args: &str) -> Result<u32, ()> {
    match fork() {
        0 => {
            let _ = execve(path, args);
            exit(-1);
        }
        p if p > 0 => Ok(p as u32),
        _ => Err(()),
    }
}

/// POSIX wait(-1): (pid, exit_code) of the first dead child — reaped by
/// the kernel. Err = no children / timeout.
pub fn waitpid_any(timeout_ms: u64) -> Result<(u32, i64), ()> {
    let r = sc2(shared::SYS_WAITPID, u32::MAX as u64, timeout_ms);
    if is_err(r) {
        Err(())
    } else {
        Ok(((r >> 32) as u32, (r & 0xffff_ffff) as i64))
    }
}
pub fn kill(pid: u32) -> bool {
    sc1(shared::SYS_KILL, pid as u64) == 0
}
// ---------------------------------------------------------------------------
// networking
// ---------------------------------------------------------------------------
/// Ping an IPv4 host (a.b.c.d packed big-endian into u32).
/// Returns round-trip ms, or None on timeout / no device.
pub fn net_ping(ip: u32, timeout_ms: u64) -> Option<u64> {
    let r = sc2(shared::SYS_NET_PING, ip as u64, timeout_ms);
    if r == u64::MAX { None } else { Some(r) }
}
/// Resolve a hostname to an IPv4 address via a real DNS query (UDP/53).
pub fn net_dns(name: &str) -> Option<[u8; 4]> {
    let mut ip = [0u8; 4];
    let r = sc3(
        shared::SYS_NET_DNS,
        name.as_ptr() as u64,
        name.len() as u64,
        ip.as_mut_ptr() as u64,
    );
    if r == u64::MAX { None } else { Some(ip) }
}
/// Real HTTP GET over real TCP: resolves `host` (DNS/UDP) then
/// `GET / HTTP/1.0` on port 80. Returns up to 4 KiB of the response.
pub fn net_http(host: &str) -> Option<alloc::vec::Vec<u8>> {
    let mut buf = alloc::vec![0u8; 4096];
    let n = sc4(
        shared::SYS_NET_HTTP,
        host.as_ptr() as u64,
        host.len() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    );
    if n == u64::MAX {
        None
    } else {
        buf.truncate(n as usize);
        Some(buf)
    }
}
/// Real UDP socket: bind a local port, sendto/recvfrom on the wire.
pub struct UdpSock {
    pub lport: u16,
}
impl UdpSock {
    /// bind(lport): Err on already-bound or no device.
    pub fn open(lport: u16) -> Option<UdpSock> {
        if sc1(shared::SYS_NET_UDP_OPEN, lport as u64) == u64::MAX {
            None
        } else {
            Some(UdpSock { lport })
        }
    }
    /// sendto(dst_ip, dport, payload) — real ARP + wire send.
    pub fn send_to(&self, dst_ip: [u8; 4], dport: u16, payload: &[u8]) -> Option<()> {
        let ip = u32::from_be_bytes(dst_ip) as u64;
        let r = sc5(
            shared::SYS_NET_UDP_SEND,
            self.lport as u64,
            ip,
            dport as u64,
            payload.as_ptr() as u64,
            payload.len() as u64,
        );
        if r == u64::MAX { None } else { Some(()) }
    }
    /// recvfrom(timeout_ms): (src_ip, src_port, payload) — real wire datagram.
    pub fn recv_from(&self, timeout_ms: u64) -> Option<([u8; 4], u16, alloc::vec::Vec<u8>)> {
        let mut buf = alloc::vec![0u8; 2048];
        let n = sc4(
            shared::SYS_NET_UDP_RECV,
            self.lport as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            timeout_ms,
        );
        if n == u64::MAX || n < 6 {
            return None;
        }
        buf.truncate(n as usize);
        let ip: [u8; 4] = buf[..4].try_into().ok()?;
        let port = u16::from_be_bytes([buf[4], buf[5]]);
        Some((ip, port, buf.split_off(6)))
    }
}
impl Drop for UdpSock {
    fn drop(&mut self) {
        sc1(shared::SYS_NET_UDP_CLOSE, self.lport as u64);
    }
}
/// A userspace TCP stream: SYN handshake on connect, send/recv on the
/// kernel socket queue, FIN on drop.
pub struct TcpSock {
    pub lport: u16,
}
impl TcpSock {
    /// Connect local port `lport` to `ip:rport` (real 3-way handshake).
    pub fn connect(lport: u16, ip: [u8; 4], rport: u16) -> Option<Self> {
        if sc3(shared::SYS_NET_TCP_OPEN, lport as u64, u32::from_be_bytes(ip) as u64, rport as u64) == shared::SYS_ERR {
            None
        } else {
            Some(Self { lport })
        }
    }
    /// Send data (<=1400B per call); retransmitted by the kernel until ACKed.
    pub fn send(&self, data: &[u8]) -> Option<()> {
        if sc3(shared::SYS_NET_TCP_SEND, self.lport as u64, data.as_ptr() as u64, data.len() as u64) == shared::SYS_ERR {
            None
        } else {
            Some(())
        }
    }
    /// Next in-order chunk, or None on peer close/timeout.
    pub fn recv(&self, timeout_ms: u64) -> Option<Vec<u8>> {
        let mut buf = alloc::vec![0u8; 4096];
        let n = sc4(shared::SYS_NET_TCP_RECV, self.lport as u64, buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ms);
        if n == shared::SYS_ERR || n == 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }
}
impl Drop for TcpSock {
    fn drop(&mut self) {
        sc1(shared::SYS_NET_TCP_CLOSE, self.lport as u64);
    }
}

/// A TCP listener: mark a port, then `accept` inbound conns as TcpSock
/// handles keyed by kernel conn id (several clients may share a port).
pub struct TcpListener {
    pub lport: u16,
}
impl TcpListener {
    pub fn bind(lport: u16) -> Option<Self> {
        if sc1(shared::SYS_NET_TCP_LISTEN, lport as u64) == shared::SYS_ERR {
            None
        } else {
            Some(Self { lport })
        }
    }
    /// Next fully-handshaken conn: (socket, peer ip, peer port).
    pub fn accept(&self, timeout_ms: u64) -> Option<(TcpSock, [u8; 4], u16)> {
        let mut out = [0u8; 8];
        let cid = sc3(
            shared::SYS_NET_TCP_ACCEPT,
            self.lport as u64,
            out.as_mut_ptr() as u64,
            timeout_ms,
        );
        if cid == shared::SYS_ERR {
            return None;
        }
        let rip: [u8; 4] = out[..4].try_into().ok()?;
        let rport = u16::from_be_bytes([out[4], out[5]]);
        Some((TcpSock { lport: cid as u16 }, rip, rport))
    }
}
impl Drop for TcpListener {
    fn drop(&mut self) {
        sc1(shared::SYS_NET_TCP_UNLISTEN, self.lport as u64);
    }
}

/// (total_bytes, free_bytes) of the data volume.
pub fn df() -> Option<(u64, u64)> {
    let mut out = [0u64; 2];
    if sc1(shared::SYS_DF, out.as_mut_ptr() as u64) == shared::SYS_ERR {
        return None;
    }
    Some((out[0], out[1]))
}

/// Kernel ARP cache dump (`arp`).
pub fn arp_stat() -> String {
    let mut buf = alloc::vec![0u8; 2048];
    let n = sc2(shared::SYS_ARP, buf.as_mut_ptr() as u64, buf.len() as u64);
    if n == shared::SYS_ERR {
        return String::new();
    }
    buf.truncate(n as usize);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Fill `buf` with random bytes — RDRAND when the CPU has it, else the
/// kernel's rdtsc-seeded PRNG. Returns bytes written.
pub fn rand_fill(buf: &mut [u8]) -> usize {
    sc2(shared::SYS_RAND, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
}
/// One random u64, or None if the syscall failed.
pub fn rand_u64() -> Option<u64> {
    let mut b = [0u8; 8];
    if rand_fill(&mut b) == 8 {
        Some(u64::from_le_bytes(b))
    } else {
        None
    }
}

/// Tail of the kernel log ring buffer (`dmesg`).
pub fn klog() -> String {
    let mut buf = alloc::vec![0u8; 16 * 1024];
    let n = sc2(shared::SYS_KLOG, buf.as_mut_ptr() as u64, buf.len() as u64);
    if n == shared::SYS_ERR {
        return String::new();
    }
    buf.truncate(n as usize);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Kernel framebuffer screenshot: writes a P6 PPM of the live display
/// to `path` on the data volume.
pub fn shot(path: &str) -> bool {
    sc3(shared::SYS_SHOT, path.as_ptr() as u64, path.len() as u64, 0) != shared::SYS_ERR
}

/// `netstat` dump of the kernel socket tables.
pub fn net_stat() -> String {
    let mut buf = alloc::vec![0u8; 4096];
    let n = sc2(shared::SYS_NET_STAT, buf.as_mut_ptr() as u64, buf.len() as u64);
    if n == shared::SYS_ERR {
        return String::new();
    }
    buf.truncate(n as usize);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Kernel clipboard (survives app exit — real cross-app copy/paste).
pub fn clip_set(data: &[u8]) {
    sc2(shared::SYS_CLIP_SET, data.as_ptr() as u64, data.len() as u64);
}
pub fn clip_get() -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let n = sc2(shared::SYS_CLIP_GET, buf.as_mut_ptr() as u64, buf.len() as u64);
    if n == shared::SYS_ERR {
        return Vec::new();
    }
    buf.truncate(n as usize);
    buf
}

/// Re-run a real DHCP DISCOVER/OFFER/REQUEST/ACK; returns the leased ip.
pub fn net_dhcp() -> Option<[u8; 4]> {
    let r = sc0(shared::SYS_NET_DHCP);
    if r == shared::SYS_ERR {
        None
    } else {
        Some((r as u32).to_be_bytes())
    }
}

/// (mac, ip) of the virtio-net device, if present.
pub fn net_info() -> Option<([u8; 6], [u8; 4])> {
    let mut b = [0u8; 10];
    if sc1(shared::SYS_NET_INFO, b.as_mut_ptr() as u64) == u64::MAX {
        return None;
    }
    let mut mac = [0u8; 6];
    let mut ip = [0u8; 4];
    mac.copy_from_slice(&b[..6]);
    ip.copy_from_slice(&b[6..]);
    Some((mac, ip))
}

/// Sound the PC speaker at `freq` Hz for `ms` (non-blocking; kernel silences
/// the gate when the duration elapses). `0`/`0` silences immediately.
/// SYS_PCAP control. op: 0 start, 1 stop, 2 stats (pkts<<32|dropped), 3 on?
/// op 4: fetch the pcap file image into `out` (returns len, or -needed).
pub fn pcap(op: u64, out: &mut [u8]) -> i64 {
    sc3(
        shared::SYS_PCAP,
        op,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    ) as i64
}

/// Own process id.
pub fn getpid() -> u32 {
    sc0(shared::SYS_GETPID) as u32
}

/// SYS_NICE: set scheduling priority (-20 high ..= 19 low, clamped).
/// pid 0 = self. Returns the stored nice value, or -1000 if no such pid.
pub fn set_nice(pid: u32, nice: i64) -> i64 {
    sc2(shared::SYS_NICE, pid as u64, nice as u64) as i64
}

pub fn beep(freq: u32, ms: u64) {
    sc2(shared::SYS_BEEP, freq as u64, ms);
}

pub fn poweroff() -> ! {
    sc0(shared::SYS_POWEROFF);
    loop {}
}
pub fn reboot() -> ! {
    sc0(shared::SYS_REBOOT);
    loop {}
}

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------
pub fn mmap(size: u64) -> Option<*mut u8> {
    let p = sc3(shared::SYS_MMAP, size, 0, 0);
    if p == 0 || is_err(p) {
        None
    } else {
        Some(p as *mut u8)
    }
}

/// mmap_file(fd, size, offset): real demand-paged file mapping — the VA
/// range is reserved now, each 4KiB page faults in from disk on first
/// touch (zero past EOF). None if fd isn't a real file.
pub fn mmap_file(fd: i64, size: u64, offset: u64) -> Option<*mut u8> {
    let p = sc3(shared::SYS_MMAP_FILE, fd as u64, size, offset);
    if p == 0 || is_err(p) {
        None
    } else {
        Some(p as *mut u8)
    }
}

/// munmap(addr, len): unmap a tracked user mapping — PTEs cleared,
/// owned frames freed, shm/fb borrowed pages detached.
pub fn munmap(addr: *mut u8, len: u64) -> bool {
    sc2(shared::SYS_MUNMAP, addr as u64, len) == 0
}

/// mprotect(addr, len, prot): change real page permissions
/// (PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4). Violations fault for real.
pub fn mprotect(addr: *mut u8, len: u64, prot: u64) -> bool {
    sc3(shared::SYS_MPROTECT, addr as u64, len, prot) == 0
}

/// chrt(pid, class): set scheduler class — SCHED_OTHER=0, SCHED_RT=1.
pub fn chrt(pid: u32, class: u64) -> bool {
    sc2(shared::SYS_CHRT, pid as u64, class) == 0
}

/// Kernel shm registry dump ("id owner size refs" per line) for `ipcs -m`.
pub fn ipcs() -> String {
    let mut buf = [0u8; 4096];
    let n = sc2(
        shared::SYS_IPCS,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ) as usize;
    String::from_utf8_lossy(&buf[..n.min(4096)]).into_owned()
}
/// Enumerate PCI functions into `buf` (kernel SYS_PCI_SCAN). Returns count.
pub fn pci_scan(buf: &mut [shared::PciEnt]) -> usize {
    sc2(
        shared::SYS_PCI_SCAN,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ) as usize
}

pub fn meminfo() -> shared::MemInfo {
    let mut mi = shared::MemInfo::default();
    sc1(shared::SYS_MEMINFO, &mut mi as *mut _ as u64);
    mi
}
pub fn proclist(max: usize) -> Vec<shared::ProcInfo> {
    let mut buf = alloc::vec![shared::ProcInfo::default(); max];
    let n = sc2(shared::SYS_PROCLIST, buf.as_mut_ptr() as u64, max as u64);
    buf.truncate(if is_err(n) { 0 } else { n as usize });
    buf
}
pub fn fb_info() -> Option<shared::FbInfo> {
    let mut f = shared::FbInfo::default();
    let r = sc1(shared::SYS_FB_INFO, &mut f as *mut _ as u64);
    if is_err(r) {
        None
    } else {
        Some(f)
    }
}
pub fn datetime() -> shared::DateTime {
    let mut dt = shared::DateTime::default();
    sc1(shared::SYS_TIME, &mut dt as *mut _ as u64);
    dt
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------
pub const O_RDONLY: u64 = shared::O_RDONLY;
pub const O_WRONLY: u64 = shared::O_WRONLY;
pub const O_RDWR: u64 = shared::O_RDWR;
pub const O_CREATE: u64 = shared::O_CREATE;
pub const O_TRUNC: u64 = shared::O_TRUNC;
pub const O_APPEND: u64 = shared::O_APPEND;

pub fn open(path: &str, flags: u64) -> Result<i64, i64> {
    let fd = sc3(shared::SYS_OPEN, path.as_ptr() as u64, path.len() as u64, flags);
    if is_err(fd) {
        Err(fd as i64)
    } else {
        Ok(fd as i64)
    }
}
pub fn close(fd: i64) {
    sc1(shared::SYS_CLOSE, fd as u64);
}
pub fn read(fd: i64, buf: &mut [u8]) -> Result<usize, i64> {
    let n = sc3(shared::SYS_READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
    if is_err(n) {
        Err(n as i64)
    } else {
        Ok(n as usize)
    }
}
pub fn write(fd: i64, buf: &[u8]) -> Result<usize, i64> {
    let n = sc3(shared::SYS_WRITE, fd as u64, buf.as_ptr() as u64, buf.len() as u64);
    if is_err(n) {
        Err(n as i64)
    } else {
        Ok(n as usize)
    }
}
pub fn seek(fd: i64, off: u64, whence: u64) -> Result<u64, i64> {
    let p = sc3(shared::SYS_SEEK, fd as u64, off, whence);
    if is_err(p) {
        Err(p as i64)
    } else {
        Ok(p)
    }
}
pub fn stat(path: &str) -> Result<shared::Stat, i64> {
    let mut st = shared::Stat::default();
    let r = sc3(shared::SYS_STAT, path.as_ptr() as u64, path.len() as u64, &mut st as *mut _ as u64);
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(st)
    }
}
pub fn readdir(path: &str) -> Result<Vec<shared::DirEntry>, i64> {
    let mut buf = alloc::vec![shared::DirEntry::default(); shared::DIR_ENTRY_MAX];
    let n = sc4(
        shared::SYS_READDIR,
        path.as_ptr() as u64,
        path.len() as u64,
        buf.as_mut_ptr() as u64,
        shared::DIR_ENTRY_MAX as u64,
    );
    if is_err(n) {
        Err(n as i64)
    } else {
        buf.truncate(n as usize);
        Ok(buf)
    }
}
/// Set a file's modify time (unix seconds) via SYS_UTIME.
pub fn utime(path: &str, secs: u64) -> Result<(), i64> {
    let r = sc3(
        shared::SYS_UTIME,
        path.as_ptr() as u64,
        path.len() as u64,
        secs,
    );
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(())
    }
}
/// Set the user-settable FAT attribute bits (0x01 ro, 0x02 hidden, 0x04 sys).
pub fn setattr(path: &str, attr: u8) -> Result<(), i64> {
    let r = sc3(
        shared::SYS_SETATTR,
        path.as_ptr() as u64,
        path.len() as u64,
        attr as u64,
    );
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(())
    }
}
/// Set the system wall clock to unix `secs` (writes the RTC too).
pub fn set_time(secs: u64) {
    sc1(shared::SYS_RTC_SET, secs);
}

/// Set (mask != u64::MAX) and/or query the per-task file-creation umask;
/// returns the previous mask.
pub fn umask(mask: u64) -> u64 {
    sc1(shared::SYS_UMASK, mask)
}

/// Clear the kernel log ring (`dmesg -c`).
pub fn klog_clear() {
    sc0(shared::SYS_KLOG_CLEAR);
}

/// Create a named pipe at `path` (absolute). 0 | <0 (EEXIST=-5).
/// Raw symlink target, or None when `path` isn't a symlink.
pub fn readlink(path: &str) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = sc4(
        shared::SYS_READLINK,
        path.as_ptr() as u64,
        path.len() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ) as i64;
    if n < 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

pub fn mkfifo(path: &str) -> i64 {
    sc2(shared::SYS_MKFIFO, path.as_ptr() as u64, path.len() as u64) as i64
}

pub const LOCK_SH: u64 = shared::LOCK_SH;
pub const LOCK_EX: u64 = shared::LOCK_EX;
pub const LOCK_NB: u64 = shared::LOCK_NB;
pub const LOCK_UN: u64 = shared::LOCK_UN;

/// Advisory file lock: LOCK_SH|LOCK_EX (+LOCK_NB) acquires, LOCK_UN releases.
/// 0 | -35 EWOULDBLOCK | <0. Held locks drop when this task exits.
pub fn flock(path: &str, op: u64) -> i64 {
    sc3(
        shared::SYS_FLOCK,
        path.as_ptr() as u64,
        path.len() as u64,
        op,
    ) as i64
}
pub fn mkdir(path: &str) -> Result<(), i64> {
    let r = sc2(shared::SYS_MKDIR, path.as_ptr() as u64, path.len() as u64);
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(())
    }
}
pub fn remove(path: &str) -> Result<(), i64> {
    let r = sc2(shared::SYS_REMOVE, path.as_ptr() as u64, path.len() as u64);
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(())
    }
}
pub fn rename(from: &str, to: &str) -> Result<(), i64> {
    let r = sc4(
        shared::SYS_RENAME,
        from.as_ptr() as u64,
        from.len() as u64,
        to.as_ptr() as u64,
        to.len() as u64,
    );
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(())
    }
}
pub fn chdir(path: &str) -> bool {
    sc2(shared::SYS_CHDIR, path.as_ptr() as u64, path.len() as u64) == 0
}
pub fn getcwd() -> String {
    let mut buf = [0u8; 256];
    let n = sc2(shared::SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64);
    if is_err(n) {
        String::from("/")
    } else {
        String::from_utf8_lossy(&buf[..n as usize]).into_owned()
    }
}
/// Read an entire file into memory.
pub fn read_all(path: &str) -> Result<Vec<u8>, i64> {
    let fd = open(path, O_RDONLY)?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) => {
                close(fd);
                return Err(e);
            }
        }
    }
    close(fd);
    Ok(out)
}
/// Write an entire file (create+truncate).
pub fn write_all(path: &str, data: &[u8]) -> Result<(), i64> {
    let fd = open(path, O_WRONLY | O_CREATE | O_TRUNC)?;
    let mut off = 0;
    while off < data.len() {
        match write(fd, &data[off..]) {
            Ok(0) => {
                close(fd);
                return Err(-5);
            }
            Ok(n) => off += n,
            Err(e) => {
                close(fd);
                return Err(e);
            }
        }
    }
    close(fd);
    Ok(())
}

// ---------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------
pub fn ipc_listen(name: &str) -> u32 {
    sc2(shared::SYS_IPC_LISTEN, name.as_ptr() as u64, name.len() as u64) as u32
}
pub fn ipc_connect(name: &str) -> Option<u32> {
    let p = sc2(shared::SYS_IPC_CONNECT, name.as_ptr() as u64, name.len() as u64);
    if is_err(p) {
        None
    } else {
        Some(p as u32)
    }
}
pub fn ipc_send(port: u32, bytes: &[u8]) -> Result<(), i64> {
    let r = sc3(shared::SYS_IPC_SEND, port as u64, bytes.as_ptr() as u64, bytes.len() as u64);
    if is_err(r) {
        Err(r as i64)
    } else {
        Ok(())
    }
}
/// Returns bytes read, 0 on timeout.
pub fn ipc_recv(port: u32, buf: &mut [u8], timeout_ms: u64) -> Result<usize, i64> {
    let n = sc4(shared::SYS_IPC_RECV, port as u64, buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ms);
    if is_err(n) {
        Err(n as i64)
    } else {
        Ok(n as usize)
    }
}
pub fn ipc_close(port: u32) {
    sc1(shared::SYS_IPC_CLOSE, port as u64);
}
/// Owning task of a port, 0 if the port is gone (owner died or closed it).
pub fn ipc_owner(port: u32) -> u32 {
    sc1(shared::SYS_IPC_OWNER, port as u64) as u32
}

// ---------------------------------------------------------------------------
// shm
// ---------------------------------------------------------------------------
pub fn shm_create(size: usize) -> Option<u32> {
    let id = sc1(shared::SYS_SHM_CREATE, size as u64);
    if is_err(id) {
        None
    } else {
        Some(id as u32)
    }
}
/// Map shm into this process's address space. Returns (ptr, bytes).
pub fn shm_map(id: u32) -> Option<*mut u8> {
    let p = sc1(shared::SYS_SHM_MAP, id as u64);
    if p == 0 || is_err(p) {
        None
    } else {
        Some(p as *mut u8)
    }
}
pub fn shm_drop(id: u32) {
    sc1(shared::SYS_SHM_DROP, id as u64);
}

// ---------------------------------------------------------------------------
// printing (serial debug console)
// ---------------------------------------------------------------------------
pub fn debug_write(bytes: &[u8]) {
    sc2(shared::SYS_DEBUG, bytes.as_ptr() as u64, bytes.len() as u64);
}

pub struct Dbg;
impl fmt::Write for Dbg {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        debug_write(s.as_bytes());
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::Dbg.write_fmt(format_args!($($arg)*));
    }};
}
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// entry + heap + panic
// ---------------------------------------------------------------------------
#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

pub fn heap_init() {
    const HEAP_SIZE: usize = 24 * 1024 * 1024;
    let base = mmap(HEAP_SIZE as u64).expect("heap mmap");
    unsafe { HEAP.lock().init(base, HEAP_SIZE) };
}

/// User entry: kernel passes args_ptr in rdi, args_len in rsi.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(args_ptr: u64, args_len: u64) -> ! {
    heap_init();
    let code = entry(args_ptr, args_len);
    exit(code)
}

/// Weakly-linked per-app entry point: each bin crate defines `user_main`.
fn entry(args_ptr: u64, args_len: u64) -> i64 {
    extern "C" {
        fn user_main(args_ptr: u64, args_len: u64) -> i64;
    }
    unsafe { user_main(args_ptr, args_len) }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("app panic: {}", info);
    exit(-101)
}

/// RFC 1321 MD5 — real digest, integer-only.
pub fn md5(data: &[u8] ) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}


/// RFC 3174 SHA-1.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    let mut h = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), K[0]),
                1 => (b ^ c ^ d, K[1]),
                2 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}


/// (op,pid,buf,cap): op 0 start syscall tracing pid, 1 stop, 2 drain
/// packed records (7 LE u64s: nr,a1..a5,ret) into buf. Returns 0 | n | <0.
pub fn strace(op: u64, pid: u32, out: &mut [u8]) -> i64 {
    sc4(
        shared::SYS_STRACE,
        op,
        pid as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    ) as i64
}

/// (pid, sig): POSIX-lite signal — 9/15 kill, 19 STOP, 18 CONT. 0 | <0.
pub fn kill2(pid: u32, sig: u64) -> i64 {
    sc2(shared::SYS_KILL2, pid as u64, sig) as i64
}

/// Kernel nodename (uname -n / hostname).
pub fn hostname() -> String {
    let mut buf = [0u8; 64];
    let n = sc2(
        shared::SYS_HOSTNAME_GET,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ) as usize;
    if n == usize::MAX {
        return String::from("cosmos");
    }
    String::from_utf8_lossy(&buf[..n.min(64)]).into_owned()
}

/// Delete an ARP cache entry (`arp -d <ip>`). Returns true when one existed.
pub fn arp_delete(ip: [u8; 4]) -> bool {
    let v = ((ip[0] as u64) << 24) | ((ip[1] as u64) << 16) | ((ip[2] as u64) << 8) | ip[3] as u64;
    sc1(shared::SYS_ARP_DEL, v) == 1
}

/// Set the kernel nodename. Returns true on success.
pub fn set_hostname(s: &str) -> bool {
    sc2(
        shared::SYS_HOSTNAME_SET,
        s.as_ptr() as u64,
        s.len().min(64) as u64,
    ) == 0
}

/// Anonymous pipe: returns (read_fd, write_fd), or None on failure.
pub fn pipe() -> Option<(i64, i64)> {
    let v = sc0(shared::SYS_PIPE);
    if v == u64::MAX {
        return None;
    }
    Some(((v & 0xffff_ffff) as i64, (v >> 32) as i64))
}

/// Clone `oldfd` into slot `newfd` (POSIX dup2). Returns newfd or -1.
pub fn dup2(oldfd: u64, newfd: u64) -> i64 {
    sc2(shared::SYS_DUP2, oldfd, newfd) as i64
}

/// Wait until any of `fds`/`evs` is ready or `timeout_ms` passes
/// (u64::MAX = forever). evs bits: 1=read, 2=write. Returns count ready.
pub fn poll(fds: &[u32], evs: &[u32], timeout_ms: u64) -> i64 {
    sc4(
        shared::SYS_POLL,
        fds.as_ptr() as u64,
        evs.as_ptr() as u64,
        fds.len() as u64,
        timeout_ms,
    ) as i64
}

/// Per-task resource usage: (cpu_ticks, maxrss_kib). None = no such pid.
pub fn rusage(pid: u32) -> Option<(u64, u64)> {
    let mut out = [0u64; 3];
    if sc2(shared::SYS_RUSAGE, pid as u64, out.as_mut_ptr() as u64) != 0 {
        return None;
    }
    // the kernel wrote through the raw ptr — force a real reload
    let out = unsafe { core::ptr::read_volatile(&out) };
    Some((out[0], out[2]))
}

/// fsync(2): commit `fd`'s file to stable storage. 0 | ERR. Writes are
/// already synchronous per-sector, so this confirms what always holds —
/// but it's a real device round-trip (VIRTIO_BLK_T_FLUSH), not a stub.
pub fn fsync(fd: i64) -> i64 {
    sc1(shared::SYS_FSYNC, fd as u64) as i64
}

/// sync(2): commit the whole volume. 0 | ERR (no disk attached).
pub fn sync_all() -> i64 {
    sc1(shared::SYS_FSYNC, u64::MAX) as i64
}

/// inotify_init: an fd whose reads yield "{wd} {mask} {name}\n" records.
pub fn inotify_init() -> i64 {
    sc0(shared::SYS_INOTIFY_INIT) as i64
}

/// inotify_add_watch(fd, path, mask) -> wd | <0
pub fn inotify_add(fd: i64, path: &str, mask: u64) -> i64 {
    sc4(
        shared::SYS_INOTIFY_ADD,
        fd as u64,
        path.as_ptr() as u64,
        path.len() as u64,
        mask,
    ) as i64
}

/// inotify_rm_watch
pub fn inotify_rm(fd: i64, wd: u64) -> i64 {
    sc2(shared::SYS_INOTIFY_RM, fd as u64, wd) as i64
}

// inotify mask bits (subset of Linux's)
pub const IN_ACCESS: u64 = 0x1;
pub const IN_MODIFY: u64 = 0x2;
pub const IN_ATTRIB: u64 = 0x4;
pub const IN_CLOSE_WRITE: u64 = 0x8;
pub const IN_MOVED_FROM: u64 = 0x40;
pub const IN_MOVED_TO: u64 = 0x80;
pub const IN_CREATE: u64 = 0x100;
pub const IN_DELETE: u64 = 0x200;
pub const IN_DELETE_SELF: u64 = 0x400;
pub const IN_MOVE_SELF: u64 = 0x800;
pub const IN_ISDIR: u64 = 0x4000_0000;
pub const IN_Q_OVERFLOW: u64 = 0x8000;
pub const IN_ALL: u64 = 0x0fff;

/// timerfd_create: an fd that becomes readable when the armed timer fires;
/// read yields an 8-byte LE expiration count.
pub fn timerfd_create() -> i64 {
    sc0(shared::SYS_TIMERFD) as i64
}

/// timerfd_settime(fd, init_ms, interval_ms): arm (init>0) or disarm.
/// interval_ms>0 re-arms periodically. 0 | ERR.
pub fn timerfd_set(fd: i64, init_ms: u64, interval_ms: u64) -> i64 {
    sc3(shared::SYS_TFD_SET, fd as u64, init_ms, interval_ms) as i64
}

/// Read a timerfd's expiration count (drains it). 0 = no expiry yet.
pub fn timerfd_read(fd: i64) -> Option<u64> {
    let mut b = [0u8; 8];
    match read(fd, &mut b) {
        Ok(8) => Some(u64::from_le_bytes(b)),
        _ => None,
    }
}

/// eventfd: semaphore mode returns 1 per read and decrements instead of
/// draining the whole counter.
pub const EFD_SEMAPHORE: u64 = 0x1;

/// eventfd(initval, flags): an fd wrapping a u64 kernel counter.
/// write() adds a u64; read() returns and drains it (or decrements in sem
/// mode). Empty read / overflowing write block.
pub fn eventfd(initval: u64, flags: u64) -> i64 {
    sc2(shared::SYS_EVENTFD, initval, flags) as i64
}

/// add `v` to an eventfd counter. 8 | ERR
pub fn eventfd_write(fd: i64, v: u64) -> i64 {
    match write(fd, &v.to_le_bytes()) {
        Ok(8) => 0,
        Ok(_) => -5,
        Err(e) => e,
    }
}

/// drain an eventfd counter (nonsem) or take one unit (sem mode).
/// Blocks while the counter is zero — poll() first to check.
pub fn eventfd_read(fd: i64) -> Option<u64> {
    let mut b = [0u8; 8];
    match read(fd, &mut b) {
        Ok(8) => Some(u64::from_le_bytes(b)),
        _ => None,
    }
}

pub const EPOLL_CTL_ADD: u64 = 1;
pub const EPOLL_CTL_DEL: u64 = 2;
pub const EPOLL_CTL_MOD: u64 = 3;
pub const EPOLLIN: u64 = 0x1;
pub const EPOLLOUT: u64 = 0x2;

/// epoll_create: an fd owning a kernel interest set.
pub fn epoll_create() -> i64 {
    sc0(shared::SYS_EPOLL_CREATE) as i64
}

/// epoll_ctl(epfd, op, fd, events): register/del/modify an fd's interest.
/// events = EPOLLIN|EPOLLOUT bits. 0 | ERR
pub fn epoll_ctl(epfd: i64, op: u64, fd: i64, events: u64) -> i64 {
    sc4(
        shared::SYS_EPOLL_CTL,
        epfd as u64,
        op,
        fd as u64,
        events,
    ) as i64
}

/// epoll_wait(epfd, out, timeout_ms): fills `out` with (fd, revents) pairs
/// for ready interests; returns how many were written. Blocks until one
/// fires or the timeout elapses (u64::MAX = forever).
pub fn epoll_wait(epfd: i64, out: &mut [(u32, u32)], timeout_ms: u64) -> i64 {
    sc4(
        shared::SYS_EPOLL_WAIT,
        epfd as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
        timeout_ms,
    ) as i64
}

/// socketpair: bidirectional connected fds (AF_UNIX SOCK_STREAM semantics).
/// Returns (fdA, fdB); bytes written to one are read from the other.
pub fn socketpair() -> Option<(i64, i64)> {
    socketpair_t(SOCK_STREAM)
}
/// socketpair_t(ty): SOCK_STREAM pair (sockpair object) or SOCK_DGRAM
/// pair (two cross-linked AF_UNIX mailboxes).
pub fn socketpair_t(ty: u64) -> Option<(i64, i64)> {
    let v = sc1(shared::SYS_SOCKETPAIR, ty);
    if v == u64::MAX {
        return None;
    }
    Some(((v & 0xffff_ffff) as i64, (v >> 32) as i64))
}

/// pidfd_create: an fd that becomes readable when `pid` exits; reading it
/// yields the 8-byte exit status. -1 if the task is absent/already dead.
/// ppoll: poll under a temporary signal mask (mask = u64::MAX = no swap).
pub fn ppoll(fds: &[u32], evs: &[u32], timeout_ms: u64, mask: u64) -> i64 {
    sc5(
        shared::SYS_PPOLL,
        fds.as_ptr() as u64,
        evs.as_ptr() as u64,
        fds.len() as u64,
        timeout_ms,
        mask,
    ) as i64
}

/// splice: move up to `len` bytes in_fd -> out_fd through a pipe end.
pub fn splice(in_fd: i32, out_fd: i32, len: usize) -> i64 {
    sc3(shared::SYS_SPLICE, in_fd as u64, out_fd as u64, len as u64) as i64
}

/// process_vm_readv: copy `buf.len()` bytes from `pid`'s memory at `addr`.
pub fn process_vm_readv(pid: u32, addr: u64, buf: &mut [u8]) -> i64 {
    sc5(
        shared::SYS_PROCESS_VM,
        pid as u64,
        addr,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    ) as i64
}

/// process_vm_writev: write `buf` into `pid`'s memory at `addr`.
pub fn process_vm_writev(pid: u32, addr: u64, buf: &[u8]) -> i64 {
    sc5(
        shared::SYS_PROCESS_VM,
        pid as u64,
        addr,
        buf.as_ptr() as u64,
        buf.len() as u64,
        1,
    ) as i64
}

/// sysinfo: (uptime_sec, totalram_kb, freeram_kb, procs)
pub fn sysinfo() -> Option<(u64, u64, u64, u64)> {
    let mut out = [0u64; 4];
    if sc1(shared::SYS_SYSINFO, out.as_mut_ptr() as u64) != 0 {
        return None;
    }
    let out = unsafe { core::ptr::read_volatile(&out) };
    Some((out[0], out[1], out[2], out[3]))
}

/// close_range: close every fd in [first, last].
pub fn close_range(first: u32, last: u32) -> i64 {
    sc2(shared::SYS_CLOSE_RANGE, first as u64, last as u64) as i64
}

/// pidfd_send_signal: send `sig` to the task behind `pidfd` (0 = probe).
pub fn pidfd_send_signal(pidfd: i32, sig: u64) -> i64 {
    sc2(shared::SYS_PIDFD_SIGNAL, pidfd as u64, sig) as i64
}

pub fn pidfd(pid: u32) -> i64 {
    sc1(shared::SYS_PIDFD, pid as u64) as i64
}

/// Read a pidfd's 8-byte exit status (poll() first — blocks while alive).
pub fn pidfd_read(fd: i64) -> Option<i64> {
    let mut b = [0u8; 8];
    match read(fd, &mut b) {
        Ok(8) => Some(i64::from_le_bytes(b)),
        _ => None,
    }
}

pub const F_DUPFD: u64 = shared::F_DUPFD;
pub const F_GETFL: u64 = shared::F_GETFL;
pub const F_SETFL: u64 = shared::F_SETFL;
pub const O_NONBLOCK: u64 = shared::O_NONBLOCK;

/// fcntl(fd, cmd, arg): F_DUPFD (dup into first slot >= arg, shared pos),
/// F_GETFL (fd status flags), F_SETFL (set O_APPEND|O_NONBLOCK bits).
pub fn fcntl(fd: i64, cmd: u64, arg: u64) -> i64 {
    sc3(shared::SYS_FCNTL, fd as u64, cmd, arg) as i64
}

/// fstat: stat through a descriptor (real files, pseudo-fs and object fds).
pub fn fstat(fd: i64) -> Option<shared::Stat> {
    let mut st = shared::Stat { size: 0, is_dir: 0, mtime: 0, attr: 0 };
    match sc2(shared::SYS_FSTAT, fd as u64, &mut st as *mut _ as u64) {
        0 => Some(st),
        _ => None,
    }
}

/// ftruncate: resize the file behind `fd` to `len` (pad/cut). 0 | ERR
pub fn ftruncate(fd: i64, len: u64) -> i64 {
    sc2(shared::SYS_FTRUNCATE, fd as u64, len) as i64
}

/// sendfile: kernel-side copy from `inf` to `outf` (no userspace bounce).
/// `off`: Some(offset) reads from that file offset and updates it (POSIX),
/// leaving the fd position untouched. Returns bytes copied (may be short).
pub fn sendfile(outf: i64, inf: i64, off: Option<&mut u64>, count: u64) -> i64 {
    let p = off.map(|o| o as *mut u64 as u64).unwrap_or(0);
    sc4(shared::SYS_SENDFILE, outf as u64, inf as u64, p, count) as i64
}

/// Copy `inf` to `outf` entirely through sendfile (loops on short writes).
pub fn sendfile_all(outf: i64, inf: i64, count: u64) -> i64 {
    let mut done = 0u64;
    while done < count {
        match sendfile(outf, inf, None, count - done) {
            0 => break,                 // EOF
            e if e < 0 && e != -11 => return e,
            -11 => break,               // EAGAIN: caller may poll+retry
            n => done += n as u64,
        }
        if done >= count {
            break;
        }
    }
    done as i64
}

/// readv/writev: scatter/gather I/O over (ptr,len) pairs.
pub fn readv(fd: i64, iovs: &mut [(*mut u8, usize)]) -> i64 {
    let flat: Vec<u64> = iovs.iter().flat_map(|(p, l)| [*p as u64, *l as u64]).collect();
    sc3(shared::SYS_READV, fd as u64, flat.as_ptr() as u64, iovs.len() as u64) as i64
}
pub fn writev(fd: i64, iovs: &[(*const u8, usize)]) -> i64 {
    let flat: Vec<u64> = iovs.iter().flat_map(|(p, l)| [*p as u64, *l as u64]).collect();
    sc3(shared::SYS_WRITEV, fd as u64, flat.as_ptr() as u64, iovs.len() as u64) as i64
}

pub const SOCK_STREAM: u64 = shared::SOCK_STREAM;
pub const SOCK_DGRAM: u64 = shared::SOCK_DGRAM;

/// socket(type) -> real fd bound to a kernel socket object (/socket/{id}).
/// The fd works with read/write/poll/epoll/close like any other.
pub fn socket(stream_type: u64) -> i64 {
    sc2(shared::SYS_SOCKET, stream_type, shared::AF_INET) as i64
}
/// socket(type, domain): AF_INET (2) or AF_UNIX (1).
pub fn socketx(stream_type: u64, domain: u64) -> i64 {
    sc2(shared::SYS_SOCKET, stream_type, domain) as i64
}
pub fn bind(fd: i64, lport: u16) -> i64 {
    sc2(shared::SYS_BIND, fd as u64, lport as u64) as i64
}
/// Bind an AF_UNIX socket to a filesystem-style name ("/x.sock").
pub fn bind_path(fd: i64, name: &str) -> i64 {
    sc3(
        shared::SYS_BIND,
        fd as u64,
        name.as_ptr() as u64,
        name.len() as u64,
    ) as i64
}
pub fn connect(fd: i64, ip: [u8; 4], port: u16) -> i64 {
    sc3(shared::SYS_CONNECT, fd as u64, u32::from_be_bytes(ip) as u64, port as u64) as i64
}
/// Connect an AF_UNIX socket to a bound+listening name.
pub fn connect_path(fd: i64, name: &str) -> i64 {
    sc3(
        shared::SYS_CONNECT,
        fd as u64,
        name.as_ptr() as u64,
        name.len() as u64,
    ) as i64
}
/// shutdown(fd, how): 0=read side (EOF), 1=write side (FIN to the peer),
/// 2=both. Real half-close — the peer sees EOF after its buffer drains.
pub fn shutdown(fd: i64, how: u64) -> i64 {
    sc2(shared::SYS_SHUTDOWN, fd as u64, how) as i64
}
/// getsockname -> raw sockaddr-lite: [fam u16le][inet: ip4|port2be] or
/// [unix: name bytes + NUL]. Returns bytes written.
pub fn getsockname(fd: i64, out: &mut [u8]) -> Result<usize, i64> {
    let r = sc3(
        shared::SYS_GETSOCKNAME,
        fd as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    ) as i64;
    if r < 0 {
        Err(r)
    } else {
        Ok(r as usize)
    }
}
pub fn getpeername(fd: i64, out: &mut [u8]) -> Result<usize, i64> {
    let r = sc3(
        shared::SYS_GETPEERNAME,
        fd as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    ) as i64;
    if r < 0 {
        Err(r)
    } else {
        Ok(r as usize)
    }
}
pub fn listen(fd: i64, backlog: u64) -> i64 {
    sc2(shared::SYS_LISTEN, fd as u64, backlog) as i64
}
/// accept -> (connfd, peer ip, peer port); peer fields are zeroed when
/// peer_out isn't wanted... here always returned (kernel writes [ip4|port2]).
pub fn accept(fd: i64) -> Result<(i64, [u8; 4], u16), i64> {
    let mut peer = [0u8; 8];
    let r = sc2(shared::SYS_ACCEPT, fd as u64, peer.as_mut_ptr() as u64) as i64;
    if r < 0 {
        return Err(r);
    }
    Ok((
        r,
        [peer[0], peer[1], peer[2], peer[3]],
        u16::from_be_bytes([peer[4], peer[5]]),
    ))
}
/// sendto: UDP datagram to an explicit peer; TCP ignores the address.
pub fn sendto(fd: i64, data: &[u8], ip: [u8; 4], port: u16) -> i64 {
    sc5(
        shared::SYS_SENDTO,
        fd as u64,
        data.as_ptr() as u64,
        data.len() as u64,
        u32::from_be_bytes(ip) as u64,
        port as u64,
    ) as i64
}
/// recvfrom: read + the sender's (ip,port) for datagram sockets.
pub fn recvfrom(fd: i64, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), i64> {
    recvfrom_flags(fd, buf, 0)
}
/// recvfrom with flags — flag bit0 = MSG_PEEK: the front datagram/stream
/// bytes are copied but NOT consumed (the next read gets them again).
pub fn recvfrom_flags(
    fd: i64,
    buf: &mut [u8],
    flags: u64,
) -> Result<(usize, [u8; 4], u16), i64> {
    let mut src = [0u8; 8];
    let r = sc5(
        shared::SYS_RECVFROM,
        fd as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        src.as_mut_ptr() as u64,
        flags,
    ) as i64;
    if r < 0 {
        return Err(r);
    }
    Ok((
        r as usize,
        [src[0], src[1], src[2], src[3]],
        u16::from_be_bytes([src[4], src[5]]),
    ))
}
pub const MSG_PEEK: u64 = 1;
/// sendmsg: stream write that can carry one fd to the peer (SCM_RIGHTS,
/// AF_UNIX only). Pass -1 as `pass` for no ancillary data.
pub fn sendmsg(fd: i64, data: &[u8], pass: i64) -> i64 {
    sc4(
        shared::SYS_SENDMSG,
        fd as u64,
        data.as_ptr() as u64,
        data.len() as u64,
        pass as u64,
    ) as i64
}
/// recvmsg: read + the fd the peer sent us, if any (Some(fd) — adopt it
/// like any other fd: read/write/close work on it).
pub fn recvmsg(fd: i64, buf: &mut [u8]) -> Result<(usize, Option<i64>), i64> {
    let mut out: i64 = -1;
    let r = sc4(
        shared::SYS_RECVMSG,
        fd as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        &mut out as *mut i64 as u64,
    ) as i64;
    if r < 0 {
        return Err(r);
    }
    Ok((r as usize, if out >= 0 { Some(out) } else { None }))
}
/// sendto_path: AF_UNIX datagram send to a bound path name. An unbound
/// socket auto-binds `/tmp/udg-{id}` first (like Linux autobind).
pub fn sendto_path(fd: i64, name: &str, data: &[u8]) -> i64 {
    sc5(
        shared::SYS_SENDTO_PATH,
        fd as u64,
        data.as_ptr() as u64,
        data.len() as u64,
        name.as_ptr() as u64,
        name.len() as u64,
    ) as i64
}
/// recvfrom_path: pop one AF_UNIX datagram + the sender's path name.
pub fn recvfrom_path(
    fd: i64,
    buf: &mut [u8],
    name_out: &mut [u8],
) -> Result<(usize, usize), i64> {
    let r = sc5(
        shared::SYS_RECVFROM_PATH,
        fd as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        name_out.as_mut_ptr() as u64,
        name_out.len() as u64,
    ) as i64;
    if r < 0 {
        return Err(r);
    }
    // kernel writes the sender name NUL-terminated
    let nl = name_out.iter().position(|&c| c == 0).unwrap_or(name_out.len());
    Ok((r as usize, nl))
}
/// getsockopt: SOL_SOCKET queries (SO_TYPE/SO_DOMAIN/SO_ACCEPTCONN/
/// SO_SNDBUF/SO_RCVBUF/SO_ERROR). Returns the option value.
pub fn getsockopt(fd: i64, level: u64, opt: u64) -> Result<u32, i64> {
    let mut out = [0u8; 4];
    let r = sc5(
        shared::SYS_GETSOCKOPT,
        fd as u64,
        level,
        opt,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    ) as i64;
    if r < 0 {
        return Err(r);
    }
    Ok(u32::from_le_bytes(out))
}
/// setsockopt: SOL_SOCKET (1) — SO_REUSEADDR (2) relaxes the bind
/// port-in-use rule; SO_BROADCAST (6) permits sends to bcast dsts.
pub fn setsockopt(fd: i64, level: u64, opt: u64, val: u64) -> i64 {
    sc4(
        shared::SYS_SETSOCKOPT,
        fd as u64,
        level,
        opt,
        val,
    ) as i64
}
/// One traceroute hop: (ttl, Some((hop_ip, rtt_ms)) when an ICMP error
/// answered, reached=true when the target's own 3/3 arrived).
pub fn net_trace(
    ip: u32,
    max_hops: u8,
) -> alloc::vec::Vec<(u8, Option<([u8; 4], u64)>, bool)> {
    let mut buf = [0u8; 16 * 30];
    let n = sc4(
        shared::SYS_NET_TRACE,
        ip as u64,
        max_hops as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    );
    let mut out = alloc::vec::Vec::new();
    if n == u64::MAX {
        return out;
    }
    for e in buf[..(n as usize).min(buf.len())].chunks_exact(16) {
        let ttl = e[0];
        let got = e[1] & 1 != 0;
        let reached = e[1] & 2 != 0;
        let ip: [u8; 4] = e[4..8].try_into().unwrap_or([0; 4]);
        let ms = u64::from_be_bytes(e[8..16].try_into().unwrap_or([0; 8]));
        out.push((ttl, if got { Some((ip, ms)) } else { None }, reached));
    }
    out
}

/// fd-based TCP socket — poll/read/write/close all work on it.
pub struct TcpFd(pub i64);
impl TcpFd {
    pub fn connect(ip: [u8; 4], port: u16) -> Result<Self, i64> {
        let fd = socket(SOCK_STREAM);
        if fd < 0 {
            return Err(fd);
        }
        match connect(fd, ip, port) {
            0 => Ok(Self(fd)),
            e => {
                close(fd);
                Err(e)
            }
        }
    }
    pub fn listen(lport: u16) -> Result<Self, i64> {
        let fd = socket(SOCK_STREAM);
        if fd < 0 {
            return Err(fd);
        }
        if bind(fd, lport) != 0 {
            close(fd);
            return Err(-1);
        }
        if listen(fd, 4) != 0 {
            close(fd);
            return Err(-1);
        }
        Ok(Self(fd))
    }
    /// Blocking accept -> connected TcpFd + peer.
    pub fn accept(&self) -> Result<(Self, [u8; 4], u16), i64> {
        accept(self.0).map(|(fd, ip, p)| (Self(fd), ip, p))
    }
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        read(self.0, buf)
    }
    pub fn write(&self, data: &[u8]) -> Result<usize, i64> {
        write(self.0, data)
    }
}
impl Drop for TcpFd {
    fn drop(&mut self) {
        close(self.0);
    }
}

/// fd-based UDP socket — bind, then sendto/recvfrom or connect+read/write.
pub struct UdpFd(pub i64);
impl UdpFd {
    pub fn bind(lport: u16) -> Result<Self, i64> {
        let fd = socket(SOCK_DGRAM);
        if fd < 0 {
            return Err(fd);
        }
        match bind(fd, lport) {
            0 => Ok(Self(fd)),
            e => {
                close(fd);
                Err(e)
            }
        }
    }
    pub fn sendto(&self, data: &[u8], ip: [u8; 4], port: u16) -> i64 {
        sendto(self.0, data, ip, port)
    }
    pub fn recvfrom(&self, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), i64> {
        recvfrom(self.0, buf)
    }
    /// Set the default peer so plain read()/write() work.
    pub fn connect(&self, ip: [u8; 4], port: u16) -> i64 {
        connect(self.0, ip, port)
    }
}
impl Drop for UdpFd {
    fn drop(&mut self) {
        close(self.0);
    }
}

/// fd-based AF_UNIX stream socket — bind_path+listen+accept or connect_path,
/// then plain read/write/poll like any fd.
pub struct UnixFd(pub i64);
impl UnixFd {
    pub fn new() -> Result<Self, i64> {
        let fd = socketx(SOCK_STREAM, shared::AF_UNIX);
        if fd < 0 {
            Err(fd)
        } else {
            Ok(Self(fd))
        }
    }
    pub fn listen(path: &str) -> Result<Self, i64> {
        let fd = socketx(SOCK_STREAM, shared::AF_UNIX);
        if fd < 0 {
            return Err(fd);
        }
        if bind_path(fd, path) != 0 || listen(fd, 4) != 0 {
            close(fd);
            return Err(-1);
        }
        Ok(Self(fd))
    }
    pub fn connect(path: &str) -> Result<Self, i64> {
        let fd = socketx(SOCK_STREAM, shared::AF_UNIX);
        if fd < 0 {
            return Err(fd);
        }
        match connect_path(fd, path) {
            0 => Ok(Self(fd)),
            e => {
                close(fd);
                Err(e)
            }
        }
    }
    pub fn accept(&self) -> Result<Self, i64> {
        accept(self.0).map(|(fd, _, _)| Self(fd))
    }
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        read(self.0, buf)
    }
    pub fn write(&self, data: &[u8]) -> Result<usize, i64> {
        write(self.0, data)
    }
}
impl Drop for UnixFd {
    fn drop(&mut self) {
        close(self.0);
    }
}
