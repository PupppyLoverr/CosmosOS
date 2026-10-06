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
mod font16;
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
    let r = sc2(shared::SYS_WAITPID, pid as u64, timeout_ms);
    if is_err(r) {
        Err(())
    } else {
        Ok(r as i64)
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
    let p = sc1(shared::SYS_MMAP, size);
    if p == 0 || is_err(p) {
        None
    } else {
        Some(p as *mut u8)
    }
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
