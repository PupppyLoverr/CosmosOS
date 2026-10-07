//! CosmosOS shared ABI: syscall numbers, kernel<->userspace data types,
//! and the window-server wire protocol. Used by both the kernel and `ustd`.
#![no_std]
pub mod font16;

// ---------------------------------------------------------------------------
// Syscall numbers (int 0x80: nr=rax, args rdi,rsi,rdx,r8,r9; ret rax)
// ---------------------------------------------------------------------------
pub const SYS_EXIT: u64 = 0;
pub const SYS_YIELD: u64 = 1;
pub const SYS_SPAWN: u64 = 2; // (path_ptr,path_len,arg_ptr,arg_len) -> pid | !0
pub const SYS_SLEEP_MS: u64 = 3; // (ms)
pub const SYS_MMAP: u64 = 4; // (size) -> user ptr | 0
pub const SYS_DEBUG: u64 = 5; // (ptr,len) -> write bytes to kernel serial log

pub const SYS_OPEN: u64 = 10; // (path_ptr,path_len,flags) -> fd | !0
pub const SYS_CLOSE: u64 = 11; // (fd)
pub const SYS_READ: u64 = 12; // (fd,buf,len) -> n | !0
pub const SYS_WRITE: u64 = 13; // (fd,buf,len) -> n | !0
pub const SYS_SEEK: u64 = 14; // (fd,offset,whence) -> pos | !0
pub const SYS_STAT: u64 = 15; // (path_ptr,len,&mut Stat) -> 0 | !0
pub const SYS_READDIR: u64 = 16; // (path_ptr,len,&mut DirEntry buf,max) -> n | !0
pub const SYS_MKDIR: u64 = 17; // (path_ptr,len)
pub const SYS_REMOVE: u64 = 18; // (path_ptr,len, is_dir)
pub const SYS_RENAME: u64 = 19; // (old_ptr,old_len,new_ptr,new_len)

pub const SYS_SHM_CREATE: u64 = 20; // (size) -> shm id | !0
pub const SYS_SHM_MAP: u64 = 21; // (id) -> ptr | 0
pub const SYS_SHM_DROP: u64 = 22; // (id)

pub const SYS_IPC_LISTEN: u64 = 30; // (name_ptr,len) -> port | !0
pub const SYS_IPC_CONNECT: u64 = 31; // (name_ptr,len) -> port | !0
pub const SYS_IPC_SEND: u64 = 32; // (port,buf,len)
pub const SYS_IPC_RECV: u64 = 33; // (port,buf,buflen,timeout_ms) -> n | 0 timeout | !0
pub const SYS_IPC_CLOSE: u64 = 34; // (port)
pub const SYS_IPC_OWNER: u64 = 35; // (port) -> owner pid | 0

pub const SYS_MEMINFO: u64 = 40; // (&mut MemInfo)
pub const SYS_TIME: u64 = 41; // (&mut DateTime)
pub const SYS_UPTIME_MS: u64 = 42; // -> ms
pub const SYS_PROCLIST: u64 = 43; // (&mut ProcInfo buf, max) -> n
pub const SYS_POWEROFF: u64 = 44;
pub const SYS_REBOOT: u64 = 45;
pub const SYS_FB_INFO: u64 = 46; // (&mut FbInfo) -> 0 | !0 (first claim wins)
pub const SYS_CHDIR: u64 = 47; // (path_ptr,len)
pub const SYS_GETCWD: u64 = 48; // (buf,len) -> n
pub const SYS_WAITPID: u64 = 49; // (pid,timeout_ms) -> exit_code | ERR
pub const SYS_KILL: u64 = 50; // (pid) -> 0 | ERR
pub const SYS_NET_PING: u64 = 51; // (ip u32 BE-packed, timeout_ms) -> rtt_ms | ERR
pub const SYS_NET_INFO: u64 = 52; // (&mut [u8;10] {mac[6],ip[4]}) -> 0 | ERR
pub const SYS_NET_DNS: u64 = 53; // (name_ptr,len, out [u8;4]) -> 0 | ERR (real UDP/53)
pub const SYS_NET_HTTP: u64 = 54; // (host_ptr,len, out, outlen) -> n | ERR (real TCP/80 GET /)
pub const SYS_NET_UDP_OPEN: u64 = 55; // (lport) -> 0 | ERR (bind local port)
pub const SYS_NET_UDP_SEND: u64 = 56; // (lport, dst_ip u32 BE-packed, dport, ptr, len) -> 0 | ERR
pub const SYS_NET_UDP_RECV: u64 = 57; // (lport, buf, cap, timeout_ms) -> n | ERR; buf=[srcip:4][sport:2][payload]
pub const SYS_NET_UDP_CLOSE: u64 = 58; // (lport) -> 0
pub const SYS_NET_DHCP: u64 = 59;      // () -> assigned ip (u32 BE-packed) | ERR
pub const SYS_NET_TCP_OPEN: u64 = 60;  // (lport, ip u32, rport) -> 0 | ERR (SYN handshake)
pub const SYS_NET_TCP_SEND: u64 = 61;  // (lport, ptr, len<=1400) -> 0 | ERR (retransmit till acked)
pub const SYS_NET_TCP_RECV: u64 = 62;  // (lport, buf, cap, timeout_ms) -> n | ERR
pub const SYS_NET_TCP_CLOSE: u64 = 63; // (lport) -> 0 (FIN + drop)
pub const SYS_CLIP_SET: u64 = 64;      // (ptr,len) -> 0 | ERR  (kernel clipboard)
pub const SYS_CLIP_GET: u64 = 65;      // (buf,cap) -> n | ERR
pub const SYS_NET_STAT: u64 = 66;      // (buf,cap) -> n | ERR  (socket table dump)
pub const SYS_DF: u64 = 67;            // (ptr to [u64;2]) -> 0 | ERR  {total_bytes, free_bytes}
pub const SYS_KLOG: u64 = 68;          // (buf,cap) -> n | ERR  kernel log ring tail
pub const SYS_ARP: u64 = 69;           // (buf,cap) -> n | ERR  ARP cache dump
pub const SYS_NET_TCP_LISTEN: u64 = 70;   // (lport) -> 0 | ERR  mark port listening
pub const SYS_NET_TCP_ACCEPT: u64 = 71;   // (lport, ptr to 8B out, timeout) -> cid | ERR
pub const SYS_NET_TCP_UNLISTEN: u64 = 72; // (lport) -> 0
pub const SYS_SHOT: u64 = 73;             // (path_ptr,path_len) -> 0 | ERR  fb -> PPM file
pub const SYS_RAND: u64 = 74;             // (buf,cap<=4096) -> n | ERR  hardware/seeded random bytes
pub const SYS_PCI_SCAN: u64 = 75;         // (&mut PciEnt buf, max) -> n | ERR
pub const SYS_BEEP: u64 = 76;             // (freq_hz, ms) -> 0  PC speaker via PIT ch2 + port 0x61

pub const SYS_GETPID: u64 = 77;           // () -> pid
pub const SYS_NICE: u64 = 78;             // (pid, nice) -> stored nice | -3
pub const SYS_PCAP: u64 = 79;             // (op, buf, cap) -> varies (see pcap.rs)
pub const SYS_STRACE: u64 = 80;           // (op,pid,buf,cap): 0 start 1 stop 2 drain
pub const SYS_KILL2: u64 = 81;            // (pid,sig): 9/15 kill, 19 STOP, 18 CONT -> 0 | ERR
pub const SYS_HOSTNAME_GET: u64 = 82;      // (buf,cap) -> n | ERR
pub const SYS_HOSTNAME_SET: u64 = 83;      // (ptr,len<=64) -> 0 | ERR
pub const SYS_ARP_DEL: u64 = 84;           // (ip as u32 BE) -> 1 deleted | 0 absent
pub const SYS_UTIME: u64 = 85;             // (path_ptr,len,secs) -> 0 | ERR  set file mtime
pub const SYS_SETATTR: u64 = 86;           // (path_ptr,len,attr) -> 0 | ERR  set FAT attr bits
pub const SYS_RTC_SET: u64 = 87;           // (unix_secs) -> 0            set wall clock (RTC + base)
pub const SYS_UMASK: u64 = 88;             // (mask|U64MAX=query) -> old   per-task file-create mask
pub const SYS_KLOG_CLEAR: u64 = 89;        // () -> 0                      clear the kernel log ring
pub const SYS_MKFIFO: u64 = 90;            // (path_ptr,len) -> 0 | ERR    create named pipe (mkfifo)
pub const SYS_READLINK: u64 = 91;          // (path_ptr,len,out,cap) -> len | ERR raw symlink target
pub const SYS_FLOCK: u64 = 92;             // (path_ptr,len,op) -> 0 | ERR  advisory file lock (LOCK_SH|EX|NB|UN)

// SYS_FLOCK op bits
pub const LOCK_SH: u64 = 1;
pub const LOCK_EX: u64 = 2;
pub const LOCK_NB: u64 = 4;
pub const LOCK_UN: u64 = 8;
pub const SYS_MUNMAP: u64 = 93;          // (addr,len) -> 0 | ERR   unmap tracked user mappings
pub const SYS_MPROTECT: u64 = 94;        // (addr,len,prot R|W|X=1|2|4) -> 0 | ERR
pub const SYS_CHRT: u64 = 95;            // (pid,class 0=other|1=rt) -> 0 | ERR  realtime class
pub const SYS_IPCS: u64 = 96;            // (buf,cap) -> n | ERR    shm registry dump
pub const SYS_PIPE: u64 = 97;            // () -> rfd | wfd<<32        anonymous pipe pair
pub const SYS_DUP2: u64 = 98;            // (oldfd,newfd) -> newfd | ERR  alias an fd
pub const SYS_POLL: u64 = 99;            // (fds,evs,nfds,timeout_ms) -> nready | ERR
pub const SYS_RUSAGE: u64 = 100;         // (pid,out{utime,stime,maxrss_kb}) -> 0 | ERR
pub const SYS_FSYNC: u64 = 101;          // (fd | u64::MAX=all) -> 0 | ERR   commit file/device
pub const SYS_INOTIFY_INIT: u64 = 102;   // () -> fd | ERR                 watch-instance fd
pub const SYS_INOTIFY_ADD: u64 = 103;    // (fd,path_ptr,len,mask) -> wd | ERR
pub const SYS_INOTIFY_RM: u64 = 104;     // (fd,wd) -> 0 | ERR
pub const SYS_TIMERFD: u64 = 105;        // () -> fd | ERR                 timer object fd
pub const SYS_TFD_SET: u64 = 106;        // (fd,init_ms,interval_ms) -> 0 | ERR
pub const SYS_EVENTFD: u64 = 107;        // (initval,flags) -> fd | ERR    event-counter fd
pub const SYS_EPOLL_CREATE: u64 = 108;   // () -> fd | ERR                 epoll interest-set fd
pub const SYS_EPOLL_CTL: u64 = 109;      // (epfd,op,fd,events) -> 0 | ERR add/del/mod an interest
pub const SYS_EPOLL_WAIT: u64 = 110;     // (epfd,out_ptr,max,timeout_ms) -> nready | ERR
pub const SYS_SOCKETPAIR: u64 = 111;     // () -> fdA | fdB<<32 | ERR
pub const SYS_PIDFD: u64 = 112;          // (pid) -> fd | ERR
pub const SYS_FCNTL: u64 = 113;          // (fd,cmd,arg) -> per-cmd | ERR
pub const F_DUPFD: u64 = 0;
pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;
pub const SYS_FSTAT: u64 = 114;          // (fd,&mut Stat) -> 0 | ERR
pub const SYS_FTRUNCATE: u64 = 115;      // (fd,len) -> 0 | ERR
pub const SYS_SENDFILE: u64 = 116;       // (out,in,off_ptr|0,count) -> n | ERR
pub const SYS_READV: u64 = 117;          // (fd,iov_ptr,iovcnt) -> n | ERR
pub const SYS_WRITEV: u64 = 118;         // (fd,iov_ptr,iovcnt) -> n | ERR
pub const SOCK_STREAM: u64 = 1;          // TCP socket
pub const SOCK_DGRAM: u64 = 2;           // UDP socket
pub const AF_UNIX: u64 = 1;              // unix-domain socket family
pub const AF_INET: u64 = 2;              // ipv4 socket family
pub const SYS_SOCKET: u64 = 119;         // (SOCK_*[, domain]) -> fd | ERR
pub const SYS_BIND: u64 = 120;           // (fd, lport|name_ptr, [len]) -> 0 | ERR
pub const SYS_CONNECT: u64 = 121;        // (fd, ip|name_ptr, port|len) -> 0 | ERR
pub const SYS_LISTEN: u64 = 122;         // (fd, backlog) -> 0 | ERR
pub const SYS_ACCEPT: u64 = 123;         // (fd, peer_out[8]|0) -> connfd | ERR
pub const SYS_SENDTO: u64 = 124;         // (fd, buf, len, ip u32 BE, port) -> n | ERR
pub const SYS_RECVFROM: u64 = 125;       // (fd, buf, cap, src_out[8]|0) -> n | ERR
pub const SYS_SHUTDOWN: u64 = 126;       // (fd, how 0=rd 1=wr 2=both) -> 0 | ERR
pub const SYS_GETSOCKNAME: u64 = 127;    // (fd, out, cap) -> n | ERR
pub const SYS_GETPEERNAME: u64 = 128;    // (fd, out, cap) -> n | ERR
pub const SYS_SENDMSG: u64 = 129;        // (fd, buf, len, passfd|usize::MAX) -> n | ERR
pub const SYS_RECVMSG: u64 = 130;        // (fd, buf, cap, fd_out|0) -> n | ERR
pub const SYS_SENDTO_PATH: u64 = 131;    // (fd, buf, len, name_ptr, name_len) -> n | ERR
pub const SYS_RECVFROM_PATH: u64 = 132;  // (fd, buf, cap, name_out|0, name_cap) -> n | ERR
pub const SYS_GETSOCKOPT: u64 = 133;     // (fd, level, opt, out, cap) -> n | ERR
pub const SYS_NET_TRACE: u64 = 134;      // (ip u32 BE, max_hops, out, cap) -> n | ERR
pub const SYS_SETSOCKOPT: u64 = 135;
pub const SYS_MMAP_FILE: u64 = 136;     // (fd, size, offset) -> user ptr | 0     // (fd, level, opt, val) -> 0 | errno
pub const SYS_CLONE: u64 = 137;        // (entry, arg) -> pid | !0  — thread in the caller's mm
pub const SYS_FUTEX: u64 = 138;        // (uaddr, op, val, timeout_ms) -> 0|n | -errno  — futex wait/wake
pub const SYS_FORK: u64 = 139;         // () -> pid | 0 (child) | !0  — eager copy-on-fork
pub const SYS_EXECVE: u64 = 140;       // (path_ptr,path_len,args_ptr,args_len) -> 0 | !0 — replaces the image
pub const SYS_SIGACTION: u64 = 141;    // (sig, handler) -> old handler | !0 — 0=DFL 1=IGN
pub const SYS_SIGRETURN: u64 = 142;    // () -> restores the pushed signal frame
pub const SYS_SIGPROCMASK: u64 = 143;    // (how 0=BLOCK 1=UNBLOCK 2=SETMASK, mask) -> old mask | !0
pub const SYS_SIGNALFD: u64 = 144;       // (mask) -> fd | !0 — reads pending sigs as 128B records
pub const SYS_ALARM: u64 = 145;          // (secs) -> prev remaining secs — SIGALRM one-shot
pub const SOL_SOCKET: u64 = 1;
pub const SO_REUSEADDR: u64 = 2;
pub const SO_TYPE: u64 = 3;
pub const SO_ERROR: u64 = 4;
pub const SO_SNDBUF: u64 = 7;
pub const SO_RCVBUF: u64 = 8;
pub const SO_BROADCAST: u64 = 6;
pub const SO_KEEPALIVE: u64 = 9;
pub const SO_RCVTIMEO: u64 = 20;
pub const SO_SNDTIMEO: u64 = 21;
pub const SO_ACCEPTCONN: u64 = 30;
pub const SO_PROTOCOL: u64 = 38;
pub const SO_DOMAIN: u64 = 39;
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const SCHED_OTHER: u64 = 0;
pub const SCHED_RT: u64 = 1;
pub const SYS_ERR: u64 = u64::MAX;

// open flags
pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;
pub const O_NONBLOCK: u64 = 64;

// seek whence
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

// ---------------------------------------------------------------------------
// Kernel-provided structs
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemInfo {
    pub total_kb: u64,
    pub used_kb: u64,
    pub kernel_heap_kb: u64,
    pub tasks: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcInfo {
    pub pid: u32,
    pub is_user: u32,
    pub mem_kb: u64,
    pub cpu_ticks: u64, // 10ms PIT ticks this task has run
    pub name: [u8; 32],
}
impl Default for ProcInfo {
    fn default() -> Self {
        Self { pid: 0, is_user: 0, mem_kb: 0, cpu_ticks: 0, name: [0; 32] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub size: u64,
    pub is_dir: u32,
    pub mtime: u64, // seconds since unix epoch (0 if unknown)
    pub attr: u32,  // FAT attribute byte (0 on pseudo-fs)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 96],
    pub name_len: u8,
    pub is_dir: u8,
    pub size: u64,
    pub mtime: u64,
    pub attr: u8,   // FAT attribute byte (0 on pseudo-fs)
}
impl Default for DirEntry {
    fn default() -> Self {
        Self { name: [0; 96], name_len: 0, is_dir: 0, size: 0, mtime: 0, attr: 0 }
    }
}
pub const DIR_ENTRY_MAX: usize = 64;

/// One PCI function, filled by SYS_PCI_SCAN.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PciEnt {
    pub bus: u8,
    pub dev: u8,
    pub fun: u8,
    pub class: u8,    // base class code (cfg 0x0B)
    pub subclass: u8, // cfg 0x0A
    pub _pad: u8,
    pub vendor: u16,
    pub device: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FbInfo {
    pub addr: u64, // user-space virtual address of mapped framebuffer
    pub width: u32,
    pub height: u32,
    pub stride: u32, // pixels per row
    pub bpp: u16,    // bits per pixel (32 = BGRX/XRGB)
    pub format: u8,  // 0 = BGR, 1 = RGB
}

// ---------------------------------------------------------------------------
// Input events: kernel -> winserver ("cosmos:input" port)
// ---------------------------------------------------------------------------
pub const INPUT_PORT: &str = "cosmos:input";
pub const WS_PORT: &str = "cosmos:win";

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Key = 1,
    Mouse = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InputKey {
    pub kind: u8, // InputKind::Key
    pub down: u8,
    pub chr: u8, // ASCII char if printable (0 otherwise)
    pub mods: u8, // bit0 ctrl, bit1 shift, bit2 alt, bit3 super
    pub key: u32, // KeyCode
    pub scancode: u32, // raw set-1 scancode (with E0 bit 8 set for extended)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InputMouse {
    pub kind: u8, // InputKind::Mouse
    pub buttons: u8, // bit0 left, bit1 right, bit2 middle
    pub dx: i16,
    pub dy: i16,
    pub wheel: i8,
    pub _pad: u8,
}

// ---------------------------------------------------------------------------
// Window server protocol (over "cosmos:win" ipc port)
// Message = WsHeader { kind, len } followed by payload bytes.
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WsHeader {
    pub kind: u16,
    pub len: u16,   // payload bytes following the header
    pub reply: u32, // sender's reply/event port (client -> server requests)
}

// request kinds (app -> winserver)
pub const REQ_CREATE_WIN: u16 = 1;
pub const REQ_PRESENT: u16 = 2;
pub const REQ_SET_TITLE: u16 = 3;
pub const REQ_CLOSE_WIN: u16 = 4;
pub const REQ_PING: u16 = 5;
pub const REQ_LIST_WINS: u16 = 7;  // () -> RSP_WIN_LIST (WinInfo[])
pub const REQ_FOCUS_WIN: u16 = 8;  // (window_id u32) raise + focus + unmin
pub const REQ_MOVE_WIN: u16 = 9;   // (ReqMoveWin) reposition top-left
// response kinds (winserver -> app)
pub const RSP_WIN_CREATED: u16 = 100;
pub const RSP_ERROR: u16 = 101;
pub const RSP_WIN_LIST: u16 = 110;
// event kinds (winserver -> app)
pub const EV_KEY: u16 = 200;
pub const EV_POINTER: u16 = 201;
pub const EV_FOCUS: u16 = 202;
pub const EV_CLOSE: u16 = 203;
pub const EV_RESIZE_REQ: u16 = 204;
// resize ack (app -> winserver)
pub const REQ_RESIZE_ACK: u16 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqCreateWin {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub flags: u32, // bit0: decorate, bit1: resizable
    pub title: [u8; 48],
}
pub const WIN_DECORATE: u32 = 1;
pub const WIN_RESIZABLE: u32 = 2;

/// Window decoration metrics used by the compositor (shared with apps so
/// they can lay out their client area consistently).
pub const TITLE_H: u32 = 26;
pub const BORDER_W: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RspWinCreated {
    pub window_id: u32,
    pub shm_id: u32,
    pub w: u32,
    pub h: u32,
    pub stride: u32, // pixels per row in the shm surface
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqPresent {
    pub window_id: u32,
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32, // dirty rect in window coords; w=0 => whole window
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqSetTitle {
    pub window_id: u32,
    pub title: [u8; 48],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqMoveWin {
    pub window_id: u32,
    pub x: i32,
    pub y: i32,
}

/// One row of the REQ_LIST_WINS reply (payload = WinInfo[] of all windows,
/// focused workspace first is NOT implied -- order is z-order).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinInfo {
    pub id: u32,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub ws: u32,
    pub state: u8, // bit0 minimized, bit1 focused, bit2 maximized
    pub _pad: [u8; 3],
    pub title: [u8; 48],
}
pub const WIN_ST_MIN: u8 = 1;
pub const WIN_ST_FOCUS: u8 = 2;
pub const WIN_ST_MAX: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvKey {
    pub window_id: u32,
    pub key: u32, // KeyCode
    pub chr: u8,  // ASCII char if printable
    pub down: u8,
    pub mods: u8, // bit0 ctrl, bit1 shift, bit2 alt, bit3 super
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvPointer {
    pub window_id: u32,
    pub x: i32,
    pub y: i32,     // window-relative
    pub buttons: u8, // current button state
    pub wheel: i8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvFocus {
    pub window_id: u32,
    pub focused: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvResizeReq {
    pub window_id: u32,
    pub w: u32,
    pub h: u32,
    pub shm_id: u32, // new backing surface created by the server
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqResizeAck {
    pub window_id: u32,
    pub shm_id: u32,
    pub w: u32,
    pub h: u32,
}

/// Keyboard key codes delivered to apps (abstracted from scancodes).
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyCode {
    None = 0,
    Char = 1, // printable char; see `chr` field
    Enter = 2,
    Backspace = 3,
    Tab = 4,
    Escape = 5,
    Left = 6,
    Right = 7,
    Up = 8,
    Down = 9,
    Home = 10,
    End = 11,
    PageUp = 12,
    PageDown = 13,
    Delete = 14,
    F1 = 15,
    F2 = 16,
    F3 = 17,
    F4 = 18,
    F5 = 19,
    F6 = 20,
    F7 = 21,
    F8 = 22,
    F9 = 23,
    F10 = 24,
    F11 = 25,
    F12 = 26,
    Super = 27,
    Ctrl = 28,
    Alt = 29,
    Shift = 30,
}

/// IPC payload ceiling for window protocol messages.
pub const WS_MSG_MAX: usize = 256;
