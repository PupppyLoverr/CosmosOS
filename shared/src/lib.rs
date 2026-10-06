//! CosmosOS shared ABI: syscall numbers, kernel<->userspace data types,
//! and the window-server wire protocol. Used by both the kernel and `ustd`.
#![no_std]

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

pub const SYS_ERR: u64 = u64::MAX;

// open flags
pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;

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
    pub name: [u8; 32],
}
impl Default for ProcInfo {
    fn default() -> Self {
        Self { pid: 0, is_user: 0, mem_kb: 0, name: [0; 32] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub size: u64,
    pub is_dir: u32,
    pub mtime: u64, // seconds since unix epoch (0 if unknown)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 96],
    pub name_len: u8,
    pub is_dir: u8,
    pub size: u64,
    pub mtime: u64,
}
impl Default for DirEntry {
    fn default() -> Self {
        Self { name: [0; 96], name_len: 0, is_dir: 0, size: 0, mtime: 0 }
    }
}
pub const DIR_ENTRY_MAX: usize = 64;

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
// response kinds (winserver -> app)
pub const RSP_WIN_CREATED: u16 = 100;
pub const RSP_ERROR: u16 = 101;
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
