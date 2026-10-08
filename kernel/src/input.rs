//! PS/2 keyboard + mouse via i8042. Events go to the "cosmos:input" port.
//!
//! IRQ handlers must never take locks or allocate: a spinlock held by an
//! interrupted syscall would deadlock the whole machine. So IRQs push into
//! lock-free SPSC rings and `pump` drains them later, in syscall context
//! (from `syscall::dispatch`) where locks and allocation are safe.
use crate::ipc;
use crate::sprintln;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use shared::{InputKey, InputKind, InputMouse, INPUT_PORT};
use x86_64::instructions::port::Port;

const DATA: u16 = 0x60;
const CMD: u16 = 0x64;

/// Single-producer (IRQ) / single-consumer (syscall-context pump) ring.
struct Spsc<T, const N: usize> {
    buf: UnsafeCell<[core::mem::MaybeUninit<T>; N]>,
    head: AtomicUsize, // written by producer
    tail: AtomicUsize, // written by consumer
}
unsafe impl<T, const N: usize> Sync for Spsc<T, N> {}

impl<T: Copy, const N: usize> Spsc<T, N> {
    const fn new() -> Self {
        Spsc {
            buf: UnsafeCell::new([const { core::mem::MaybeUninit::uninit() }; N]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }
    /// IRQ side. Drops when full.
    fn push(&self, v: T) {
        let h = self.head.load(Ordering::Relaxed);
        let next = (h + 1) % N;
        if next == self.tail.load(Ordering::Acquire) {
            return; // full
        }
        unsafe { (*self.buf.get())[h].write(v) };
        self.head.store(next, Ordering::Release);
    }
    /// Consumer side (any non-IRQ context).
    fn pop(&self) -> Option<T> {
        let t = self.tail.load(Ordering::Relaxed);
        if t == self.head.load(Ordering::Acquire) {
            return None;
        }
        let v = unsafe { (*self.buf.get())[t].assume_init() };
        self.tail.store((t + 1) % N, Ordering::Release);
        Some(v)
    }
}

static KEYS: Spsc<InputKey, 128> = Spsc::new();
static MICE: Spsc<InputMouse, 128> = Spsc::new();

static mut MOUSE_PKT: [u8; 4] = [0; 4];
static mut MOUSE_IDX: usize = 0;
static mut E0_PENDING: bool = false;
static mut MOD_SHIFT: u8 = 0;
static mut MOD_CTRL: u8 = 0;
static mut MOD_ALT: u8 = 0;
static mut MOD_SUPER: u8 = 0;
static mut MOD_CAPS: bool = false;

fn wait_write() {
    for _ in 0..100000 {
        let s: u8 = unsafe { Port::new(CMD).read() };
        if s & 0x02 == 0 {
            return;
        }
    }
}
fn wait_read() -> bool {
    for _ in 0..100000 {
        let s: u8 = unsafe { Port::new(CMD).read() };
        if s & 0x01 != 0 {
            return true;
        }
    }
    false
}
fn cmd(c: u8) {
    wait_write();
    unsafe {
        Port::new(CMD).write(c);
    }
}
fn data_write(v: u8) {
    wait_write();
    unsafe {
        Port::new(DATA).write(v);
    }
}
fn data_read() -> u8 {
    let _ = wait_read();
    unsafe { Port::new(DATA).read() }
}
fn aux_write(v: u8) -> u8 {
    cmd(0xD4);
    data_write(v);
    data_read()
}

pub fn init() {
    // disable ports during setup
    cmd(0xAD); // disable kbd
    cmd(0xA7); // disable aux
    // flush output buffer
    while wait_read() {
        let _: u8 = unsafe { Port::new(DATA).read() };
    }
    // config: enable IRQs, enable translation (set-1 scancodes)
    cmd(0x20);
    let mut cfg = data_read();
    cfg |= 0x01 | 0x02 | 0x40;
    cmd(0x60);
    data_write(cfg);
    // enable ports
    cmd(0xAE);
    cmd(0xA8);
    // mouse: default settings, enable streaming
    let _ = aux_write(0xF6);
    let _ = aux_write(0xF4);
    sprintln!("[input] ps/2 keyboard+mouse enabled");
}

/// IRQ counters for /proc/interrupts.
pub static KBD_IRQS: AtomicUsize = AtomicUsize::new(0);
pub static MOUSE_IRQS: AtomicUsize = AtomicUsize::new(0);

pub fn on_kbd_irq() {
    KBD_IRQS.fetch_add(1, Ordering::Relaxed);
    let sc: u8 = unsafe { Port::new(DATA).read() };
    unsafe {
        if sc == 0xE0 {
            E0_PENDING = true;
            return;
        }
        let e0 = E0_PENDING;
        E0_PENDING = false;
        let down = sc & 0x80 == 0;
        let code = sc & 0x7F;
        match (code, e0) {
            (0x1D, false) | (0x1D, true) => MOD_CTRL = if down { 1 } else { 0 },
            (0x2A, false) | (0x36, false) => MOD_SHIFT = if down { 1 } else { 0 },
            (0x38, _) => MOD_ALT = if down { 1 } else { 0 },
            (0x5B, true) | (0x5C, true) => MOD_SUPER = if down { 1 } else { 0 },
            (0x3A, false) if down => MOD_CAPS = !MOD_CAPS,
            _ => {}
        }
        let (key, chr) = scancode_to_key(code, e0);
        let mods = MOD_CTRL | (MOD_SHIFT << 1) | (MOD_ALT << 2) | (MOD_SUPER << 3);
        KEYS.push(InputKey {
            kind: InputKind::Key as u8,
            down: down as u8,
            chr: if down { chr } else { 0 },
            mods,
            key,
            scancode: code as u32 | if e0 { 0x100 } else { 0 },
        });
    }
}

pub fn on_mouse_irq() {
    MOUSE_IRQS.fetch_add(1, Ordering::Relaxed);
    let b: u8 = unsafe { Port::new(DATA).read() };
    unsafe {
        let i = MOUSE_IDX;
        if i == 0 && (b & 0x08) == 0 {
            return; // resync: first byte must have bit3
        }
        MOUSE_PKT[i] = b;
        MOUSE_IDX = (i + 1) % 3;
        if MOUSE_IDX == 0 {
            let p = MOUSE_PKT;
            let mut dx = p[1] as i16;
            let mut dy = p[2] as i16;
            if p[0] & 0x10 != 0 {
                dx -= 256;
            }
            if p[0] & 0x20 != 0 {
                dy -= 256;
            }
            MICE.push(InputMouse {
                kind: InputKind::Mouse as u8,
                buttons: p[0] & 0x07,
                dx,
                dy: -dy, // ps/2 y is inverted
                wheel: 0,
                _pad: 0,
            });
        }
    }
}

/// Drain raw ring events to the winserver's input port (if listening).
/// MUST be called from a context where locks/allocs are safe (syscall or
/// task context) — never from an IRQ.
pub fn pump() {
    if ipc::connect(INPUT_PORT).is_none() {
        return; // nobody listening yet — keep events queued
    }
    while let Some(k) = KEYS.pop() {
        let bytes = unsafe {
            core::slice::from_raw_parts(&k as *const _ as *const u8, core::mem::size_of::<InputKey>())
        };
        if ipc::push_named(INPUT_PORT, bytes).is_err() {
            // port queue full — drop (better than wedging the pipeline)
            break;
        }
    }
    // Coalesce consecutive pure moves: only the latest position matters,
    // while button/wheel transitions must stay lossless (a dropped press
    // edge is a lost click). This is what keeps the input port from
    // filling with stale motion under pointer floods.
    let mut pending: Option<InputMouse> = None;
    while let Some(m) = MICE.pop() {
        if let Some(mut p) = pending {
            if p.buttons == m.buttons && p.wheel == m.wheel {
                // same button/wheel state → pure motion: accumulate deltas
                p.dx = p.dx.saturating_add(m.dx);
                p.dy = p.dy.saturating_add(m.dy);
                pending = Some(p);
                continue;
            }
            let pb = unsafe {
                core::slice::from_raw_parts(&p as *const _ as *const u8, core::mem::size_of::<InputMouse>())
            };
            if ipc::push_named(INPUT_PORT, pb).is_err() {
                break;
            }
        }
        pending = Some(m);
    }
    if let Some(m) = pending {
        let bytes = unsafe {
            core::slice::from_raw_parts(&m as *const _ as *const u8, core::mem::size_of::<InputMouse>())
        };
        let _ = ipc::push_named(INPUT_PORT, bytes);
    }
}

/// Called by ipc when a listener registers for the input port.
pub fn flush() {
    pump();
}

pub fn modifiers() -> (bool, bool, bool, bool, bool) {
    unsafe { (MOD_SHIFT != 0, MOD_CTRL != 0, MOD_ALT != 0, MOD_SUPER != 0, MOD_CAPS) }
}

/// Translate a set-1 scancode (+ modifiers) into (KeyCode, ascii char).
pub fn scancode_to_key(code: u8, e0: bool) -> (u32, u8) {
    use shared::KeyCode::*;
    let (shift, _ctrl, _alt, _super_, caps) = modifiers();
    let k = match (code, e0) {
        (0x1C, false) => (Enter as u32, b'\n'),
        (0x0E, false) => (Backspace as u32, 8),
        (0x0F, false) => (Tab as u32, b'\t'),
        (0x01, false) => (Escape as u32, 27),
        (0x4B, true) => (Left as u32, 0),
        (0x4D, true) => (Right as u32, 0),
        (0x48, true) => (Up as u32, 0),
        (0x50, true) => (Down as u32, 0),
        (0x47, true) => (Home as u32, 0),
        (0x4F, true) => (End as u32, 0),
        (0x49, true) => (PageUp as u32, 0),
        (0x51, true) => (PageDown as u32, 0),
        (0x53, true) => (Delete as u32, 0),
        (0x3B, false) => (F1 as u32, 0),
        (0x3C, false) => (F2 as u32, 0),
        (0x3D, false) => (F3 as u32, 0),
        (0x3E, false) => (F4 as u32, 0),
        (0x3F, false) => (F5 as u32, 0),
        (0x40, false) => (F6 as u32, 0),
        (0x41, false) => (F7 as u32, 0),
        (0x42, false) => (F8 as u32, 0),
        (0x43, false) => (F9 as u32, 0),
        (0x44, false) => (F10 as u32, 0),
        (0x57, false) => (F11 as u32, 0),
        (0x58, false) => (F12 as u32, 0),
        (0x5B, true) | (0x5C, true) => (Super as u32, 0),
        (0x1D, _) => (Ctrl as u32, 0),
        (0x38, _) => (Alt as u32, 0),
        (0x2A, false) | (0x36, false) => (Shift as u32, 0),
        _ => {
            let ch = SCANCODE_ASCII[code as usize];
            if ch == 0 {
                (0, 0)
            } else {
                let ch = ascii_shift(ch, shift, caps);
                (Char as u32, ch)
            }
        }
    };
    k
}

fn ascii_shift(c: u8, shift: bool, caps: bool) -> u8 {
    let c = c as char;
    let out = if c.is_ascii_lowercase() && (shift != caps) {
        c.to_ascii_uppercase()
    } else {
        c
    };
    if shift && !out.is_ascii_lowercase() {
        match out {
            '1' => return b'!',
            '2' => return b'@',
            '3' => return b'#',
            '4' => return b'$',
            '5' => return b'%',
            '6' => return b'^',
            '7' => return b'&',
            '8' => return b'*',
            '9' => return b'(',
            '0' => return b')',
            '-' => return b'_',
            '=' => return b'+',
            '[' => return b'{',
            ']' => return b'}',
            '\\' => return b'|',
            ';' => return b':',
            '\'' => return b'"',
            ',' => return b'<',
            '.' => return b'>',
            '/' => return b'?',
            '`' => return b'~',
            _ => {}
        }
    }
    out as u8
}

static SCANCODE_ASCII: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x02] = b'1';
    t[0x03] = b'2';
    t[0x04] = b'3';
    t[0x05] = b'4';
    t[0x06] = b'5';
    t[0x07] = b'6';
    t[0x08] = b'7';
    t[0x09] = b'8';
    t[0x0A] = b'9';
    t[0x0B] = b'0';
    t[0x0C] = b'-';
    t[0x0D] = b'=';
    t[0x10] = b'q';
    t[0x11] = b'w';
    t[0x12] = b'e';
    t[0x13] = b'r';
    t[0x14] = b't';
    t[0x15] = b'y';
    t[0x16] = b'u';
    t[0x17] = b'i';
    t[0x18] = b'o';
    t[0x19] = b'p';
    t[0x1A] = b'[';
    t[0x1B] = b']';
    t[0x2B] = b'\\';
    t[0x1E] = b'a';
    t[0x1F] = b's';
    t[0x20] = b'd';
    t[0x21] = b'f';
    t[0x22] = b'g';
    t[0x23] = b'h';
    t[0x24] = b'j';
    t[0x25] = b'k';
    t[0x26] = b'l';
    t[0x27] = b';';
    t[0x28] = b'\'';
    t[0x29] = b'`';
    t[0x2C] = b'z';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b'm';
    t[0x33] = b',';
    t[0x34] = b'.';
    t[0x35] = b'/';
    t[0x39] = b' ';
    t
};
