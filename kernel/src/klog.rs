//! In-kernel log ring buffer — everything written to serial also lands
//! here so userspace can read it back (`dmesg`) even though COM1 output
//! is lost once the VM window is closed.
//!
//! Fixed-size, no allocation: sprintln is used before the heap exists
//! and from panic paths, so this buffer must never touch the allocator.
use spin::Mutex;

const CAP: usize = 32 * 1024;

struct Ring {
    buf: [u8; CAP],
    /// Index of the oldest byte (buffer is always treated as full once
    /// `len` reaches CAP; before that, `head` stays 0).
    head: usize,
    len: usize,
}

static RING: Mutex<Ring> = Mutex::new(Ring {
    buf: [0; CAP],
    head: 0,
    len: 0,
});

fn push_locked(r: &mut Ring, b: u8) {
    if r.len == CAP {
        r.buf[r.head] = b;
        r.head = (r.head + 1) % CAP;
    } else {
        let i = (r.head + r.len) % CAP;
        r.buf[i] = b;
        r.len += 1;
    }
}

pub fn append(s: &str) {
    // try_lock: a panic mid-append must not deadlock the panic handler
    if let Some(mut r) = RING.try_lock() {
        for &b in s.as_bytes() {
            push_locked(&mut r, b);
        }
    }
}

pub fn append_byte(b: u8) {
    if let Some(mut r) = RING.try_lock() {
        push_locked(&mut r, b);
    }
}

/// Empty the ring (`dmesg -c` reads then clears).
pub fn clear() {
    let mut r = RING.lock();
    r.head = 0;
    r.len = 0;
}

/// Copy up to `out.len()` tail bytes of the log into `out`; returns the
/// number written.
pub fn read_tail(out: &mut [u8]) -> usize {
    let r = RING.lock();
    let n = out.len().min(r.len);
    // tail starts `n` bytes before the write position
    let tail_len = r.len;
    let start = (r.head + tail_len - n) % CAP;
    for i in 0..n {
        out[i] = r.buf[(start + i) % CAP];
    }
    n
}
