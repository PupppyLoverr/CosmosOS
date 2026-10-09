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
    /// Bytes appended since the last SYSLOG_ACTION_READ drain — the
    /// shared global read cursor (any reader consumes it, like klogctl).
    unread: usize,
    /// True when the next byte starts a new record — klog stamps each
    /// record's start with `[ secs.usecs ]` like real dmesg.
    at_bol: bool,
}

static RING: Mutex<Ring> = Mutex::new(Ring {
    buf: [0; CAP],
    head: 0,
    len: 0,
    unread: 0,
    at_bol: true,
});

/// Fixed-buffer writer for the record timestamp — klog runs before the
/// heap and from panic paths, so the stamp is formatted into a stack
/// array, never through the allocator.
struct StampBuf {
    buf: [u8; 24],
    len: usize,
}
impl core::fmt::Write for StampBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &c in s.as_bytes() {
            if self.len >= self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len] = c;
            self.len += 1;
        }
        Ok(())
    }
}

fn push_locked(r: &mut Ring, b: u8) {
    if r.at_bol && b != b'\n' {
        r.at_bol = false;
        let ms = crate::timer::uptime_ms();
        let mut w = StampBuf { buf: [0; 24], len: 0 };
        use core::fmt::Write;
        let _ = write!(&mut w, "[{:>5}.{:06}] ", ms / 1000, ms % 1000 * 1000);
        for i in 0..w.len {
            push_inner(r, w.buf[i]);
        }
    }
    if b == b'\n' {
        r.at_bol = true;
    }
    push_inner(r, b);
}

fn push_inner(r: &mut Ring, b: u8) {
    r.unread = r.unread.saturating_add(1);
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
    r.unread = 0;
}

/// syslog(9) — bytes appended but not yet drained by SYSLOG_ACTION_READ.
pub fn unread_len() -> usize {
    let r = RING.lock();
    r.unread.min(r.len)
}

/// syslog(10) — the ring's total capacity.
pub fn buffer_size() -> usize {
    CAP
}

/// syslog(3) — copy the not-yet-consumed tail into `out`, drain the
/// shared read cursor. Returns bytes written.
pub fn read_unread(out: &mut [u8]) -> usize {
    let mut r = RING.lock();
    let n = out.len().min(r.unread).min(r.len);
    let tail_len = r.len;
    let start = (r.head + tail_len - n) % CAP;
    for i in 0..n {
        out[i] = r.buf[(start + i) % CAP];
    }
    r.unread = r.unread.saturating_sub(n);
    n
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
