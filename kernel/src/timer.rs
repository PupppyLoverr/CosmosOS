//! PIT (8253/8254) periodic tick + CMOS RTC wall-clock read.
use crate::sprintln;
use shared::DateTime;
use spin::Mutex;
use x86_64::instructions::port::Port;

pub const TICK_HZ: u64 = 100;
static TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn ticks() -> u64 {
    TICKS.load(core::sync::atomic::Ordering::Relaxed)
}
pub fn uptime_ms() -> u64 {
    ticks() * (1000 / TICK_HZ)
}
pub(crate) fn bump_ticks() {
    TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Program PIT channel 0 for `TICK_HZ` periodic interrupts.
pub fn init_pit() {
    let divisor = (1193182u32 / TICK_HZ as u32).max(1);
    unsafe {
        let mut cmd: Port<u8> = Port::new(0x43);
        cmd.write(0x36u8); // channel 0, lobyte/hibyte, square-wave-ish mode 3? mode 2 for periodic: use 0x34? Use mode 2 (rate gen) 0x34
        let mut ch0: Port<u8> = Port::new(0x40);
        ch0.write((divisor & 0xFF) as u8);
        ch0.write(((divisor >> 8) & 0xFF) as u8);
    }
    sprintln!("[pit] {} Hz (divisor {})", TICK_HZ, divisor);
}

// ---------------- RTC (CMOS) ----------------
static BASE: Mutex<Option<DateTime>> = Mutex::new(None);

fn cmos(reg: u8) -> u8 {
    unsafe {
        let mut a: Port<u8> = Port::new(0x70);
        a.write(reg);
        let mut d: Port<u8> = Port::new(0x71);
        d.read()
    }
}

fn update_in_progress() -> bool {
    cmos(0x0A) & 0x80 != 0
}

fn bcd(b: u8, is_bcd: bool) -> u8 {
    if is_bcd {
        (b & 0x0F) + ((b >> 4) * 10)
    } else {
        b
    }
}

/// Read the RTC once at boot and store the base time; `datetime()` adds uptime.
pub fn init_rtc() {
    // wait for update-in-progress to clear
    for _ in 0..1_000_000 {
        if !update_in_progress() {
            break;
        }
    }
    let regb = cmos(0x0B);
    let is_bcd = regb & 0x04 == 0;
    let is_24 = regb & 0x02 != 0;
    let sec = bcd(cmos(0x00), is_bcd);
    let min = bcd(cmos(0x02), is_bcd);
    let mut hour = bcd(cmos(0x04) & 0x7F, is_bcd);
    if !is_24 && (cmos(0x04) & 0x80) != 0 {
        hour = (hour + 12) % 24;
    }
    let day = bcd(cmos(0x07), is_bcd);
    let month = bcd(cmos(0x08), is_bcd);
    let year = 2000u16 + bcd(cmos(0x09), is_bcd) as u16;
    *BASE.lock() = Some(DateTime {
        year,
        month,
        day,
        hour,
        minute: min,
        second: sec,
    });
    sprintln!(
        "[rtc] {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    );
}

const DAYS_IN_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap(y: u16) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Current wall clock = RTC base + uptime. Enough accuracy for a status clock.
pub fn datetime() -> DateTime {
    let base = *BASE.lock();
    let mut dt = match base {
        Some(d) => d,
        None => DateTime { year: 2026, month: 1, day: 1, hour: 0, minute: 0, second: 0 },
    };
    let secs = dt.second as u64 + uptime_ms() / 1000;
    dt.second = (secs % 60) as u8;
    let mins = dt.minute as u64 + secs / 60;
    dt.minute = (mins % 60) as u8;
    let hrs = dt.hour as u64 + mins / 60;
    dt.hour = (hrs % 24) as u8;
    let mut days = hrs / 24;
    while days > 0 {
        let dim = DAYS_IN_MONTH[(dt.month - 1) as usize] + if dt.month == 2 && is_leap(dt.year) { 1 } else { 0 };
        if dt.day + (days as u8) <= dim {
            dt.day += days as u8;
            break;
        }
        days -= (dim - dt.day + 1) as u64;
        dt.day = 1;
        dt.month += 1;
        if dt.month > 12 {
            dt.month = 1;
            dt.year += 1;
        }
    }
    dt
}
