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
    // PC speaker: silence when the programmed duration elapses.
    let left = BEEP_TICKS_LEFT.load(core::sync::atomic::Ordering::Relaxed);
    if left != 0 {
        if left <= 1 {
            speaker_off();
        } else {
            BEEP_TICKS_LEFT.store(left - 1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

// ---------------- PC speaker (PIT channel 2 + port 0x61) ----------------
//
// Channel 2 of the 8254 feeds a gate on port 0x61; setting bits 0 (gate from
// PIT2) and 1 (speaker data enable) makes the cone oscillate at the channel's
// programmed square-wave frequency. Real hardware path — on a physical PC this
// is the classic "beep".
static BEEP_TICKS_LEFT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

fn speaker_off() {
    BEEP_TICKS_LEFT.store(0, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let mut g: Port<u8> = Port::new(0x61);
        let v = g.read();
        g.write(v & !0x03u8);
    }
}

/// Sound the PC speaker at `freq` Hz for `ms` milliseconds. Non-blocking: the
/// expiry is armed in tick units and `bump_ticks` silences the gate. `freq==0`
/// or `ms==0` silences immediately; re-arming replaces the pending beep.
pub fn beep(freq: u32, ms: u64) {
    if freq == 0 || ms == 0 {
        speaker_off();
        return;
    }
    let divisor = (1193182u32 / freq.max(20)).clamp(1, 0xFFFF);
    unsafe {
        let mut cmd: Port<u8> = Port::new(0x43);
        cmd.write(0xB6u8); // channel 2, lobyte/hibyte, mode 3 (square wave)
        let mut ch2: Port<u8> = Port::new(0x42);
        ch2.write((divisor & 0xFF) as u8);
        ch2.write(((divisor >> 8) & 0xFF) as u8);
        let mut g: Port<u8> = Port::new(0x61);
        let v = g.read();
        g.write(v | 0x03);
    }
    let t = (ms.saturating_mul(TICK_HZ) / 1000).max(1);
    BEEP_TICKS_LEFT.store(t.min(u64::from(u32::MAX)), core::sync::atomic::Ordering::Relaxed);
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

// Howard Hinnant's civil algorithms (public domain) — inverse of
// days_from_civil so unix seconds can be written back to the RTC.
fn civil_from_days(z: i64) -> (u16, u8, u8) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((if m <= 2 { y + 1 } else { y }) as u16, m as u8, d as u8)
}

fn cmos_write(reg: u8, val: u8) {
    unsafe {
        let mut a: Port<u8> = Port::new(0x70);
        a.write(reg);
        let mut d: Port<u8> = Port::new(0x71);
        d.write(val);
    }
}

/// Set the wall clock to unix `secs`: rebase the in-memory clock AND write
/// the CMOS RTC registers (BCD-aware; updates held off via the SET bit).
pub fn set_unix(secs: u64) {
    // rebase so datetime() = base + uptime returns `secs` right now
    let base = (secs as i64 - (uptime_ms() / 1000) as i64).max(0) as u64;
    let (y, m, d) = civil_from_days((base / 86400) as i64);
    let rem = base % 86400;
    *BASE.lock() = Some(DateTime {
        year: y,
        month: m,
        day: d,
        hour: (rem / 3600) as u8,
        minute: ((rem % 3600) / 60) as u8,
        second: (rem % 60) as u8,
    });
    // persist to the hardware RTC (what a real `hwclock --systohc` does)
    let (ty, tm, td) = civil_from_days((secs / 86400) as i64);
    let trem = secs % 86400;
    let regb = cmos(0x0B);
    let is_bcd = regb & 0x04 == 0;
    let enc = |v: u8| -> u8 {
        if is_bcd {
            ((v / 10) << 4) | (v % 10)
        } else {
            v
        }
    };
    cmos_write(0x0B, regb | 0x80); // SET: hold updates during the write
    cmos_write(0x00, enc((trem % 60) as u8));
    cmos_write(0x02, enc(((trem % 3600) / 60) as u8));
    cmos_write(0x04, enc((trem / 3600) as u8));
    cmos_write(0x07, enc(td));
    cmos_write(0x08, enc(tm));
    cmos_write(0x09, enc((ty % 100) as u8));
    cmos_write(0x0B, regb & !0x80);
    sprintln!("[rtc] set to unix {}", secs);
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
