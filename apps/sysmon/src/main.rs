//! cosmos-sysmon: real-time task list + memory usage + uptime, refreshed
//! every second from SYS_PROCLIST / SYS_MEMINFO.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

struct Sysmon {
    win: Window,
    c: Canvas,
    dirty: bool,
    mem_hist: Vec<u64>, // used_kb samples
}

impl Sysmon {
    fn redraw(&mut self) {
        let c = self.c;
        c.fill(0, 0, c.w as i32, c.h as i32, draw::PANEL);
        let mi = ustd::meminfo();
        c.text(12, 10, "System Monitor", draw::TEXT, None);
        c.text(12, 30, &alloc::format!("uptime {}s   tasks {}", ustd::uptime_ms() / 1000, mi.tasks), draw::DIM, None);
        // memory bar
        let y = 56;
        c.text(12, y, &alloc::format!("memory  {} / {} KiB ({}%)", mi.used_kb, mi.total_kb, mi.used_kb * 100 / mi.total_kb.max(1)), draw::TEXT, None);
        let bw = c.w as i32 - 24;
        c.fill(12, y + 22, bw, 14, draw::EDGE);
        let used_w = (bw as u64 * mi.used_kb / mi.total_kb.max(1)) as i32;
        c.fill(12, y + 22, used_w, 14, draw::ACCENT);
        c.text(12, y + 40, &alloc::format!("kernel heap {} KiB", mi.kernel_heap_kb), draw::DIM, None);
        // mem history sparkline
        self.mem_hist.push(mi.used_kb);
        if self.mem_hist.len() > 60 {
            self.mem_hist.remove(0);
        }
        let sy = y + 62;
        let sh = 40;
        c.border(12, sy, bw, sh, draw::EDGE);
        for (i, &v) in self.mem_hist.iter().enumerate() {
            let h = (v * sh as u64 / mi.total_kb.max(1)) as i32;
            let x = 12 + i as i32 * (bw / 60).max(1);
            c.fill(x, sy + sh - h, (bw / 60).max(1), h, draw::DIM);
        }
        // tasks
        let ty = sy + sh + 14;
        c.text(12, ty, "processes", draw::TEXT, None);
        c.fill(12, ty + 16, bw, 1, draw::EDGE);
        let procs = ustd::proclist(64);
        let mut yy = ty + 24;
        let mut sorted: Vec<_> = procs.iter().collect();
        sorted.sort_by_key(|p| p.pid);
        for p in sorted {
            if yy > c.h as i32 - 24 {
                break;
            }
            let name = core::str::from_utf8(&p.name).unwrap_or("?").trim_end_matches('\0');
            let kind = if p.is_user != 0 { "user" } else { "kern" };
            c.text(12, yy, &alloc::format!("{:>3}  {:<6} {:<20} {} KiB", p.pid, kind, name, p.mem_kb), draw::DIM, None);
            yy += 18;
        }
        self.win.present_all();
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[sysmon] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(240, 80, 480, 420, WIN_DECORATE | WIN_RESIZABLE, "System Monitor")
        .expect("create window");
    let mut s = Sysmon { win, c: win.canvas(), dirty: true, mem_hist: Vec::new() };
    let mut last = 0u64;
    loop {
        match wm.next_event(500) {
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if s.win.remap(r.shm_id, r.w, r.h) {
                    s.c = s.win.canvas();
                    s.win.resize_ack(r.shm_id, r.w, r.h);
                    s.dirty = true;
                }
            }
            _ => {}
        }
        let now = ustd::uptime_ms();
        if now - last >= 1000 {
            last = now;
            s.dirty = true;
        }
        if s.dirty {
            s.dirty = false;
            s.redraw();
        }
    }
}
