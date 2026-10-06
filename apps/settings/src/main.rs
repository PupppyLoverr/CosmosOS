//! cosmos-settings: real persisted settings written to /etc/cosmos.conf.
//! Other components read the same file (e.g. winserver cursor scale).
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

const CFG_PATH: &str = "/etc/cosmos.conf";

struct Row {
    key: &'static str,
    label: &'static str,
    options: &'static [&'static str],
    cur: usize,
}

struct Settings {
    win: Window,
    c: Canvas,
    rows: Vec<Row>,
    sel: i32,
    status: String,
    dirty: bool,
}

fn load(rows: &mut Vec<Row>) {
    let data = ustd::read_all(CFG_PATH).unwrap_or_default();
    let text = String::from_utf8_lossy(&data);
    for r in rows.iter_mut() {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == r.key {
                    if let Some(i) = r.options.iter().position(|o| *o == v.trim()) {
                        r.cur = i;
                    }
                }
            }
        }
    }
}

fn save(rows: &[Row]) -> Result<(), i64> {
    let mut out = String::from("# CosmosOS settings\n");
    for r in rows {
        out.push_str(&alloc::format!("{}={}\n", r.key, r.options[r.cur]));
    }
    let _ = ustd::mkdir("/etc");
    ustd::write_all(CFG_PATH, out.as_bytes())
}

impl Settings {
    fn redraw(&mut self) {
        let c = self.c;
        c.fill(0, 0, c.w as i32, c.h as i32, draw::PANEL);
        c.text(14, 12, "Settings", draw::TEXT, None);
        c.fill(10, 34, c.w as i32 - 20, 1, draw::EDGE);
        for (i, r) in self.rows.iter().enumerate() {
            let y = 50 + i as i32 * 56;
            if i as i32 == self.sel {
                c.fill(6, y - 8, c.w as i32 - 12, 50, draw::EDGE);
            }
            c.text(14, y, r.label, draw::TEXT, None);
            // option buttons
            let mut bx = 14;
            for (oi, o) in r.options.iter().enumerate() {
                let w = o.len() as i32 * 8 + 22;
                let cur = oi == r.cur;
                c.fill(bx, y + 20, w, 24, if cur { draw::ACCENT } else { draw::BG });
                c.border(bx, y + 20, w, 24, draw::EDGE);
                c.text(bx + 11, y + 24, o, if cur { draw::BLACK } else { draw::TEXT }, None);
                bx += w + 8;
            }
        }
        let y = 50 + self.rows.len() as i32 * 56 + 10;
        c.fill(14, y, 120, 26, draw::BG);
        c.border(14, y, 120, 26, draw::EDGE);
        c.text(26, y + 5, "Apply", draw::TEXT, None);
        c.text(14, y + 34, &self.status, draw::DIM, None);
        self.win.present_all();
    }

    fn click(&mut self, x: i32, y: i32, buttons: u8) {
        if buttons & 1 == 0 {
            return;
        }
        for (i, r) in self.rows.iter_mut().enumerate() {
            let ry = 50 + i as i32 * 56;
            if y >= ry - 8 && y < ry + 42 {
                self.sel = i as i32;
                let mut bx = 14;
                for (oi, o) in r.options.iter().enumerate() {
                    let w = o.len() as i32 * 8 + 22;
                    if x >= bx && x < bx + w && y >= ry + 20 && y < ry + 44 {
                        r.cur = oi;
                        self.status = alloc::format!("{} = {} (click Apply)", r.key, o);
                        self.dirty = true;
                        return;
                    }
                    bx += w + 8;
                }
            }
        }
        let ay = 50 + self.rows.len() as i32 * 56 + 10;
        if x >= 14 && x < 134 && y >= ay && y < ay + 26 {
            match save(&self.rows) {
                Ok(_) => self.status = alloc::format!("saved to {}", CFG_PATH),
                Err(e) => self.status = alloc::format!("save failed: {}", e),
            }
            self.dirty = true;
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[settings] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(160, 120, 460, 380, WIN_DECORATE | WIN_RESIZABLE, "Settings")
        .expect("create window");
    let mut s = Settings {
        win,
        c: win.canvas(),
        rows: alloc::vec![
            Row { key: "wallpaper", label: "Wallpaper tone", options: &["dark", "darker", "graphite"], cur: 0 },
            Row { key: "cursor_speed", label: "Cursor speed", options: &["slow", "normal", "fast"], cur: 1 },
            Row { key: "clock_seconds", label: "Taskbar clock", options: &["hh:mm", "hh:mm:ss"], cur: 1 },
        ],
        sel: -1,
        status: String::from("changes apply to /etc/cosmos.conf"),
        dirty: true,
    };
    load(&mut s.rows);
    loop {
        match wm.next_event(250) {
            Some((EV_POINTER, pl)) if pl.len() >= 16 => {
                let p: EvPointer = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                s.click(p.x, p.y, p.buttons);
            }
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
        if s.dirty {
            s.dirty = false;
            s.redraw();
        }
    }
}
