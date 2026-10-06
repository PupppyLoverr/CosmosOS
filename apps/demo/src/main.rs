//! cosmos-demo: a native Rust demo app exercising the app API end-to-end —
//! animated scene (bouncing ball + fps meter) in a resizable window, file I/O
//! of a score persisted to disk, keyboard control.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

fn isqrt(n: u32) -> u32 {
    // no SSE: integer square root (SSE state isn't saved across task switches)
    let mut x = n;
    let mut c = 0u32;
    let mut d = 1u32 << 30;
    while d > n {
        d >>= 2;
    }
    while d != 0 {
        if x >= c + d {
            x -= c + d;
            c = (c >> 1) + d;
        } else {
            c >>= 1;
        }
        d >>= 2;
    }
    c
}

struct Demo {
    win: Window,
    c: Canvas,
    x: i32,
    y: i32,
    vx: i32,
    vy: i32,
    r: i32,
    score: u32,
    frames: u64,
    fps: u32,
    last_sec: u64,
    paused: bool,
    dirty: bool,
}

impl Demo {
    fn circle(&self, cx: i32, cy: i32, r: i32, col: u32) {
        let c = self.c;
        for dy in -r..r {
            let span = isqrt((r * r - dy * dy) as u32) as i32;
            c.fill(cx - span, cy + dy, span * 2, 1, col);
        }
    }

    fn tick(&mut self) {
        if !self.paused {
            self.x += self.vx;
            self.y += self.vy;
            let (w, h) = (self.c.w as i32, self.c.h as i32);
            if self.x - self.r < 0 || self.x + self.r >= w {
                self.vx = -self.vx;
                self.x += self.vx * 2;
            }
            if self.y - self.r < 26 || self.y + self.r >= h {
                self.vy = -self.vy;
                self.y += self.vy * 2;
            }
        }
        self.frames += 1;
        let now = ustd::uptime_ms();
        if now - self.last_sec >= 1000 {
            self.fps = self.frames as u32;
            self.frames = 0;
            self.last_sec = now;
        }
        self.dirty = true;
    }

    fn redraw(&mut self) {
        let c = self.c;
        c.fill(0, 0, c.w as i32, c.h as i32, draw::BLACK);
        c.fill(0, 0, c.w as i32, 22, draw::PANEL);
        c.text(8, 3, &alloc::format!("cosmos-demo  fps={}  score={}  [space]=pause [+/-]=size", self.fps, self.score), draw::DIM, None);
        // moving ball with trail
        for i in 1..5 {
            self.circle(self.x - self.vx * i, self.y - self.vy * i, (self.r - i * 2).max(2), 0xFF202226);
        }
        self.circle(self.x, self.y, self.r, draw::ACCENT);
        c.fill(0, c.h as i32 - 20, c.w as i32, 20, draw::PANEL);
        c.text(8, c.h as i32 - 18, "real app: shm surface + input + file persistence", draw::DIM, None);
        self.win.present_all();
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        if k.key == KeyCode::Char as u32 {
            match k.chr {
                b' ' => self.paused = !self.paused,
                b'+' | b'=' => self.r = (self.r + 4).min(120),
                b'-' | b'_' => self.r = (self.r - 4).max(6),
                b's' => {
                    let d = alloc::format!("score={}\n", self.score);
                    let _ = ustd::mkdir("/var");
                    let _ = ustd::write_all("/var/demo-score.txt", d.as_bytes());
                }
                _ => {}
            }
            self.score += 1;
            self.dirty = true;
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[demo] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(320, 140, 520, 360, WIN_DECORATE | WIN_RESIZABLE, "Demo - native app")
        .expect("create window");
    let score = ustd::read_all("/var/demo-score.txt")
        .ok()
        .and_then(|d| {
            let s = String::from_utf8_lossy(&d);
            s.trim_start_matches("score=").trim().parse::<u32>().ok()
        })
        .unwrap_or(0);
    let mut d = Demo {
        win,
        c: win.canvas(),
        x: 200,
        y: 120,
        vx: 4,
        vy: 3,
        r: 24,
        score,
        frames: 0,
        fps: 0,
        last_sec: ustd::uptime_ms(),
        paused: false,
        dirty: true,
    };
    loop {
        match wm.next_event(12) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                d.on_key(&k);
            }
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if d.win.remap(r.shm_id, r.w, r.h) {
                    d.c = d.win.canvas();
                    d.win.resize_ack(r.shm_id, r.w, r.h);
                    d.dirty = true;
                }
            }
            _ => {}
        }
        d.tick();
        if d.dirty {
            d.dirty = false;
            d.redraw();
        }
    }
}
