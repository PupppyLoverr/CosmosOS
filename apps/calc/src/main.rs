//! cosmos-calc: a real clickable integer calculator.
//! Integer-only (userspace runs without SSE) — / is integer division.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

const LABELS: [&str; 16] = [
    "7", "8", "9", "/", //
    "4", "5", "6", "*", //
    "1", "2", "3", "-", //
    "0", "C", "=", "+",
];
const COLS: i32 = 4;
const BTN_Y0: i32 = 56; // below the display
const PAD: i32 = 6;

struct Calc {
    win: Window,
    c: Canvas,
    disp: String, // what's being typed / the result
    acc: i64,
    op: u8, // pending op: '+', '-', '*', '/', 0=none
    fresh: bool, // next digit starts a new number
    err: bool,
    dirty: bool,
}

impl Calc {
    fn apply(&mut self) {
        let n: i64 = self.disp.parse().unwrap_or(0);
        self.acc = match self.op {
            b'+' => self.acc.checked_add(n).unwrap_or(i64::MAX),
            b'-' => self.acc.checked_sub(n).unwrap_or(i64::MIN),
            b'*' => self.acc.checked_mul(n).unwrap_or(i64::MAX),
            b'/' => {
                if n == 0 {
                    self.err = true;
                    0
                } else {
                    self.acc / n
                }
            }
            _ => n, // first number in
        };
        self.disp = if self.err {
            String::from("div by 0")
        } else {
            alloc::format!("{}", self.acc)
        };
        self.fresh = true;
    }

    fn press(&mut self, ch: u8) {
        match ch {
            b'0'..=b'9' => {
                if self.fresh || self.err {
                    self.disp.clear();
                    self.fresh = false;
                    self.err = false;
                }
                if self.disp.len() < 18 {
                    self.disp.push(ch as char);
                }
            }
            b'+' | b'-' | b'*' | b'/' => {
                if self.err {
                    return;
                }
                self.apply();
                if !self.err {
                    self.op = ch;
                }
            }
            b'=' | b'\n' => {
                self.apply();
                self.op = 0;
            }
            b'c' | b'C' | 27 => {
                self.disp = String::from("0");
                self.acc = 0;
                self.op = 0;
                self.fresh = true;
                self.err = false;
            }
            _ => return,
        }
        self.dirty = true;
    }

    fn btn_rect(&self, i: i32) -> (i32, i32, i32, i32) {
        let col = i % COLS;
        let row = i / COLS;
        let avail = self.c.w as i32 - PAD * (COLS + 1);
        let bw = avail / COLS;
        let bh = 40;
        (
            PAD + col * (bw + PAD),
            BTN_Y0 + row * (bh + PAD),
            bw,
            bh,
        )
    }

    fn redraw(&mut self) {
        let c = self.c;
        c.fill(0, 0, c.w as i32, c.h as i32, draw::BLACK);
        // display
        c.fill(PAD, 8, c.w as i32 - PAD * 2, 40, draw::PANEL);
        let right = c.w as i32 - PAD - 10;
        let x = right - self.disp.len() as i32 * 8;
        c.text(x.max(PAD + 8), 20, &self.disp, draw::TEXT, None);
        // pending op hint
        if self.op != 0 {
            c.text(PAD + 8, 20, &alloc::format!("{}", self.op as char), draw::DIM, None);
        }
        // buttons
        for i in 0..16 {
            let (x, y, w, h) = self.btn_rect(i);
            c.fill(x, y, w, h, draw::PANEL);
            c.border(x, y, w, h, draw::EDGE);
            c.text(x + w / 2 - 4, y + h / 2 - 8, LABELS[i as usize], draw::TEXT, None);
        }
        self.win.present_all();
    }

    fn click(&mut self, x: i32, y: i32, buttons: u8) {
        if buttons & 1 == 0 {
            return;
        }
        for i in 0..16 {
            let (bx, by, bw, bh) = self.btn_rect(i);
            if x >= bx && x < bx + bw && y >= by && y < by + bh {
                let l = LABELS[i as usize];
                self.press(if l.len() == 1 { l.as_bytes()[0] } else { 0 });
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[calc] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(200, 140, 248, 256, WIN_DECORATE, "Calculator")
        .expect("create window");
    let mut calc = Calc {
        win,
        c: win.canvas(),
        disp: String::from("0"),
        acc: 0,
        op: 0,
        fresh: true,
        err: false,
        dirty: true,
    };
    loop {
        match wm.next_event(250) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if k.down != 0 {
                    match k.key as u32 {
                        x if x == KeyCode::Char as u32 => calc.press(k.chr),
                        x if x == KeyCode::Enter as u32 => calc.press(b'='),
                        x if x == KeyCode::Escape as u32 => calc.press(b'c'),
                        _ => {}
                    }
                }
            }
            Some((EV_POINTER, pl)) if pl.len() >= 16 => {
                let p: EvPointer = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                calc.click(p.x, p.y, p.buttons);
            }
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if calc.win.remap(r.shm_id, r.w, r.h) {
                    calc.c = calc.win.canvas();
                    calc.win.resize_ack(r.shm_id, r.w, r.h);
                    calc.dirty = true;
                }
            }
            _ => {}
        }
        if calc.dirty {
            calc.dirty = false;
            calc.redraw();
        }
    }
}
