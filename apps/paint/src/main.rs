//! cosmos-paint: a real mouse drawing app.
//! Left-drag draws with the brush; right-drag erases; b/e toggle brush/
//! eraser, [/] shrink/grow, c clears, s saves the canvas as a real PPM
//! file on the data volume.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

const TOOL_H: i32 = 26;

struct Paint {
    win: Window,
    c: Canvas,
    last: Option<(i32, i32)>, // last stroke point while the button is down
    brush: i32,               // half-size of the square brush
    eraser: bool,
    status: String,
    dirty: bool,
}

impl Paint {
    /// One stamp of the brush (filled square in canvas space).
    fn stamp(&mut self, x: i32, y: i32) {
        let col = if self.eraser { draw::BLACK } else { draw::TEXT };
        let r = self.brush;
        self.c.fill(x - r, y - r, r * 2 + 1, r * 2 + 1, col);
    }

    /// Stroke from the last point to (x,y) — interpolates so fast drags
    /// don't leave dotted gaps.
    fn stroke(&mut self, x: i32, y: i32) {
        match self.last {
            Some((lx, ly)) => {
                let dx = x - lx;
                let dy = y - ly;
                let steps = dx.abs().max(dy.abs()).max(1);
                for i in 0..=steps {
                    self.stamp(lx + dx * i / steps, ly + dy * i / steps);
                }
            }
            None => self.stamp(x, y),
        }
        self.last = Some((x, y));
        self.dirty = true;
    }

    fn save(&mut self) {
        // find a free /paint-N.ppm name
        let mut n = 1u32;
        let path = loop {
            let p = alloc::format!("/paint-{}.ppm", n);
            if ustd::stat(&p).is_err() {
                break p;
            }
            n += 1;
            if n > 999 {
                break p;
            }
        };
        let (w, h) = (self.c.w as usize, (self.c.h as i32 - TOOL_H) as usize);
        let mut out = alloc::format!("P6\n{} {}\n255\n", w, h).into_bytes();
        out.reserve(w * h * 3);
        for y in TOOL_H..TOOL_H + h as i32 {
            for x in 0..w as i32 {
                let px = self.c.get(x, y);
                out.push((px >> 16) as u8);
                out.push((px >> 8) as u8);
                out.push(px as u8);
            }
        }
        match ustd::write_all(&path, &out) {
            Ok(_) => self.status = alloc::format!("saved {} ({} bytes)", path, out.len()),
            Err(e) => self.status = alloc::format!("save failed: err {}", e),
        }
        self.dirty = true;
    }

    fn redraw(&mut self) {
        // toolbar
        self.c.fill(0, 0, self.c.w as i32, TOOL_H, draw::PANEL);
        self.c.text(
            8,
            5,
            &alloc::format!(
                "brush {} {}{}  b brush  e eraser  [/] size  c clear  s save",
                self.brush,
                if self.eraser { "eraser" } else { "draw" },
                if self.status.is_empty() {
                    String::new()
                } else {
                    alloc::format!("   | {}", self.status)
                }
            ),
            draw::DIM,
            None,
        );
        self.win.present_all();
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[paint] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(120, 90, 640, 460, WIN_DECORATE | WIN_RESIZABLE, "Paint")
        .expect("create window");
    let mut p = Paint {
        win,
        c: win.canvas(),
        last: None,
        brush: 2,
        eraser: false,
        status: String::new(),
        dirty: true,
    };
    // start with a clean canvas below the toolbar
    p.c.fill(0, TOOL_H, p.c.w as i32, p.c.h as i32 - TOOL_H, draw::BLACK);
    loop {
        match wm.next_event(250) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if k.down != 0 && k.key == KeyCode::Char as u32 {
                    match k.chr.to_ascii_lowercase() {
                        b'b' => {
                            p.eraser = false;
                            p.dirty = true;
                        }
                        b'e' => {
                            p.eraser = true;
                            p.dirty = true;
                        }
                        b'c' => {
                            p.c.fill(0, TOOL_H, p.c.w as i32, p.c.h as i32 - TOOL_H, draw::BLACK);
                            p.status = String::from("cleared");
                            p.dirty = true;
                        }
                        b'[' => {
                            p.brush = (p.brush - 1).max(1);
                            p.dirty = true;
                        }
                        b']' => {
                            p.brush = (p.brush + 1).min(8);
                            p.dirty = true;
                        }
                        b's' => p.save(),
                        _ => {}
                    }
                }
            }
            Some((EV_POINTER, pl)) if pl.len() >= 16 => {
                let pt: EvPointer = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if pt.y >= TOOL_H {
                    if pt.buttons & 1 != 0 {
                        p.stroke(pt.x, pt.y);
                    } else if pt.buttons & 2 != 0 {
                        let was = p.eraser;
                        p.eraser = true;
                        p.stroke(pt.x, pt.y);
                        p.eraser = was;
                    } else {
                        p.last = None;
                    }
                } else {
                    p.last = None;
                }
            }
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if p.win.remap(r.shm_id, r.w, r.h) {
                    p.c = p.win.canvas();
                    p.c.fill(0, TOOL_H, p.c.w as i32, p.c.h as i32 - TOOL_H, draw::BLACK);
                    p.win.resize_ack(r.shm_id, r.w, r.h);
                    p.dirty = true;
                }
            }
            _ => {}
        }
        if p.dirty {
            p.dirty = false;
            p.redraw();
        }
    }
}
