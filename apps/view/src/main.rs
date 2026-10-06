//! cosmos-view: a real image viewer for binary PPM (P6) files — the format
//! Paint saves. Opens `/x.ppm`, scales down by integer factor to fit the
//! window, +/= and - zoom, arrows/hjkl pan, q/Esc quits.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

struct Img {
    w: usize,
    h: usize,
    px: Vec<u8>, // RGB triplets
}

/// Parse a binary P6 PPM: `P6` ws W ws H ws MAXVAL 1ws data.
/// Comments (`#` to end-of-line) may appear after any token.
fn parse_ppm(d: &[u8]) -> Option<Img> {
    if d.len() < 3 || &d[0..2] != b"P6" {
        return None;
    }
    let mut i = 2usize;
    // token reader: skips whitespace + comments
    let mut tok = |i: &mut usize| -> Option<usize> {
        loop {
            while *i < d.len() && (d[*i] as char).is_whitespace() {
                *i += 1;
            }
            if *i < d.len() && d[*i] == b'#' {
                while *i < d.len() && d[*i] != b'\n' {
                    *i += 1;
                }
                continue;
            }
            break;
        }
        let mut v = 0usize;
        let mut any = false;
        while *i < d.len() && d[*i].is_ascii_digit() {
            v = v * 10 + (d[*i] - b'0') as usize;
            any = true;
            *i += 1;
        }
        if any {
            Some(v)
        } else {
            None
        }
    };
    let w = tok(&mut i)?;
    let h = tok(&mut i)?;
    let max = tok(&mut i)?;
    if w == 0 || h == 0 || max != 255 || w > 4096 || h > 4096 {
        return None;
    }
    i += 1; // exactly one whitespace byte after maxval
    if i + w * h * 3 > d.len() {
        return None;
    }
    Some(Img {
        w,
        h,
        px: d[i..i + w * h * 3].to_vec(),
    })
}

struct View {
    win: Window,
    c: Canvas,
    img: Img,
    path: String,
    zoom: i32,  // 0 = fit-to-window; >0 = integer scale 1..8
    ox: i32,    // pan origin in canvas pixels (can be negative)
    oy: i32,
    dirty: bool,
}

impl View {
    /// Draw scale for the current mode (fit picks the largest integer
    /// downscale that shows the whole image; zoom N draws at 1/N source px).
    fn scale(&self) -> i32 {
        if self.zoom > 0 {
            self.zoom
        } else {
            let sx = (self.img.w as i32 + self.c.w as i32 - 1) / self.c.w as i32;
            let sy = (self.img.h as i32 + (self.c.h as i32 - 22) - 1) / (self.c.h as i32 - 22).max(1);
            sx.max(sy).max(1)
        }
    }

    fn px_at(&self, ix: usize, iy: usize) -> u32 {
        let o = (iy * self.img.w + ix) * 3;
        ((self.img.px[o] as u32) << 16) | ((self.img.px[o + 1] as u32) << 8) | self.img.px[o + 2] as u32
    }

    /// Origin that centers the image in the canvas at scale `s`.
    fn centered(&self, s: i32) -> (i32, i32) {
        (
            (self.c.w as i32 - self.img.w as i32 / s) / 2,
            (self.c.h as i32 - 22 - self.img.h as i32 / s) / 2,
        )
    }

    fn redraw(&mut self) {
        let s = self.scale();
        // image area
        self.c.fill(0, 0, self.c.w as i32, self.c.h as i32 - 22, 0xFF1A1B1D);
        let dw = self.img.w as i32 / s;
        let dh = self.img.h as i32 / s;
        let mut cx = if self.zoom == 0 {
            (self.c.w as i32 - dw) / 2
        } else {
            self.ox
        };
        let mut cy = if self.zoom == 0 {
            (self.c.h as i32 - 22 - dh) / 2
        } else {
            self.oy
        };
        cx = cx.min(self.c.w as i32 - 1);
        cy = cy.min(self.c.h as i32 - 23);
        for y in 0..dh {
            let sy_px = (y * s) as usize;
            let dy = cy + y;
            if dy < 0 || dy >= self.c.h as i32 - 22 {
                continue;
            }
            for x in 0..dw {
                let dx = cx + x;
                if dx < 0 || dx >= self.c.w as i32 {
                    continue;
                }
                self.c.put(dx, dy, self.px_at((x * s) as usize, sy_px));
            }
        }
        // status bar
        self.c.fill(0, self.c.h as i32 - 22, self.c.w as i32, 22, draw::PANEL);
        self.c.text(
            8,
            self.c.h as i32 - 17,
            &alloc::format!(
                "{}  {}x{}  1/{}x   +/- zoom  arrows pan  f fit  q quit",
                self.path, self.img.w, self.img.h, s
            ),
            draw::DIM,
            None,
        );
        self.win.present_all();
    }

    fn pan(&mut self, dx: i32, dy: i32) {
        if self.zoom > 0 {
            self.ox += dx;
            self.oy += dy;
            self.dirty = true;
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(args_ptr: u64, args_len: u64) -> i64 {
    println!("[view] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let args = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
            args_ptr as *const u8,
            args_len as usize,
        ))
    };
    let path = String::from(args.trim());
    let win = wm
        .create_window(140, 80, 640, 500, WIN_DECORATE | WIN_RESIZABLE, "View")
        .expect("create window");
    let rd = ustd::read_all(&path);
    let mut v = match rd.ok().and_then(|d| parse_ppm(&d)) {
        Some(img) => View {
            win,
            c: win.canvas(),
            img,
            path,
            zoom: 0,
            ox: 0,
            oy: 0,
            dirty: true,
        },
        None => {
            // not a P6 PPM (or unreadable): say so in the window
            let mut v = View {
                win,
                c: win.canvas(),
                img: Img { w: 0, h: 0, px: Vec::new() },
                path,
                zoom: 0,
                ox: 0,
                oy: 0,
                dirty: false,
            };
            v.c.fill(0, 0, v.c.w as i32, v.c.h as i32, draw::BLACK);
            v.c.text(16, 20, "not a P6 PPM (or unreadable)", draw::TEXT, None);
            v.c.text(16, 40, "usage: view <file.ppm>   q quits", draw::DIM, None);
            v.win.present_all();
            v
        }
    };
    loop {
        match wm.next_event(250) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if k.down == 0 {
                    continue;
                }
                match k.key {
                    x if x == KeyCode::Escape as u32 => return 0,
                    x if x == KeyCode::Left as u32 => v.pan(24, 0),
                    x if x == KeyCode::Right as u32 => v.pan(-24, 0),
                    x if x == KeyCode::Up as u32 => v.pan(0, 24),
                    x if x == KeyCode::Down as u32 => v.pan(0, -24),
                    x if x == KeyCode::Char as u32 => match k.chr.to_ascii_lowercase() {
                        b'q' => return 0,
                        b'+' | b'=' => {
                            v.zoom = (v.zoom - 1).max(1);
                            let (ox, oy) = v.centered(v.zoom);
                            v.ox = ox;
                            v.oy = oy;
                            v.dirty = true;
                        }
                        b'-' | b'_' => {
                            v.zoom = (v.zoom + 1).min(8);
                            let (ox, oy) = v.centered(v.zoom);
                            v.ox = ox;
                            v.oy = oy;
                            v.dirty = true;
                        }
                        b'f' => {
                            v.zoom = 0;
                            v.dirty = true;
                        }
                        b'h' => v.pan(24, 0),
                        b'l' => v.pan(-24, 0),
                        b'k' => v.pan(0, 24),
                        b'j' => v.pan(0, -24),
                        _ => {}
                    },
                    _ => {}
                }
            }
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if v.win.remap(r.shm_id, r.w, r.h) {
                    v.c = v.win.canvas();
                    v.win.resize_ack(r.shm_id, r.w, r.h);
                    v.dirty = true;
                }
            }
            _ => {}
        }
        if v.dirty {
            v.dirty = false;
            v.redraw();
        }
    }
}
