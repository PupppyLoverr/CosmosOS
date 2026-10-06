//! Immediate-mode 32bpp drawing over a shared surface or the framebuffer.
use crate::font16::FONT16;

#[derive(Clone, Copy)]
pub struct Canvas {
    pub ptr: *mut u32,
    pub w: u32,
    pub h: u32,
    pub stride: u32, // pixels per row
    pub clip: (i32, i32, i32, i32), // (x,y,w,h) — primitives intersect it
}

// Palette (matches winserver chrome; monochrome-first).
pub const BLACK: u32 = 0xFF0A0A0B;
pub const BG: u32 = 0xFF141518;
pub const PANEL: u32 = 0xFF1D1F23;
pub const EDGE: u32 = 0xFF303237;
pub const TEXT: u32 = 0xFFE6E7EA;
pub const DIM: u32 = 0xFF9A9DA3;
pub const ACCENT: u32 = 0xFFD9D9DC;

impl Canvas {
    pub fn new(ptr: *mut u32, w: u32, h: u32, stride: u32) -> Self {
        Self { ptr, w, h, stride, clip: (0, 0, w as i32, h as i32) }
    }

    /// Restrict drawing to a rect (all primitives intersect it). Reset with
    /// `reset_clip` when done — callers that copy may outlive the set.
    pub fn set_clip(&mut self, x: i32, y: i32, w: i32, h: i32) {
        self.clip = (x, y, w, h);
    }
    pub fn reset_clip(&mut self) {
        self.clip = (0, 0, self.w as i32, self.h as i32);
    }

    #[inline]
    pub fn put(&self, x: i32, y: i32, c: u32) {
        let (cx, cy, cw, ch) = self.clip;
        if x >= 0 && y >= 0 && (x as u32) < self.w && (y as u32) < self.h
            && x >= cx && x < cx + cw && y >= cy && y < cy + ch
        {
            unsafe {
                *self.ptr.add(y as usize * self.stride as usize + x as usize) = c;
            }
        }
    }

    #[inline]
    pub fn get(&self, x: i32, y: i32) -> u32 {
        if x >= 0 && y >= 0 && (x as u32) < self.w && (y as u32) < self.h {
            unsafe { *self.ptr.add(y as usize * self.stride as usize + x as usize) }
        } else {
            0
        }
    }

    pub fn fill(&self, x: i32, y: i32, w: i32, h: i32, c: u32) {
        let (cx, cy, cw, ch) = self.clip;
        let x0 = x.max(0).max(cx);
        let y0 = y.max(0).max(cy);
        let x1 = (x + w).min(self.w as i32).min(cx + cw);
        let y1 = (y + h).min(self.h as i32).min(cy + ch);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        for yy in y0..y1 {
            let row = unsafe { self.ptr.add(yy as usize * self.stride as usize + x0 as usize) };
            for xx in 0..(x1 - x0) as usize {
                unsafe { *row.add(xx) = c };
            }
        }
    }

    /// Vertical gradient fill (subtle, used for wallpaper/panels).
    pub fn fill_grad(&self, x: i32, y: i32, w: i32, h: i32, top: u32, bot: u32) {
        if h <= 0 {
            return;
        }
        for i in 0..h {
            let t = (i * 255 / h.max(1)) as u32;
            let c = lerp(top, bot, t);
            self.fill(x, y + i, w, 1, c);
        }
    }

    pub fn border(&self, x: i32, y: i32, w: i32, h: i32, c: u32) {
        self.fill(x, y, w, 1, c);
        self.fill(x, y + h - 1, w, 1, c);
        self.fill(x, y, 1, h, c);
        self.fill(x + w - 1, y, 1, h, c);
    }

    /// Draw one 8x16 glyph. `bg` Some = opaque cell fill.
    pub fn glyph(&self, x: i32, y: i32, ch: u8, fg: u32, bg: Option<u32>) {
        let g = &FONT16[ch as usize];
        for (row, &bits) in g.iter().enumerate() {
            if let Some(b) = bg {
                self.fill(x, y + row as i32, 8, 1, b);
            }
            for col in 0..8 {
                if bits & (0x80 >> col) != 0 {
                    self.put(x + col, y + row as i32, fg);
                }
            }
        }
    }

    /// Draw a NUL-free &str at (x,y); returns end x.
    pub fn text(&self, x: i32, y: i32, s: &str, fg: u32, bg: Option<u32>) -> i32 {
        let mut cx = x;
        for b in s.bytes() {
            let g = if (0x20..=0xFE).contains(&b) { b } else { b'?' };
            self.glyph(cx, y, g, fg, bg);
            cx += 8;
        }
        cx
    }

    /// Text width in pixels.
    pub fn text_w(s: &str) -> i32 {
        s.len() as i32 * 8
    }

    /// Draw a single-line clipped label centered in a rect.
    pub fn label(&self, x: i32, y: i32, w: i32, s: &str, fg: u32) {
        let mut cx = x + 4;
        let max_x = x + w - 4;
        for b in s.bytes() {
            if cx + 8 > max_x {
                break;
            }
            self.glyph(cx, y, b, fg, None);
            cx += 8;
        }
    }

    /// Copy a rect within the canvas (for terminal scroll / drag effects).
    pub fn copy_rect(&self, sx: i32, sy: i32, dx: i32, dy: i32, w: i32, h: i32) {
        // copy via temp buffer rows to stay safe on overlap
        let mut line = alloc::vec::Vec::with_capacity(w as usize);
        for row in 0..h {
            line.clear();
            for col in 0..w {
                line.push(self.get(sx + col, sy + row));
            }
            for (col, &px) in line.iter().enumerate() {
                self.put(dx + col as i32, dy + row, px);
            }
        }
    }

    /// Scroll the whole canvas up by `dy` pixels, filling the vacated area.
    pub fn scroll_up(&self, dy: i32, fill: u32) {
        if dy <= 0 {
            return;
        }
        if dy as u32 >= self.h {
            self.fill(0, 0, self.w as i32, self.h as i32, fill);
            return;
        }
        self.copy_rect(0, dy, 0, 0, self.w as i32, self.h as i32 - dy);
        self.fill(0, self.h as i32 - dy, self.w as i32, dy, fill);
    }

    /// Fill with alpha blending over existing pixels.
    pub fn fill_alpha(&self, x: i32, y: i32, w: i32, h: i32, c: u32, a: u32) {
        let x0 = x.max(0);
        let y0 = y.max(0);
        let x1 = (x + w).min(self.w as i32);
        let y1 = (y + h).min(self.h as i32);
        for yy in y0..y1 {
            for xx in x0..x1 {
                let d = self.get(xx, yy);
                self.put(xx, yy, lerp(d, c, a));
            }
        }
    }
}

/// lerp between two ARGB colors, t in 0..=255 (channel-wise).
pub fn lerp(a: u32, b: u32, t: u32) -> u32 {
    let t = t.min(255);
    let inv = 255 - t;
    let ar = ((a >> 16) & 0xFF) * inv;
    let ag = ((a >> 8) & 0xFF) * inv;
    let ab = (a & 0xFF) * inv;
    let br = ((b >> 16) & 0xFF) * t;
    let bg = ((b >> 8) & 0xFF) * t;
    let bb = (b & 0xFF) * t;
    let alpha = (((a >> 24) & 0xFF) * inv + ((b >> 24) & 0xFF) * t) / 255;
    (alpha << 24) | (((ar + br) / 255) << 16) | (((ag + bg) / 255) << 8) | ((ab + bb) / 255)
}
