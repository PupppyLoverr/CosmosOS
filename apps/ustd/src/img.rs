//! Real image decoders: binary/ASCII PPM, uncompressed BMP (24/32-bit
//! BI_RGB), and QOI. `decode` sniffs the format from the bytes.
//! Output pixels are 0xRRGGBB rows (`w*h` long).

use alloc::vec::Vec;

pub struct Img {
    pub w: usize,
    pub h: usize,
    pub px: Vec<u32>,
}

pub fn decode(d: &[u8]) -> Option<Img> {
    ppm(d).or_else(|| bmp(d)).or_else(|| qoi(d))
}

/// Nearest-neighbour scale of `img` into a `w*h` 0xRRGGBB buffer.
pub fn scale(img: &Img, w: usize, h: usize) -> Vec<u32> {
    let mut out = alloc::vec![0u32; w * h];
    if img.w == 0 || img.h == 0 {
        return out;
    }
    for y in 0..h {
        let sy = y * img.h / h;
        for x in 0..w {
            let sx = x * img.w / w;
            out[y * w + x] = img.px[sy * img.w + sx];
        }
    }
    out
}

// ---------------- PPM (P6 binary, P3 ASCII) ----------------
fn ppm(d: &[u8]) -> Option<Img> {
    if d.len() < 3 || d[0] != b'P' || (d[1] != b'6' && d[1] != b'3') {
        return None;
    }
    let ascii = d[1] == b'3';
    let mut i = 2usize;
    // token reader: skips whitespace + `#` comments
    macro_rules! tok {
        () => {{
            loop {
                while i < d.len() && (d[i] as char).is_whitespace() {
                    i += 1;
                }
                if i < d.len() && d[i] == b'#' {
                    while i < d.len() && d[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                break;
            }
            let mut v = 0usize;
            let mut any = false;
            while i < d.len() && d[i].is_ascii_digit() {
                v = v * 10 + (d[i] - b'0') as usize;
                any = true;
                i += 1;
            }
            if any {
                Some(v)
            } else {
                None
            }
        }};
    }
    let w = tok!()?;
    let h = tok!()?;
    let max = tok!()?;
    if w == 0 || h == 0 || max == 0 || max > 255 || w > 8192 || h > 8192 {
        return None;
    }
    let mut px = Vec::with_capacity(w * h);
    if ascii {
        for _ in 0..w * h {
            let (r, g, b) = (tok!()?, tok!()?, tok!()?);
            let (r, g, b) = (r * 255 / max, g * 255 / max, b * 255 / max);
            px.push(((r as u32) << 16) | ((g as u32) << 8) | b as u32);
        }
    } else {
        i += 1; // single whitespace after maxval
        if i + w * h * 3 > d.len() {
            return None;
        }
        for p in 0..w * h {
            let (r, g, b) = (
                d[i + p * 3] as usize,
                d[i + p * 3 + 1] as usize,
                d[i + p * 3 + 2] as usize,
            );
            let (r, g, b) = (r * 255 / max, g * 255 / max, b * 255 / max);
            px.push(((r as u32) << 16) | ((g as u32) << 8) | b as u32);
        }
    }
    Some(Img { w, h, px })
}

// ---------------- BMP (uncompressed 24/32-bit BI_RGB) ----------------
fn bmp(d: &[u8]) -> Option<Img> {
    if d.len() < 54 || &d[0..2] != b"BM" {
        return None;
    }
    let u32l = |o: usize| -> u32 {
        u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
    };
    let u16l = |o: usize| -> u16 { u16::from_le_bytes([d[o], d[o + 1]]) };
    let off = u32l(10) as usize;
    let dib = u32l(14) as usize;
    if dib < 40 {
        return None;
    }
    let w = u32l(18) as i32;
    let h_raw = u32l(22) as i32;
    let top_down = h_raw < 0;
    let h = h_raw.abs();
    let planes = u16l(26);
    let bpp = u16l(28);
    let comp = u32l(30);
    if planes != 1 || comp != 0 || (bpp != 24 && bpp != 32) || w <= 0 || h <= 0 {
        return None;
    }
    let (w, h) = (w as usize, h as usize);
    if w > 8192 || h > 8192 {
        return None;
    }
    let stride = (w * (bpp as usize) / 8 + 3) & !3;
    if off + stride * h > d.len() {
        return None;
    }
    let mut px = alloc::vec![0u32; w * h];
    for y in 0..h {
        let sy = if top_down { y } else { h - 1 - y };
        let row = off + sy * stride;
        for x in 0..w {
            let p = row + x * (bpp as usize) / 8;
            let (b, g, r) = (d[p] as u32, d[p + 1] as u32, d[p + 2] as u32);
            px[y * w + x] = (r << 16) | (g << 8) | b;
        }
    }
    Some(Img { w, h, px })
}

// ---------------- QOI ----------------
fn qoi(d: &[u8]) -> Option<Img> {
    if d.len() < 14 + 8 || &d[0..4] != b"qoif" {
        return None;
    }
    let w = u32::from_be_bytes([d[4], d[5], d[6], d[7]]) as usize;
    let h = u32::from_be_bytes([d[8], d[9], d[10], d[11]]) as usize;
    if w == 0 || h == 0 || w > 8192 || h > 8192 {
        return None;
    }
    let mut px = Vec::with_capacity(w * h);
    let mut index = [(0u8, 0u8, 0u8, 0u8); 64];
    let (mut r, mut g, mut b, mut a) = (0u8, 0u8, 0u8, 255u8);
    let mut i = 14usize;
    let total = w * h;
    let mut run = 0usize;
    while px.len() < total && i < d.len() {
        if run > 0 {
            run -= 1;
        } else {
            let v = d[i];
            i += 1;
            match v {
                0xFE => {
                    if i + 3 > d.len() {
                        return None;
                    }
                    r = d[i];
                    g = d[i + 1];
                    b = d[i + 2];
                    i += 3;
                }
                0xFF => {
                    if i + 4 > d.len() {
                        return None;
                    }
                    r = d[i];
                    g = d[i + 1];
                    b = d[i + 2];
                    a = d[i + 3];
                    i += 4;
                }
                _ => match v >> 6 {
                    0 => {
                        // QOI_OP_INDEX
                        let (ir, ig, ib, ia) = index[(v & 0x3F) as usize];
                        r = ir;
                        g = ig;
                        b = ib;
                        a = ia;
                    }
                    1 => {
                        // QOI_OP_DIFF
                        r = r.wrapping_add(((v >> 4) & 3).wrapping_sub(2));
                        g = g.wrapping_add(((v >> 2) & 3).wrapping_sub(2));
                        b = b.wrapping_add((v & 3).wrapping_sub(2));
                    }
                    2 => {
                        // QOI_OP_LUMA
                        if i >= d.len() {
                            return None;
                        }
                        let b2 = d[i];
                        i += 1;
                        let dg = (v & 0x3F) as i32 - 32;
                        let dr = dg + ((b2 >> 4) & 0xF) as i32 - 8;
                        let db = dg + (b2 & 0xF) as i32 - 8;
                        r = (r as i32 + dr).clamp(0, 255) as u8;
                        g = (g as i32 + dg).clamp(0, 255) as u8;
                        b = (b as i32 + db).clamp(0, 255) as u8;
                    }
                    _ => {
                        // QOI_OP_RUN
                        run = (v & 0x3F) as usize; // (v&0x3f)+1 total, one emitted below
                    }
                },
            }
            index[((r as usize * 3 + g as usize * 5 + b as usize * 7 + a as usize * 11) % 64)] =
                (r, g, b, a);
        }
        px.push(((r as u32) << 16) | ((g as u32) << 8) | b as u32);
    }
    if px.len() != total {
        return None;
    }
    Some(Img { w, h, px })
}
