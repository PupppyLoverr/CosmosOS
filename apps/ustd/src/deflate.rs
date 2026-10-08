//! DEFLATE encoder (RFC 1951): fixed-Huffman blocks + greedy LZ77 with
//! hash-chain match search, falling back to a stored block when the
//! compressed form would be larger. Output is real DEFLATE, decodable by
//! zlib/gzip/our own `inflate`.
use alloc::vec::Vec;

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
    13, 13,
];

struct W {
    out: Vec<u8>,
    cur: u32,
    n: u32,
}
impl W {
    fn new() -> Self {
        W { out: Vec::new(), cur: 0, n: 0 }
    }
    // extra/parameter bits pack LSB-first
    fn bits(&mut self, v: u32, n: u32) {
        self.cur |= v << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.cur as u8);
            self.cur >>= 8;
            self.n -= 8;
        }
    }
    // huffman codes are stored most-significant-bit first
    fn code(&mut self, c: u32, n: u32) {
        for i in (0..n).rev() {
            self.bits((c >> i) & 1, 1);
        }
    }
    fn flush(&mut self) {
        if self.n > 0 {
            self.out.push(self.cur as u8);
            self.cur = 0;
            self.n = 0;
        }
    }
}

fn lit_code(s: u16) -> (u32, u32) {
    match s {
        0..=143 => (0x30 + s as u32, 8),
        144..=255 => (0x190 + (s - 144) as u32, 9),
        256..=279 => ((s - 256) as u32, 7),
        _ => (0xC0 + (s - 280) as u32, 8),
    }
}

fn len_idx(l: usize) -> usize {
    if l == 258 {
        return 28;
    }
    let mut i = 0;
    while i + 1 < LEN_BASE.len() && LEN_BASE[i + 1] as usize <= l {
        i += 1;
    }
    i
}

fn dist_idx(d: usize) -> usize {
    let mut i = 0;
    while i + 1 < DIST_BASE.len() && DIST_BASE[i + 1] as usize <= d {
        i += 1;
    }
    i
}

const WIN: usize = 32768;
const HBITS: usize = 15;
const MAX_TRIES: usize = 96;

fn hash3(d: &[u8], i: usize) -> usize {
    (((d[i] as usize) << 10) ^ ((d[i + 1] as usize) << 5) ^ d[i + 2] as usize)
        & ((1 << HBITS) - 1)
}

fn deflate_fixed(d: &[u8], w: &mut W) {
    let n = d.len();
    let mut head = alloc::vec![-1i64; 1 << HBITS];
    let mut prev = alloc::vec![-1i64; n + 2];
    let mut i = 0usize;
    while i < n {
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        if i + 3 <= n {
            let h = hash3(d, i);
            let mut cand = head[h];
            let mut tries = MAX_TRIES;
            while cand >= 0 && tries > 0 {
                let c = cand as usize;
                if i - c > WIN {
                    break;
                }
                let max = (n - i).min(258);
                let mut l = 0usize;
                // cheap pre-check on the byte that would beat current best
                if d[c + best_len] == d[i + best_len] {
                    while l < max && d[c + l] == d[i + l] {
                        l += 1;
                    }
                    if l > best_len && l >= 3 {
                        best_len = l;
                        best_dist = i - c;
                        if l == max {
                            break;
                        }
                    }
                }
                cand = prev[c];
                tries -= 1;
            }
        }
        if best_len >= 3 {
            // emit length/distance pair and register every matched position
            let li = len_idx(best_len);
            let (c, cn) = lit_code(257 + li as u16);
            w.code(c, cn);
            w.bits(
                (best_len - LEN_BASE[li] as usize) as u32,
                LEN_EXTRA[li] as u32,
            );
            let di = dist_idx(best_dist);
            w.code(di as u32, 5);
            w.bits(
                (best_dist - DIST_BASE[di] as usize) as u32,
                DIST_EXTRA[di] as u32,
            );
            let end = i + best_len;
            while i < end {
                if i + 3 <= n {
                    let h = hash3(d, i);
                    prev[i] = head[h];
                    head[h] = i as i64;
                }
                i += 1;
            }
        } else {
            let (c, cn) = lit_code(d[i] as u16);
            w.code(c, cn);
            if i + 3 <= n {
                let h = hash3(d, i);
                prev[i] = head[h];
                head[h] = i as i64;
            }
            i += 1;
        }
    }
    let (c, cn) = lit_code(256);
    w.code(c, cn);
}

/// Raw DEFLATE stream. Picks the smaller of a stored block vs a fixed
/// Huffman block (real encoders do the same for incompressible data).
pub fn deflate(d: &[u8]) -> Vec<u8> {
    let mut w = W::new();
    w.bits(1, 1); // BFINAL
    w.bits(1, 2); // BTYPE=01 fixed
    deflate_fixed(d, &mut w);
    w.flush();
    if d.len() < 65536 && w.out.len() >= d.len() + 5 {
        let mut s = W::new();
        s.bits(1, 1); // BFINAL
        s.bits(0, 2); // BTYPE=00 stored
        if s.n > 0 {
            // pad the partial header byte with zeros (stored blocks are
            // byte-aligned) — the 3 bits already in `cur` are the header
            s.out.push(s.cur as u8);
            s.cur = 0;
            s.n = 0;
        }
        let l = d.len() as u16;
        s.out.extend_from_slice(&l.to_le_bytes());
        s.out.extend_from_slice(&(!l).to_le_bytes());
        s.out.extend_from_slice(d);
        return s.out;
    }
    w.out
}

/// gzip member (RFC 1952): header, deflate body, CRC32 + ISIZE trailer.
pub fn gzip_data(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len() / 2 + 64);
    out.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
    out.extend_from_slice(&deflate(d));
    out.extend_from_slice(&crate::inflate::crc32(d).to_le_bytes());
    out.extend_from_slice(&(d.len() as u32).to_le_bytes());
    out
}

/// zlib stream (RFC 1950): 0x78 0x9c + deflate + adler32 BE.
pub fn zlib_data(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len() / 2 + 16);
    out.extend_from_slice(&[0x78, 0x9c]);
    out.extend_from_slice(&deflate(d));
    out.extend_from_slice(&crate::inflate::adler32(d).to_be_bytes());
    out
}
