//! DEFLATE (RFC 1951) decoder — real zlib/gzip decompression.
//! Huffman decoding is canonical code-lengths with bit-reversed stream order,
//! LZ77 copy distances/history included. Integer-only, no_std.

use alloc::vec::Vec;

const MAX_BITS: usize = 15;

struct Bits<'a> {
    d: &'a [u8],
    pos: usize, // byte position
    bit: u32,   // 0..8 within current byte
}

impl<'a> Bits<'a> {
    fn new(d: &'a [u8]) -> Self {
        Bits { d, pos: 0, bit: 0 }
    }
    /// Read `n` bits (LSB-first packing per RFC 1951).
    fn bits(&mut self, n: u32) -> Result<u32, &'static str> {
        let mut v = 0u32;
        for i in 0..n {
            if self.pos >= self.d.len() {
                return Err("truncated deflate stream");
            }
            let b = (self.d[self.pos] >> self.bit) & 1;
            v |= (b as u32) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.pos += 1;
            }
        }
        Ok(v)
    }
    /// Byte-align (start of a stored block).
    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }
}

/// Canonical Huffman decoder built from code lengths.
struct Huff {
    /// count[n] = # symbols with code length n; offsets[n] = first symbol index
    count: [u16; MAX_BITS + 1],
    /// symbols sorted by (len, symbol)
    syms: Vec<u16>,
}

impl Huff {
    fn new(lens: &[u8]) -> Result<Self, &'static str> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lens {
            if l as usize > MAX_BITS {
                return Err("bad huffman code length");
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut offs = [0usize; MAX_BITS + 1];
        for i in 1..MAX_BITS {
            offs[i + 1] = offs[i] + count[i] as usize;
        }
        let mut syms = alloc::vec![0u16; lens.len()];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                syms[offs[l as usize]] = s as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huff { count, syms })
    }
    /// Decode one symbol. Stream reads codes MSB-first within each code.
    fn sym(&self, b: &mut Bits) -> Result<u16, &'static str> {
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0u32;
        for len in 1..=MAX_BITS {
            code |= b.bits(1)?;
            let cnt = self.count[len] as u32;
            if code < first + cnt {
                return Ok(self.syms[(index + (code - first)) as usize]);
            }
            index += cnt;
            first = (first + cnt) << 1;
            code <<= 1;
        }
        Err("bad huffman symbol")
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
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
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn fixed_tables() -> (Huff, Huff) {
    let mut lit = [0u8; 288];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist = [5u8; 30];
    (
        Huff::new(&lit).unwrap(),
        Huff::new(&dist).unwrap(),
    )
}

fn dynamic_tables(b: &mut Bits) -> Result<(Huff, Huff), &'static str> {
    let hlit = b.bits(5)? as usize + 257;
    let hdist = b.bits(5)? as usize + 1;
    let hclen = b.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err("bad table sizes");
    }
    let mut cl = [0u8; 19];
    for i in 0..hclen {
        cl[CLEN_ORDER[i]] = b.bits(3)? as u8;
    }
    let clh = Huff::new(&cl)?;
    let mut lens = alloc::vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < hlit + hdist {
        let s = clh.sym(b)?;
        match s {
            0..=15 => {
                lens[i] = s as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err("repeat with no prior length");
                }
                let prev = lens[i - 1];
                let rep = 3 + b.bits(2)? as usize;
                for _ in 0..rep {
                    if i >= lens.len() {
                        return Err("length overflow");
                    }
                    lens[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let rep = 3 + b.bits(3)? as usize;
                i += rep;
                if i > lens.len() {
                    return Err("length overflow");
                }
            }
            18 => {
                let rep = 11 + b.bits(7)? as usize;
                i += rep;
                if i > lens.len() {
                    return Err("length overflow");
                }
            }
            _ => return Err("bad code-length symbol"),
        }
    }
    let lit = Huff::new(&lens[..hlit])?;
    let dist = Huff::new(&lens[hlit..])?;
    Ok((lit, dist))
}

/// Inflate a raw DEFLATE stream. Returns the decompressed bytes.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut b = Bits::new(data);
    let mut out = Vec::new();
    loop {
        let last = b.bits(1)?;
        let ty = b.bits(2)?;
        match ty {
            0 => {
                b.align();
                if b.pos + 4 > b.d.len() {
                    return Err("truncated stored block");
                }
                let len = u16::from_le_bytes([b.d[b.pos], b.d[b.pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([b.d[b.pos + 2], b.d[b.pos + 3]]);
                if nlen != !(len as u16) {
                    return Err("stored block LEN/NLEN mismatch");
                }
                b.pos += 4;
                if b.pos + len > b.d.len() {
                    return Err("truncated stored data");
                }
                out.extend_from_slice(&b.d[b.pos..b.pos + len]);
                b.pos += len;
            }
            1 | 2 => {
                let (lit, dist) = if ty == 1 {
                    fixed_tables()
                } else {
                    dynamic_tables(&mut b)?
                };
                loop {
                    let s = lit.sym(&mut b)?;
                    match s {
                        0..=255 => out.push(s as u8),
                        256 => break,
                        257..=285 => {
                            let i = (s - 257) as usize;
                            if i >= LEN_BASE.len() {
                                return Err("bad length symbol");
                            }
                            let len = LEN_BASE[i] as usize
                                + b.bits(LEN_EXTRA[i] as u32)? as usize;
                            let ds = dist.sym(&mut b)? as usize;
                            if ds >= DIST_BASE.len() {
                                return Err("bad distance symbol");
                            }
                            let d = DIST_BASE[ds] as usize
                                + b.bits(DIST_EXTRA[ds] as u32)? as usize;
                            if d > out.len() {
                                return Err("distance too far back");
                            }
                            let start = out.len() - d;
                            for k in 0..len {
                                let v = out[start + k];
                                out.push(v);
                            }
                        }
                        _ => return Err("bad literal/length symbol"),
                    }
                }
            }
            _ => return Err("reserved block type"),
        }
        if last == 1 {
            return Ok(out);
        }
    }
}

/// Unwrap a zlib (RFC 1950) stream: 2-byte header, deflate body, adler32 tail.
/// Returns the inflate payload slice to feed `inflate`.
pub fn zlib_body(d: &[u8]) -> Result<&[u8], &'static str> {
    if d.len() < 6 || d[0] & 0x0F != 8 || (d[0] as u32 * 256 + d[1] as u32) % 31 != 0 {
        return Err("not a zlib stream");
    }
    Ok(&d[2..d.len() - 4])
}

/// Parse a gzip (RFC 1952) header, returning the deflate body start offset.
pub fn gzip_body(d: &[u8]) -> Result<usize, &'static str> {
    if d.len() < 10 || d[0] != 0x1f || d[1] != 0x8b || d[2] != 8 {
        return Err("not a gzip stream");
    }
    let flg = d[3];
    let mut p = 10;
    if flg & 4 != 0 {
        // FEXTRA
        if p + 2 > d.len() {
            return Err("truncated gzip");
        }
        let xlen = u16::from_le_bytes([d[p], d[p + 1]]) as usize;
        p += 2 + xlen;
    }
    for flag in [8u8, 16u8] {
        if flg & flag != 0 {
            // FNAME / FCOMMENT: NUL-terminated
            while p < d.len() && d[p] != 0 {
                p += 1;
            }
            p += 1;
        }
    }
    if flg & 2 != 0 {
        p += 2; // FHCRC
    }
    if p >= d.len() {
        return Err("truncated gzip");
    }
    Ok(p)
}

/// adler32 for zlib stream verification.
pub fn adler32(d: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &x in d {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Reflected CRC32 (poly 0xEDB88320) — the ZIP/gzip kind.
pub fn crc32(data: &[u8]) -> u32 {
    let mut tbl = [0u32; 256];
    for (i, e) in tbl.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        *e = c;
    }
    let mut crc = !0u32;
    for b in data {
        crc = tbl[((crc ^ *b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}
