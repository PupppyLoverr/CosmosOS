//! cosmos-terminal: a real shell in a window. Line editing, history, and
//! commands that exercise the true filesystem/process syscalls.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

const COLS: usize = 90;
const ROWS: usize = 40;
const CW: i32 = 8;
const CH: i32 = 16;

const DIM_CAL: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"];

fn cal_leap(y: u16) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Days since 1970-01-01 (a Thursday) for y-01-01 + in-year offset.
fn cal_days(y: u16, m: u8, d: u8) -> u64 {
    let mut n = 0u64;
    for yy in 1970..y {
        n += if cal_leap(yy) { 366 } else { 365 };
    }
    for mm in 1..m {
        n += DIM_CAL[(mm - 1) as usize] as u64 + if mm == 2 && cal_leap(y) { 1 } else { 0 };
    }
    n + d as u64 - 1
}

/// Split a statement at its first top-level `;`, `&&` or `||`
/// (returns (before, op, after)). Single `|` (pipe) does not match.
fn stmt_split(s: &str) -> Option<(&str, u8, &str)> {
    let b = s.as_bytes();
    let mut i = 0;
    let (mut sq, mut dq) = (false, false);
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b';' if !sq && !dq => return Some((&s[..i], b';', &s[i + 1..])),
            b'&' if !sq && !dq && i + 1 < b.len() && b[i + 1] == b'&' => {
                return Some((&s[..i], b'&', &s[i + 2..]));
            }
            b'|' if !sq && !dq && i + 1 < b.len() && b[i + 1] == b'|' => {
                return Some((&s[..i], b'|', &s[i + 2..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// First byte index of `want` that is NOT inside '...' or "..." quotes.
fn find_unquoted(s: &str, want: u8) -> Option<usize> {
    let b = s.as_bytes();
    let (mut sq, mut dq) = (false, false);
    for i in 0..b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            x if x == want && !sq && !dq => return Some(i),
            _ => {}
        }
    }
    None
}

/// Shell word-splitting: whitespace separates, '...' and "..." group (and are
/// stripped). Returns (word, was_quoted) per token — quoted words are exempt
/// from glob expansion, like a real shell.
fn tokenize(s: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut sq, mut dq) = (false, false);
    let mut quoted = false;
    let mut any = false;
    for c in s.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                quoted = true;
                any = true;
            }
            '"' if !sq => {
                dq = !dq;
                quoted = true;
                any = true;
            }
            c if c.is_whitespace() && !sq && !dq => {
                if any {
                    out.push((core::mem::take(&mut cur), quoted));
                    quoted = false;
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push((cur, quoted));
    }
    out
}

/// Unix epoch seconds -> (y, m, d, h, min, s) UTC.
fn epoch_to_dt(secs: u64) -> (u16, u8, u8, u8, u8, u8) {
    let mut d = secs / 86400;
    let rem = secs % 86400;
    let mut y = 1970u16;
    loop {
        let dy = if cal_leap(y) { 366 } else { 365 };
        if d >= dy { d -= dy; y += 1; } else { break; }
    }
    let mut m = 1u8;
    loop {
        let dm = DIM_CAL[(m - 1) as usize] as u64 + if m == 2 && cal_leap(y) { 1 } else { 0 };
        if d >= dm { d -= dm; m += 1; } else { break; }
    }
    (
        y,
        m,
        d as u8 + 1,
        (rem / 3600) as u8,
        ((rem % 3600) / 60) as u8,
        (rem % 60) as u8,
    )
}

/// Render one month as text lines (Sunday-first), or mark today.
fn cal_render(m: u8, y: u16) -> Vec<String> {
    let mut out = Vec::new();
    let title = alloc::format!("{} {}", MONTHS[(m - 1) as usize], y);
    let pad = (20usize.saturating_sub(title.len())) / 2;
    out.push(alloc::format!("{}{}", " ".repeat(pad), title));
    out.push(String::from("Su Mo Tu We Th Fr Sa"));
    let first_wd = ((cal_days(y, m, 1) + 4) % 7) as usize; // 0=Sunday
    let dim = DIM_CAL[(m - 1) as usize] + if m == 2 && cal_leap(y) { 1 } else { 0 };
    let mut line = String::from("   ".repeat(first_wd));
    for d in 1..=dim {
        line.push_str(&alloc::format!("{:>2} ", d));
        if (first_wd + d as usize) % 7 == 0 || d == dim {
            out.push(String::from(line.trim_end()));
            line.clear();
        }
    }
    out
}

/// Integer expression evaluator: + - * / % ( ) unary-minus.
/// No floats (userspace has no SSE state switching).
fn expr_eval(s: &str) -> Result<i64, &'static str> {
    let mut p = ExprP { b: s.as_bytes(), i: 0 };
    let v = p.expr()?;
    p.ws();
    if p.i != p.b.len() { return Err("trailing characters"); }
    Ok(v)
}

struct ExprP<'a> { b: &'a [u8], i: usize }

impl<'a> ExprP<'a> {
    fn ws(&mut self) { while self.i < self.b.len() && self.b[self.i] == b' ' { self.i += 1; } }
    fn peek(&mut self) -> Option<u8> { self.ws(); self.b.get(self.i).copied() }
    fn eat(&mut self, c: u8) -> bool { if self.peek() == Some(c) { self.i += 1; true } else { false } }
    fn expr(&mut self) -> Result<i64, &'static str> {
        let mut v = self.term()?;
        loop {
            if self.eat(b'+') { v = v.checked_add(self.term()?).ok_or("overflow")?; }
            else if self.eat(b'-') { v = v.checked_sub(self.term()?).ok_or("overflow")?; }
            else { break; }
        }
        Ok(v)
    }
    fn term(&mut self) -> Result<i64, &'static str> {
        let mut v = self.factor()?;
        loop {
            if self.eat(b'*') { v = v.checked_mul(self.factor()?).ok_or("overflow")?; }
            else if self.eat(b'/') {
                let d = self.factor()?;
                if d == 0 { return Err("division by zero"); }
                v /= d;
            } else if self.eat(b'%') {
                let d = self.factor()?;
                if d == 0 { return Err("division by zero"); }
                v %= d;
            } else { break; }
        }
        Ok(v)
    }
    fn factor(&mut self) -> Result<i64, &'static str> {
        if self.eat(b'(') {
            let v = self.expr()?;
            if !self.eat(b')') { return Err("missing )"); }
            return Ok(v);
        }
        if self.eat(b'-') { return Ok(-self.factor()?); }
        self.ws();
        let s = self.i;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() { self.i += 1; }
        if s == self.i { return Err("expected number"); }
        core::str::from_utf8(&self.b[s..self.i]).unwrap_or("").parse::<i64>().map_err(|_| "bad number")
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut i = 0;
    for part in s.split('.') {
        if i >= 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        let mut v: u32 = 0;
        for c in part.bytes() {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as u32;
        }
        if v > 255 {
            return None;
        }
        out[i] = v as u8;
        i += 1;
    }
    if i == 4 { Some(out) } else { None }
}

/// IPv4 literal or DNS name — tries the literal first, then a real
/// DNS query (UDP/53).
fn host_arg(s: &str) -> Option<[u8; 4]> {
    parse_ipv4(s).or_else(|| ustd::net_dns(s))
}

/// Shell-style wildcard match: `*` (any run) and `?` (single char).
fn wild_match(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_p, mut star_s) = (usize::MAX, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_p = pi;
            star_s = si;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_s += 1;
            si = star_s;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Classic unified-hunk diff on two line slices: trims the common
/// prefix/suffix, runs LCS on the differing middle, emits `n a/m/d` blocks
/// in the style of traditional diff output. Bounded: caps each side at
/// 1024 lines so the O(m*n) LCS table stays under ~4 MiB.
fn diff_lines(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    // trim shared prefix / suffix
    let mut lo = 0usize;
    let (mut ahi, mut bhi) = (a.len(), b.len());
    while lo < ahi && lo < bhi && a[lo] == b[lo] {
        lo += 1;
    }
    while ahi > lo && bhi > lo && a[ahi - 1] == b[bhi - 1] {
        ahi -= 1;
        bhi -= 1;
    }
    let (am, bm) = (&a[lo..ahi], &b[lo..bhi]);
    let (m, n) = (am.len(), bm.len());
    if m == 0 && n == 0 {
        return out;
    }
    // LCS length table (m+1 x n+1)
    let mut t = alloc::vec![0u32; (m + 1) * (n + 1)];
    for i in (0..m).rev() {
        for j in (0..n).rev() {
            t[i * (n + 1) + j] = if am[i] == bm[j] {
                t[(i + 1) * (n + 1) + j + 1] + 1
            } else {
                t[(i + 1) * (n + 1) + j].max(t[i * (n + 1) + j + 1])
            };
        }
    }
    // backtrack: flat op list — 0=eq(skip),1=del,2=add — then group
    // consecutive non-eq ops into one hunk
    #[derive(Clone, Copy)]
    enum Op {
        Eq,
        Del(usize),
        Add(usize),
    }
    let mut ops: Vec<Op> = Vec::with_capacity(m + n);
    let (mut i, mut j) = (0usize, 0usize);
    while i < m && j < n {
        if am[i] == bm[j] {
            ops.push(Op::Eq);
            i += 1;
            j += 1;
        } else if t[(i + 1) * (n + 1) + j] >= t[i * (n + 1) + j + 1] {
            ops.push(Op::Del(i));
            i += 1;
        } else {
            ops.push(Op::Add(j));
            j += 1;
        }
    }
    while i < m {
        ops.push(Op::Del(i));
        i += 1;
    }
    while j < n {
        ops.push(Op::Add(j));
        j += 1;
    }
    let mut k = 0usize;
    let (mut a_cur, mut b_cur) = (0usize, 0usize);
    while k < ops.len() {
        if matches!(ops[k], Op::Eq) {
            a_cur += 1;
            b_cur += 1;
            k += 1;
            continue;
        }
        // hunk: run of Del/Add ops
        let (mut dels, mut adds) = (Vec::new(), Vec::new());
        let (a0, b0) = (a_cur, b_cur);
        while k < ops.len() {
            match ops[k] {
                Op::Del(di) => {
                    dels.push(di);
                    a_cur += 1;
                }
                Op::Add(ai) => {
                    adds.push(ai);
                    b_cur += 1;
                }
                Op::Eq => break,
            }
            k += 1;
        }
        let (a1, b1) = (a_cur, b_cur);
        if dels.is_empty() {
            out.push(alloc::format!("{}a{}", a0 + lo, rng(b0 + lo, b1 + lo)));
            for &x in &adds {
                out.push(alloc::format!("> {}", bm[x]));
            }
        } else if adds.is_empty() {
            out.push(alloc::format!("{}d{}", rng(a0 + lo, a1 + lo), b0 + lo));
            for &x in &dels {
                out.push(alloc::format!("< {}", am[x]));
            }
        } else {
            out.push(alloc::format!("{}c{}", rng(a0 + lo, a1 + lo), rng(b0 + lo, b1 + lo)));
            for &x in &dels {
                out.push(alloc::format!("< {}", am[x]));
            }
            out.push(String::from("---"));
            for &x in &adds {
                out.push(alloc::format!("> {}", bm[x]));
            }
        }
    }
    out
}

/// Traditional-diff line-range notation: `N` or `N,M` (1-based inclusive).
fn rng(lo0: usize, hi0: usize) -> String {
    // input is 0-based [lo,hi)
    if hi0 <= lo0 + 1 {
        alloc::format!("{}", lo0 + 1)
    } else {
        alloc::format!("{},{}", lo0 + 1, hi0)
    }
}

/// Real SHA-256 (FIPS 180-4). Verified against the "" and "abc" vectors.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    let mut w = [0u32; 64];
    for chunk in msg.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = ((ch[0] as u32) << 16)
            | ((*ch.get(1).unwrap_or(&0) as u32) << 8)
            | (*ch.get(2).unwrap_or(&0) as u32);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut val = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        val[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        let v = val[c as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Write `v` as a zero-padded octal field of width `w` at `buf[off..]` (tar).
fn tar_octal(buf: &mut [u8], off: usize, w: usize, v: u64) {
    let s = alloc::format!("{:0>width$o}", v, width = w - 1);
    let b = s.as_bytes();
    let n = b.len().min(w - 1);
    buf[off..off + n].copy_from_slice(&b[b.len() - n..]);
    buf[off + n] = 0;
}

struct Term {
    win: Window,
    c: Canvas,
    lines: Vec<String>, // scrollback
    cur: String,        // editing line
    cx: usize,          // cursor char pos
    hist: Vec<String>,
    hi: usize,
    view: usize, // scrollback: lines hidden from the bottom (0 = tail)
    dirty_all: bool,
    needs_cursor_flip: bool,
    capture: Option<Vec<String>>, // output capture for pipes/redirects
    pipe_in: Option<String>,     // stdin text delivered by the previous stage
    watch: Option<(String, u64, u64)>, // (cmd, interval_ms, last_run_ms)
    vars: alloc::collections::BTreeMap<String, String>, // shell vars ($NAME)
    prev_cwd: String,                                  // for `cd -`
    pager: Option<(Vec<String>, usize)>,               // (all lines, page top) for `more`
    httpd: Option<ustd::TcpListener>,                  // `httpd <port>` server mode
    nc: Option<ustd::TcpSock>,                         // `nc <ip> <port>` raw session
    last_ok: bool,                                     // success of the last statement (for && / ||)
    sel: Option<((usize, usize), (usize, usize))>,     // scrollback selection (line,col)->(line,col)
    sel_drag: bool,                                    // left button currently held
    pq: String,                                        // pager search query
    pg_input: bool,                                    // pager `/` input active
    tailf: Option<(String, u64)>,                      // `tail -f`: (path, next byte offset)
    tailf_last: u64,                                   // last poll ms
    yesing: Option<String>,                            // `yes`: repeated line (mode)
    prev_buttons: u8,                                  // pointer buttons last event (edge detect)
}

impl Term {
    fn push_line(&mut self, s: &str) {
        // wrap at COLS
        let mut rest = s;
        loop {
            let n = if rest.len() <= COLS {
                self.lines.push(String::from(rest));
                true
            } else {
                let (a, b) = rest.split_at(COLS);
                self.lines.push(String::from(a));
                rest = b;
                false
            };
            // each appended line bumps view so a scrolled window stays pinned
            if self.view > 0 {
                self.view += 1;
            }
            if n {
                break;
            }
        }
        if self.lines.len() > 400 {
            let drop = self.lines.len() - 400;
            self.lines.drain(0..drop);
            self.view = self.view.saturating_sub(drop);
        }
    }

    /// Command output: goes to the capture buffer during a pipe/redirect
    /// stage, else to the scrollback.
    fn emit(&mut self, s: &str) {
        if let Some(c) = self.capture.as_mut() {
            c.push(String::from(s));
        } else {
            self.push_line(s);
        }
    }

    /// Emit an error line and mark the current statement failed (for
    /// `&&`/`||` statement chaining).
    fn fail(&mut self, s: &str) {
        self.last_ok = false;
        self.emit(s);
    }

    /// Run `cmd` with output captured; returns the captured lines.
    fn run_captured(&mut self, cmd: &str) -> Vec<String> {
        let saved = self.capture.replace(Vec::new());
        self.run(cmd);
        let out = self.capture.take().unwrap_or_default();
        self.capture = saved;
        out
    }

    /// Expand $NAME tokens from the shell var table (whole-word vars).
    fn expand_vars(&self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'?' {
                // $? — previous command's exit status (still in last_ok)
                out.push(if self.last_ok { '0' } else { '1' });
                i += 2;
            } else if b[i] == b'$' && i + 1 < b.len() && (b[i + 1].is_ascii_alphanumeric() || b[i + 1] == b'_') {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                let name = core::str::from_utf8(&b[i + 1..j]).unwrap_or("");
                if let Some(v) = self.vars.get(name) {
                    out.push_str(v);
                }
                i = j;
            } else {
                out.push(b[i] as char);
                i += 1;
            }
        }
        out
    }

    /// Expand one glob arg (`dir/pat` or bare `pat` against cwd).
    /// Returns the matching paths (dir-prefixed when a dir part was given),
    /// or the arg itself untouched when nothing matches — shell semantics.
    fn glob_expand(&self, arg: &str) -> Vec<String> {
        if !arg.contains('*') && !arg.contains('?') {
            return alloc::vec![String::from(arg)];
        }
        let (dir, pat) = match arg.rfind('/') {
            Some(i) => (&arg[..i + 1], &arg[i + 1..]),
            None => ("", arg),
        };
        let read_dir = if dir.is_empty() {
            ustd::getcwd()
        } else {
            String::from(dir.trim_end_matches('/'))
        };
        let mut out = Vec::new();
        if let Ok(ents) = ustd::readdir(&read_dir) {
            for e in &ents {
                let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("");
                if wild_match(pat, name) {
                    out.push(alloc::format!("{}{}", dir, name));
                }
            }
        }
        if out.is_empty() {
            out.push(String::from(arg));
        }
        out
    }

    /// Lines per `more` page. The scrollback region is rows_vis-1 (prompt
    /// row) and the --More-- status row eats another: h/16 - 3 so a full
    /// page fits without clipping its first line.
    fn page_lines(&self) -> usize {
        ((self.c.h as usize / CH as usize) - 3).max(4)
    }

    /// First line after `top` matching self.pq, wrapping (less-style).
    fn pager_next(&self, all: &[String], top: usize) -> Option<usize> {
        if self.pq.is_empty() {
            return None;
        }
        for off in 1..=all.len() {
            let i = (top + off) % all.len();
            if all[i].contains(&self.pq) {
                return Some(i);
            }
        }
        None
    }

    /// Replace the last scrollback line with the `/query` input display.
    fn edit_search_line(&mut self) {
        if let Some(last) = self.lines.last_mut() {
            if last.starts_with('/') || last.starts_with("--More--") {
                *last = alloc::format!("/{}", self.pq);
                return;
            }
        }
        self.push_line(&alloc::format!("/{}", self.pq));
    }

    /// Paint one page of `all` starting at `top`.
    fn page(&mut self, top: usize, all: Vec<String>) {
        let page = self.page_lines();
        self.lines.clear();
        self.view = 0;
        for l in all.iter().skip(top).take(page) {
            self.push_line(l);
        }
        let pct = if all.is_empty() { 100 } else { ((top + page).min(all.len())) * 100 / all.len() };
        self.push_line(&alloc::format!("--More--({}%  Space next, b back, q quit)", pct));
        self.pager = Some((all, top));
        self.dirty_all = true;
    }

    /// Recursive `tree` rendering (depth-capped).
    fn tree_recur(&mut self, path: &str, prefix: String, depth: usize) {
        if depth > 6 {
            return;
        }
        let ents = match ustd::readdir(path) {
            Ok(e) => e,
            Err(e) => {
                self.fail(&alloc::format!("{}[err {}]", prefix, e));
                return;
            }
        };
        let n = ents.len();
        for (i, e) in ents.iter().enumerate() {
            let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
            let last = i + 1 == n;
            self.emit(&alloc::format!("{}{} {}", prefix, if last { "`--" } else { "|--" }, name));
            if e.is_dir != 0 {
                let child = if path == "/" {
                    alloc::format!("/{}", name)
                } else {
                    alloc::format!("{}/{}", path, name)
                };
                let next = alloc::format!("{}{}", prefix, if last { "    " } else { "|   " });
                self.tree_recur(&child, next, depth + 1);
            }
        }
    }

    /// Persist history to /history.txt (last 100 commands).
    fn save_hist(&self) {
        let start = self.hist.len().saturating_sub(100);
        let body = self.hist[start..].join("\n") + "\n";
        let _ = ustd::write_all("/history.txt", body.as_bytes());
    }

    fn load_hist(&mut self) {
        if let Ok(d) = ustd::read_all("/history.txt") {
            let s = String::from_utf8_lossy(&d);
            for l in s.lines().filter(|l| !l.is_empty()) {
                self.hist.push(String::from(l));
            }
            self.hi = self.hist.len();
        }
    }

    fn prompt_str(&self) -> String {
        alloc::format!("{} $ ", ustd::getcwd())
    }

    fn redraw(&mut self) {
        self.c.fill(0, 0, self.c.w as i32, self.c.h as i32, draw::BLACK);
        let rows_vis = (self.c.h as usize / CH as usize).saturating_sub(1);
        let prompt = self.prompt_str();
        let total_cur_lines = (prompt.len() + self.cur.len()) / COLS + 1;
        let region = rows_vis.saturating_sub(total_cur_lines);
        let end = self.lines.len().saturating_sub(self.view.min(self.lines.len()));
        let start = end.saturating_sub(region);
        // selection highlight under the text (normalized line range)
        if let Some((a, b)) = self.sel {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            for li in lo.0..=hi.0 {
                if li < start || li >= end {
                    continue;
                }
                let l = &self.lines[li];
                let c0 = if li == lo.0 { lo.1.min(l.len()) } else { 0 };
                let c1 = if li == hi.0 { hi.1.min(l.len()) } else { l.len() };
                if c1 <= c0 {
                    continue;
                }
                let row = li - start;
                self.c.fill(8 + c0 as i32 * CW, 8 + row as i32 * CH, (c1 - c0) as i32 * CW, CH, draw::EDGE);
            }
        }
        let mut y = 8i32;
        for line in &self.lines[start..end] {
            if y + CH > self.c.h as i32 - 4 {
                break;
            }
            self.c.text(8, y, line, draw::TEXT, None);
            y += CH;
        }
        // prompt + input
        self.c.text(8, y, &prompt, 0xFF7FD08A, None);
        let px = 8 + prompt.len() as i32 * CW;
        self.c.text(px, y, &self.cur, draw::TEXT, None);
        // cursor
        let curx = px + self.cx as i32 * CW;
        if self.needs_cursor_flip {
            self.c.fill(curx, y, 2, CH, draw::ACCENT);
        }
        self.win.present_all();
    }

    fn run(&mut self, input: &str) {
        let input = input.trim();
        if input.is_empty() {
            return;
        }
        // history expansion: `!!` reruns the last command, `!n` reruns entry n
        // (1-based, as `history` lists it). A lone `!` line is ignored.
        if input.starts_with('!') {
            let spec = &input[1..];
            let idx = if spec == "!" {
                self.hist.len().checked_sub(1)
            } else {
                spec.parse::<usize>().ok().and_then(|n| n.checked_sub(1))
            };
            match idx.and_then(|i| self.hist.get(i).cloned()) {
                Some(line) => {
                    self.push_line(&alloc::format!("$ {}", line));
                    self.run(&line);
                }
                None => self.fail(&alloc::format!("!: no such history entry '{}'", spec)),
            }
            return;
        }
        // statement operators: `a; b` (always), `a && b` (on ok), `a || b` (on fail)
        if let Some((l, op, r)) = stmt_split(input) {
            self.last_ok = true;
            self.run(l);
            let ok = self.last_ok;
            match op {
                b';' => self.run(r),
                b'&' if ok => self.run(r),
                b'|' if !ok => self.run(r),
                _ => {}
            }
            return;
        }
        if let Some(rest) = input.strip_prefix("time ") {
            let t0 = ustd::uptime_ms();
            self.run(rest);
            self.emit(&alloc::format!("  {} ms", ustd::uptime_ms() - t0));
            return;
        }
        // pipe: left | right  (right may itself contain pipes/redirects)
        if let Some(pi) = find_unquoted(input, b'|') {
            let left = input[..pi].trim();
            let right = input[pi + 1..].trim();
            let out = self.run_captured(left);
            let saved = self.pipe_in.replace(out.join("\n"));
            self.run(right);
            self.pipe_in = saved;
            return;
        }
        // redirect: cmd > file  /  cmd >> file
        if let Some(pi) = find_unquoted(input, b'>') {
            let left = input[..pi].trim();
            let mut rest = input[pi + 1..].trim();
            let append = rest.starts_with('>');
            if append {
                rest = rest[1..].trim_start();
            }
            let fname = rest.split_whitespace().next().unwrap_or("");
            if fname.is_empty() {
                self.fail("usage: <cmd> > file  (or >> to append)");
                return;
            }
            // `echo -n ... > f` suppresses the trailing newline
            let nonl = left == "echo -n" || left.starts_with("echo -n ");
            let out = self.run_captured(left);
            let mut body = out.join("\n");
            if !body.is_empty() && !nonl {
                body.push('\n');
            }
            let r = if append {
                let mut prev = ustd::read_all(fname).unwrap_or_default();
                prev.extend_from_slice(body.as_bytes());
                ustd::write_all(fname, &prev)
            } else {
                ustd::write_all(fname, body.as_bytes())
            };
            if let Err(e) = r {
                self.fail(&alloc::format!("{}: err {}", fname, e));
            }
            return;
        }
        self.hist.push(String::from(input));
        self.hi = self.hist.len();
        self.save_hist();
        // $VAR expansion (whole-token vars; $ followed by name chars)
        let expanded = self.expand_vars(input);
        let input = expanded.as_str();
        // quote-aware word-split; quoted words keep metachars literal and are
        // exempt from glob expansion
        let toks = tokenize(input);
        let cmd = toks.first().map(|t| t.0.as_str()).unwrap_or("");
        let mut args: Vec<&str> = toks[1.min(toks.len())..]
            .iter()
            .map(|t| t.0.as_str())
            .collect();
        // glob expansion for filesystem commands: UNQUOTED args containing * ?
        // are expanded against the target dir's entries (unmatched args pass
        // through literally, like a real shell)
        const GLOBBABLE: &[&str] = &[
            "ls", "cat", "rm", "cp", "mv", "du", "wc", "head", "tail", "hex", "stat",
            "sha256sum", "strings", "sort", "uniq", "cut", "more", "diff", "base64",
            "show", "tar",
        ];
        let gexp: Vec<String> = if GLOBBABLE.contains(&cmd)
            && toks[1.min(toks.len())..]
                .iter()
                .any(|t| !t.1 && (t.0.contains('*') || t.0.contains('?')))
        {
            toks[1.min(toks.len())..]
                .iter()
                .flat_map(|t| {
                    if !t.1 && (t.0.contains('*') || t.0.contains('?')) {
                        self.glob_expand(&t.0)
                    } else {
                        alloc::vec![t.0.clone()]
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        if !gexp.is_empty() {
            args = gexp.iter().map(|s| s.as_str()).collect();
        }
        // optimistic success — fail() marks the statement failed; $? /
        // && / || read this after the command finishes
        self.last_ok = true;
        match cmd {
            "help" => {
                for l in [
                    "commands: help ls cd pwd cat mkdir touch rm mv cp echo",
                    "          clear ps mem uname whoami date ping resolve httpget ifconfig dhcp",
                    "          netstat kill <pid> grep <pat> <file> (or -r <dir>) uptime",
                    "          hex <file> wc <file> du <path> history time <cmd>",
                    "          head/tail [-n N] <file> sort <file>",
                    "          a | b   cmd > file   cmd >> file   watch [-n s] cmd",
                    "          df  (volume usage)  more  cal  tree  seq  sleep  sh  calc  ntp",
                    "          httpd <port>  arp  dmesg  nc <ip> <port>  true  false",
                    "          fserve <port> <file>  fget <ip> <port> <out>  shot [path]",
                    "          find <dir> [pat]  killall <name>  basename/dirname  strings",
                    "          diff <a> <b>  stat <path>  sort -n/-r/-u  wc -l/-w/-c",
                    "          uniq [-c]  tr [-d] <a> <b>  cut -d X -f N  tee [-a] <file>",
                    "          base64 [-d] <file>  sha256sum <file..>  tar cf|tf|xf  echo -n",
                    "          show <file.ppm> (image viewer)  globs: ls *.txt  cat *.ppm",
                    "          grep -r/-v/-n/-c/-i  sed 's/a/b/g'  xargs  nl  rev  fmt [-w N]",
                    "          cmp <a> <b>  tail -f <file>  yes  read VAR  wait <pid>  !! / !n",
                    "          ops: a ; b   a && b   a || b   drag-select copies to clipboard",
                    "          more: Space/b page, / search, n next",
                    "          reboot shutdown exit",
                    "          <binary>  - run /bin/<name> (e.g. cosmos-demo)",
                ] {
                    self.emit(l);
                }
            }
            "ls" => {
                let p = args.first().copied().unwrap_or(".");
                let dir = if p == "." { ustd::getcwd() } else { String::from(p) };
                // a file (not dir) arg lists the file itself
                if let Ok(st) = ustd::stat(&dir) {
                    if st.is_dir == 0 {
                        self.emit(&alloc::format!("  {}  ({} B)", dir, st.size));
                        return;
                    }
                }
                match ustd::readdir(&dir) {
                    Ok(ents) => {
                        if ents.is_empty() {
                            self.emit("  (empty)");
                        }
                        for e in ents {
                            let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                            let line = if e.is_dir != 0 {
                                alloc::format!("  {}/", name)
                            } else {
                                alloc::format!("  {}  ({} B)", name, e.size)
                            };
                            self.emit(&line);
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("ls: {}: err {}", dir, e)),
                }
            }
            "cd" => {
                let cur = ustd::getcwd();
                let dest = if args.first() == Some(&"-") {
                    if self.prev_cwd.is_empty() {
                        self.emit("cd: no previous dir");
                        return;
                    }
                    self.prev_cwd.clone()
                } else {
                    String::from(*args.first().unwrap_or(&"/"))
                };
                if ustd::chdir(&dest) {
                    self.prev_cwd = cur;
                } else {
                    self.fail(&alloc::format!("cd: {}: no such dir", dest));
                }
            }
            "pwd" => self.emit(&ustd::getcwd()),
            "true" => {}
            "false" => self.last_ok = false,
            "set" => {
                // set NAME=value | set   (list) | set -u NAME (unset)
                if args.is_empty() {
                    for i in 0..self.vars.len() {
                        let (k, v) = self.vars.iter().nth(i).unwrap();
                        let line = alloc::format!("{}={}", k, v);
                        self.emit(&line);
                    }
                } else if args.first() == Some(&"-u") {
                    if let Some(n) = args.get(1) {
                        self.vars.remove(*n);
                    }
                } else if let Some(eq) = args[0].find('=') {
                    let (n, v) = args[0].split_at(eq);
                    self.vars.insert(String::from(n), String::from(&v[1..]));
                } else {
                    self.fail("usage: set NAME=value | set -u NAME");
                }
            }
            "env" => {
                for i in 0..self.vars.len() {
                    let (k, v) = self.vars.iter().nth(i).unwrap();
                    let line = alloc::format!("{}={}", k, v);
                    self.emit(&line);
                }
            }
            "which" => match args.first() {
                Some(c) => {
                    let p = alloc::format!("/bin/{}", c);
                    match ustd::stat(&p) {
                        Ok(_) => self.emit(&p),
                        Err(_) => self.fail(&alloc::format!("which: {} not found", c)),
                    }
                }
                None => self.fail("usage: which <cmd>"),
            },
            "cat" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let s = String::from_utf8_lossy(&d);
                        for l in s.lines() {
                            self.emit(l);
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("cat: {}: err {}", p, e)),
                },
                None => match self.pipe_in.clone() {
                    Some(s) => {
                        for l in s.lines() {
                            self.emit(l);
                        }
                    }
                    None => self.fail("usage: cat <file>"),
                },
            },
            "mkdir" => {
                let (mkpath, target) = if args.first() == Some(&"-p") {
                    (true, args.get(1))
                } else {
                    (false, args.first())
                };
                match target {
                    Some(p) if mkpath => {
                        // mkdir -p: create each component, tolerate existing
                        let mut acc = String::new();
                        if p.starts_with('/') {
                            acc.push('/');
                        }
                        for part in p.split('/').filter(|s| !s.is_empty()) {
                            if !acc.is_empty() && !acc.ends_with('/') {
                                acc.push('/');
                            }
                            acc.push_str(part);
                            let _ = ustd::mkdir(&acc);
                        }
                    }
                    Some(p) => {
                        if let Err(e) = ustd::mkdir(p) {
                            self.fail(&alloc::format!("mkdir: err {}", e));
                        }
                    }
                    None => self.fail("usage: mkdir [-p] <dir>"),
                }
            },
            "touch" => match args.first() {
                Some(p) => {
                    if let Err(e) = ustd::write_all(p, b"") {
                        self.fail(&alloc::format!("touch: err {}", e));
                    }
                }
                None => self.fail("usage: touch <file>"),
            },
            "rm" => {
                let (rec, target) = if args.first() == Some(&"-r") {
                    (true, args.get(1))
                } else {
                    (false, args.first())
                };
                match target {
                    Some(p) => {
                        let r = if rec { self.rm_tree(p) } else { ustd::remove(p) };
                        if let Err(e) = r {
                            self.fail(&alloc::format!("rm: {}: err {}", p, e));
                        }
                    }
                    None => self.fail("usage: rm [-r] <path>"),
                }
            }
            "mv" => {
                if args.len() < 2 {
                    self.fail("usage: mv <from> <to>");
                } else if let Err(e) = ustd::rename(args[0], args[1]) {
                    self.fail(&alloc::format!("mv: err {}", e));
                }
            }
            "cp" => {
                if args.len() < 2 {
                    self.fail("usage: cp <from> <to>");
                } else {
                    match ustd::read_all(args[0]) {
                        Ok(d) => {
                            if let Err(e) = ustd::write_all(args[1], &d) {
                                self.fail(&alloc::format!("cp: err {}", e));
                            }
                        }
                        Err(e) => self.fail(&alloc::format!("cp: {}: err {}", args[0], e)),
                    }
                }
            }
            "echo" => {
                // echo [-n] args... — printing only; `>` redirection is
                // handled by the top-level quote-aware redirect splitter
                let joined = if args.first() == Some(&"-n") {
                    args[1..].join(" ")
                } else {
                    args.join(" ")
                };
                self.emit(&joined);
            }
            "clear" => self.lines.clear(),
            "ps" => {
                for p in ustd::proclist(64) {
                    let name = core::str::from_utf8(&p.name)
                        .unwrap_or("?")
                        .trim_end_matches('\0');
                    self.emit(&alloc::format!(
                        "  pid={} {} mem={}KB cpu={}ms",
                        p.pid,
                        name,
                        p.mem_kb,
                        p.cpu_ticks * 10
                    ));
                }
            }
            "mem" => {
                let mi = ustd::meminfo();
                self.emit(&alloc::format!(
                    "  total={}KB used={}KB heap={}KB tasks={}",
                    mi.total_kb, mi.used_kb, mi.kernel_heap_kb, mi.tasks
                ));
            }
            "uname" => self.emit("CosmosOS 0.1 x86_64 (rust kernel)"),
            "uptime" => {
                let ms = ustd::uptime_ms();
                self.emit(&alloc::format!(
                    "up {}h {:02}m {:02}s",
                    ms / 3_600_000,
                    (ms / 60_000) % 60,
                    (ms / 1000) % 60
                ));
            }
            "whoami" => self.emit("cosmos"),
            "tree" => {
                let root = match args.first() {
                    Some(p) if *p != "." => String::from(*p),
                    _ => ustd::getcwd(),
                };
                self.emit(&root);
                let r = root.clone();
                self.tree_recur(&r, "".into(), 0);
            }
            "sleep" => match args.first().and_then(|s| s.parse::<u64>().ok()) {
                Some(ms) => ustd::sleep_ms(ms),
                None => self.fail("usage: sleep <ms>"),
            },
            "seq" => {
                // seq END | seq START END | seq START STEP END
                let (a, st, b) = match args.len() {
                    1 => (1i64, 1i64, args[0].parse::<i64>().unwrap_or(0)),
                    2 => (args[0].parse::<i64>().unwrap_or(0), 1, args[1].parse::<i64>().unwrap_or(0)),
                    _ => (args[0].parse::<i64>().unwrap_or(0),
                          args[1].parse::<i64>().unwrap_or(1).max(1),
                          args[2].parse::<i64>().unwrap_or(0)),
                };
                let mut n = a;
                while n <= b {
                    self.emit(&alloc::format!("{}", n));
                    n += st;
                    if n > b + 10_000 { break; } // guard runaway
                }
            }
            "calc" => {
                let expr = args.join("");
                match expr_eval(&expr) {
                    Ok(v) => self.emit(&alloc::format!("{}", v)),
                    Err(e) => self.emit(&alloc::format!("calc: {}", e)),
                }
            }
            "sh" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let s = String::from_utf8_lossy(&d).into_owned();
                        for line in s.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            self.emit(&alloc::format!("$ {}", line));
                            self.run(line);
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("sh: {}: err {}", p, e)),
                },
                None => self.fail("usage: sh <file>"),
            },
            "cal" => {
                // cal [month [year]] — real Gregorian calendar
                let now = ustd::datetime();
                let mo = args.first().and_then(|s| s.parse::<u32>().ok()).map(|m| m as u8).unwrap_or(now.month);
                let yr = args.get(1).and_then(|s| s.parse::<u32>().ok()).map(|y| y as u16).unwrap_or(now.year);
                if !(1..=12).contains(&mo) {
                    self.fail("cal: month must be 1-12");
                } else {
                    for l in cal_render(mo, yr) { self.emit(&l); }
                }
            }
            "date" => {
                let d = ustd::datetime();
                self.emit(&alloc::format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    d.year, d.month, d.day, d.hour, d.minute, d.second
                ));
            }
            "ping" => match args.first() {
                Some(s) => match host_arg(s) {
                    Some(ip) => {
                        let (a, b, c, d) = (ip[0], ip[1], ip[2], ip[3]);
                        let packed = ((a as u32) << 24) | ((b as u32) << 16)
                            | ((c as u32) << 8) | d as u32;
                        match ustd::net_ping(packed, 2000) {
                            Some(rtt) => self.emit(&alloc::format!(
                                "reply from {}.{}.{}.{}: time={}ms", a, b, c, d, rtt
                            )),
                            None => self.emit(&alloc::format!(
                                "ping {}.{}.{}.{}: timeout", a, b, c, d
                            )),
                        }
                    }
                    None => self.fail(&alloc::format!("ping: can't resolve '{}'", s)),
                },
                None => self.fail("usage: ping <host|a.b.c.d>  (try 10.0.2.2)"),
            },
            "ntp" => {
                // real SNTP query (UDP/123) — epoch -> date, vs RTC
                let host = args.first().copied().unwrap_or("pool.ntp.org");
                match ustd::net_dns(host) {
                    Some(ip) => {
                        let got = (|| -> Option<(u64, u64)> {
                            let sock = ustd::UdpSock::open(49123)?;
                            let mut pkt = [0u8; 48];
                            pkt[0] = 0x1B; // LI=0 VN=3 Mode=3 (client)
                            sock.send_to(ip, 123, &pkt)?;
                            let (_, _, resp) = sock.recv_from(4000)?;
                            if resp.len() < 44 {
                                return None;
                            }
                            let secs = u32::from_be_bytes([
                                resp[40], resp[41], resp[42], resp[43],
                            ]) as u64;
                            let t0 = ustd::uptime_ms();
                            Some((secs.saturating_sub(2208988800), t0))
                        })();
                        match got {
                            Some((unix, _)) => {
                                let (y, mo, d, h, mi, s) = epoch_to_dt(unix);
                                self.emit(&alloc::format!(
                                    "ntp: {}.{}.{}.{} -> {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                                    ip[0], ip[1], ip[2], ip[3], y, mo, d, h, mi, s
                                ));
                                let rtc = ustd::datetime();
                                let now_s = (cal_days(rtc.year, rtc.month, rtc.day)) * 86400
                                    + rtc.hour as u64 * 3600 + rtc.minute as u64 * 60 + rtc.second as u64;
                                let drift = if unix >= now_s { unix - now_s } else { now_s - unix };
                                self.emit(&alloc::format!(
                                    "rtc is {}s {} ntp",
                                    drift,
                                    if unix >= now_s { "behind" } else { "ahead of" }
                                ));
                            }
                            None => self.emit(&alloc::format!(
                                "ntp: {}.{}.{}.{}: no response",
                                ip[0], ip[1], ip[2], ip[3]
                            )),
                        }
                    }
                    None => self.fail(&alloc::format!("ntp: {}: DNS failed", host)),
                }
            }
            "resolve" => match args.first() {
                Some(host) => match ustd::net_dns(host) {
                    Some(ip) => self.emit(&alloc::format!(
                        "{} -> {}.{}.{}.{}",
                        host, ip[0], ip[1], ip[2], ip[3]
                    )),
                    None => self.fail(&alloc::format!("resolve: {}: no answer", host)),
                },
                None => self.fail("usage: resolve <hostname>  (real DNS over UDP/53)"),
            },
            "httpget" => match args.first() {
                Some(host) => match ustd::net_http(host) {
                    Some(body) => {
                        let mut out = false;
                        if let Some(i) = args.iter().position(|a| a == &"-o") {
                            if let Some(f) = args.get(i + 1) {
                                match ustd::write_all(f, &body) {
                                    Ok(_) => self.emit(&alloc::format!(
                                        "  saved {}B to {}",
                                        body.len(),
                                        f
                                    )),
                                    Err(e) => self.fail(&alloc::format!("httpget: {}: err {}", f, e)),
                                }
                                out = true;
                            }
                        }
                        if !out {
                            let s = String::from_utf8_lossy(&body);
                            for l in s.lines().take(12) {
                                self.emit(l);
                            }
                        }
                    }
                    None => self.fail(&alloc::format!("httpget: {}: failed", host)),
                },
                None => self.fail("usage: httpget <host> [-o file]  (real TCP/80 GET /)"),
            },
            "grep" => {
                // grep [-r] [-v] [-n] [-c] [-i] <pat> [file|dir]
                let flag = |f: &str| args.iter().any(|a| *a == f);
                let (rec, inv, num, cnt, ci) =
                    (flag("-r"), flag("-v"), flag("-n"), flag("-c"), flag("-i"));
                let pos: Vec<&str> = args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .copied()
                    .collect();
                let pat = pos.first().map(|p| {
                    if ci {
                        p.to_ascii_lowercase()
                    } else {
                        String::from(*p)
                    }
                });
                let path = pos.get(1).copied();
                match (pat, path) {
                    (Some(p), Some(path)) => self.grep_run(&p, path, (ci, rec, inv, num, cnt)),
                    (Some(p), None) => match self.pipe_in.clone() {
                        Some(s) => {
                            let mut hits = 0usize;
                            for (i, l) in s.lines().enumerate() {
                                let hay = if ci {
                                    l.to_ascii_lowercase()
                                } else {
                                    String::from(l)
                                };
                                if hay.contains(&p) != inv {
                                    hits += 1;
                                    if !cnt {
                                        if num {
                                            self.emit(&alloc::format!("{}: {}", i + 1, l));
                                        } else {
                                            self.emit(l);
                                        }
                                    }
                                }
                            }
                            if cnt {
                                self.emit(&alloc::format!("{}", hits));
                            }
                        }
                        None => self.fail("usage: grep [-r] [-vnci] <pat> <file|dir>"),
                    },
                    _ => self.fail("usage: grep [-r] [-vnci] <pat> <file|dir>"),
                }
            }
            "hex" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        for (i, ch) in d.chunks(16).take(64).enumerate() {
                            let mut line = alloc::format!("{:04x}: ", i * 16);
                            for b in ch {
                                line.push_str(&alloc::format!("{:02x} ", b));
                            }
                            for _ in ch.len()..16 {
                                line.push_str("   ");
                            }
                            line.push_str(" ");
                            for b in ch {
                                line.push(if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' });
                            }
                            self.emit(&line);
                        }
                        if d.len() > 1024 {
                            self.emit(&alloc::format!("  ... ({} bytes total)", d.len()));
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("hex: {}: err {}", p, e)),
                },
                None => self.fail("usage: hex <file>  (first 1KiB)"),
            },
            "du" => match args.first() {
                Some(p) => {
                    let n = self.du_tree(p, 0);
                    self.emit(&alloc::format!("  {} B total", n));
                }
                None => self.fail("usage: du <path>  (recursive bytes)"),
            },
            "df" => match ustd::df() {
                Some((total, free)) => {
                    let used = total - free;
                    self.emit(&alloc::format!("  total {} MiB  used {} MiB  free {} MiB", total / (1024 * 1024), used / (1024 * 1024), free / (1024 * 1024)));
                    self.emit(&alloc::format!("  ({} B / {} B used)", used, total));
                }
                None => self.emit("df: no volume mounted"),
            },
            "shot" => {
                // shot [path]: kernel dumps the live framebuffer to a P6 PPM
                let path = match args.first() {
                    Some(p) => String::from(*p),
                    None => (1..100)
                        .map(|i| alloc::format!("/shot-{}.ppm", i))
                        .find(|p| ustd::stat(p).is_err())
                        .unwrap_or_else(|| String::from("/shot.ppm")),
                };
                if ustd::shot(&path) {
                    match ustd::stat(&path) {
                        Ok(st) => self.emit(&alloc::format!("shot: {} ({}B)", path, st.size)),
                        Err(_) => self.emit(&alloc::format!("shot: {}", path)),
                    }
                } else {
                    self.fail("shot: failed (no framebuffer?)");
                }
            }
            "more" => {
                let content = match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                        Err(e) => {
                            self.fail(&alloc::format!("more: {}: err {}", p, e));
                            None
                        }
                    },
                    None => self.pipe_in.clone(),
                };
                if let Some(s) = content {
                    let ls: Vec<String> = s.lines().map(String::from).collect();
                    self.page(0, ls);
                } else if args.is_empty() && self.pipe_in.is_none() {
                    self.fail("usage: more <file>   (Space/PgDn next, b back, q quit)");
                }
            }
            "httpd" => match args.first().and_then(|s| s.parse::<u16>().ok()) {
                Some(port) => match ustd::TcpListener::bind(port) {
                    Some(l) => {
                        self.httpd = Some(l);
                        self.emit(&alloc::format!(
                            "httpd: listening on :{} — Esc to stop",
                            port
                        ));
                    }
                    None => self.fail(&alloc::format!("httpd: :{} already in use", port)),
                },
                None => self.fail("usage: httpd <port>  (serves a status page, Esc stops)"),
            },
            "fserve" => {
                // fserve <port> <file>: serve the file to ONE client then stop
                match (
                    args.first().and_then(|s| s.parse::<u16>().ok()),
                    args.get(1),
                ) {
                    (Some(port), Some(path)) => match ustd::read_all(path) {
                        Ok(data) => match ustd::TcpListener::bind(port) {
                            Some(l) => {
                                self.emit(&alloc::format!(
                                    "fserve: {} ({}B) on :{} — waiting up to 30s for a client",
                                    path, data.len(), port
                                ));
                                match l.accept(30000) {
                                    Some((sock, rip, rport)) => {
                                        self.emit(&alloc::format!(
                                            "fserve: client {}.{}.{}.{}:{}",
                                            rip[0], rip[1], rip[2], rip[3], rport
                                        ));
                                        // brief pump: let the peer's opening chatter
                                        // settle (mirrors httpd's recv-before-send)
                                        let _ = sock.recv(300);
                                        let mut ok = true;
                                        for ch in data.chunks(1400) {
                                            if sock.send(ch).is_none() {
                                                ok = false;
                                                break;
                                            }
                                        }
                                        if ok {
                                            self.emit(&alloc::format!(
                                                "fserve: sent {}B",
                                                data.len()
                                            ));
                                        } else {
                                            self.fail("fserve: send aborted (peer went away)");
                                        }
                                    }
                                    None => self.fail("fserve: no client within 30s"),
                                }
                            }
                            None => self.fail(&alloc::format!("fserve: :{} already in use", port)),
                        },
                        Err(e) => self.fail(&alloc::format!("fserve: {}: err {}", path, e)),
                    },
                    _ => self.fail("usage: fserve <port> <file>  (serves one client then stops)"),
                }
            }
            "fget" => {
                // fget <ip> <port> <out>: TCP-download whatever the peer sends
                match (
                    args.first().and_then(|s| host_arg(s)),
                    args.get(1).and_then(|s| s.parse::<u16>().ok()),
                    args.get(2),
                ) {
                    (Some(ip), Some(port), Some(out)) => {
                        let lport = 42000u16 + (ustd::uptime_ms() % 2000) as u16;
                        match ustd::TcpSock::connect(lport, ip, port) {
                            Some(sock) => {
                                let mut data: Vec<u8> = Vec::new();
                                loop {
                                    match sock.recv(5000) {
                                        Some(d) => data.extend_from_slice(&d),
                                        None => break,
                                    }
                                }
                                match ustd::write_all(out, &data) {
                                    Ok(_) => self.emit(&alloc::format!(
                                        "fget: {}B -> {}",
                                        data.len(),
                                        out
                                    )),
                                    Err(e) => self.fail(&alloc::format!("fget: {}: err {}", out, e)),
                                }
                            }
                            None => self.fail(&alloc::format!("fget: connect to :{} failed", port)),
                        }
                    }
                    _ => self.fail("usage: fget <host|a.b.c.d> <port> <out>  (TCP download to file)"),
                }
            }
            "nc" => {
                match (
                    args.first().and_then(|s| host_arg(s)),
                    args.get(1).and_then(|s| s.parse::<u16>().ok()),
                ) {
                    (Some(ip), Some(port)) => {
                        let lport = 40000u16 + (ustd::uptime_ms() % 2000) as u16;
                        match ustd::TcpSock::connect(lport, ip, port) {
                            Some(s) => {
                                self.emit(&alloc::format!(
                                    "nc: connected to {}.{}.{}.{}:{} — keystrokes send, Esc closes",
                                    ip[0], ip[1], ip[2], ip[3], port
                                ));
                                self.nc = Some(s);
                            }
                            None => self.fail(&alloc::format!("nc: connect to :{} failed", port)),
                        }
                    }
                    _ => self.fail("usage: nc <host|a.b.c.d> <port>  (raw TCP session, Esc closes)"),
                }
            }
            "watch" => {
                // watch [-n secs] <cmd...>: re-run every N secs until Esc/Enter
                let (mut ms, mut i) = (1000u64, 0usize);
                if args.first() == Some(&"-n") {
                    ms = args
                        .get(1)
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(1)
                        .max(1)
                        * 1000;
                    i = 2;
                }
                if args.len() <= i {
                    self.fail("usage: watch [-n secs] <cmd...>  (Esc/Enter exits)");
                } else {
                    self.watch = Some((args[i..].join(" "), ms, 0));
                    self.emit(&alloc::format!("watching every {}ms — Esc/Enter to stop", ms));
                }
            }
            "history" => {
                for i in 0..self.hist.len() {
                    let line = alloc::format!("  {:>3}  {}", i + 1, self.hist[i]);
                    self.emit(&line);
                }
            }
            "wc" => self.wc_run(&args),
            "head" | "tail" | "sort" => {
                let popt = args.iter().position(|a| !a.starts_with('-')).map(|i| args[i]);
                let n: usize = args
                    .iter()
                    .position(|a| a == &"-n")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10);
                let mut blen = 0usize;
                let content = match popt {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => {
                            blen = d.len();
                            Some(String::from_utf8_lossy(&d).into_owned())
                        }
                        Err(e) => {
                            self.fail(&alloc::format!("{}: {}: err {}", cmd, p, e));
                            None
                        }
                    },
                    None => {
                        blen = self.pipe_in.as_ref().map(|s| s.len()).unwrap_or(0);
                        self.pipe_in.clone()
                    }
                };
                match content {
                    Some(s) => {
                        let mut ls: Vec<&str> = s.lines().collect();
                        if cmd == "sort" {
                            if args.iter().any(|a| a == &"-n") {
                                // numeric: compare leading signed-integer fields (0 if none)
                                let num = |l: &&str| -> i64 {
                                    let t = l.trim_start();
                                    let neg = t.starts_with('-');
                                    let digits: String = t.chars()
                                        .skip(neg as usize)
                                        .take_while(|c| c.is_ascii_digit())
                                        .collect();
                                    let v: i64 = digits.parse().unwrap_or(0);
                                    if neg { -v } else { v }
                                };
                                ls.sort_by_key(num);
                            } else {
                                ls.sort();
                            }
                            if args.iter().any(|a| a == &"-u") {
                                ls.dedup();
                            }
                            if args.iter().any(|a| a == &"-r") {
                                ls.reverse();
                            }
                            for l in ls {
                                self.emit(l);
                            }
                        } else if cmd == "head" {
                            for l in ls.iter().take(n) {
                                self.emit(l);
                            }
                        } else {
                            for l in ls.iter().skip(ls.len().saturating_sub(n)) {
                                self.emit(l);
                            }
                            // tail -f: keep following new appended bytes
                            if cmd == "tail" && args.iter().any(|a| *a == "-f") {
                                if let Some(p) = popt {
                                    self.tailf = Some((String::from(p), blen as u64));
                                    self.tailf_last = 0;
                                    self.emit("  (following — Esc/Enter to stop)");
                                } else {
                                    self.fail("tail: -f needs a file");
                                }
                            }
                        }
                    }
                    None => self.fail(&alloc::format!("usage: {} [-n N] <file>", cmd)),
                }
            }
            "uniq" | "tr" | "cut" | "tee" | "base64" | "sha256sum" | "tar" => {
                match cmd {
                    "sha256sum" => {
                        let mut any = false;
                        for a in args.iter() {
                            match ustd::read_all(a) {
                                Ok(d) => {
                                    any = true;
                                    let dg = sha256(&d);
                                    let mut hx = String::new();
                                    for b in dg {
                                        hx.push_str(&alloc::format!("{:02x}", b));
                                    }
                                    self.emit(&alloc::format!("{}  {}", hx, a));
                                }
                                Err(e) => self.fail(&alloc::format!("sha256sum: {}: err {}", a, e)),
                            }
                        }
                        if !any && !args.is_empty() {
                            // nothing readable — fail already reported
                        } else if !any {
                            match &self.pipe_in {
                                Some(s) => {
                                    let dg = sha256(s.as_bytes());
                                    let mut hx = String::new();
                                    for b in dg {
                                        hx.push_str(&alloc::format!("{:02x}", b));
                                    }
                                    self.emit(&alloc::format!("{}  -", hx));
                                }
                                None => self.fail("usage: sha256sum <file...>"),
                            }
                        }
                    }
                    "base64" => {
                        let decode = args.iter().any(|a| a == &"-d");
                        let src = args.iter().find(|a| !a.starts_with('-'));
                        let data: Option<Vec<u8>> = match src {
                            Some(p) => match ustd::read_all(p) {
                                Ok(d) => Some(d),
                                Err(e) => {
                                    self.fail(&alloc::format!("base64: {}: err {}", p, e));
                                    None
                                }
                            },
                            None => self.pipe_in.as_ref().map(|s| s.as_bytes().to_vec()),
                        };
                        match data {
                            Some(d) if decode => match b64_decode(&String::from_utf8_lossy(&d)) {
                                Some(dec) => self.emit(&String::from_utf8_lossy(&dec)),
                                None => self.fail("base64: invalid input"),
                            },
                            Some(d) => {
                                let enc = b64_encode(&d);
                                for chunk in enc.as_bytes().chunks(76) {
                                    self.emit(core::str::from_utf8(chunk).unwrap_or(""));
                                }
                            }
                            None => {
                                if src.is_none() {
                                    self.fail("usage: base64 [-d] <file>");
                                }
                            }
                        }
                    }
                    "tar" => {
                        // minimal ustar: tar cf out.tar f.. | tar tf a.tar | tar xf a.tar
                        let sub = args.first().copied().unwrap_or("");
                        match sub {
                            "cf" => match (args.get(1), args.get(2)) {
                                (Some(out), Some(_)) => {
                                    let mut arc: Vec<u8> = Vec::new();
                                    let mut ok = true;
                                    for f in &args[2..] {
                                        let (d, st) = match (ustd::read_all(f), ustd::stat(f)) {
                                            (Ok(d), Ok(st)) => (d, st),
                                            _ => {
                                                self.fail(&alloc::format!("tar: {}: unreadable", f));
                                                ok = false;
                                                break;
                                            }
                                        };
                                        let mut h = [0u8; 512];
                                        let name = f.rsplit('/').next().unwrap_or(f);
                                        let nb = name.as_bytes();
                                        let nn = nb.len().min(100);
                                        h[..nn].copy_from_slice(&nb[..nn]);
                                        tar_octal(&mut h, 100, 8, 0o644); // mode
                                        tar_octal(&mut h, 108, 8, 0); // uid
                                        tar_octal(&mut h, 116, 8, 0); // gid
                                        tar_octal(&mut h, 124, 12, d.len() as u64); // size
                                        tar_octal(&mut h, 136, 12, st.mtime); // mtime
                                        for i in 148..156 {
                                            h[i] = b' ';
                                        }
                                        h[156] = b'0'; // regular file
                                        h[257..263].copy_from_slice(b"ustar\0");
                                        h[263] = b'0';
                                        h[264] = b'0';
                                        let sum: u64 = h.iter().map(|b| *b as u64).sum();
                                        tar_octal(&mut h, 148, 8, sum);
                                        h[155] = b' ';
                                        arc.extend_from_slice(&h);
                                        arc.extend_from_slice(&d);
                                        let pad = (512 - d.len() % 512) % 512;
                                        arc.resize(arc.len() + pad, 0);
                                    }
                                    if ok {
                                        arc.resize(arc.len() + 1024, 0);
                                        match ustd::write_all(out, &arc) {
                                            Ok(()) => self.emit(&alloc::format!(
                                                "tar: {} -> {} ({} B)",
                                                args.len() - 2,
                                                out,
                                                arc.len()
                                            )),
                                            Err(e) => self
                                                .fail(&alloc::format!("tar: {}: err {}", out, e)),
                                        }
                                    }
                                }
                                _ => self.fail("usage: tar cf out.tar <file...>"),
                            },
                            "tf" | "xf" => match args.get(1) {
                                Some(path) => match ustd::read_all(path) {
                                    Ok(d) => {
                                        let mut off = 0usize;
                                        let mut nfiles = 0usize;
                                        loop {
                                            if off + 512 > d.len() || d[off..off + 100].iter().all(|b| *b == 0) {
                                                break;
                                            }
                                            let h = &d[off..off + 512];
                                            let name = core::str::from_utf8(&h[..100])
                                                .unwrap_or("")
                                                .trim_end_matches('\0');
                                            let size = u64::from_str_radix(
                                                core::str::from_utf8(&h[124..136])
                                                    .unwrap_or("")
                                                    .trim_end_matches('\0')
                                                    .trim(),
                                                8,
                                            )
                                            .unwrap_or(0);
                                            off += 512;
                                            if sub == "tf" {
                                                self.emit(name);
                                            } else {
                                                let data = &d[off..off + size as usize];
                                                let base = name.rsplit('/').next().unwrap_or(name);
                                                match ustd::write_all(base, data) {
                                                    Ok(()) => self.emit(&alloc::format!(
                                                        "x {} ({} B)",
                                                        base, size
                                                    )),
                                                    Err(e) => self.fail(&alloc::format!(
                                                        "tar: {}: err {}",
                                                        base, e
                                                    )),
                                                }
                                            }
                                            nfiles += 1;
                                            off += ((size as usize) + 511) / 512 * 512;
                                        }
                                        if nfiles == 0 {
                                            self.fail("tar: empty or invalid archive");
                                        }
                                    }
                                    Err(e) => self.fail(&alloc::format!("tar: {}: err {}", path, e)),
                                },
                                None => self.fail(&alloc::format!("usage: tar {} <a.tar>", sub)),
                            },
                            _ => self.fail("usage: tar cf|tf|xf ..."),
                        }
                    }
                    "uniq" => {
                        let content = match args.iter().find(|a| !a.starts_with('-')) {
                            Some(p) => match ustd::read_all(p) {
                                Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                                Err(e) => {
                                    self.fail(&alloc::format!("uniq: {}: err {}", p, e));
                                    None
                                }
                            },
                            None => self.pipe_in.clone(),
                        };
                        if let Some(s) = content {
                            let count = args.iter().any(|a| a == &"-c");
                            let mut prev: Option<&str> = None;
                            let mut n = 1usize;
                            for l in s.lines() {
                                if prev == Some(l) {
                                    n += 1;
                                    continue;
                                }
                                if let Some(p) = prev {
                                    if count {
                                        self.emit(&alloc::format!("{:7} {}", n, p));
                                    } else {
                                        self.emit(p);
                                    }
                                }
                                prev = Some(l);
                                n = 1;
                            }
                            if let Some(p) = prev {
                                if count {
                                    self.emit(&alloc::format!("{:7} {}", n, p));
                                } else {
                                    self.emit(p);
                                }
                            }
                        }
                    }
                    "tr" => {
                        // tr [-d] <set1> [set2] — ranges like a-z expand
                        let del = args.iter().any(|a| a == &"-d");
                        let pos: Vec<&&str> = args.iter().filter(|a| !a.starts_with('-')).collect();
                        let expand = |spec: &str| -> Vec<u8> {
                            let b = spec.as_bytes();
                            let mut v = Vec::new();
                            let mut i = 0;
                            while i < b.len() {
                                if i + 2 < b.len() && b[i + 1] == b'-' && b[i + 2] > b[i] {
                                    for c in b[i]..=b[i + 2] {
                                        v.push(c);
                                    }
                                    i += 3;
                                } else {
                                    v.push(b[i]);
                                    i += 1;
                                }
                            }
                            v
                        };
                        match (del, pos.first(), pos.get(1)) {
                            (_, Some(s1), s2) => {
                                let a = expand(s1);
                                let b: Vec<u8> = s2.map(|s| expand(s)).unwrap_or_default();
                                let mut map = [0u8; 256];
                                let mut has = [false; 256];
                                for &c in &a {
                                    has[c as usize] = true;
                                }
                                let mut delm = [false; 256];
                                if del {
                                    delm = has;
                                }
                                for (i, &c) in a.iter().enumerate() {
                                    map[c as usize] = if i < b.len() {
                                        b[i]
                                    } else {
                                        *b.last().unwrap_or(&c)
                                    };
                                }
                                let src = self.pipe_in.clone().unwrap_or_default();
                                let mut out = String::new();
                                for ch in src.chars() {
                                    let cb = ch as usize;
                                    if cb < 256 && delm[cb] && ch != '\n' {
                                        continue;
                                    }
                                    if cb < 256 && has[cb] && !del {
                                        let m = map[cb];
                                        out.push(m as char);
                                    } else {
                                        out.push(ch);
                                    }
                                }
                                for l in out.lines() {
                                    self.emit(l);
                                }
                            }
                            _ => self.fail("usage: tr [-d] <set1> <set2>"),
                        }
                    }
                    "cut" => {
                        // cut -d X -f N[,M..] <file|stdin>
                        let delim = args
                            .iter()
                            .position(|a| a == &"-d")
                            .and_then(|i| args.get(i + 1))
                            .map(|s| s.chars().next().unwrap_or('\t'))
                            .unwrap_or('\t');
                        let fields: Vec<usize> = args
                            .iter()
                            .position(|a| a == &"-f")
                            .and_then(|i| args.get(i + 1))
                            .map(|s| {
                                s.split(',')
                                    .filter_map(|x| x.parse::<usize>().ok())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let src = args.iter().enumerate().find(|(i, a)| {
                            !a.starts_with('-') && *i > 0 && args[i - 1] != "-d" && args[i - 1] != "-f"
                        }).map(|(_, a)| *a);
                        let content = match src {
                            Some(p) => match ustd::read_all(p) {
                                Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                                Err(e) => {
                                    self.fail(&alloc::format!("cut: {}: err {}", p, e));
                                    None
                                }
                            },
                            None => self.pipe_in.clone(),
                        };
                        match (content, fields.is_empty()) {
                            (Some(s), false) => {
                                let dstr = alloc::format!("{}", delim);
                                for l in s.lines() {
                                    let parts: Vec<&str> = l.split(delim).collect();
                                    let got: Vec<&str> = fields
                                        .iter()
                                        .filter_map(|f| parts.get(f.saturating_sub(1)).copied())
                                        .collect();
                                    self.emit(&got.join(&dstr));
                                }
                            }
                            (Some(_), true) => self.fail("cut: need -f N[,M..]"),
                            (None, _) => self.fail("usage: cut -d X -f N[,M..] <file>"),
                        }
                    }
                    "tee" => {
                        // tee [-a] file — pipe stdin to stdout AND the file
                        let append = args.iter().any(|a| a == &"-a");
                        let src = args.iter().find(|a| !a.starts_with('-'));
                        let inp_owned = self.pipe_in.clone();
                        match (src, inp_owned) {
                            (Some(path), Some(inp)) => {
                                let r = if append {
                                    match ustd::read_all(path) {
                                        Ok(mut old) => {
                                            old.extend_from_slice(inp.as_bytes());
                                            ustd::write_all(path, &old)
                                        }
                                        Err(_) => ustd::write_all(path, inp.as_bytes()),
                                    }
                                } else {
                                    ustd::write_all(path, inp.as_bytes())
                                };
                                match r {
                                    Ok(()) => {
                                        for l in inp.lines() {
                                            self.emit(l);
                                        }
                                    }
                                    Err(e) => {
                                        self.fail(&alloc::format!("tee: {}: err {}", path, e))
                                    }
                                }
                            }
                            (None, _) => self.fail("usage: tee [-a] <file>"),
                            (_, None) => self.fail("tee: no stdin"),
                        }
                    }
                    _ => {}
                }
            }
            "netstat" => {
                for l in ustd::net_stat().lines() {
                    self.emit(l);
                }
            }
            "arp" => {
                for l in ustd::arp_stat().lines() {
                    self.emit(l);
                }
            }
            "dmesg" => {
                // last 40 lines of the kernel log ring buffer
                let s = ustd::klog();
                let ls: Vec<&str> = s.lines().collect();
                for l in ls.iter().skip(ls.len().saturating_sub(40)) {
                    self.emit(l);
                }
            }
            "kill" => match args.first() {
                Some(p) => match p.parse::<u32>() {
                    Ok(pid) if ustd::kill(pid) => self.emit(&alloc::format!("killed {}", pid)),
                    _ => self.fail("kill: no such pid"),
                },
                None => self.fail("usage: kill <pid>"),
            },
            "killall" => match args.first() {
                Some(name) => {
                    let mut n = 0u32;
                    for p in ustd::proclist(64) {
                        let pname = core::str::from_utf8(&p.name)
                            .unwrap_or("")
                            .trim_end_matches('\0');
                        if pname.contains(*name) && ustd::kill(p.pid) {
                            n += 1;
                        }
                    }
                    if n == 0 {
                        self.fail(&alloc::format!("killall: no process matching '{}'", name));
                    } else {
                        self.emit(&alloc::format!("killed {} process(es)", n));
                    }
                }
                None => self.fail("usage: killall <name-substr>"),
            },
            "basename" => match args.first() {
                Some(p) => {
                    let t = p.trim_end_matches('/');
                    self.emit(t.rsplit('/').next().unwrap_or("/"));
                }
                None => self.fail("usage: basename <path>"),
            },
            "dirname" => match args.first() {
                Some(p) => {
                    let t = p.trim_end_matches('/');
                    match t.rfind('/') {
                        None => self.emit("."),
                        Some(0) => self.emit("/"),
                        Some(i) => self.emit(&t[..i]),
                    }
                }
                None => self.fail("usage: dirname <path>"),
            },
            "strings" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let mut run = String::new();
                        let emit_run = |term: &mut Self, run: &mut String| {
                            if run.len() >= 4 {
                                term.emit(run);
                            }
                            run.clear();
                        };
                        for &b in d.iter() {
                            if b.is_ascii_graphic() || b == b' ' {
                                run.push(b as char);
                            } else {
                                emit_run(self, &mut run);
                            }
                        }
                        emit_run(self, &mut run);
                    }
                    Err(e) => self.fail(&alloc::format!("strings: {}: err {}", p, e)),
                },
                None => self.fail("usage: strings <file>"),
            },
            "find" => {
                // find <dir> [pat]: recursive name-match (glob * and ?)
                let (dir, pat) = (
                    args.first().copied().unwrap_or("/"),
                    args.get(1).copied().unwrap_or("*"),
                );
                match ustd::stat(dir) {
                    Ok(st) if st.is_dir != 0 => self.find_run(dir, pat),
                    Ok(_) => {
                        if wild_match(pat, dir) {
                            self.emit(dir);
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("find: {}: err {}", dir, e)),
                }
            }
            "diff" => match (args.first(), args.get(1)) {
                (Some(pa), Some(pb)) => match (ustd::read_all(pa), ustd::read_all(pb)) {
                    (Ok(da), Ok(db)) => {
                        let sa = String::from_utf8_lossy(&da).into_owned();
                        let sb = String::from_utf8_lossy(&db).into_owned();
                        let la: Vec<String> = sa.lines().take(1024).map(String::from).collect();
                        let lb: Vec<String> = sb.lines().take(1024).map(String::from).collect();
                        let out = diff_lines(&la, &lb);
                        if out.is_empty() {
                            self.emit("(identical)");
                        }
                        for l in out {
                            self.emit(&l);
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => self.fail(&alloc::format!("diff: err {}", e)),
                },
                _ => self.fail("usage: diff <fileA> <fileB>"),
            },
            "stat" => match args.first() {
                Some(p) => match ustd::stat(p) {
                    Ok(st) => {
                        let (y, mo, d, h, mi, se) = epoch_to_dt(st.mtime);
                        self.emit(&alloc::format!("  {}: {} B {}", p, st.size, if st.is_dir != 0 { "(dir)" } else { "" }));
                        self.emit(&alloc::format!(
                            "  mtime {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, mi, se
                        ));
                    }
                    Err(e) => self.fail(&alloc::format!("stat: {}: err {}", p, e)),
                },
                None => self.fail("usage: stat <path>"),
            },
            "dhcp" => match ustd::net_dhcp() {
                Some(ip) => self.emit(&alloc::format!(
                    "dhcp: lease {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]
                )),
                None => self.fail("dhcp: no response (net down or no server)"),
            },
            "ifconfig" => match ustd::net_info() {
                Some((mac, ip)) => {
                    self.emit(&alloc::format!(
                        "net0: ip {}.{}.{}.{} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip[0], ip[1], ip[2], ip[3],
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    ));
                }
                None => self.emit("no network device"),
            },
            "reboot" => ustd::reboot(),
            "shutdown" | "poweroff" => ustd::poweroff(),
            "exit" => self.win.close(),
            "show" => match args.first() {
                Some(p) => match ustd::spawn("/bin/cosmos-view", p) {
                    Ok(pid) => self.emit(&alloc::format!("spawned view (pid {})", pid)),
                    Err(_) => self.fail("show: spawn failed"),
                },
                None => self.fail("usage: show <file.ppm>"),
            },
            "yes" => {
                self.yesing = Some(if args.is_empty() {
                    String::from("y")
                } else {
                    args.join(" ")
                });
                self.emit("yes running — Esc/Enter to stop");
            }
            "sed" => {
                // sed 's/old/new/[g]' [file] — per-line substitute
                let spec = args.first().copied().unwrap_or("");
                let b = spec.as_bytes();
                let parsed = if b.len() >= 4 && b[0] == b's' {
                    let d = b[1] as char;
                    let parts: Vec<&str> = spec[2..].split(d).collect();
                    if parts.len() >= 2 {
                        Some((String::from(parts[0]), String::from(parts[1]), parts.get(2).map(|f| f.contains('g')).unwrap_or(false)))
                    } else {
                        None
                    }
                } else {
                    None
                };
                let input_text = match args.get(1) {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                        Err(e) => {
                            self.fail(&alloc::format!("sed: {}: err {}", p, e));
                            None
                        }
                    },
                    None => self.pipe_in.clone(),
                };
                match (parsed, input_text) {
                    (Some((old, new, g)), Some(s)) => {
                        if old.is_empty() {
                            self.fail("sed: empty pattern");
                            return;
                        }
                        for l in s.lines() {
                            let r = if g { l.replace(&old, &new) } else { l.replacen(&old, &new, 1) };
                            self.emit(&r);
                        }
                    }
                    (None, _) => self.fail("usage: sed 's/old/new/[g]' [file]"),
                    _ => {}
                }
            }
            "xargs" => {
                // xargs <cmd> [args...]: run `<cmd args> <line>` per stdin line
                if args.is_empty() {
                    self.fail("usage: <cmd> | xargs <cmd> [args...]");
                    return;
                }
                let base = args.join(" ");
                if let Some(s) = self.pipe_in.clone() {
                    for l in s.lines() {
                        if l.is_empty() {
                            continue;
                        }
                        for o in self.run_captured(&alloc::format!("{} {}", base, l)) {
                            self.emit(&o);
                        }
                    }
                } else {
                    self.fail("xargs: no input (pipe lines in)");
                }
            }
            "nl" | "rev" | "fmt" => {
                // nl numbers lines; rev reverses chars; fmt rewraps to -w cols
                let wi = args.iter().position(|a| a == &"-w");
                let width: usize = wi
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(72);
                let skip = wi.map(|i| i + 1);
                let popt = args
                    .iter()
                    .enumerate()
                    .find(|(i, a)| !a.starts_with('-') && Some(*i) != skip)
                    .map(|(_, a)| *a);
                let content = match popt {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                        Err(e) => {
                            self.fail(&alloc::format!("{}: {}: err {}", cmd, p, e));
                            None
                        }
                    },
                    None => self.pipe_in.clone(),
                };
                if let Some(s) = content {
                    match cmd {
                        "nl" => {
                            for (i, l) in s.lines().enumerate() {
                                self.emit(&alloc::format!("  {:>4}  {}", i + 1, l));
                            }
                        }
                        "rev" => {
                            for l in s.lines() {
                                self.emit(&l.chars().rev().collect::<String>());
                            }
                        }
                        _ => {
                            // greedy word-wrap
                            let mut cur = String::new();
                            let flush = |c: &mut String, t: &mut Term| {
                                if !c.is_empty() {
                                    t.emit(c);
                                    c.clear();
                                }
                            };
                            for w in s.split_whitespace() {
                                if !cur.is_empty() && cur.len() + 1 + w.len() > width {
                                    flush(&mut cur, self);
                                }
                                if !cur.is_empty() {
                                    cur.push(' ');
                                }
                                cur.push_str(w);
                            }
                            flush(&mut cur, self);
                        }
                    }
                }
            }
            "cmp" => {
                // byte-compare two files; reports first differing byte
                match (args.first(), args.get(1)) {
                    (Some(a), Some(b)) => {
                        match (ustd::read_all(a), ustd::read_all(b)) {
                            (Ok(da), Ok(db)) => {
                                let n = da.len().min(db.len());
                                let mut diff = None;
                                for i in 0..n {
                                    if da[i] != db[i] {
                                        diff = Some(i);
                                        break;
                                    }
                                }
                                match diff {
                                    Some(i) => self.emit(&alloc::format!("{} {} differ: byte {}", a, b, i)),
                                    None if da.len() != db.len() => self.emit(&alloc::format!(
                                        "{} {} differ: length ({} vs {} bytes)", a, b, da.len(), db.len()
                                    )),
                                    None => {}
                                }
                            }
                            (Err(e), _) | (_, Err(e)) => self.fail(&alloc::format!("cmp: err {}", e)),
                        }
                    }
                    _ => self.fail("usage: cmp <file1> <file2>"),
                }
            }
            "read" => {
                // read VAR: consume one stdin (pipe) line into $VAR
                match args.first() {
                    Some(v) => match self.pipe_in.clone() {
                        Some(s) => {
                            let mut it = s.splitn(2, '\n');
                            let line = it.next().unwrap_or("");
                            self.vars.insert(String::from(*v), String::from(line));
                            // remaining lines stay in stdin for the next `read`
                            self.pipe_in = it.next().map(|r| String::from(r));
                            self.emit(&alloc::format!("{}='{}'", v, line));
                        }
                        None => self.fail("read: no input (pipe lines in)"),
                    },
                    None => self.fail("usage: <cmd> | read VAR"),
                }
            }
            "wait" => match args.first().and_then(|a| a.parse::<u32>().ok()) {
                Some(pid) => match ustd::waitpid(pid, 30_000) {
                    Ok(code) => self.emit(&alloc::format!("pid {} exited (status {})", pid, code)),
                    Err(_) => self.fail(&alloc::format!("wait: {}: timeout or no such task", pid)),
                },
                None => self.fail("usage: wait <pid>"),
            },
            _ => {
                // try running it as a binary
                let path = alloc::format!("/bin/{}", cmd);
                if ustd::stat(&path).is_ok() {
                    match ustd::spawn(&path, &args.join(" ")) {
                        Ok(pid) => {
                            self.emit(&alloc::format!("spawned {} (pid {})", cmd, pid));
                        }
                        Err(_) => self.fail(&alloc::format!("{}: spawn failed", cmd)),
                    }
                } else {
                    self.fail(&alloc::format!("{}: unknown command", cmd));
                }
            }
        }
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        // pager mode: Space/PgDn next page, b/PgUp back, q/Esc/Enter quits;
        // `/` searches (Enter runs, Esc cancels input), n repeats
        if self.pager.is_some() {
            if self.pg_input {
                match k.key as u32 {
                    x if x == KeyCode::Enter as u32 => {
                        self.pg_input = false;
                        let (all, top) = self.pager.take().unwrap();
                        match self.pager_next(&all, top) {
                            Some(i) => self.page(i, all),
                            None => {
                                self.push_line("(not found)");
                                self.pager = Some((all, top));
                            }
                        }
                    }
                    x if x == KeyCode::Escape as u32 => {
                        self.pg_input = false;
                        self.pq.clear();
                        self.push_line("(search cancelled)");
                    }
                    x if x == KeyCode::Backspace as u32 => {
                        self.pq.pop();
                        self.edit_search_line();
                    }
                    x if x == KeyCode::Char as u32 && k.chr != 0 => {
                        self.pq.push(k.chr as char);
                        self.edit_search_line();
                    }
                    _ => {}
                }
                self.dirty_all = true;
                return;
            }
            match k.key as u32 {
                x if x == KeyCode::Char as u32 && k.chr == b'/' => {
                    self.pg_input = true;
                    self.pq.clear();
                    self.edit_search_line();
                }
                x if x == KeyCode::Char as u32 && k.chr == b'n' => {
                    if !self.pq.is_empty() {
                        let (all, top) = self.pager.take().unwrap();
                        match self.pager_next(&all, top) {
                            Some(i) => self.page(i, all),
                            None => {
                                self.push_line("(not found)");
                                self.pager = Some((all, top));
                            }
                        }
                    }
                }
                x if x == KeyCode::Char as u32 && (k.chr == b' ' || k.chr == b'q' || k.chr == b'Q' || k.chr == b'b') => {
                    if k.chr == b' ' {
                        let (all, top) = self.pager.take().unwrap();
                        let page = self.page_lines();
                        if top + page >= all.len() {
                            self.push_line("(end)");
                        } else {
                            self.page(top + page, all);
                        }
                    } else if k.chr == b'b' || k.chr == b'B' {
                        let (all, top) = self.pager.take().unwrap();
                        let page = self.page_lines();
                        self.page(top.saturating_sub(page), all);
                    } else {
                        self.pager = None;
                        self.push_line("");
                    }
                }
                x if x == KeyCode::PageDown as u32 => {
                    let (all, top) = self.pager.take().unwrap();
                    let page = self.page_lines();
                    if top + page >= all.len() {
                        self.push_line("(end)");
                    } else {
                        self.page(top + page, all);
                    }
                }
                x if x == KeyCode::PageUp as u32 => {
                    let (all, top) = self.pager.take().unwrap();
                    let page = self.page_lines();
                    self.page(top.saturating_sub(page), all);
                }
                x if x == KeyCode::Escape as u32 || x == KeyCode::Enter as u32 => {
                    self.pager = None;
                    self.push_line("");
                }
                _ => {}
            }
            self.dirty_all = true;
            return;
        }
        // nc mode: keystrokes are sent raw over the socket; Esc closes
        if let Some(s) = &self.nc {
            match k.key as u32 {
                x if x == KeyCode::Escape as u32 => {
                    self.nc = None;
                    self.cur.clear();
                    self.cx = 0;
                    self.push_line("nc: closed");
                }
                x if x == KeyCode::Enter as u32 => {
                    let _ = s.send(b"\r\n");
                    self.cur.clear();
                    self.cx = 0;
                }
                x if x == KeyCode::Backspace as u32 => {
                    let _ = s.send(&[0x7f]);
                    self.cur.pop();
                    self.cx = self.cx.saturating_sub(1);
                }
                x if x == KeyCode::Char as u32 => {
                    let _ = s.send(&[k.chr]);
                    self.cur.push(k.chr as char);
                    self.cx += 1;
                }
                _ => {}
            }
            self.dirty_all = true;
            return;
        }
        // httpd mode: Esc stops the listener (other keys keep working)
        if self.httpd.is_some() && k.key == KeyCode::Escape as u32 {
            self.httpd = None; // Drop -> SYS_NET_TCP_UNLISTEN
            self.push_line("httpd: stopped");
            self.dirty_all = true;
            return;
        }
        // during watch/tail -f/yes modes, Esc or Enter stops; other keys ignored
        if self.watch.is_some() || self.tailf.is_some() || self.yesing.is_some() {
            if k.key == KeyCode::Escape as u32 || k.key == KeyCode::Enter as u32 {
                if self.watch.is_some() {
                    self.watch = None;
                    self.push_line("watch stopped");
                }
                if self.tailf.is_some() {
                    self.tailf = None;
                    self.push_line("tail: stopped");
                }
                if self.yesing.is_some() {
                    self.yesing = None;
                    self.push_line("yes: stopped");
                }
                self.dirty_all = true;
            }
            return;
        }
        // Ctrl+C cancels the current input line (like a real tty)
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 && (k.chr == b'c' || k.chr == b'C') {
            if !self.cur.is_empty() {
                let prompt = self.prompt_str();
                self.emit(&alloc::format!("{}{}^C", prompt, self.cur));
                self.cur.clear();
                self.cx = 0;
                self.dirty_all = true;
            }
            return;
        }
        // Ctrl+L clears the screen
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 && (k.chr == b'l' || k.chr == b'L') {
            self.lines.clear();
            self.view = 0;
            self.redraw();
            return;
        }
        // Ctrl+V pastes the kernel clipboard into the edit line
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 && (k.chr == b'v' || k.chr == b'V') {
            for b in ustd::clip_get() {
                if b.is_ascii() && b != b'\n' && b != b'\r' {
                    self.cur.insert(self.cx, b as char);
                    self.cx += 1;
                }
            }
            self.view = 0;
            self.dirty_all = true;
            return;
        }
        if k.key == KeyCode::PageUp as u32 {
            let max = self.lines.len().saturating_sub(1);
            self.view = (self.view + 20).min(max);
        } else if k.key == KeyCode::PageDown as u32 {
            self.view = self.view.saturating_sub(20);
        } else if k.key == KeyCode::Tab as u32 {
            self.complete();
        } else if k.key == KeyCode::Char as u32 {
            self.cur.insert(self.cx, k.chr as char);
            self.cx += 1;
        } else if k.key == KeyCode::Enter as u32 {
            let line = core::mem::take(&mut self.cur);
            self.cx = 0;
            let prompt = self.prompt_str();
            self.emit(&alloc::format!("{}{}", prompt, line));
            self.run(&line);
        } else if k.key == KeyCode::Backspace as u32 {
            if self.cx > 0 {
                self.cx -= 1;
                self.cur.remove(self.cx);
            }
        } else if k.key == KeyCode::Delete as u32 {
            if self.cx < self.cur.len() {
                self.cur.remove(self.cx);
            }
        } else if k.key == KeyCode::Left as u32 {
            self.cx = self.cx.saturating_sub(1);
        } else if k.key == KeyCode::Right as u32 {
            if self.cx < self.cur.len() {
                self.cx += 1;
            }
        } else if k.key == KeyCode::Home as u32 {
            self.cx = 0;
        } else if k.key == KeyCode::End as u32 {
            self.cx = self.cur.len();
        } else if k.key == KeyCode::Up as u32 {
            if self.hi > 0 {
                self.hi -= 1;
                self.cur = self.hist.get(self.hi).cloned().unwrap_or_default();
                self.cx = self.cur.len();
            }
        } else if k.key == KeyCode::Down as u32 {
            if self.hi < self.hist.len() {
                self.hi += 1;
                self.cur = self.hist.get(self.hi).cloned().unwrap_or_default();
                self.cx = self.cur.len();
            }
        }
        // typing snaps back to the tail (PgUp/PgDn above keep the view)
        if k.key != KeyCode::PageUp as u32 && k.key != KeyCode::PageDown as u32 {
            self.view = 0;
        }
        self.dirty_all = true;
    }

    /// Tab-complete: command names before the first space, paths after.
    /// Inserts the longest common prefix of the matches.
    fn complete(&mut self) {
        const CMDS: &[&str] = &[
            "help", "ls", "cd", "pwd", "cat", "mkdir", "touch", "rm", "mv", "cp",
            "echo", "clear", "ps", "mem", "uname", "whoami", "date", "ping",
            "resolve", "httpget", "ifconfig", "dhcp", "netstat", "kill", "grep",
            "uptime", "reboot", "shutdown", "exit", "history", "time",
            "head", "tail", "sort", "wc", "hex", "du", "watch", "df",
            "set", "env", "which", "more", "cal", "tree", "seq", "sleep", "sh", "calc",
            "dmesg", "arp", "httpd", "ntp", "nc", "fserve", "fget", "true", "false",
            "shot", "find", "killall", "basename", "dirname", "strings", "diff", "stat",
            "uniq", "tr", "cut", "tee", "base64", "sha256sum", "tar", "show",
            "yes", "sed", "xargs", "nl", "rev", "fmt", "cmp", "read", "wait",
        ];
        // word being completed = text after the last space before the caret
        let head = &self.cur[..self.cx];
        let word_start = head.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let word = &head[word_start..];
        let mut cands: Vec<String> = Vec::new();
        if word_start == 0 {
            // command position — match built-ins + /bin binaries
            for c in CMDS {
                if c.starts_with(word) {
                    cands.push(String::from(*c));
                }
            }
            if let Ok(ents) = ustd::readdir("/bin") {
                for e in ents {
                    if e.is_dir == 0 {
                        let n = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("");
                        if n.starts_with(word) {
                            cands.push(String::from(n));
                        }
                    }
                }
            }
        } else {
            // path position — split dir/prefix, readdir, keep trailing / on dirs
            let (dir, prefix) = match word.rfind('/') {
                Some(i) => (&word[..i + 1], &word[i + 1..]),
                None => ("", word),
            };
            let dir_path = if dir.is_empty() { "." } else { dir };
            if let Ok(ents) = ustd::readdir(dir_path) {
                for e in ents {
                    let n = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("");
                    if n.starts_with(prefix) {
                        cands.push(alloc::format!(
                            "{}{}{}",
                            dir,
                            n,
                            if e.is_dir != 0 { "/" } else { "" }
                        ));
                    }
                }
            }
        }
        if cands.is_empty() {
            return;
        }
        // longest common prefix
        let mut lcp = cands[0].clone();
        for c in &cands[1..] {
            let mut i = 0;
            for (a, b) in lcp.bytes().zip(c.bytes()) {
                if a != b {
                    break;
                }
                i += 1;
            }
            lcp.truncate(i);
        }
        if lcp.len() > word.len() {
            let add = String::from(&lcp[word.len()..]);
            for (i, ch) in add.chars().enumerate() {
                self.cur.insert(self.cx + i, ch);
            }
            self.cx += add.len();
        } else if cands.len() == 1 {
            // exact match — add a space after commands
            if word_start == 0 {
                self.cur.insert(self.cx, ' ');
                self.cx += 1;
            }
        } else {
            // ambiguous — list the matches
            for c in &cands {
                self.emit(&alloc::format!("  {}", c));
            }
        }
    }

    /// Recursive byte total for `du`.
    fn du_tree(&mut self, path: &str, depth: usize) -> u64 {
        match ustd::readdir(path) {
            Ok(ents) => {
                let mut total = 0u64;
                for e in ents {
                    let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                    let p = alloc::format!("{}{}{}", path, if path.ends_with('/') { "" } else { "/" }, name);
                    if e.is_dir != 0 {
                        total += self.du_tree(&p, depth + 1);
                    } else {
                        total += e.size;
                        if depth == 0 {
                            self.emit(&alloc::format!("  {:>8} {}", e.size, p));
                        }
                    }
                }
                total
            }
            Err(_) => match ustd::stat(path) {
                Ok(st) => st.size,
                Err(_) => {
                    self.fail(&alloc::format!("du: {}: not found", path));
                    0
                }
            },
        }
    }

    /// Recursive delete: walk the tree removing files, then dirs bottom-up.
    fn rm_tree(&mut self, path: &str) -> Result<(), i64> {
        match ustd::readdir(path) {
            Ok(ents) => {
                for e in ents {
                    let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                    let p = alloc::format!("{}{}{}", path, if path.ends_with('/') { "" } else { "/" }, name);
                    if e.is_dir != 0 {
                        self.rm_tree(&p)?;
                    } else {
                        ustd::remove(&p)?;
                    }
                }
                ustd::remove(path)
            }
            Err(_) => ustd::remove(path), // plain file (or bad path — remove reports)
        }
    }

    /// wc [-l] [-w] [-c] [files...]: line/word/byte counts per file + a total
    /// row when several files are given. Byte counts use raw file bytes
    /// (not the lossy-decoded text). No files → counts stdin (pipe).
    fn wc_run(&mut self, args: &[&str]) {
        let (fl, fw, fc) = (
            args.iter().any(|a| a == &"-l"),
            args.iter().any(|a| a == &"-w"),
            args.iter().any(|a| a == &"-c"),
        );
        let files: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .copied()
            .collect();
        let counts = |raw: &[u8], s: &str| -> (usize, usize, usize) {
            let (mut l, mut w) = (0usize, 0usize);
            let mut in_w = false;
            for ch in s.chars() {
                if ch == '\n' {
                    l += 1;
                }
                if ch.is_whitespace() {
                    in_w = false;
                } else if !in_w {
                    in_w = true;
                    w += 1;
                }
            }
            (l, w, raw.len())
        };
        let show = |t: &mut Term, c: (usize, usize, usize), name: &str| {
            let tag = if name.is_empty() {
                String::new()
            } else {
                alloc::format!(" {}", name)
            };
            match (fl, fw, fc) {
                (true, false, false) => t.emit(&alloc::format!("{}{}", c.0, tag)),
                (false, true, false) => t.emit(&alloc::format!("{}{}", c.1, tag)),
                (false, false, true) => t.emit(&alloc::format!("{}{}", c.2, tag)),
                _ => t.emit(&alloc::format!("  {} {} {}{}", c.0, c.1, c.2, tag)),
            }
        };
        if files.is_empty() {
            if let Some(s) = self.pipe_in.clone() {
                show(self, counts(s.as_bytes(), &s), "");
                return;
            }
            self.fail("usage: wc [-lwc] <file..>");
            return;
        }
        let multi = files.len() > 1;
        let mut tot = (0usize, 0usize, 0usize);
        for f in &files {
            match ustd::read_all(f) {
                Ok(d) => {
                    let s = String::from_utf8_lossy(&d);
                    let c = counts(&d, &s);
                    tot.0 += c.0;
                    tot.1 += c.1;
                    tot.2 += c.2;
                    show(self, c, if multi { f } else { "" });
                }
                Err(e) => self.fail(&alloc::format!("wc: {}: err {}", f, e)),
            }
        }
        if multi {
            show(self, tot, "total");
        }
    }

    /// opts = (ci, rec, inv, num, cnt); `pat` is pre-lowered when ci.
    fn grep_file(&mut self, pat: &str, path: &str, opts: (bool, bool, bool, bool, bool)) {
        let (ci, _, inv, num, cnt) = opts;
        match ustd::read_all(path) {
            Ok(d) => {
                let s = String::from_utf8_lossy(&d);
                let mut hits = 0usize;
                for (i, l) in s.lines().enumerate() {
                    let hay = if ci {
                        l.to_ascii_lowercase()
                    } else {
                        String::from(l)
                    };
                    if hay.contains(pat) != inv {
                        hits += 1;
                        if !cnt {
                            if num {
                                self.emit(&alloc::format!("{}:{}: {}", path, i + 1, l));
                            } else {
                                self.emit(&alloc::format!("{}: {}", path, l));
                            }
                        }
                    }
                }
                if cnt {
                    self.emit(&alloc::format!("{}: {}", path, hits));
                }
            }
            Err(e) => self.fail(&alloc::format!("grep: {}: err {}", path, e)),
        }
    }

    fn grep_run(&mut self, pat: &str, path: &str, opts: (bool, bool, bool, bool, bool)) {
        let rec = opts.1;
        if !rec {
            self.grep_file(pat, path, opts);
            return;
        }
        let mut stack = alloc::vec::Vec::new();
        stack.push(String::from(path));
        while let Some(dir) = stack.pop() {
            match ustd::readdir(&dir) {
                Ok(ents) => {
                    for e in ents {
                        let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                        let p = alloc::format!("{}{}{}", dir, if dir.ends_with('/') { "" } else { "/" }, name);
                        if e.is_dir != 0 {
                            stack.push(p);
                        } else {
                            self.grep_file(pat, &p, opts);
                        }
                    }
                }
                Err(_) => self.grep_file(pat, &dir, opts), // a plain file was passed
            }
        }
    }

    /// find: recursive name-match walk printing full paths.
    fn find_run(&mut self, dir: &str, pat: &str) {
        let mut stack = alloc::vec::Vec::new();
        stack.push(String::from(dir));
        while let Some(d) = stack.pop() {
            match ustd::readdir(&d) {
                Ok(ents) => {
                    for e in ents {
                        let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                        let p = alloc::format!(
                            "{}{}{}",
                            d,
                            if d.ends_with('/') { "" } else { "/" },
                            name
                        );
                        if wild_match(pat, name) {
                            self.emit(&alloc::format!(
                                "{}{}",
                                p,
                                if e.is_dir != 0 { "/" } else { "" }
                            ));
                        }
                        if e.is_dir != 0 {
                            stack.push(p);
                        }
                    }
                }
                Err(_) => self.fail(&alloc::format!("find: {}: can't open", d)),
            }
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[terminal] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(60, 60, 740, 500, WIN_DECORATE | WIN_RESIZABLE, "Terminal")
        .expect("create window");
    let mut t = Term {
        win,
        c: win.canvas(),
        lines: Vec::new(),
        cur: String::new(),
        cx: 0,
        hist: Vec::new(),
        hi: 0,
        view: 0,
        dirty_all: true,
        needs_cursor_flip: true,
        capture: None,
        pipe_in: None,
        watch: None,
        httpd: None,
        nc: None,
        last_ok: true,
        vars: alloc::collections::BTreeMap::new(),
        prev_cwd: String::new(),
        pager: None,
        sel: None,
        sel_drag: false,
        pq: String::new(),
        pg_input: false,
        tailf: None,
        tailf_last: 0,
        yesing: None,
        prev_buttons: 0,
    };
    t.load_hist();
    t.push_line("CosmosOS terminal - type 'help'");
    t.push_line("");
    t.redraw();
    let mut last_blink = ustd::uptime_ms();
    loop {
        match wm.next_event(120) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                t.on_key(&k);
            }
            Some((EV_POINTER, pl)) if pl.len() >= 16 => {
                let p: shared::EvPointer = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                // right-button press edge pastes the clipboard into the edit
                // line (X11 middle-click style)
                if p.buttons & 2 != 0 && t.prev_buttons & 2 == 0 {
                    for b in ustd::clip_get() {
                        if b.is_ascii() && b != b'\n' && b != b'\r' {
                            t.cur.insert(t.cx, b as char);
                            t.cx += 1;
                        }
                    }
                    t.dirty_all = true;
                }
                t.prev_buttons = p.buttons;
                if p.wheel > 0 {
                    let max = t.lines.len().saturating_sub(1);
                    t.view = (t.view + 3 * p.wheel as usize).min(max);
                    t.dirty_all = true;
                } else if p.wheel < 0 {
                    t.view = t.view.saturating_sub(3 * (-p.wheel) as usize);
                    t.dirty_all = true;
                }
                // left-drag selects scrollback text; release copies it to
                // the kernel clipboard (X11 PRIMARY semantics)
                if p.buttons & 1 != 0 && !t.lines.is_empty() {
                    let rows_vis = (t.c.h as usize / CH as usize).saturating_sub(1);
                    let prompt = t.prompt_str();
                    let total_cur = (prompt.len() + t.cur.len()) / COLS + 1;
                    let region = rows_vis.saturating_sub(total_cur);
                    let end = t.lines.len().saturating_sub(t.view.min(t.lines.len()));
                    let start = end.saturating_sub(region);
                    let row = ((p.y - 8) / CH).clamp(0, region.max(1) as i32 - 1) as usize;
                    let li = (start + row).min(end.saturating_sub(1));
                    let col = (((p.x - 8) / CW).max(0) as usize)
                        .min(t.lines.get(li).map(|l| l.len()).unwrap_or(0));
                    if !t.sel_drag {
                        t.sel = Some(((li, col), (li, col)));
                        t.sel_drag = true;
                    } else if let Some((a, _)) = t.sel {
                        t.sel = Some((a, (li, col)));
                    }
                    t.dirty_all = true;
                } else if t.sel_drag {
                    t.sel_drag = false;
                    if let Some((a, b)) = t.sel.take() {
                        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                        let mut txt = String::new();
                        for li in lo.0..=hi.0 {
                            if li >= t.lines.len() {
                                break;
                            }
                            let l = &t.lines[li];
                            let c0 = if li == lo.0 { lo.1.min(l.len()) } else { 0 };
                            let c1 = if li == hi.0 { hi.1.min(l.len()) } else { l.len() };
                            if c1 > c0 {
                                txt.push_str(&l[c0..c1]);
                            }
                            if li < hi.0 {
                                txt.push('\n');
                            }
                        }
                        if !txt.is_empty() {
                            ustd::clip_set(txt.as_bytes());
                            t.push_line(&alloc::format!("(copied {} B)", txt.len()));
                            t.dirty_all = true;
                        }
                    }
                }
            }
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_FOCUS, _)) => {}
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if t.win.remap(r.shm_id, r.w, r.h) {
                    t.c = t.win.canvas();
                    t.win.resize_ack(r.shm_id, r.w, r.h);
                    t.dirty_all = true;
                }
            }
            _ => {}
        }
        let now = ustd::uptime_ms();
        // httpd mode: poll for one accepted conn per loop turn
        if let Some(l) = &t.httpd {
            if let Some((sock, rip, rport)) = l.accept(0) {
                let req = sock.recv(400).unwrap_or_default();
                let line = String::from_utf8_lossy(&req);
                let first = line.lines().next().unwrap_or("");
                let up = ustd::uptime_ms() / 1000;
                let body = alloc::format!(
                    "<html><body><h1>CosmosOS</h1><p>real inbound TCP — this page is served from inside the guest</p><p>uptime {}s</p></body></html>",
                    up
                );
                let resp = alloc::format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.send(resp.as_bytes());
                t.push_line(&alloc::format!(
                    "httpd: {} <- {}.{}.{}.{}:{}",
                    if first.is_empty() { "conn" } else { first },
                    rip[0], rip[1], rip[2], rip[3], rport
                ));
                t.dirty_all = true;
            }
        }
        // nc mode: drain inbound bytes; detect remote close via netstat
        if t.nc.is_some() {
            let lport = t.nc.as_ref().unwrap().lport;
            let mut got = false;
            loop {
                let d = t.nc.as_ref().unwrap().recv(0);
                match d {
                    Some(d) => {
                        got = true;
                        let txt = String::from_utf8_lossy(&d);
                        for l in txt.split('\n') {
                            t.push_line(l.trim_end_matches('\r'));
                        }
                    }
                    None => break,
                }
            }
            if got {
                t.dirty_all = true;
            }
            let tag = alloc::format!("tcp  :{} ", lport);
            let mut alive = false;
            for l in ustd::net_stat().lines() {
                if l.starts_with(&tag) && !l.ends_with("Closed") {
                    alive = true;
                }
            }
            if !alive {
                t.nc = None;
                t.push_line("nc: remote closed the connection");
                t.dirty_all = true;
            }
        }
        // watch mode: re-run the command, repaint with fresh output
        if let Some((cmd, ms, last)) = t.watch.clone() {
            if now - last >= ms {
                let out = t.run_captured(&cmd);
                let hdr = alloc::format!("$ {}   (every {}ms — Esc/Enter to stop)", cmd, ms);
                t.lines.clear();
                t.view = 0;
                t.push_line(&hdr);
                for l in out.iter().take(30) {
                    t.push_line(l);
                }
                t.watch = Some((cmd, ms, now));
                t.dirty_all = true;
            }
        }
        // tail -f mode: poll the file, print bytes appended since last read
        if let Some((path, off)) = t.tailf.clone() {
            if now - t.tailf_last >= 400 {
                t.tailf_last = now;
                if let Ok(d) = ustd::read_all(&path) {
                    if (d.len() as u64) > off {
                        let s = String::from_utf8_lossy(&d[off as usize..]);
                        for l in s.lines().take(20) {
                            t.push_line(l);
                        }
                        t.tailf = Some((path, d.len() as u64));
                        t.dirty_all = true;
                    }
                }
            }
        }
        // yes mode: flood the scrollback with the line
        if let Some(text) = t.yesing.clone() {
            for _ in 0..4 {
                t.push_line(&text);
            }
            t.dirty_all = true;
        }
        if now - last_blink >= 500 {
            last_blink = now;
            t.needs_cursor_flip = !t.needs_cursor_flip;
            t.dirty_all = true;
        }
        if t.dirty_all {
            t.dirty_all = false;
            t.redraw();
        }
    }
}
