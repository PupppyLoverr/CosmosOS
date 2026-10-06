//! cosmos-terminal: a real shell in a window. Line editing, history, and
//! commands that exercise the true filesystem/process syscalls.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::{String, ToString};
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
    let mut pd = 0i32; // depth inside $(...)
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'$' if !sq && i + 1 < b.len() && b[i + 1] == b'(' => {
                pd += 1;
                i += 1;
            }
            b')' if pd > 0 => pd -= 1,
            b';' if !sq && !dq && pd == 0 => return Some((&s[..i], b';', &s[i + 1..])),
            b'&' if !sq && !dq && pd == 0 && i + 1 < b.len() && b[i + 1] == b'&' => {
                return Some((&s[..i], b'&', &s[i + 2..]));
            }
            b'|' if !sq && !dq && pd == 0 && i + 1 < b.len() && b[i + 1] == b'|' => {
                return Some((&s[..i], b'|', &s[i + 2..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// First byte index of `want` that is NOT inside '...' / "..." quotes or
/// a `$(...)` substitution (paren depth tracked).
fn find_unquoted(s: &str, want: u8) -> Option<usize> {
    let b = s.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut pd = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'$' if !sq && i + 1 < b.len() && b[i + 1] == b'(' => {
                pd += 1;
                i += 1;
            }
            b')' if pd > 0 => pd -= 1,
            x if x == want && !sq && !dq && pd == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split on `;` only (quote- and `$(...)`-aware); `&&`/`||` stay inside the
/// resulting statements so `if a && b; then` keeps its condition intact.
fn split_semi(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut sq, mut dq) = (false, false);
    let mut pd = 0i32;
    let mut start = 0usize;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'$' if !sq && i + 1 < b.len() && b[i + 1] == b'(' => {
                pd += 1;
                i += 1;
            }
            b')' if pd > 0 => pd -= 1,
            b';' if !sq && !dq && pd == 0 => {
                out.push(String::from(s[start..i].trim()));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(String::from(s[start..].trim()));
    out
}

/// Does a statement begin a `for`/`while`/`until` loop ('f'), an `if`
/// conditional ('i'), a `case` ('c'), or no block (0)? Keyword must be the
/// first word.
fn block_kw(s: &str) -> u8 {
    for (kw, tag) in [
        ("for", b'f'),
        ("while", b'f'),
        ("until", b'f'),
        ("if", b'i'),
        ("case", b'c'),
    ] {
        if s == kw || s.starts_with(kw) && s[kw.len()..].starts_with(char::is_whitespace) {
            return tag;
        }
    }
    0
}

/// Find an unquoted `<<DELIM` in a line: returns (byte pos of `<<`,
/// delimiter, byte pos just past the delimiter token). Supports `<<-D`
/// (leading tabs stripped from body) and quoted delimiters `<<'D'`/`<<"D"`.
fn heredoc_scan(s: &str) -> Option<(usize, String, usize)> {
    let b = s.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut pd = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => {
                sq = !sq;
                i += 1;
            }
            b'"' if !sq => {
                dq = !dq;
                i += 1;
            }
            b'$' if !sq && i + 1 < b.len() && b[i + 1] == b'(' => {
                pd += 1;
                i += 1;
            }
            b')' if pd > 0 => {
                pd -= 1;
                i += 1;
            }
            b'<' if !sq && !dq && pd == 0 && i + 1 < b.len() && b[i + 1] == b'<' => {
                let mut j = i + 2;
                if j < b.len() && b[j] == b'-' {
                    j += 1;
                }
                while j < b.len() && b[j] == b' ' {
                    j += 1;
                }
                // `<<\x01N` is our own marker (a body already extracted) —
                // leave it alone, don't scan a second heredoc out of it.
                if j < b.len() && b[j] == 0x01 {
                    i += 2;
                    continue;
                }
                let q = if j < b.len() && (b[j] == b'\'' || b[j] == b'"') {
                    let c = b[j];
                    j += 1;
                    Some(c)
                } else {
                    None
                };
                let ds = j;
                while j < b.len()
                    && !b" \t;&|<>".contains(&b[j])
                    && Some(b[j]) != q
                {
                    j += 1;
                }
                if j == ds || j >= b.len() && q.is_some() {
                    return None;
                }
                let d = String::from(&s[ds..j]);
                if q.is_some() {
                    j += 1; // closing quote
                }
                return Some((i, d, j));
            }
            _ => i += 1,
        }
    }
    None
}

/// Normalize script text into a flat statement stream for `run_stmts`.
/// Returns (stmts, heredoc_bodies, unclosed_delim): phase 0 lifts heredoc
/// bodies out of the raw line stream (`cmd <<EOF` ... `EOF` lines become a
/// `<<\x01N` marker on the command statement, the body lines are literal text
/// -- never split or keyword-checked), then joins `\`-continuations, drops
/// blank/comment lines, `;`-splits, then separates a leading `do`/`then`/`else`
/// keyword from the rest of its statement so `for i in a; do echo x; done`
/// becomes [for.., do, echo x, done]. `elif C` is kept glued (the cond travels
/// with the keyword); its following `then` is consumed by the if-parser.
fn norm_stmts(src: &str) -> (Vec<String>, Vec<String>, Option<String>) {
    let mut bodies: Vec<String> = Vec::new();
    let mut unclosed: Option<String> = None;
    let mut pre: Vec<String> = Vec::new();
    {
        let mut lines = src.lines().peekable();
        while let Some(raw) = lines.next() {
            if let Some((pos, delim, dend)) = heredoc_scan(raw) {
                let strip_tabs = raw[pos + 2..].trim_start().starts_with('-');
                let mut body = String::new();
                let mut closed = false;
                for l in lines.by_ref() {
                    let l = l.strip_suffix('\r').unwrap_or(l);
                    let cmp = if strip_tabs {
                        l.trim_start_matches('\t')
                    } else {
                        l
                    };
                    if cmp == delim {
                        closed = true;
                        break;
                    }
                    body.push_str(cmp);
                    body.push('\n');
                }
                if !closed {
                    unclosed = Some(delim);
                    pre.push(String::from(raw));
                    break; // rest of the input is unterminated body text
                }
                let idx = bodies.len();
                bodies.push(body);
                let mut ln = String::from(&raw[..pos]);
                ln.push_str("<<\x01");
                ln.push_str(&alloc::format!("{}", idx));
                ln.push_str(&raw[dend..]);
                pre.push(ln);
            } else {
                pre.push(String::from(raw));
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in pre.iter().map(|s| s.as_str()) {
        let mut line = String::from(pending.as_str());
        line.push_str(raw);
        pending.clear();
        if line.trim_end().ends_with('\\') {
            pending = String::from(&line.trim_end()[..line.trim_end().len() - 1]);
            pending.push(' ');
            continue;
        }
        let line = String::from(line.trim());
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for stmt in split_semi(&line) {
            let s = String::from(stmt.trim());
            let hit = ["do ", "then ", "else "]
                .iter()
                .find(|kw| s.starts_with(**kw));
            match hit {
                Some(kw) => {
                    out.push(String::from(kw.trim()));
                    out.push(String::from(s[kw.len()..].trim()));
                }
                None => out.push(s),
            }
        }
    }
    if !pending.trim().is_empty() {
        for stmt in split_semi(pending.trim()) {
            out.push(stmt);
        }
    }
    (out, bodies, unclosed)
}

/// How many unclosed blocks a normalized statement stream opens. >0 means
/// interactive input needs a continuation line.
fn block_depth(stmts: &[String]) -> i32 {
    let mut d = 0i32;
    for s in stmts {
        let s = s.trim();
        if block_kw(s) != 0 {
            d += 1;
        } else if s == "done" || s == "fi" || s == "esac" {
            d -= 1;
        }
    }
    d
}

/// Shell word-splitting: whitespace separates, '...' and "..." group (and are
/// stripped). Returns (word, was_quoted) per token -- quoted words are exempt
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

/// IPv4 literal or DNS name -- tries the literal first, then a real
/// DNS query (UDP/53).
fn host_arg(s: &str) -> Option<[u8; 4]> {
    parse_ipv4(s).or_else(|| ustd::net_dns(s))
}

/// Human-readable byte count for `du -h`/`df -h`: B/K/M/G suffixes.
fn human_size(n: u64) -> String {
    if n >= 1 << 30 {
        alloc::format!("{}.{:01}G", n >> 30, (n % (1 << 30)) * 10 / (1 << 30))
    } else if n >= 1 << 20 {
        alloc::format!("{}.{:01}M", n >> 20, (n % (1 << 20)) * 10 / (1 << 20))
    } else if n >= 1 << 10 {
        alloc::format!("{}.{:01}K", n >> 10, (n % (1 << 10)) * 10 / (1 << 10))
    } else {
        alloc::format!("{}B", n)
    }
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
#[derive(Clone, Copy)]
enum DiffOp {
    Eq,
    Del(usize),
    Add(usize),
}

/// LCS edit script over two line slices: flat op list of Eq/Del(a_i)/Add(b_j).
fn diff_ops(am: &[String], bm: &[String]) -> Vec<DiffOp> {
    let (m, n) = (am.len(), bm.len());
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
    let mut ops: Vec<DiffOp> = Vec::with_capacity(m + n);
    let (mut i, mut j) = (0usize, 0usize);
    while i < m && j < n {
        if am[i] == bm[j] {
            ops.push(DiffOp::Eq);
            i += 1;
            j += 1;
        } else if t[(i + 1) * (n + 1) + j] >= t[i * (n + 1) + j + 1] {
            ops.push(DiffOp::Del(i));
            i += 1;
        } else {
            ops.push(DiffOp::Add(j));
            j += 1;
        }
    }
    while i < m {
        ops.push(DiffOp::Del(i));
        i += 1;
    }
    while j < n {
        ops.push(DiffOp::Add(j));
        j += 1;
    }
    ops
}

/// Classic ed-style diff output (`n a/m/d` + `<> ` lines).
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
    if am.is_empty() && bm.is_empty() {
        return out;
    }
    let ops = diff_ops(am, bm);
    let mut k = 0usize;
    let (mut a_cur, mut b_cur) = (0usize, 0usize);
    while k < ops.len() {
        if matches!(ops[k], DiffOp::Eq) {
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
                DiffOp::Del(di) => {
                    dels.push(di);
                    a_cur += 1;
                }
                DiffOp::Add(ai) => {
                    adds.push(ai);
                    b_cur += 1;
                }
                DiffOp::Eq => break,
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

/// Parse `@@ -a[,b] +c[,d] @@` -> (a_start, b_start) (1-based).
fn parse_hunk(h: &str) -> Option<(usize, usize)> {
    let inner = h.trim().strip_prefix("@@")?;
    let mut it = inner.split_whitespace();
    let a = it.next()?.strip_prefix('-')?;
    let b = it.next()?.strip_prefix('+')?;
    let pa = |s: &str| s.split(',').next()?.parse::<usize>().ok();
    Some((pa(a)?, pa(b)?))
}

/// mini-awk: `awk [-F c] 'prog' [file]`. prog = optional `BEGIN{..}` /
/// `END{..}` plus `pattern { stmts }` rules. pattern: /substr/, NR==n,
/// NR<n, NR>n, NR%n==m, or empty (all lines). stmts: `print e,..` or
/// `var=expr` / `var+=expr`; exprs support + - * / % on fields/vars/numbers.
fn awk_eval(prog: &str, input: &str, fs: Option<char>) -> Result<Vec<String>, String> {
    // split program into rules: [BEGIN{..}] [pat]{ .. } [END{..}]
    let mut rules: Vec<(String, String)> = Vec::new();
    let mut rest = prog.trim();
    let mut begin = String::new();
    let mut end = String::new();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(r) = rest.strip_prefix("BEGIN") {
            let p = r.find('{').ok_or("awk: BEGIN needs {..}")?;
            let q = match_brace(&r[p..]).ok_or("awk: unclosed {}")? + p;
            begin = String::from(&r[p + 1..q]);
            rest = &r[q + 1..];
            continue;
        }
        if let Some(r) = rest.strip_prefix("END") {
            let p = r.find('{').ok_or("awk: END needs {..}")?;
            let q = match_brace(&r[p..]).ok_or("awk: unclosed {}")? + p;
            end = String::from(&r[p + 1..q]);
            rest = &r[q + 1..];
            continue;
        }
        match rest.find('{') {
            // pattern-only rule: `pat` alone means `pat { print $0 }`
            None => {
                rules.push((String::from(rest.trim()), String::from("print")));
                rest = "";
            }
            Some(p) => {
                let pat = rest[..p].trim();
                let q = match_brace(&rest[p..]).ok_or("awk: unclosed {}")? + p;
                rules.push((String::from(pat), String::from(&rest[p + 1..q])));
                rest = &rest[q + 1..];
            }
        }
    }
    let mut vars: alloc::collections::BTreeMap<String, i64> = Default::default();
    let mut out: Vec<String> = Vec::new();
    awk_stmts(&begin, &String::from(input), 0, &[], &mut vars, &mut out)?;
    for (ln, line) in input.lines().enumerate() {
        let fields: Vec<String> = match fs {
            Some(c) => line.split(c).map(String::from).collect(),
            None => line.split_whitespace().map(String::from).collect(),
        };
        for (pat, body) in &rules {
            if awk_pat_matches(pat, ln + 1, line)? {
                awk_stmts(body, &String::from(line), ln + 1, &fields, &mut vars, &mut out)?;
            }
        }
    }
    awk_stmts(&end, &String::new(), input.lines().count(), &[], &mut vars, &mut out)?;
    Ok(out)
}

/// index of the `}` matching the `{` at s[0] (nesting-aware, quote-aware).
fn match_brace(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.first() != Some(&b'{') {
        return None;
    }
    let (mut d, mut i, mut q) = (0usize, 0usize, 0u8);
    while i < b.len() {
        match b[i] {
            c if q != 0 && c == q => q = 0,
            b'\'' | b'"' if q == 0 => q = b[i],
            b'{' if q == 0 => d += 1,
            b'}' if q == 0 => {
                d -= 1;
                if d == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn awk_pat_matches(pat: &str, nr: usize, line: &str) -> Result<bool, String> {
    let p = pat.trim();
    if p.is_empty() {
        return Ok(true);
    }
    if p.starts_with('/') && p.ends_with('/') && p.len() >= 2 {
        return Ok(line.contains(&p[1..p.len() - 1]));
    }
    if let Some(r) = p.strip_prefix("NR") {
        let r = r.trim();
        for op in ["==", "!=", ">=", "<=", ">", "<"] {
            if let Some(n) = r.strip_prefix(op) {
                let v: i64 = n.trim().parse().map_err(|_| "awk: bad NR cond")?;
                let a = nr as i64;
                return Ok(match op {
                    "==" => a == v,
                    "!=" => a != v,
                    ">=" => a >= v,
                    "<=" => a <= v,
                    ">" => a > v,
                    _ => a < v,
                });
            }
        }
        if let Some(n) = r.strip_prefix('%') {
            // NR%n==m
            let mut it = n.split("==");
            let m: i64 = it.next().and_then(|x| x.trim().parse().ok()).ok_or("awk: bad NR%")?;
            let v: i64 = it.next().and_then(|x| x.trim().parse().ok()).ok_or("awk: bad NR%")?;
            return Ok(nr as i64 % m == v);
        }
        return Err(String::from("awk: bad NR condition"));
    }
    Ok(line.contains(p))
}

/// run `;`-separated awk stmts: `print expr,..` / `var=expr` / `var+=expr`.
fn awk_stmts(
    body: &str,
    line: &String,
    nr: usize,
    fields: &[String],
    vars: &mut alloc::collections::BTreeMap<String, i64>,
    out: &mut Vec<String>,
) -> Result<(), String> {
    for st in body.split(';') {
        let st = st.trim();
        if st.is_empty() {
            continue;
        }
        if let Some(e) = st.strip_prefix("print") {
            let e = e.trim();
            if e.is_empty() {
                out.push(line.clone());
                continue;
            }
            let mut parts = Vec::new();
            let mut dep = 0i32;
            let mut last = 0;
            for (i, c) in e.char_indices() {
                match c {
                    '(' => dep += 1,
                    ')' => dep -= 1,
                    ',' if dep == 0 => {
                        parts.push(&e[last..i]);
                        last = i + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&e[last..]);
            let vals: Result<Vec<String>, String> = parts
                .iter()
                .map(|p| awk_show(p.trim(), line, nr, fields, vars))
                .collect();
            out.push(vals?.join(" "));
        } else if let Some(p) = st.find("+=") {
            let name = st[..p].trim();
            let rhs = st[p + 2..].trim();
            let v = awk_num(rhs, line, nr, fields, vars)?;
            *vars.entry(String::from(name)).or_insert(0) += v;
        } else if let Some(p) = st.find('=') {
            let name = st[..p].trim();
            let rhs = st[p + 1..].trim();
            vars.insert(String::from(name), awk_num(rhs, line, nr, fields, vars)?);
        } else {
            return Err(alloc::format!("awk: unknown stmt '{}'", st));
        }
    }
    Ok(())
}

/// awk value display: string literal or numeric expr result.
fn awk_show(
    e: &str,
    line: &str,
    nr: usize,
    fields: &[String],
    vars: &alloc::collections::BTreeMap<String, i64>,
) -> Result<String, String> {
    if e.starts_with('"') && e.ends_with('"') && e.len() >= 2 {
        return Ok(String::from(&e[1..e.len() - 1]));
    }
    // bare $N / $NF / $0 prints the raw field text (awk semantics)
    if let Some(r) = e.strip_prefix('$') {
        let r = r.trim();
        let idx = if r == "NF" {
            Some(fields.len())
        } else {
            r.parse::<usize>().ok()
        };
        if let Some(i) = idx {
            return Ok(if i == 0 {
                String::from(line)
            } else {
                fields.get(i - 1).cloned().unwrap_or_default()
            });
        }
    }
    Ok(alloc::format!("{}", awk_num(e, line, nr, fields, vars)?))
}

/// numeric expression: terms `+ -` then `* / %`, parens, $N/$NF, NF, NR, vars.
fn awk_num(
    e: &str,
    line: &str,
    nr: usize,
    fields: &[String],
    vars: &alloc::collections::BTreeMap<String, i64>,
) -> Result<i64, String> {
    let b = e.as_bytes();
    let mut pos = 0usize;
    fn ws(b: &[u8], p: &mut usize) {
        while *p < b.len() && b[*p].is_ascii_whitespace() {
            *p += 1;
        }
    }
    fn atom(
        b: &[u8],
        p: &mut usize,
        line: &str,
        nr: usize,
        fields: &[String],
        vars: &alloc::collections::BTreeMap<String, i64>,
    ) -> Result<i64, String> {
        ws(b, p);
        if *p >= b.len() {
            return Err(String::from("awk: empty expr"));
        }
        if b[*p] == b'(' {
            *p += 1;
            let v = expr(b, p, line, nr, fields, vars)?;
            ws(b, p);
            if *p >= b.len() || b[*p] != b')' {
                return Err(String::from("awk: missing ')'"));
            }
            *p += 1;
            return Ok(v);
        }
        if b[*p] == b'-' {
            *p += 1;
            return Ok(-atom(b, p, line, nr, fields, vars)?);
        }
        if b[*p] == b'$' {
            *p += 1;
            ws(b, p);
            let s = *p;
            while *p < b.len() && b[*p].is_ascii_alphanumeric() {
                *p += 1;
            }
            let t = &b[s..*p];
            let idx = if t == b"NF" {
                fields.len()
            } else {
                core::str::from_utf8(t)
                    .ok()
                    .and_then(|x| x.parse::<usize>().ok())
                    .ok_or("awk: bad $ref")?
            };
            let f = if idx == 0 {
                line.to_string()
            } else {
                fields.get(idx - 1).cloned().unwrap_or_default()
            };
            // awk field->number: leading numeric prefix (sign + digits), else 0
            let t: String = f
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
                .collect();
            return Ok(t.parse().unwrap_or(0));
        }
        let s = *p;
        while *p < b.len() && (b[*p].is_ascii_alphanumeric() || b[*p] == b'_') {
            *p += 1;
        }
        let t = core::str::from_utf8(&b[s..*p]).unwrap_or("");
        if t == "NR" {
            return Ok(nr as i64);
        }
        if t == "NF" {
            return Ok(fields.len() as i64);
        }
        if let Ok(v) = t.parse::<i64>() {
            return Ok(v);
        }
        if t.is_empty() {
            return Err(String::from("awk: empty term"));
        }
        Ok(*vars.get(t).unwrap_or(&0))
    }
    fn term(
        b: &[u8],
        p: &mut usize,
        line: &str,
        nr: usize,
        fields: &[String],
        vars: &alloc::collections::BTreeMap<String, i64>,
    ) -> Result<i64, String> {
        let mut v = atom(b, p, line, nr, fields, vars)?;
        loop {
            ws(b, p);
            let op = match b.get(*p) {
                Some(b'*') => b'*',
                Some(b'/') => b'/',
                Some(b'%') => b'%',
                _ => break,
            };
            *p += 1;
            let r = atom(b, p, line, nr, fields, vars)?;
            v = match op {
                b'*' => v * r,
                b'/' => v.checked_div(r).ok_or("awk: div by 0")?,
                _ => v.checked_rem(r).ok_or("awk: mod by 0")?,
            };
        }
        Ok(v)
    }
    fn expr(
        b: &[u8],
        p: &mut usize,
        line: &str,
        nr: usize,
        fields: &[String],
        vars: &alloc::collections::BTreeMap<String, i64>,
    ) -> Result<i64, String> {
        let mut v = term(b, p, line, nr, fields, vars)?;
        loop {
            ws(b, p);
            let op = match b.get(*p) {
                Some(b'+') => b'+',
                Some(b'-') => b'-',
                _ => break,
            };
            *p += 1;
            let r = term(b, p, line, nr, fields, vars)?;
            v = if op == b'+' { v + r } else { v - r };
        }
        Ok(v)
    }
    let v = expr(b, &mut pos, line, nr, fields, vars)?;
    ws(b, &mut pos);
    if pos < b.len() {
        return Err(alloc::format!("awk: trailing '{}'", &e[pos..]));
    }
    Ok(v)
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

/// Unified-context diff (`diff -u`): `@@ -s,c +s,c @@` hunks with `ctx`
/// context lines; change runs <=2*ctx apart merge into one hunk.
fn diff_unified(a: &[String], b: &[String], ctx: usize) -> Vec<String> {
    let mut lo = 0usize;
    let (mut ahi, mut bhi) = (a.len(), b.len());
    while lo < ahi && lo < bhi && a[lo] == b[lo] {
        lo += 1;
    }
    while ahi > lo && bhi > lo && a[ahi - 1] == b[bhi - 1] {
        ahi -= 1;
        bhi -= 1;
    }
    let ops = diff_ops(&a[lo..ahi], &b[lo..bhi]);
    let mut out: Vec<String> = Vec::new();
    let mut k = 0usize;
    let (mut ai, mut bi) = (lo, lo); // absolute 0-based line indices
    while k < ops.len() {
        // eq run before the next change
        let mut eqs = 0usize;
        while let Some(DiffOp::Eq) = ops.get(k) {
            k += 1;
            eqs += 1;
        }
        if k == ops.len() {
            break;
        }
        // hunk: leading context = min(ctx, eqs)
        let lead = eqs.min(ctx);
        let hs_a = ai + eqs - lead;
        let hs_b = bi + eqs - lead;
        let mut lines: Vec<String> = Vec::new();
        // emit the last `lead` eq lines as leading context
        for t in 0..lead {
            lines.push(alloc::format!(" {}", a[ai + eqs - lead + t]));
        }
        ai += eqs;
        bi += eqs;
        // consume change ops, merging following eq runs <=2*ctx
        loop {
            while k < ops.len() {
                match ops[k] {
                    DiffOp::Del(d) => {
                        lines.push(alloc::format!("-{}", a[lo + d]));
                        ai += 1;
                        k += 1;
                    }
                    DiffOp::Add(x) => {
                        lines.push(alloc::format!("+{}", b[lo + x]));
                        bi += 1;
                        k += 1;
                    }
                    DiffOp::Eq => break,
                }
            }
            // peek at the eq run after the change run
            let mut q = k;
            let mut run = 0usize;
            while let Some(DiffOp::Eq) = ops.get(q) {
                q += 1;
                run += 1;
            }
            let tail = run.min(ctx);
            if q == ops.len() || run > 2 * ctx {
                // hunk ends: emit only `tail` context eqs
                for _ in 0..tail {
                    lines.push(alloc::format!(" {}", a[ai]));
                    ai += 1;
                    bi += 1;
                    k += 1;
                }
                break;
            }
            // short eq run: keep it and merge with the next change run
            for _ in 0..run {
                lines.push(alloc::format!(" {}", a[ai]));
                ai += 1;
                bi += 1;
                k += 1;
            }
        }
        let alen = lines.iter().filter(|l| !l.starts_with('+')).count();
        let blen = lines.iter().filter(|l| !l.starts_with('-')).count();
        let a_start = if alen == 0 { hs_a } else { hs_a + 1 };
        let b_start = if blen == 0 { hs_b } else { hs_b + 1 };
        out.push(alloc::format!("@@ -{},{} +{},{} @@", a_start, alen, b_start, blen));
        out.extend(lines);
    }
    out
}

/// Parse a note name (`A4`, `C#5`, `Eb3`, `R` = rest) or a raw frequency
/// into Hz. Equal temperament, A4 = 440, integer math only (no FP on this
/// target). Returns None on garbage.
fn note_freq(s: &str) -> Option<u32> {
    if let Ok(f) = s.parse::<u32>() {
        return (f > 0).then_some(f);
    }
    let b = s.as_bytes();
    if b.len() < 2 {
        return None;
    }
    let semi = match b[0] {
        b'C' | b'c' => 0i32,
        b'D' | b'd' => 2,
        b'E' | b'e' => 4,
        b'F' | b'f' => 5,
        b'G' | b'g' => 7,
        b'A' | b'a' => 9,
        b'B' | b'b' => 11,
        b'R' | b'r' => return Some(0), // rest: freq 0 silences the speaker
        _ => return None,
    };
    let mut i = 1;
    let semi = match b.get(i) {
        Some(b'#') | Some(b'+') => {
            i += 1;
            semi + 1
        }
        Some(b'b') if semi > 0 => {
            i += 1;
            semi - 1
        }
        _ => semi,
    };
    let oct = s[i..].parse::<i32>().ok()?;
    // midi = 12*(octave+1) + semitone; freq = 440 * 2^((midi-69)/12).
    // 2^(s/12) ratios in 1e6 fixed point for one octave:
    const SEMI: [u64; 12] = [
        1_000_000, 1_059_463, 1_122_462, 1_189_207, 1_259_921, 1_334_840,
        1_414_214, 1_498_307, 1_587_401, 1_681_793, 1_781_797, 1_887_749,
    ];
    let d = 12 * (oct + 1) + semi - 69;
    let (o, r) = (d.div_euclid(12), d.rem_euclid(12) as usize);
    let mut num: u64 = 440 * SEMI[r];
    if o >= 0 {
        num = num.checked_shl(o as u32)?;
    } else {
        num >>= (-o).min(40) as u32;
    }
    let f = num / 1_000_000 + ((num % 1_000_000 >= 500_000) as u64);
    if f < 1 || f > 20_000 {
        None
    } else {
        Some(f as u32)
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

/// Reflected CRC32 (poly 0xEDB88320, init/final invert) -- the ZIP/gzip kind.
fn crc32(data: &[u8]) -> u32 {
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

/// DOS timestamp pair (time, date) from the kernel RTC.
fn dos_datetime() -> (u16, u16) {
    let dt = ustd::datetime();
    let t = ((dt.hour as u16) << 11) | ((dt.minute as u16) << 5) | (dt.second as u16 >> 1);
    let d = (((dt.year.max(1980) - 1980) as u16) << 9)
        | ((dt.month.clamp(1, 12) as u16) << 5)
        | (dt.day.clamp(1, 31) as u16);
    (t, d)
}

/// Create any missing parents of `path` (mkdir -p semantics, tolerant).
fn uu_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(45) {
        out.push((chunk.len() as u8 + 32) as char);
        for trip in chunk.chunks(3) {
            let b = [trip.first().copied().unwrap_or(0),
                     trip.get(1).copied().unwrap_or(0),
                     trip.get(2).copied().unwrap_or(0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for s in [18, 12, 6, 0] {
                let c = ((n >> s) & 63) as u8;
                out.push(if c == 0 { '`' } else { (c + 32) as char });
            }
        }
        out.push('\n');
    }
    out
}

/// Decode a uuencoded text: (target filename, bytes).
fn uu_decode(text: &str) -> Option<(String, Vec<u8>)> {
    let mut it = text.lines();
    let begin = it.find(|l| l.starts_with("begin "))?;
    let name = begin.split_whitespace().nth(2).unwrap_or("out.bin");
    let name = name.rsplit('/').next().unwrap_or(name);
    let mut out = Vec::new();
    for line in it {
        if line == "end" || line.is_empty() {
            break;
        }
        let b = line.as_bytes();
        if b.is_empty() {
            break;
        }
        let len = (b[0].wrapping_sub(32)) as usize;
        if len == 0 {
            break; // '`' or ' ' end-of-data line
        }
        let mut got = 0usize;
        for quad in b[1..].chunks(4) {
            if got >= len {
                break;
            }
            let mut n = 0u32;
            for (i, &c) in quad.iter().enumerate() {
                let v = if c == b'`' || c == b' ' { 0u32 } else { c.wrapping_sub(32) as u32 };
                n |= v << (18 - i * 6);
            }
            for shift in [16, 8, 0] {
                if got < len {
                    out.push((n >> shift) as u8);
                    got += 1;
                }
            }
        }
    }
    Some((String::from(name), out))
}

fn dns_name(out: &mut Vec<u8>, name: &str) {
    for part in name.trim_end_matches('.').split('.') {
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.push(0);
}

/// Read a (possibly compressed) domain name at `pos` in `pkt`.
fn dns_read_name(pkt: &[u8], pos: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut s = String::new();
    let mut i = pos;
    let mut end = 0usize;
    loop {
        let l = *pkt.get(i)? as usize;
        if l & 0xc0 == 0xc0 {
            let off = ((l & 0x3f) << 8) | *pkt.get(i + 1)? as usize;
            let (rest, _) = dns_read_name(pkt, off, depth + 1)?;
            if !s.is_empty() {
                s.push('.');
            }
            s.push_str(&rest);
            if end == 0 {
                end = i + 2;
            }
            break;
        }
        if l == 0 {
            if end == 0 {
                end = i + 1;
            }
            break;
        }
        if !s.is_empty() {
            s.push('.');
        }
        s.push_str(&String::from_utf8_lossy(pkt.get(i + 1..i + 1 + l)?));
        i += 1 + l;
    }
    Some((s, end))
}

/// Real dig: build a wire-format DNS query, send it through UdpSock,
/// parse the answer section. Returns display lines.
fn dig_query(name: &str, qtype: u16) -> Result<Vec<String>, String> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&0x1a2bu16.to_be_bytes()); // id
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qd
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    dns_name(&mut q, name);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    let sock = ustd::UdpSock::open(15353).ok_or_else(|| String::from("dig: socket failed"))?;
    sock.send_to([10, 0, 2, 3], 53, &q)
        .ok_or_else(|| String::from("dig: send failed"))?;
    let (_, _, p) = sock
        .recv_from(3000)
        .ok_or_else(|| String::from("dig: no answer (timeout)"))?;
    if p.len() < 12 {
        return Err(String::from("dig: short reply"));
    }
    let id = u16::from_be_bytes([p[0], p[1]]);
    let rcode = p[3] & 0x0f;
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    let an = u16::from_be_bytes([p[6], p[7]]) as usize;
    let ns = u16::from_be_bytes([p[8], p[9]]) as usize;
    let mut out = alloc::vec![
        alloc::format!(";; id {} rcode {} answers {} authority {}", id, rcode, an, ns),
        alloc::format!(";; QUESTION: {} {}", name, qtype),
    ];
    let mut pos = 12;
    // skip questions
    for _ in 0..qd {
        let (_, e) = dns_read_name(&p, pos, 0).ok_or_else(|| String::from("dig: bad qname"))?;
        pos = e + 4;
    }
    let tname = |t: u16| match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "?",
    };
    for _ in 0..an {
        let (nm, e) = dns_read_name(&p, pos, 0).ok_or_else(|| String::from("dig: bad answer"))?;
        pos = e;
        if pos + 10 > p.len() {
            break;
        }
        let ty = u16::from_be_bytes([p[pos], p[pos + 1]]);
        let ttl = u32::from_be_bytes([p[pos + 4], p[pos + 5], p[pos + 6], p[pos + 7]]);
        let rd = u16::from_be_bytes([p[pos + 8], p[pos + 9]]) as usize;
        pos += 10;
        if pos + rd > p.len() {
            break;
        }
        let data = &p[pos..pos + rd];
        let val = match ty {
            1 if rd == 4 => alloc::format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
            2 | 5 | 12 => dns_read_name(&p, pos, 0).map(|(n, _)| n).unwrap_or_default(),
            15 if rd > 2 => alloc::format!(
                "{} {}",
                u16::from_be_bytes([data[0], data[1]]),
                dns_read_name(&p, pos + 2, 0).map(|(n, _)| n).unwrap_or_default()
            ),
            16 => {
                let mut t = String::from("\"");
                let mut i = 0;
                while i < data.len() {
                    let l = data[i] as usize;
                    i += 1;
                    t.push_str(&String::from_utf8_lossy(&data[i..(i + l).min(data.len())]));
                    i += l;
                }
                t.push('"');
                t
            }
            28 if rd == 16 => alloc::format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([data[0], data[1]]),
                u16::from_be_bytes([data[2], data[3]]),
                u16::from_be_bytes([data[4], data[5]]),
                u16::from_be_bytes([data[6], data[7]]),
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]])
            ),
            _ => {
                let mut h = String::from("0x");
                for b in data {
                    h.push_str(&alloc::format!("{:02x}", b));
                }
                h
            }
        };
        out.push(alloc::format!("{}  {}  IN  {}  {}", nm, ttl, tname(ty), val));
        pos += rd;
    }
    if an == 0 {
        out.push(String::from(";; no answers"));
    }
    Ok(out)
}

fn hexs(data: &[u8]) -> String {
    let mut s = String::new();
    for b in data {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}

/// 5-row block glyphs for `banner` (A-Z 0-9 and common punct).
fn banner_glyph(c: char) -> [&'static str; 5] {
    match c.to_ascii_uppercase() {
        'A' => [" ### ", "#   #", "#####", "#   #", "#   #"],
        'B' => ["#### ", "#   #", "#### ", "#   #", "#### "],
        'C' => [" ####", "#    ", "#    ", "#    ", " ####"],
        'D' => ["#### ", "#   #", "#   #", "#   #", "#### "],
        'E' => ["#####", "#    ", "#### ", "#    ", "#####"],
        'F' => ["#####", "#    ", "#### ", "#    ", "#    "],
        'G' => [" ####", "#    ", "#  ##", "#   #", " ####"],
        'H' => ["#   #", "#   #", "#####", "#   #", "#   #"],
        'I' => ["#####", "  #  ", "  #  ", "  #  ", "#####"],
        'J' => ["#####", "   # ", "   # ", "#  # ", " ##  "],
        'K' => ["#   #", "#  # ", "###  ", "#  # ", "#   #"],
        'L' => ["#    ", "#    ", "#    ", "#    ", "#####"],
        'M' => ["#   #", "## ##", "# # #", "#   #", "#   #"],
        'N' => ["#   #", "##  #", "# # #", "#  ##", "#   #"],
        'O' => [" ### ", "#   #", "#   #", "#   #", " ### "],
        'P' => ["#### ", "#   #", "#### ", "#    ", "#    "],
        'Q' => [" ### ", "#   #", "# # #", "#  # ", " ## #"],
        'R' => ["#### ", "#   #", "#### ", "#  # ", "#   #"],
        'S' => [" ####", "#    ", " ### ", "    #", "#### "],
        'T' => ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
        'U' => ["#   #", "#   #", "#   #", "#   #", " ### "],
        'V' => ["#   #", "#   #", "#   #", " # # ", "  #  "],
        'W' => ["#   #", "#   #", "# # #", "## ##", "#   #"],
        'X' => ["#   #", " # # ", "  #  ", " # # ", "#   #"],
        'Y' => ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
        'Z' => ["#####", "   # ", "  #  ", " #   ", "#####"],
        '0' => [" ### ", "#  ##", "# # #", "##  #", " ### "],
        '1' => ["  #  ", " ##  ", "  #  ", "  #  ", "#####"],
        '2' => [" ### ", "#   #", "  ## ", " #   ", "#####"],
        '3' => ["#### ", "    #", " ### ", "    #", "#### "],
        '4' => ["#  # ", "#  # ", "#####", "   # ", "   # "],
        '5' => ["#####", "#    ", "#### ", "    #", "#### "],
        '6' => [" ### ", "#    ", "#### ", "#   #", " ### "],
        '7' => ["#####", "   # ", "  #  ", " #   ", " #   "],
        '8' => [" ### ", "#   #", " ### ", "#   #", " ### "],
        '9' => [" ### ", "#   #", " ####", "    #", " ### "],
        '!' => ["  #  ", "  #  ", "  #  ", "     ", "  #  "],
        '?' => [" ### ", "#   #", "  ## ", "     ", "  #  "],
        '.' => ["     ", "     ", "     ", "     ", "  #  "],
        '-' => ["     ", "     ", "#####", "     ", "     "],
        '+' => ["     ", "  #  ", "#####", "  #  ", "     "],
        '*' => ["# # #", " ### ", "#####", " ### ", "# # #"],
        '/' => ["    #", "   # ", "  #  ", " #   ", "#    "],
        ':' => ["     ", "  #  ", "     ", "  #  ", "     "],
        '=' => ["     ", "#####", "     ", "#####", "     "],
        '#' => [" # # ", "#####", " # # ", "#####", " # # "],
        _ => ["     ", "     ", "     ", "     ", "     "],
    }
}

/// units table: (name, micro-multiplier to category base, category)
const UNITS: &[(&str, u64, &str)] = &[
    ("mm", 1_000, "len"), ("cm", 10_000, "len"), ("m", 1_000_000, "len"),
    ("km", 1_000_000_000, "len"), ("in", 25_400, "len"), ("ft", 304_800, "len"),
    ("yd", 914_400, "len"), ("mi", 1_609_344_000, "len"),
    ("mg", 1, "mass"), ("g", 1_000, "mass"), ("kg", 1_000_000, "mass"),
    ("t", 1_000_000_000, "mass"), ("oz", 28_350, "mass"), ("lb", 453_592, "mass"),
    ("B", 1, "data"), ("KiB", 1_024, "data"), ("MiB", 1_048_576, "data"),
    ("GiB", 1_073_741_824, "data"), ("TiB", 1_099_511_627_776, "data"),
    ("KB", 1_000, "data"), ("MB", 1_000_000, "data"), ("GB", 1_000_000_000, "data"),
    ("ms", 1_000, "time"), ("s", 1_000_000, "time"), ("min", 60_000_000, "time"),
    ("h", 3_600_000_000, "time"), ("d", 86_400_000_000, "time"),
    ("w", 604_800_000_000, "time"),
];

/// Real HTML->text: drop script/style, block tags -> newline, decode the
/// common entities, collapse whitespace, wrap at ~72 cols.
fn html_to_text(html: &[u8]) -> String {
    let s = String::from_utf8_lossy(html).into_owned();
    let mut out = String::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let (mut i, mut skip) = (0usize, 0u32);
    while i < b.len() {
        if b[i] == b'<' {
            if let Some(end) = s[i..].find('>') {
                let tag = s[i + 1..i + end].trim().to_lowercase();
                let tn: &str = tag.trim_start_matches('/').split(|c: char| c == ' ' || c == '>').next().unwrap_or("");
                if tn == "script" || tn == "style" || tn == "head" {
                    skip += if tag.starts_with('/') { 0 } else { 1 };
                    if tag.starts_with('/') && skip > 0 {
                        skip -= 1;
                    }
                }
                if skip == 0 && matches!(tn, "p" | "div" | "br" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "hr" | "title") {
                    out.push('\n');
                }
                i += end + 1;
                continue;
            }
            break;
        }
        if b[i] == b'&' {
            if let Some(end) = s[i..].find(';') {
                if end <= 10 {
                    let ent = &s[i + 1..i + end];
                    let rep = match ent {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "nbsp" => " ",
                        "#39" | "apos" => "'",
                        _ => "",
                    };
                    if !rep.is_empty() || ent.starts_with('#') && ent[1..].parse::<u32>().is_ok() {
                        if rep.is_empty() {
                            // numeric entity
                            if let Ok(cp) = ent[1..].parse::<u32>() {
                                out.push(char::from_u32(cp).unwrap_or(' '));
                            }
                        } else {
                            out.push_str(rep);
                        }
                        i += end + 1;
                        continue;
                    }
                }
            }
        }
        if skip == 0 {
            let c = b[i] as char;
            out.push(if c.is_whitespace() { ' ' } else { c });
        }
        i += 1;
    }
    // preserve block-tag newlines; wrap each paragraph to ~72 cols
    let mut res = String::new();
    for para in out.split('\n') {
        let mut col = 0usize;
        let mut any = false;
        for word in para.split(' ').filter(|w| !w.is_empty()) {
            if col + word.len() + 1 > 72 && col > 0 {
                res.push('\n');
                col = 0;
            } else if col > 0 {
                res.push(' ');
                col += 1;
            }
            res.push_str(word);
            col += word.len();
            any = true;
        }
        if any {
            res.push('\n');
        }
    }
    res
}

fn now_str() -> String {
    let d = ustd::datetime();
    alloc::format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        d.year, d.month, d.day, d.hour, d.minute, d.second
    )
}

fn fmt_fixed(millionths: u64) -> String {
    // millionths -> "i.frac" with trailing zeros trimmed
    let i = millionths / 1_000_000;
    let mut f = millionths % 1_000_000;
    if f == 0 {
        return alloc::format!("{}", i);
    }
    let mut digs = alloc::format!("{:06}", f);
    while digs.ends_with('0') {
        digs.pop();
    }
    alloc::format!("{}.{}", i, digs)
}

fn mkdir_parents(path: &str) {
    let mut acc = String::new();
    if path.starts_with('/') {
        acc.push('/');
    }
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        if !acc.is_empty() && !acc.ends_with('/') {
            acc.push('/');
        }
        acc.push_str(part);
        let _ = ustd::mkdir(&acc);
    }
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

/// mkdir -p: create each missing component of `path` (absolute or relative).
fn mkdir_p(path: &str) -> Result<(), i64> {
    let mut cur = String::new();
    if path.starts_with('/') {
        cur.push('/');
    }
    for c in path.split('/').filter(|c| !c.is_empty()) {
        if !cur.is_empty() && !cur.ends_with('/') {
            cur.push('/');
        }
        cur.push_str(c);
        match ustd::mkdir(&cur) {
            Ok(()) | Err(_) => {} // exists-or-created both fine
        }
    }
    Ok(())
}

/// Append `path` (file or directory) to a ustar archive; recurses into dirs
/// emitting typeflag-'5' directory entries. `name` in the archive keeps the
/// path given (stripped of a leading '/').
fn tar_add(arc: &mut Vec<u8>, path: &str) -> usize {
    let st = match ustd::stat(path) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let name = path.trim_start_matches('/');
    if st.is_dir != 0 {
        // dir entry
        let mut h = [0u8; 512];
        let dn = alloc::format!("{}/", name.trim_end_matches('/'));
        let nb = dn.as_bytes();
        let nn = nb.len().min(100);
        h[..nn].copy_from_slice(&nb[..nn]);
        tar_octal(&mut h, 100, 8, 0o755);
        tar_octal(&mut h, 136, 12, st.mtime);
        for i in 148..156 {
            h[i] = b' ';
        }
        h[156] = b'5';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263] = b'0';
        h[264] = b'0';
        let sum: u64 = h.iter().map(|b| *b as u64).sum();
        tar_octal(&mut h, 148, 8, sum);
        h[155] = b' ';
        arc.extend_from_slice(&h);
        let mut n = 1usize;
        if let Ok(ents) = ustd::readdir(path) {
            for e in ents {
                let en = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("");
                if en == "." || en == ".." || en.is_empty() {
                    continue;
                }
                let c = tar_add(arc, &alloc::format!("{}/{}", path, en));
                if c == 0 {
                    return 0;
                }
                n += c;
            }
        }
        return n;
    }
    let d = match ustd::read_all(path) {
        Ok(d) => d,
        Err(_) => return 0,
    };
    let mut h = [0u8; 512];
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
    1
}

/// Options for one grep pass (file or stdin).
#[derive(Clone, Copy, Default)]
struct GrepOpts {
    rec: bool,
    inv: bool,
    num: bool,
    cnt: bool,
    ci: bool,
    word: bool,
    exact: bool,
    only: bool,  // -o: print just the matching spans
    quiet: bool, // -q: status only
    files: u8,   // 0 normal, 1 = -l (with matches), 2 = -L (without)
    before: usize,
    after: usize,
    maxm: usize,
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
    httpd: Option<(ustd::TcpListener, String)>,        // `httpd <port> [root]` server mode
    nc: Option<ustd::TcpSock>,                         // `nc <ip> <port>` raw session
    nc_listen: Option<ustd::TcpListener>,              // `nc -l <port>` waiting for a client
    nc_udp: Option<(ustd::UdpSock, Option<([u8; 4], u16)>)>, // `nc -u`/`-lu` UDP session (peer learned)
    last_ok: bool,                                     // success of the last statement (for && / ||)
    sel: Option<((usize, usize), (usize, usize))>,     // scrollback selection (line,col)->(line,col)
    sel_drag: bool,                                    // left button currently held
    pq: String,                                        // pager search query
    pg_input: bool,                                    // pager `/` input active
    tailf: Option<(String, u64)>,
    top: Option<u64>,           // top mode: refresh interval ms
    jobs: Vec<(u32, String)>,   // tracked spawned processes (jobs/fg/disown/$!)
    last_spawn: u32,            // pid of the most recent spawned process ($!)
    strace_p: Option<u32>,      // pid being syscall-traced (strace -p, modal)
    setx: bool,                 // set -x: echo each statement before running
    errexit: bool,              // set -e: abort the statement list on failure
    no_alias_once: bool,        // builtin/command: skip alias expansion once
    top_last: u64,
    top_prev: Vec<(u32, u64)>,  // (pid, cpu_ticks) snapshot for %CPU deltas                      // `tail -f`: (path, next byte offset)
    tailf_last: u64,                                   // last poll ms
    yesing: Option<String>,                            // `yes`: repeated line (mode)
    at_q: Vec<(u64, String)>,                          // `at`: (fire_ms, cmd) deferred commands
    cron_q: Vec<(u64, u64, String)>,                   // `cron`: (period_ms, next_fire_ms, cmd)
    yank: String,                                       // readline kill-ring (Ctrl-K/U/W -> Ctrl-Y)
    cap_bin: Option<Vec<u8>>,                           // binary capture channel (gzip -c etc.)
    last_cap_bin: Vec<u8>,                              // bin captured by the last run_captured
    script_fd: Option<i64>,                             // `script` typescript log fd
    prev_buttons: u8,                                  // pointer buttons last event (edge detect)
    aliases: Vec<(String, String)>,                    // `alias` table (name -> expansion)
    subst_depth: u8,                                   // $(...) recursion guard
    rs: Option<(String, usize)>,                       // Ctrl-R search: (query, oldest scanned hist idx)
    rs_saved: String,                                  // edit line saved when rsearch began
    run_depth: u8,                                     // nested run() calls don't record history
    read_modal: Option<(String, usize)>,               // interactive `read VAR` awaiting a typed line
    funcs: Vec<(String, String)>,                      // user functions: name -> body source
    func_collect: Option<String>,                      // function name while its multi-line body is collected
    func_depth: u8,                                    // recursion guard for function calls
    func_bdepth: i32,                                  // brace depth while collecting a func body
    block_buf: String,                                 // unfinished for/while/if/heredoc input awaiting its closer
    heredocs: Vec<String>,                             // heredoc bodies extracted by norm_stmts (`<<\x01N` markers)
    flow: u8,                                          // 0 none, 1 break, 2 continue, 3 script-exit
    script_depth: u8,                                  // >0 inside sh/source/eval -- `exit` stops script not window
    dirstack: Vec<String>,                             // pushd/popd stack (dirs prints it)
    host: String,                                      // hostname (persisted in /hostname)
}

impl Term {
    fn push_line(&mut self, s: &str) {
        // tabs have no glyph in the 8x8 font -- expand to 4 spaces
        let owned = if s.contains('\t') {
            s.replace('\t', "    ")
        } else {
            String::from(s)
        };
        if let Some(fd) = self.script_fd {
            let _ = ustd::write(fd, alloc::format!("{}\n", owned).as_bytes());
        }
        // wrap at COLS
        let mut rest = owned.as_str();
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
    /// stage, else to the scrollback. Embedded newlines split into lines.
    fn emit(&mut self, s: &str) {
        let mut cleaned = String::new();
        let s = self.bell(s, &mut cleaned);
        for l in s.split('\n') {
            if let Some(c) = self.capture.as_mut() {
                c.push(String::from(l));
            } else {
                self.push_line(l);
            }
        }
    }

    /// Binary command output: captured byte-exact during pipes/redirects,
    /// lossy-printed to the scrollback otherwise.
    fn emit_bin(&mut self, data: &[u8]) {
        if let Some(c) = self.cap_bin.as_mut() {
            c.extend_from_slice(data);
        } else {
            let s = String::from_utf8_lossy(data).into_owned();
            self.emit(&s);
        }
    }

    /// BEL (\\x07) rings the PC speaker instead of printing a glyph.
    fn bell<'a>(&mut self, s: &'a str, cleaned: &'a mut String) -> &'a str {
        if !s.contains('\x07') {
            return s;
        }
        ustd::beep(880, 80);
        *cleaned = s.chars().filter(|&c| c != '\x07').collect();
        cleaned
    }

    /// `echo -n` semantics: append to the current last line (screen or
    /// capture) instead of starting a new one.
    fn emit_no_nl(&mut self, s: &str) {
        let mut cleaned = String::new();
        let s = self.bell(s, &mut cleaned);
        if let Some(c) = self.capture.as_mut() {
            match c.last_mut() {
                Some(last) => last.push_str(s),
                None => c.push(String::from(s)),
            }
        } else {
            match self.lines.last_mut() {
                Some(last) => last.push_str(s),
                None => self.push_line(s),
            }
        }
    }

    /// Emit an error line and mark the current statement failed (for
    /// `&&`/`||` statement chaining).
    fn fail(&mut self, s: &str) {
        self.last_ok = false;
        self.emit(s);
    }

    /// Apply a unified diff to files in cwd: `---`/`+++` headers pick the
    /// target, each `@@ -s,c +s,c @@` hunk is located by matching its
    /// context+removed lines (searched ±64 lines around the expected spot,
    /// tracking cumulative offset like real patch).
    fn run_patch(&mut self, text: &str) {
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0usize;
        let mut any = false;
        while i < lines.len() {
            // --- a/name / --- name
            if !lines[i].starts_with("--- ") {
                i += 1;
                continue;
            }
            let mut target = String::new();
            // GNU patch prefers the '---' (old) name; fall back to '+++'
            let mut name = |l: &str| -> String {
                let n = l[4..].trim().split_whitespace().next().unwrap_or("");
                let n = n.strip_prefix("a/").or_else(|| n.strip_prefix("b/")).unwrap_or(n);
                String::from(n)
            };
            if let Some(p) = lines.get(i + 1) {
                if p.starts_with("+++ ") {
                    let old_name = name(lines[i]);
                    let new_name = name(p);
                    target = if ustd::stat(&old_name).is_ok() || new_name.is_empty() {
                        old_name
                    } else {
                        new_name
                    };
                    i += 2;
                } else {
                    i += 1;
                    continue;
                }
            }
            // gather this file's hunks
            let mut hunks: Vec<(usize, Vec<String>, Vec<String>)> = Vec::new();
            while i < lines.len() && !lines[i].starts_with("--- ") {
                if !lines[i].starts_with("@@") {
                    i += 1;
                    continue;
                }
                let hdr = lines[i];
                i += 1;
                // @@ -a,b +c,d @@
                let (a_start, _b_start) = match parse_hunk(hdr) {
                    Some(x) => x,
                    None => {
                        self.fail(&alloc::format!("patch: bad hunk header '{}'", hdr));
                        return;
                    }
                };
                let (mut old, mut new) = (Vec::new(), Vec::new());
                while i < lines.len() {
                    let l = lines[i];
                    if let Some(r) = l.strip_prefix(' ') {
                        old.push(String::from(r));
                        new.push(String::from(r));
                    } else if let Some(r) = l.strip_prefix('-') {
                        old.push(String::from(r));
                    } else if let Some(r) = l.strip_prefix('+') {
                        new.push(String::from(r));
                    } else if l.starts_with('\\') {
                        // "\ No newline at end of file" — ignore
                    } else {
                        break;
                    }
                    i += 1;
                }
                hunks.push((a_start, old, new));
            }
            if target.is_empty() || hunks.is_empty() {
                continue;
            }
            let data = match ustd::read_all(&target) {
                Ok(d) => d,
                Err(e) => {
                    self.fail(&alloc::format!("patch: {}: err {}", target, e));
                    continue;
                }
            };
            let src: Vec<String> = String::from_utf8_lossy(&data)
                .lines()
                .map(String::from)
                .collect();
            let mut cur = src.clone();
            let mut off = 0i64;
            let mut ok = true;
            for (hno, (a_start, old, new)) in hunks.iter().enumerate() {
                // expected 0-based position + cumulative offset; search ±64
                let want = (*a_start as i64 + off - 1).max(0) as usize;
                let mut at = None;
                'scan: for d in 0..64usize {
                    for cand in [want.saturating_add(d), want.saturating_sub(d)] {
                        if cand + old.len() <= cur.len()
                            && (0..old.len()).all(|x| cur[cand + x] == old[x])
                        {
                            at = Some(cand);
                            break 'scan;
                        }
                    }
                }
                match at {
                    Some(pos) => {
                        cur.splice(pos..pos + old.len(), new.iter().cloned());
                        off = pos as i64 + old.len() as i64 - (*a_start as i64 - 1 + old.len() as i64);
                        self.emit(&alloc::format!(
                            "patching {}: hunk #{} ok at line {}",
                            target, hno + 1, pos + 1
                        ));
                    }
                    None => {
                        self.fail(&alloc::format!(
                            "patch: {}: hunk #{} FAILED at {}",
                            target, hno + 1, a_start
                        ));
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                let joined = cur.join("\n") + "\n";
                match ustd::write_all(&target, joined.as_bytes()) {
                    Ok(()) => any = true,
                    Err(e) => self.fail(&alloc::format!("patch: {}: err {}", target, e)),
                }
            }
        }
        if !any {
            self.fail("patch: no hunks applied");
        }
    }

    /// Run `cmd` with output captured; returns the captured lines.
    /// Binary output (emit_bin) is collected into `last_cap_bin`.
    fn run_captured(&mut self, cmd: &str) -> Vec<String> {
        let saved = self.capture.replace(Vec::new());
        let saved_bin = self.cap_bin.replace(Vec::new());
        self.run(cmd);
        let out = self.capture.take().unwrap_or_default();
        self.last_cap_bin = self.cap_bin.take().unwrap_or_default();
        self.capture = saved;
        self.cap_bin = saved_bin;
        out
    }

    /// Expand $NAME tokens from the shell var table (whole-word vars).
    /// Single-quoted spans are literal (no expansion); double-quoted spans
    /// still expand, matching real-shell quoting rules.
    fn expand_vars(&self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        let mut squote = false;
        let mut dquote = false;
        while i < b.len() {
            if b[i] == b'\'' && !dquote {
                squote = !squote;
                out.push(b[i] as char);
                i += 1;
                continue;
            }
            if b[i] == b'"' && !squote {
                dquote = !dquote;
                out.push(b[i] as char);
                i += 1;
                continue;
            }
            if squote || b[i] != b'$' {
                out.push(b[i] as char);
                i += 1;
                continue;
            }
            if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'$' {
                // $$ -- own pid
                out.push_str(&alloc::format!("{}", ustd::getpid()));
                i += 2;
            } else if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'!' {
                // $! -- pid of the most recent spawned (background) job
                out.push_str(&alloc::format!("{}", self.last_spawn));
                i += 2;
            } else if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'?' {
                // $? -- previous command's exit status (still in last_ok)
                out.push(if self.last_ok { '0' } else { '1' });
                i += 2;
            } else if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'#' {
                // $# -- script positional-argument count (0 outside scripts)
                out.push_str(self.vars.get("#").map(|s| s.as_str()).unwrap_or("0"));
                i += 2;
            } else if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'@' {
                // $@ -- all positional params space-joined
                let n = self
                    .vars
                    .get("#")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                let parts: Vec<String> = (1..=n)
                    .filter_map(|k| self.vars.get(&alloc::format!("{}", k)).cloned())
                    .collect();
                out.push_str(&parts.join(" "));
                i += 2;
            } else if b[i] == b'$' && i + 2 < b.len() && b[i + 1] == b'(' && b[i + 2] == b'(' {
                // $((expr)) -- arithmetic via the real expression evaluator
                let mut depth = 2usize;
                let mut j = i + 3;
                while j < b.len() && depth > 0 {
                    match b[j] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                if depth == 0 {
                    let inner = core::str::from_utf8(&b[i + 3..j - 2]).unwrap_or("");
                    match expr_eval(inner) {
                        Ok(v) => out.push_str(&alloc::format!("{}", v)),
                        Err(e) => out.push_str(&alloc::format!("$(({}:{}))", inner, e)),
                    }
                    i = j;
                } else {
                    out.push('$');
                    i += 1;
                }
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

    /// `test`/`[` evaluator: unary file/string tests and three-token
    /// comparisons. Returns the boolean; `last_ok` mirrors it.
    fn eval_test(&mut self, a: &[&str]) -> bool {
        if a.first() == Some(&"!") {
            return !self.eval_test(&a[1..]);
        }
        match a.len() {
            0 => false,
            1 => !a[0].is_empty(),
            2 => match a[0] {
                "-e" => ustd::stat(a[1]).is_ok(),
                "-f" => ustd::stat(a[1]).map(|s| s.is_dir == 0).unwrap_or(false),
                "-d" => ustd::stat(a[1]).map(|s| s.is_dir != 0).unwrap_or(false),
                "-r" | "-w" | "-x" => ustd::stat(a[1]).is_ok(), // single permissive fs
                "-z" => a[1].is_empty(),
                "-n" => !a[1].is_empty(),
                _ => {
                    self.fail(&alloc::format!("test: unknown unary '{}'", a[0]));
                    false
                }
            },
            3 => {
                let (l, op, r) = (a[0], a[1], a[2]);
                match op {
                    "=" | "==" => l == r,
                    "!=" => l != r,
                    "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" => {
                        match (l.parse::<i64>(), r.parse::<i64>()) {
                            (Ok(li), Ok(ri)) => match op {
                                "-eq" => li == ri,
                                "-ne" => li != ri,
                                "-lt" => li < ri,
                                "-le" => li <= ri,
                                "-gt" => li > ri,
                                _ => li >= ri,
                            },
                            _ => {
                                self.fail("test: integer expression expected");
                                false
                            }
                        }
                    }
                    _ => {
                        self.fail(&alloc::format!("test: unknown op '{}'", op));
                        false
                    }
                }
            }
            _ => {
                self.fail("test: too many arguments");
                false
            }
        }
    }

    /// Expand `$(cmd)` substitutions: runs the inner command with output
    /// captured and splices the text in place (interior newlines kept, like a
    /// real shell's word-splitting after substitution -- quoted `$(...)` stays
    /// one word because the quotes still wrap the spliced text). Ignored inside
    /// single quotes; nested $( ) allowed, recursion capped.
    fn expand_subst(&mut self, s: &str) -> String {
        if self.subst_depth >= 4 || !s.contains("$(") {
            return String::from(s);
        }
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut sq = false;
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'\'' => {
                    sq = !sq;
                    out.push('\'');
                    i += 1;
                }
                b'$' if !sq && i + 1 < b.len() && b[i + 1] == b'(' => {
                    // $(( is arithmetic — expand_vars owns it, not subst
                    if i + 2 < b.len() && b[i + 2] == b'(' {
                        out.push('$');
                        i += 1;
                        continue;
                    }
                    // find matching ')' (nesting counts)
                    let mut d = 1i32;
                    let mut j = i + 2;
                    while j < b.len() && d > 0 {
                        if b[j] == b'(' {
                            d += 1;
                        } else if b[j] == b')' {
                            d -= 1;
                        }
                        j += 1;
                    }
                    if d != 0 {
                        out.push('$');
                        i += 1; // unbalanced -- leave literal
                        continue;
                    }
                    let inner = core::str::from_utf8(&b[i + 2..j - 1]).unwrap_or("");
                    self.subst_depth += 1;
                    let lines = self.run_captured(inner);
                    self.subst_depth -= 1;
                    out.push_str(&lines.join("\n"));
                    i = j;
                }
                c => {
                    out.push(c as char);
                    i += 1;
                }
            }
        }
        out
    }

    /// Replace the command word with its alias (repeat up to 8 hops so
    /// alias-to-alias chains resolve but self-referential ones stop).
    fn expand_alias(&self, input: &str) -> String {
        let mut cur = String::from(input);
        for _ in 0..8 {
            let end = cur.find(char::is_whitespace).unwrap_or(cur.len());
            let head = &cur[..end];
            let Some(v) = self
                .aliases
                .iter()
                .find(|(n, _)| n == head)
                .map(|(_, v)| v.clone())
            else {
                break;
            };
            if v == head {
                break;
            }
            let rest = &cur[end..];
            cur = alloc::format!("{}{}", v, rest);
        }
        cur
    }

    /// Expand one glob arg (`dir/pat` or bare `pat` against cwd).
    /// Returns the matching paths (dir-prefixed when a dir part was given),
    /// or the arg itself untouched when nothing matches -- shell semantics.
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
        if self.read_modal.is_some() {
            return String::new();
        }
        alloc::format!("{} $ ", ustd::getcwd())
    }

    fn finish_read(&mut self, line: String) {
        if let Some((var, n)) = self.read_modal.take() {
            let v = if n > 0 && line.len() > n {
                line[..n].to_string()
            } else {
                line
            };
            self.vars.insert(var, v);
        }
    }

    fn redraw(&mut self) {
        self.c.fill(0, 0, self.c.w as i32, self.c.h as i32, draw::BLACK);
        let rows_vis = (self.c.h as usize / CH as usize).saturating_sub(1);
        let prompt = if let Some((q, _)) = &self.rs {
            alloc::format!("rsearch '{}': ", q)
        } else {
            self.prompt_str()
        };
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

    /// Interactive entry point: tracks call depth so only the top-level
    /// command line reaches history -- nested run() calls (pipe stages, &&
    /// operands, script lines, watch ticks, !! expansions) don't pollute it.
    fn run(&mut self, input: &str) {
        let top = self.run_depth == 0;
        // mid-collection of a multi-line function body: append until the
        // unquoted braces balance
        if top && self.func_collect.is_some() {
            let (o, c) = brace_scan(input);
            self.func_bdepth += o - c;
            self.block_buf.push('\n');
            self.block_buf.push_str(input);
            if self.func_bdepth <= 0 {
                let src = core::mem::take(&mut self.block_buf);
                let name = self.func_collect.take().unwrap();
                self.func_bdepth = 0;
                match func_open(&src) {
                    Some((_, Some(body), trailing)) => {
                        self.funcs.retain(|(n, _)| n != &name);
                        self.funcs.push((name.clone(), body));
                        if !trailing.is_empty() {
                            self.run(&trailing);
                        }
                    }
                    _ => self.fail(&alloc::format!("{}: bad function body", name)),
                }
            } else {
                self.emit("> ");
            }
            return;
        }
        // fresh function definition: name() { ... or `function name { ...`
        if top && !input.trim_start().starts_with('!') {
            if let Some((name, body, trailing)) = func_open(input) {
                match body {
                    Some(b) => {
                        self.funcs.retain(|(n, _)| n != &name);
                        self.funcs.push((name, b));
                        if !trailing.is_empty() {
                            self.run(&trailing);
                        }
                    }
                    None => {
                        let (o, c) = brace_scan(input);
                        self.func_bdepth = o - c;
                        self.block_buf = String::from(input.trim());
                        self.func_collect = Some(name);
                        self.emit("> ");
                    }
                }
                return;
            }
        }
        // continuation of a multi-line block (for/while/until/if/case/heredoc)
        if top && !self.block_buf.is_empty() {
            let joined = alloc::format!("{}\n{}", core::mem::take(&mut self.block_buf), input);
            let (stmts, bodies, unclosed) = norm_stmts(&joined);
            if block_depth(&stmts) > 0 || unclosed.is_some() {
                self.block_buf = joined;
                self.emit("> "); // still unclosed -- keep collecting
            } else {
                self.run_depth = self.run_depth.saturating_add(1);
                self.heredocs = bodies;
                self.run_stmts(&stmts, 0, false);
                self.run_depth = self.run_depth.saturating_sub(1);
            }
            return;
        }
        self.run_depth = self.run_depth.saturating_add(1);
        // record the typed line once, at the top -- recursion via
        // ; && || pipes redirects subst scripts watch never lands in
        // history. `!`-lines record their expansion (inside run_body)
        if top {
            let t = input.trim();
            if !t.is_empty() && !t.starts_with('!') {
                self.hist.push(String::from(t));
                self.hi = self.hist.len();
                self.save_hist();
            }
        }
        // block statements take the structured path -- at any depth, so
        // `eval 'for i in 1 2; do echo $i; done'` works too
        let (stmts, bodies, unclosed) = norm_stmts(input);
        if stmts.iter().any(|s| block_kw(s.trim()) != 0) || unclosed.is_some() {
            if block_depth(&stmts) > 0 || unclosed.is_some() {
                if top {
                    self.block_buf = String::from(input.trim());
                    self.emit("> ");
                } else {
                    self.fail("sh: unterminated block");
                }
            } else {
                let saved = core::mem::replace(&mut self.heredocs, bodies);
                self.run_stmts(&stmts, 0, false);
                self.heredocs = saved;
            }
            self.run_depth = self.run_depth.saturating_sub(1);
            return;
        }
        self.run_body(input, top);
        self.run_depth = self.run_depth.saturating_sub(1);
    }

    /// Execute a normalized statement stream (from `norm_stmts`) with real
    /// block structure: `for VAR in w..` / `while|until COND` loops,
    /// `if/elif/else/fi` conditionals, `break`/`continue`/`exit` control flow.
    /// trace=true echoes `$ stmt` per executed statement (like `sh -x`).
    fn run_stmts(&mut self, stmts: &[String], depth: u8, trace: bool) {
        if depth > 16 {
            self.fail("sh: block nesting too deep");
            return;
        }
        // collect body stmts [start..] until the `done` that closes THIS loop;
        // nested for/while/until/if openers + their closers tracked by a stack
        let collect_loop = |stmts: &[String], start: usize| -> Option<usize> {
            let mut stack: alloc::vec::Vec<u8> = Vec::new();
            let mut j = start;
            while j < stmts.len() {
                let t = stmts[j].trim();
                match block_kw(t) {
                    b'f' => stack.push(b'f'),
                    b'i' => stack.push(b'i'),
                    b'c' => stack.push(b'c'),
                    0 if t == "done" => {
                        if stack.pop() != Some(b'f') {
                            return Some(j); // our closer (stack was empty)
                        }
                    }
                    0 if t == "fi" || t == "esac" => {
                        stack.pop();
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        };
        // for if: collect segments until `fi`, split at depth-0 else/elif
        let collect_if = |stmts: &[String],
                          start: usize|
         -> Option<(usize, Vec<(Option<String>, Vec<String>)>)> {
            let mut stack: alloc::vec::Vec<u8> = Vec::new();
            let mut segs: Vec<(Option<String>, Vec<String>)> =
                alloc::vec![(None, Vec::new())]; // cond patched by caller
            let mut j = start;
            while j < stmts.len() {
                let t = stmts[j].trim();
                if stack.is_empty() {
                    if t == "fi" {
                        return Some((j + 1, segs));
                    }
                    if t == "else" {
                        segs.push((None, Vec::new()));
                        j += 1;
                        continue;
                    }
                    if let Some(cond) = t.strip_prefix("elif ") {
                        // next stmt must be `then`
                        if stmts.get(j + 1).map(|x| x.trim() == "then") != Some(true) {
                            return None; // elif without then: malformed
                        }
                        segs.push((Some(String::from(cond.trim())), Vec::new()));
                        j += 2;
                        continue;
                    }
                    if t == "done" || t == "esac" {
                        return None; // done/esac inside if-body without a loop/case: malformed
                    }
                }
                match block_kw(t) {
                    b'f' => stack.push(b'f'),
                    b'i' => stack.push(b'i'),
                    b'c' => stack.push(b'c'),
                    0 if t == "done" || t == "fi" || t == "esac" => {
                        stack.pop();
                    }
                    _ => {}
                }
                segs.last_mut().unwrap().1.push(String::from(t));
                j += 1;
            }
            None
        };
        let mut i = 0usize;
        while i < stmts.len() {
            if self.flow != 0 {
                return; // break/continue/exit unwinds to the owning loop
            }
            let s = String::from(stmts[i].trim());
            i += 1;
            if s.is_empty() {
                continue;
            }
            match block_kw(&s) {
                b'f' => {
                    let is_while = s.starts_with("while");
                    let is_until = s.starts_with("until");
                    // header: `for V in W..` or `while|until COND`
                    let head = s.split_whitespace().next().unwrap_or("");
                    let rest = s[head.len()..].trim();
                    if stmts.get(i).map(|x| x.trim() == "do") != Some(true) {
                        self.fail("sh: 'do' expected");
                        return;
                    }
                    i += 1;
                    let Some(end) = collect_loop(stmts, i) else {
                        self.fail("sh: 'done' expected");
                        return;
                    };
                    let body: Vec<String> = stmts[i..end].to_vec();
                    i = end + 1;
                    if head == "for" {
                        // `for V in w w w` -- expand subst+vars+globs per word.
                        // `for V in` (empty list) iterates zero times, like real sh.
                        let inpos = match rest.find(" in ") {
                            Some(p) => p,
                            None if rest.ends_with(" in") => rest.len() - 3,
                            None => {
                                self.fail("usage: for V in W...; do ...; done");
                                return;
                            }
                        };
                        let var = String::from(rest[..inpos].trim());
                        if var.is_empty()
                            || !var
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            self.fail("sh: bad loop variable");
                            return;
                        }
                        let wstr = if inpos + 4 <= rest.len() {
                            String::from(rest[inpos + 4..].trim())
                        } else {
                            String::new()
                        };
                        let substd = self.expand_subst(&wstr);
                        let vard = self.expand_vars(&substd);
                        let mut words: Vec<String> = Vec::new();
                        for (w, q) in tokenize(&vard) {
                            if !q && (w.contains('*') || w.contains('?')) {
                                words.extend(self.glob_expand(&w));
                            } else {
                                words.push(w);
                            }
                        }
                        for w in words {
                            self.vars.insert(var.clone(), w);
                            self.run_stmts(&body, depth + 1, trace);
                            match self.flow {
                                1 => {
                                    self.flow = 0;
                                    break;
                                }
                                2 => self.flow = 0,
                                f if f != 0 => return,
                                _ => {}
                            }
                        }
                    } else {
                        // while/until: re-run COND each iteration, last_ok decides
                        let mut guard = 0u32;
                        loop {
                            guard += 1;
                            if guard > 200_000 {
                                self.fail("sh: loop iteration limit");
                                return;
                            }
                            self.run(rest);
                            let ok = self.last_ok;
                            if (is_while && !ok) || (is_until && ok) {
                                break;
                            }
                            self.run_stmts(&body, depth + 1, trace);
                            match self.flow {
                                1 => {
                                    self.flow = 0;
                                    break;
                                }
                                2 => self.flow = 0,
                                f if f != 0 => return,
                                _ => {}
                            }
                        }
                    }
                }
                b'i' => {
                    let cond0 = String::from(s[2..].trim());
                    if stmts.get(i).map(|x| x.trim() == "then") != Some(true) {
                        self.fail("sh: 'then' expected");
                        return;
                    }
                    i += 1;
                    let Some((end, mut segs)) = collect_if(stmts, i) else {
                        self.fail("sh: 'fi' expected");
                        return;
                    };
                    i = end;
                    segs[0].0 = Some(cond0);
                    for (cond, body) in &segs {
                        let take = match cond {
                            None => true, // else
                            Some(c) => {
                                self.run(c);
                                self.last_ok
                            }
                        };
                        if take {
                            self.run_stmts(body, depth + 1, trace);
                            break;
                        }
                    }
                }
                b'c' => {
                    // `case WORD in pat [| pat...]) stmts ;; ... esac`
                    let rest = s[4..].trim();
                    let (word, mut armtext) = match rest.find(" in") {
                        Some(p) => (
                            String::from(rest[..p].trim()),
                            String::from(rest[p + 3..].trim()),
                        ),
                        None => (String::from(rest.trim()), String::new()),
                    };
                    // `in` glued to the next stmt (`case W` \n `in a) x`)
                    if armtext.is_empty() {
                        if let Some(nx) = stmts.get(i) {
                            let nx = nx.trim();
                            if nx == "in" {
                                i += 1;
                            } else if let Some(r) = nx.strip_prefix("in ") {
                                armtext = String::from(r.trim());
                                i += 1;
                            }
                        }
                    }
                    // collect the arm region until OUR esac (nested blocks
                    // tracked so an inner esac/done/fi doesn't close us)
                    let mut stack: alloc::vec::Vec<u8> = Vec::new();
                    let mut region: Vec<String> = Vec::new();
                    if !armtext.is_empty() {
                        region.push(armtext);
                    }
                    let mut end = None;
                    while i < stmts.len() {
                        let t = stmts[i].trim();
                        if stack.is_empty() && t == "esac" {
                            end = Some(i + 1);
                            break;
                        }
                        match block_kw(t) {
                            b'f' => stack.push(b'f'),
                            b'i' => stack.push(b'i'),
                            b'c' => stack.push(b'c'),
                            0 if t == "done" || t == "fi" || t == "esac" => {
                                let want = if t == "done" {
                                    b'f'
                                } else if t == "fi" {
                                    b'i'
                                } else {
                                    b'c'
                                };
                                if stack.pop() != Some(want) {
                                    self.fail("sh: mismatched block end");
                                    return;
                                }
                            }
                            _ => {}
                        }
                        region.push(String::from(t));
                        i += 1;
                    }
                    let Some(e) = end else {
                        self.fail("sh: 'esac' expected");
                        return;
                    };
                    i = e;
                    // arms split at the empty stmt a `;;` leaves behind;
                    // each arm head is `pats) first-body-stmt`
                    let mut arms: Vec<(Vec<String>, Vec<String>)> = Vec::new();
                    let mut cur: Option<(Vec<String>, Vec<String>)> = None;
                    for st in region {
                        let t = st.trim();
                        if t.is_empty() {
                            if let Some(a) = cur.take() {
                                arms.push(a);
                            }
                            continue;
                        }
                        // `pats)` arm head: a `)` before any whitespace. POSIX
                        // wants `;;` between arms but we also accept bare
                        // `pats)` lines (friendlier for hand-typed scripts).
                        let headp = t
                            .find(')')
                            .filter(|p| !t[..*p].bytes().any(|c| c == b' ' || c == b'\t'));
                        if cur.is_none() || headp.is_some() {
                            if let Some(a) = cur.take() {
                                arms.push(a);
                            }
                            let Some(p) = headp else {
                                self.fail("sh: case arm ')' expected");
                                return;
                            };
                            {
                                let pats = t[..p].trim_start_matches('(').trim();
                                let list: Vec<String> = pats
                                    .split('|')
                                    .map(|x| String::from(x.trim()))
                                    .filter(|x| !x.is_empty())
                                    .collect();
                                let mut body = Vec::new();
                                let r = t[p + 1..].trim();
                                if !r.is_empty() {
                                    body.push(String::from(r));
                                }
                                cur = Some((list, body));
                            }
                        } else {
                            cur.as_mut().unwrap().1.push(String::from(t));
                        }
                    }
                    if let Some(a) = cur.take() {
                        arms.push(a);
                    }
                    // expand the case word, match arms in order (first wins)
                    let wsub = self.expand_subst(&word);
                    let w = self.expand_vars(&wsub);
                    for (pats, body) in &arms {
                        if pats.iter().any(|p| wild_match(p, &w)) {
                            self.run_stmts(body, depth + 1, trace);
                            break;
                        }
                    }
                }
                _ => {
                    if trace && self.script_depth > 0 {
                        self.emit(&alloc::format!("+ {}", s));
                    }
                    self.run(&s);
                    if self.errexit && !self.last_ok {
                        return;
                    }
                }
            }
        }
    }

    fn run_body(&mut self, input: &str, top: bool) {
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
            } else if let Ok(n) = spec.parse::<usize>() {
                n.checked_sub(1)
            } else {
                // !prefix -- most recent history entry starting with `spec`
                self.hist.iter().rposition(|l| l.starts_with(spec))
            };
            match idx.and_then(|i| self.hist.get(i).cloned()) {
                Some(line) => {
                    self.push_line(&alloc::format!("$ {}", line));
                    if top {
                        // like bash: `!!`/!n records the expansion, not the `!` line
                        self.hist.push(line.clone());
                        self.hi = self.hist.len();
                        self.save_hist();
                    }
                    self.run(&line);
                }
                None => self.fail(&alloc::format!("!: no such history entry '{}'", spec)),
            }
            return;
        }
        // set -x: echo each statement (bash-style '+' prefix)
        if self.setx {
            self.emit(&alloc::format!("+ {}", input));
        }
        // alias expansion on the command word (chains resolve, cap 8)
        let aliased = if self.no_alias_once {
            self.no_alias_once = false;
            String::from(input)
        } else {
            self.expand_alias(input)
        };
        let input = aliased.as_str();
        // `cmd &`: spawn a /bin/<cmd> process and track it as a job.
        // (Builtins are in-process — a trailing & on one is a syntax error.)
        if let Some(inner) = strip_bg(input) {
            let w = inner.split_whitespace().next().unwrap_or("");
            let rest = inner[w.len()..].trim();
            let path = alloc::format!("/bin/{}", w);
            if ustd::stat(&path).is_ok() {
                match ustd::spawn(&path, rest) {
                    Ok(pid) => {
                        self.track(pid, inner);
                        self.emit(&alloc::format!("[{}] {}", self.jobs.len(), pid));
                    }
                    Err(_) => self.fail(&alloc::format!("{}: spawn failed", w)),
                }
            } else {
                self.fail(&alloc::format!(
                    "{}: not a binary — `&` spawns /bin/<name> (builtins run synchronously)", w
                ));
            }
            return;
        }
        // statement operators: `a; b` (always), `a && b` (on ok), `a || b` (on fail)
        if let Some((l, op, r)) = stmt_split(input) {
            self.last_ok = true;
            self.run(l);
            let ok = self.last_ok;
            if self.errexit && !ok {
                return; // set -e: a failed stmt aborts the rest of the list
            }
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
        // input redirect: cmd < file  (file content becomes the command's stdin;
        // parsed before `>` so `cmd < in > out` and `cmd > out < in` both work)
        if let Some(li) = find_unquoted(input, b'<') {
            let left = input[..li].trim();
            let rest = input[li + 1..].trim();
            // here-string: `cmd <<< text` — expanded text becomes stdin
            if rest.starts_with("<<") {
                let mut txt = rest[2..].trim();
                if txt.len() >= 2
                    && ((txt.starts_with('"') && txt.ends_with('"'))
                        || (txt.starts_with('\'') && txt.ends_with('\'')))
                {
                    txt = &txt[1..txt.len() - 1];
                }
                let sub = self.expand_subst(txt);
                let expanded = self.expand_vars(&sub);
                let saved = self.pipe_in.replace(expanded);
                self.run(left);
                self.pipe_in = saved;
                return;
            }
            // heredoc: `<<\x01N` marker left by norm_stmts -> stdin = body N
            if rest.starts_with('<') {
                let tag = rest[1..].trim_start();
                if let Some(nstr) = tag.strip_prefix('\x01') {
                    let dlen = nstr.bytes().take_while(|c| c.is_ascii_digit()).count();
                    if let Ok(n) = nstr[..dlen].parse::<usize>() {
                        let tail = nstr[dlen..].trim();
                        let body = match self.heredocs.get(n) {
                            Some(b) => b.clone(),
                            None => {
                                self.fail("sh: missing heredoc body");
                                return;
                            }
                        };
                        let saved = self.pipe_in.replace(body);
                        // tail may carry an output redirect (`cat <<E > out`)
                        let line = if tail.is_empty() {
                            String::from(left)
                        } else {
                            alloc::format!("{} {}", left, tail)
                        };
                        self.run(&line);
                        self.pipe_in = saved;
                        return;
                    }
                }
                self.fail("usage: <cmd> < file  (or <<DELIM heredoc)");
                return;
            }
            let infile = rest.split_whitespace().next().unwrap_or("");
            if infile.is_empty() {
                self.fail("usage: <cmd> < file");
                return;
            }
            let after = rest[infile.len()..].trim();
            match ustd::read_all(infile) {
                Ok(d) => {
                    let s = String::from_utf8_lossy(&d).into_owned();
                    let saved = self.pipe_in.replace(s);
                    if after.is_empty() {
                        self.run(left);
                    } else {
                        self.run(&alloc::format!("{} {}", left, after));
                    }
                    self.pipe_in = saved;
                }
                Err(e) => self.fail(&alloc::format!("< {}: err {}", infile, e)),
            }
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
            let bin = core::mem::take(&mut self.last_cap_bin);
            let r = if !bin.is_empty() {
                // binary output (e.g. gzip -c): byte-exact, no trailing NL
                if append {
                    let mut prev = ustd::read_all(fname).unwrap_or_default();
                    prev.extend_from_slice(&bin);
                    ustd::write_all(fname, &prev)
                } else {
                    ustd::write_all(fname, &bin)
                }
            } else {
                let mut body = out.join("\n");
                if !body.is_empty() && !nonl {
                    body.push('\n');
                }
                if append {
                    let mut prev = ustd::read_all(fname).unwrap_or_default();
                    prev.extend_from_slice(body.as_bytes());
                    ustd::write_all(fname, &prev)
                } else {
                    ustd::write_all(fname, body.as_bytes())
                }
            };
            if let Err(e) = r {
                self.fail(&alloc::format!("{}: err {}", fname, e));
            }
            return;
        }
        // $(cmd) substitution, then $VAR expansion
        let substd = self.expand_subst(input);
        let expanded = self.expand_vars(&substd);
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
            "show", "tar", "md5sum", "uuencode", "uudecode", "grep", "find", "file",
            "sha1sum", "cksum", "comm", "zgrep", "zip", "unzip", "chmod", "touch",
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
        // name=value statements (real sh): `x=1 y=2` sets vars; a leading run
        // `x=1 cmd ...` sets them then runs the remainder. Quoted values keep
        // their spaces; the remainder is reconstructed quote-safely.
        {
            let mut ai = 0usize;
            while ai < toks.len() {
                let (w, q) = &toks[ai];
                if *q {
                    break;
                }
                match w.find('=') {
                    Some(eq) if eq > 0 => {
                        let name = &w[..eq];
                        let first = name.chars().next().unwrap_or(' ');
                        if !(first.is_ascii_alphabetic() || first == '_')
                            || !name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            break;
                        }
                        ai += 1;
                    }
                    _ => break,
                }
            }
            if ai > 0 {
                for (w, _) in &toks[..ai] {
                    let eq = w.find('=').unwrap();
                    self.vars
                        .insert(String::from(&w[..eq]), String::from(&w[eq + 1..]));
                }
                let rest: Vec<String> = toks[ai..]
                    .iter()
                    .map(|t| {
                        if t.1 {
                            alloc::format!("'{}'", t.0.replace('\'', ""))
                        } else {
                            t.0.clone()
                        }
                    })
                    .collect();
                if !rest.is_empty() {
                    self.run(&rest.join(" "));
                } else {
                    self.last_ok = true; // bare assignment succeeds
                }
                return;
            }
        }
        // user-defined function call: positional params $0..$9 $# $@ are
        // scoped to the call and restored after (like the `sh` runner)
        if let Some(body) = self
            .funcs
            .iter()
            .find(|(n, _)| n == cmd)
            .map(|(_, b)| b.clone())
        {
            if self.func_depth >= 16 {
                self.fail("function: recursion too deep");
                return;
            }
            let keys: Vec<String> = (0..args.len() + 1)
                .map(|i| {
                    if i == 0 {
                        String::from("#")
                    } else {
                        alloc::format!("{}", i - 1)
                    }
                })
                .collect();
            let saved: Vec<Option<String>> =
                keys.iter().map(|k| self.vars.get(k).cloned()).collect();
            self.vars.insert(String::from("0"), String::from(cmd));
            self.vars
                .insert(String::from("#"), alloc::format!("{}", args.len()));
            for (i, a) in args.iter().enumerate() {
                self.vars.insert(alloc::format!("{}", i + 1), String::from(*a));
            }
            self.func_depth += 1;
            self.run(&body);
            self.func_depth -= 1;
            for (k, v) in keys.iter().zip(saved) {
                match v {
                    Some(v) => {
                        self.vars.insert(k.clone(), v);
                    }
                    None => {
                        self.vars.remove(k);
                    }
                }
            }
            return;
        }
        // optimistic success -- fail() marks the statement failed; $? /
        // && / || read this after the command finishes
        self.last_ok = true;
        match cmd {
            "help" => {
                let lines = Self::HELP_LINES;
                match args.first() {
                    Some(q) => {
                        let mut any = false;
                        for l in lines {
                            if l.contains(q) {
                                self.emit(l);
                                any = true;
                            }
                        }
                        if !any {
                            self.emit(&alloc::format!("help: no entry for '{}'", q));
                        }
                    }
                    None => {
                        for l in lines {
                            self.emit(l);
                        }
                    }
                }
            }
            "ls" => {
                // ls [-aSlr] [paths...]: -a shows dotfiles (hidden by default),
                // -S sorts by size descending, -r reverses, -l forces the long
                // one-per-line form (the default layout already). Multiple dir
                // args get a `path:` header each.
                let mut show_all = false;
                let mut by_size = false;
                let mut by_time = false;
                let mut rev = false;
                let mut i = 0usize;
                while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
                    for c in args[i][1..].chars() {
                        match c {
                            'a' => show_all = true,
                            'S' => by_size = true,
                            't' => by_time = true,
                            'r' => rev = true,
                            'l' | '1' => {}
                            _ => {
                                self.fail(&alloc::format!("ls: bad flag -{}", c));
                                return;
                            }
                        }
                    }
                    i += 1;
                }
                let paths: Vec<&str> = if args.len() <= i {
                    alloc::vec!["."]
                } else {
                    args[i..].to_vec()
                };
                let multi = paths.len() > 1;
                for p in paths {
                    let dir = if p == "." { ustd::getcwd() } else { String::from(p) };
                    // a file (not dir) arg lists the file itself
                    if let Ok(st) = ustd::stat(&dir) {
                        if st.is_dir == 0 {
                            self.emit(&alloc::format!("  {}  ({} B)", dir, st.size));
                            continue;
                        }
                    }
                    if multi {
                        self.emit(&alloc::format!("{}:", dir));
                    }
                    match ustd::readdir(&dir) {
                        Ok(ents) => {
                            let mut ents = ents;
                            if !show_all {
                                ents.retain(|e| e.name[0] != b'.');
                            }
                            if by_size {
                                ents.sort_by(|a, b| {
                                    b.is_dir.cmp(&a.is_dir).then(b.size.cmp(&a.size))
                                });
                            } else if by_time {
                                ents.sort_by(|a, b| b.mtime.cmp(&a.mtime));
                            } else {
                                ents.sort_by(|a, b| {
                                    a.name[..a.name_len as usize]
                                        .cmp(&b.name[..b.name_len as usize])
                                });
                            }
                            if rev {
                                ents.reverse();
                            }
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
            "break" => self.flow = 1,      // unwinds to the enclosing run_stmts loop
            "continue" => self.flow = 2,
            "return" => {
                if self.script_depth > 0 {
                    self.flow = 3; // return from a sourced script
                } else {
                    self.fail("return: only meaningful in a script");
                }
            }
            "eval" => {
                if args.is_empty() {
                    self.fail("usage: eval <cmd> [args...]");
                } else {
                    self.run(&args.join(" "));
                }
            }
            "set" => {
                // set NAME=value | set | set -u NAME | set -x|+x|-e|+e
                match args.first().map(|a| *a) {
                    Some("-x") | Some("+x") | Some("-e") | Some("+e") => {
                        match args[0] {
                            "-x" => self.setx = true,
                            "+x" => self.setx = false,
                            "-e" => self.errexit = true,
                            _ => self.errexit = false,
                        }
                        return;
                    }
                    _ => {}
                }
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
            "export" => {
                // export NAME=value | export NAME  (var exists for child lines)
                match args.first() {
                    Some(a) if a.contains('=') => {
                        let eq = a.find('=').unwrap();
                        let (n, v) = a.split_at(eq);
                        self.vars.insert(String::from(n), String::from(&v[1..]));
                    }
                    Some(a) => {
                        if self.vars.get(*a).is_none() {
                            self.vars.insert(String::from(*a), String::new());
                        }
                    }
                    None => {
                        for (k, v) in self.vars.clone() {
                            self.emit(&alloc::format!("export {}={}", k, v));
                        }
                    }
                }
            }
            "unset" => {
                // unset [-f] NAME...: -f removes functions, plain removes vars
                let mut fflag = false;
                let names: Vec<&str> = args
                    .iter()
                    .filter(|a| {
                        if **a == "-f" {
                            fflag = true;
                            false
                        } else if **a == "-v" {
                            false
                        } else {
                            true
                        }
                    })
                    .cloned()
                    .collect();
                if names.is_empty() {
                    self.fail("usage: unset [-f] NAME...");
                }
                for a in names {
                    if fflag {
                        self.funcs.retain(|(n, _)| n != a);
                    } else {
                        self.vars.remove(a);
                    }
                }
            }
            "function" | "declare" | "typeset" => {
                // bare/`-f` lists defined functions; `function name { ... }`
                // definitions are parsed by run() before we ever get here
                let defs_only = args.iter().any(|a| *a == "-f");
                let flist = self.funcs.clone();
                for (n, b) in &flist {
                    self.emit(&alloc::format!("{}() {{ {}; }}", n, b));
                }
                if self.funcs.is_empty() && !defs_only {
                    self.emit("no functions defined");
                }
            }
            "man" => {
                // man [-k pat] <page>: real man pages from /man/<name>.txt
                match args.first() {
                    Some(&"-k") => {
                        let pat = args.get(1).copied().unwrap_or("").to_lowercase();
                        let mut any = false;
                        if let Ok(ents) = ustd::readdir("/man") {
                            for e in ents {
                                let ename = core::str::from_utf8(
                                    &e.name[..e.name_len as usize],
                                )
                                .unwrap_or("?");
                                let p = alloc::format!("/man/{}", ename);
                                if let Ok(d) = ustd::read_all(&p) {
                                    let first = String::from_utf8_lossy(&d)
                                        .lines()
                                        .next()
                                        .unwrap_or("")
                                        .to_string();
                                    if pat.is_empty()
                                        || first.to_lowercase().contains(&pat)
                                        || ename.to_lowercase().contains(&pat)
                                    {
                                        self.emit(&alloc::format!(
                                            "{} - {}",
                                            ename.trim_end_matches(".txt"),
                                            first
                                        ));
                                        any = true;
                                    }
                                }
                            }
                        }
                        if !any {
                            self.emit(&alloc::format!("{}: nothing appropriate", pat));
                        }
                    }
                    Some(a) => {
                        let p = alloc::format!("/man/{}.txt", a);
                        match ustd::read_all(&p) {
                            Ok(d) => self.emit(&String::from_utf8_lossy(&d)),
                            Err(_) => self.run(&alloc::format!("help {}", a)),
                        }
                    }
                    None => self.emit("man: what manual page do you want?"),
                }
            }
            "env" => {
                // env [-i] [cmd...]: -i runs the command with cleared vars
                if args.first() == Some(&"-i") {
                    let rest: Vec<&str> = args[1..].to_vec();
                    if rest.is_empty() {
                        return;
                    }
                    let saved = core::mem::take(&mut self.vars);
                    self.run(&rest.join(" "));
                    self.vars = saved;
                    return;
                }
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
                    // real touch must not truncate: rewrite existing bytes
                    // (bumps mtime), create empty only when absent
                    match ustd::read_all(p) {
                        Ok(d) => {
                            if let Err(e) = ustd::write_all(p, &d) {
                                self.fail(&alloc::format!("touch: err {}", e));
                            }
                        }
                        Err(_) => {
                            if let Err(e) = ustd::write_all(p, b"") {
                                self.fail(&alloc::format!("touch: err {}", e));
                            }
                        }
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
                // cp [-r] <from> <to> -- into-dir and -r recursive copies work
                let rec = args.iter().any(|a| a == &"-r" || a == &"-R");
                let pos: Vec<&str> = args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .copied()
                    .collect();
                match (pos.first(), pos.get(1)) {
                    (Some(f), Some(t)) => self.cp_any(f, t, rec),
                    _ => self.fail("usage: cp [-r] <from> <to>"),
                }
            }
            "echo" => {
                // echo [-n] [-e] args... -- printing only; `>` redirection is
                // handled by the top-level quote-aware redirect splitter
                let (mut i, mut nonl, mut esc) = (0usize, false, false);
                while i < args.len() && (args[i] == "-n" || args[i] == "-e") {
                    nonl |= args[i] == "-n";
                    esc |= args[i] == "-e";
                    i += 1;
                }
                let mut joined = args[i.min(args.len())..].join(" ");
                if esc {
                    // interpret \n \t \\ escapes
                    let mut s = String::with_capacity(joined.len());
                    let mut it = joined.chars().peekable();
                    while let Some(c) = it.next() {
                        if c == '\\' {
                            match it.next() {
                                Some('n') => s.push('\n'),
                                Some('t') => s.push('\t'),
                                Some('\\') => s.push('\\'),
                                Some(o) => {
                                    s.push('\\');
                                    s.push(o);
                                }
                                None => s.push('\\'),
                            }
                        } else {
                            s.push(c);
                        }
                    }
                    joined = s;
                }
                if nonl {
                    self.emit_no_nl(&joined);
                } else {
                    self.emit(&joined);
                }
            }
            "clear" => self.lines.clear(),
            "ps" => {
                // real /proc-backed table: state+nice from /proc/<pid>/status,
                // cpu/mem from the kernel proclist
                self.emit("  PID  NI  STATE       VSZ_kB   CPU_ms  NAME");
                for p in ustd::proclist(64) {
                    let name = core::str::from_utf8(&p.name)
                        .unwrap_or("?")
                        .trim_end_matches('\0');
                    let (mut st, mut ni) = (String::from("?"), String::from("?"));
                    if let Ok(d) = ustd::read_all(&alloc::format!("/proc/{}/status", p.pid)) {
                        let s = String::from_utf8_lossy(&d).into_owned();
                        for l in s.lines() {
                            if let Some(v) = l.strip_prefix("State:\t") {
                                st = String::from(v.split(' ').next().unwrap_or("?"));
                            }
                            if let Some(v) = l.strip_prefix("Nice:\t") {
                                ni = String::from(v);
                            }
                        }
                    }
                    self.emit(&alloc::format!(
                        "  {:>3}  {:>2}  {:<11} {:>7}  {:>7}  {}",
                        p.pid,
                        ni,
                        &st,
                        p.mem_kb,
                        p.cpu_ticks * 10,
                        name
                    ));
                }
            }
            "nice" => {
                // nice [-n N] <cmd...>: run a command at lower/higher priority
                let (mut ni, mut i) = (10i64, 1usize);
                if args.first() == Some(&"-n") {
                    ni = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                    i = 2;
                }
                if args.len() <= i {
                    // bare nice: show current priority from /proc status
                    let pid = ustd::getpid();
                    let s = ustd::read_all(&alloc::format!("/proc/{}/status", pid))
                        .map(|d| String::from_utf8_lossy(&d).into_owned())
                        .unwrap_or_default();
                    let ni = s.lines()
                        .find_map(|l| l.strip_prefix("Nice:\t"))
                        .unwrap_or("0");
                    self.emit(ni);
                } else {
                    let prev = ustd::set_nice(0, ni);
                    self.emit(&alloc::format!("nice {}: {}", args[i..].join(" "), prev));
                    for l in self.run_captured(&args[i..].join(" ")) {
                        self.emit(&l);
                    }
                    ustd::set_nice(0, 0);
                }
            }
            "renice" => {
                // renice <nice> <pid...>
                match args.first().and_then(|a| a.parse::<i64>().ok()) {
                    None => self.fail("usage: renice <nice -20..19> <pid...>"),
                    Some(ni) => {
                        let mut ok = true;
                        for a in &args[1..] {
                            match a.parse::<u32>() {
                                Ok(pid) => {
                                    let r = ustd::set_nice(pid, ni);
                                    if r == -1000 {
                                        self.fail(&alloc::format!("renice: {}: no such pid", pid));
                                        ok = false;
                                    } else {
                                        self.emit(&alloc::format!("{}: nice -> {}", pid, r));
                                    }
                                }
                                Err(_) => {
                                    self.fail(&alloc::format!("renice: '{}': bad pid", a));
                                    ok = false;
                                }
                            }
                        }
                        if !ok {
                            self.fail("");
                        }
                    }
                }
            }
            "pgrep" | "pkill" => {
                // pgrep [-x] <pat> / pkill [-x] <pat>: match process names
                let exact = args.iter().any(|a| *a == "-x");
                let pat = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");
                let me = ustd::getpid();
                let mut hits = 0usize;
                for p in ustd::proclist(64) {
                    if p.pid == me || p.is_user == 0 {
                        continue;
                    }
                    let name = core::str::from_utf8(&p.name)
                        .unwrap_or("?")
                        .trim_end_matches('\0');
                    let m = if exact { name == pat } else { name.contains(pat) };
                    if m {
                        hits += 1;
                        if cmd == "pgrep" {
                            self.emit(&alloc::format!("{}", p.pid));
                        } else {
                            let ok = ustd::kill(p.pid);
                            self.emit(&alloc::format!(
                                "pkill: {} {} {}",
                                p.pid,
                                name,
                                if ok { "killed" } else { "failed" }
                            ));
                        }
                    }
                }
                if hits == 0 {
                    self.fail(&alloc::format!("{}: no process matched '{}'", cmd, pat));
                }
            }
            "top" => {
                // top [ms]: live process table sorted by %CPU; Esc/Enter/q stops
                let ms = args
                    .first()
                    .and_then(|a| a.parse::<u64>().ok())
                    .unwrap_or(1000)
                    .max(200);
                self.top = Some(ms);
                self.top_last = 0;
                self.top_prev.clear();
            }
            "dc" => {
                // dc: real RPN desk calculator. tokens: nums, + - * / % p n d r c f
                let expr = args.join(" ");
                let src = if expr.is_empty() {
                    self.pipe_in.clone().unwrap_or_default()
                } else {
                    expr
                };
                let mut stack: Vec<i64> = Vec::new();
                let mut bad = false;
                for tok in src.split_whitespace() {
                    match tok.parse::<i64>() {
                        Ok(v) => stack.push(v),
                        Err(_) => match tok {
                            "+" | "-" | "*" | "/" | "%" => {
                                if stack.len() < 2 {
                                    self.fail("dc: stack empty");
                                    bad = true;
                                    break;
                                }
                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                let v = match tok {
                                    "+" => a.wrapping_add(b),
                                    "-" => a.wrapping_sub(b),
                                    "*" => a.wrapping_mul(b),
                                    "/" => {
                                        if b == 0 {
                                            self.fail("dc: div by zero");
                                            bad = true;
                                            break;
                                        }
                                        a / b
                                    }
                                    _ => a % b,
                                };
                                stack.push(v);
                            }
                            "p" => match stack.last() {
                                Some(v) => self.emit(&alloc::format!("{}", v)),
                                None => self.fail("dc: stack empty"),
                            },
                            "n" => match stack.pop() {
                                Some(v) => self.emit(&alloc::format!("{}", v)),
                                None => self.fail("dc: stack empty"),
                            },
                            "d" => match stack.last() {
                                Some(v) => stack.push(*v),
                                None => self.fail("dc: stack empty"),
                            },
                            "r" => {
                                if stack.len() < 2 {
                                    self.fail("dc: stack empty");
                                    bad = true;
                                    break;
                                }
                                let n = stack.len();
                                stack.swap(n - 1, n - 2);
                            }
                            "c" => stack.clear(),
                            "f" => {
                                for v in stack.iter().rev() {
                                    self.emit(&alloc::format!("{}", v));
                                }
                            }
                            _ => {
                                self.fail(&alloc::format!("dc: '{}': bad token", tok));
                                bad = true;
                                break;
                            }
                        },
                    }
                }
                if bad {
                    self.fail("");
                }
            }
            "vmstat" => {
                // real snapshot: procs/memory/cpu from kernel counters
                let mi = ustd::meminfo();
                let procs = ustd::proclist(64);
                let total: u64 = procs.iter().map(|p| p.cpu_ticks).sum();
                let user_ticks: u64 = procs.iter().filter(|p| p.is_user != 0).map(|p| p.cpu_ticks).sum();
                let busy = if total > 0 { user_ticks * 100 / total } else { 0 };
                self.emit("procs ---memory(KB)--- --cpu--");
                self.emit(&alloc::format!(
                    "  {:>3}  {:>9} {:>9}  {:>3}% {:>3}%",
                    procs.len(), mi.used_kb, mi.total_kb - mi.used_kb, busy, 100 - busy
                ));
            }
            "free" => {
                let mi = ustd::meminfo();
                self.emit("           total       used       free");
                self.emit(&alloc::format!(
                    "Mem:    {:>9} {:>9} {:>9} KB",
                    mi.total_kb,
                    mi.used_kb,
                    mi.total_kb - mi.used_kb
                ));
            }
            "pcap" => match args.first().copied() {
                // pcap on|off|status|save <file> -- real ethernet frame capture
                Some("on") => {
                    ustd::pcap(0, &mut []);
                    self.emit("pcap: capturing (256KiB ring, save cap 250KiB)");
                }
                Some("off") | None => {
                    if args.first().is_none() {
                        let st = ustd::pcap(2, &mut []);
                        let (pkts, drop) = ((st >> 32) as u64, st & 0xFFFF_FFFF);
                        self.emit(&alloc::format!(
                            "pcap: {} pkts captured, {} dropped, {}",
                            pkts,
                            drop,
                            if ustd::pcap(3, &mut[]) == 1 { "ON" } else { "OFF" }
                        ));
                    } else {
                        ustd::pcap(1, &mut []);
                        self.emit("pcap: stopped");
                    }
                }
                Some("status") => {
                    let st = ustd::pcap(2, &mut []);
                    self.emit(&alloc::format!(
                        "pcap: {} pkts, {} dropped, {}",
                        (st >> 32) as u64,
                        st & 0xFFFF_FFFF,
                        if ustd::pcap(3, &mut[]) == 1 { "ON" } else { "OFF" }
                    ));
                }
                Some("save") => match args.get(1) {
                    Some(path) => {
                        let mut buf = alloc::vec![0u8; 250 * 1024];
                        let n = ustd::pcap(4, &mut buf);
                        if n < 0 {
                            self.fail(&alloc::format!("pcap: save: err {}", n));
                        } else {
                            match ustd::write_all(path, &buf[..n as usize]) {
                                Ok(_) => self.emit(&alloc::format!(
                                    "  wrote {}B pcap to {}", n, path
                                )),
                                Err(e) => self.fail(&alloc::format!("pcap: {}: err {}", path, e)),
                            }
                        }
                    }
                    None => self.fail("usage: pcap save <file>"),
                },
                Some(_) => self.fail("usage: pcap [on|off|status|save <file>]"),
            },
            "ftp" => {
                // ftp <host[:port]> <remotefile> [localfile]: anonymous FTP RETR (PASV)
                match (args.first(), args.get(1)) {
                    (Some(h), Some(rp)) => {
                        let lp = args.get(2).copied()
                            .map(String::from)
                            .unwrap_or_else(|| {
                                rp.rsplit('/').next().unwrap_or("ftp.out").to_string()
                            });
                        match Self::ftp_get(h, rp) {
                            Ok(d) => match ustd::write_all(&lp, &d) {
                                Ok(_) => self.emit(&alloc::format!(
                                    "ftp: {}B -> {}", d.len(), lp
                                )),
                                Err(e) => self.fail(&alloc::format!("ftp: {}: err {}", lp, e)),
                            },
                            Err(e) => self.fail(&e),
                        }
                    }
                    _ => self.fail("usage: ftp <host[:port]> <remotepath> [localfile]"),
                }
            }
            "lsof" => {
                // real open-file table from /proc/<pid>/fds
                self.emit("PID   FD  PATH");
                for p in ustd::proclist(64) {
                    if let Ok(d) = ustd::read_all(&alloc::format!("/proc/{}/fds", p.pid)) {
                        for l in String::from_utf8_lossy(&d).lines() {
                            if let Some((fd, path)) = l.split_once(": ") {
                                self.emit(&alloc::format!("{:<5} {}  {}", p.pid, fd, path));
                            }
                        }
                    }
                }
            }
            "fuser" => match args.first() {
                // fuser <path>: pids holding the file open
                Some(path) => {
                    let mut hits = 0;
                    for p in ustd::proclist(64) {
                        if let Ok(d) = ustd::read_all(&alloc::format!("/proc/{}/fds", p.pid)) {
                            let hit = String::from_utf8_lossy(&d)
                                .lines()
                                .any(|l| l.split_once(": ").map(|(_, p2)| p2) == Some(*path));
                            if hit {
                                self.emit(&alloc::format!("{}", p.pid));
                                hits += 1;
                            }
                        }
                    }
                    if hits == 0 {
                        self.emit(&alloc::format!("{}: no users", path));
                    }
                }
                None => self.fail("usage: fuser <path>"),
            },
            "burn" => {
                // burn [ms]: real CPU hog for scheduler/nice/top demos
                let ms = args.first().and_then(|a| a.parse::<u64>().ok()).unwrap_or(2000);
                let t0 = ustd::uptime_ms();
                let mut acc = 0u64;
                while ustd::uptime_ms() - t0 < ms {
                    for i in 0..10_000u64 {
                        acc = acc.wrapping_add(i ^ (acc << 1));
                    }
                }
                core::hint::black_box(acc);
                self.emit(&alloc::format!("burned {}ms", ustd::uptime_ms() - t0));
            }
            "cron" => {
                // cron [list|add <sec> <cmd...>|del <n>]: recurring commands in /crontab
                match args.first().copied() {
                    Some("add") => {
                        match (args.get(1).and_then(|s| s.parse::<u64>().ok()), args.get(2)) {
                            (Some(sec), Some(_)) => {
                                let line = alloc::format!("{} {}", sec, args[2..].join(" "));
                                let mut cur = ustd::read_all("/crontab")
                                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                                    .unwrap_or_default();
                                if !cur.is_empty() && !cur.ends_with('\n') {
                                    cur.push('\n');
                                }
                                cur.push_str(&line);
                                cur.push('\n');
                                match ustd::write_all("/crontab", cur.as_bytes()) {
                                    Ok(_) => {
                                        self.cron_load();
                                        self.emit(&alloc::format!("cron: +{}", line));
                                    }
                                    Err(e) => self.fail(&alloc::format!("cron: err {}", e)),
                                }
                            }
                            _ => self.fail("usage: cron add <secs> <cmd...>"),
                        }
                    }
                    Some("del") => {
                        let n = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                        let cur = ustd::read_all("/crontab")
                            .map(|d| String::from_utf8_lossy(&d).into_owned())
                            .unwrap_or_default();
                        let keep: Vec<&str> = cur
                            .lines()
                            .enumerate()
                            .filter(|(i, _)| *i != n)
                            .map(|(_, l)| l)
                            .collect();
                        match ustd::write_all("/crontab", keep.join("\n").as_bytes()) {
                            Ok(_) => {
                                self.cron_load();
                                self.emit(&alloc::format!("cron: -line {}", n));
                            }
                            Err(e) => self.fail(&alloc::format!("cron: err {}", e)),
                        }
                    }
                    _ => {
                        let cur = ustd::read_all("/crontab")
                            .map(|d| String::from_utf8_lossy(&d).into_owned())
                            .unwrap_or_default();
                        if cur.is_empty() {
                            self.emit("cron: empty (cron add <sec> <cmd...>)");
                        }
                        for (i, l) in cur.lines().enumerate() {
                            self.emit(&alloc::format!("  [{}] {}", i, l));
                        }
                        self.emit(&alloc::format!("cron: {} armed entries", self.cron_q.len()));
                    }
                }
            }
            "browse" => match args.first() {
                // browse <url>: fetch + render HTML as text (real tag-strip)
                Some(url) => {
                    let (req, _) = Self::parse_url(url);
                    match ustd::net_http(&req) {
                        Some(body) => {
                            // skip the HTTP header block
                            let txt = String::from_utf8_lossy(&body).into_owned();
                            let h = txt.find("\r\n\r\n")
                                .map(|i| &txt[i + 4..])
                                .or_else(|| txt.find("\n\n").map(|i| &txt[i + 2..]))
                                .unwrap_or(&txt);
                            for l in html_to_text(h.as_bytes()).lines() {
                                self.emit(l);
                            }
                        }
                        None => self.fail(&alloc::format!("browse: {}: failed", req)),
                    }
                }
                None => self.fail("usage: browse <http://host/path>"),
            },
            "mem" => {
                let mi = ustd::meminfo();
                self.emit(&alloc::format!(
                    "  total={}KB used={}KB heap={}KB tasks={}",
                    mi.total_kb, mi.used_kb, mi.kernel_heap_kb, mi.tasks
                ));
            }
            "factor" => {
                // factor N...: trial-division prime factorization
                let mut ok = true;
                for a in args.iter().filter(|a| !a.starts_with('-')) {
                    match a.parse::<u64>() {
                        Ok(0) | Err(_) => {
                            self.fail(&alloc::format!("factor: '{}' not a positive int", a));
                            ok = false;
                        }
                        Ok(n) => {
                            let (mut m, mut fs, mut d) = (n, Vec::new(), 2u64);
                            while d * d <= m && d < 1_000_000 {
                                while m % d == 0 {
                                    fs.push(d);
                                    m /= d;
                                }
                                d += if d == 2 { 1 } else { 2 };
                            }
                            if m > 1 {
                                fs.push(m);
                            }
                            let mut line = alloc::format!("{}:", n);
                            for f in &fs {
                                line.push_str(&alloc::format!(" {}", f));
                            }
                            self.emit(&line);
                        }
                    }
                }
                if !ok {
                    self.last_ok = false;
                }
            }
            "shuf" => {
                // shuf [file|-n N|-i lo-hi]: Fisher-Yates over input lines
                // using kernel rand; -i shuffles lo..hi, -n limits output
                let mut lo = 1u64;
                let mut hi = 0u64;
                let mut limit = usize::MAX;
                let mut file = "";
                let mut skip = false;
                for (i, a) in args.iter().enumerate() {
                    if skip {
                        skip = false;
                        continue;
                    }
                    if let Some(r) = a.strip_prefix("-i") {
                        let r = if r.is_empty() {
                            skip = true;
                            args.get(i + 1).copied().unwrap_or("")
                        } else {
                            r
                        };
                        if let Some((l, h)) = r.split_once('-') {
                            lo = l.parse().unwrap_or(1);
                            hi = h.parse().unwrap_or(0);
                        }
                    } else if let Some(n) = a.strip_prefix("-n") {
                        let n = if n.is_empty() {
                            skip = true;
                            args.get(i + 1).copied().unwrap_or("")
                        } else {
                            n
                        };
                        limit = n.parse().unwrap_or(usize::MAX);
                    } else if !a.starts_with('-') {
                        file = a;
                    }
                }
                let mut lines: Vec<String> = if hi >= lo && file.is_empty() {
                    (lo..=hi).map(|n| alloc::format!("{}", n)).collect()
                } else {
                    let data = if file.is_empty() {
                        self.pipe_in.clone().unwrap_or_default()
                    } else {
                        match ustd::read_all(file) {
                            Ok(d) => String::from_utf8_lossy(&d).into_owned(),
                            Err(e) => {
                                self.fail(&alloc::format!("shuf: {}: err {}", file, e));
                                String::new()
                            }
                        }
                    };
                    data.lines().map(|l| String::from(l)).collect()
                };
                // Fisher-Yates with kernel rand_u64
                for i in (1..lines.len()).rev() {
                    let j = (ustd::rand_u64().unwrap_or(i as u64) % (i as u64 + 1)) as usize;
                    lines.swap(i, j);
                }
                for l in lines.iter().take(limit) {
                    self.emit(l);
                }
            }
            "cksum" => {
                // cksum file: POSIX CRC (0x04C11DB7, reflected, len-augmented)
                let f = args.first().copied().filter(|a| !a.starts_with('-')).unwrap_or("");
                let mut bad = false;
                let data = if f.is_empty() {
                    self.pipe_in.clone().unwrap_or_default().into_bytes()
                } else {
                    match ustd::read_all(f) {
                        Ok(d) => d,
                        Err(e) => {
                            self.fail(&alloc::format!("cksum: {}: err {}", f, e));
                            bad = true;
                            Vec::new()
                        }
                    }
                };
                if !bad {
                    // POSIX cksum: MSB-first poly 0x04C11DB7, then the byte
                    // count fed in LSB-first, final inversion
                    let mut tbl = [0u32; 256];
                    for (i, e) in tbl.iter_mut().enumerate() {
                        let mut c = (i as u32) << 24;
                        for _ in 0..8 {
                            c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C11DB7 } else { c << 1 };
                        }
                        *e = c;
                    }
                    let mut crc = 0u32;
                    for b in &data {
                        crc = (crc << 8) ^ tbl[(((crc >> 24) as u8) ^ *b) as usize];
                    }
                    let mut len = data.len() as u64;
                    while len > 0 {
                        crc = (crc << 8) ^ tbl[(((crc >> 24) as u8) ^ (len & 0xFF) as u8) as usize];
                        len >>= 8;
                    }
                    self.emit(&alloc::format!("{} {} {}", !crc, data.len(), f));
                }
            }
            "tac" => {
                // cat with lines in reverse order (file or stdin)
                let data = match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => d,
                        Err(e) => {
                            self.fail(&alloc::format!("tac: {}: err {}", p, e));
                            Vec::new()
                        }
                    },
                    None => self
                        .pipe_in
                        .clone()
                        .unwrap_or_default()
                        .into_bytes(),
                };
                let s = String::from_utf8_lossy(&data);
                let mut lines: Vec<&str> = s.lines().collect();
                lines.reverse();
                for l in lines {
                    self.emit(l);
                }
            }
            "fold" => {
                // fold [-w N] -- wrap lines at column N (default 80)
                let (mut w, mut file) = (80usize, None);
                let mut it = args.iter().peekable();
                while let Some(a) = it.next() {
                    if *a == "-w" {
                        w = it.next().and_then(|x| x.parse().ok()).unwrap_or(80);
                    } else if let Some(v) = a.strip_prefix("-w") {
                        w = v.parse().unwrap_or(80);
                    } else {
                        file = Some(*a);
                    }
                }
                let data = match file {
                    Some(p) => ustd::read_all(p).unwrap_or_default(),
                    None => self.pipe_in.clone().unwrap_or_default().into_bytes(),
                };
                let s = String::from_utf8_lossy(&data);
                for l in s.lines() {
                    let mut rest = l;
                    while rest.len() > w && w > 0 {
                        let mut cut = w;
                        while !rest.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        self.emit(&rest[..cut]);
                        rest = &rest[cut..];
                    }
                    self.emit(rest);
                }
            }
            "column" => {
                // column -t: align whitespace-separated fields into columns
                let tbl = args.first() == Some(&"-t");
                let file = args.iter().find(|a| **a != "-t");
                let data = match file {
                    Some(p) => ustd::read_all(p).unwrap_or_default(),
                    None => self.pipe_in.clone().unwrap_or_default().into_bytes(),
                };
                let s = String::from_utf8_lossy(&data);
                if !tbl {
                    for l in s.lines() {
                        self.emit(l);
                    }
                } else {
                    let rows: Vec<Vec<&str>> = s
                        .lines()
                        .map(|l| l.split_whitespace().collect())
                        .collect();
                    let ncol = rows.iter().map(|r| r.len()).max().unwrap_or(0);
                    let mut widths = alloc::vec![0usize; ncol];
                    for r in &rows {
                        for (i, c) in r.iter().enumerate() {
                            widths[i] = widths[i].max(c.len());
                        }
                    }
                    for r in &rows {
                        let mut line = String::new();
                        for (i, c) in r.iter().enumerate() {
                            if i + 1 < r.len() {
                                line.push_str(&alloc::format!("{:<w$}  ", c, w = widths[i]));
                            } else {
                                line.push_str(c);
                            }
                        }
                        self.emit(&line);
                    }
                }
            }
            "truncate" => {
                // truncate -s N file -- real length change (pad with zeros or cut)
                let mut size = None;
                let mut file = None;
                let mut it = args.iter().peekable();
                while let Some(a) = it.next() {
                    if *a == "-s" {
                        size = it.next().and_then(|x| x.parse::<usize>().ok());
                    } else if let Some(v) = a.strip_prefix("-s") {
                        size = v.parse().ok();
                    } else {
                        file = Some(*a);
                    }
                }
                match (size, file) {
                    (Some(n), Some(p)) => {
                        let mut d = ustd::read_all(p).unwrap_or_default();
                        d.resize(n, 0);
                        match ustd::write_all(p, &d) {
                            Ok(()) => {}
                            Err(e) => self.fail(&alloc::format!("truncate: err {}", e)),
                        }
                    }
                    _ => self.fail("usage: truncate -s N <file>"),
                }
            }
            "mktemp" => {
                // create a unique empty file under /tmp, print its name
                let _ = ustd::mkdir("/tmp");
                for _ in 0..100 {
                    let p = alloc::format!(
                        "/tmp/tmp{:06}",
                        ustd::rand_u64().unwrap_or(0) % 1_000_000
                    );
                    if ustd::stat(&p).is_err() {
                        match ustd::write_all(&p, b"") {
                            Ok(()) => {
                                self.emit(&p);
                                break;
                            }
                            Err(e) => {
                                self.fail(&alloc::format!("mktemp: err {}", e));
                                break;
                            }
                        }
                    }
                }
            }
            "clip" => {
                // clip [text] | cmd | clip   -- kernel clipboard in/out
                match args.first() {
                    Some(_) => ustd::clip_set(args.join(" ").as_bytes()),
                    None => match self.pipe_in.clone() {
                        Some(s) => ustd::clip_set(s.as_bytes()),
                        None => {
                            let b = ustd::clip_get();
                            if !b.is_empty() {
                                self.emit(&String::from_utf8_lossy(&b));
                            }
                        }
                    },
                }
            }
            "pushd" => match args.first() {
                Some(d) => {
                    let cur = ustd::getcwd();
                    if ustd::chdir(d) {
                        self.dirstack.push(cur);
                        self.emit(&ustd::getcwd());
                    } else {
                        self.fail(&alloc::format!("pushd: {}: no such dir", d));
                    }
                }
                None => self.fail("usage: pushd <dir>"),
            },
            "popd" => match self.dirstack.pop() {
                Some(d) => {
                    if ustd::chdir(&d) {
                        self.emit(&d);
                    } else {
                        self.fail(&alloc::format!("popd: {}: no such dir", d));
                    }
                }
                None => self.fail("popd: directory stack empty"),
            },
            "dirs" => {
                let mut line = ustd::getcwd();
                for d in self.dirstack.iter().rev() {
                    line.push(' ');
                    line.push_str(d);
                }
                self.emit(&line);
            }
            "zip" => {
                // real ZIP container: entries deflate (method 8) when that
                // wins, else STORE — extractable by any standard unzip.
                let Some(zname) = args.first() else {
                    self.fail("usage: zip <out.zip> <file>...");
                    return;
                };
                let (mt, md) = dos_datetime();
                let mut out: Vec<u8> = Vec::new();
                let mut central: Vec<u8> = Vec::new();
                let mut n = 0u16;
                for f in &args[1..] {
                    let data = match ustd::read_all(f) {
                        Ok(d) => d,
                        Err(e) => {
                            self.fail(&alloc::format!("zip: {}: err {}", f, e));
                            continue;
                        }
                    };
                    let name = f.trim_start_matches('/');
                    let crc = crc32(&data);
                    let def = ustd::deflate::deflate(&data);
                    let (body, method) = if def.len() < data.len() {
                        (def, 8u16)
                    } else {
                        (data.clone(), 0u16)
                    };
                    let lhoff = out.len() as u32;
                    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
                    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
                    out.extend_from_slice(&0u16.to_le_bytes());  // flags
                    out.extend_from_slice(&method.to_le_bytes());
                    out.extend_from_slice(&mt.to_le_bytes());
                    out.extend_from_slice(&md.to_le_bytes());
                    out.extend_from_slice(&crc.to_le_bytes());
                    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
                    out.extend_from_slice(name.as_bytes());
                    out.extend_from_slice(&body);
                    central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
                    central.extend_from_slice(&20u16.to_le_bytes()); // made by
                    central.extend_from_slice(&20u16.to_le_bytes()); // need
                    central.extend_from_slice(&0u16.to_le_bytes());
                    central.extend_from_slice(&method.to_le_bytes());
                    central.extend_from_slice(&mt.to_le_bytes());
                    central.extend_from_slice(&md.to_le_bytes());
                    central.extend_from_slice(&crc.to_le_bytes());
                    central.extend_from_slice(&(body.len() as u32).to_le_bytes());
                    central.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
                    central.extend_from_slice(&0u16.to_le_bytes()); // extra
                    central.extend_from_slice(&0u16.to_le_bytes()); // comment
                    central.extend_from_slice(&0u16.to_le_bytes()); // disk
                    central.extend_from_slice(&0u16.to_le_bytes()); // int attr
                    central.extend_from_slice(&0u32.to_le_bytes()); // ext attr
                    central.extend_from_slice(&lhoff.to_le_bytes());
                    central.extend_from_slice(name.as_bytes());
                    n += 1;
                    self.emit(&alloc::format!(
                        "  add: {} ({} -> {} B{})",
                        name, data.len(), body.len(),
                        if method == 8 { ", deflate" } else { ", stored" }
                    ));
                }
                if n == 0 {
                    self.fail("zip: no files added");
                } else {
                    let cd_off = out.len() as u32;
                    let cd_size = central.len() as u32;
                    out.extend_from_slice(&central);
                    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
                    out.extend_from_slice(&0u16.to_le_bytes()); // disk
                    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
                    out.extend_from_slice(&n.to_le_bytes());
                    out.extend_from_slice(&n.to_le_bytes());
                    out.extend_from_slice(&cd_size.to_le_bytes());
                    out.extend_from_slice(&cd_off.to_le_bytes());
                    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
                    match ustd::write_all(zname, &out) {
                        Ok(()) => self.emit(&alloc::format!("zip: {} -> {} ({} B)", n, zname, out.len())),
                        Err(e) => self.fail(&alloc::format!("zip: {}: err {}", zname, e)),
                    }
                }
            }
            "unzip" | "zipinfo" => {
                // parse central directory via the EOCD record at the tail --
                // robust against data-descriptor entries in foreign archives
                let list_only = cmd != "unzip" || args.iter().any(|a| *a == "-l");
                let mut dest = String::new();
                let mut zpath = None;
                let mut it = args.iter();
                while let Some(a) = it.next() {
                    if *a == "-d" {
                        dest = String::from(it.next().copied().unwrap_or(""));
                    } else if *a != "-l" {
                        zpath = Some(*a);
                    }
                }
                let Some(zp) = zpath else {
                    self.fail("usage: unzip [-l] <archive.zip> [-d dir]");
                    return;
                };
                let data = match ustd::read_all(zp) {
                    Ok(d) => d,
                    Err(e) => {
                        self.fail(&alloc::format!("unzip: {}: err {}", zp, e));
                        return;
                    }
                };
                let rd16 = |o: usize| -> Option<u16> {
                    data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
                };
                let rd32 = |o: usize| -> Option<u32> {
                    data.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                };
                // EOCD signature 0x06054b50 in the last 64KiB+22
                let lo = data.len().saturating_sub(65557);
                let mut eocd = None;
                if data.len() >= 22 {
                    for i in (lo..=data.len() - 22).rev() {
                        if rd32(i) == Some(0x0605_4b50) {
                            eocd = Some(i);
                            break;
                        }
                    }
                }
                let Some(eo) = eocd else {
                    self.fail("unzip: not a zip archive (no EOCD)");
                    return;
                };
                let (Some(mut n), Some(mut off)) =
                    (rd16(eo + 10), rd32(eo + 16).map(|x| x as usize))
                else {
                    self.fail("unzip: truncated EOCD");
                    return;
                };
                let mut count = 0u16;
                while n > 0 && off + 46 <= data.len() && rd32(off) == Some(0x0201_4b50) {
                    let method = rd16(off + 10).unwrap_or(0);
                    let usize_ = rd32(off + 24).unwrap_or(0) as usize;
                    let csize_ = rd32(off + 20).unwrap_or(0) as usize;
                    let nlen = rd16(off + 28).unwrap_or(0) as usize;
                    let elen = rd16(off + 30).unwrap_or(0) as usize;
                    let clen = rd16(off + 32).unwrap_or(0) as usize;
                    let lhoff = rd32(off + 42).unwrap_or(0) as usize;
                    let name = data
                        .get(off + 46..off + 46 + nlen)
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default();
                    // sanitize member path: no leading '/', no '.'/'..' parts
                    let is_dir_ent = name.ends_with('/');
                    let name: String = name
                        .split('/')
                        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
                        .collect::<Vec<_>>()
                        .join("/");
                    if name.is_empty() {
                        count += 1;
                        n -= 1;
                        off += 46 + nlen + elen + clen;
                        continue;
                    }
                    if list_only {
                        self.emit(&alloc::format!("{:>8}  {}", usize_, name));
                    } else {
                        // locate the file data: local header's own name/extra
                        // lens differ from the central record's
                        let ok = rd32(lhoff) == Some(0x0403_4b50);
                        let ln = rd16(lhoff + 26).unwrap_or(0) as usize;
                        let le = rd16(lhoff + 28).unwrap_or(0) as usize;
                        let dstart = lhoff + 30 + ln + le;
                        // method 0 (STORE): body is raw usize_ bytes;
                        // method 8 (DEFLATE): body is csize_ compressed bytes
                        let body = data.get(dstart..dstart + if method == 0 { usize_ } else { csize_ });
                        let inflated: Option<Vec<u8>> = match (ok, body, method) {
                            (_, _, m) if m != 0 && m != 8 => {
                                self.fail(&alloc::format!("unzip: {}: method {} unsupported (STORE/DEFLATE only)", name, m));
                                None
                            }
                            (true, Some(b), 8) => match ustd::inflate::inflate(b) {
                                Ok(d) => Some(d),
                                Err(e) => {
                                    self.fail(&alloc::format!("unzip: {}: deflate: {}", name, e));
                                    None
                                }
                            },
                            (true, Some(b), _) => Some(b.to_vec()),
                            _ => {
                                self.fail(&alloc::format!("unzip: {}: bad local header", name));
                                None
                            }
                        };
                        if let Some(b) = inflated {
                            if method == 8 && b.len() != usize_ {
                                self.fail(&alloc::format!("unzip: {}: size mismatch", name));
                            } else {
                                let outp = if dest.is_empty() {
                                    // no -d: extract relative to the CWD
                                    name.clone()
                                } else {
                                    alloc::format!("{}/{}", dest.trim_end_matches('/'), name)
                                };
                                if is_dir_ent {
                                    let _ = ustd::mkdir(&outp);
                                } else {
                                    mkdir_parents(&outp);
                                    if ustd::inflate::crc32(&b) != rd32(off + 16).unwrap_or(0) {
                                        self.fail(&alloc::format!("unzip: {}: bad CRC", name));
                                    } else {
                                        match ustd::write_all(&outp, &b) {
                                            Ok(()) => self.emit(&alloc::format!("  inflating: {}", outp)),
                                            Err(e) => self.fail(&alloc::format!("unzip: {}: err {}", outp, e)),
                                        }
                                    }
                                }
                            }
                        }
                    }
                    count += 1;
                    n -= 1;
                    off += 46 + nlen + elen + clen;
                }
                if count == 0 {
                    self.fail("unzip: empty or corrupt central directory");
                }
            }
            "gzip" => {
                // gzip [-c] file — real DEFLATE compression, writes file.gz
                // (or stdout with -c). Source is kept.
                let to_stdout = args.first().map(|a| *a == "-c").unwrap_or(false);
                let path = args.iter().find(|a| !a.starts_with('-')).copied();
                let Some(p) = path else {
                    self.fail("usage: gzip [-c] <file>");
                    return;
                };
                match ustd::read_all(p) {
                    Ok(d) => {
                        let gz = ustd::deflate::gzip_data(&d);
                        if to_stdout {
                            self.emit_bin(&gz);
                        } else {
                            let outp = alloc::format!("{}.gz", p);
                            match ustd::write_all(&outp, &gz) {
                                Ok(()) => self.emit(&alloc::format!(
                                    "{} -> {} ({} -> {} B, saved {}%)",
                                    p, outp, d.len(), gz.len(),
                                    100usize.saturating_sub(gz.len() * 100 / d.len().max(1))
                                )),
                                Err(e) => self.fail(&alloc::format!("gzip: {}: err {}", outp, e)),
                            }
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("gzip: {}: err {}", p, e)),
                }
            }
            "gunzip" | "zcat" => {
                // gunzip [-c] file.gz — real gzip/DEFLATE decompression.
                // zcat (or -c) writes to stdout; gunzip writes <name minus .gz>.
                let to_stdout = cmd == "zcat" || args.first().map(|a| *a == "-c").unwrap_or(false);
                let path = args.iter().find(|a| !a.starts_with('-')).copied();
                let Some(p) = path else {
                    self.fail("usage: gunzip [-c] <file.gz>  |  zcat <file.gz>");
                    return;
                };
                match ustd::read_all(p) {
                    Ok(d) => match ustd::inflate::gzip_body(&d) {
                        Ok(off) => {
                            // body ends 8 bytes before EOF: isize32 + crc32
                            match ustd::inflate::inflate(&d[off..d.len().saturating_sub(8)]) {
                                Ok(out) => {
                                    let rd32 = |o: usize| -> Option<u32> {
                                        d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                                    };
                                    let isize_ = rd32(d.len() - 4).unwrap_or(0) as usize;
                                    let crc = rd32(d.len() - 8).unwrap_or(0);
                                    if out.len() != isize_ || ustd::inflate::crc32(&out) != crc {
                                        self.fail("gunzip: CRC/size mismatch");
                                    } else if to_stdout {
                                        self.emit_bin(&out);
                                    } else {
                                        let outp = if let Some(st) = p.strip_suffix(".gz") {
                                            String::from(st)
                                        } else {
                                            alloc::format!("{}.out", p)
                                        };
                                        match ustd::write_all(&outp, &out) {
                                            Ok(()) => self.emit(&alloc::format!("{} -> {}", p, outp)),
                                            Err(e) => self.fail(&alloc::format!("gunzip: {}: err {}", outp, e)),
                                        }
                                    }
                                }
                                Err(e) => self.fail(&alloc::format!("gunzip: {}", e)),
                            }
                        }
                        Err(e) => self.fail(&alloc::format!("gunzip: {}", e)),
                    },
                    Err(e) => self.fail(&alloc::format!("gunzip: {}: err {}", p, e)),
                }
            }
            "lspci" => {
                // real PCI config-space enumeration (SYS_PCI_SCAN)
                let mut ents = [shared::PciEnt::default(); 64];
                let n = ustd::pci_scan(&mut ents);
                for e in ents.iter().take(n) {
                    self.emit(&alloc::format!(
                        "  {:02x}:{:02x}.{}  class {:02x}{:02x}  {:04x}:{:04x}",
                        e.bus, e.dev, e.fun, e.class, e.subclass, e.vendor, e.device
                    ));
                }
                if n == 0 {
                    self.emit("  (no pci devices)");
                }
            }
            "lscpu" => {
                // real CPUID vendor/brand/features + rdtsc MHz estimate
                let (mut vendor, mut brand) = ([0u8; 12], [0u8; 48]);
                let (mut ecx1, mut edx1, mut ebx7) = (0u32, 0u32, 0u32);
                unsafe {
                    let r = core::arch::x86_64::__cpuid(0);
                    vendor[0..4].copy_from_slice(&r.ebx.to_le_bytes());
                    vendor[4..8].copy_from_slice(&r.edx.to_le_bytes());
                    vendor[8..12].copy_from_slice(&r.ecx.to_le_bytes());
                    let r = core::arch::x86_64::__cpuid(1);
                    ecx1 = r.ecx;
                    edx1 = r.edx;
                    if core::arch::x86_64::__cpuid(0x80000000).eax >= 0x80000004 {
                        for (i, leaf) in (0x80000002u32..=0x80000004).enumerate() {
                            let r = core::arch::x86_64::__cpuid(leaf);
                            for (j, reg) in [r.eax, r.ebx, r.ecx, r.edx].iter().enumerate() {
                                brand[i * 16 + j * 4..i * 16 + j * 4 + 4]
                                    .copy_from_slice(&reg.to_le_bytes());
                            }
                        }
                    }
                    if core::arch::x86_64::__cpuid(0).eax >= 7 {
                        ebx7 = core::arch::x86_64::__cpuid_count(7, 0).ebx;
                    }
                    let t0 = core::arch::x86_64::_rdtsc();
                    let m0 = ustd::uptime_ms();
                    while ustd::uptime_ms() - m0 < 20 {
                        core::hint::spin_loop();
                    }
                    let mhz = (core::arch::x86_64::_rdtsc() - t0)
                        / ((ustd::uptime_ms() - m0).max(1) * 1000);
                    let vend = core::str::from_utf8(&vendor).unwrap_or("?");
                    let br = core::str::from_utf8(&brand).unwrap_or("?").trim_matches('\0').trim();
                    self.emit(&alloc::format!("  vendor: {}", vend));
                    self.emit(&alloc::format!("  model: {}", if br.is_empty() { "?" } else { br }));
                    self.emit(&alloc::format!("  clock: ~{} MHz (rdtsc)", mhz));
                    let mut flags: Vec<&str> = Vec::new();
                    if edx1 & (1 << 0) != 0 { flags.push("fpu"); }
                    if edx1 & (1 << 23) != 0 { flags.push("mmx"); }
                    if edx1 & (1 << 25) != 0 { flags.push("sse"); }
                    if edx1 & (1 << 26) != 0 { flags.push("sse2"); }
                    if ecx1 & (1 << 0) != 0 { flags.push("sse3"); }
                    if ecx1 & (1 << 9) != 0 { flags.push("ssse3"); }
                    if ecx1 & (1 << 19) != 0 { flags.push("sse4.1"); }
                    if ecx1 & (1 << 20) != 0 { flags.push("sse4.2"); }
                    if ecx1 & (1 << 25) != 0 { flags.push("aesni"); }
                    if ecx1 & (1 << 28) != 0 { flags.push("avx"); }
                    if ecx1 & (1 << 30) != 0 { flags.push("rdrand"); }
                    if ebx7 & (1 << 5) != 0 { flags.push("avx2"); }
                    if ebx7 & (1 << 7) != 0 { flags.push("smep"); }
                    if ebx7 & (1 << 20) != 0 { flags.push("smap"); }
                    if ebx7 & (1 << 18) != 0 { flags.push("rdseed"); }
                    self.emit(&alloc::format!("  flags: {}", flags.join(" ")));
                }
            }
            "uname" => {
                // uname [-srmva]: kernel name/release/machine -- bare prints -s
                let all = args.iter().any(|a| a.contains('a'));
                let mut parts: Vec<&str> = Vec::new();
                let f = args.first().copied().unwrap_or("");
                if args.is_empty() || all || f.contains('s') {
                    parts.push("CosmosOS");
                }
                if all || f.contains('r') {
                    parts.push("0.1");
                }
                if all || f.contains('v') {
                    parts.push("rust-kernel");
                }
                if all || f.contains('m') {
                    parts.push("x86_64");
                }
                if all || f.contains('o') {
                    parts.push("CosmosOS");
                }
                if parts.is_empty() {
                    parts.push("CosmosOS");
                }
                self.emit(&parts.join(" "));
            }
            "test" | "[" => {
                let mut a: Vec<&str> = args.clone();
                if cmd == "[" {
                    if a.last() == Some(&"]") {
                        a.pop();
                    } else {
                        self.fail("[: missing ]");
                        return;
                    }
                }
                self.last_ok = self.eval_test(&a);
            }
            "rand" => {
                // rand [n] [-x]: n random u64s (default 1), -x hex
                let hex = args.iter().any(|a| *a == "-x");
                let n = args
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1)
                    .min(64);
                for _ in 0..n {
                    match ustd::rand_u64() {
                        Some(v) if hex => self.emit(&alloc::format!("{:016x}", v)),
                        Some(v) => self.emit(&alloc::format!("{}", v)),
                        None => self.fail("rand: kernel rng unavailable"),
                    }
                }
            }
            "mount" => match ustd::df() {
                Some((tot, free)) => self.emit(&alloc::format!(
                    "cosmos-data.img on / type fat32 (rw) -- {} total, {} free",
                    human_size(tot),
                    human_size(free)
                )),
                None => self.emit("mount: no volumes mounted"),
            },
            "rmdir" => match args.first() {
                Some(p) => match ustd::remove(p) {
                    Ok(()) => {}
                    Err(e) => self.fail(&alloc::format!("rmdir: {}: err {}", p, e)),
                },
                None => self.fail("usage: rmdir <dir>  (empty dirs only)"),
            },
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
            // sh / source / . -- all run the file's lines in THIS shell
            // context, so vars/aliases the script sets persist afterwards
            "sh" | "source" | "." => {
                let mut a: &[&str] = args.as_slice();
                let mut trace = false;
                if a.first() == Some(&"-x") {
                    trace = true;
                    a = &a[1..];
                }
                match a.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        // positional params: $0 = script path, $1..$N = args,
                        // $# = arg count -- previous values restored after.
                        let keys: Vec<String> = (0..a.len() + 1)
                            .map(|i| {
                                if i == 0 { String::from("#") } else { alloc::format!("{}", i - 1) }
                            })
                            .collect();
                        let saved: Vec<Option<String>> =
                            keys.iter().map(|k| self.vars.get(k).cloned()).collect();
                        self.vars.insert(String::from("0"), String::from(*p));
                        self.vars.insert(String::from("#"), alloc::format!("{}", a.len() - 1));
                        for (i, x) in a[1..].iter().enumerate() {
                            self.vars.insert(alloc::format!("{}", i + 1), String::from(*x));
                        }
                        let s = String::from_utf8_lossy(&d).into_owned();
                        let (stmts, bodies, unclosed) = norm_stmts(&s);
                        if let Some(d) = unclosed {
                            self.fail(&alloc::format!("sh: unterminated heredoc <<{}", d));
                        } else {
                            let saved_hd = core::mem::replace(&mut self.heredocs, bodies);
                            self.script_depth += 1;
                            self.run_stmts(&stmts, 0, trace);
                            self.heredocs = saved_hd;
                        }
                        self.script_depth = self.script_depth.saturating_sub(1);
                        self.flow = 0;
                        for (k, v) in keys.iter().zip(saved) {
                            match v {
                                Some(v) => { self.vars.insert(k.clone(), v); }
                                None => { self.vars.remove(k); }
                            }
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("sh: {}: err {}", p, e)),
                },
                None => self.fail("usage: sh [-x] <file> [args...]  (for/if/while/break/exit ok)"),
                }
            },
            "cal" => {
                // cal [month [year]] -- real Gregorian calendar
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
                match args.first() {
                    // date +FORMAT: %Y %m %d %H %M %S %T %F %%
                    Some(f) if f.starts_with('+') => {
                        let f = &f[1..];
                        let mut out = String::new();
                        let mut ch = f.chars().peekable();
                        while let Some(c) = ch.next() {
                            if c != '%' {
                                out.push(c);
                                continue;
                            }
                            match ch.next() {
                                Some('Y') => out.push_str(&alloc::format!("{:04}", d.year)),
                                Some('y') => out.push_str(&alloc::format!("{:02}", d.year % 100)),
                                Some('m') => out.push_str(&alloc::format!("{:02}", d.month)),
                                Some('d') => out.push_str(&alloc::format!("{:02}", d.day)),
                                Some('H') => out.push_str(&alloc::format!("{:02}", d.hour)),
                                Some('M') => out.push_str(&alloc::format!("{:02}", d.minute)),
                                Some('S') => out.push_str(&alloc::format!("{:02}", d.second)),
                                Some('T') => out.push_str(&alloc::format!(
                                    "{:02}:{:02}:{:02}", d.hour, d.minute, d.second
                                )),
                                Some('F') => out.push_str(&alloc::format!(
                                    "{:04}-{:02}-{:02}", d.year, d.month, d.day
                                )),
                                Some('%') => out.push('%'),
                                Some(o) => {
                                    out.push('%');
                                    out.push(o);
                                }
                                None => out.push('%'),
                            }
                        }
                        self.emit(&out);
                    }
                    Some(f) => self.fail(&alloc::format!("date: bad arg '{}' (use +FORMAT)", f)),
                    None => {
                        self.emit(&alloc::format!(
                            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                            d.year, d.month, d.day, d.hour, d.minute, d.second
                        ));
                    }
                }
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
                // real SNTP query (UDP/123) -- epoch -> date, vs RTC
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
                Some(url) => {
                    let (req, _) = Self::parse_url(url);
                    match ustd::net_http(&req) {
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
                    None => self.fail(&alloc::format!("httpget: {}: failed", req)),
                    }
                }
                None => self.fail("usage: httpget <http://host[:port]/path> [-o file]"),
            },
            "grep" => {
                // grep [-r] [-vnciwx] [-A n] [-B n] [-C n] [-m n] <pat> [file|dir]
                let mut o = GrepOpts {
                    maxm: usize::MAX,
                    ..Default::default()
                };
                let mut skip: Vec<usize> = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    match *a {
                        "-A" | "-B" | "-C" | "-m" => {
                            let v = args
                                .get(i + 1)
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(0);
                            match *a {
                                "-A" => o.after = v,
                                "-B" => o.before = v,
                                "-C" => {
                                    o.before = v;
                                    o.after = v;
                                }
                                _ => o.maxm = v.max(1),
                            }
                            skip.push(i + 1);
                        }
                        // combined short flags: -rni works like -r -n -i
                        s if s.starts_with('-') && s.len() > 1 => {
                            for ch in s[1..].bytes() {
                                match ch {
                                    b'r' => o.rec = true,
                                    b'v' => o.inv = true,
                                    b'n' => o.num = true,
                                    b'c' => o.cnt = true,
                                    b'i' => o.ci = true,
                                    b'w' => o.word = true,
                                    b'x' => o.exact = true,
                                    b'o' => o.only = true,
                                    b'q' => o.quiet = true,
                                    b'l' => o.files = 1,
                                    b'L' => o.files = 2,
                                    b'F' | b'E' | b'e' => {} // already literal
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let pos: Vec<&str> = args
                    .iter()
                    .enumerate()
                    .filter(|(i, a)| !a.starts_with('-') && !skip.contains(i))
                    .map(|(_, a)| *a)
                    .collect();
                let pat = pos.first().map(|p| {
                    if o.ci {
                        p.to_ascii_lowercase()
                    } else {
                        String::from(*p)
                    }
                });
                match (pat, pos.get(1).copied()) {
                    (Some(p), Some(_)) => {
                        // every positional after the pattern is a file/dir operand
                        let mut hits = 0usize;
                        for path in &pos[1..] {
                            hits += self.grep_run(&p, path, &o);
                        }
                        if o.quiet {
                            self.last_ok = hits > 0;
                        }
                    }
                    (Some(p), None) => match self.pipe_in.clone() {
                        Some(s) => {
                            let lines: Vec<&str> = s.lines().collect();
                            let hits = self.grep_lines(&p, &lines, "", &o);
                            if o.cnt {
                                self.emit(&alloc::format!("{}", hits));
                            }
                            if o.quiet {
                                self.last_ok = hits > 0;
                            }
                        }
                        None => self.fail("usage: grep [-r] [-vnciwxoqlLFe] [-ABCmn] <pat> <file|dir>"),
                    },
                    _ => self.fail("usage: grep [-r] [-vnciwxoqlLFe] [-ABCmn] <pat> <file|dir>"),
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
            "du" => {
                let (human, p) = if args.first().map(|s| *s) == Some("-h") {
                    (true, args.get(1).copied())
                } else {
                    (false, args.first().copied())
                };
                match p {
                    Some(p) => {
                        let n = self.du_tree(p, 0, human);
                        if human {
                            self.emit(&alloc::format!("  {} total", human_size(n)));
                        } else {
                            self.emit(&alloc::format!("  {} B total", n));
                        }
                    }
                    None => self.fail("usage: du [-h] <path>  (recursive bytes)"),
                }
            }
            "df" => {
                let human = args.first().map(|s| *s) == Some("-h");
                match ustd::df() {
                    Some((total, free)) => {
                        let used = total - free;
                        if human {
                            self.emit(&alloc::format!(
                                "  total {}  used {}  free {}",
                                human_size(total), human_size(used), human_size(free)
                            ));
                        } else {
                            self.emit(&alloc::format!("  total {} MiB  used {} MiB  free {} MiB", total / (1024 * 1024), used / (1024 * 1024), free / (1024 * 1024)));
                            self.emit(&alloc::format!("  ({} B / {} B used)", used, total));
                        }
                    }
                    None => self.emit("df: no volume mounted"),
                }
            }
            "file" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let kind = if d.len() >= 4 && &d[0..4] == b"\x7fELF" {
                            alloc::format!("ELF 64-bit executable ({} B)", d.len())
                        } else if d.len() >= 2 && &d[0..2] == b"P6" {
                            String::from("P6 PPM image")
                        } else if d.len() >= 2 && d[0] == 0x1f && d[1] == 0x8b {
                            String::from("gzip compressed data")
                        } else if d.len() >= 262 && &d[257..262] == b"ustar" {
                            alloc::format!("ustar archive ({} B)", d.len())
                        } else if d.len() >= 4 && &d[0..4] == b"%PDF" {
                            String::from("PDF document")
                        } else if d.iter().all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\n' || *b == b'\r' || *b == b'\t') {
                            alloc::format!("ASCII text ({} B, {} lines)", d.len(), d.iter().filter(|&&b| b == b'\n').count())
                        } else {
                            alloc::format!("data ({} B)", d.len())
                        };
                        self.emit(&alloc::format!("{}: {}", p, kind));
                    }
                    Err(e) => self.fail(&alloc::format!("file: {}: err {}", p, e)),
                },
                None => self.fail("usage: file <path>  (identify by magic)"),
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
                Some(port) => {
                    let root = args.get(1).copied().unwrap_or("/");
                    match ustd::stat(root) {
                        Ok(st) if st.is_dir != 0 => {}
                        Ok(_) => {
                            self.fail(&alloc::format!("httpd: {}: not a directory", root));
                            return;
                        }
                        Err(e) => {
                            self.fail(&alloc::format!("httpd: {}: err {}", root, e));
                            return;
                        }
                    }
                    match ustd::TcpListener::bind(port) {
                        Some(l) => {
                            self.httpd = Some((l, String::from(root)));
                            self.emit(&alloc::format!(
                                "httpd: serving {} on :{} -- Esc to stop",
                                root,
                                port
                            ));
                        }
                        None => {
                            self.fail(&alloc::format!("httpd: :{} already in use", port))
                        }
                    }
                }
                None => self.fail("usage: httpd <port> [root]  (real static files, Esc stops)"),
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
                                    "fserve: {} ({}B) on :{} -- waiting up to 30s for a client",
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
                let udp = args
                    .iter()
                    .any(|a| a == &"-u" || a == &"-lu" || a == &"-ul");
                let listen = args
                    .iter()
                    .any(|a| a == &"-l" || a == &"-lu" || a == &"-ul");
                let pos: Vec<&str> = args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .cloned()
                    .collect();
                if udp && listen {
                    match pos.first().and_then(|s| s.parse::<u16>().ok()) {
                        Some(port) => match ustd::UdpSock::open(port) {
                            Some(s) => {
                                self.emit(&alloc::format!(
                                    "nc: udp listening on :{} -- keystrokes send to last peer, Esc closes",
                                    port
                                ));
                                self.nc_udp = Some((s, None));
                            }
                            None => self.fail(&alloc::format!("nc: udp bind :{} failed", port)),
                        },
                        None => self.fail("usage: nc -lu <port>"),
                    }
                } else if udp {
                    match (
                        pos.first().and_then(|s| host_arg(s)),
                        pos.get(1).and_then(|s| s.parse::<u16>().ok()),
                    ) {
                        (Some(ip), Some(port)) => {
                            let lport = 41000u16 + (ustd::uptime_ms() % 2000) as u16;
                            match ustd::UdpSock::open(lport) {
                                Some(s) => {
                                    self.emit(&alloc::format!(
                                        "nc: udp {} -> {}.{}.{}.{}:{} -- keystrokes send, Esc closes",
                                        lport, ip[0], ip[1], ip[2], ip[3], port
                                    ));
                                    self.nc_udp = Some((s, Some((ip, port))));
                                }
                                None => self.fail("nc: udp open failed"),
                            }
                        }
                        _ => self.fail("usage: nc -u <host|a.b.c.d> <port>  |  nc -lu <port>"),
                    }
                } else if args.first().map(|s| *s) == Some("-l") {
                    match args.get(1).and_then(|s| s.parse::<u16>().ok()) {
                        Some(port) => match ustd::TcpListener::bind(port) {
                            Some(l) => {
                                self.emit(&alloc::format!(
                                    "nc: listening on :{} -- Esc cancels",
                                    port
                                ));
                                self.nc_listen = Some(l);
                            }
                            None => self.fail(&alloc::format!("nc: listen :{} failed", port)),
                        },
                        None => self.fail("usage: nc -l <port>"),
                    }
                } else {
                    match (
                        args.first().and_then(|s| host_arg(s)),
                        args.get(1).and_then(|s| s.parse::<u16>().ok()),
                    ) {
                        (Some(ip), Some(port)) => {
                            let lport = 40000u16 + (ustd::uptime_ms() % 2000) as u16;
                            match ustd::TcpSock::connect(lport, ip, port) {
                                Some(s) => {
                                    self.emit(&alloc::format!(
                                        "nc: connected to {}.{}.{}.{}:{} -- keystrokes send, Esc closes",
                                        ip[0], ip[1], ip[2], ip[3], port
                                    ));
                                    self.nc = Some(s);
                                }
                                None => self.fail(&alloc::format!("nc: connect to :{} failed", port)),
                            }
                        }
                        _ => self.fail("usage: nc <host|a.b.c.d> <port>  |  nc -l <port>  (Esc closes)"),
                    }
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
                    self.emit(&alloc::format!("watching every {}ms -- Esc/Enter to stop", ms));
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
                // -n N (value arg, skipped as a file) or -N numeric shorthand
                let ni = args.iter().position(|a| a == &"-n");
                // value-arg positions: -n, -k, -t each consume their next token
                let mut valpos: Vec<usize> = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    if *a == "-n" || *a == "-k" || *a == "-t" || *a == "-o" {
                        valpos.push(i + 1);
                    }
                }
                let popt = args
                    .iter()
                    .enumerate()
                    .find(|(i, a)| !a.starts_with('-') && !valpos.contains(i))
                    .map(|(_, a)| *a);
                let n: usize = ni
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .or_else(|| {
                        args.iter().find_map(|a| {
                            if a.starts_with('-') {
                                a[1..].parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                    })
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
                            // -t SEP field separator; -k N sorts by Nth field (1-based)
                            let ti = args.iter().position(|a| a == &"-t");
                            let sep: Option<char> = ti
                                .and_then(|i| args.get(i + 1))
                                .and_then(|s| s.chars().next());
                            let ki = args.iter().position(|a| a == &"-k");
                            let keyf: usize = ki
                                .and_then(|i| args.get(i + 1))
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            if keyf > 0 || sep.is_some() {
                                let field = |l: &&str| -> String {
                                    let parts: Vec<&str> = match sep {
                                        Some(c) => l.split(c).collect(),
                                        None => l.split_whitespace().collect(),
                                    };
                                    parts
                                        .get(keyf.saturating_sub(1))
                                        .map(|s| String::from(*s))
                                        .unwrap_or_default()
                                };
                                ls.sort_by_key(|l| field(l));
                            } else if args.iter().any(|a| a == &"-n") {
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
                            // -o FILE: write the sorted output to a file
                            match args.iter().position(|a| a == &"-o") {
                                Some(oi) => {
                                    let f = args.get(oi + 1).copied().unwrap_or("");
                                    let mut body = ls.join("\n");
                                    if !body.is_empty() {
                                        body.push('\n');
                                    }
                                    if let Err(e) = ustd::write_all(f, body.as_bytes()) {
                                        self.fail(&alloc::format!("sort: {}: err {}", f, e));
                                    }
                                }
                                None => {
                                    for l in ls {
                                        self.emit(l);
                                    }
                                }
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
                                    self.emit("  (following -- Esc/Enter to stop)");
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
                            // nothing readable -- fail already reported
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
                        // ustar: tar cf out.tar <file|dir>.. | tar tf|tv a.tar | tar xf a.tar [members..]
                        // cf walks dirs recursively emitting '5' dir entries;
                        // xf honors member paths (mkdir -p parents, '..' dropped).
                        let sub = args.first().copied().unwrap_or("");
                        // 'z' in the flag word = gzip layer (tar czf/xzf/tzf)
                        let zflag = sub.contains('z');
                        let op = if sub.contains('c') {
                            "cf"
                        } else if sub.contains('x') {
                            "xf"
                        } else if sub.contains('t') {
                            if sub.contains('v') { "tv" } else { "tf" }
                        } else {
                            ""
                        };
                        match op {
                            "cf" => match (args.get(1), args.get(2)) {
                                (Some(out), Some(_)) => {
                                    let mut arc: Vec<u8> = Vec::new();
                                    let mut ok = true;
                                    let mut nmem = 0usize;
                                    for f in &args[2..] {
                                        let c = tar_add(&mut arc, f.trim_end_matches('/'));
                                        if c == 0 {
                                            self.fail(&alloc::format!("tar: {}: unreadable", f));
                                            ok = false;
                                            break;
                                        }
                                        nmem += c;
                                    }
                                    if ok {
                                        arc.resize(arc.len() + 1024, 0);
                                        let payload = if zflag {
                                            ustd::deflate::gzip_data(&arc)
                                        } else {
                                            arc
                                        };
                                        match ustd::write_all(out, &payload) {
                                            Ok(()) => self.emit(&alloc::format!(
                                                "tar: {} -> {} ({} B)",
                                                nmem,
                                                out,
                                                payload.len()
                                            )),
                                            Err(e) => self
                                                .fail(&alloc::format!("tar: {}: err {}", out, e)),
                                        }
                                    }
                                }
                                _ => self.fail("usage: tar cf out.tar <file|dir...>"),
                            },
                            "tf" | "tv" | "xf" => match args.get(1) {
                                Some(path) => match ustd::read_all(path).and_then(|raw| {
                                    // tar xzf/tzf: transparent gzip unwrap —
                                    // also auto-detect the magic when 'z' is
                                    // omitted, like GNU tar -a
                                    if zflag || raw.starts_with(&[0x1f, 0x8b]) {
                                        ustd::inflate::gzip_body(&raw)
                                            .ok()
                                            .and_then(|o| ustd::inflate::inflate(&raw[o..raw.len() - 8]).ok())
                                            .ok_or(-99)
                                    } else {
                                        Ok(raw)
                                    }
                                }) {
                                    Ok(d) => {
                                        // optional member filter: tar xf a.tar m1 m2
                                        let filter: Vec<&str> = args[2..]
                                            .iter()
                                            .map(|s| s.trim_start_matches('/'))
                                            .collect();
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
                                            let is_dir = h[156] == b'5';
                                            off += 512;
                                            let want = filter.is_empty()
                                                || filter.iter().any(|f| name == *f
                                                    || name.starts_with(&alloc::format!("{}/", f)));
                                            if want {
                                                if op == "tf" {
                                                    self.emit(name);
                                                } else if op == "tv" {
                                                    let mtime = u64::from_str_radix(
                                                        core::str::from_utf8(&h[136..148])
                                                            .unwrap_or("")
                                                            .trim_matches(|c| c == '\0' || c == ' '),
                                                        8,
                                                    )
                                                    .unwrap_or(0);
                                                    let (y, mo, dd, hh, mm, _s) = epoch_to_dt(mtime);
                                                    self.emit(&alloc::format!(
                                                        "{}{:>9} {:04}-{:02}-{:02} {:02}:{:02}  {}",
                                                        if is_dir { "d" } else { "-" },
                                                        size, y, mo, dd, hh, mm, name
                                                    ));
                                                } else {
                                                    // xf: honor member path (drop .. / leading /)
                                                    let mut parts: Vec<&str> = name
                                                        .split('/')
                                                        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
                                                        .collect();
                                                    if is_dir {
                                                        parts.pop();
                                                    }
                                                    let rel = parts.join("/");
                                                    if rel.is_empty() {
                                                        nfiles += 1;
                                                        off += ((size as usize) + 511) / 512 * 512;
                                                        continue;
                                                    }
                                                    if is_dir {
                                                        let _ = mkdir_p(&rel);
                                                        self.emit(&alloc::format!("x {}/", rel));
                                                    } else {
                                                        if let Some((dpar, _)) = rel.rsplit_once('/') {
                                                            let _ = mkdir_p(dpar);
                                                        }
                                                        let data = &d[off..off + size as usize];
                                                        match ustd::write_all(&rel, data) {
                                                            Ok(()) => self.emit(&alloc::format!(
                                                                "x {} ({} B)",
                                                                rel, size
                                                            )),
                                                            Err(e) => self.fail(&alloc::format!(
                                                                "tar: {}: err {}",
                                                                rel, e
                                                            )),
                                                        }
                                                    }
                                                }
                                                nfiles += 1;
                                            }
                                            off += ((size as usize) + 511) / 512 * 512;
                                        }
                                        if nfiles == 0 {
                                            self.fail(if filter.is_empty() {
                                                "tar: empty or invalid archive"
                                            } else {
                                                "tar: no matching members"
                                            });
                                        }
                                    }
                                    Err(e) => self.fail(&alloc::format!("tar: {}: err {}", path, e)),
                                },
                                None => self.fail(&alloc::format!("usage: tar {} <a.tar> [members..]", sub)),
                            },
                            _ => self.fail("usage: tar cf|tf|tv|xf ..."),
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
                            // uniq [-cdui]: -c counts, -d only dup runs,
                            // -u only singleton runs, -i case-insensitive
                            let count = args.iter().any(|a| a == &"-c");
                            let only_dup = args.iter().any(|a| a == &"-d");
                            let only_uniq = args.iter().any(|a| a == &"-u");
                            let ci = args.iter().any(|a| a == &"-i");
                            // group consecutive runs (respecting -i)
                            let mut runs: Vec<(&str, usize)> = Vec::new();
                            for l in s.lines() {
                                let eq = match runs.last() {
                                    Some((p, _)) if ci => p.eq_ignore_ascii_case(l),
                                    Some((p, _)) => *p == l,
                                    None => false,
                                };
                                if eq {
                                    runs.last_mut().unwrap().1 += 1;
                                } else {
                                    runs.push((l, 1));
                                }
                            }
                            for (p, n) in runs {
                                if only_dup && n < 2 {
                                    continue;
                                }
                                if only_uniq && n > 1 {
                                    continue;
                                }
                                if count {
                                    self.emit(&alloc::format!("{:7} {}", n, p));
                                } else {
                                    self.emit(p);
                                }
                            }
                        }
                    }
                    "tr" => {
                        // tr [-d] <set1> [set2] -- ranges like a-z expand
                        let del = args.iter().any(|a| a == &"-d");
                        let pos: Vec<&&str> = args.iter().filter(|a| !a.starts_with('-')).collect();
                        let expand = |spec: &str| -> Vec<u8> {
                            let b = spec.as_bytes();
                            let mut v = Vec::new();
                            let mut i = 0;
                            while i < b.len() {
                                if b[i] == b'\\' && i + 1 < b.len() {
                                    // real tr decodes escapes in the set args
                                    let e = match b[i + 1] {
                                        b'n' => b'\n',
                                        b't' => b'\t',
                                        b'r' => b'\r',
                                        b'0' => 0u8,
                                        b'\\' => b'\\',
                                        c => c,
                                    };
                                    v.push(e);
                                    i += 2;
                                } else if i + 2 < b.len() && b[i + 1] == b'-' && b[i + 2] > b[i] {
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
                        // tee [-a] file -- pipe stdin to stdout AND the file
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
            "awk" => {
                // awk [-F c] 'prog' [file] — input = file arg or stdin
                let (mut fs, mut rest) = (None, args.as_slice());
                if let Some(f) = rest.first().and_then(|a| a.strip_prefix("-F")) {
                    fs = f.chars().next();
                    rest = &rest[1..];
                }
                let (prog, file) = match rest {
                    [p] => (Some(*p), None),
                    [p, f, ..] => (Some(*p), Some(*f)),
                    _ => (None, None),
                };
                let Some(prog) = prog else {
                    self.fail("usage: awk [-F c] 'prog' [file]");
                    return;
                };
                let input = match file {
                    Some(f) => match ustd::read_all(f) {
                        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
                        Err(e) => {
                            self.fail(&alloc::format!("awk: {}: err {}", f, e));
                            return;
                        }
                    },
                    None => match self.pipe_in.clone() {
                        Some(s) => s,
                        None => {
                            self.fail("awk: no input (file arg or pipe)");
                            return;
                        }
                    },
                };
                match awk_eval(prog, &input, fs) {
                    Ok(lines) => {
                        for l in lines {
                            self.emit(&l);
                        }
                    }
                    Err(e) => self.fail(&e),
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
            "kill" => {
                // kill [-9|-15|-18|-19|-KILL|-TERM|-STOP|-CONT] <pid|%n>
                let mut sig: u64 = 15;
                let mut ti = 0usize;
                while let Some(a) = args.get(ti) {
                    if a.starts_with('-') && a.len() > 1 {
                        sig = match *a {
                            "-9" | "-KILL" => 9,
                            "-15" | "-TERM" => 15,
                            "-19" | "-STOP" => 19,
                            "-18" | "-CONT" => 18,
                            _ => {
                                self.fail(&alloc::format!("kill: bad signal {}", a));
                                return;
                            }
                        };
                        ti += 1;
                    } else {
                        break;
                    }
                }
                let Some(a) = args.get(ti) else {
                    self.fail("usage: kill [-sig] <pid|%n>");
                    return;
                };
                let pid = if let Some(n) = a.strip_prefix('%') {
                    match n.parse::<usize>().ok().and_then(|i| self.jobs.get(i.wrapping_sub(1))) {
                        Some((p, _)) => *p,
                        None => {
                            self.fail(&alloc::format!("kill: %{}: no such job", n));
                            return;
                        }
                    }
                } else {
                    match a.parse::<u32>() {
                        Ok(p) => p,
                        Err(_) => {
                            self.fail("usage: kill [-sig] <pid|%n>");
                            return;
                        }
                    }
                };
                let r = ustd::kill2(pid, sig);
                if r == 0 {
                    if sig == 9 || sig == 15 {
                        self.jobs.retain(|(p, _)| *p != pid);
                    }
                    self.emit(&alloc::format!(
                        "{} {}", match sig { 9 | 15 => "killed", 19 => "stopped", _ => "continued" }, pid
                    ));
                } else {
                    self.fail("kill: no such pid (or protected)");
                }
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
                // find <dir> [-name pat] [-type f|d] [-maxdepth n] [pat]
                let mut pat = "*";
                let mut want_dir: Option<bool> = None;
                let mut maxd = usize::MAX;
                let mut skip: Vec<usize> = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    match *a {
                        "-name" => {
                            if let Some(v) = args.get(i + 1) {
                                pat = v;
                                skip.push(i + 1);
                            }
                        }
                        "-type" => {
                            if let Some(v) = args.get(i + 1) {
                                want_dir = Some(*v == "d");
                                skip.push(i + 1);
                            }
                        }
                        "-maxdepth" => {
                            if let Some(v) = args.get(i + 1) {
                                maxd = v.parse().unwrap_or(usize::MAX);
                                skip.push(i + 1);
                            }
                        }
                        _ => {}
                    }
                }
                // -exec's command template must not leak into positionals
                if let Some(xi) = args.iter().position(|a| *a == "-exec") {
                    let end = args[xi + 1..]
                        .iter()
                        .position(|a| *a == ";")
                        .map(|p| xi + 1 + p)
                        .unwrap_or(args.len());
                    for i in xi + 1..=end {
                        skip.push(i);
                    }
                }
                let pos: Vec<&str> = args
                    .iter()
                    .enumerate()
                    .filter(|(i, a)| !a.starts_with('-') && !skip.contains(i))
                    .map(|(_, a)| *a)
                    .collect();
                let dir = pos.first().copied().unwrap_or("/");
                if let Some(p2) = pos.get(1) {
                    pat = p2;
                }
                match ustd::stat(dir) {
                    Ok(st) if st.is_dir != 0 => {
                        if let Some(xi) = args.iter().position(|a| *a == "-exec") {
                            // find -exec cmd [args... {} ...] \; -- run per match
                            let end = args[xi + 1..]
                                .iter()
                                .position(|a| *a == ";")
                                .map(|p| xi + 1 + p)
                                .unwrap_or(args.len());
                            let tpl: Vec<&str> = args[xi + 1..end].to_vec();
                            if tpl.is_empty() {
                                self.fail("find: -exec needs a command ending in ;");
                            } else {
                                for m in self.find_collect(dir, pat, want_dir, maxd) {
                                    let m = m.trim_end_matches('/');
                                    let cmdline = tpl
                                        .iter()
                                        .map(|a| a.replace("{}", m))
                                        .collect::<Vec<String>>()
                                        .join(" ");
                                    for l in self.run_captured(&cmdline) {
                                        self.emit(&l);
                                    }
                                }
                            }
                        } else {
                            self.find_run(dir, pat, want_dir, maxd);
                        }
                    }
                    Ok(_) => {
                        if wild_match(pat, dir) && want_dir != Some(true) {
                            self.emit(dir);
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("find: {}: err {}", dir, e)),
                }
            }
            "diff" => {
                // diff [-u|-q|-i|-w|-B] a b — ed-style by default; -q reports
                // only that files differ; -i/-w/-B normalize before comparing
                let unified = args.iter().any(|a| *a == "-u");
                let brief = args.iter().any(|a| *a == "-q" || *a == "--brief");
                let ci = args.iter().any(|a| *a == "-i");
                let nows = args.iter().any(|a| *a == "-w");
                let noblank = args.iter().any(|a| *a == "-B");
                let paths: Vec<&&str> = args.iter().filter(|a| !a.starts_with('-')).collect();
                match (paths.first(), paths.get(1)) {
                    (Some(pa), Some(pb)) => match (ustd::read_all(pa), ustd::read_all(pb)) {
                        (Ok(da), Ok(db)) => {
                            let sa = String::from_utf8_lossy(&da).into_owned();
                            let sb = String::from_utf8_lossy(&db).into_owned();
                            let norm = |l: &str| -> String {
                                let mut r = String::from(l);
                                if nows {
                                    r = r.split_whitespace().collect();
                                }
                                if ci {
                                    r = r.to_lowercase();
                                }
                                r
                            };
                            let mut la: Vec<String> = sa.lines().take(1024).map(norm).collect();
                            let mut lb: Vec<String> = sb.lines().take(1024).map(norm).collect();
                            if noblank {
                                la.retain(|l| !l.is_empty());
                                lb.retain(|l| !l.is_empty());
                            }
                            let out = if unified {
                                diff_unified(&la, &lb, 3)
                            } else {
                                diff_lines(&la, &lb)
                            };
                            if brief {
                                if out.is_empty() {
                                    self.emit(&alloc::format!("{} {} identical", pa, pb));
                                } else {
                                    self.emit(&alloc::format!("{} {} differ", pa, pb));
                                    self.last_ok = false;
                                }
                            } else {
                                if out.is_empty() {
                                    self.emit("(identical)");
                                } else {
                                    self.last_ok = false; // diff exits nonzero on differences
                                }
                                if unified && !out.is_empty() {
                                    self.emit(&alloc::format!("--- {}", pa));
                                    self.emit(&alloc::format!("+++ {}", pb));
                                }
                                for l in out {
                                    self.emit(&l);
                                }
                            }
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            self.fail(&alloc::format!("diff: err {}", e))
                        }
                    },
                    _ => self.fail("usage: diff [-u|-q|-i|-w|-B] <fileA> <fileB>"),
                }
            }
            "patch" => {
                // patch [file.diff] — apply a unified diff (from `diff -u`).
                // Reads the diff file given, or stdin (pipe heredoc) when none.
                let text = match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
                        Err(e) => {
                            self.fail(&alloc::format!("patch: {}: err {}", p, e));
                            return;
                        }
                    },
                    None => self.pipe_in.clone().unwrap_or_default(),
                };
                if text.is_empty() {
                    self.fail("usage: patch <file.diff>   (or pipe a unified diff)");
                    return;
                }
                self.run_patch(&text);
            }
            "md5sum" | "sha256sum" | "sha1sum" if args.iter().any(|a| *a == "-c") => {
                // sum -c <listfile>: lines "hash  name" -> verify each
                match args.iter().find(|a| !a.starts_with('-')) {
                    Some(listf) => match ustd::read_all(listf) {
                        Ok(d) => {
                            let mut bad = 0;
                            for l in String::from_utf8_lossy(&d).lines() {
                                let l = l.trim();
                                if l.is_empty() {
                                    continue;
                                }
                                let mut it = l.splitn(2, "  ");
                                let want = it.next().unwrap_or("");
                                let name = it.next().unwrap_or("").trim_start_matches('*');
                                let got = ustd::read_all(name).map(|data| {
                                    match cmd {
                                        "md5sum" => hexs(&ustd::md5(&data)),
                                        "sha1sum" => hexs(&ustd::sha1(&data)),
                                        _ => hexs(&sha256(&data)),
                                    }
                                }).unwrap_or_default();
                                if got == want {
                                    self.emit(&alloc::format!("{}: OK", name));
                                } else {
                                    self.emit(&alloc::format!("{}: FAILED", name));
                                    bad += 1;
                                }
                            }
                            if bad > 0 {
                                self.fail(&alloc::format!("{}: {} failed", cmd, bad));
                            }
                        }
                        Err(e) => self.fail(&alloc::format!("{}: {}: err {}", cmd, listf, e)),
                    },
                    None => self.fail(&alloc::format!("usage: {} -c <listfile>", cmd)),
                }
            }
            "md5sum" => {
                // real MD5 (RFC 1321) of each file or stdin
                let mut any = false;
                for a in args.iter() {
                    match ustd::read_all(a) {
                        Ok(d) => {
                            any = true;
                            let h = ustd::md5(&d);
                            let mut hx = String::new();
                            for b in h {
                                hx.push_str(&alloc::format!("{:02x}", b));
                            }
                            self.emit(&alloc::format!("{}  {}", hx, a));
                        }
                        Err(e) => self.fail(&alloc::format!("md5sum: {}: err {}", a, e)),
                    }
                }
                if !any {
                    if let Some(t) = &self.pipe_in {
                        let h = ustd::md5(t.as_bytes());
                        let mut hx = String::new();
                        for b in h {
                            hx.push_str(&alloc::format!("{:02x}", b));
                        }
                        self.emit(&alloc::format!("{}  -", hx));
                    } else {
                        self.fail("usage: md5sum <file>...");
                    }
                }
            }
            "uuencode" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let name = p.rsplit('/').next().unwrap_or(p);
                        self.emit(&alloc::format!("begin 644 {}", name));
                        for line in uu_encode(&d).lines() {
                            self.emit(line);
                        }
                        self.emit("`");
                        self.emit("end");
                    }
                    Err(e) => self.fail(&alloc::format!("uuencode: {}: err {}", p, e)),
                },
                None => self.fail("usage: uuencode <file>   (binary->text on stdout)"),
            },
            "uudecode" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => match uu_decode(&String::from_utf8_lossy(&d)) {
                        Some((name, data)) => match ustd::write_all(&name, &data) {
                            Ok(()) => self.emit(&alloc::format!("uudecode: {} ({} B)", name, data.len())),
                            Err(e) => self.fail(&alloc::format!("uudecode: {}: err {}", name, e)),
                        },
                        None => self.fail("uudecode: no 'begin' line"),
                    },
                    Err(e) => self.fail(&alloc::format!("uudecode: {}: err {}", p, e)),
                },
                None => self.fail("usage: uudecode <file.uu>"),
            },
            "zgrep" => {
                // zgrep [-flags] <pat> <file.gz>... — grep inside gzipped files
                let mut o = GrepOpts::default();
                let mut pos: Vec<&str> = Vec::new();
                for a in args.iter() {
                    match *a {
                        "-n" => o.num = true,
                        "-i" => o.ci = true,
                        "-v" => o.inv = true,
                        "-w" => o.word = true,
                        "-x" => o.exact = true,
                        "-c" => o.cnt = true,
                        _ if a.starts_with('-') => {}
                        _ => pos.push(*a),
                    }
                }
                match (pos.first(), pos.get(1)) {
                    (Some(pat), Some(_)) => {
                        let pat = String::from(*pat);
                        for p in &pos[1..] {
                            match ustd::read_all(p) {
                                Ok(raw) => match ustd::inflate::gzip_body(&raw)
                                    .ok()
                                    .and_then(|off| ustd::inflate::inflate(&raw[off..raw.len() - 8]).ok())
                                {
                                    Some(d) => {
                                        let text = String::from_utf8_lossy(&d).into_owned();
                                        let lines: Vec<&str> = text.lines().collect();
                                        let pref = if pos.len() > 2 { *p } else { "" };
                                        self.grep_lines(&pat, &lines, pref, &o);
                                    }
                                    None => self.fail(&alloc::format!("zgrep: {}: not gzip", p)),
                                },
                                Err(e) => self.fail(&alloc::format!("zgrep: {}: err {}", p, e)),
                            }
                        }
                    }
                    _ => self.fail("usage: zgrep [-nivcwx] <pat> <file.gz>..."),
                }
            }
            "portscan" => {
                // real TCP connect() scan through the stack (SYN -> SYN-ACK or RST)
                let Some(host) = args.first() else {
                    self.fail("usage: portscan <host> [lo-hi | port...] (<=64 ports)");
                    return;
                };
                let ip = match parse_ipv4(host) {
                    Some(ip) => Some(ip),
                    None => ustd::net_dns(host),
                };
                let Some(ip) = ip else {
                    self.fail(&alloc::format!("portscan: {}: no such host", host));
                    return;
                };
                let mut ports: Vec<u16> = Vec::new();
                match args.get(1) {
                    Some(r) if r.contains('-') => {
                        let mut it = r.split('-');
                        let lo: u16 = it.next().and_then(|x| x.parse().ok()).unwrap_or(1);
                        let hi: u16 = it.next().and_then(|x| x.parse().ok()).unwrap_or(lo).min(lo + 63);
                        ports = (lo..=hi).collect();
                    }
                    None => ports = alloc::vec![21, 22, 23, 53, 80, 110, 443, 3306, 8080],
                    _ => {
                        for a in &args[1..] {
                            if let Ok(p) = a.parse::<u16>() {
                                ports.push(p);
                            }
                            if ports.len() >= 64 {
                                break;
                            }
                        }
                    }
                }
                self.emit(&alloc::format!("scanning {}.{}.{}.{} ({} ports)...", ip[0], ip[1], ip[2], ip[3], ports.len()));
                let nports = ports.len();
                let mut lport = 16300u16;
                let mut open = 0u32;
                for p in ports {
                    lport += 1;
                    match ustd::TcpSock::connect(lport, ip, p) {
                        Some(s) => {
                            drop(s);
                            open += 1;
                            self.emit(&alloc::format!("  {}/tcp  open", p));
                        }
                        None => self.emit(&alloc::format!("  {}/tcp  closed", p)),
                    }
                }
                self.emit(&alloc::format!("portscan: {} open of {}", open, nports));
            }
            "dig" => {
                // dig <name> [A|MX|NS|TXT|CNAME|AAAA|ANY] — raw DNS over UDP/53
                let Some(name) = args.first() else {
                    self.fail("usage: dig <name> [type]");
                    return;
                };
                let qt = match args.get(1).map(|s| s.to_uppercase()).as_deref() {
                    None | Some("A") => 1u16,
                    Some("NS") => 2,
                    Some("CNAME") => 5,
                    Some("SOA") => 6,
                    Some("PTR") => 12,
                    Some("MX") => 15,
                    Some("TXT") => 16,
                    Some("AAAA") => 28,
                    Some("ANY") => 255,
                    Some(t) => {
                        self.fail(&alloc::format!("dig: unknown type '{}'", t));
                        return;
                    }
                };
                match dig_query(name, qt) {
                    Ok(lines) => {
                        for l in lines {
                            self.emit(&l);
                        }
                    }
                    Err(e) => self.fail(&e),
                }
            }
            "sha1sum" => {
                // real SHA-1 (RFC 3174) of each file
                for a in args.iter() {
                    match ustd::read_all(a) {
                        Ok(d) => self.emit(&alloc::format!("{}  {}", hexs(&ustd::sha1(&d)), a)),
                        Err(e) => self.fail(&alloc::format!("sha1sum: {}: err {}", a, e)),
                    }
                }
                if args.is_empty() {
                    self.fail("usage: sha1sum <file>...");
                }
            }
            "od" => {
                // od [-An] [-t x1|c] <file> — canonical octal-dump-style view
                let mut offbase = 8usize; // octal offsets by default
                let mut chars = false;
                let mut path = "";
                for a in args.iter() {
                    match *a {
                        "-A" | "-Ax" | "-tx1" | "-A x" => {}
                        "-Ax" => offbase = 16,
                        "-An" => offbase = 0,
                        "-c" | "-t c" | "-tc" => chars = true,
                        "-tx1c" => chars = true,
                        _ if !a.starts_with('-') => path = a,
                        _ => {}
                    }
                }
                if path.is_empty() {
                    self.fail("usage: od [-An|-Ax] [-tx1c] <file>");
                    return;
                }
                match ustd::read_all(path) {
                    Ok(d) => {
                        for (i, ch) in d.chunks(16).enumerate() {
                            let mut l = if offbase == 16 {
                                alloc::format!("{:08x}  ", i * 16)
                            } else if offbase == 8 {
                                alloc::format!("{:07o}  ", i * 16)
                            } else {
                                String::new()
                            };
                            for b in ch {
                                l.push_str(&alloc::format!("{:02x} ", b));
                            }
                            for _ in 0..16 - ch.len() {
                                l.push_str("   ");
                            }
                            if chars {
                                l.push(' ');
                                for b in ch {
                                    l.push(if b.is_ascii_graphic() || *b == b' ' {
                                        *b as char
                                    } else {
                                        '.'
                                    });
                                }
                            }
                            self.emit(&l);
                        }
                        self.emit(&alloc::format!("{:07o}", d.len()));
                    }
                    Err(e) => self.fail(&alloc::format!("od: {}: err {}", path, e)),
                }
            }
            "xxd" => {
                // xxd <file> — hex + ascii, vim-style
                match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => {
                            for (i, ch) in d.chunks(16).enumerate() {
                                let mut l = alloc::format!("{:08x}: ", i * 16);
                                for (j, b) in ch.iter().enumerate() {
                                    if j == 8 { l.push(' '); }
                                    l.push_str(&alloc::format!("{:02x} ", b));
                                }
                                let pad = 16 - ch.len();
                                for _ in 0..pad { l.push_str("   "); }
                                if ch.len() <= 8 { l.push(' '); }
                                for b in ch {
                                    l.push(if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' });
                                }
                                self.emit(&l);
                            }
                        }
                        Err(e) => self.fail(&alloc::format!("xxd: {}: err {}", p, e)),
                    },
                    None => self.fail("usage: xxd <file>"),
                }
            }
            "banner" => {
                let text = args.join(" ");
                if text.is_empty() {
                    self.fail("usage: banner <text>");
                    return;
                }
                for row in 0..5 {
                    let mut l = String::new();
                    for c in text.chars() {
                        for g in banner_glyph(c)[row].chars() {
                            l.push(g);
                        }
                        l.push(' ');
                        if l.len() > 80 { break; }
                    }
                    self.emit(&l);
                }
            }
            "units" => {
                // units <n> <from> <to> — fixed-point unit conversion
                match (args.first(), args.get(1), args.get(2)) {
                    (Some(n), Some(f), Some(t)) => {
                        let n: u64 = n.parse().unwrap_or(0);
                        let fu = UNITS.iter().find(|u| u.0.eq_ignore_ascii_case(f));
                        let tu = UNITS.iter().find(|u| u.0.eq_ignore_ascii_case(t));
                        match (fu, tu) {
                            (Some(fu), Some(tu)) if fu.2 == tu.2 => {
                                // n*from in micro-base units, divide into 'to'
                                let micro = n.saturating_mul(fu.1);
                                let whole = micro / tu.1;
                                let rem = micro % tu.1;
                                let frac6 = rem.saturating_mul(1_000_000) / tu.1;
                                self.emit(&alloc::format!(
                                    "{} {} = {} {}",
                                    n, f,
                                    fmt_fixed(whole * 1_000_000 + frac6),
                                    t
                                ));
                            }
                            (Some(_), Some(_)) => self.fail("units: incompatible dimensions"),
                            _ => self.fail("units: unknown unit"),
                        }
                    }
                    _ => self.fail("usage: units <n> <from> <to>   (e.g. units 5 km mi)"),
                }
            }
            "pr" => {
                // pr <file> — paginate with page headers (66-line pages)
                match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => {
                            let text = String::from_utf8_lossy(&d);
                            let lines: Vec<&str> = text.lines().collect();
                            let per = 56usize;
                            let mut page = 0usize;
                            let mut i = 0usize;
                            while i < lines.len() || page == 0 {
                                self.emit(&alloc::format!("{}  {}  Page {}", now_str(), p, page + 1));
                                self.emit("");
                                for _ in 0..per {
                                    if i < lines.len() {
                                        self.emit(lines[i]);
                                        i += 1;
                                    }
                                }
                                self.emit("");
                                page += 1;
                            }
                        }
                        Err(e) => self.fail(&alloc::format!("pr: {}: err {}", p, e)),
                    },
                    None => self.fail("usage: pr <file>"),
                }
            }
            "apropos" => match args.first() {
                Some(q) => {
                    let lines = Self::HELP_LINES;
                    let mut any = false;
                    for l in lines {
                        if l.to_lowercase().contains(&q.to_lowercase()) {
                            self.emit(l);
                            any = true;
                        }
                    }
                    if !any {
                        self.emit(&alloc::format!("{}: nothing appropriate", q));
                    }
                }
                None => self.fail("usage: apropos <keyword>"),
            },
            "whereis" => match args.first() {
                Some(q) => {
                    let mut found: Vec<String> = Vec::new();
                    if Self::BUILTINS.contains(q) {
                        found.push(String::from("builtin"));
                    }
                    let p = alloc::format!("/bin/{}", q);
                    if ustd::stat(&p).is_ok() {
                        found.push(p);
                    }
                    if ustd::stat(q).is_ok() {
                        found.push(String::from(*q));
                    }
                    if found.is_empty() {
                        self.emit(&alloc::format!("{}:", q));
                    } else {
                        self.emit(&alloc::format!("{}: {}", q, found.join(" ")));
                    }
                }
                None => self.fail("usage: whereis <name>"),
            },
            "fortune" => {
                match ustd::read_all("/fortunes.txt") {
                    Ok(d) => {
                        let text = String::from_utf8_lossy(&d);
                        let items: Vec<&str> = text.split('%').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
                        if items.is_empty() {
                            self.fail("fortune: empty jar");
                        } else {
                            let i = (ustd::rand_u64().unwrap_or(1) as usize) % items.len();
                            for l in items[i].lines() {
                                self.emit(l);
                            }
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("fortune: /fortunes.txt: err {}", e)),
                }
            }
            "uuidgen" => {
                let mut b = [0u8; 16];
                ustd::rand_fill(&mut b);
                b[6] = (b[6] & 0x0f) | 0x40; // v4
                b[8] = (b[8] & 0x3f) | 0x80; // variant
                self.emit(&alloc::format!(
                    "{}-{}-{}-{}-{}",
                    hexs(&b[0..4]), hexs(&b[4..6]), hexs(&b[6..8]),
                    hexs(&b[8..10]), hexs(&b[10..])
                ));
            }
            "logger" => {
                // logger <msg...> — append a timestamped line to /log/messages.txt
                if args.is_empty() {
                    self.fail("usage: logger <message...>");
                    return;
                }
                mkdir_parents("/log/x");
                let line = alloc::format!(
                    "[{}] term: {}\n",
                    now_str(),
                    args.join(" ")
                );
                let prev = ustd::read_all("/log/messages.txt").unwrap_or_default();
                let mut d = prev;
                d.extend_from_slice(line.as_bytes());
                match ustd::write_all("/log/messages.txt", &d) {
                    Ok(()) => self.emit("logger: recorded"),
                    Err(e) => self.fail(&alloc::format!("logger: err {}", e)),
                }
            }
            "whois" => {
                // real WHOIS over TCP/43: query whois.iana.org, follow the
                // 'refer:' referral to the registry server.
                let Some(q) = args.first() else {
                    self.fail("usage: whois <domain>");
                    return;
                };
                match Self::whois_query(q) {
                    Ok(lines) => {
                        for l in &lines {
                            self.emit(l);
                        }
                    }
                    Err(e) => self.fail(&e),
                }
            }
            "fdisk" => {
                // fdisk -l — parse the real MBR partition table off /dev/vda
                let list = args.iter().any(|a| *a == "-l") || args.is_empty();
                if !list {
                    self.fail("usage: fdisk -l");
                    return;
                }
                let Ok(fd) = ustd::open("/dev/vda", ustd::O_RDONLY) else {
                    self.fail("fdisk: no disk");
                    return;
                };
                let mut sec = [0u8; 512];
                let r = ustd::read(fd, &mut sec);
                ustd::close(fd);
                let Ok(n) = r else { self.fail("fdisk: read failed"); return; };
                if n < 512 {
                    self.fail("fdisk: short read");
                    return;
                }
                if sec[510] != 0x55 || sec[511] != 0xAA {
                    self.emit("no valid partition table (superfloppy / FAT BPB at sector 0)");
                } else {
                    self.emit("Disk /dev/vda: 128 MiB, 262144 sectors");
                    self.emit("Dev       Start      Sectors    Size  Type");
                    for i in 0..4 {
                        let e = &sec[446 + i * 16..446 + i * 16 + 16];
                        let ty = e[4];
                        if ty == 0 { continue; }
                        let lba = u32::from_le_bytes(e[8..12].try_into().unwrap());
                        let sz = u32::from_le_bytes(e[12..16].try_into().unwrap());
                        self.emit(&alloc::format!(
                            "/dev/vda{}   {:<9} {:<10} {:>4}M  0x{:02x}",
                            i + 1, lba, sz, (sz as u64) * 512 / (1 << 20), ty
                        ));
                    }
                }
            }
            "vol" | "blkid" => {
                // filesystem identity off /dev/vda's FAT BPB (real metadata)
                let Ok(fd) = ustd::open("/dev/vda", ustd::O_RDONLY) else {
                    self.fail("vol: no disk");
                    return;
                };
                let mut sec = [0u8; 512];
                let _ = ustd::read(fd, &mut sec);
                ustd::close(fd);
                let oem = String::from_utf8_lossy(&sec[3..11]).trim().to_string();
                let bps = u16::from_le_bytes([sec[11], sec[12]]);
                let spc = sec[13];
                let nf = sec[16];
                let spt = u16::from_le_bytes([sec[24], sec[25]]);
                let fatsz = u32::from_le_bytes(sec[36..40].try_into().unwrap());
                let serial = u32::from_le_bytes(sec[67..71].try_into().unwrap());
                let label = String::from_utf8_lossy(&sec[71..82]).trim().to_string();
                let fstyp = String::from_utf8_lossy(&sec[82..90]).trim().to_string();
                self.emit(&alloc::format!("/dev/vda: {} [{}] serial {:08x}", fstyp, label, serial));
                self.emit(&alloc::format!(
                    "  oem={} bytes/sec={} sec/clus={} fats={} sec/track={} fatsz={}",
                    oem, bps, spc, nf, spt, fatsz
                ));
            }
            "script" => {
                // script [file] — start/stop a session typescript log
                if self.script_fd.is_some() {
                    let fd = self.script_fd.take().unwrap();
                    ustd::close(fd);
                    self.emit("script: stopped");
                } else {
                    let p = args.first().copied().unwrap_or("/typescript.log");
                    match ustd::open(p, ustd::O_WRONLY | ustd::O_CREATE | ustd::O_APPEND) {
                        Ok(fd) => {
                            self.script_fd = Some(fd);
                            self.emit(&alloc::format!("script: logging to {}", p));
                        }
                        Err(e) => self.fail(&alloc::format!("script: {}: err {}", p, e)),
                    }
                }
            }
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
            "jobs" => {
                // list tracked jobs; + marks the most recent, dead ones reap out
                let live: alloc::vec::Vec<u32> = ustd::proclist(64).iter().map(|p| p.pid).collect();
                let mut keep: Vec<(u32, String)> = Vec::new();
                let last = self.jobs.len();
                let jlist = self.jobs.clone();
                for (i, (pid, c)) in jlist.iter().enumerate() {
                    if live.contains(pid) {
                        // real state from the kernel via /proc, not cached
                        let state = ustd::read_all(&alloc::format!("/proc/{}/status", pid))
                            .map(|d| {
                                if String::from_utf8_lossy(&d).contains("T (stopped)") {
                                    "stopped "
                                } else {
                                    "running "
                                }
                            })
                            .unwrap_or("running ");
                        self.emit(&alloc::format!(
                            "[{}]{} {} {} {}", i + 1, if i + 1 == last { "+" } else { " " }, pid, state, c
                        ));
                        keep.push((*pid, c.clone()));
                    } else {
                        self.emit(&alloc::format!("[{}]  {} done     {}", i + 1, pid, c));
                    }
                }
                if self.jobs.is_empty() {
                    self.emit("jobs: none");
                }
                self.jobs = keep;
            }
            "bg" => {
                // bg [n]: SIGCONT job n — keeps running in the background
                let idx = args
                    .first()
                    .map(|a| a.trim_start_matches('%').parse::<usize>().ok())
                    .flatten()
                    .unwrap_or(self.jobs.len());
                match idx.checked_sub(1).and_then(|i| self.jobs.get(i).cloned()) {
                    Some((pid, c)) => {
                        if ustd::kill2(pid, 18) == 0 {
                            self.emit(&alloc::format!("[{}]+ {} &", idx, c));
                        } else {
                            self.fail(&alloc::format!("bg: {}: gone", pid));
                        }
                    }
                    None => self.fail("bg: no such job"),
                }
            }
            "fg" => {
                // fg [n]: SIGCONT (in case stopped), then wait for exit
                let idx = args
                    .first()
                    .map(|a| a.trim_start_matches('%').parse::<usize>().ok())
                    .flatten()
                    .unwrap_or(self.jobs.len());
                match idx.checked_sub(1).and_then(|i| self.jobs.get(i).map(|j| j.0)) {
                    Some(pid) => {
                        ustd::kill2(pid, 18);
                        self.jobs.retain(|(p, _)| *p != pid);
                        match ustd::waitpid(pid, 60_000) {
                            Ok(code) => self.emit(&alloc::format!("[{}] exited ({})", pid, code)),
                            Err(_) => self.fail(&alloc::format!("fg: {}: timeout or gone", pid)),
                        }
                    }
                    None => self.fail("fg: no such job"),
                }
            }
            "disown" => {
                match args.first().map(|a| a.trim_start_matches('%').parse::<usize>().ok()).flatten() {
                    Some(n) if n >= 1 && n <= self.jobs.len() => {
                        let (pid, _) = self.jobs.remove(n - 1);
                        self.emit(&alloc::format!("disowned job {} (pid {})", n, pid));
                    }
                    _ if args.is_empty() => {
                        self.jobs.clear();
                        self.emit("disowned all jobs");
                    }
                    _ => self.fail("disown: no such job"),
                }
            }
            "strace" => {
                // strace -p <pid>: live syscall trace (q/Esc detaches)
                match args.iter().position(|a| a == &"-p").and_then(|i| args.get(i + 1)).and_then(|a| a.parse::<u32>().ok()) {
                    Some(pid) => {
                        if ustd::strace(0, pid, &mut []) < 0 {
                            self.fail(&alloc::format!("strace: {}: no such task", pid));
                        } else {
                            self.emit(&alloc::format!("strace: attached to {} (q to detach)", pid));
                            self.strace_p = Some(pid);
                        }
                    }
                    None => {
                        // strace <cmd...>: spawn the binary already traced
                        let Some(w) = args.first() else {
                            self.fail("usage: strace -p <pid> | strace <cmd...>");
                            return;
                        };
                        let path = alloc::format!("/bin/{}", w);
                        if ustd::stat(&path).is_err() {
                            self.fail(&alloc::format!("strace: {}: not a binary", w));
                            return;
                        }
                        match ustd::spawn(&path, &args[1..].join(" ")) {
                            Ok(pid) => {
                                self.track(pid, &path);
                                if ustd::strace(0, pid, &mut []) == 0 {
                                    self.emit(&alloc::format!("strace: attached to {} (q to detach)", pid));
                                    self.strace_p = Some(pid);
                                } else {
                                    self.fail("strace: attach failed");
                                }
                            }
                            Err(_) => self.fail(&alloc::format!("strace: {}: spawn failed", w)),
                        }
                    }
                }
            }
            "iostat" => match ustd::read_all("/proc/iostat") {
                Ok(d) => {
                    let t = String::from_utf8_lossy(&d);
                    self.emit("        ops       bytes");
                    for (i, l) in t.lines().take(2).enumerate() {
                        let mut w = l.split_whitespace();
                        let _k = w.next();
                        let (o, b) = (
                            w.next().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0),
                            w.next().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0),
                        );
                        self.emit(&alloc::format!(
                            "{} {:>7} {:>11}", if i == 0 { "read " } else { "write" }, o, b
                        ));
                    }
                }
                Err(e) => self.fail(&alloc::format!("iostat: err {}", e)),
            },
            "halt" => ustd::poweroff(),
            "tput" => match args.first() {
                Some(&"cols") => self.emit(&alloc::format!("{}", COLS)),
                Some(&"lines") => self.emit(&alloc::format!("{}", ROWS)),
                _ => self.fail("usage: tput cols|lines"),
            },
            "builtin" | "command" => {
                // run cmd bypassing alias expansion (still hits builtins)
                if args.is_empty() {
                    self.fail("usage: builtin|command <cmd...>");
                    return;
                }
                self.no_alias_once = true;
                self.run(&args.join(" "));
            }
            "exec" => {
                // exec <cmd...>: replace the terminal process (window closes)
                match args.first() {
                    Some(w) => {
                        let path = alloc::format!("/bin/{}", w);
                        if ustd::stat(&path).is_ok() {
                            match ustd::spawn(&path, &args[1..].join(" ")) {
                                Ok(_) => self.win.close(),
                                Err(_) => self.fail(&alloc::format!("exec: {}: spawn failed", w)),
                            }
                        } else {
                            self.fail(&alloc::format!("exec: {}: not a binary", w));
                        }
                    }
                    None => self.fail("usage: exec <cmd...>"),
                }
            }
            "sysctl" => {
                // real kernel/machine parameters
                let mi = ustd::meminfo();
                self.emit(&alloc::format!("kernel.hostname = {}", self.host));
                self.emit("kernel.osrelease = 0.1");
                self.emit("kernel.arch = x86_64");
                self.emit(&alloc::format!("vm.page_size = {}", 4096));
                self.emit(&alloc::format!("vm.mem_total_kb = {}", mi.total_kb));
                self.emit(&alloc::format!("vm.mem_free_kb = {}", mi.total_kb.saturating_sub(mi.used_kb)));
                self.emit("hw.ncpu = 1");
            }
            "dos2unix" | "unix2dos" => {
                // convert CRLF<->LF on a file in place, or pipe content
                match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => {
                            let t = String::from_utf8_lossy(&d).into_owned();
                            let out = if cmd == "dos2unix" {
                                t.replace("\r\n", "\n")
                            } else {
                                t.replace("\r\n", "\n").replace("\n", "\r\n")
                            };
                            match ustd::write_all(p, out.as_bytes()) {
                                Ok(()) => self.emit(&alloc::format!("{}: {} converted", cmd, p)),
                                Err(e) => self.fail(&alloc::format!("{}: write err {}", cmd, e)),
                            }
                        }
                        Err(e) => self.fail(&alloc::format!("{}: {}: err {}", cmd, p, e)),
                    },
                    None => match self.pipe_in.clone() {
                        Some(t) => {
                            let out = if cmd == "dos2unix" {
                                t.replace("\r\n", "\n")
                            } else {
                                t.replace("\r\n", "\n").replace("\n", "\r\n")
                            };
                            for l in out.split('\n') {
                                self.emit(l);
                            }
                        }
                        None => self.fail(&alloc::format!("usage: {} <file>  (or pipe)", cmd)),
                    },
                }
            }
            "base32" => {
                // RFC 4648 base32 (-d decodes); file arg or stdin
                let dec = args.iter().any(|a| a == &"-d");
                let src = args
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .and_then(|p| ustd::read_all(p).ok())
                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                    .or_else(|| self.pipe_in.clone());
                match src {
                    Some(t) => {
                        if dec {
                            match b32_decode(t.trim()) {
                                Some(d) => match String::from_utf8(d.clone()) {
                                    Ok(s) => {
                                        for l in s.lines() {
                                            self.emit(l);
                                        }
                                    }
                                    Err(_) => self.emit(&hexs(&d)),
                                },
                                None => self.fail("base32: bad input"),
                            }
                        } else {
                            for l in b32_encode(t.as_bytes()).lines() {
                                self.emit(l);
                            }
                        }
                    }
                    None => self.fail("usage: base32 [-d] [file]"),
                }
            }

            "arch" | "nproc" => {
                if cmd == "arch" {
                    self.emit("x86_64");
                } else {
                    self.emit("1");
                }
            }
            "reboot" => ustd::reboot(),
            "shutdown" | "poweroff" => ustd::poweroff(),
            "beep" => {
                let f = args
                    .first()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(880);
                let ms = args
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(120);
                ustd::beep(f, ms);
            }
            "play" => match args.first() {
                None => self.fail("usage: play <file>  (lines: NOTE|HZ,DUR_MS)"),
                Some(path) => match ustd::read_all(path) {
                    Err(e) => self.fail(&alloc::format!("play: {path}: {e}")),
                    Ok(data) => {
                        let text = String::from_utf8_lossy(&data);
                        let mut n = 0u32;
                        let mut bad = false;
                        for (ln, raw) in text.lines().enumerate() {
                            let l = raw.trim();
                            if l.is_empty() || l.starts_with('#') {
                                continue;
                            }
                            let mut it = l.split([',', ' ', '\t']).filter(|s| !s.is_empty());
                            let note = it.next().unwrap_or("");
                            let dur = it.next().and_then(|s| s.parse::<u64>().ok());
                            let rest = note.eq_ignore_ascii_case("r")
                                || note.eq_ignore_ascii_case("rest")
                                || note.eq_ignore_ascii_case("pause");
                            match (rest, note_freq(note), dur) {
                                (true, _, Some(d)) => {
                                    ustd::sleep_ms(d);
                                }
                                (false, Some(f), Some(d)) => {
                                    ustd::beep(f, d);
                                    ustd::sleep_ms(d);
                                    n += 1;
                                }
                                _ => {
                                    self.fail(&alloc::format!(
                                        "play: bad line {}: {l}",
                                        ln + 1
                                    ));
                                    bad = true;
                                    break;
                                }
                            }
                        }
                        if !bad {
                            self.emit(&alloc::format!("play: {n} note(s)"));
                        }
                    }
                },
            },
            "exit" => {
                if self.script_depth > 0 {
                    self.flow = 3; // inside sh/source: stop the script
                } else {
                    self.win.close();
                }
            }
            "show" => match args.first() {
                Some(p) => match ustd::spawn("/bin/cosmos-view", p).map(|pid| { self.track(pid, p); pid }) {
                    Ok(pid) => self.emit(&alloc::format!("spawned view (pid {})", pid)),
                    Err(_) => self.fail("show: spawn failed"),
                },
                None => self.fail("usage: show <file.ppm>"),
            },
            "at" => {
                // at <secs> <cmd...>: run cmd after N seconds (non-blocking)
                match args.first().and_then(|s| s.parse::<u64>().ok()) {
                    Some(secs) if args.len() > 1 => {
                        let cmd = args[1..].join(" ");
                        let when = ustd::uptime_ms() + secs * 1000;
                        self.at_q.push((when, cmd.clone()));
                        self.at_q.sort_by_key(|(t, _)| *t);
                        self.emit(&alloc::format!("scheduled in {}s: {}", secs, cmd));
                    }
                    _ => self.fail("usage: at <seconds> <command>"),
                }
            }
            "yes" => {
                self.yesing = Some(if args.is_empty() {
                    String::from("y")
                } else {
                    args.join(" ")
                });
                self.emit("yes running -- Esc/Enter to stop");
            }
            "sed" => {
                // sed [-i] [-n] 's/a/b/[g]' | 'N[,M]p' | 'N[,M]d' [file]
                //   p = select range, d = drop range, s/// = substitute;
                //   -i edits the file in place, -n with s/// prints only
                //   lines the substitution changed
                let inplace = args.iter().any(|a| a == &"-i");
                let quiet = args.iter().any(|a| a == &"-n");
                let pos: Vec<&str> = args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .copied()
                    .collect();
                let spec = pos.first().copied().unwrap_or("");
                let file = pos.get(1).copied();
                let input_text = match file {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                        Err(e) => {
                            self.fail(&alloc::format!("sed: {}: err {}", p, e));
                            None
                        }
                    },
                    None => self.pipe_in.clone(),
                };
                let Some(s) = input_text else {
                    return;
                };
                // range op: "N[,M]p" or "N[,M]d" (1-based line numbers)
                let parse_range = |sp: &str| -> Option<(usize, usize, u8)> {
                    if sp.is_empty() {
                        return None;
                    }
                    let (num, op) = sp.split_at(sp.len() - 1);
                    let op = op.as_bytes()[0];
                    if op != b'p' && op != b'd' {
                        return None;
                    }
                    let (a, b) = match num.split_once(',') {
                        Some((x, y)) => (x.trim().parse().ok()?, y.trim().parse().ok()?),
                        None => (num.trim().parse().ok()?, 0),
                    };
                    if a == 0 {
                        return None;
                    }
                    Some((a, if b == 0 { a } else { b }, op))
                };
                let mut out: Vec<String> = Vec::new();
                let mut bad = false;
                if let Some((a, b, op)) = parse_range(spec) {
                    for (i, l) in s.lines().enumerate() {
                        let inr = a <= i + 1 && i + 1 <= b;
                        if (op == b'p') == inr {
                            out.push(String::from(l));
                        }
                    }
                } else {
                    // s/// substitution
                    let b = spec.as_bytes();
                    let parsed = if b.len() >= 4 && b[0] == b's' {
                        let d = b[1] as char;
                        let parts: Vec<&str> = spec[2..].split(d).collect();
                        if parts.len() >= 2 {
                            Some((
                                String::from(parts[0]),
                                String::from(parts[1]),
                                parts.get(2).map(|f| f.contains('g')).unwrap_or(false),
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    match parsed {
                        Some((old, new, g)) => {
                            if old.is_empty() {
                                self.fail("sed: empty pattern");
                                return;
                            }
                            for l in s.lines() {
                                let r = if g {
                                    l.replace(&old, &new)
                                } else {
                                    l.replacen(&old, &new, 1)
                                };
                                if !quiet || r != l {
                                    out.push(r);
                                }
                            }
                        }
                        None => bad = true,
                    }
                }
                if bad {
                    self.fail("usage: sed [-i] [-n] 's/a/b/[g]' | 'N[,M]p' | 'N[,M]d' [file]");
                    return;
                }
                if inplace {
                    match file {
                        Some(f) => {
                            let mut body = out.join("\n");
                            if !body.is_empty() {
                                body.push('\n');
                            }
                            match ustd::write_all(f, body.as_bytes()) {
                                Ok(_) => self.emit(&alloc::format!(
                                    "sed: {} <- {} line(s)",
                                    f,
                                    out.len()
                                )),
                                Err(e) => {
                                    self.fail(&alloc::format!("sed: {}: err {}", f, e))
                                }
                            }
                        }
                        None => self.fail("sed -i: needs a file"),
                    }
                } else {
                    for l in &out {
                        self.emit(l);
                    }
                }
            }
            "xargs" => {
                // xargs [-n N] [-0] [-I STR] [-t] <cmd> [args...]
                // -n N batches N stdin items per run; -0 splits on NUL; -I
                // substitutes STR in the command with the item; -t echoes.
                let mut nbatch = 0usize;
                let mut repl: Option<String> = None;
                let mut trace = false;
                let mut nul = false;
                let mut ci = 0usize;
                while ci < args.len() {
                    match args[ci] {
                        "-n" => {
                            nbatch = args.get(ci + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                            ci += 2;
                        }
                        "-I" => {
                            repl = args.get(ci + 1).map(|s| String::from(*s));
                            ci += 2;
                        }
                        "-t" => {
                            trace = true;
                            ci += 1;
                        }
                        "-0" => {
                            nul = true;
                            ci += 1;
                        }
                        _ => break,
                    }
                }
                let rest = &args[ci..];
                if rest.is_empty() {
                    self.fail("usage: <cmd> | xargs [-n N] [-0] [-I STR] [-t] <cmd> [args...]");
                    return;
                }
                let base = rest.join(" ");
                if let Some(s) = self.pipe_in.clone() {
                    let items: Vec<&str> = if nul {
                        s.split('\0').collect()
                    } else {
                        // real xargs splits items on blanks+newlines by default
                        s.split_whitespace().collect()
                    };
                    let items: Vec<&str> = items
                        .into_iter()
                        .filter(|l| !l.trim().is_empty())
                        .collect();
                    let batch = if repl.is_some() {
                        1 // -I runs once per item (each gets its own substitution)
                    } else if nbatch > 0 {
                        nbatch
                    } else {
                        1
                    };
                    for chunk in items.chunks(batch) {
                        let line = match &repl {
                            Some(r) => base.replace(r.as_str(), chunk[0].trim()),
                            None => alloc::format!("{} {}", base, chunk.join(" ")),  
                        };
                        if trace {
                            self.emit(&alloc::format!("+ {}", line));
                        }
                        for o in self.run_captured(&line) {
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
                // read [-p prompt] [-n count] VAR: stdin (pipe) line -> $VAR
                let mut prompt = "";
                let mut ncount: usize = 0;
                let mut ai = 0usize;
                while ai < args.len() {
                    match args[ai] {
                        "-p" => {
                            prompt = args.get(ai + 1).unwrap_or(&"");
                            ai += 2;
                        }
                        "-n" => {
                            ncount = args.get(ai + 1).and_then(|x| x.parse().ok()).unwrap_or(0);
                            ai += 2;
                        }
                        _ => break,
                    }
                }
                let rargs = &args[ai..];
                if !prompt.is_empty() {
                    self.emit(prompt);
                }
                match rargs.first() {
                    Some(v) => match self.pipe_in.clone() {
                        Some(s) => {
                            let mut it = s.splitn(2, '\n');
                            let line = it.next().unwrap_or("");
                            let line = if ncount > 0 && line.len() > ncount { &line[..ncount] } else { line };
                            self.vars.insert(String::from(*v), String::from(line));
                            // remaining lines stay in stdin for the next `read`
                            self.pipe_in = it.next().map(|r| String::from(r));
                            self.emit(&alloc::format!("{}='{}'", v, line));
                        }
                        None => {
                            // interactive top-level only: capture the next
                            // line the user types (script bodies have no tty)
                            if self.run_depth == 1 && self.script_depth == 0 {
                                self.read_modal = Some((String::from(*v), ncount));
                            } else {
                                self.fail("read: no input (pipe lines in)");
                            }
                        }
                    },
                    None => self.fail("usage: <cmd> | read VAR"),
                }
            }
            "wait" => match args.first().map(|a| *a) {
                // wait: no args waits for all tracked jobs
                None => {
                    if self.jobs.is_empty() {
                        self.emit("wait: no jobs");
                        return;
                    }
                    let js = core::mem::take(&mut self.jobs);
                    for (pid, c) in js {
                        match ustd::waitpid(pid, 30_000) {
                            Ok(code) => self.emit(&alloc::format!("[{}] {} exited ({})", pid, c, code)),
                            Err(_) => self.fail(&alloc::format!("wait: {}: gone", pid)),
                        }
                    }
                }
                Some(a) => {
                    let pid = if let Some(n) = a.strip_prefix('%') {
                        match n.parse::<usize>().ok().and_then(|i| self.jobs.get(i.wrapping_sub(1))) {
                            Some((p, _)) => *p,
                            None => {
                                self.fail(&alloc::format!("wait: %{}: no such job", n));
                                return;
                            }
                        }
                    } else {
                        match a.parse::<u32>() {
                            Ok(p) => p,
                            Err(_) => {
                                self.fail("usage: wait [pid|%n]");
                                return;
                            }
                        }
                    };
                    self.jobs.retain(|(p, _)| *p != pid);
                    match ustd::waitpid(pid, 30_000) {
                        Ok(code) => self.emit(&alloc::format!("pid {} exited (status {})", pid, code)),
                        Err(_) => self.fail(&alloc::format!("wait: {}: timeout or no such task", pid)),
                    }
                }
            },
            "alias" => {
                if args.is_empty() {
                    for i in 0..self.aliases.len() {
                        let (n, v) = &self.aliases[i];
                        let line = alloc::format!("{}='{}'", n, v);
                        self.emit(&line);
                    }
                } else {
                    for a in args {
                        match a.find('=') {
                            Some(i) => {
                                let (n, v) = (&a[..i], &a[i + 1..]);
                                self.aliases.retain(|(x, _)| x != n);
                                self.aliases
                                    .push((String::from(n), String::from(v)));
                            }
                            None => match self.aliases.iter().find(|(n, _)| n == a) {
                                Some((n, v)) => {
                                    self.emit(&alloc::format!("{}='{}'", n, v))
                                }
                                None => self
                                    .fail(&alloc::format!("alias: {}: not found", a)),
                            },
                        }
                    }
                }
            }
            "unalias" => match args.first() {
                Some(n) => self.aliases.retain(|(x, _)| x != n),
                None => self.fail("usage: unalias <name>"),
            },
            "type" => match args.first() {
                Some(name) => {
                    if let Some((_, v)) = self.aliases.iter().find(|(n, _)| n == name) {
                        self.emit(&alloc::format!("{} is aliased to '{}'", name, v));
                    } else if Self::BUILTINS.contains(name) {
                        self.emit(&alloc::format!("{} is a shell builtin", name));
                    } else if ustd::stat(&alloc::format!("/bin/{}", name)).is_ok() {
                        self.emit(&alloc::format!("{} is /bin/{}", name, name));
                    } else {
                        self.fail(&alloc::format!("type: {}: not found", name));
                    }
                }
                None => self.fail("usage: type <cmd>"),
            },
            "hostname" => match args.first() {
                None => {
                    let h = self.host.clone();
                    self.emit(&h);
                }
                Some(n) => {
                    // persist so the next terminal boot reads the same name
                    self.host = String::from(*n);
                    self.vars
                        .insert(String::from("HOSTNAME"), self.host.clone());
                    if let Err(e) = ustd::write_all("/hostname", n.as_bytes()) {
                        self.fail(&alloc::format!("hostname: persist err {}", e));
                    }
                }
            },
            "id" => self.emit("uid=0(cosmos) gid=0(cosmos)"),
            "printf" => {
                // printf 'fmt' [args]: %s %d %i %x %% + \n \t \\ escapes;
                // the format re-cycles when args outnumber conversions
                match args.first() {
                    Some(fmt) => {
                        let rest = &args[1.min(args.len())..];
                        let mut ri = 0usize;
                        let mut line = String::new();
                        loop {
                            let start_ri = ri;
                            let b = fmt.as_bytes();
                            let mut i = 0;
                            while i < b.len() {
                                match b[i] {
                                    b'\\' if i + 1 < b.len() => {
                                        match b[i + 1] {
                                            b'n' => line.push('\n'),
                                            b't' => line.push('\t'),
                                            b'\\' => line.push('\\'),
                                            c => {
                                                line.push('\\');
                                                line.push(c as char);
                                            }
                                        }
                                        i += 2;
                                    }
                                    b'%' if i + 1 < b.len() => {
                                        match b[i + 1] {
                                            b'%' => line.push('%'),
                                            b's' => {
                                                line.push_str(
                                                    rest.get(ri).copied().unwrap_or(""),
                                                );
                                                ri += 1;
                                            }
                                            b'd' | b'i' => {
                                                line.push_str(
                                                    rest.get(ri).copied().unwrap_or("0"),
                                                );
                                                ri += 1;
                                            }
                                            b'x' => {
                                                let v: i64 = rest
                                                    .get(ri)
                                                    .and_then(|s| s.parse().ok())
                                                    .unwrap_or(0);
                                                line.push_str(&alloc::format!("{:x}", v));
                                                ri += 1;
                                            }
                                            c => {
                                                line.push('%');
                                                line.push(c as char);
                                            }
                                        }
                                        i += 2;
                                    }
                                    c => {
                                        line.push(c as char);
                                        i += 1;
                                    }
                                }
                            }
                            // re-cycle the format only while a pass actually
                            // consumed args (fmt with no conversions + extra
                            // args would otherwise loop forever)
                            if ri == start_ri || ri >= rest.len() {
                                break;
                            }
                        }
                        for l in line.split('\n') {
                            self.emit(l);
                        }
                    }
                    None => self.fail("usage: printf 'fmt' [args..]"),
                }
            }
            "dd" => {
                // dd if=X of=Y [bs=N] [count=M] [skip=N] -- real byte-level copy
                let (mut fi, mut fo) = ("", "");
                let (mut bs, mut count, mut skip) = (512usize, usize::MAX, 0usize);
                for a in args {
                    if let Some(v) = a.strip_prefix("if=") {
                        fi = v;
                    } else if let Some(v) = a.strip_prefix("of=") {
                        fo = v;
                    } else if let Some(v) = a.strip_prefix("bs=") {
                        bs = v.parse().unwrap_or(512);
                    } else if let Some(v) = a.strip_prefix("count=") {
                        count = v.parse().unwrap_or(usize::MAX);
                    } else if let Some(v) = a.strip_prefix("skip=") {
                        skip = v.parse().unwrap_or(0);
                    }
                }
                if fi.is_empty() {
                    self.fail("usage: dd if=<in> of=<out> [bs=N] [count=M] [skip=N]");
                    return;
                }
                match ustd::read_all(fi) {
                    Ok(d) => {
                        let s0 = (skip * bs).min(d.len());
                        let n = (count.saturating_mul(bs)).min(d.len() - s0);
                        let chunk = &d[s0..s0 + n];
                        if fo.is_empty() {
                            for l in String::from_utf8_lossy(chunk).lines() {
                                self.emit(l);
                            }
                        } else {
                            match ustd::write_all(fo, chunk) {
                                Ok(_) => self.emit(&alloc::format!(
                                    "  {} bytes copied {} -> {}", n, fi, fo
                                )),
                                Err(e) => {
                                    self.fail(&alloc::format!("dd: {}: err {}", fo, e))
                                }
                            }
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("dd: {}: err {}", fi, e)),
                }
            }
            "split" => {
                // split [-l N] <file> [prefix]: write prefix_aa, _ab ... ≤N lines
                let li = args.iter().position(|a| a == &"-l");
                let nlines: usize = li
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1000);
                let skipi = li.map(|i| i + 1);
                let pos: Vec<&str> = args
                    .iter()
                    .enumerate()
                    .filter(|(i, a)| !a.starts_with('-') && Some(*i) != skipi)
                    .map(|(_, a)| *a)
                    .collect();
                match pos.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => {
                            let s = String::from_utf8_lossy(&d);
                            let prefix = pos.get(1).copied().unwrap_or("x");
                            let mut written = 0usize;
                            let mut chunk: Vec<&str> = Vec::new();
                            let mut part = 0usize;
                            let suffix = |n: usize| {
                                let (a, b) = ((n / 26) as u8, (n % 26) as u8);
                                alloc::format!("{}{}", (b'a' + a) as char, (b'a' + b) as char)
                            };
                            let mut lines = s.lines().peekable();
                            while lines.peek().is_some() {
                                chunk.clear();
                                for _ in 0..nlines.max(1) {
                                    match lines.next() {
                                        Some(l) => chunk.push(l),
                                        None => break,
                                    }
                                }
                                let name = alloc::format!("{}{}", prefix, suffix(part));
                                match ustd::write_all(
                                    &name,
                                    alloc::format!("{}\n", chunk.join("\n")).as_bytes(),
                                ) {
                                    Ok(_) => {
                                        part += 1;
                                        written += chunk.len();
                                    }
                                    Err(e) => {
                                        self.fail(&alloc::format!(
                                            "split: {}: err {}", name, e
                                        ));
                                        return;
                                    }
                                }
                            }
                            self.emit(&alloc::format!(
                                "  {} lines -> {} part(s) {}{}...", written, part, prefix,
                                suffix(0)
                            ));
                        }
                        Err(e) => self.fail(&alloc::format!("split: {}: err {}", p, e)),
                    },
                    None => self.fail("usage: split [-l N] <file> [prefix]"),
                }
            }
            "wget" => {
                // wget [-O out] <url>: httpget that saves (default: basename)
                let ui = args
                    .iter()
                    .position(|a| !a.starts_with('-'))
                    .map(|i| args[i]);
                match ui {
                    Some(url) => {
                        let (req, fname) = Self::parse_url(url);
                        let out = args
                            .iter()
                            .position(|a| a == &"-O")
                            .and_then(|i| args.get(i + 1))
                            .map(|s| String::from(*s))
                            .unwrap_or(fname);
                        match ustd::net_http(&req) {
                            Some(body) => match ustd::write_all(&out, &body) {
                                Ok(_) => self.emit(&alloc::format!(
                                    "  saved {}B to {}  ({})", body.len(), out, req
                                )),
                                Err(e) => self
                                    .fail(&alloc::format!("wget: {}: err {}", out, e)),
                            },
                            None => self.fail(&alloc::format!("wget: {}: failed", req)),
                        }
                    }
                    None => self.fail("usage: wget [-O out] <http://host[:port]/path>"),
                }
            }
            "comm" | "join" | "paste" => {
                // comm a b = 3-col sorted merge; join a b = merge on field 1;
                // paste a b [-d c] = side-by-side columns
                let pos: Vec<&str> = args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .copied()
                    .collect();
                match (pos.first(), pos.get(1)) {
                    (Some(pa), Some(pb)) => match (ustd::read_all(pa), ustd::read_all(pb)) {
                        (Ok(da), Ok(db)) => {
                            let la: Vec<String> = String::from_utf8_lossy(&da)
                                .lines()
                                .map(String::from)
                                .collect();
                            let lb: Vec<String> = String::from_utf8_lossy(&db)
                                .lines()
                                .map(String::from)
                                .collect();
                            match cmd {
                                "comm" => {
                                    let (mut i, mut j) = (0usize, 0usize);
                                    while i < la.len() && j < lb.len() {
                                        match la[i].cmp(&lb[j]) {
                                            core::cmp::Ordering::Less => {
                                                let l = la[i].clone();
                                                self.emit(&l);
                                                i += 1;
                                            }
                                            core::cmp::Ordering::Greater => {
                                                let l = alloc::format!("\t{}", lb[j]);
                                                self.emit(&l);
                                                j += 1;
                                            }
                                            core::cmp::Ordering::Equal => {
                                                let l = alloc::format!("\t\t{}", la[i]);
                                                self.emit(&l);
                                                i += 1;
                                                j += 1;
                                            }
                                        }
                                    }
                                    for l in &la[i..] {
                                        self.emit(l);
                                    }
                                    for l in &lb[j..] {
                                        let l = alloc::format!("\t{}", l);
                                        self.emit(&l);
                                    }
                                }
                                "join" => {
                                    for l1 in &la {
                                        let f1: Vec<&str> = l1.split_whitespace().collect();
                                        if f1.is_empty() {
                                            continue;
                                        }
                                        for l2 in &lb {
                                            let f2: Vec<&str> =
                                                l2.split_whitespace().collect();
                                            if f2.first() == f1.first() {
                                                let rest1 = f1[1..].join(" ");
                                                let rest2 = f2[1..].join(" ");
                                                let out = alloc::format!(
                                                    "{} {} {}",
                                                    f1[0],
                                                    rest1,
                                                    rest2
                                                );
                                                self.emit(&out);
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    // paste [-d c]
                                    let d = args
                                        .iter()
                                        .position(|a| a == &"-d")
                                        .and_then(|i| args.get(i + 1))
                                        .and_then(|s| s.chars().next())
                                        .unwrap_or('\t');
                                    let n = la.len().max(lb.len());
                                    for i in 0..n {
                                        let a = la.get(i).map(|s| s.as_str()).unwrap_or("");
                                        let b = lb.get(i).map(|s| s.as_str()).unwrap_or("");
                                        let out = alloc::format!("{}{}{}", a, d, b);
                                        self.emit(&out);
                                    }
                                }
                            }
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            self.fail(&alloc::format!("{}: err {}", cmd, e))
                        }
                    },
                    _ => self.fail(&alloc::format!("usage: {} <file1> <file2>", cmd)),
                }
            }
            "expand" | "unexpand" => {
                // expand: tabs -> N spaces; unexpand: leading N-space runs -> tabs
                let ni = args.iter().position(|a| a == &"-t");
                let n: usize = ni
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(8)
                    .max(1);
                let nskip = ni.map(|i| i + 1);
                let popt = args
                    .iter()
                    .enumerate()
                    .find(|(i, a)| !a.starts_with('-') && Some(*i) != nskip)
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
                    let pad: String = core::iter::repeat(' ').take(n).collect();
                    for l in s.lines() {
                        if cmd == "expand" {
                            let out = l.replace('\t', &pad);
                            self.emit(&out);
                        } else {
                            // leading whitespace only (real unexpand converts
                            // all runs; leading is what matters for indent)
                            let spaces = l.len() - l.trim_start_matches(' ').len();
                            let tabs = spaces / n;
                            let rem = spaces % n;
                            let mut out = String::new();
                            for _ in 0..tabs {
                                out.push('\t');
                            }
                            for _ in 0..rem {
                                out.push(' ');
                            }
                            out.push_str(l.trim_start_matches(' '));
                            self.emit(&out);
                        }
                    }
                }
            }
            _ => {
                // try running it as a binary
                let path = alloc::format!("/bin/{}", cmd);
                if ustd::stat(&path).is_ok() {
                    match ustd::spawn(&path, &args.join(" ")) {
                        Ok(pid) => {
                            self.track(pid, &path);
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

    /// Reverse-history search state update: scans backward for the newest
    /// entry matching the query (rs.1 is the exclusive scan bound -- the
    /// last match's index -- so a repeat Ctrl-R finds the next older hit).
    fn rs_update(&mut self) {
        let Some((q, bound)) = self.rs.clone() else {
            return;
        };
        let m = (0..bound.min(self.hist.len()))
            .rev()
            .find(|&i| self.hist[i].contains(&q));
        match m {
            Some(i) => {
                self.rs = Some((q, i));
                self.cur = self.hist[i].clone();
                self.cx = self.cur.len();
            }
            None => {
                self.rs = Some((q, bound));
                self.cur.clear();
                self.cx = 0;
            }
        }
    }

    /// Runs /.cosmosrc at startup (aliases, vars) without polluting history.
    fn source_rc(&mut self) {
        let Ok(d) = ustd::read_all("/.cosmosrc") else {
            return;
        };
        let h0 = self.hist.len();
        let s = String::from_utf8_lossy(&d).into_owned();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.run(line);
        }
        self.hist.truncate(h0);
        self.hi = self.hist.len();
        self.last_ok = true;
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        // Ctrl-R reverse history search: typing refines the query, another
        // Ctrl-R steps to an older match, Enter runs the match, Esc restores
        if self.rs.is_some() {
            match k.key as u32 {
                x if x == KeyCode::Enter as u32 => {
                    self.rs = None;
                    let line = core::mem::take(&mut self.cur);
                    self.cx = 0;
                    let prompt = self.prompt_str();
                    self.emit(&alloc::format!("{}{}", prompt, line));
                    self.run(&line);
                }
                x if x == KeyCode::Escape as u32 => {
                    self.rs = None;
                    self.cur = core::mem::take(&mut self.rs_saved);
                    self.cx = self.cur.len();
                }
                x if x == KeyCode::Backspace as u32 => {
                    if let Some((q, b)) = &mut self.rs {
                        q.pop();
                        *b = self.hist.len();
                    }
                    self.rs_update();
                }
                x if x == KeyCode::Char as u32
                    && k.mods & 1 != 0
                    && (k.chr == b'r' || k.chr == b'R') =>
                {
                    self.rs_update();
                }
                x if x == KeyCode::Char as u32 && k.chr != 0 => {
                    if let Some((q, b)) = &mut self.rs {
                        q.push(k.chr as char);
                        *b = self.hist.len();
                    }
                    self.rs_update();
                }
                _ => {}
            }
            self.dirty_all = true;
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
        // nc udp mode: keystrokes send datagrams to the peer; Esc closes
        if self.nc_udp.is_some() {
            let peer = self.nc_udp.as_ref().unwrap().1;
            match k.key as u32 {
                x if x == KeyCode::Escape as u32 => {
                    self.nc_udp = None;
                    self.cur.clear();
                    self.cx = 0;
                    self.push_line("nc: udp closed");
                }
                _ => {
                    if let Some((rip, rport)) = peer {
                        let bytes: &[u8] = match k.key as u32 {
                            x if x == KeyCode::Enter as u32 => b"\r\n",
                            x if x == KeyCode::Backspace as u32 => &[0x7f],
                            x if x == KeyCode::Char as u32 => core::slice::from_ref(&k.chr),
                            _ => &[],
                        };
                        if !bytes.is_empty() {
                            let _ = self.nc_udp.as_ref().unwrap().0.send_to(rip, rport, bytes);
                        }
                    }
                    match k.key as u32 {
                        x if x == KeyCode::Enter as u32 => {
                            self.cur.clear();
                            self.cx = 0;
                        }
                        x if x == KeyCode::Backspace as u32 => {
                            self.cur.pop();
                            self.cx = self.cx.saturating_sub(1);
                        }
                        x if x == KeyCode::Char as u32 => {
                            self.cur.push(k.chr as char);
                            self.cx += 1;
                        }
                        _ => {}
                    }
                }
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
        // nc -l: Esc cancels the pending listen
        if self.nc_listen.is_some() && k.key == KeyCode::Escape as u32 {
            self.nc_listen = None;
            self.push_line("nc: listen cancelled");
            self.dirty_all = true;
            return;
        }
        // during watch/tail -f/yes modes, Esc or Enter stops; other keys ignored
        if self.watch.is_some() || self.tailf.is_some() || self.yesing.is_some() || self.top.is_some() || self.strace_p.is_some() {
            if k.key == KeyCode::Escape as u32
                || k.key == KeyCode::Enter as u32
                || (self.top.is_some() && k.chr == b'q')
                || (self.strace_p.is_some() && k.chr == b'q')
            {
                if let Some(pid) = self.strace_p.take() {
                    ustd::strace(1, pid, &mut []);
                    self.push_line("strace: detached");
                }
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
                if self.top.is_some() {
                    self.top = None;
                    self.push_line("top: stopped");
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
        // Ctrl+R starts reverse history search
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 && (k.chr == b'r' || k.chr == b'R') {
            self.rs_saved = core::mem::take(&mut self.cur);
            self.cx = 0;
            self.rs = Some((String::new(), self.hist.len()));
            self.dirty_all = true;
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
        // readline editing: Ctrl-A home, Ctrl-E end, Ctrl-K kill to EOL,
        // Ctrl-U kill to BOL, Ctrl-W kill word, Ctrl-Y yank
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 {
            match k.chr {
                b'a' | b'A' => {
                    self.cx = 0;
                    self.dirty_all = true;
                    return;
                }
                b'e' | b'E' => {
                    self.cx = self.cur.len();
                    self.dirty_all = true;
                    return;
                }
                b'k' | b'K' => {
                    if self.cx < self.cur.len() {
                        self.yank = self.cur[self.cx..].to_string();
                        self.cur.truncate(self.cx);
                        self.dirty_all = true;
                    }
                    return;
                }
                b'u' | b'U' => {
                    if self.cx > 0 {
                        self.yank = self.cur[..self.cx].to_string();
                        self.cur.replace_range(..self.cx, "");
                        self.cx = 0;
                        self.dirty_all = true;
                    }
                    return;
                }
                b'w' | b'W' => {
                    if self.cx > 0 {
                        let mut s = self.cx;
                        let b = self.cur.as_bytes();
                        while s > 0 && b[s - 1] == b' ' {
                            s -= 1;
                        }
                        while s > 0 && b[s - 1] != b' ' {
                            s -= 1;
                        }
                        self.yank = self.cur[s..self.cx].to_string();
                        self.cur.replace_range(s..self.cx, "");
                        self.cx = s;
                        self.dirty_all = true;
                    }
                    return;
                }
                b'y' | b'Y' => {
                    if !self.yank.is_empty() {
                        let y = self.yank.clone();
                        self.cur.insert_str(self.cx, &y);
                        self.cx += y.len();
                        self.dirty_all = true;
                    }
                    return;
                }
                _ => {}
            }
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
            // `read -n N` completes the instant N chars are in — no Enter
            if let Some((_, n)) = &self.read_modal {
                if *n > 0 && self.cur.len() >= *n {
                    let line = core::mem::take(&mut self.cur);
                    self.cx = 0;
                    self.emit(&line);
                    self.finish_read(line);
                }
            }
        } else if k.key == KeyCode::Enter as u32 {
            let line = core::mem::take(&mut self.cur);
            self.cx = 0;
            let prompt = self.prompt_str();
            self.emit(&alloc::format!("{}{}", prompt, line));
            if self.read_modal.is_some() {
                self.finish_read(line);
            } else {
                self.run(&line);
            }
        } else if k.key == KeyCode::Escape as u32 && self.read_modal.is_some() {
            self.read_modal = None;
            self.cur.clear();
            self.cx = 0;
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

    /// Builtin command names (tab completion + `type`).
    const BUILTINS: &'static [&'static str] = &[
        "help", "ls", "cd", "pwd", "cat", "mkdir", "touch", "rm", "mv", "cp",
        "echo", "clear", "ps", "mem", "uname", "whoami", "date", "ping",
        "resolve", "httpget", "wget", "ifconfig", "dhcp", "netstat", "kill", "grep",
        "uptime", "reboot", "shutdown", "exit", "history", "time",
        "head", "tail", "sort", "wc", "hex", "du", "watch", "df",
        "set", "env", "which", "more", "cal", "tree", "seq", "sleep", "sh", "calc",
        "dmesg", "arp", "httpd", "ntp", "nc", "fserve", "fget", "true", "false",
        "shot", "find", "killall", "basename", "dirname", "strings", "diff", "stat",
        "uniq", "tr", "cut", "tee", "base64", "sha256sum", "tar", "show",
        "yes", "sed", "xargs", "nl", "rev", "fmt", "cmp", "read", "wait",
        "alias", "unalias", "type", "hostname", "id", "printf", "dd", "split",
        "source", "comm", "join", "paste", "expand", "unexpand", "at", "file",
        "test", "[", "rand", "mount", "rmdir",
        "export", "unset", "man",
        "lspci", "lscpu", "factor", "shuf", "cksum",
        "eval", "break", "continue", "return",
        "for", "while", "until", "if", "do", "done", "then", "else", "elif", "fi",
        "tac", "fold", "column", "truncate", "mktemp", "clip", "pushd", "popd",
        "dirs", "zip", "unzip", "zipinfo", "beep", "play", "gzip", "gunzip", "zcat",
        "patch", "awk", "case", "esac",
        "md5sum", "uuencode", "uudecode", "zgrep", "portscan", "dig",
        "sha1sum", "od", "xxd", "banner", "units", "pr", "apropos", "whereis",
        "jobs", "fg", "bg", "disown", "halt", "arch", "nproc", "iostat", "strace",
        "tput", "builtin", "command", "exec", "dos2unix", "unix2dos", "base32", "sysctl",
        "fortune", "uuidgen", "logger", "whois", "fdisk", "vol", "blkid", "script",
        "nice", "renice", "pgrep", "pkill", "top", "dc", "vmstat", "free",
        "pcap", "ftp", "lsof", "fuser", "burn", "cron", "browse",
        "function", "declare", "typeset",
    ];

    const HELP_LINES: &'static [&'static str] = &[
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
                    "          alias/unalias  type  printf  dd  split  wget  hostname  id",
                    "          $(cmd) substitution   echo -e \\n \\t   help <cmd> filters",
                    "          cmd < file  source/. <file>  comm join paste  cp -r",
                    "          grep -A/-B/-C/-m/-w/-x  sed -i / '2,4d' / 'Np'  expand -t N",
                    "          find -name/-type/-maxdepth  Ctrl-R history search  .cosmosrc",
                    "          at <secs> <cmd>  httpd <port> [root] serves real files",
                    "          nc -l <port> listens  file <path> magic type  du/df -h human",
                    "          test/[ expr: -e -f -d -z -n = != -eq -ne -lt -le -gt -ge !",
                    "          ls -a -S -r  rand [n] [-x]  mount  rmdir  uname -srmva",
                    "          sh <file> args -> $0 $1..$N $#   !<prefix> reruns match",
                    "          more: Space/b page, / search, n next",
                    "          beep [hz ms]  play <file> (NOTE|HZ,DUR per line, R=rest)",
                    "          zip (deflate)/unzip/zipinfo  gzip [-c]  gunzip  zcat  /proc/*",
                    "          sh: case W in p|p) .. ;; esac   cmd <<EOF heredoc",
                    "          diff -u <a> <b>  patch <file.diff>  awk [-F c] 'prog' [file]",
                    "          tar cf|tf|tv|xf (dirs recurse, xf honors paths, 'z' = gz)",
                    "          /dev/{null,zero,full,random,urandom}  md5sum  uuencode/uudecode",
                    "          zgrep <pat> <file.gz>  portscan <host> [lo-hi|p..]  dig <name> [type]",
                    "          readline: Ctrl-A/E/K/U/W/Y",
                    "          sha1sum  od/xxd  banner  units  pr  apropos  whereis",
                    "          fortune  uuidgen  logger  whois  fdisk -l  vol  script",
                    "          nice/renice  pgrep/pkill  top  dc  vmstat  free",
                    "          sort -k/-t  find -exec  $$ (own pid)",
                    "          pcap capture  ftp (anon PASV)  lsof/fuser",
                    "          burn  cron  browse (html->text)  sums -c",
                    "          name() { cmds; }  function name { .. } -> $1..$9 $@ $#",
                    "          declare -f/typeset -f  unset -f name  man [-k pat] <page>",
                    "          reboot shutdown exit",
                    "          <binary>  - run /bin/<name> (e.g. cosmos-demo)",
    ];

    /// Register a spawned process in the jobs table + set $!.
    fn track(&mut self, pid: u32, cmdline: &str) {
        self.last_spawn = pid;
        self.jobs.push((pid, String::from(cmdline)));
    }

    /// Reload /crontab into cron_q; entries `period_s cmd...` fire every period.
    fn cron_load(&mut self) {
        self.cron_q.clear();
        if let Ok(d) = ustd::read_all("/crontab") {
            let now = ustd::uptime_ms();
            for l in String::from_utf8_lossy(&d).lines() {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let mut it = l.splitn(2, ' ');
                if let (Some(sec), Some(cmd)) = (it.next(), it.next()) {
                    if let Ok(s) = sec.parse::<u64>() {
                        if s > 0 {
                            self.cron_q.push((s * 1000, now + s * 1000, String::from(cmd.trim())));
                        }
                    }
                }
            }
        }
    }

    /// Anonymous FTP RETR over real TCP/21+PASV data channel.
    /// ftp_get("ftp.example.org", "pub/file") -> Ok(bytes)
    fn ftp_get(host: &str, rpath: &str) -> Result<Vec<u8>, String> {
        fn read_reply(s: &ustd::TcpSock, want: u32) -> Result<String, String> {
            let mut buf = Vec::new();
            let deadline = ustd::uptime_ms() + 5000;
            loop {
                match s.recv(600) {
                    Some(d) => {
                        buf.extend_from_slice(&d);
                        let txt = String::from_utf8_lossy(&buf).into_owned();
                        // complete reply = last line "^NNN " (or single-line)
                        for l in txt.lines() {
                            if l.len() >= 4 && l.as_bytes()[3] == b' '
                                && l[..3].chars().all(|c| c.is_ascii_digit())
                            {
                                let code: u32 = l[..3].parse().unwrap_or(0);
                                if want != 0 && code / 100 != want / 100 {
                                    return Err(alloc::format!("ftp: got {} want {}", code, want));
                                }
                                return Ok(txt);
                            }
                        }
                        if ustd::uptime_ms() > deadline || buf.len() > 8192 {
                            return Err(String::from("ftp: reply timeout"));
                        }
                    }
                    None => return Err(String::from("ftp: connection closed")),
                }
            }
        }
        fn cmd(s: &ustd::TcpSock, c: &str, want: u32) -> Result<String, String> {
            s.send(alloc::format!("{}\r\n", c).as_bytes())
                .ok_or_else(|| String::from("ftp: send failed"))?;
            read_reply(s, want)
        }
        let (host, port) = match host.split_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(21)),
            None => (host, 21),
        };
        let ip = match ustd::net_dns(host) {
            Some(i) => i,
            None => parse_ipv4(host)
                .ok_or_else(|| alloc::format!("ftp: {}: no DNS", host))?,
        };
        let ctl = (16810..16814)
            .find_map(|lp| ustd::TcpSock::connect(lp, ip, port))
            .ok_or_else(|| alloc::format!("ftp: {}:{}: connect failed", host, port))?;
        read_reply(&ctl, 220)?;
        cmd(&ctl, "USER anonymous", 330)?; // 331 or 230 (class 3)
        cmd(&ctl, "PASS cosmos@", 230)?;
        cmd(&ctl, "TYPE I", 200)?;
        let pasv = cmd(&ctl, "PASV", 200)?;
        // "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
        let nums: Vec<u32> = pasv
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();
        if nums.len() < 6 {
            return Err(alloc::format!("ftp: bad PASV: {}", pasv.trim()));
        }
        let n = nums.len();
        let dip = [nums[n - 6] as u8, nums[n - 5] as u8, nums[n - 4] as u8, nums[n - 3] as u8];
        let dport = (nums[n - 2] * 256 + nums[n - 1]) as u16;
        let data = (16840..16844)
            .find_map(|lp| ustd::TcpSock::connect(lp, dip, dport))
            .ok_or_else(|| String::from("ftp: data connect failed"))?;
        cmd(&ctl, &alloc::format!("RETR {}", rpath), 100)?; // 150/125
        let mut out = Vec::new();
        let deadline = ustd::uptime_ms() + 15000;
        loop {
            match data.recv(1000) {
                Some(d) => {
                    out.extend_from_slice(&d);
                    if out.len() > 1 << 20 || ustd::uptime_ms() > deadline {
                        break;
                    }
                }
                None => break,
            }
        }
        let _ = read_reply(&ctl, 226);
        let _ = cmd(&ctl, "QUIT", 200);
        Ok(out)
    }

    /// Real WHOIS over TCP/43: query whois.iana.org for the referral,
    /// then the registry server. Returns output lines.
    fn whois_query(q: &str) -> Result<Vec<String>, String> {
        fn query(server: &str, q: &str) -> Result<Vec<String>, String> {
            let ip = ustd::net_dns(server)
                .ok_or_else(|| alloc::format!("whois: {}: no DNS", server))?;
            let mut lport = 16800u16;
            let mut sock = None;
            for _ in 0..8 {
                lport += 1;
                if let Some(s) = ustd::TcpSock::connect(lport, ip, 43) {
                    sock = Some(s);
                    break;
                }
            }
            let sock = sock.ok_or_else(|| alloc::format!("whois: {}:43: connect failed", server))?;
            sock.send(alloc::format!("{}\r\n", q).as_bytes())
                .ok_or_else(|| String::from("whois: send failed"))?;
            let mut out = Vec::new();
            let mut buf = Vec::new();
            let deadline = ustd::uptime_ms() + 6000;
            loop {
                match sock.recv(800) {
                    Some(d) => {
                        buf.extend_from_slice(&d);
                        if buf.len() > 8192 || ustd::uptime_ms() > deadline {
                            break;
                        }
                    }
                    None => break,
                }
            }
            for l in String::from_utf8_lossy(&buf).lines() {
                out.push(String::from(l));
            }
            Ok(out)
        }
        let mut lines = query("whois.iana.org", q)?;
        let refer = lines
            .iter()
            .find(|l| l.to_lowercase().starts_with("refer:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string());
        if let Some(r) = refer {
            lines.push(alloc::format!(";; referred to {}", r));
            match query(&r, q) {
                Ok(mut more) => lines.append(&mut more),
                Err(e) => lines.push(alloc::format!(";; {}: {}", r, e)),
            }
        }
        Ok(lines)
    }

    /// Tab-complete: command names before the first space, paths after.
    /// Inserts the longest common prefix of the matches.
    fn complete(&mut self) {
        // word being completed = text after the last space before the caret
        let head = &self.cur[..self.cx];
        let word_start = head.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let word = &head[word_start..];
        let mut cands: Vec<String> = Vec::new();
        if word_start == 0 {
            // command position -- match built-ins + /bin binaries
            for c in Self::BUILTINS {
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
            // path position -- split dir/prefix, readdir, keep trailing / on dirs
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
            // exact match -- add a space after commands
            if word_start == 0 {
                self.cur.insert(self.cx, ' ');
                self.cx += 1;
            }
        } else {
            // ambiguous -- list the matches
            for c in &cands {
                self.emit(&alloc::format!("  {}", c));
            }
        }
    }

    /// Recursive byte total for `du`.
    fn du_tree(&mut self, path: &str, depth: usize, human: bool) -> u64 {
        match ustd::readdir(path) {
            Ok(ents) => {
                let mut total = 0u64;
                for e in ents {
                    let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                    let p = alloc::format!("{}{}{}", path, if path.ends_with('/') { "" } else { "/" }, name);
                    if e.is_dir != 0 {
                        total += self.du_tree(&p, depth + 1, human);
                    } else {
                        total += e.size;
                        if depth == 0 {
                            if human {
                                self.emit(&alloc::format!("  {:>8} {}", human_size(e.size), p));
                            } else {
                                self.emit(&alloc::format!("  {:>8} {}", e.size, p));
                            }
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
            Err(_) => ustd::remove(path), // plain file (or bad path -- remove reports)
        }
    }

    /// http://host[:port]/path → (kernel arg "host[:port]/path", basename).
    /// https:// is left in the host and fails DNS honestly (no TLS stack).
    fn parse_url(url: &str) -> (String, String) {
        let u = url.strip_prefix("http://").unwrap_or(url);
        let fname = u.rsplit('/').next().unwrap_or("index.html");
        (
            String::from(u),
            String::from(if fname.is_empty() { "index.html" } else { fname }),
        )
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

    /// One grep pass over `lines`. `prefix` (a path) prints `path:N:` for
    /// matches and `path-N-` for context lines, mirroring real grep.
    /// `pat` is pre-lowered when ci. Returns the match count.
    fn grep_lines(&mut self, pat: &str, lines: &[&str], prefix: &str, o: &GrepOpts) -> usize {
        let is_match = |l: &str| -> bool {
            let hay = if o.ci {
                l.to_ascii_lowercase()
            } else {
                String::from(l)
            };
            if o.exact {
                hay.trim() == pat
            } else if o.word {
                hay.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|t| t == pat)
            } else {
                hay.contains(pat)
            }
        };
        let fmt = |i: usize, l: &str, ctx: bool| -> String {
            let mut pre = String::new();
            if !prefix.is_empty() {
                pre.push_str(prefix);
                pre.push(if ctx { '-' } else { ':' });
            }
            if o.num {
                pre.push_str(&alloc::format!("{}{}", i + 1, if ctx { '-' } else { ':' }));
            }
            alloc::format!("{}{}", pre, l)
        };
        let mut hits = 0usize;
        let mut printed_up_to = 0usize; // lines already emitted (exclusive)
        let mut after_left = 0usize;
        let show = !o.cnt && !o.quiet && o.files == 0;
        for (i, l) in lines.iter().enumerate() {
            if is_match(l) != o.inv {
                hits += 1;
                if o.only && !o.inv && !o.quiet {
                    // -o: emit each matching span, one per line
                    let hay = if o.ci {
                        l.to_ascii_lowercase()
                    } else {
                        String::from(*l)
                    };
                    if o.word || o.exact {
                        self.emit(pat);
                    } else {
                        let pb = pat.as_bytes();
                        let hb = hay.as_bytes();
                        let mut s = 0usize;
                        while s + pb.len() <= hb.len() {
                            if &hb[s..s + pb.len()] == pb {
                                self.emit(&l[s..s + pb.len()]);
                                s += pb.len();
                            } else {
                                s += 1;
                            }
                        }
                    }
                } else if show {
                    let from = i.saturating_sub(o.before).max(printed_up_to);
                    for j in from..i {
                        self.emit(&fmt(j, lines[j], true));
                    }
                    self.emit(&fmt(i, l, false));
                    printed_up_to = i + 1;
                    after_left = o.after;
                }
                if hits >= o.maxm {
                    // flush the -A tail of the final match
                    let mut j = i + 1;
                    while after_left > 0 && j < lines.len() {
                        if show {
                            self.emit(&fmt(j, lines[j], true));
                        }
                        after_left -= 1;
                        j += 1;
                    }
                    break;
                }
            } else if after_left > 0 {
                if show {
                    self.emit(&fmt(i, l, true));
                    printed_up_to = i + 1;
                }
                after_left -= 1;
            }
        }
        hits
    }

    fn grep_file(&mut self, pat: &str, path: &str, o: &GrepOpts) -> usize {
        match ustd::read_all(path) {
            Ok(d) => {
                let s = String::from_utf8_lossy(&d).into_owned();
                let lines: Vec<&str> = s.lines().collect();
                let hits = self.grep_lines(pat, &lines, path, o);
                if o.files == 1 && hits > 0 {
                    self.emit(path);
                } else if o.files == 2 && hits == 0 {
                    self.emit(path);
                } else if o.cnt {
                    self.emit(&alloc::format!("{}: {}", path, hits));
                }
                hits
            }
            Err(e) => {
                self.fail(&alloc::format!("grep: {}: err {}", path, e));
                0
            }
        }
    }

    fn grep_run(&mut self, pat: &str, path: &str, o: &GrepOpts) -> usize {
        if !o.rec {
            return self.grep_file(pat, path, o);
        }
        let mut total = 0usize;
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
                            total += self.grep_file(pat, &p, o);
                        }
                    }
                }
                Err(_) => total += self.grep_file(pat, &dir, o), // a plain file was passed
            }
        }
        total
    }

    /// find: recursive name-match walk printing full paths.
    /// `want_dir` filters by entry type; `maxd` bounds descent depth.
    /// Iterative directory walk: paths matching (pat, want_dir, maxd).
    /// Returns display strings (dirs carry a trailing '/').
    fn find_collect(&mut self, dir: &str, pat: &str, want_dir: Option<bool>, maxd: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = alloc::vec::Vec::new();
        stack.push((String::from(dir), 0usize));
        while let Some((d, dep)) = stack.pop() {
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
                        let is_dir = e.is_dir != 0;
                        if wild_match(pat, name)
                            && want_dir.map(|w| is_dir == w).unwrap_or(true)
                        {
                            out.push(alloc::format!("{}{}", p, if is_dir { "/" } else { "" }));
                        }
                        if is_dir && dep < maxd {
                            stack.push((p, dep + 1));
                        }
                    }
                }
                Err(_) => self.fail(&alloc::format!("find: {}: can't open", d)),
            }
        }
        out
    }

    fn find_run(&mut self, dir: &str, pat: &str, want_dir: Option<bool>, maxd: usize) {
        for p in self.find_collect(dir, pat, want_dir, maxd) {
            self.emit(&p);
        }
    }

    /// cp -r: copy a file, or a directory tree when `rec`. `to` naming
    /// follows real cp: a directory target copies INTO it.
    fn cp_any(&mut self, from: &str, to: &str, rec: bool) {
        match ustd::stat(from) {
            Ok(st) if st.is_dir != 0 => {
                if !rec {
                    self.fail("cp: omitting directory (use -r)");
                    return;
                }
                let dst = match ustd::stat(to) {
                    Ok(d) if d.is_dir != 0 => {
                        let base = from
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or(from);
                        alloc::format!("{}/{}", to.trim_end_matches('/'), base)
                    }
                    _ => String::from(to),
                };
                if let Err(e) = ustd::mkdir(&dst) {
                    self.fail(&alloc::format!("cp: {}: err {}", dst, e));
                    return;
                }
                match ustd::readdir(from) {
                    Ok(ents) => {
                        for e in ents {
                            let name =
                                core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                            let f = alloc::format!("{}/{}", from.trim_end_matches('/'), name);
                            let t = alloc::format!("{}/{}", dst, name);
                            self.cp_any(&f, &t, rec);
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("cp: {}: err {}", from, e)),
                }
            }
            Ok(_) => {
                let dst = match ustd::stat(to) {
                    Ok(d) if d.is_dir != 0 => {
                        let base = from
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or(from);
                        alloc::format!("{}/{}", to.trim_end_matches('/'), base)
                    }
                    _ => String::from(to),
                };
                match ustd::read_all(from) {
                    Ok(d) => {
                        if let Err(e) = ustd::write_all(&dst, &d) {
                            self.fail(&alloc::format!("cp: {}: err {}", dst, e));
                        }
                    }
                    Err(e) => self.fail(&alloc::format!("cp: {}: err {}", from, e)),
                }
            }
            Err(e) => self.fail(&alloc::format!("cp: {}: err {}", from, e)),
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
        nc_listen: None,
        nc_udp: None,
        last_ok: true,
        vars: alloc::collections::BTreeMap::new(),
        prev_cwd: String::new(),
        pager: None,
        sel: None,
        sel_drag: false,
        pq: String::new(),
        pg_input: false,
        tailf: None,
        top: None,
        top_last: 0,
        top_prev: Vec::new(),
        tailf_last: 0,
        at_q: Vec::new(),
        cron_q: Vec::new(),
        jobs: Vec::new(),
        last_spawn: 0,
        strace_p: None,
        setx: false,
        errexit: false,
        no_alias_once: false,
        yank: String::new(),
        cap_bin: None,
        last_cap_bin: Vec::new(),
        script_fd: None,
        yesing: None,
        prev_buttons: 0,
        aliases: Vec::new(),
        subst_depth: 0,
        run_depth: 0,
        read_modal: None,
        funcs: Vec::new(),
        func_collect: None,
        func_depth: 0,
        func_bdepth: 0,
        block_buf: String::new(),
        heredocs: Vec::new(),
        flow: 0,
        script_depth: 0,
        dirstack: Vec::new(),
        rs: None,
        rs_saved: String::new(),
        host: ustd::read_all("/hostname")
            .ok()
            .map(|d| String::from(String::from_utf8_lossy(&d).trim()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| String::from("cosmos")),
    };
    t.vars
        .insert(String::from("HOSTNAME"), t.host.clone());
    t.load_hist();
    t.cron_load();
    t.source_rc();
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
        if let Some((l, root)) = &t.httpd {
            if let Some((sock, rip, rport)) = l.accept(0) {
                let req = sock.recv(400).unwrap_or_default();
                let line = String::from_utf8_lossy(&req);
                let first = line.lines().next().unwrap_or("");
                // GET /path -- sanitize, map under the docroot, serve a real
                // file or an autoindex listing
                let path = first
                    .strip_prefix("GET ")
                    .unwrap_or("/")
                    .split_whitespace()
                    .next()
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/");
                let bad = path.contains("..") || path.bytes().any(|b| !(32..127).contains(&b));
                let clean = path.trim_start_matches('/');
                let mut full = alloc::format!(
                    "{}{}",
                    if root.ends_with('/') || clean.is_empty() {
                        String::from(root.trim_end_matches('/'))
                    } else {
                        alloc::format!("{}/", root.trim_end_matches('/'))
                    },
                    clean
                );
                if full.is_empty() {
                    full.push('/');
                }
                let is_dir = ustd::stat(&full).map(|s| s.is_dir != 0).unwrap_or(false);
                if is_dir && !full.ends_with('/') {
                    full.push('/');
                }
                let index = alloc::format!("{}index.html", full);
                let (status, mime, body): (&str, &str, Vec<u8>) = if bad {
                    ("400 Bad Request", "text/plain", Vec::from(&b"bad request"[..]))
                } else if is_dir && ustd::stat(&index).is_ok() {
                    match ustd::read_all(&index) {
                        Ok(d) => ("200 OK", "text/html", d),
                        Err(_) => ("404 Not Found", "text/html", Vec::from(&b"<h1>404</h1>"[..])),
                    }
                } else if is_dir {
                    // autoindex: real directory listing with links
                    let mut h = alloc::format!(
                        "<html><body><h1>Index of /{}</h1><pre>",
                        clean
                    );
                    if let Ok(ents) = ustd::readdir(&full) {
                        for e in ents {
                            let name = core::str::from_utf8(&e.name[..e.name_len as usize])
                                .unwrap_or("?");
                            let disp = alloc::format!(
                                "{}{}",
                                name,
                                if e.is_dir != 0 { "/" } else { "" }
                            );
                            let dirpart = alloc::format!(
                                "/{}",
                                clean.trim_end_matches('/')
                            );
                            h.push_str(&alloc::format!(
                                "<a href=\"{}{}{}\">{}</a>  {} B\n",
                                dirpart,
                                if dirpart == "/" { "" } else { "/" },
                                disp,
                                disp,
                                e.size
                            ));
                        }
                    }
                    h.push_str("</pre></body></html>");
                    ("200 OK", "text/html", h.into_bytes())
                } else {
                    match ustd::read_all(&full) {
                        Ok(d) => {
                            let mime = if full.ends_with(".html") || full.ends_with(".htm") {
                                "text/html"
                            } else if full.ends_with(".txt") {
                                "text/plain"
                            } else if full.ends_with(".ppm") {
                                "image/x-portable-pixmap"
                            } else {
                                "application/octet-stream"
                            };
                            ("200 OK", mime, d)
                        }
                        Err(_) => ("404 Not Found", "text/html", Vec::from(&b"<h1>404 Not Found</h1>"[..])),
                    }
                };
                let resp = alloc::format!(
                    "HTTP/1.0 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    mime,
                    body.len()
                );
                let _ = sock.send(resp.as_bytes());
                let _ = sock.send(&body);
                t.push_line(&alloc::format!(
                    "httpd: {} -> {} <- {}.{}.{}.{}:{}",
                    first,
                    status,
                    rip[0], rip[1], rip[2], rip[3], rport
                ));
                t.dirty_all = true;
            }
        }
        // nc -l: accept a pending inbound connection into the nc session
        if let Some(l) = &t.nc_listen {
            if let Some((s, rip, rport)) = l.accept(0) {
                t.nc = Some(s);
                t.nc_listen = None;
                t.push_line(&alloc::format!(
                    "nc: client {}.{}.{}.{}:{} connected -- keystrokes send, Esc closes",
                    rip[0], rip[1], rip[2], rip[3], rport
                ));
                t.dirty_all = true;
            }
        }
        // nc udp mode: drain inbound datagrams; remember the last peer
        if t.nc_udp.is_some() {
            let mut pending: Vec<([u8; 4], u16, Vec<u8>)> = Vec::new();
            loop {
                let d = t.nc_udp.as_ref().unwrap().0.recv_from(0);
                match d {
                    Some(dg) => pending.push(dg),
                    None => break,
                }
            }
            let got = !pending.is_empty();
            for (rip, rport, d) in pending {
                if let Some((_, peer)) = &mut t.nc_udp {
                    *peer = Some((rip, rport));
                }
                let txt = String::from_utf8_lossy(&d);
                for l in txt.split('\n') {
                    t.push_line(l.trim_end_matches('\r'));
                }
            }
            if got {
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
                let hdr = alloc::format!("$ {}   (every {}ms -- Esc/Enter to stop)", cmd, ms);
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
        // top mode: live process table; %CPU = cpu_ticks delta share
        if let Some(ms) = t.top {
            if now - t.top_last >= ms {
                t.top_last = now;
                let procs = ustd::proclist(64);
                // delta vs previous snapshot -> %CPU
                let mut dsum = 0u64;
                let mut delta: Vec<(u32, u64)> = Vec::new();
                for p in &procs {
                    let prev = t
                        .top_prev
                        .iter()
                        .find(|(id, _)| *id == p.pid)
                        .map(|(_, c)| *c)
                        .unwrap_or(0);
                    let d = p.cpu_ticks.saturating_sub(prev);
                    delta.push((p.pid, d));
                    dsum += d;
                }
                t.top_prev = procs.iter().map(|p| (p.pid, p.cpu_ticks)).collect();
                t.lines.clear();
                t.view = 0;
                let mi = ustd::meminfo();
                t.push_line(&alloc::format!(
                    "top - {}ms - {} procs, mem {}% used  (Esc/Enter/q stops)",
                    ms,
                    procs.len(),
                    if mi.total_kb > 0 { mi.used_kb * 100 / mi.total_kb } else { 0 }
                ));
                t.push_line("  PID   NI  %CPU   VSZ_kB  STATE  NAME");
                let mut scored: Vec<(u64, u32, u64, String, String, String)> = procs
                    .iter()
                    .map(|p| {
                        let d = delta.iter().find(|(id, _)| *id == p.pid).map(|(_, v)| *v).unwrap_or(0);
                        let name = core::str::from_utf8(&p.name).unwrap_or("?").trim_end_matches('\0');
                        let (mut st, mut ni) = (String::from("?"), String::from("?"));
                        if let Ok(dd) = ustd::read_all(&alloc::format!("/proc/{}/status", p.pid)) {
                            let s = String::from_utf8_lossy(&dd).into_owned();
                            for l in s.lines() {
                                if let Some(v) = l.strip_prefix("State:\t") {
                                    st = String::from(v.split(' ').next().unwrap_or("?"));
                                }
                                if let Some(v) = l.strip_prefix("Nice:\t") {
                                    ni = String::from(v);
                                }
                            }
                        }
                        (d, p.pid, p.mem_kb, ni, String::from(st), String::from(name))
                    })
                    .collect();
                scored.sort_by(|a, b| b.0.cmp(&a.0));
                for (d, pid, mem, ni, st, name) in scored.iter().take(20) {
                    let st: &str = st;
                    let pct = if dsum > 0 { d * 100 / dsum } else { 0 };
                    t.push_line(&alloc::format!(
                        "  {:>3} {:>3}  {:>3}%  {:>7}  {:<5}  {}",
                        pid, ni, pct, mem, st, name
                    ));
                }
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
        // `cron`: recurring commands (period_s cmd) fire on their period
        {
            let mut fired: Vec<String> = Vec::new();
            for e in t.cron_q.iter_mut() {
                if e.1 <= now {
                    e.1 = now + e.0;
                    fired.push(e.2.clone());
                }
            }
            for c in fired {
                t.push_line(&alloc::format!("cron: {}", c));
                t.run(&c);
            }
            if !t.cron_q.is_empty() {
                t.dirty_all = true;
            }
        }
        // strace -p: drain the traced task's syscall records periodically
        if let Some(pid) = t.strace_p {
            let mut buf = alloc::vec![0u8; 56 * 32];
            let n = ustd::strace(2, pid, &mut buf);
            if n < 0 {
                t.push_line(&alloc::format!("strace: pid {} gone", pid));
                t.strace_p = None;
                t.dirty_all = true;
            } else if n > 0 {
                for rec in buf[..n as usize].chunks_exact(56) {
                    let rd = |i: usize| {
                        u64::from_le_bytes(rec[i * 8..i * 8 + 8].try_into().unwrap())
                    };
                    t.push_line(&alloc::format!(
                        "  {}({}, {}, {}, {}, {}) = {}",
                        sys_name(rd(0)), rd(1), rd(2), rd(3), rd(4), rd(5), rd(6)
                    ));
                }
                t.dirty_all = true;
            }
        }
        // `at` queue: run due deferred commands (in submission order)
        {
            let mut due = 0usize;
            while due < t.at_q.len() && t.at_q[due].0 <= now {
                due += 1;
            }
            if due > 0 {
                let fired: Vec<(u64, String)> = t.at_q.drain(..due).collect();
                for (_, cmd) in fired {
                    t.push_line(&alloc::format!("at: {}", cmd));
                    t.run(&cmd);
                }
                t.dirty_all = true;
            }
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

/// Strip a trailing unquoted `&` (job control). Returns the inner command.
fn strip_bg(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    if b.is_empty() || b[b.len() - 1] != b'&' {
        return None;
    }
    // `&&` is the stmt operator, not a background marker
    if b.len() >= 2 && b[b.len() - 2] == b'&' {
        return None;
    }
    let inner = s[..s.len() - 1].trim_end();
    if inner.is_empty() {
        None
    } else {
        Some(inner)
    }
}

/// Number -> name for the syscall table (strace output).
fn sys_name(nr: u64) -> &'static str {
    use shared::*;
    match nr {
        SYS_READ => "read",
        SYS_WRITE => "write",
        SYS_OPEN => "open",
        SYS_CLOSE => "close",
        SYS_STAT => "stat",
        SYS_SEEK => "seek",
        SYS_READDIR => "readdir",
        SYS_MKDIR => "mkdir",
        SYS_REMOVE => "remove",
        SYS_RENAME => "rename",
        SYS_SPAWN => "spawn",
        SYS_EXIT => "exit",
        SYS_YIELD => "yield",
        SYS_SLEEP_MS => "sleep_ms",
        SYS_UPTIME_MS => "uptime_ms",
        SYS_TIME => "datetime",
        SYS_MEMINFO => "meminfo",
        SYS_KILL => "kill",
        SYS_KILL2 => "kill2",
        SYS_WAITPID => "waitpid",
        SYS_PROCLIST => "proclist",
        SYS_GETPID => "getpid",
        SYS_GETCWD => "getcwd",
        SYS_CHDIR => "chdir",
        SYS_NICE => "nice",
        SYS_IPC_LISTEN => "ipc_listen",
        SYS_IPC_CONNECT => "ipc_connect",
        SYS_IPC_SEND => "ipc_send",
        SYS_IPC_RECV => "ipc_recv",
        SYS_IPC_CLOSE => "ipc_close",
        SYS_IPC_OWNER => "ipc_owner",
        SYS_SHM_CREATE => "shm_create",
        SYS_SHM_MAP => "shm_map",
        SYS_SHM_DROP => "shm_drop",
        SYS_NET_PING => "net_ping",
        SYS_NET_INFO => "net_info",
        SYS_NET_DNS => "net_dns",
        SYS_NET_DHCP => "net_dhcp",
        SYS_NET_HTTP => "net_http",
        SYS_NET_STAT => "net_stat",
        SYS_NET_UDP_OPEN => "udp_open",
        SYS_NET_UDP_SEND => "udp_send",
        SYS_NET_UDP_RECV => "udp_recv",
        SYS_NET_UDP_CLOSE => "udp_close",
        SYS_NET_TCP_OPEN => "tcp_open",
        SYS_NET_TCP_SEND => "tcp_send",
        SYS_NET_TCP_RECV => "tcp_recv",
        SYS_NET_TCP_CLOSE => "tcp_close",
        SYS_NET_TCP_LISTEN => "tcp_listen",
        SYS_NET_TCP_ACCEPT => "tcp_accept",
        SYS_NET_TCP_UNLISTEN => "tcp_unlisten",
        SYS_PCAP => "pcap",
        SYS_STRACE => "strace",
        SYS_KLOG => "klog",
        SYS_BEEP => "beep",
        SYS_DF => "df",
        SYS_RAND => "rand",
        SYS_ARP => "arp",
        SYS_PCI_SCAN => "pci_scan",
        SYS_FB_INFO => "fb_info",
        SYS_SHOT => "shot",
        SYS_CLIP_SET => "clip_set",
        SYS_CLIP_GET => "clip_get",
        SYS_POWEROFF => "poweroff",
        SYS_REBOOT => "reboot",
        SYS_DEBUG => "debug",
        SYS_MMAP => "mmap",
        _ => "?",
    }
}

/// RFC 4648 base32 encode (A-Z2-7, '=' padding, 64-col lines).
fn b32_encode(data: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut col = 0usize;
    for ch in data.chunks(5) {
        let mut b = [0u8; 5];
        b[..ch.len()].copy_from_slice(ch);
        let v = (b[0] as u64) << 32 | (b[1] as u64) << 24 | (b[2] as u64) << 16 | (b[3] as u64) << 8 | b[4] as u64;
        let n = match ch.len() {
            1 => 2, 2 => 4, 3 => 5, 4 => 7, _ => 8,
        };
        for i in 0..n {
            out.push(A[((v >> (35 - i * 5)) & 0x1f) as usize] as char);
        }
        for _ in n..8 {
            out.push('=');
        }
        col += 8;
        if col >= 64 {
            out.push('\n');
            col = 0;
        }
    }
    out
}

/// RFC 4648 base32 decode; ignores whitespace, '=' padding. None on bad char.
fn b32_decode(t: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut nbits = 0u32;
    for c in t.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 5) | v as u64;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Parse a function-definition opener: `name() {`, `name(){`, or
/// `function name [()] {`. Returns (name, body-if-closed-on-this-line,
/// text-after-the-closing-brace). `body=None` means the `{` is still open —
/// the caller keeps collecting lines. Unquoted braces only; `{` inside
/// 'quotes' is literal text.
fn func_open(s: &str) -> Option<(String, Option<String>, String)> {
    let t = s.trim();
    let rest = if let Some(r) = t.strip_prefix("function") {
        r.trim_start()
    } else {
        t
    };
    // name = leading identifier; then optional `()`, then `{`
    let nend = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if nend == 0 {
        return None;
    }
    let name = &rest[..nend];
    if !name.chars().next().unwrap().is_ascii_alphabetic() && !name.starts_with('_') {
        return None;
    }
    let mut r = rest[nend..].trim_start();
    if let Some(rp) = r.strip_prefix("()") {
        r = rp.trim_start();
    } else if t.starts_with("function") {
        // `function name {` form is fine without ()
    } else {
        return None; // `name {` without () is not a func def
    }
    if !r.starts_with('{') {
        return None;
    }
    // scan for the matching unquoted `}` (nested braces count)
    let b = r.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut depth = 0i32;
    let mut i = 0;
    let mut close_at = None;
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'{' if !sq && !dq => depth += 1,
            b'}' if !sq && !dq => {
                depth -= 1;
                if depth == 0 {
                    close_at = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    match close_at {
        Some(c) => {
            let body = r[1..c].trim().to_string();
            let trailing = r[c + 1..].trim().to_string();
            Some((String::from(name), Some(body), trailing))
        }
        None => Some((String::from(name), None, String::new())),
    }
}

/// Count unquoted `{`/`}` braces in a line (for multi-line func collection).
/// Returns (open, close) counts.
fn brace_scan(s: &str) -> (i32, i32) {
    let b = s.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let (mut o, mut c) = (0i32, 0i32);
    for &ch in b {
        match ch {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'{' if !sq && !dq => o += 1,
            b'}' if !sq && !dq => c += 1,
            _ => {}
        }
    }
    (o, c)
}
