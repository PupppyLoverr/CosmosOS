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
use ustd::{print, println};

const COLS: usize = 90;
const ROWS: usize = 40;
const CW: i32 = 8;
const CH: i32 = 16;

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
            if b[i] == b'$' && i + 1 < b.len() && (b[i + 1].is_ascii_alphanumeric() || b[i + 1] == b'_') {
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

    /// Lines per `more` page (whole visible area).
    fn page_lines(&self) -> usize {
        ((self.c.h as usize / CH as usize) - 2).max(4)
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
        if let Some(rest) = input.strip_prefix("time ") {
            let t0 = ustd::uptime_ms();
            self.run(rest);
            self.emit(&alloc::format!("  {} ms", ustd::uptime_ms() - t0));
            return;
        }
        // pipe: left | right  (right may itself contain pipes/redirects)
        if let Some(pi) = input.find('|') {
            let left = input[..pi].trim();
            let right = input[pi + 1..].trim();
            let out = self.run_captured(left);
            let saved = self.pipe_in.replace(out.join("\n"));
            self.run(right);
            self.pipe_in = saved;
            return;
        }
        // redirect: cmd > file  /  cmd >> file
        if let Some(pi) = input.find('>') {
            let left = input[..pi].trim();
            let mut rest = input[pi + 1..].trim();
            let append = rest.starts_with('>');
            if append {
                rest = rest[1..].trim_start();
            }
            let fname = rest.split_whitespace().next().unwrap_or("");
            if fname.is_empty() {
                self.emit("usage: <cmd> > file  (or >> to append)");
                return;
            }
            let out = self.run_captured(left);
            let mut body = out.join("\n");
            if !body.is_empty() {
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
                self.emit(&alloc::format!("{}: err {}", fname, e));
            }
            return;
        }
        self.hist.push(String::from(input));
        self.hi = self.hist.len();
        self.save_hist();
        // $VAR expansion (whole-token vars; $ followed by name chars)
        let expanded = self.expand_vars(input);
        let input = expanded.as_str();
        let mut it = input.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let args: Vec<&str> = it.collect();
        match cmd {
            "help" => {
                for l in [
                    "commands: help ls cd pwd cat mkdir touch rm mv cp echo",
                    "          clear ps mem uname whoami date ping resolve httpget ifconfig dhcp",
                    "          netstat kill <pid> grep <pat> <file> (or -r <dir>) uptime",
                    "          hex <file> wc <file> du <path> history time <cmd>",
                    "          head/tail [-n N] <file> sort <file>",
                    "          a | b   cmd > file   cmd >> file   watch [-n s] cmd",
                    "          df  (volume usage)  more <file> (pager)",
                    "          reboot shutdown exit",
                    "          <binary>  - run /bin/<name> (e.g. cosmos-demo)",
                ] {
                    self.emit(l);
                }
            }
            "ls" => {
                let p = args.first().copied().unwrap_or(".");
                let dir = if p == "." { ustd::getcwd() } else { String::from(p) };
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
                    Err(e) => self.emit(&alloc::format!("ls: {}: err {}", dir, e)),
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
                    self.emit(&alloc::format!("cd: {}: no such dir", dest));
                }
            }
            "pwd" => self.emit(&ustd::getcwd()),
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
                    self.emit("usage: set NAME=value | set -u NAME");
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
                        Err(_) => self.emit(&alloc::format!("which: {} not found", c)),
                    }
                }
                None => self.emit("usage: which <cmd>"),
            },
            "cat" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let s = String::from_utf8_lossy(&d);
                        for l in s.lines() {
                            self.emit(l);
                        }
                    }
                    Err(e) => self.emit(&alloc::format!("cat: {}: err {}", p, e)),
                },
                None => match self.pipe_in.clone() {
                    Some(s) => {
                        for l in s.lines() {
                            self.emit(l);
                        }
                    }
                    None => self.emit("usage: cat <file>"),
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
                            self.emit(&alloc::format!("mkdir: err {}", e));
                        }
                    }
                    None => self.emit("usage: mkdir [-p] <dir>"),
                }
            },
            "touch" => match args.first() {
                Some(p) => {
                    if let Err(e) = ustd::write_all(p, b"") {
                        self.emit(&alloc::format!("touch: err {}", e));
                    }
                }
                None => self.emit("usage: touch <file>"),
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
                            self.emit(&alloc::format!("rm: {}: err {}", p, e));
                        }
                    }
                    None => self.emit("usage: rm [-r] <path>"),
                }
            }
            "mv" => {
                if args.len() < 2 {
                    self.emit("usage: mv <from> <to>");
                } else if let Err(e) = ustd::rename(args[0], args[1]) {
                    self.emit(&alloc::format!("mv: err {}", e));
                }
            }
            "cp" => {
                if args.len() < 2 {
                    self.emit("usage: cp <from> <to>");
                } else {
                    match ustd::read_all(args[0]) {
                        Ok(d) => {
                            if let Err(e) = ustd::write_all(args[1], &d) {
                                self.emit(&alloc::format!("cp: err {}", e));
                            }
                        }
                        Err(e) => self.emit(&alloc::format!("cp: {}: err {}", args[0], e)),
                    }
                }
            }
            "echo" => {
                // echo hello > file  |  echo hello
                let joined = args.join(" ");
                if let Some(i) = joined.find('>') {
                    let (text, path) = joined.split_at(i);
                    let path = path[1..].trim();
                    let mut d = String::from(text.trim());
                    d.push('\n');
                    if let Err(e) = ustd::write_all(path, d.as_bytes()) {
                        self.emit(&alloc::format!("echo: err {}", e));
                    }
                } else {
                    self.emit(&joined);
                }
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
            "date" => {
                let d = ustd::datetime();
                self.emit(&alloc::format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    d.year, d.month, d.day, d.hour, d.minute, d.second
                ));
            }
            "ping" => match args.first() {
                Some(s) => match parse_ipv4(s) {
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
                    None => self.emit(&alloc::format!("ping: bad ip '{}'", s)),
                },
                None => self.emit("usage: ping <a.b.c.d>  (try 10.0.2.2)"),
            },
            "resolve" => match args.first() {
                Some(host) => match ustd::net_dns(host) {
                    Some(ip) => self.emit(&alloc::format!(
                        "{} -> {}.{}.{}.{}",
                        host, ip[0], ip[1], ip[2], ip[3]
                    )),
                    None => self.emit(&alloc::format!("resolve: {}: no answer", host)),
                },
                None => self.emit("usage: resolve <hostname>  (real DNS over UDP/53)"),
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
                                    Err(e) => self.emit(&alloc::format!("httpget: {}: err {}", f, e)),
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
                    None => self.emit(&alloc::format!("httpget: {}: failed", host)),
                },
                None => self.emit("usage: httpget <host> [-o file]  (real TCP/80 GET /)"),
            },
            "grep" => {
                // grep <pat> <file> | grep -r <pat> <dir>
                let (rec, pat, path) = if args.first() == Some(&"-r") {
                    (true, args.get(1).copied(), args.get(2).copied())
                } else {
                    (false, args.first().copied(), args.get(1).copied())
                };
                match (pat, path) {
                    (Some(p), Some(path)) => self.grep_run(p, path, rec),
                    (Some(p), None) => match self.pipe_in.clone() {
                        Some(s) => {
                            for l in s.lines() {
                                if l.contains(p) {
                                    self.emit(l);
                                }
                            }
                        }
                        None => self.emit("usage: grep <pat> <file> | grep -r <pat> <dir>"),
                    },
                    _ => self.emit("usage: grep <pat> <file> | grep -r <pat> <dir>"),
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
                    Err(e) => self.emit(&alloc::format!("hex: {}: err {}", p, e)),
                },
                None => self.emit("usage: hex <file>  (first 1KiB)"),
            },
            "du" => match args.first() {
                Some(p) => {
                    let n = self.du_tree(p, 0);
                    self.emit(&alloc::format!("  {} B total", n));
                }
                None => self.emit("usage: du <path>  (recursive bytes)"),
            },
            "df" => match ustd::df() {
                Some((total, free)) => {
                    let used = total - free;
                    self.emit(&alloc::format!("  total {} MiB  used {} MiB  free {} MiB", total / (1024 * 1024), used / (1024 * 1024), free / (1024 * 1024)));
                    self.emit(&alloc::format!("  ({} B / {} B used)", used, total));
                }
                None => self.emit("df: no volume mounted"),
            },
            "more" => {
                let content = match args.first() {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                        Err(e) => {
                            self.emit(&alloc::format!("more: {}: err {}", p, e));
                            None
                        }
                    },
                    None => self.pipe_in.clone(),
                };
                if let Some(s) = content {
                    let ls: Vec<String> = s.lines().map(String::from).collect();
                    self.page(0, ls);
                } else if args.is_empty() && self.pipe_in.is_none() {
                    self.emit("usage: more <file>   (Space/PgDn next, b back, q quit)");
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
                    self.emit("usage: watch [-n secs] <cmd...>  (Esc/Enter exits)");
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
            "head" | "tail" | "sort" | "wc" => {
                let popt = args.iter().position(|a| !a.starts_with('-')).map(|i| args[i]);
                let n: usize = args
                    .iter()
                    .position(|a| a == &"-n")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10);
                let content = match popt {
                    Some(p) => match ustd::read_all(p) {
                        Ok(d) => Some(String::from_utf8_lossy(&d).into_owned()),
                        Err(e) => {
                            self.emit(&alloc::format!("{}: {}: err {}", cmd, p, e));
                            None
                        }
                    },
                    None => self.pipe_in.clone(),
                };
                match content {
                    Some(s) => {
                        let mut ls: Vec<&str> = s.lines().collect();
                        if cmd == "wc" {
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
                            self.emit(&alloc::format!("  {} lines {} words {} bytes", l, w, s.len()));
                        } else if cmd == "sort" {
                            ls.sort();
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
                        }
                    }
                    None => self.emit(&alloc::format!("usage: {} [-n N] <file>", cmd)),
                }
            }
            "netstat" => {
                for l in ustd::net_stat().lines() {
                    self.emit(l);
                }
            }
            "kill" => match args.first() {
                Some(p) => match p.parse::<u32>() {
                    Ok(pid) if ustd::kill(pid) => self.emit(&alloc::format!("killed {}", pid)),
                    _ => self.emit("kill: no such pid"),
                },
                None => self.emit("usage: kill <pid>"),
            },
            "dhcp" => match ustd::net_dhcp() {
                Some(ip) => self.emit(&alloc::format!(
                    "dhcp: lease {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]
                )),
                None => self.emit("dhcp: no response (net down or no server)"),
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
            _ => {
                // try running it as a binary
                let path = alloc::format!("/bin/{}", cmd);
                if ustd::stat(&path).is_ok() {
                    match ustd::spawn(&path, &args.join(" ")) {
                        Ok(pid) => {
                            self.emit(&alloc::format!("spawned {} (pid {})", cmd, pid));
                        }
                        Err(_) => self.emit(&alloc::format!("{}: spawn failed", cmd)),
                    }
                } else {
                    self.emit(&alloc::format!("{}: unknown command", cmd));
                }
            }
        }
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        // pager mode: Space/PgDn next page, b/PgUp back, q/Esc/Enter quits
        if self.pager.is_some() {
            match k.key as u32 {
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
        // during watch mode, Esc or Enter stops it; other keys are ignored
        if self.watch.is_some() {
            if k.key == KeyCode::Escape as u32 || k.key == KeyCode::Enter as u32 {
                self.watch = None;
                self.push_line("watch stopped");
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
            "set", "env", "which", "more",
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
                    self.emit(&alloc::format!("du: {}: not found", path));
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

    fn grep_file(&mut self, pat: &str, path: &str) {
        match ustd::read_all(path) {
            Ok(d) => {
                let s = String::from_utf8_lossy(&d);
                for l in s.lines() {
                    if l.contains(pat) {
                        self.emit(&alloc::format!("{}: {}", path, l));
                    }
                }
            }
            Err(e) => self.emit(&alloc::format!("grep: {}: err {}", path, e)),
        }
    }

    fn grep_run(&mut self, pat: &str, path: &str, rec: bool) {
        if !rec {
            self.grep_file(pat, path);
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
                            self.grep_file(pat, &p);
                        }
                    }
                }
                Err(_) => self.grep_file(pat, &dir), // a plain file was passed
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
        vars: alloc::collections::BTreeMap::new(),
        prev_cwd: String::new(),
        pager: None,
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
                if p.wheel > 0 {
                    let max = t.lines.len().saturating_sub(1);
                    t.view = (t.view + 3 * p.wheel as usize).min(max);
                    t.dirty_all = true;
                } else if p.wheel < 0 {
                    t.view = t.view.saturating_sub(3 * (-p.wheel) as usize);
                    t.dirty_all = true;
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
