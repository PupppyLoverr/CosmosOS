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
    dirty_all: bool,
    needs_cursor_flip: bool,
}

impl Term {
    fn push_line(&mut self, s: &str) {
        // wrap at COLS
        let mut rest = s;
        loop {
            if rest.len() <= COLS {
                self.lines.push(String::from(rest));
                break;
            }
            let (a, b) = rest.split_at(COLS);
            self.lines.push(String::from(a));
            rest = b;
        }
        if self.lines.len() > 400 {
            let drop = self.lines.len() - 400;
            self.lines.drain(0..drop);
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
        let start = self.lines.len().saturating_sub(rows_vis.saturating_sub(total_cur_lines));
        let mut y = 8i32;
        for line in &self.lines[start..] {
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
        self.hist.push(String::from(input));
        self.hi = self.hist.len();
        let mut it = input.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let args: Vec<&str> = it.collect();
        match cmd {
            "help" => {
                for l in [
                    "commands: help ls cd pwd cat mkdir touch rm mv cp echo",
                    "          clear ps mem uname whoami date ping resolve ifconfig",
                    "          reboot shutdown exit",
                    "          <binary>  - run /bin/<name> (e.g. cosmos-demo)",
                ] {
                    self.push_line(l);
                }
            }
            "ls" => {
                let p = args.first().copied().unwrap_or(".");
                let dir = if p == "." { ustd::getcwd() } else { String::from(p) };
                match ustd::readdir(&dir) {
                    Ok(ents) => {
                        if ents.is_empty() {
                            self.push_line("  (empty)");
                        }
                        for e in ents {
                            let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
                            let line = if e.is_dir != 0 {
                                alloc::format!("  {}/", name)
                            } else {
                                alloc::format!("  {}  ({} B)", name, e.size)
                            };
                            self.push_line(&line);
                        }
                    }
                    Err(e) => self.push_line(&alloc::format!("ls: {}: err {}", dir, e)),
                }
            }
            "cd" => {
                let p = args.first().copied().unwrap_or("/");
                if !ustd::chdir(p) {
                    self.push_line(&alloc::format!("cd: {}: no such dir", p));
                }
            }
            "pwd" => self.push_line(&ustd::getcwd()),
            "cat" => match args.first() {
                Some(p) => match ustd::read_all(p) {
                    Ok(d) => {
                        let s = String::from_utf8_lossy(&d);
                        for l in s.lines() {
                            self.push_line(l);
                        }
                    }
                    Err(e) => self.push_line(&alloc::format!("cat: {}: err {}", p, e)),
                },
                None => self.push_line("usage: cat <file>"),
            },
            "mkdir" => match args.first() {
                Some(p) => {
                    if let Err(e) = ustd::mkdir(p) {
                        self.push_line(&alloc::format!("mkdir: err {}", e));
                    }
                }
                None => self.push_line("usage: mkdir <dir>"),
            },
            "touch" => match args.first() {
                Some(p) => {
                    if let Err(e) = ustd::write_all(p, b"") {
                        self.push_line(&alloc::format!("touch: err {}", e));
                    }
                }
                None => self.push_line("usage: touch <file>"),
            },
            "rm" => match args.first() {
                Some(p) => {
                    if let Err(e) = ustd::remove(p) {
                        self.push_line(&alloc::format!("rm: err {}", e));
                    }
                }
                None => self.push_line("usage: rm <path>"),
            },
            "mv" => {
                if args.len() < 2 {
                    self.push_line("usage: mv <from> <to>");
                } else if let Err(e) = ustd::rename(args[0], args[1]) {
                    self.push_line(&alloc::format!("mv: err {}", e));
                }
            }
            "cp" => {
                if args.len() < 2 {
                    self.push_line("usage: cp <from> <to>");
                } else {
                    match ustd::read_all(args[0]) {
                        Ok(d) => {
                            if let Err(e) = ustd::write_all(args[1], &d) {
                                self.push_line(&alloc::format!("cp: err {}", e));
                            }
                        }
                        Err(e) => self.push_line(&alloc::format!("cp: {}: err {}", args[0], e)),
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
                        self.push_line(&alloc::format!("echo: err {}", e));
                    }
                } else {
                    self.push_line(&joined);
                }
            }
            "clear" => self.lines.clear(),
            "ps" => {
                for p in ustd::proclist(64) {
                    let name = core::str::from_utf8(&p.name)
                        .unwrap_or("?")
                        .trim_end_matches('\0');
                    self.push_line(&alloc::format!(
                        "  pid={} {} mem={}KB",
                        p.pid,
                        name,
                        p.mem_kb
                    ));
                }
            }
            "mem" => {
                let mi = ustd::meminfo();
                self.push_line(&alloc::format!(
                    "  total={}KB used={}KB heap={}KB tasks={}",
                    mi.total_kb, mi.used_kb, mi.kernel_heap_kb, mi.tasks
                ));
            }
            "uname" => self.push_line("CosmosOS 0.1 x86_64 (rust kernel)"),
            "whoami" => self.push_line("cosmos"),
            "date" => {
                let d = ustd::datetime();
                self.push_line(&alloc::format!(
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
                            Some(rtt) => self.push_line(&alloc::format!(
                                "reply from {}.{}.{}.{}: time={}ms", a, b, c, d, rtt
                            )),
                            None => self.push_line(&alloc::format!(
                                "ping {}.{}.{}.{}: timeout", a, b, c, d
                            )),
                        }
                    }
                    None => self.push_line(&alloc::format!("ping: bad ip '{}'", s)),
                },
                None => self.push_line("usage: ping <a.b.c.d>  (try 10.0.2.2)"),
            },
            "resolve" => match args.first() {
                Some(host) => match ustd::net_dns(host) {
                    Some(ip) => self.push_line(&alloc::format!(
                        "{} -> {}.{}.{}.{}",
                        host, ip[0], ip[1], ip[2], ip[3]
                    )),
                    None => self.push_line(&alloc::format!("resolve: {}: no answer", host)),
                },
                None => self.push_line("usage: resolve <hostname>  (real DNS over UDP/53)"),
            },
            "ifconfig" => match ustd::net_info() {
                Some((mac, ip)) => {
                    self.push_line(&alloc::format!(
                        "net0: ip {}.{}.{}.{} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip[0], ip[1], ip[2], ip[3],
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    ));
                }
                None => self.push_line("no network device"),
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
                            self.push_line(&alloc::format!("spawned {} (pid {})", cmd, pid));
                        }
                        Err(_) => self.push_line(&alloc::format!("{}: spawn failed", cmd)),
                    }
                } else {
                    self.push_line(&alloc::format!("{}: unknown command", cmd));
                }
            }
        }
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        if k.key == KeyCode::Char as u32 {
            self.cur.insert(self.cx, k.chr as char);
            self.cx += 1;
        } else if k.key == KeyCode::Enter as u32 {
            let line = core::mem::take(&mut self.cur);
            self.cx = 0;
            let prompt = self.prompt_str();
            self.push_line(&alloc::format!("{}{}", prompt, line));
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
        self.dirty_all = true;
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
        dirty_all: true,
        needs_cursor_flip: true,
    };
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
