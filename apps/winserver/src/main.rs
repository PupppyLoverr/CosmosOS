//! winserver: the CosmosOS compositor + desktop shell.
//!
//! Owns the framebuffer, composites per-window shm surfaces with chrome
//! (titlebar, borders, buttons), routes PS/2 input to the focused app, and
//! provides the taskbar / launcher / workspaces.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::println;

// ---- palette ---------------------------------------------------------------
const WALL_TOP: u32 = 0xFF181A1E;
const WALL_BOT: u32 = 0xFF0B0C0E;
const TBAR: u32 = 0xFF101114;
const TBAR_EDGE: u32 = 0xFF2A2C31;
const TITLE_ACT: u32 = 0xFF2B2E34;
const TITLE_IDLE: u32 = 0xFF1C1E22;
const BTN_HOV: u32 = 0xFF3A3D44;
const CLOSE_HOV: u32 = 0xFFC0392B;
const TXT: u32 = draw::TEXT;
const DIM: u32 = draw::DIM;
const CURSOR: u32 = 0xFFF2F3F5;
const MENU_BG: u32 = 0xFF17181C;
const MENU_HOV: u32 = 0xFF2E3138;

const TBAR_H: i32 = 36;
const BTN_SZ: i32 = 18; // caption buttons
const SNAP: i32 = 8; // screen edge snap margin
const RESIZE_R: i32 = 5; // resize border hit width

// ---- windows ---------------------------------------------------------------
struct Win {
    id: u32,
    owner: u32, // client reply port
    x: i32,
    y: i32,
    w: i32,
    h: i32, // outer (chrome-included) size
    shm_id: u32,
    ptr: *mut u32,
    stride: i32,
    cw: i32,
    ch: i32, // client surface size
    title: String,
    flags: u32,
    min: bool,
    maxed: bool,
    saved: (i32, i32, i32, i32), // pre-maximize rect
    ws: u32,
    pending_shm: u32, // resize in flight
    pid: u32,
}

impl Win {
    fn deco(&self) -> bool {
        self.flags & WIN_DECORATE != 0
    }
    fn resizable(&self) -> bool {
        self.flags & WIN_RESIZABLE != 0
    }
    // client area top-left in screen coords
    fn client_x(&self) -> i32 {
        self.x + if self.deco() { BORDER_W as i32 } else { 0 }
    }
    fn client_y(&self) -> i32 {
        self.y + if self.deco() { (TITLE_H + BORDER_W) as i32 } else { 0 }
    }
    fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.x + self.w && py >= self.y && py < self.y + self.h
    }
}

struct Drag {
    win: u32,
    mode: u8, // 0 move, 1 resize
    ox: i32,
    oy: i32, // grab offset inside window
    rx: i32,
    ry: i32,
    rw: i32,
    rh: i32, // live rect while dragging
}

struct Launcher {
    open: bool,
    items: Vec<(&'static str, &'static str)>, // (label, binary path)
    sel: i32,
}

static mut MX: i32 = 512;
static mut MY: i32 = 384;
static mut BTNS: u8 = 0;

struct S {
    fb: Canvas,
    fw: i32,
    fh: i32,
    wins: Vec<Win>,
    next_id: u32,
    focus: u32,
    ws_port: u32,
    in_port: u32,
    drag: Option<Drag>,
    launcher: Launcher,
    workspace: u32,
    dirty: bool,
    damage: Option<(i32, i32, i32, i32)>, // union of damaged rects (x,y,w,h)
    last_tick: u64,
    last_frame: u64,
    wall: Vec<u32>, // wallpaper cache (fh-TBAR_H rows)
}

impl S {
    fn win_at(&self, x: i32, y: i32) -> Option<usize> {
        for i in (0..self.wins.len()).rev() {
            let w = &self.wins[i];
            if w.ws == self.workspace && !w.min && w.contains(x, y) {
                return Some(i);
            }
        }
        None
    }
    fn win_mut(&mut self, id: u32) -> Option<&mut Win> {
        self.wins.iter_mut().find(|w| w.id == id)
    }
    fn win_idx(&self, id: u32) -> Option<usize> {
        self.wins.iter().position(|w| w.id == id)
    }
}

fn send_ev(port: u32, kind: u16, payload: &[u8]) {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(payload);
    let _ = ustd::ipc_send(port, &v);
}

fn main_loop() -> ! {
    let fbi = ustd::fb_info().expect("fb claim — winserver must be the first fb user");
    let fb = Canvas::new(fbi.addr as *mut u32, fbi.width, fbi.height, fbi.stride);
    let ws_port = ustd::ipc_listen(WS_PORT);
    let in_port = ustd::ipc_listen(INPUT_PORT);
    println!("[winserver] up: fb={}x{} ws_port={} in_port={}", fbi.width, fbi.height, ws_port, in_port);

    // pre-render wallpaper once into a cache buffer
    let wall_h = (fbi.height as i32 - TBAR_H) as usize;
    let mut wall = alloc::vec![0u32; fbi.width as usize * wall_h];
    {
        let cw = Canvas::new(wall.as_mut_ptr(), fbi.width, wall_h as u32, fbi.width);
        cw.fill_grad(0, 0, fbi.width as i32, fbi.height as i32 - TBAR_H, WALL_TOP, WALL_BOT);
    }

    let mut s = S {
        fb,
        fw: fbi.width as i32,
        fh: fbi.height as i32,
        wall,
        wins: Vec::new(),
        next_id: 1,
        focus: 0,
        ws_port,
        in_port,
        drag: None,
        launcher: Launcher {
            open: false,
            items: alloc::vec![
                ("Terminal", "/bin/cosmos-terminal"),
                ("Files", "/bin/cosmos-files"),
                ("Text Editor", "/bin/cosmos-editor"),
                ("Settings", "/bin/cosmos-settings"),
                ("System Monitor", "/bin/cosmos-sysmon"),
                ("Demo", "/bin/cosmos-demo"),
            ],
            sel: -1,
        },
        workspace: 0,
        dirty: true,
        damage: None,
        last_tick: 0,
        last_frame: 0,
    };

    composite(&mut s);
    loop {
        // drain input
        let mut buf = alloc::vec![0u8; WS_MSG_MAX + 16];
        let mut progressed = false;
        while let Ok(n) = ustd::ipc_recv(s.in_port, &mut buf, 0) {
            if n == 0 {
                break;
            }
            progressed |= handle_input(&mut s, &buf[..n]);
        }
        // drain window requests
        while let Ok(n) = ustd::ipc_recv(s.ws_port, &mut buf, 0) {
            if n == 0 {
                break;
            }
            progressed = true;
            handle_req(&mut s, &buf[..n]);
        }
        // per-second taskbar refresh + reap windows whose owner died —
        // damage the taskbar strip and let the single composite path draw
        // it (never clear dirty without compositing — dropped composites
        // leave "ghost" windows).
        let up = ustd::uptime_ms();
        if up / 1000 != s.last_tick {
            s.last_tick = up / 1000;
            reap_dead(&mut s);
            let (fh, fw) = (s.fh, s.fw);
            dmg(&mut s, 0, fh - TBAR_H, fw, TBAR_H);
        }
        // composite throttle: ~50fps max so input/ws-port drains keep up
        // under floods (damage composites are cheap but share the gate).
        if up.wrapping_sub(s.last_frame) >= 20 {
            if s.dirty {
                s.fb.reset_clip();
                composite(&mut s);
                s.last_frame = ustd::uptime_ms();
                s.dirty = false;
                s.damage = None;
            } else if let Some((dx, dy, dw, dh)) = s.damage.take() {
                s.fb.set_clip(dx, dy, dw, dh);
                composite(&mut s);
                s.last_frame = ustd::uptime_ms();
                s.fb.reset_clip();
            }
        }
        if !progressed {
            // wait for more input — the message that wakes us still counts
            match ustd::ipc_recv(s.in_port, &mut buf, 16) {
                Ok(n) if n > 0 => { handle_input(&mut s, &buf[..n]); }
                _ => {}
            }
        }
    }
}

// ---- input ------------------------------------------------------------------
fn handle_input(s: &mut S, msg: &[u8]) -> bool {
    if msg.is_empty() {
        return false;
    }
    match msg[0] {
        x if x == InputKind::Key as u8 => {
            if msg.len() < core::mem::size_of::<InputKey>() {
                return false;
            }
            let k: InputKey = unsafe { core::ptr::read_unaligned(msg.as_ptr() as *const _) };
            on_key(s, &k);
        }
        x if x == InputKind::Mouse as u8 => {
            if msg.len() < core::mem::size_of::<InputMouse>() {
                return false;
            }
            let m: InputMouse = unsafe { core::ptr::read_unaligned(msg.as_ptr() as *const _) };
            on_mouse(s, &m);
        }
        _ => return false,
    }
    true
}

/// Union a rect into the damage accumulator (cheaper than a full dirty).
fn dmg(s: &mut S, x: i32, y: i32, w: i32, h: i32) {
    if w <= 0 || h <= 0 {
        return;
    }
    match s.damage {
        Some((dx, dy, dw, dh)) => {
            let x0 = x.min(dx);
            let y0 = y.min(dy);
            let x1 = (x + w).max(dx + dw);
            let y1 = (y + h).max(dy + dh);
            s.damage = Some((x0, y0, x1 - x0, y1 - y0));
        }
        None => s.damage = Some((x, y, w, h)),
    }
}

fn spawn_app(path: &str) {
    match ustd::spawn(path, "") {
        Ok(pid) => println!("[winserver] spawned {} pid={}", path, pid),
        Err(_) => println!("[winserver] spawn {} failed", path),
    }
}

fn on_key(s: &mut S, k: &InputKey) {
    // F4-F9 launch apps; F1/F2 switch workspaces
    if k.down != 0 {
        let app = match k.key {
            x if x == KeyCode::F4 as u32 => Some("/bin/cosmos-terminal"),
            x if x == KeyCode::F5 as u32 => Some("/bin/cosmos-files"),
            x if x == KeyCode::F6 as u32 => Some("/bin/cosmos-editor"),
            x if x == KeyCode::F7 as u32 => Some("/bin/cosmos-settings"),
            x if x == KeyCode::F8 as u32 => Some("/bin/cosmos-sysmon"),
            x if x == KeyCode::F9 as u32 => Some("/bin/cosmos-demo"),
            _ => None,
        };
        if let Some(p) = app {
            spawn_app(p);
            return;
        }
        // Alt+Tab cycles focus among windows on this workspace
        if k.key == KeyCode::Tab as u32 && k.mods & 4 != 0 {
            let ids: Vec<u32> = s
                .wins
                .iter()
                .filter(|w| w.ws == s.workspace && !w.min)
                .map(|w| w.id)
                .collect();
            if !ids.is_empty() {
                let next = ids
                    .iter()
                    .position(|&i| i == s.focus)
                    .map(|i| ids[(i + 1) % ids.len()])
                    .unwrap_or(ids[0]);
                focus_raise(s, next);
            }
            return;
        }
    }
    // F1/F2 switch workspaces
    if k.down != 0 && (k.key == KeyCode::F1 as u32 || k.key == KeyCode::F2 as u32) {
        let tgt = if k.key == KeyCode::F1 as u32 { 0 } else { 1 };
        if tgt != s.workspace {
            s.workspace = tgt;
            s.focus = top_id(s);
            s.dirty = true;
        }
        return;
    }
    if let Some(w) = s.wins.iter().find(|w| w.id == s.focus && w.ws == s.workspace && !w.min) {
        let ev = EvKey { window_id: w.id, key: k.key, chr: k.chr, down: k.down, mods: k.mods, _pad: 0 };
        send_ev(
            w.owner,
            EV_KEY,
            unsafe { core::slice::from_raw_parts(&ev as *const _ as *const u8, core::mem::size_of::<EvKey>()) },
        );
    }
}

fn on_mouse(s: &mut S, m: &InputMouse) {
    let (mut nx, mut ny) = unsafe { (MX + m.dx as i32, MY + m.dy as i32) };
    nx = nx.clamp(0, s.fw - 1);
    ny = ny.clamp(0, s.fh - 1);
    let (px, py) = unsafe { (MX, MY) };
    let pbtns = unsafe { BTNS };
    unsafe {
        MX = nx;
        MY = ny;
        BTNS = m.buttons;
    }

    // active drag?
    if let Some(d) = s.drag.as_mut() {
        if m.buttons & 1 == 0 {
            // released: apply
            let d = s.drag.take().unwrap();
            finish_drag(s, d);
            s.dirty = true;
        } else {
            d.rx = nx - d.ox;
            d.ry = ny - d.oy;
            if d.mode == 1 {
                // window may have been closed/reaped mid-drag — drop the
                // drag instead of panicking on the unwrap
                let Some(w) = s.wins.iter().find(|w| w.id == d.win) else {
                    s.drag = None;
                    s.dirty = true;
                    return;
                };
                // resize to the pointer's position relative to the corner
                let (wx, wy) = (w.x, w.y);
                d.rw = (nx - wx).max(160);
                d.rh = (ny - wy).max(100);
            }
            s.dirty = true;
        }
        return;
    }

    let pressed = m.buttons & 1 != 0 && pbtns & 1 == 0;
    if pressed {
        mouse_press(s, nx, ny);
        return;
    }

    // motion: cursor moved — damage only the two 16px cursor cells
    if nx != px || ny != py {
        dmg(s, px, py, 16, 16);
        dmg(s, nx, ny, 16, 16);
    }
    // forward motion to the window under the cursor (or focused)
    if let Some(i) = s.win_at(nx, ny) {
        let w = &s.wins[i];
        let ev = EvPointer {
            window_id: w.id,
            x: nx - w.client_x(),
            y: ny - w.client_y(),
            buttons: m.buttons,
            wheel: m.wheel,
            _pad: [0; 2],
        };
        send_ev(w.owner, EV_POINTER, unsafe {
            core::slice::from_raw_parts(&ev as *const _ as *const u8, core::mem::size_of::<EvPointer>())
        });
    }
}

fn mouse_press(s: &mut S, x: i32, y: i32) {
    // taskbar?
    if y >= s.fh - TBAR_H {
        taskbar_click(s, x);
        s.dirty = true;
        return;
    }
    // launcher menu?
    if s.launcher.open {
        let mw = 220;
        let mh = s.launcher.items.len() as i32 * 30 + 8;
        let mx = 0;
        let my = s.fh - TBAR_H - mh;
        if x >= mx && x < mx + mw && y >= my && y < my + mh {
            let idx = (y - my - 4) / 30;
            if idx >= 0 && (idx as usize) < s.launcher.items.len() {
                let (_, path) = s.launcher.items[idx as usize];
                let _ = ustd::spawn(path, "");
                s.launcher.open = false;
            }
            s.dirty = true;
            return;
        }
        s.launcher.open = false;
    }
    // windows, topmost first
    if let Some(i) = s.win_at(x, y) {
        let id = s.wins[i].id;
        focus_raise(s, id);
        let w = s.win_mut(id).unwrap();
        let rel_y = y - w.y;
        let rel_x = x - w.x;
        if w.deco() && rel_y < TITLE_H as i32 + BORDER_W as i32 {
            // caption buttons: [close][max][min] on right
            let bx = w.w - BORDER_W as i32 - BTN_SZ;
            if rel_x >= bx && rel_x < bx + BTN_SZ {
                // close
                close_win(s, id);
                return;
            }
            let bx2 = bx - BTN_SZ - 2;
            if w.resizable() && rel_x >= bx2 && rel_x < bx2 + BTN_SZ {
                toggle_max(s, id);
                return;
            }
            let bx3 = bx2 - BTN_SZ - 2;
            if rel_x >= bx3 && rel_x < bx3 + BTN_SZ {
                if let Some(w) = s.win_mut(id) {
                    w.min = true;
                }
                if s.focus == id {
                    s.focus = top_id(s);
                }
                return;
            }
            // titlebar drag
            s.drag = Some(Drag { win: id, mode: 0, ox: rel_x, oy: rel_y, rx: w.x, ry: w.y, rw: w.w, rh: w.h });
            return;
        }
        // resize border?
        if w.deco() && w.resizable() && (rel_x >= w.w - RESIZE_R || rel_y >= w.h - RESIZE_R) {
            s.drag = Some(Drag { win: id, mode: 1, ox: rel_x, oy: rel_y, rx: w.x, ry: w.y, rw: w.w, rh: w.h });
            return;
        }
        // client area -> forward click
        let ev = EvPointer {
            window_id: id,
            x: x - w.client_x(),
            y: y - w.client_y(),
            buttons: unsafe { BTNS },
            wheel: 0,
            _pad: [0; 2],
        };
        send_ev(w.owner, EV_POINTER, unsafe {
            core::slice::from_raw_parts(&ev as *const _ as *const u8, core::mem::size_of::<EvPointer>())
        });
        return;
    }
}

fn finish_drag(s: &mut S, d: Drag) {
    if d.mode == 0 {
        // move / snap
        let (w, h) = (s.fw, s.fh - TBAR_H);
        let edge_x = d.rx;
        let edge_y = d.ry;
        if let Some(wr) = s.win_mut(d.win) {
            if d.ry <= -SNAP && wr.resizable() {
                // snap top -> maximize
                wr.saved = (wr.x, wr.y, wr.w, wr.h);
                wr.x = 0;
                wr.y = 0;
                wr.w = w;
                wr.h = h;
                wr.maxed = true;
                request_resize(s, d.win);
            } else if edge_x <= -SNAP && wr.resizable() {
                wr.saved = (wr.x, wr.y, wr.w, wr.h);
                wr.x = 0;
                wr.y = 0;
                wr.w = w / 2;
                wr.h = h;
                wr.maxed = true;
                request_resize(s, d.win);
            } else if edge_x + wr.w >= w + SNAP && wr.resizable() {
                wr.saved = (wr.x, wr.y, wr.w, wr.h);
                wr.x = w / 2;
                wr.y = 0;
                wr.w = w / 2;
                wr.h = h;
                wr.maxed = true;
                request_resize(s, d.win);
            } else {
                wr.x = d.rx;
                wr.y = d.ry;
            }
        }
    } else {
        // resize apply
        if let Some(wr) = s.win_mut(d.win) {
            wr.w = d.rw.max(160);
            wr.h = d.rh.max(80);
        }
        request_resize(s, d.win);
    }
}

fn request_resize(s: &mut S, id: u32) {
    let (cw, ch, owner) = match s.wins.iter().find(|w| w.id == id) {
        Some(w) => (w.w - if w.deco() { 2 * BORDER_W as i32 } else { 0 }, w.h - if w.deco() { TITLE_H as i32 + 2 * BORDER_W as i32 } else { 0 }, w.owner),
        None => return,
    };
    let shm = ustd::shm_create((cw * ch * 4) as usize).unwrap_or(0);
    if shm == 0 {
        return;
    }
    if let Some(w) = s.win_mut(id) {
        w.pending_shm = shm;
    }
    let ev = EvResizeReq { window_id: id, w: cw as u32, h: ch as u32, shm_id: shm };
    send_ev(owner, EV_RESIZE_REQ, unsafe {
        core::slice::from_raw_parts(&ev as *const _ as *const u8, core::mem::size_of::<EvResizeReq>())
    });
}

fn toggle_max(s: &mut S, id: u32) {
    let (w, h) = (s.fw, s.fh - TBAR_H);
    let mut resized = false;
    if let Some(wr) = s.win_mut(id) {
        if wr.maxed {
            let (sx, sy, sw, sh) = wr.saved;
            wr.x = sx;
            wr.y = sy;
            wr.w = sw;
            wr.h = sh;
            wr.maxed = false;
            resized = true;
        } else {
            wr.saved = (wr.x, wr.y, wr.w, wr.h);
            wr.x = 0;
            wr.y = 0;
            wr.w = w;
            wr.h = h;
            wr.maxed = true;
            resized = true;
        }
    }
    if resized {
        request_resize(s, id);
    }
}

fn focus_raise(s: &mut S, id: u32) {
    if let Some(i) = s.win_idx(id) {
        if i + 1 != s.wins.len() {
            let w = s.wins.remove(i);
            s.wins.push(w);
        }
    }
    if s.focus != id {
        if let Some(old) = s.wins.iter().find(|w| w.id == s.focus) {
            let ev = EvFocus { window_id: old.id, focused: 0, _pad: [0; 3] };
            send_ev(old.owner, EV_FOCUS, unsafe {
                core::slice::from_raw_parts(&ev as *const _ as *const u8, core::mem::size_of::<EvFocus>())
            });
        }
        s.focus = id;
        if let Some(w) = s.wins.iter().find(|w| w.id == id) {
            let ev = EvFocus { window_id: id, focused: 1, _pad: [0; 3] };
            send_ev(w.owner, EV_FOCUS, unsafe {
                core::slice::from_raw_parts(&ev as *const _ as *const u8, core::mem::size_of::<EvFocus>())
            });
        }
    }
}

fn top_id(s: &S) -> u32 {
    s.wins
        .iter()
        .rev()
        .find(|w| w.ws == s.workspace && !w.min)
        .map(|w| w.id)
        .unwrap_or(0)
}

/// Remove windows whose owning app died (port freed by kernel teardown).
fn reap_dead(s: &mut S) {
    let mut i = 0;
    while i < s.wins.len() {
        if ustd::ipc_owner(s.wins[i].owner) == 0 {
            let w = s.wins.remove(i);
            if w.shm_id != 0 {
                ustd::shm_drop(w.shm_id);
            }
            if s.focus == w.id {
                s.focus = top_id(s);
            }
            s.dirty = true;
        } else {
            i += 1;
        }
    }
}

fn close_win(s: &mut S, id: u32) {
    if let Some(i) = s.win_idx(id) {
        let (wx, wy, ww, wh) = (s.wins[i].x, s.wins[i].y, s.wins[i].w, s.wins[i].h);
        let w = s.wins.remove(i);
        // tell the app to exit gracefully — it may ignore and keep running headless
        send_ev(w.owner, EV_CLOSE, &id.to_le_bytes());
        if w.shm_id != 0 {
            ustd::shm_drop(w.shm_id);
        }
        if s.focus == id {
            s.focus = top_id(s);
        }
        // repaint the vacated rect + the newly focused window's deco —
        // without this the closed window's pixels ghost until an
        // unrelated composite (x-close never marked anything dirty)
        dmg(s, wx, wy, ww, wh);
        if let Some(nf) = s
            .wins
            .iter()
            .find(|w| w.id == s.focus && w.ws == s.workspace && !w.min)
            .map(|w| (w.x, w.y, w.w, w.h))
        {
            dmg(s, nf.0, nf.1, nf.2, nf.3);
        }
    }
}

// ---- window requests ---------------------------------------------------------
fn handle_req(s: &mut S, msg: &[u8]) {
    if msg.len() < 8 {
        return;
    }
    let kind = u16::from_le_bytes([msg[0], msg[1]]);
    let len = u16::from_le_bytes([msg[2], msg[3]]) as usize;
    let reply = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let pl = &msg[8..(8 + len).min(msg.len())];

    match kind {
        REQ_CREATE_WIN => {
            if pl.len() < core::mem::size_of::<ReqCreateWin>() {
                return;
            }
            let r: ReqCreateWin = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
            let (cw, ch) = (r.w as i32, r.h as i32);
            let Some(shm) = ustd::shm_create((cw * ch * 4) as usize) else {
                send_ev(reply, RSP_ERROR, &0u32.to_le_bytes());
                return;
            };
            let Some(ptr) = ustd::shm_map(shm) else {
                send_ev(reply, RSP_ERROR, &1u32.to_le_bytes());
                return;
            };
            let ptr = ptr as *mut u32;
            let id = s.next_id;
            s.next_id += 1;
            let deco = r.flags & WIN_DECORATE != 0;
            let ow = cw + if deco { 2 * BORDER_W as i32 } else { 0 };
            let oh = ch + if deco { TITLE_H as i32 + 2 * BORDER_W as i32 } else { 0 };
            let mut title = String::new();
            for &b in r.title.iter() {
                if b == 0 {
                    break;
                }
                title.push(b as char);
            }
            let w = Win {
                id,
                owner: reply,
                x: r.x,
                y: r.y,
                w: ow,
                h: oh,
                shm_id: shm,
                ptr,
                stride: cw,
                cw,
                ch,
                title,
                flags: r.flags,
                min: false,
                maxed: false,
                saved: (0, 0, 0, 0),
                ws: s.workspace,
                pending_shm: 0,
                pid: 0,
            };
            s.wins.push(w);
            // Reply before EV_FOCUS: the client's create_window polls this
            // port for RSP_WIN_CREATED and must see it first.
            let rsp = RspWinCreated { window_id: id, shm_id: shm, w: r.w, h: r.h, stride: r.w };
            send_ev(reply, RSP_WIN_CREATED, unsafe {
                core::slice::from_raw_parts(&rsp as *const _ as *const u8, core::mem::size_of::<RspWinCreated>())
            });
            focus_raise(s, id);
            s.dirty = true;
        }
        REQ_PRESENT => {
            if pl.len() < core::mem::size_of::<ReqPresent>() {
                return;
            }
            let r: ReqPresent = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
            if let Some(w) = s.wins.iter().find(|w| w.id == r.window_id) {
                let (wx, wy, ww, wh) = (w.x, w.y, w.w, w.h);
                dmg(s, wx, wy, ww, wh); // damage just this window's rect
            }
        }
        REQ_SET_TITLE => {
            if pl.len() < core::mem::size_of::<ReqSetTitle>() {
                return;
            }
            let r: ReqSetTitle = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
            if let Some(w) = s.win_mut(r.window_id) {
                w.title.clear();
                for &b in r.title.iter() {
                    if b == 0 {
                        break;
                    }
                    w.title.push(b as char);
                }
                s.dirty = true;
            }
        }
        REQ_CLOSE_WIN => {
            if pl.len() >= 4 {
                let id = u32::from_le_bytes([pl[0], pl[1], pl[2], pl[3]]);
                close_win(s, id);
                s.dirty = true;
            }
        }
        REQ_RESIZE_ACK => {
            if pl.len() < core::mem::size_of::<ReqResizeAck>() {
                return;
            }
            let r: ReqResizeAck = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
            if let Some(w) = s.win_mut(r.window_id) {
                if w.pending_shm == r.shm_id {
                    w.shm_id = r.shm_id;
                    if let Some(p) = ustd::shm_map(r.shm_id) {
                        w.ptr = p as *mut u32;
                    }
                    w.stride = r.w as i32;
                    w.cw = r.w as i32;
                    w.ch = r.h as i32;
                    w.pending_shm = 0;
                    s.dirty = true;
                }
            }
        }
        _ => {}
    }
}

// ---- rendering ----------------------------------------------------------------
fn composite(s: &mut S) {
    let fb = s.fb;
    // wallpaper (cached), clipped to fb.clip
    let (cx, cy, cw, ch) = fb.clip;
    let rx0 = cx.max(0);
    let ry0 = cy.max(0);
    let rx1 = (cx + cw).min(s.fw);
    let ry1 = (cy + ch).min(s.fh - TBAR_H);
    let wall_rows = s.wall.len() / s.fw.max(1) as usize;
    if rx1 > rx0 && ry1 > ry0 {
        for y in (ry0 as usize)..wall_rows.min(ry1 as usize) {
            let dst = unsafe { fb.ptr.add(y * fb.stride as usize + rx0 as usize) };
            let src = unsafe { s.wall.as_ptr().add(y * s.fw as usize + rx0 as usize) };
            unsafe { core::ptr::copy_nonoverlapping(src, dst, (rx1 - rx0) as usize) };
        }
    }
    // windows bottom-to-top on this workspace
    for i in 0..s.wins.len() {
        let w = &s.wins[i];
        if w.ws != s.workspace || w.min {
            continue;
        }
        draw_window(s, w);
    }
    draw_taskbar(s);
    if s.launcher.open {
        draw_launcher(s);
    }
    blit_cursor(s, unsafe { MX }, unsafe { MY });
}

fn draw_window(s: &S, w: &Win) {
    let fb = s.fb;
    let focused = w.id == s.focus;
    if w.deco() {
        let ty = w.y;
        // titlebar
        fb.fill(w.x, ty, w.w, TITLE_H as i32 + BORDER_W as i32, if focused { TITLE_ACT } else { TITLE_IDLE });
        // title text
        let ty_text = ty + (TITLE_H as i32 - 16) / 2 + BORDER_W as i32;
        let mut cx = w.x + BORDER_W as i32 + 8;
        for b in w.title.bytes() {
            if cx + 8 > w.x + w.w - (3 * (BTN_SZ + 4)) {
                break;
            }
            fb.glyph(cx, ty_text, b, if focused { TXT } else { DIM }, None);
            cx += 8;
        }
        // buttons: min, max, close
        let btn_y = ty + BORDER_W as i32 + (TITLE_H as i32 - BTN_SZ) / 2;
        let bx = w.x + w.w - BORDER_W as i32 - BTN_SZ;
        fb.fill(bx, btn_y, BTN_SZ, BTN_SZ, if focused { TITLE_ACT } else { TITLE_IDLE });
        fb.border(bx, btn_y, BTN_SZ, BTN_SZ, TBAR_EDGE);
        // X
        let c = bx + BTN_SZ / 2;
        let cy = btn_y + BTN_SZ / 2;
        for d in -4..4 {
            fb.put(c + d, cy + d, TXT);
            fb.put(c + d, cy - d - 1, TXT);
        }
        if w.resizable() {
            let bx2 = bx - BTN_SZ - 2;
            fb.fill(bx2, btn_y, BTN_SZ, BTN_SZ, if focused { TITLE_ACT } else { TITLE_IDLE });
            fb.border(bx2, btn_y, BTN_SZ, BTN_SZ, TBAR_EDGE);
            fb.border(bx2 + 4, btn_y + 4, BTN_SZ - 8, BTN_SZ - 8, TXT);
            let bx3 = bx2 - BTN_SZ - 2;
            fb.fill(bx3, btn_y, BTN_SZ, BTN_SZ, if focused { TITLE_ACT } else { TITLE_IDLE });
            fb.border(bx3, btn_y, BTN_SZ, BTN_SZ, TBAR_EDGE);
            fb.fill(bx3 + 4, btn_y + BTN_SZ - 6, BTN_SZ - 8, 2, TXT);
        }
        // outer border
        fb.fill(w.x, w.y + TITLE_H as i32, w.w, BORDER_W as i32, TBAR_EDGE);
        fb.fill(w.x, w.y + w.h - BORDER_W as i32, w.w, BORDER_W as i32, TBAR_EDGE);
        fb.fill(w.x, w.y + TITLE_H as i32, BORDER_W as i32, w.h - TITLE_H as i32, TBAR_EDGE);
        fb.fill(w.x + w.w - BORDER_W as i32, w.y + TITLE_H as i32, BORDER_W as i32, w.h - TITLE_H as i32, TBAR_EDGE);
    }
    // client surface
    let cx = w.client_x();
    let cy = w.client_y();
    let sw = w.cw;
    let sh = w.ch;
    let (clx, cly, clw, clh) = s.fb.clip;
    let x0 = cx.max(0).max(clx);
    let y0 = cy.max(0).max(cly);
    let x1 = (cx + sw).min(s.fw).min(clx + clw);
    let y1 = (cy + sh).min(s.fh - TBAR_H).min(cly + clh);
    if x1 <= x0 || y1 <= y0 {
        return;
    }
    for yy in y0..y1 {
        let srow = unsafe { w.ptr.add((yy - cy) as usize * w.stride as usize + (x0 - cx) as usize) };
        let drow = unsafe { s.fb.ptr.add(yy as usize * s.fb.stride as usize + x0 as usize) };
        for i in 0..(x1 - x0) as usize {
            unsafe { *drow.add(i) = *srow.add(i) };
        }
    }
    // drag outline (ghost) while resizing
    if let Some(d) = &s.drag {
        if d.win == w.id && d.mode == 1 {
            s.fb.border(d.rx, d.ry, d.rw, d.rh, 0xFF8A8D93);
        }
    }
}

fn draw_taskbar(s: &S) {
    let fb = s.fb;
    let y = s.fh - TBAR_H;
    fb.fill(0, y, s.fw, TBAR_H, TBAR);
    fb.fill(0, y, s.fw, 1, TBAR_EDGE);
    // launcher button
    let lw = 96;
    fb.fill(0, y + 4, lw, TBAR_H - 8, if s.launcher.open { MENU_HOV } else { TBAR });
    fb.border(0, y + 4, lw, TBAR_H - 8, TBAR_EDGE);
    fb.text(14, y + (TBAR_H - 16) / 2, "Cosmos", TXT, None);
    // workspace buttons
    for i in 0..2u32 {
        let bx = 104 + i as i32 * 30;
        fb.fill(bx, y + 4, 26, TBAR_H - 8, if s.workspace == i { MENU_HOV } else { TBAR });
        fb.border(bx, y + 4, 26, TBAR_H - 8, TBAR_EDGE);
        fb.text(bx + 9, y + (TBAR_H - 16) / 2, if i == 0 { "1" } else { "2" }, TXT, None);
    }
    // app buttons for this workspace
    let mut bx = 172;
    for w in s.wins.iter().filter(|w| w.ws == s.workspace) {
        let bw = 132;
        if bx + bw > s.fw - 260 {
            break;
        }
        let active = w.id == s.focus && !w.min;
        fb.fill(bx, y + 4, bw, TBAR_H - 8, if active { MENU_HOV } else { TBAR });
        fb.border(bx, y + 4, bw, TBAR_H - 8, TBAR_EDGE);
        fb.label(bx, y + (TBAR_H - 16) / 2, bw, &w.title, if w.min { DIM } else { TXT });
        bx += bw + 6;
    }
    // clock + mem on the right
    let dt = ustd::datetime();
    let mi = ustd::meminfo();
    let txt = alloc::format!(
        "{:02}:{:02}:{:02}  {}MiB/{}MiB",
        dt.hour,
        dt.minute,
        dt.second,
        mi.used_kb / 1024,
        mi.total_kb / 1024
    );
    let tw = Canvas::text_w(&txt);
    fb.text(s.fw - tw - 12, y + (TBAR_H - 16) / 2, &txt, DIM, None);
}

fn draw_launcher(s: &S) {
    let fb = s.fb;
    let mw = 220;
    let mh = s.launcher.items.len() as i32 * 30 + 8;
    let my = s.fh - TBAR_H - mh;
    fb.fill(0, my, mw, mh, MENU_BG);
    fb.border(0, my, mw, mh, TBAR_EDGE);
    for (i, (label, _)) in s.launcher.items.iter().enumerate() {
        let iy = my + 4 + i as i32 * 30;
        if s.launcher.sel == i as i32 {
            fb.fill(2, iy, mw - 4, 28, MENU_HOV);
        }
        fb.text(16, iy + 6, label, TXT, None);
    }
}

fn taskbar_click(s: &mut S, x: i32) {
    if x < 96 {
        s.launcher.open = !s.launcher.open;
        return;
    }
    // workspaces
    for i in 0..2u32 {
        let bx = 104 + i as i32 * 30;
        if x >= bx && x < bx + 26 {
            s.workspace = i;
            s.focus = top_id(s);
            return;
        }
    }
    // app buttons
    let mut bx = 172;
    for w in s.wins.iter().filter(|w| w.ws == s.workspace) {
        let bw = 132;
        if bx + bw > s.fw - 260 {
            break;
        }
        if x >= bx && x < bx + bw {
            let id = w.id;
            if w.min {
                if let Some(wr) = s.win_mut(id) {
                    wr.min = false;
                }
            }
            focus_raise(s, id);
            return;
        }
        bx += bw + 6;
    }
}

// ---- cursor -------------------------------------------------------------------
const CURSOR_BITS: [u16; 16] = [
    0b1000_0000_0000_0000,
    0b1100_0000_0000_0000,
    0b1110_0000_0000_0000,
    0b1111_0000_0000_0000,
    0b1111_1000_0000_0000,
    0b1111_1100_0000_0000,
    0b1111_1110_0000_0000,
    0b1111_1111_0000_0000,
    0b1111_1111_1000_0000,
    0b1111_1100_0000_0000,
    0b1110_1110_0000_0000,
    0b1100_0110_0000_0000,
    0b1000_0110_0000_0000,
    0b0000_0011_0000_0000,
    0b0000_0011_0000_0000,
    0b0000_0000_0000_0000,
];

fn blit_cursor(s: &S, x: i32, y: i32) {
    for r in 0..16 {
        for c in 0..16 {
            if CURSOR_BITS[r] & (0x8000 >> c) != 0 {
                s.fb.put(x + c as i32, y + r as i32, CURSOR);
            }
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    main_loop();
}
