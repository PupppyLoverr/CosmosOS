//! cosmos-files: a real file manager over the FAT32 data disk.
//! Click a directory to enter it, ".." to go up; toolbar has New Folder /
//! Delete; selection is real  - Delete acts on the filesystem.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

const ROW_H: i32 = 26;
const SIDE_W: i32 = 0; // no sidebar  - keep chrome minimal

struct Files {
    win: Window,
    c: Canvas,
    cwd: String,
    ents: Vec<shared::DirEntry>,
    sel: i32,
    scroll: i32,
    status: String,
    new_name: String,
    editing: bool,
    rename_from: Option<String>, // F2 rename: full path of the entry being renamed
    dirty: bool,
}

impl Files {
    fn reload(&mut self) {
        self.ents = ustd::readdir(&self.cwd).unwrap_or_default();
        self.ents.sort_by(|a, b| (b.is_dir.cmp(&a.is_dir)).then(a.name.cmp(&b.name)));
        self.sel = -1;
        self.scroll = 0;
        self.dirty = true;
        let t = alloc::format!("Files  - {}", self.cwd);
        self.win.set_title(&t);
    }

    fn entry_name(e: &shared::DirEntry) -> String {
        String::from_utf8_lossy(&e.name[..e.name_len as usize]).into_owned()
    }

    fn row_rect(&self, i: i32) -> (i32, i32, i32) {
        (4, 40 + i * ROW_H - self.scroll, self.c.w as i32 - 8)
    }

    fn redraw(&mut self) {
        let c = self.c;
        c.fill(0, 0, c.w as i32, c.h as i32, draw::PANEL);
        // toolbar
        c.fill(0, 0, c.w as i32, 34, draw::EDGE);
        c.text(10, 9, &alloc::format!("{}  {} items", self.cwd, self.ents.len()), draw::TEXT, None);
        let bw = 96;
        c.fill(c.w as i32 - bw - 8 - bw - 8, 5, bw, 24, draw::PANEL);
        c.border(c.w as i32 - bw - 8 - bw - 8, 5, bw, 24, draw::EDGE);
        c.text(c.w as i32 - bw - 8 - bw - 8 + 8, 9, if self.editing { "* name" } else { "New Folder" }, draw::TEXT, None);
        c.fill(c.w as i32 - bw - 8, 5, bw, 24, draw::PANEL);
        c.border(c.w as i32 - bw - 8, 5, bw, 24, draw::EDGE);
        c.text(c.w as i32 - bw - 8 + 16, 9, "Delete", draw::TEXT, None);
        if self.editing {
            let prompt = if self.rename_from.is_some() { "rename: " } else { "name: " };
            c.text(10 + Canvas::text_w(&alloc::format!("{}  {} items", self.cwd, self.ents.len())) + 16, 9, &alloc::format!("{}{}", prompt, self.new_name), 0xFF7FD08A, None);
            // caret underscore
            c.text(10 + Canvas::text_w(&alloc::format!("{}  {} items", self.cwd, self.ents.len())) + 16 + Canvas::text_w(&alloc::format!("{}{}", prompt, self.new_name)), 9, "_", 0xFF7FD08A, None);
        }
        // list
        let vis = ((c.h as i32 - 44) / ROW_H) as i32;
        let mut i = self.scroll / ROW_H;
        let mut drawn = 0;
        // ".." entry
        if self.cwd != "/" {
            let (rx, ry, _rw) = (4, 40 + drawn * ROW_H - self.scroll, c.w as i32 - 8);
            c.text(rx + 10, ry + 5, "..", draw::DIM, None);
            drawn += 1;
        }
        while i < self.ents.len() as i32 && drawn < vis {
            let e = &self.ents[i as usize];
            let (rx, ry, rw) = self.row_rect(i + if self.cwd != "/" { 1 } else { 0 } - if self.cwd != "/" { 1 } else { 0 });
            let ry = 40 + drawn * ROW_H;
            if i == self.sel {
                c.fill(rx, ry, rw, ROW_H, draw::EDGE);
            }
            let name = Self::entry_name(e);
            if e.is_dir != 0 {
                c.fill(rx + 8, ry + 6, 14, 12, 0xFF3A3D44);
                c.fill(rx + 8, ry + 4, 6, 4, 0xFF3A3D44);
                c.text(rx + 30, ry + 5, &name, draw::TEXT, None);
            } else {
                c.fill(rx + 9, ry + 4, 12, 15, 0xFF303237);
                c.text(rx + 30, ry + 5, &name, draw::DIM, None);
                c.text(rx + rw - 110, ry + 5, &alloc::format!("{} B", e.size), draw::DIM, None);
            }
            i += 1;
            drawn += 1;
        }
        // status
        c.fill(0, c.h as i32 - 22, c.w as i32, 22, draw::EDGE);
        c.text(10, c.h as i32 - 19, &self.status, draw::DIM, None);
        self.win.present_all();
    }

    fn click(&mut self, x: i32, y: i32, buttons: u8) {
        if buttons & 1 == 0 {
            return;
        }
        let w = self.c.w as i32;
        let bw = 96;
        if y < 34 {
            if x >= w - bw * 2 - 16 && x < w - bw - 8 {
                // new folder: enter name-editing mode
                self.editing = true;
                self.rename_from = None;
                self.new_name.clear();
                self.status = String::from("type folder name, Enter to create");
            } else if x >= w - bw - 8 {
                // delete selected
                if self.sel >= 0 && (self.sel as usize) < self.ents.len() {
                    let name = Self::entry_name(&self.ents[self.sel as usize]);
                    let path = alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, name);
                    match ustd::remove(&path) {
                        Ok(_) => {
                            self.status = alloc::format!("deleted {}", name);
                            self.reload();
                        }
                        Err(e) => self.status = alloc::format!("delete failed: {}", e),
                    }
                } else {
                    self.status = String::from("nothing selected");
                }
            }
            self.dirty = true;
            return;
        }
        // list
        let row = (y - 40 + self.scroll) / ROW_H;
        let has_up = self.cwd != "/";
        if row == 0 && has_up {
            // go up
            let mut parts: Vec<&str> = self.cwd.split('/').filter(|s| !s.is_empty()).collect();
            parts.pop();
            self.cwd = alloc::format!("/{}", parts.join("/"));
            if self.cwd.is_empty() {
                self.cwd = String::from("/");
            }
            self.reload();
            return;
        }
        let idx = row - if has_up { 1 } else { 0 };
        if idx >= 0 && (idx as usize) < self.ents.len() {
            let i = idx as usize;
            if self.sel == i as i32 && self.ents[i].is_dir != 0 {
                // second click on a dir = enter it
                let name = Self::entry_name(&self.ents[i]);
                self.cwd = alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, name);
                self.reload();
                return;
            }
            if self.sel == i as i32 && self.ents[i].is_dir == 0 {
                // second click on a file = open it in the editor
                self.open_selected();
                return;
            }
            self.sel = i as i32;
            let e = &self.ents[i];
            self.status = alloc::format!("{} {} B   (F2 rename, Del delete)", Self::entry_name(e), e.size);
            self.dirty = true;
        }
    }

    fn open_selected(&mut self) {
        let i = self.sel as usize;
        let name = Self::entry_name(&self.ents[i]);
        let path = alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, name);
        match ustd::spawn("/bin/cosmos-editor", &path) {
            Ok(_) => self.status = alloc::format!("opened {}", name),
            Err(_) => self.status = alloc::format!("spawn failed"),
        }
        self.dirty = true;
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        if self.editing {
            if k.key == KeyCode::Char as u32 {
                self.new_name.push(k.chr as char);
            } else if k.key == KeyCode::Backspace as u32 {
                self.new_name.pop();
            } else if k.key == KeyCode::Enter as u32 {
                if !self.new_name.is_empty() {
                    let newp = alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, self.new_name);
                    if let Some(oldp) = self.rename_from.take() {
                        match ustd::rename(&oldp, &newp) {
                            Ok(_) => {
                                self.status = alloc::format!("renamed to {}", self.new_name);
                                self.editing = false;
                                self.reload();
                            }
                            Err(e) => self.status = alloc::format!("rename failed: {}", e),
                        }
                    } else {
                        match ustd::mkdir(&newp) {
                            Ok(_) => {
                                self.status = alloc::format!("created {}", self.new_name);
                                self.editing = false;
                                self.reload();
                            }
                            Err(e) => self.status = alloc::format!("mkdir failed: {}", e),
                        }
                    }
                }
            } else if k.key == KeyCode::Escape as u32 {
                self.editing = false;
                self.rename_from = None;
            }
            self.dirty = true;
            return;
        }
        match k.key as u32 {
            x if x == KeyCode::Down as u32 => {
                self.sel = (self.sel + 1).min(self.ents.len() as i32 - 1);
            }
            x if x == KeyCode::Up as u32 => {
                self.sel = (self.sel - 1).max(-1);
            }
            x if x == KeyCode::Enter as u32 => {
                if self.sel >= 0 {
                    let i = self.sel as usize;
                    if self.ents[i].is_dir != 0 {
                        let name = Self::entry_name(&self.ents[i]);
                        self.cwd = alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, name);
                        self.reload();
                        return;
                    }
                    self.open_selected();
                }
            }
            x if x == KeyCode::Delete as u32 => {
                if self.sel >= 0 && (self.sel as usize) < self.ents.len() {
                    let name = Self::entry_name(&self.ents[self.sel as usize]);
                    let path = alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, name);
                    match ustd::remove(&path) {
                        Ok(_) => {
                            self.status = alloc::format!("deleted {}", name);
                            self.reload();
                        }
                        Err(e) => self.status = alloc::format!("delete failed: {}", e),
                    }
                } else {
                    self.status = String::from("nothing selected");
                }
            }
            x if x == KeyCode::F2 as u32 => {
                if self.sel >= 0 && (self.sel as usize) < self.ents.len() {
                    let name = Self::entry_name(&self.ents[self.sel as usize]);
                    self.rename_from = Some(alloc::format!("{}{}{}", self.cwd, if self.cwd.ends_with('/') { "" } else { "/" }, name));
                    self.editing = true;
                    self.new_name = name.clone();
                    self.status = alloc::format!("rename {}", name);
                } else {
                    self.status = String::from("nothing selected");
                }
            }
            x if x == KeyCode::Backspace as u32 => {
                if self.cwd != "/" {
                    let mut parts: Vec<&str> = self.cwd.split('/').filter(|s| !s.is_empty()).collect();
                    parts.pop();
                    self.cwd = alloc::format!("/{}", parts.join("/"));
                    if self.cwd.is_empty() {
                        self.cwd = String::from("/");
                    }
                    self.reload();
                    return;
                }
            }
            _ => {}
        }
        self.dirty = true;
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[files] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let win = wm
        .create_window(120, 90, 620, 460, WIN_DECORATE | WIN_RESIZABLE, "Files  - /")
        .expect("create window");
    let mut f = Files {
        win,
        c: win.canvas(),
        cwd: String::from("/"),
        ents: Vec::new(),
        sel: -1,
        scroll: 0,
        status: String::new(),
        new_name: String::new(),
        editing: false,
        rename_from: None,
        dirty: true,
    };
    f.reload();
    loop {
        match wm.next_event(250) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                f.on_key(&k);
            }
            Some((EV_POINTER, pl)) if pl.len() >= 16 => {
                let p: EvPointer = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if p.wheel != 0 {
                    // wheel: >0 up, <0 down — 3 rows per tick
                    let vis = ((f.c.h as i32 - 44) / ROW_H).max(1);
                    let rows = f.ents.len() as i32 + if f.cwd != "/" { 1 } else { 0 };
                    let max = (rows - vis).max(0) * ROW_H;
                    if p.wheel > 0 {
                        f.scroll = (f.scroll - 3 * ROW_H).max(0);
                    } else {
                        f.scroll = (f.scroll + 3 * ROW_H).min(max);
                    }
                    f.dirty = true;
                }
                f.click(p.x, p.y, p.buttons);
            }
            Some((EV_CLOSE, _)) => return 0,
            // regaining focus = a good moment to pick up fs changes made
            // elsewhere (e.g. files created in the terminal)
            Some((EV_FOCUS, pl)) if pl.len() >= 8 => {
                let e: EvFocus = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if e.focused != 0 {
                    f.reload();
                }
            }
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if f.win.remap(r.shm_id, r.w, r.h) {
                    f.c = f.win.canvas();
                    f.win.resize_ack(r.shm_id, r.w, r.h);
                    f.dirty = true;
                }
            }
            _ => {}
        }
        if f.dirty {
            f.dirty = false;
            f.redraw();
        }
    }
}
