//! cosmos-editor: a real text editor  - open, edit, save (F2 or Ctrl+S), type
//! directly into the file. Persisted to the FAT32 disk.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use shared::*;
use ustd::draw::{self, Canvas};
use ustd::wm::{self, Window};
use ustd::println;

struct Editor {
    win: Window,
    c: Canvas,
    path: String,
    text: String,
    cx: usize, // caret byte idx
    sel: Option<(usize, usize)>, // selected byte range [start,end)
    find_q: Option<String>, // Ctrl-F: live find query (None = not finding)
    rep_q: Option<String>,  // Ctrl-H phase 1: typing the search term
    rep_with: Option<String>, // Ctrl-H phase 2: search locked, typing replacement
    goto_q: Option<String>, // Ctrl-G: line-number prompt
    saveas_q: Option<String>, // Ctrl-Shift-S: save-as path prompt
    open_q: Option<String>,   // Ctrl-O: open-file path prompt
    open_confirm: bool,       // dirty-buffer: Ctrl-O pressed once (confirm pending)
    new_confirm: bool,        // dirty-buffer: Ctrl-N pressed once (confirm pending)
    close_confirm: bool,      // dirty-buffer: Ctrl-W pressed once (confirm pending)
    scroll: usize, // first visible line
    dirty_text: bool,
    dirty_ui: bool,
    status: String,
    drag_anchor: Option<usize>, // byte idx where the mouse press started
    ldown: bool,
    undo: Vec<(usize, String, String)>, // (pos, deleted, inserted) inverse ops
    redo: Vec<(usize, String, String)>,
    ins_tail: Option<usize>,            // running typed-insert run start (coalescing)
}

impl Editor {
    /// Record an edit's inverse for Ctrl-Z: the op deleted `del` and
    /// inserted `ins` at byte `pos`. Any new edit clears the redo stack.
    fn rec(&mut self, pos: usize, del: String, ins: String) {
        if self.undo.len() >= 200 {
            self.undo.remove(0);
        }
        self.undo.push((pos, del, ins));
        self.redo.clear();
    }

    /// Typed-char inserts coalesce into the top undo op when contiguous.
    fn rec_ins(&mut self, pos: usize, s: &str) {
        if self.ins_tail == Some(pos) {
            if let Some(last) = self.undo.last_mut() {
                last.2.push_str(s);
                self.ins_tail = Some(pos + s.len());
                return;
            }
        }
        self.rec(pos, String::new(), String::from(s));
        self.ins_tail = Some(pos + s.len());
    }

    fn do_undo(&mut self) {
        match self.undo.pop() {
            Some((pos, del, ins)) => {
                self.text
                    .replace_range(pos..pos + ins.len(), "");
                if !del.is_empty() {
                    self.text.insert_str(pos, &del);
                }
                self.cx = pos + del.len();
                self.redo.push((pos, del, ins));
                self.sel = None;
                self.ins_tail = None;
                self.dirty_text = true;
                self.dirty_ui = true;
            }
            None => {
                self.status = String::from("nothing to undo");
                self.dirty_ui = true;
            }
        }
    }

    fn do_redo(&mut self) {
        match self.redo.pop() {
            Some((pos, del, ins)) => {
                self.text
                    .replace_range(pos..pos + del.len(), "");
                if !ins.is_empty() {
                    self.text.insert_str(pos, &ins);
                }
                self.cx = pos + ins.len();
                self.undo.push((pos, del, ins));
                self.sel = None;
                self.ins_tail = None;
                self.dirty_text = true;
                self.dirty_ui = true;
            }
            None => {
                self.status = String::from("nothing to redo");
                self.dirty_ui = true;
            }
        }
    }

    fn lines(&self) -> Vec<&str> {
        self.text.split('\n').collect()
    }

    fn caret_rc(&self) -> (usize, usize) {
        // byte idx -> (row, col)
        let mut r = 0usize;
        let mut c = 0usize;
        for (i, b) in self.text.bytes().enumerate() {
            if i == self.cx {
                break;
            }
            if b == b'\n' {
                r += 1;
                c = 0;
            } else {
                c += 1;
            }
        }
        (r, c)
    }

    fn idx_of(&self, row: usize, col: usize) -> usize {
        let mut r = 0;
        let mut c = 0;
        for (i, b) in self.text.bytes().enumerate() {
            if r == row && c == col {
                return i;
            }
            if b == b'\n' {
                r += 1;
                c = 0;
            } else {
                c += 1;
            }
        }
        self.text.len()
    }

    fn redraw(&mut self) {
        let c = self.c;
        c.fill(0, 0, c.w as i32, c.h as i32, draw::BLACK);
        // header
        c.fill(0, 0, c.w as i32, 26, draw::PANEL);
        c.text(8, 5, &alloc::format!("{}{}", self.path, if self.dirty_text { " *" } else { "" }), draw::TEXT, None);
        c.text(c.w as i32 - 296, 5, "Ctrl-S save  Ctrl-F/G find  Ctrl-H replace  Ctrl-D dup", draw::DIM, None); // header hint
        // text area
        let lines = self.lines();
        let vis = ((c.h as i32 - 34) / 16) as usize;
        // selection highlight rects first (under the text)
        if let Some((s0, s1)) = self.sel {
            let mut byte_i = 0usize;
            for (row, l) in lines.iter().enumerate() {
                if row < self.scroll || row >= self.scroll + vis {
                    byte_i += l.len() + 1;
                    continue;
                }
                let line_end = byte_i + l.len() + 1; // +1 for the \n
                let lo = s0.max(byte_i);
                let hi = s1.min(line_end);
                if lo < hi {
                    let x0 = 36 + (lo - byte_i) as i32 * 8;
                    let x1 = 36 + (hi - byte_i).min(l.len()) as i32 * 8;
                    c.fill(x0, 30 + (row - self.scroll) as i32 * 16, x1 - x0 + 8, 16, draw::EDGE);
                }
                byte_i = line_end;
            }
        }
        for (i, l) in lines.iter().skip(self.scroll).take(vis).enumerate() {
            let y = 30 + i as i32 * 16;
            // line numbers
            c.text(4, y, &alloc::format!("{:>3}", self.scroll + i + 1), draw::DIM, None);
            c.text(36, y, l, draw::TEXT, None);
        }
        // caret
        let (r, col) = self.caret_rc();
        if r >= self.scroll {
            c.fill(36 + col as i32 * 8, 30 + (r - self.scroll) as i32 * 16, 2, 16, draw::ACCENT);
        }
        // status bar (becomes the find field while Ctrl-F is active)
        c.fill(0, c.h as i32 - 22, c.w as i32, 22, draw::PANEL);
        if let Some(q) = &self.rep_q {
            c.text(8, c.h as i32 - 19, &alloc::format!("replace: {}_", q), draw::TEXT, None);
        } else if let Some(q) = &self.rep_with {
            c.text(8, c.h as i32 - 19, &alloc::format!("with: {}_", q), draw::TEXT, None);
        } else if let Some(q) = &self.find_q {
            c.text(8, c.h as i32 - 19, &alloc::format!("find: {}_", q), draw::TEXT, None);
        } else if let Some(q) = &self.goto_q {
            c.text(8, c.h as i32 - 19, &alloc::format!("goto line: {}_", q), draw::TEXT, None);
        } else if let Some(q) = &self.saveas_q {
            c.text(8, c.h as i32 - 19, &alloc::format!("save as: {}_", q), draw::TEXT, None);
        } else if let Some(q) = &self.open_q {
            c.text(8, c.h as i32 - 19, &alloc::format!("open: {}_", q), draw::TEXT, None);
        } else {
            c.text(8, c.h as i32 - 19, &alloc::format!("{}:{}  {} bytes  {}", r + 1, col + 1, self.text.len(), self.status), draw::DIM, None);
        }
        self.win.present_all();
    }

    fn ensure_caret_visible(&mut self) {
        let (r, _) = self.caret_rc();
        let vis = ((self.c.h as i32 - 34) / 16) as usize;
        if r < self.scroll {
            self.scroll = r;
        } else if r >= self.scroll + vis {
            self.scroll = r + 1 - vis;
        }
    }

    fn save(&mut self) {
        match ustd::write_all(&self.path, self.text.as_bytes()) {
            Ok(_) => {
                self.dirty_text = false;
                self.status = alloc::format!("saved {}", self.path);
                self.refresh_title();
            }
            Err(e) => self.status = alloc::format!("save failed: {}", e),
        }
        self.dirty_ui = true;
    }

    /// Load `path` into the buffer (Ctrl-O): replaces the document.
    fn load(&mut self, path: &str) {
        match ustd::read_all(path) {
            Ok(d) => {
                self.text = String::from_utf8_lossy(&d).into_owned();
                self.path = String::from(path);
                self.cx = 0;
                self.sel = None;
                self.scroll = 0;
                self.undo.clear();
                self.redo.clear();
                self.ins_tail = None;
                self.dirty_text = false;
                self.status = alloc::format!("opened {} ({}B)", path, d.len());
                self.refresh_title();
            }
            Err(e) => self.status = alloc::format!("open failed: {} ({})", path, e),
        }
        self.dirty_ui = true;
    }

    /// Title shows a * while there are unsaved edits.
    fn refresh_title(&self) {
        self.win.set_title(&alloc::format!(
            "Editor  - {}{}",
            self.path,
            if self.dirty_text { " *" } else { "" }
        ));
    }

    fn on_key(&mut self, k: &EvKey) {
        if k.down == 0 {
            return;
        }
        // the dirty-buffer confirm arms for exactly one chord — any
        // other key disarms it, but bare modifier presses (the Ctrl
        // half of the confirming chord itself) must not
        let is_mod_key = matches!(
            k.key as u32,
            x if x == KeyCode::Super as u32
                || x == KeyCode::Ctrl as u32
                || x == KeyCode::Alt as u32
                || x == KeyCode::Shift as u32
        );
        let is_ctrlo = k.key == KeyCode::Char as u32
            && k.mods & 1 != 0
            && k.chr.to_ascii_lowercase() == b'o';
        if !is_ctrlo && !is_mod_key {
            self.open_confirm = false;
        }
        let is_ctrln = k.key == KeyCode::Char as u32
            && k.mods & 1 != 0
            && k.chr.to_ascii_lowercase() == b'n';
        if !is_ctrln && !is_mod_key {
            self.new_confirm = false;
        }
        let is_ctrlw = k.key == KeyCode::Char as u32
            && k.mods & 1 != 0
            && k.chr.to_ascii_lowercase() == b'w';
        if !is_ctrlw && !is_mod_key {
            self.close_confirm = false;
        }
        // save-as mode: keys go to the path prompt
        if self.saveas_q.is_some() {
            match k.key as u32 {
                x if x == KeyCode::Char as u32 => {
                    self.saveas_q.as_mut().unwrap().push(k.chr as char);
                }
                x if x == KeyCode::Backspace as u32 => {
                    self.saveas_q.as_mut().unwrap().pop();
                }
                x if x == KeyCode::Enter as u32 => {
                    let q = core::mem::take(&mut self.saveas_q).unwrap_or_default();
                    let q = q.trim();
                    if !q.is_empty() {
                        self.path = String::from(q);
                        self.save();
                    }
                }
                x if x == KeyCode::Escape as u32 => self.saveas_q = None,
                _ => {}
            }
            self.dirty_ui = true;
            return;
        }
        // open-file mode: keys go to the path prompt
        if self.open_q.is_some() {
            match k.key as u32 {
                x if x == KeyCode::Char as u32 => {
                    self.open_q.as_mut().unwrap().push(k.chr as char);
                }
                x if x == KeyCode::Backspace as u32 => {
                    self.open_q.as_mut().unwrap().pop();
                }
                x if x == KeyCode::Enter as u32 => {
                    let q = core::mem::take(&mut self.open_q).unwrap_or_default();
                    let q = q.trim();
                    if !q.is_empty() {
                        self.load(q);
                    }
                }
                x if x == KeyCode::Escape as u32 => self.open_q = None,
                _ => {}
            }
            self.dirty_ui = true;
            return;
        }
        // goto-line mode: digits go to the line prompt
        if self.goto_q.is_some() {
            match k.key as u32 {
                x if x == KeyCode::Char as u32 => {
                    if k.chr.is_ascii_digit() {
                        self.goto_q.as_mut().unwrap().push(k.chr as char);
                    }
                }
                x if x == KeyCode::Backspace as u32 => {
                    self.goto_q.as_mut().unwrap().pop();
                }
                x if x == KeyCode::Enter as u32 => {
                    let q = core::mem::take(&mut self.goto_q).unwrap_or_default();
                    if let Ok(n) = q.parse::<usize>() {
                        let rows = self.lines().len();
                        let row = n.saturating_sub(1).min(rows.saturating_sub(1));
                        self.cx = self.idx_of(row, 0);
                        self.sel = None;
                        self.ensure_caret_visible();
                        self.status = alloc::format!("line {}", row + 1);
                    }
                }
                x if x == KeyCode::Escape as u32 => self.goto_q = None,
                _ => {}
            }
            self.dirty_ui = true;
            return;
        }
        // replace mode: Enter locks the search term, second Enter runs
        // a real replace-all (each replacement recorded for undo)
        if self.rep_q.is_some() || self.rep_with.is_some() {
            match k.key as u32 {
                x if x == KeyCode::Escape as u32 => {
                    self.rep_q = None;
                    self.rep_with = None;
                    self.status = String::from("replace cancelled");
                }
                x if x == KeyCode::Backspace as u32 => {
                    if let Some(w) = &mut self.rep_with {
                        w.pop();
                    } else if let Some(q) = &mut self.rep_q {
                        q.pop();
                    }
                }
                x if x == KeyCode::Char as u32 => {
                    if let Some(w) = &mut self.rep_with {
                        w.push(k.chr as char);
                    } else if let Some(q) = &mut self.rep_q {
                        q.push(k.chr.to_ascii_lowercase() as char);
                    }
                }
                x if x == KeyCode::Enter as u32 => {
                    if self.rep_with.is_some() {
                        // phase 2: run the replace-all, clear both fields
                        let q = self.rep_q.take().unwrap_or_default();
                        let w = self.rep_with.take().unwrap_or_default();
                        if !q.is_empty() {
                            let hay = self.text.to_lowercase();
                            let mut pos = Vec::new();
                            let mut from = 0usize;
                            while let Some(i) = hay[from..].find(&q) {
                                pos.push(from + i);
                                from += i + q.len();
                            }
                            let n = pos.len();
                            // apply back-to-front so earlier offsets stay valid
                            for &i in pos.iter().rev() {
                                let del = String::from(&self.text[i..i + q.len()]);
                                self.rec(i, del, String::from(w.as_str()));
                                self.text.replace_range(i..i + q.len(), &w);
                            }
                            self.ins_tail = None;
                            self.dirty_text = true;
                            self.dirty_ui = true;
                            self.status = alloc::format!("replaced {} of '{}'", n, q);
                        }
                    } else {
                        // phase 1 done: keep the query in rep_q, arm rep_with
                        match &self.rep_q {
                            Some(q) if !q.is_empty() => {
                                self.rep_with = Some(String::new());
                            }
                            _ => {
                                self.rep_q = None;
                                self.status = String::from("empty search");
                            }
                        }
                    }
                }
                _ => {}
            }
            self.dirty_ui = true;
            return;
        }
        // find mode: keys go to the query
        if self.find_q.is_some() {
            match k.key as u32 {
                x if x == KeyCode::Char as u32 => {
                    self.find_q.as_mut().unwrap().push(k.chr.to_ascii_lowercase() as char);
                }
                x if x == KeyCode::Backspace as u32 => {
                    self.find_q.as_mut().unwrap().pop();
                }
                x if x == KeyCode::Enter as u32 => {
                    let q = core::mem::take(&mut self.find_q).unwrap_or_default();
                    if !q.is_empty() {
                        // first match at/after the caret, wrapping around
                        let hay = self.text.to_lowercase();
                        let hit = hay[self.cx..].find(&q).map(|i| self.cx + i)
                            .or_else(|| hay[..self.cx].find(&q));
                        match hit {
                            Some(i) => {
                                self.cx = i;
                                self.sel = Some((i, i + q.len()));
                                self.ensure_caret_visible();
                                self.status = alloc::format!("found '{}':", q);
                            }
                            None => self.status = alloc::format!("no match for '{}'", q),
                        }
                    }
                }
                x if x == KeyCode::Escape as u32 => self.find_q = None,
                _ => {}
            }
            self.dirty_ui = true;
            return;
        }
        // ctrl chords: save + clipboard
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 {
            match k.chr.to_ascii_lowercase() {
                b'h' => {
                    self.rep_q = Some(String::new());
                    self.dirty_ui = true;
                    return;
                }
                b'f' => {
                    self.find_q = Some(String::new());
                    self.dirty_ui = true;
                    return;
                }
                b'd' => {
                    // Ctrl-D: duplicate the current line below itself
                    let (r, _c) = self.caret_rc();
                    let lines = self.lines();
                    if r < lines.len() {
                        let start = self.idx_of(r, 0);
                        let mut end = start + lines[r].len();
                        if end < self.text.len() {
                            end += 1; // include the newline when present
                        }
                        let chunk = String::from(&self.text[start..end]);
                        if chunk.ends_with('\n') {
                            self.rec(start, String::new(), chunk.clone());
                            self.text.insert_str(start, &chunk);
                            self.cx = start + chunk.len();
                        } else {
                            // last line has no trailing newline — append
                            // "\n<line>" after it instead of gluing text
                            let dup = alloc::format!("\n{}", chunk);
                            self.rec(end, String::new(), dup.clone());
                            self.text.insert_str(end, &dup);
                            self.cx = end + 1;
                        }
                        self.status = String::from("line duplicated");
                        self.dirty_text = true;
                        self.dirty_ui = true;
                    }
                    return;
                }
                b'g' => {
                    self.goto_q = Some(String::new());
                    self.dirty_ui = true;
                    return;
                }
                b'o' => {
                    // Ctrl-O: open file — a dirty buffer needs one more
                    // Ctrl-O to confirm discarding the edits
                    if self.dirty_text && !self.open_confirm {
                        self.open_confirm = true;
                        self.status = String::from("unsaved changes - Ctrl-O again to discard");
                    } else {
                        self.open_confirm = false;
                        self.open_q = Some(self.path.clone());
                    }
                    self.dirty_ui = true;
                    return;
                }
                b'n' => {
                    // Ctrl-N: new buffer — same dirty guard as Ctrl-O
                    if self.dirty_text && !self.new_confirm {
                        self.new_confirm = true;
                        self.status = String::from("unsaved changes - Ctrl-N again to discard");
                    } else {
                        self.new_confirm = false;
                        self.text.clear();
                        self.cx = 0;
                        self.scroll = 0;
                        self.sel = None;
                        self.undo.clear();
                        self.redo.clear();
                        self.path = String::from("/untitled.txt");
                        self.dirty_text = false;
                        self.status = String::from("new buffer");
                        self.dirty_ui = true;
                    }
                    return;
                }
                _ => {}
            }
        }
        // Ctrl+Home/End: document start/end
        if k.mods & 1 != 0 && k.key == KeyCode::Home as u32 {
            self.cx = 0;
            self.ensure_caret_visible();
            self.dirty_ui = true;
            return;
        }
        if k.mods & 1 != 0 && k.key == KeyCode::End as u32 {
            self.cx = self.text.len();
            self.ensure_caret_visible();
            self.dirty_ui = true;
            return;
        }
        // Ctrl+W closes the window (double-press when the buffer is dirty)
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 && k.chr.to_ascii_lowercase() == b'w' {
            if self.dirty_text && !self.close_confirm {
                self.close_confirm = true;
                self.status = String::from("unsaved changes - Ctrl-W again to close");
                self.dirty_ui = true;
                return;
            }
            self.win.close();
            return;
        }
        if k.key == KeyCode::Char as u32 && k.mods & 1 != 0 {
            match k.chr.to_ascii_lowercase() {
                b's' if k.mods & 2 != 0 => {
                    // Ctrl-Shift-S: save as...
                    self.saveas_q = Some(self.path.clone());
                    self.dirty_ui = true;
                }
                b's' => self.save(),
                b'a' => {
                    self.sel = if self.text.is_empty() { None } else { Some((0, self.text.len())) };
                }
                b'c' | b'x' => {
                    if let Some((s0, s1)) = self.sel {
                        ustd::clip_set(&self.text.as_bytes()[s0..s1]);
                        self.status = alloc::format!("{}d {}B", if k.chr == b'c' || k.chr == b'C' { "copie" } else { "cut" }, s1 - s0);
                        if k.chr == b'x' || k.chr == b'X' {
                            let del = String::from(&self.text[s0..s1]);
                            self.text.replace_range(s0..s1, "");
                            self.cx = s0;
                            self.sel = None;
                            self.rec(s0, del, String::new());
                            self.ins_tail = None;
                            self.dirty_text = true;
                        }
                    }
                }
                b'v' => {
                    let d = ustd::clip_get();
                    if !d.is_empty() {
                        let s = String::from_utf8_lossy(&d).into_owned();
                        let (pos, del) = if let Some((s0, s1)) = self.sel.take() {
                            let d = String::from(&self.text[s0..s1]);
                            self.text.replace_range(s0..s1, "");
                            self.cx = s0;
                            (s0, d)
                        } else {
                            (self.cx, String::new())
                        };
                        self.text.insert_str(self.cx, &s);
                        self.cx += s.len();
                        self.rec(pos, del, s);
                        self.ins_tail = None;
                        self.dirty_text = true;
                    }
                }
                b'z' if k.mods & 2 != 0 => self.do_redo(), // Ctrl-Shift-Z
                b'z' => self.do_undo(),
                b'y' => self.do_redo(),
                _ => {}
            }
            self.dirty_ui = true;
            return;
        }
        // selection-aware edit keys
        if let Some((s0, s1)) = self.sel {
            match k.key as u32 {
                x if x == KeyCode::Backspace as u32 || x == KeyCode::Delete as u32 => {
                    let del = String::from(&self.text[s0..s1]);
                    self.text.replace_range(s0..s1, "");
                    self.cx = s0;
                    self.sel = None;
                    self.rec(s0, del, String::new());
                    self.ins_tail = None;
                    self.dirty_text = true;
                    self.dirty_ui = true;
                    return;
                }
                x if x == KeyCode::Ctrl as u32 || x == KeyCode::Shift as u32
                    || x == KeyCode::Alt as u32 || x == KeyCode::Super as u32 => {}
                _ => self.sel = None, // any other key collapses the selection
            }
        }
        match k.key as u32 {
            x if x == KeyCode::Char as u32 => {
                let c = String::from(k.chr as char);
                self.text.insert_str(self.cx, &c);
                self.rec_ins(self.cx, &c);
                self.cx += 1;
                self.dirty_text = true;
            }
            x if x == KeyCode::Enter as u32 => {
                self.text.insert(self.cx, '\n');
                self.rec(self.cx, String::new(), String::from("\n"));
                self.ins_tail = None; // newline breaks the typed-run coalescing
                self.cx += 1;
                self.dirty_text = true;
            }
            x if x == KeyCode::Backspace as u32 => {
                if self.cx > 0 {
                    self.cx -= 1;
                    let del = String::from(self.text.remove(self.cx));
                    self.rec(self.cx, del, String::new());
                    self.ins_tail = None;
                    self.dirty_text = true;
                }
            }
            x if x == KeyCode::Delete as u32 => {
                if self.cx < self.text.len() {
                    let del = String::from(self.text.remove(self.cx));
                    self.rec(self.cx, del, String::new());
                    self.ins_tail = None;
                    self.dirty_text = true;
                }
            }
            x if x == KeyCode::Left as u32 => self.cx = self.cx.saturating_sub(1),
            x if x == KeyCode::Right as u32 => {
                if self.cx < self.text.len() {
                    self.cx += 1;
                }
            }
            x if x == KeyCode::Up as u32 => {
                let (r, c) = self.caret_rc();
                if r > 0 {
                    self.cx = self.idx_of(r - 1, c);
                }
            }
            x if x == KeyCode::Down as u32 => {
                let (r, c) = self.caret_rc();
                if r + 1 < self.lines().len() {
                    self.cx = self.idx_of(r + 1, c);
                }
            }
            x if x == KeyCode::Home as u32 => {
                let (r, _) = self.caret_rc();
                self.cx = self.idx_of(r, 0);
            }
            x if x == KeyCode::End as u32 => {
                let (r, _) = self.caret_rc();
                let eol = self.lines().get(r).map(|l| l.len()).unwrap_or(0);
                self.cx = self.idx_of(r, eol);
            }
            x if x == KeyCode::PageUp as u32 => {
                self.scroll = self.scroll.saturating_sub(10);
            }
            x if x == KeyCode::PageDown as u32 => {
                self.scroll += 10;
            }
            _ => {}
        }
        self.ensure_caret_visible();
        self.refresh_title();
        self.dirty_ui = true;
    }
}

#[unsafe(no_mangle)]
extern "C" fn user_main(args_ptr: u64, args_len: u64) -> i64 {
    println!("[editor] starting");
    let wm = loop {
        match wm::connect() {
            Some(w) => break w,
            None => ustd::sleep_ms(200),
        }
    };
    let args = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize))
    };
    let path = if args.trim().is_empty() { "/notes.txt".to_string() } else { args.trim().to_string() };
    let text = ustd::read_all(&path).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
    let win = wm
        .create_window(200, 60, 640, 480, WIN_DECORATE | WIN_RESIZABLE, &alloc::format!("Editor  - {}", path))
        .expect("create window");
    let mut e = Editor {
        win,
        c: win.canvas(),
        path,
        text,
        cx: 0,
        sel: None,
        find_q: None,
        rep_q: None,
        rep_with: None,
        goto_q: None,
        saveas_q: None,
        open_q: None,
        open_confirm: false,
        new_confirm: false,
        close_confirm: false,
        scroll: 0,
        dirty_text: false,
        dirty_ui: true,
        status: String::from("ready"),
        undo: Vec::new(),
        redo: Vec::new(),
        ins_tail: None,
        drag_anchor: None,
        ldown: false,
    };
    loop {
        match wm.next_event(250) {
            Some((EV_KEY, pl)) if pl.len() >= 12 => {
                let k: EvKey = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                e.on_key(&k);
            }
            Some((EV_POINTER, pl)) if pl.len() >= 16 => {
                let p: EvPointer = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                // wheel scrolls the text view
                if p.wheel > 0 {
                    e.scroll = e.scroll.saturating_sub(3);
                    e.dirty_ui = true;
                } else if p.wheel < 0 {
                    let vis = ((e.c.h as usize - 34) / 16).max(1);
                    let max = e.lines().len().saturating_sub(vis);
                    e.scroll = (e.scroll + 3).min(max);
                    e.dirty_ui = true;
                }
                // left-press inside the text area moves the caret there;
                // holding the button and dragging extends a selection.
                if p.buttons & 1 != 0 && p.y >= 30 && p.x >= 36 {
                    let row = e.scroll + ((p.y - 30) / 16).max(0) as usize;
                    let col = ((p.x - 36) / 8).max(0) as usize;
                    let lines = e.lines();
                    if row < lines.len() {
                        let idx = e.idx_of(row, col.min(lines[row].len()));
                        e.cx = idx;
                        if !e.ldown {
                            e.drag_anchor = Some(idx);
                            e.sel = None;
                        } else if let Some(a) = e.drag_anchor {
                            e.sel = if a == idx { None } else { Some((a.min(idx), a.max(idx))) };
                        }
                        e.ldown = true;
                        e.dirty_ui = true;
                    }
                } else {
                    e.ldown = false;
                    e.drag_anchor = None;
                }
            }
            Some((EV_CLOSE, _)) => return 0,
            Some((EV_RESIZE_REQ, pl)) if pl.len() >= 16 => {
                let r: EvResizeReq = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
                if e.win.remap(r.shm_id, r.w, r.h) {
                    e.c = e.win.canvas();
                    e.win.resize_ack(r.shm_id, r.w, r.h);
                    e.dirty_ui = true;
                }
            }
            _ => {}
        }
        if e.dirty_ui {
            e.dirty_ui = false;
            e.redraw();
        }
    }
}
