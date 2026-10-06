//! Window-server client: connect, create windows, present dirty rects,
//! and receive input/focus/resize events.
use crate::{ipc_connect, ipc_listen, ipc_recv, ipc_send, shm_map};
use alloc::vec::Vec;
use shared::*;

pub struct Wm {
    pub srv: u32, // "cosmos:win" port
    pub ev: u32,  // our reply/event port
}

#[derive(Clone, Copy)]
pub struct Window {
    pub id: u32,
    pub shm_id: u32,
    pub w: u32,
    pub h: u32,
    pub stride: u32,
    pub ptr: *mut u32,
    srv: u32,
    ev: u32,
}

fn pack(kind: u16, reply: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    v.extend_from_slice(&reply.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn send_req(srv: u32, reply: u32, kind: u16, payload: &[u8]) {
    let _ = ipc_send(srv, &pack(kind, reply, payload));
}

/// Connect to the window server. Returns None if it isn't up yet.
pub fn connect() -> Option<Wm> {
    let srv = ipc_connect(WS_PORT)?;
    let ev = ipc_listen("");
    if ev == 0 {
        return None;
    }
    Some(Wm { srv, ev })
}

/// Block until a message arrives on `ev` (returns kind+payload).
pub fn poll(ev: u32, timeout_ms: u64) -> Option<(u16, Vec<u8>)> {
    let mut buf = alloc::vec![0u8; WS_MSG_MAX + 16];
    let n = ipc_recv(ev, &mut buf, timeout_ms).ok()?;
    if n < 8 {
        return None;
    }
    let kind = u16::from_le_bytes([buf[0], buf[1]]);
    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let end = (8 + len).min(n);
    Some((kind, buf[8..end].to_vec()))
}

impl Wm {
    /// Create a decorated window; the server allocates the backing surface.
    pub fn create_window(&self, x: i32, y: i32, w: u32, h: u32, flags: u32, title: &str) -> Option<Window> {
        let mut req = ReqCreateWin { x, y, w, h, flags, title: [0; 48] };
        let n = title.len().min(48);
        req.title[..n].copy_from_slice(&title.as_bytes()[..n]);
        let payload = unsafe {
            core::slice::from_raw_parts(&req as *const _ as *const u8, core::mem::size_of::<ReqCreateWin>())
        };
        send_req(self.srv, self.ev, REQ_CREATE_WIN, payload);
        let (kind, pl) = poll(self.ev, 2000)?;
        if kind != RSP_WIN_CREATED || pl.len() < core::mem::size_of::<RspWinCreated>() {
            return None;
        }
        let rsp: RspWinCreated = unsafe { core::ptr::read_unaligned(pl.as_ptr() as *const _) };
        let ptr = shm_map(rsp.shm_id)? as *mut u32;
        Some(Window {
            id: rsp.window_id,
            shm_id: rsp.shm_id,
            w: rsp.w,
            h: rsp.h,
            stride: rsp.stride,
            ptr,
            srv: self.srv,
            ev: self.ev,
        })
    }

    /// Wait for the next window event; returns the parsed payload.
    pub fn next_event(&self, timeout_ms: u64) -> Option<(u16, Vec<u8>)> {
        poll(self.ev, timeout_ms)
    }
}

impl Window {
    /// Present a dirty rect (window coords). w=0 presents the whole surface.
    pub fn present(&self, x: i32, y: i32, w: u32, h: u32) {
        let r = ReqPresent { window_id: self.id, x, y, w, h };
        let payload = unsafe {
            core::slice::from_raw_parts(&r as *const _ as *const u8, core::mem::size_of::<ReqPresent>())
        };
        send_req(self.srv, self.ev, REQ_PRESENT, payload);
    }

    pub fn present_all(&self) {
        self.present(0, 0, 0, 0);
    }

    pub fn set_title(&self, title: &str) {
        let mut r = ReqSetTitle { window_id: self.id, title: [0; 48] };
        let n = title.len().min(48);
        r.title[..n].copy_from_slice(&title.as_bytes()[..n]);
        let payload = unsafe {
            core::slice::from_raw_parts(&r as *const _ as *const u8, core::mem::size_of::<ReqSetTitle>())
        };
        send_req(self.srv, self.ev, REQ_SET_TITLE, payload);
    }

    /// Ask the server to close this window.
    pub fn close(&self) {
        let payload = self.id.to_le_bytes();
        send_req(self.srv, self.ev, REQ_CLOSE_WIN, &payload);
    }

    /// Ack a resize: we mapped `shm_id` and redrew at (w,h).
    pub fn resize_ack(&self, shm_id: u32, w: u32, h: u32) {
        let r = ReqResizeAck { window_id: self.id, shm_id, w, h };
        let payload = unsafe {
            core::slice::from_raw_parts(&r as *const _ as *const u8, core::mem::size_of::<ReqResizeAck>())
        };
        send_req(self.srv, self.ev, REQ_RESIZE_ACK, payload);
    }

    /// Re-map the surface after a resize request.
    pub fn remap(&mut self, shm_id: u32, w: u32, h: u32) -> bool {
        if let Some(p) = shm_map(shm_id) {
            self.shm_id = shm_id;
            self.w = w;
            self.h = h;
            self.stride = w;
            self.ptr = p as *mut u32;
            true
        } else {
            false
        }
    }

    /// Canvas for drawing into the backing surface.
    pub fn canvas(&self) -> crate::draw::Canvas {
        crate::draw::Canvas::new(self.ptr, self.w, self.h, self.stride)
    }
}
