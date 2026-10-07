//! BSD-style sockets as real fds. `socket(2)` creates a `/socket/{id}`
//! object; `bind`/`connect`/`listen`/`accept` drive the real net stack
//! (udp_open/tcp_open/tcp_listen/tcp_accept); the fd rides the same
//! read/write/poll/epoll/close machinery as pipes and event objects.

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use spin::Mutex;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Udp,
    Tcp,         // connected stream (outbound or accepted)
    TcpListener, // listen()ed stream
}

struct Sock {
    kind: Kind,
    lport: u16,                    // bound or ephemeral local port
    cid: u16,                      // TCP_SOCKS key (== lport for outbound)
    peer: Option<([u8; 4], u16)>,  // connect()ed peer (UDP default dest)
    bound: bool,
}

static NEXT: Mutex<u64> = Mutex::new(1);
static SOCKS: Mutex<BTreeMap<u64, Sock>> = Mutex::new(BTreeMap::new());

pub fn parse(path: &str) -> Option<u64> {
    path.strip_prefix("/socket/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    parse(path).is_some()
}

fn fields(id: u64) -> Option<(Kind, u16, u16, Option<([u8; 4], u16)>)> {
    SOCKS
        .lock()
        .get(&id)
        .map(|s| (s.kind, s.lport, s.cid, s.peer))
}

/// Next ephemeral local port not claimed by this registry or the net stack.
fn ephemeral(m: &BTreeMap<u64, Sock>) -> u16 {
    for i in 0..16384u32 {
        let p = 49152 + i as u16;
        if !m.values().any(|s| s.bound && s.lport == p) && crate::net::lport_free(p) {
            return p;
        }
    }
    0
}

/// Set `id`'s local port to a fresh ephemeral one; returns it (0 = none free).
fn pick_ephemeral(m: &mut BTreeMap<u64, Sock>, id: u64) -> u16 {
    let l = ephemeral(m);
    if l != 0 {
        if let Some(s) = m.get_mut(&id) {
            s.lport = l;
            s.bound = true;
        }
    }
    l
}

/// socket(type): register an unbound socket; returns its fd path.
pub fn create(stream: bool) -> String {
    let mut n = NEXT.lock();
    let id = *n;
    *n += 1;
    SOCKS.lock().insert(
        id,
        Sock {
            kind: if stream { Kind::Tcp } else { Kind::Udp },
            lport: 0,
            cid: 0,
            peer: None,
            bound: false,
        },
    );
    format!("/socket/{}", id)
}

/// bind(fd, port): claim a local port. Err(-98) EADDRINUSE, -9 bad fd.
pub fn bind(id: u64, port: u16) -> i64 {
    if port == 0 {
        return -22;
    }
    let mut m = SOCKS.lock();
    if m.values().any(|s| s.bound && s.lport == port) {
        return -98;
    }
    let Some(s) = m.get_mut(&id) else { return -9 };
    if s.bound {
        return -22; // already bound
    }
    if !crate::net::lport_free(port) {
        return -98;
    }
    if s.kind == Kind::Udp && crate::net::udp_open(port).is_err() {
        return -98;
    }
    // TCP bind just records the port; the net stack claims it at
    // listen()/connect() like POSIX's deferred bind
    s.lport = port;
    s.bound = true;
    0
}

/// connect(fd, ip, port): UDP records the default peer; TCP runs the real
/// SYN handshake on a chosen/bound local port.
pub fn connect(id: u64, rip: [u8; 4], rport: u16) -> i64 {
    let (kind, lp) = {
        let mut m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return -9 };
        if s.peer.is_some() {
            return -106; // EISCONN
        }
        let kind = s.kind;
        let mut lp = s.lport;
        match kind {
            Kind::TcpListener => return -22,
            Kind::Udp => {
                m.get_mut(&id).unwrap().peer = Some((rip, rport));
                return 0;
            }
            Kind::Tcp => {
                if lp == 0 {
                    lp = pick_ephemeral(&mut m, id);
                    if lp == 0 {
                        return -98;
                    }
                }
            }
        }
        (kind, lp)
    };
    match kind {
        Kind::Tcp => match crate::net::tcp_open(lp, rip, rport, 6000) {
            Ok(()) => {
                if let Some(s) = SOCKS.lock().get_mut(&id) {
                    s.cid = lp;
                    s.peer = Some((rip, rport));
                    s.bound = true;
                }
                0
            }
            Err(e) => e,
        },
        _ => -22,
    }
}

/// listen(fd): mark a bound (or ephemeral) TCP socket as accepting.
pub fn listen(id: u64) -> i64 {
    let mut m = SOCKS.lock();
    {
        let Some(s) = m.get(&id) else { return -9 };
        match s.kind {
            Kind::Udp => return -95,       // EOPNOTSUPP
            Kind::TcpListener => return 0, // relisten is a no-op
            Kind::Tcp => {}
        }
        if s.peer.is_some() {
            return -106; // already connected
        }
        if s.lport == 0 {
            let l = ephemeral(&m);
            if l == 0 {
                return -98;
            }
            let s = m.get_mut(&id).unwrap();
            s.lport = l;
            s.bound = true;
        }
    }
    let lp = m.get(&id).unwrap().lport;
    match crate::net::tcp_listen(lp) {
        Ok(()) => {
            m.get_mut(&id).unwrap().kind = Kind::TcpListener;
            0
        }
        Err(e) => e,
    }
}

/// accept(fd): take one completed handshake; returns the new socket's fd
/// path + peer address. Err(-11) = none pending (EAGAIN).
pub fn accept(id: u64) -> Result<(String, [u8; 4], u16), i64> {
    let lp = match fields(id) {
        Some((Kind::TcpListener, lp, _, _)) => lp,
        Some(_) => return Err(-22), // not a listener
        None => return Err(-9),
    };
    match crate::net::tcp_accept(lp, 0) {
        Some((cid, rip, rport)) => {
            let mut n = NEXT.lock();
            let nid = *n;
            *n += 1;
            SOCKS.lock().insert(
                nid,
                Sock {
                    kind: Kind::Tcp,
                    lport: lp,
                    cid,
                    peer: Some((rip, rport)),
                    bound: true,
                },
            );
            Ok((format!("/socket/{}", nid), rip, rport))
        }
        None => Err(-11),
    }
}

/// read(fd): UDP pops one datagram (payload only); TCP pops up to buf.len()
/// of the queued stream; listener fds have no stream (-11).
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let id = parse(path).ok_or(-3i64)?;
    crate::net::pump_once(); // surface any packets that arrived since
    let (kind, lport, cid, _) = fields(id).ok_or(-9i64)?;
    match kind {
        Kind::Udp => {
            if lport == 0 {
                return Err(-89); // EDESTADDRREQ: unbound
            }
            match crate::net::udp_recv(lport, 0) {
                Some((_ip, _pt, d)) => {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    Ok(n) // datagrams larger than buf drop the rest (POSIX)
                }
                None => Err(-11),
            }
        }
        Kind::Tcp => match crate::net::tcp_read_ready(cid) {
            None => Ok(0), // peer finished and queue drained: EOF
            Some(false) => Err(-11),
            Some(true) => match crate::net::tcp_recv_some(cid, buf.len()) {
                Some(d) => {
                    buf[..d.len()].copy_from_slice(&d);
                    Ok(d.len())
                }
                None => Err(-11),
            },
        },
        Kind::TcpListener => Err(-11),
    }
}

/// write(fd): UDP sends one datagram to the connect()ed peer; TCP fires a
/// segment — blocking sockets wait for the ack (retransmit loop), O_NONBLOCK
/// fires once and reports the queued length.
pub fn try_write(path: &str, data: &[u8], nonblock: bool) -> Result<usize, i64> {
    let id = parse(path).ok_or(-3i64)?;
    let (kind, lport, cid, peer) = fields(id).ok_or(-9i64)?;
    match kind {
        Kind::Udp => {
            let Some((ip, pt)) = peer else {
                return Err(-89); // EDESTADDRREQ: no default destination
            };
            crate::net::udp_send(lport, ip, pt, data).map(|_| data.len())
        }
        Kind::Tcp => {
            if cid == 0 {
                return Err(-107); // ENOTCONN
            }
            if nonblock {
                crate::net::tcp_send_nowait(cid, data)
            } else {
                match crate::net::tcp_send(cid, data, 8000) {
                    Ok(()) => Ok(data.len().min(1400)),
                    // dead peer/timeouts surface as EPIPE
                    Err(-2) => Err(-32),
                    Err(e) => Err(e),
                }
            }
        }
        Kind::TcpListener => Err(-107),
    }
}

/// sendto(fd, buf, ip, port): UDP with an explicit per-datagram peer —
/// binds an ephemeral port on first use like POSIX. TCP ignores the addr.
pub fn sendto(path: &str, data: &[u8], ip: u32, port: u16) -> Result<usize, i64> {
    let id = parse(path).ok_or(-3i64)?;
    {
        let mut m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return Err(-9) };
        if s.kind == Kind::Udp && s.lport == 0 {
            if pick_ephemeral(&mut m, id) == 0 {
                return Err(-98);
            }
            let lp = m.get(&id).unwrap().lport;
            if crate::net::udp_open(lp).is_err() {
                return Err(-98);
            }
        }
    }
    let (kind, lport, _, _) = fields(id).ok_or(-9i64)?;
    match kind {
        Kind::Udp => crate::net::udp_send(lport, ip.to_be_bytes(), port, data)
            .map(|_| data.len()),
        Kind::Tcp => try_write(path, data, false), // addr ignored on streams
        Kind::TcpListener => Err(-107),
    }
}

/// recvfrom(fd, buf): like read() but the sender's (ip, port) comes back —
/// only meaningful for UDP; TCP behaves as read().
pub fn recvfrom(path: &str, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), i64> {
    let id = parse(path).ok_or(-3i64)?;
    crate::net::pump_once();
    let (kind, lport, _, _) = fields(id).ok_or(-9i64)?;
    match kind {
        Kind::Udp => {
            if lport == 0 {
                return Err(-89);
            }
            match crate::net::udp_recv(lport, 0) {
                Some((ip, pt, d)) => {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    Ok((n, ip, pt))
                }
                None => Err(-11),
            }
        }
        _ => try_read(path, buf).map(|n| (n, [0; 4], 0)),
    }
}

/// fd_ready hook: UDP read-ready = datagram queued; TCP = data or EOF;
/// listener = a completed handshake waiting for accept. Everything write-
/// ready when usable (UDP needs a peer, TCP needs a conn).
pub fn ready(path: &str, for_read: bool) -> bool {
    let Some(id) = parse(path) else { return false };
    crate::net::pump_once();
    let Some((kind, lport, cid, peer)) = fields(id) else {
        return true; // dead fd: readable/writable so poll wakes the closer
    };
    if for_read {
        match kind {
            Kind::Udp => crate::net::udp_ready(lport),
            Kind::Tcp => !matches!(crate::net::tcp_read_ready(cid), Some(false)),
            Kind::TcpListener => crate::net::tcp_accept_ready(lport),
        }
    } else {
        match kind {
            Kind::Udp => lport != 0 && peer.is_some(),
            Kind::Tcp => cid != 0,
            Kind::TcpListener => false,
        }
    }
}

/// fd close: release the net resource for real — UDP unbind, TCP FIN,
/// listener unregister.
pub fn close_obj(path: &str) {
    let Some(id) = parse(path) else { return };
    let Some((kind, lport, cid, _)) = fields(id) else { return };
    SOCKS.lock().remove(&id);
    match kind {
        Kind::Udp => crate::net::udp_close(lport),
        Kind::Tcp => crate::net::tcp_close(cid),
        Kind::TcpListener => crate::net::tcp_unlisten(lport),
    }
}

/// Which socket kind a path holds — for stat/debug output.
pub fn kind_name(path: &str) -> &'static str {
    match parse(path).and_then(|id| fields(id)) {
        Some((Kind::Udp, _, _, _)) => "udp",
        Some((Kind::Tcp, _, _, _)) => "tcp",
        Some((Kind::TcpListener, _, _, _)) => "tcp-listen",
        None => "?",
    }
}
