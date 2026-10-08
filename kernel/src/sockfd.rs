//! BSD-style sockets as real fds. `socket(2)` creates a `/socket/{id}`
//! object; `bind`/`connect`/`listen`/`accept` drive the real net stack
//! (udp_open/tcp_open/tcp_listen/tcp_accept); the fd rides the same
//! read/write/poll/epoll/close machinery as pipes and event objects.

use alloc::{
    collections::{BTreeMap, VecDeque},
    format,
    string::String,
};
use spin::Mutex;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Udp,
    Tcp,          // connected stream (outbound or accepted)
    TcpListener,  // listen()ed stream
    Unix,         // AF_UNIX stream (data plane = a /sockpair object)
    UnixListener, // AF_UNIX stream bound+listen()ed on a path name
    UnixDgram,    // AF_UNIX datagram (mailbox registry in udgram.rs)
}

#[derive(Clone, Copy, PartialEq)]
pub enum Dom {
    Inet,
    Unix,
}

#[derive(Clone)]
struct Sock {
    kind: Kind,
    domain: Dom,
    lport: u16,                   // bound or ephemeral local port
    cid: u16,                     // TCP_SOCKS key (== lport for outbound)
    peer: Option<([u8; 4], u16)>, // connect()ed peer (UDP default dest)
    bound: bool,
    chan: Option<String>,         // Unix: backing "/sockpair/{id}/N" path
    uname: Option<String>,        // Unix: bound path name
    peer_name: Option<String>,    // Unix client/dgram: the path it connect()ed to
    rd_off: bool,                 // shutdown(SHUT_RD)
    wr_off: bool,                 // shutdown(SHUT_WR)
    last_err: i64,                // last connect/send errno (SO_ERROR)
    owner_pid: u32,               // task that created this socket (SO_PEERCRED)
    peer_pid: u32,                // peer task's pid on unix pairs (0 = none)
    reuse: bool,                  // SO_REUSEADDR
    broadcast: bool,              // SO_BROADCAST (gate on bcast dst sends)
}

/// AF_UNIX named-socket registry: path -> listener state. `queue` holds
/// (chan path, connector pid) for each completed connect awaiting accept.
struct UListener {
    listening: bool,
    backlog: usize,
    queue: VecDeque<(String, u32)>,
    owner_pid: u32,
}

static NEXT: Mutex<u64> = Mutex::new(1);
static SOCKS: Mutex<BTreeMap<u64, Sock>> = Mutex::new(BTreeMap::new());
static UNIX_NAMES: Mutex<BTreeMap<String, UListener>> = Mutex::new(BTreeMap::new());

pub fn parse(path: &str) -> Option<u64> {
    path.strip_prefix("/socket/")?.parse().ok()
}

pub fn handles(path: &str) -> bool {
    parse(path).is_some()
}

/// Registry id -> AF_UNIX socket? (the syscall layer branches unix path
/// args on this before touching user memory for names)
pub fn is_unix(id: u64) -> bool {
    SOCKS
        .lock()
        .get(&id)
        .map(|s| s.domain == Dom::Unix)
        .unwrap_or(false)
}

fn fields(id: u64) -> Option<Sock> {
    SOCKS.lock().get(&id).cloned()
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

/// socket(type, domain): register an unbound socket; returns its fd
/// path. domain: 0/2 = AF_INET, 1 = AF_UNIX, else Err(-97).
pub fn create(stream: bool, domain: u64) -> Result<String, i64> {
    let domain = match domain {
        0 | 2 => Dom::Inet,
        1 => Dom::Unix,
        _ => return Err(-97), // EAFNOSUPPORT
    };
    let kind = match (domain, stream) {
        (Dom::Inet, true) => Kind::Tcp,
        (Dom::Inet, false) => Kind::Udp,
        (Dom::Unix, true) => Kind::Unix,
        (Dom::Unix, false) => Kind::UnixDgram,
    };
    let mut n = NEXT.lock();
    let id = *n;
    *n += 1;
    SOCKS.lock().insert(
        id,
        Sock {
            kind,
            domain,
            lport: 0,
            cid: 0,
            peer: None,
            bound: false,
            chan: None,
            uname: None,
            peer_name: None,
            rd_off: false,
            wr_off: false,
            last_err: 0,
            owner_pid: crate::task::current_id(),
            peer_pid: 0,
            reuse: false,
            broadcast: false,
        },
    );
    Ok(format!("/socket/{}", id))
}

/// bind(fd, a2, name): AF_INET claims a local port (a2); AF_UNIX claims
/// a path name (`name` bytes). Err(-98) EADDRINUSE, -9 bad fd, -22 bad args.
pub fn bind(id: u64, port: u16, name: &[u8]) -> i64 {
    let unix = {
        let m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return -9 };
        s.domain == Dom::Unix
    };
    if unix {
        return bind_unix(id, name);
    }
    if port == 0 {
        return -22;
    }
    let mut m = SOCKS.lock();
    // POSIX SO_REUSEADDR: two sockets may share a port only when every
    // existing binder AND the newcomer set it (rough Linux semantics).
    let want_reuse = m.get(&id).map(|s| s.reuse).unwrap_or(false);
    let shared = m.values().any(|s| s.bound && s.lport == port);
    if shared
        && !(want_reuse
            && m.values()
                .all(|s| !s.bound || s.lport != port || s.reuse))
    {
        return -98;
    }
    let Some(s) = m.get_mut(&id) else { return -9 };
    if s.bound {
        return -22; // already bound
    }
    if shared {
        // reuse vote passed — the port is already open in the net stack;
        // join its shared queue instead of claiming it fresh
        if s.kind == Kind::Udp && crate::net::udp_open_share(port).is_err() {
            return -98;
        }
    } else {
        if !crate::net::lport_free(port) {
            return -98;
        }
        if s.kind == Kind::Udp && crate::net::udp_open(port).is_err() {
            return -98;
        }
    }
    // TCP bind just records the port; the net stack claims it at
    // listen()/connect() like POSIX's deferred bind
    s.lport = port;
    s.bound = true;
    0
}

/// AF_UNIX bind: register the name (filesystem-visible, purely in-memory).
/// Stream sockets claim an entry in UNIX_NAMES (the listen/accept table);
/// datagram sockets claim a mailbox in udgram.rs. Either way the name is
/// taken in both namespaces — like POSIX where a socket path is one name.
fn bind_unix(id: u64, name: &[u8]) -> i64 {
    if name.len() < 2 || name.len() > 63 || name[0] != b'/' {
        return -22;
    }
    let Ok(name) = core::str::from_utf8(name) else {
        return -22;
    };
    let name = String::from(name);
    let dgram = {
        let m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return -9 };
        s.kind == Kind::UnixDgram
    };
    if dgram {
        if UNIX_NAMES.lock().contains_key(&name) || !crate::udgram::register(&name) {
            return -98;
        }
        let mut m = SOCKS.lock();
        let Some(s) = m.get_mut(&id) else {
            crate::udgram::unregister(&name);
            return -9;
        };
        if s.bound {
            crate::udgram::unregister(&name);
            return -22;
        }
        s.uname = Some(name);
        s.bound = true;
        return 0;
    }
    let mut names = UNIX_NAMES.lock();
    if names.contains_key(&name) || crate::udgram::exists(&name) {
        return -98;
    }
    let mut m = SOCKS.lock();
    let Some(s) = m.get_mut(&id) else { return -9 };
    if s.bound {
        return -22;
    }
    names.insert(
        name.clone(),
        UListener {
            listening: false,
            backlog: 0,
            queue: VecDeque::new(),
            owner_pid: 0,
        },
    );
    s.uname = Some(name);
    s.bound = true;
    0
}

/// connect(fd, a2, a3, name): inet is (a2=ip u32-be, a3=port); unix uses
/// `name`. UDP records the default peer; TCP runs the real SYN handshake;
/// Unix mints a connected pair and queues the server end for accept.
pub fn connect(id: u64, rip_u32: u32, rport: u16, name: &[u8]) -> i64 {
    {
        let unix = {
            let m = SOCKS.lock();
            let Some(s) = m.get(&id) else { return -9 };
            s.domain == Dom::Unix
        };
        if unix {
            return connect_unix(id, name);
        }
        let m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return -9 };
        if s.kind == Kind::UnixListener || s.kind == Kind::TcpListener {
            return -22;
        }
    }
    let rip = rip_u32.to_be_bytes();
    let (kind, lp) = {
        let mut m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return -9 };
        if s.peer.is_some() {
            return -106; // EISCONN
        }
        let kind = s.kind;
        let mut lp = s.lport;
        match kind {
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
            _ => return -22,
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

/// AF_UNIX connect. Stream: the name must be bound AND listening (else
/// -2/-111); a fresh sockpair links client (side 0) to the accept queue
/// (side 1). Datagram: the name must be a live mailbox (else -2) and the
/// connect just sets the default destination — re-connect repoints it.
/// Failures land in s.last_err for SO_ERROR.
fn connect_unix(id: u64, name: &[u8]) -> i64 {
    let Ok(name) = core::str::from_utf8(name) else {
        return -22;
    };
    let kind = {
        let m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return -9 };
        if s.kind != Kind::Unix && s.kind != Kind::UnixDgram {
            return -95;
        }
        if s.kind == Kind::Unix && s.chan.is_some() {
            return -106;
        }
        s.kind
    };
    if kind == Kind::UnixDgram {
        if !crate::udgram::exists(name) {
            set_err(id, -2);
            return -2; // ENOENT
        }
        // the peer of a datagram connect is the mailbox's owner
        let peer_pid = SOCKS
            .lock()
            .values()
            .find(|s| s.uname.as_deref() == Some(name))
            .map(|s| s.owner_pid)
            .unwrap_or(0);
        let mut m = SOCKS.lock();
        if let Some(s) = m.get_mut(&id) {
            s.peer_name = Some(String::from(name));
            s.peer_pid = peer_pid;
            s.bound = true;
        }
        return 0;
    }
    let mut names = UNIX_NAMES.lock();
    let Some(l) = names.get_mut(name) else {
        set_err(id, -2);
        return -2; // ENOENT
    };
    if !l.listening {
        set_err(id, -111);
        return -111; // ECONNREFUSED
    }
    if l.backlog > 0 && l.queue.len() >= l.backlog {
        set_err(id, -11);
        return -11; // would block
    }
    let Some((side0, side1)) = crate::sockpair::create() else {
        set_err(id, -24);
        return -24;
    };
    let lpid = l.owner_pid;
    l.queue.push_back((side1, crate::task::current_id()));
    let mut m = SOCKS.lock();
    if let Some(s) = m.get_mut(&id) {
        s.chan = Some(side0);
        s.peer_name = Some(String::from(name));
        s.peer_pid = lpid;
        s.bound = true;
    }
    0
}

/// Record a connect/send failure for SO_ERROR readout.
fn set_err(id: u64, e: i64) {
    if let Some(s) = SOCKS.lock().get_mut(&id) {
        s.last_err = e;
    }
}

/// Ensure a unix-dgram socket owns a mailbox: auto-bind to
/// `/tmp/udg-{id}` on first use (Linux autobind). Returns the name.
fn ensure_bound(id: u64) -> Result<String, i64> {
    let (have, auto) = {
        let m = SOCKS.lock();
        let Some(s) = m.get(&id) else { return Err(-9) };
        (s.uname.clone(), format!("/tmp/udg-{}", id))
    };
    if let Some(u) = have {
        return Ok(u);
    }
    if UNIX_NAMES.lock().contains_key(&auto) || !crate::udgram::register(&auto) {
        return Err(-98);
    }
    let mut m = SOCKS.lock();
    let Some(s) = m.get_mut(&id) else {
        crate::udgram::unregister(&auto);
        return Err(-9);
    };
    s.uname = Some(auto.clone());
    s.bound = true;
    Ok(auto)
}

/// listen(fd, backlog): inet marks a bound/ephemeral TCP port accepting;
/// unix marks its bound name listening (unbound unix -> -22 like POSIX).
pub fn listen(id: u64, backlog: usize) -> i64 {
    let mut m = SOCKS.lock();
    {
        let Some(s) = m.get(&id) else { return -9 };
        match s.kind {
            Kind::Udp | Kind::Unix => {
                if s.domain == Dom::Unix {
                    // unix stream: needs a bound name
                    if s.uname.is_none() {
                        return -22;
                    }
                } else {
                    return -95; // UDP listen: EOPNOTSUPP
                }
            }
            Kind::UnixDgram => return -95, // EOPNOTSUPP: dgrams don't listen
            Kind::TcpListener | Kind::UnixListener => return 0,
            Kind::Tcp => {}
        }
        if s.peer.is_some() || s.chan.is_some() {
            return -106; // already connected
        }
        if s.domain == Dom::Unix {
            let uname = s.uname.clone().unwrap();
            let mut names = UNIX_NAMES.lock();
            let Some(l) = names.get_mut(&uname) else {
                return -2;
            };
            l.listening = true;
            l.backlog = backlog.max(1);
            l.owner_pid = s.owner_pid;
            m.get_mut(&id).unwrap().kind = Kind::UnixListener;
            return 0;
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

/// accept(fd): take one completed connection; returns the new fd's path +
/// peer address (zeroed for unix). Err(-11) = none pending (EAGAIN).
pub fn accept(id: u64) -> Result<(String, [u8; 4], u16), i64> {
    let s = fields(id).ok_or(-9i64)?;
    match s.kind {
        Kind::TcpListener => match crate::net::tcp_accept(s.lport, 0) {
            Some((cid, rip, rport)) => {
                let mut n = NEXT.lock();
                let nid = *n;
                *n += 1;
                SOCKS.lock().insert(
                    nid,
                    Sock {
                        kind: Kind::Tcp,
                        domain: Dom::Inet,
                        lport: s.lport,
                        cid,
                        peer: Some((rip, rport)),
                        bound: true,
                        chan: None,
                        uname: None,
                        peer_name: None,
                        rd_off: false,
                        wr_off: false,
                        last_err: 0,
                        owner_pid: crate::task::current_id(),
                        peer_pid: 0,
                        reuse: false,
                        broadcast: false,
                    },
                );
                Ok((format!("/socket/{}", nid), rip, rport))
            }
            None => Err(-11),
        },
        Kind::UnixListener => {
            let uname = s.uname.clone().ok_or(-2i64)?;
            let mut names = UNIX_NAMES.lock();
            let Some(l) = names.get_mut(&uname) else {
                return Err(-2);
            };
            match l.queue.pop_front() {
                Some((p, cpid)) => {
                    drop(names);
                    // the accepted end is a first-class /socket object
                    // (getsockname/sendmsg/etc work on it); its peer is
                    // the task that connected
                    let mut n = NEXT.lock();
                    let nid = *n;
                    *n += 1;
                    SOCKS.lock().insert(
                        nid,
                        Sock {
                            kind: Kind::Unix,
                            domain: Dom::Unix,
                            lport: 0,
                            cid: 0,
                            peer: None,
                            bound: true,
                            chan: Some(p),
                            uname: None,
                            peer_name: None,
                            rd_off: false,
                            wr_off: false,
                            last_err: 0,
                            owner_pid: crate::task::current_id(),
                            peer_pid: cpid,
                            reuse: false,
                            broadcast: false,
                        },
                    );
                    Ok((format!("/socket/{}", nid), [0; 4], 0))
                }
                None => Err(-11),
            }
        }
        _ => Err(-22), // not a listener
    }
}

/// read(fd): UDP pops one datagram (payload only); TCP pops up to buf.len()
/// of the queued stream; unix delegates to its sockpair side; listener
/// fds have no stream (-11). rd_off (SHUT_RD) reads as EOF.
pub fn try_read(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let id = parse(path).ok_or(-3i64)?;
    crate::net::pump_once(); // surface any packets that arrived since
    let s = fields(id).ok_or(-9i64)?;
    if s.rd_off {
        return Ok(0);
    }
    match s.kind {
        Kind::Udp => {
            if s.lport == 0 {
                return Err(-89); // EDESTADDRREQ: unbound
            }
            match crate::net::udp_recv(s.lport, 0) {
                Some((_ip, _pt, d)) => {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    Ok(n) // datagrams larger than buf drop the rest (POSIX)
                }
                None => Err(-11),
            }
        }
        Kind::Tcp => match crate::net::tcp_read_ready(s.cid) {
            None => Ok(0), // peer finished and queue drained: EOF
            Some(false) => Err(-11),
            Some(true) => match crate::net::tcp_recv_some(s.cid, buf.len()) {
                Some(d) => {
                    buf[..d.len()].copy_from_slice(&d);
                    Ok(d.len())
                }
                None => Err(-11),
            },
        },
        Kind::Unix => match &s.chan {
            Some(c) => crate::sockpair::try_read(c, buf),
            None => Err(-107), // ENOTCONN
        },
        Kind::UnixDgram => match &s.uname {
            Some(u) => crate::udgram::recv(u, buf).map(|(n, _)| n),
            None => Err(-22), // EINVAL: recvfrom on an unbound mailbox
        },
        Kind::TcpListener | Kind::UnixListener => Err(-11),
    }
}

/// write(fd): UDP sends one datagram to the connect()ed peer; TCP fires a
/// segment (blocking waits for the ack; O_NONBLOCK reports the queued
/// length); unix writes into the sockpair. wr_off (SHUT_WR) -> EPIPE.
pub fn try_write(path: &str, data: &[u8], nonblock: bool) -> Result<usize, i64> {
    let id = parse(path).ok_or(-3i64)?;
    let s = fields(id).ok_or(-9i64)?;
    if s.wr_off {
        return Err(-32);
    }
    match s.kind {
        Kind::Udp => {
            let Some((ip, pt)) = s.peer else {
                return Err(-89); // EDESTADDRREQ: no default destination
            };
            if crate::net::is_bcast(ip) && !s.broadcast {
                return Err(-13); // EACCES: SO_BROADCAST not set
            }
            crate::net::udp_send(s.lport, ip, pt, data).map(|_| data.len())
        }
        Kind::Tcp => {
            if s.cid == 0 {
                return Err(-107); // ENOTCONN
            }
            if nonblock {
                crate::net::tcp_send_nowait(s.cid, data)
            } else {
                match crate::net::tcp_send(s.cid, data, 8000) {
                    Ok(()) => Ok(data.len().min(1400)),
                    // dead peer/timeouts surface as EPIPE
                    Err(-2) => Err(-32),
                    Err(e) => Err(e),
                }
            }
        }
        Kind::Unix => match &s.chan {
            Some(c) => crate::sockpair::try_write(c, data),
            None => Err(-107),
        },
        Kind::UnixDgram => {
            let Some(dst) = &s.peer_name else {
                return Err(-89); // EDESTADDRREQ: no default destination
            };
            let dst = dst.clone();
            match ensure_bound(id).and_then(|src| {
                let r = crate::udgram::send(&dst, &src, data);
                if r < 0 {
                    Err(r)
                } else {
                    Ok(data.len())
                }
            }) {
                Ok(n) => Ok(n),
                Err(e) => {
                    set_err(id, e);
                    Err(e)
                }
            }
        }
        Kind::TcpListener | Kind::UnixListener => Err(-107),
    }
}

/// sendto(fd, buf, ip, port): UDP with an explicit per-datagram peer —
/// binds an ephemeral port on first use like POSIX. Streams ignore the
/// addr (unix sends on its chan).
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
    let s = fields(id).ok_or(-9i64)?;
    if s.wr_off {
        return Err(-32);
    }
    match s.kind {
        Kind::Udp => {
            let dst = ip.to_be_bytes();
            if crate::net::is_bcast(dst) && !s.broadcast {
                return Err(-13); // EACCES: SO_BROADCAST not set
            }
            crate::net::udp_send(s.lport, dst, port, data).map(|_| data.len())
        }
        // addr ignored (unix-dgram uses sendto_path for a named dest)
        Kind::Tcp | Kind::Unix | Kind::UnixDgram => try_write(path, data, false),
        Kind::TcpListener | Kind::UnixListener => Err(-107),
    }
}

/// sendto_path(fd, buf, name): AF_UNIX datagram send — `name` is the
/// destination mailbox. Unbound senders auto-bind `/tmp/udg-{id}` first.
pub fn sendto_path(id: u64, name: &str, data: &[u8]) -> Result<usize, i64> {
    let s = fields(id).ok_or(-9i64)?;
    if s.kind != Kind::UnixDgram {
        return Err(-95); // EOPNOTSUPP: only unix dgrams take a path dest
    }
    if s.wr_off {
        return Err(-32);
    }
    let src = ensure_bound(id)?;
    let r = crate::udgram::send(name, &src, data);
    if r < 0 {
        set_err(id, r);
        return Err(r);
    }
    Ok(data.len())
}

/// recvfrom_path(fd, buf): AF_UNIX datagram receive — pops one packet and
/// the sender's bound/auto-bound name. Err(-22) if this sock isn't bound.
pub fn recvfrom_path(id: u64, buf: &mut [u8]) -> Result<(usize, String), i64> {
    let s = fields(id).ok_or(-9i64)?;
    if s.kind != Kind::UnixDgram {
        return Err(-95);
    }
    if s.rd_off {
        return Ok((0, String::new()));
    }
    let Some(u) = &s.uname else {
        return Err(-22); // EINVAL: nothing bound to receive into
    };
    crate::udgram::recv(u, buf)
}

/// recvfrom(fd, buf): like read() but the sender's (ip, port) comes back —
/// only meaningful for UDP; streams behave as read() with a zeroed src.
pub fn recvfrom(path: &str, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), i64> {
    let id = parse(path).ok_or(-3i64)?;
    crate::net::pump_once();
    let s = fields(id).ok_or(-9i64)?;
    match s.kind {
        Kind::Udp => {
            if s.lport == 0 {
                return Err(-89);
            }
            match crate::net::udp_recv(s.lport, 0) {
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

/// sendmsg(fd, buf, pass_path): SCM_RIGHTS — on AF_UNIX the object's path
/// is queued for the peer to adopt as a fresh fd (EOPNOTSUPP elsewhere,
/// matching POSIX's unix-only ancillary rule). Without ancillary it's a
/// plain stream write / UDP send-to-peer.
pub fn sendmsg(path: &str, data: &[u8], pass: Option<String>) -> Result<usize, i64> {
    let id = parse(path).ok_or(-3i64)?;
    let s = fields(id).ok_or(-9i64)?;
    if s.wr_off {
        return Err(-32);
    }
    match s.kind {
        Kind::Unix => match &s.chan {
            Some(c) => crate::sockpair::send_msg(c, data, pass),
            None => Err(-107), // ENOTCONN
        },
        Kind::Tcp | Kind::Udp | Kind::UnixDgram => {
            if pass.is_some() {
                return Err(-95); // EOPNOTSUPP: SCM_RIGHTS is stream-only
            }
            try_write(path, data, false)
        }
        Kind::TcpListener | Kind::UnixListener => Err(-107),
    }
}

/// recvmsg(fd, buf): like read() plus the next object path the peer
/// passed via SCM_RIGHTS for the caller to adopt as a new fd.
pub fn recvmsg(path: &str, buf: &mut [u8]) -> Result<(usize, Option<String>), i64> {
    let id = parse(path).ok_or(-3i64)?;
    let s = fields(id).ok_or(-9i64)?;
    match s.kind {
        Kind::Unix => match &s.chan {
            Some(c) => crate::sockpair::recv_msg(c, buf),
            None => Err(-107),
        },
        Kind::UnixListener => Err(-11),
        _ => try_read(path, buf).map(|n| (n, None)),
    }
}

/// `/proc/net/unix` dump — one Linux-style row per AF_UNIX socket:
/// "Num RefCount Protocol Flags Type St Inode Path" (St: 01 unconnected,
/// 02 listening, 03 connected; Type 0001 = stream).
pub fn net_unix() -> String {
    let mut out = String::from(
        "Num       RefCount Protocol Flags    Type St         Inode Path\n",
    );
    let m = SOCKS.lock();
    for (id, s) in m.iter() {
        if s.domain != Dom::Unix {
            continue;
        }
        let (st, p, ty) = match s.kind {
            Kind::UnixListener => ("02", s.uname.clone().unwrap_or_default(), "0001"),
            Kind::Unix => (
                "03",
                s.uname
                    .clone()
                    .or_else(|| s.peer_name.clone())
                    .unwrap_or_default(),
                "0001",
            ),
            Kind::UnixDgram => (
                if s.peer_name.is_some() { "03" } else { "01" },
                s.uname.clone().unwrap_or_default(),
                "0002",
            ),
            _ => continue,
        };
        out.push_str(&format!(
            "{:>10} {:>8} {:>8} {:>8} {:>4} {} {:>10} {}\n",
            id, 1, 0, "00010000", ty, st, id, p
        ));
    }
    out
}

/// fd_ready hook: UDP read-ready = datagram queued; TCP = data or EOF;
/// unix = sockpair readiness; listeners = a completed conn waiting.
pub fn ready(path: &str, for_read: bool) -> bool {
    let Some(id) = parse(path) else { return false };
    crate::net::pump_once();
    let Some(s) = fields(id) else {
        return true; // dead fd: readable/writable so poll wakes the closer
    };
    if for_read {
        if s.rd_off {
            return true; // EOF is "readable"
        }
        match s.kind {
            Kind::Udp => crate::net::udp_ready(s.lport),
            Kind::Tcp => !matches!(crate::net::tcp_read_ready(s.cid), Some(false)),
            Kind::TcpListener => crate::net::tcp_accept_ready(s.lport),
            Kind::Unix => match &s.chan {
                Some(c) => crate::sockpair::ready(c, true),
                None => false,
            },
            Kind::UnixListener => match &s.uname {
                Some(n) => UNIX_NAMES
                    .lock()
                    .get(n)
                    .map(|l| !l.queue.is_empty())
                    .unwrap_or(false),
                None => false,
            },
            Kind::UnixDgram => match &s.uname {
                Some(u) => crate::udgram::ready(u),
                None => false,
            },
        }
    } else {
        if s.wr_off {
            return false;
        }
        match s.kind {
            Kind::Udp => s.lport != 0 && s.peer.is_some(),
            Kind::Tcp => s.cid != 0,
            Kind::Unix => s
                .chan
                .as_deref()
                .map(|c| crate::sockpair::ready(c, false))
                .unwrap_or(false),
            Kind::UnixDgram => s.peer_name.is_some(),
            Kind::TcpListener | Kind::UnixListener => false,
        }
    }
}

/// shutdown(fd, how): real half-close. SHUT_RD (1) -> reads return EOF;
/// SHUT_WR (2) -> writes fail EPIPE and the peer sees FIN/EOF: TCP sends a
/// real FIN on the wire, unix marks the sockpair side write-closed.
pub fn shutdown(id: u64, how: u64) -> i64 {
    if how > 2 {
        return -22;
    }
    let rd = how == 0 || how == 2;
    let wr = how == 1 || how == 2;
    let s = {
        let mut m = SOCKS.lock();
        let Some(s) = m.get_mut(&id) else { return -9 };
        match s.kind {
            Kind::TcpListener | Kind::UnixListener => return -107,
            Kind::Tcp if s.cid == 0 => return -107,
            Kind::Udp if s.peer.is_none() => return -107,
            Kind::Unix if s.chan.is_none() => return -107,
            Kind::UnixDgram if s.peer_name.is_none() => return -107,
            _ => {}
        }
        if rd {
            s.rd_off = true;
        }
        if wr {
            s.wr_off = true;
        }
        s.clone()
    };
    if wr {
        match s.kind {
            Kind::Tcp => {
                crate::net::tcp_shutdown_wr(s.cid);
            }
            Kind::Unix => {
                if let Some(c) = &s.chan {
                    crate::sockpair::shutdown(c, 1);
                }
            }
            _ => {}
        }
    }
    0
}

/// getsockname: local address. Inet -> (our-ip, lport); unix -> bound name.
pub fn sockname(id: u64) -> Option<(Dom, [u8; 4], u16, Option<String>)> {
    let s = fields(id)?;
    Some((
        s.domain,
        if s.domain == Dom::Inet { crate::net::our_ip() } else { [0; 4] },
        s.lport,
        s.uname,
    ))
}

/// getpeername: remote address of a connected socket.
pub fn peername(id: u64) -> Result<(Dom, [u8; 4], u16, Option<String>), i64> {
    let s = fields(id).ok_or(-9i64)?;
    match s.kind {
        Kind::Tcp | Kind::Udp => match s.peer {
            Some((ip, pt)) => Ok((Dom::Inet, ip, pt, None)),
            None => Err(-107),
        },
        Kind::Unix | Kind::UnixDgram => match &s.peer_name {
            Some(n) => Ok((Dom::Unix, [0; 4], 0, Some(n.clone()))),
            None => Err(-107),
        },
        _ => Err(-107),
    }
}

/// fd close: release the real resource — UDP unbind, TCP FIN, listener
/// unregister; unix closes its chan (peer EOF) and frees its bound name
/// (any queued pending conn ends are shut so their clients see EOF).
pub fn close_obj(path: &str) {
    let Some(id) = parse(path) else { return };
    let Some(s) = fields(id) else { return };
    SOCKS.lock().remove(&id);
    match s.kind {
        Kind::Udp => crate::net::udp_close_one(s.lport),
        Kind::Tcp => crate::net::tcp_close(s.cid),
        Kind::TcpListener => crate::net::tcp_unlisten(s.lport),
        _ => {}
    }
    if let Some(c) = s.chan {
        crate::sockpair::close_obj(&c);
    }
    if let Some(uname) = s.uname {
        if s.kind == Kind::UnixDgram {
            crate::udgram::unregister(&uname); // queued packets die with it
        }
        let mut names = UNIX_NAMES.lock();
        if let Some(l) = names.remove(&uname) {
            for (p, _pid) in l.queue {
                crate::sockpair::close_obj(&p);
            }
        }
    }
}

/// Which socket kind a path holds — for stat/debug output.
pub fn kind_name(path: &str) -> &'static str {
    match parse(path).and_then(|id| fields(id).map(|s| s.kind)) {
        Some(Kind::Udp) => "udp",
        Some(Kind::Tcp) => "tcp",
        Some(Kind::TcpListener) => "tcp-listen",
        Some(Kind::Unix) => "unix",
        Some(Kind::UnixListener) => "unix-listen",
        Some(Kind::UnixDgram) => "unix-dgram",
        None => "?",
    }
}

/// getsockopt(fd, level, opt): SOL_SOCKET queries with real answers —
/// SO_TYPE/SO_DOMAIN/SO_PROTOCOL/SO_ACCEPTCONN/SO_SNDBUF/SO_RCVBUF/
/// SO_ERROR (read-and-clear of the last recorded connect/send errno).
/// Returns the u32-le value bytes. Err(-92) ENOPROTOOPT for the rest.
pub fn getsockopt(id: u64, level: u64, opt: u64) -> Result<u32, i64> {
    const SOL_SOCKET: u64 = 1;
    if level != SOL_SOCKET {
        return Err(-92); // ENOPROTOOPT
    }
    let s = fields(id).ok_or(-9i64)?;
    match opt {
        3 => Ok(match s.kind {
            // SO_TYPE
            Kind::Unix | Kind::UnixListener | Kind::Tcp | Kind::TcpListener => 1,
            Kind::Udp | Kind::UnixDgram => 2,
        }),
        39 => Ok(match s.domain {
            // SO_DOMAIN
            Dom::Unix => 1,
            Dom::Inet => 2,
        }),
        38 => Ok(0), // SO_PROTOCOL
        30 => Ok(matches!(s.kind, Kind::UnixListener | Kind::TcpListener) as u32),
        7 | 8 => Ok(65536), // SO_SNDBUF/SO_RCVBUF — the sockpair CAP
        4 => {
            // SO_ERROR: report + clear
            let e = s.last_err;
            if let Some(s2) = SOCKS.lock().get_mut(&id) {
                s2.last_err = 0;
            }
            Ok(e as u32)
        }
        17 => {
            // SO_PEERCRED: pid of the task holding the other end of a
            // unix pair (streams: connector/listener; dgram: mbox owner)
            match s.peer_pid {
                0 => Err(-107), // ENOTCONN
                p => Ok(p),
            }
        }
        2 => Ok(s.reuse as u32),      // SO_REUSEADDR
        6 => Ok(s.broadcast as u32),  // SO_BROADCAST
        _ => Err(-92),
    }
}

/// setsockopt(fd, level, opt, val): SOL_SOCKET (1) only. SO_REUSEADDR (2)
/// relaxes the port-in-use check at bind; SO_BROADCAST (6) unblocks
/// sends to 255.255.255.255 / subnet-directed broadcast.
pub fn setsockopt(id: u64, level: u64, opt: u64, val: u64) -> i64 {
    const SOL_SOCKET: u64 = 1;
    if level != SOL_SOCKET {
        return -92; // ENOPROTOOPT
    }
    let mut m = SOCKS.lock();
    let Some(s) = m.get_mut(&id) else { return -9 };
    match opt {
        2 => {
            s.reuse = val != 0;
            0
        }
        6 => {
            s.broadcast = val != 0;
            0
        }
        _ => -92,
    }
}

/// socketpair(AF_UNIX, SOCK_DGRAM): two auto-named mailboxes, each
/// pointing at the other — same mutual-delivery model as the stream
/// pair, but packet boundaries are kept. Returns (pathA, pathB).
pub fn socketpair_dgram() -> Option<(String, String)> {
    let mut n = NEXT.lock();
    let (a, b) = (*n, *n + 1);
    *n += 2;
    drop(n);
    let (na, nb) = (format!("/tmp/udgp-{}", a), format!("/tmp/udgp-{}", b));
    if !crate::udgram::register(&na) || !crate::udgram::register(&nb) {
        crate::udgram::unregister(&na);
        crate::udgram::unregister(&nb);
        return None;
    }
    let pid = crate::task::current_id();
    let mut m = SOCKS.lock();
    for (id, mine, peer) in [(a, &na, &nb), (b, &nb, &na)] {
        m.insert(
            id,
            Sock {
                kind: Kind::UnixDgram,
                domain: Dom::Unix,
                lport: 0,
                cid: 0,
                peer: None,
                bound: true,
                chan: None,
                uname: Some(mine.clone()),
                peer_name: Some(peer.clone()),
                rd_off: false,
                wr_off: false,
                last_err: 0,
                owner_pid: pid,
                peer_pid: pid,
                reuse: false,
                broadcast: false,
            },
        );
    }
    Some((format!("/socket/{}", a), format!("/socket/{}", b)))
}
