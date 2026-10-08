//! Minimal IPv4 stack on virtio-net: ethernet + ARP + ICMP echo.
//! Guest IP 10.0.2.15 (QEMU user-net convention), gateway 10.0.2.2.
//! `ping(ip)` performs a real ARP resolve + ICMP echo request/reply.
use crate::sprintln;
use crate::virtio_net::{self, NET};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Interface counters for /proc/net/dev.
pub static RX_PKTS: AtomicU64 = AtomicU64::new(0);
pub static RX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static TX_PKTS: AtomicU64 = AtomicU64::new(0);
pub static TX_BYTES: AtomicU64 = AtomicU64::new(0);
static IFACE_UP: AtomicU64 = AtomicU64::new(1);

/// Administrative interface state (`ifconfig eth0 up/down`). When down the
/// rx pump drops every frame and transmit requests fail — a real carrier
/// flag, not cosmetic.
pub fn set_up(up: bool) {
    IFACE_UP.store(up as u64, Ordering::Relaxed);
}

pub fn is_up() -> bool {
    IFACE_UP.load(Ordering::Relaxed) != 0
}

/// `/proc/net/dev` body: real rx/tx counters for the virtio-net iface.
pub fn net_dev() -> String {
    alloc::format!(
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0:{:>8}{:>8}    0    0    0     0          0         0 {:>8}{:>8}    0    0    0     0       0          0\n    lo:{:>8}{:>8}    0    0    0     0          0         0 {:>8}{:>8}    0    0    0     0       0          0\n",
        RX_BYTES.load(Ordering::Relaxed),
        RX_PKTS.load(Ordering::Relaxed),
        TX_BYTES.load(Ordering::Relaxed),
        TX_PKTS.load(Ordering::Relaxed),
        LO_RX_BYTES.load(Ordering::Relaxed),
        LO_RX_PKTS.load(Ordering::Relaxed),
        LO_TX_BYTES.load(Ordering::Relaxed),
        LO_TX_PKTS.load(Ordering::Relaxed),
    )
}

/// Fallback IP when DHCP fails (slirp's static-assignment convention).
pub const DEFAULT_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];

/// Current configured IPv4 — set by DHCP at init, defaults to `DEFAULT_IP`.
static CUR_IP: Mutex<[u8; 4]> = Mutex::new(DEFAULT_IP);
pub fn our_ip() -> [u8; 4] {
    *CUR_IP.lock()
}

static ARP_CACHE: Mutex<Vec<([u8; 4], [u8; 6])>> = Mutex::new(Vec::new());

/// Loopback (`lo`): 127.0.0.0/8 and our own address deliver back into the
/// stack instead of the wire. Queued, not dispatched inline — TX paths may
/// run inside spin-lock scopes (TCP lock during a FIN), and inline
/// delivery would recurse into the same locks.
pub const LOOPBACK_IP: [u8; 4] = [127, 0, 0, 1];
fn is_loopback(ip: [u8; 4]) -> bool {
    ip[0] == 127 || ip == our_ip()
}
static LOOPBACK_Q: Mutex<VecDeque<([u8; 4], u8, Vec<u8>)>> = Mutex::new(VecDeque::new());
// lo interface counters (/proc/net/dev row is real, like eth0's)
static LO_RX_PKTS: AtomicU64 = AtomicU64::new(0);
static LO_RX_BYTES: AtomicU64 = AtomicU64::new(0);
static LO_TX_PKTS: AtomicU64 = AtomicU64::new(0);
static LO_TX_BYTES: AtomicU64 = AtomicU64::new(0);

/// Sleep until the next IRQ (timer ticks ~10ms) so waits burn no CPU and
/// `now_ms()` advances. Syscall context runs IF=0 (interrupt gate), so we
/// enable interrupts only for the hlt window — no locks held here, and IRQ
/// handlers never lock.
/// Halt until the next IRQ (PIT/virtio) with interrupts enabled, then
/// re-mask — the kernel's sleep primitive inside syscalls.
pub(crate) fn wait_irq() {
    unsafe { core::arch::asm!("sti; hlt; cli", options(nomem, nostack)) };
}

/// Next-hop MAC for `ip`: same-subnet addresses resolve directly, anything
/// else goes via the gateway (real routing, not ARP-for-the-world).
/// Kernel routing table — the real thing `next_hop` consults. Built
/// lazily from the configured IP so a DHCP lease lands in it too.
/// `gw == 0.0.0.0` = directly connected; `dev` names the interface.
pub struct Route {
    pub dest: [u8; 4],
    pub mask: [u8; 4],
    pub gw: [u8; 4],
    pub dev: &'static str,
}
static ROUTES: Mutex<Option<Vec<Route>>> = Mutex::new(None);

fn mask_to_u32(m: [u8; 4]) -> u32 {
    u32::from_be_bytes(m)
}
fn ip_to_u32(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes(ip)
}

fn default_routes() -> Vec<Route> {
    let me = our_ip();
    vec![
        Route { dest: [127, 0, 0, 0], mask: [255, 0, 0, 0], gw: [0; 4], dev: "lo" },
        Route {
            dest: [me[0], me[1], me[2], 0],
            mask: [255, 255, 255, 0],
            gw: [0; 4],
            dev: "eth0",
        },
        Route { dest: [0; 4], mask: [0; 4], gw: GW_IP, dev: "eth0" },
    ]
}

/// Drop the synthesized table (called when the configured IP changes —
/// the connected/default routes are rebuilt from the new lease).
pub fn routes_invalidate() {
    *ROUTES.lock() = None;
}

/// Longest-prefix match: returns the next-hop IP to ARP for (`dst` itself
/// on connected routes, `gw` on routed ones). None = no route.
fn route_lookup(ip: [u8; 4]) -> Option<[u8; 4]> {
    let mut g = ROUTES.lock();
    let r = g.get_or_insert_with(default_routes);
    let mut best: Option<&Route> = None;
    for rt in r.iter() {
        if ip_to_u32(ip) & mask_to_u32(rt.mask) == ip_to_u32(rt.dest) & mask_to_u32(rt.mask) {
            if best.map(|b| mask_to_u32(rt.mask) > mask_to_u32(b.mask)).unwrap_or(true) {
                best = Some(rt);
            }
        }
    }
    best.map(|rt| if rt.gw == [0; 4] { ip } else { rt.gw })
}

/// `/proc/net/route` in Linux's exact column format (hex, little-endian
/// fields like the real file: destination/mask as hex bytes).
pub fn net_route() -> String {
    let mut g = ROUTES.lock();
    let r = g.get_or_insert_with(default_routes);
    let mut out = String::from(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
    );
    for rt in r.iter() {
        let hx = |ip: [u8; 4]| -> u32 {
            u32::from_le_bytes(ip)
        };
        let flags = if rt.gw == [0; 4] { "0003" } else { "0007" }; // U+up / U+G+up
        out.push_str(&alloc::format!(
            "{}\t{:08X}\t{:08X}\t{}\t0\t0\t0\t{:08X}\t0\t0\t0\n",
            rt.dev,
            hx(rt.dest),
            hx(rt.gw),
            flags,
            hx(rt.mask)
        ));
    }
    out
}

/// `/proc/net/route` write grammar (kernel-side of `route add/del`):
///   "add <dest>/<plen> <gw|*>"   "del <dest>[/<plen>]"
/// `*` = connected (no gateway). Returns false on a parse miss.
pub fn route_ctl(line: &str) -> bool {
    let mut f = line.split_whitespace();
    let add = match f.next() {
        Some("add") => true,
        Some("del") => return route_del(f.next().unwrap_or("")),
        _ => return false,
    };
    let Some(spec) = f.next() else { return false };
    let (dest, plen) = match spec.split_once('/') {
        Some((d, p)) => (parse_ip(d), p.parse::<u32>().unwrap_or(32)),
        None => (parse_ip(spec), 32),
    };
    let Some(dest) = dest else { return false };
    if plen > 32 {
        return false;
    }
    let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
    let gw = match f.next() {
        Some("*") | None => [0; 4],
        Some(g) => match parse_ip(g) {
            Some(g) => g,
            None => return false,
        },
    };
    let _ = add;
    let mut g = ROUTES.lock();
    let r = g.get_or_insert_with(default_routes);
    // replace an exact existing route (dest+mask) — like RTM_NEWROUTE replace
    let mask_b = mask.to_be_bytes();
    r.retain(|rt| !(rt.dest == dest && rt.mask == mask_b));
    r.push(Route { dest, mask: mask_b, gw, dev: "eth0" });
    true
}

fn route_del(spec: &str) -> bool {
    let (dest, plen) = match spec.split_once('/') {
        Some((d, p)) => (parse_ip(d), p.parse::<u32>().unwrap_or(32)),
        None => (parse_ip(spec), 32),
    };
    let Some(dest) = dest else { return false };
    let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
    let mut g = ROUTES.lock();
    let r = g.get_or_insert_with(default_routes);
    let before = r.len();
    r.retain(|rt| !(rt.dest == dest && rt.mask == mask.to_be_bytes()));
    r.len() != before
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut i = 0;
    for part in s.split('.') {
        if i >= 4 {
            return None;
        }
        out[i] = part.parse().ok()?;
        i += 1;
    }
    (i == 4).then_some(out)
}

fn next_hop(ip: [u8; 4], timeout_ms: u64) -> Option<[u8; 6]> {
    if is_loopback(ip) {
        return Some([0; 6]); // looped at the IP layer — no next-hop
    }
    if is_bcast(ip) {
        return Some([0xFF; 6]); // broadcast: ff:ff:ff:ff:ff:ff, no ARP
    }
    let nh = route_lookup(ip)?; // no route -> unrouteable (EHOSTUNREACH)
    arp_resolve(nh, timeout_ms)
}

/// Broadcast destination: 255.255.255.255 or our subnet-directed .255.
pub fn is_bcast(ip: [u8; 4]) -> bool {
    if ip == [255, 255, 255, 255] {
        return true;
    }
    let me = our_ip();
    ip[0] == me[0] && ip[1] == me[1] && ip[2] == me[2] && ip[3] == 255
}

fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}
fn put16(b: &mut [u8], v: u16) {
    b[0] = (v >> 8) as u8;
    b[1] = v as u8;
}
fn csum(data: &[u8]) -> u16 {
    let mut s: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        s += be16(&data[i..]) as u32;
        i += 2;
    }
    if i < data.len() {
        s += (data[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

fn now_ms() -> u64 {
    crate::timer::uptime_ms()
}

/// Drain the device rx queue (and anything IRQ-drained) into the handlers.
/// Net is polled: virtio-net IRQs are not wired; wait loops `sti;hlt` so the
/// PIT keeps ticking and deadlines stay real.
/// Returns (ip_proto, transport_payload) for IPv4 frames addressed to us.
fn pump_rx() -> Vec<([u8; 4], u8, Vec<u8>)> {
    let mut out = Vec::new();
    let up = is_up();
    for f in virtio_net::take_rx() {
        if !up {
            continue; // interface down: drop frames like a real NIC
        }
        crate::pcap::log_frame(&f);
        RX_PKTS.fetch_add(1, Ordering::Relaxed);
        RX_BYTES.fetch_add(f.len() as u64, Ordering::Relaxed);
        if let Some(p) = handle_frame(&f) {
            out.push(p);
        }
    }
    if let Some(n) = NET.lock().clone() {
        let mut v = Vec::new();
        n.drain_rx(&mut v);
        for f in v {
            if !up {
                continue;
            }
            crate::pcap::log_frame(&f);
            RX_PKTS.fetch_add(1, Ordering::Relaxed);
            RX_BYTES.fetch_add(f.len() as u64, Ordering::Relaxed);
            if let Some(p) = handle_frame(&f) {
                out.push(p);
            }
        }
    }
    // lo packets ride the same (src, proto, payload) path — delivered even
    // when eth0 is down (loopback is its own interface)
    let mut lq = LOOPBACK_Q.lock();
    let n_loop = lq.len();
    for _ in 0..n_loop {
        if let Some(t) = lq.pop_front() {
            LO_RX_PKTS.fetch_add(1, Ordering::Relaxed);
            LO_RX_BYTES.fetch_add(t.2.len() as u64, Ordering::Relaxed);
            out.push(t);
        }
    }
    drop(lq);
    // ICMP: answer echo requests like a real host — wire or loopback
    for (src_ip, proto, p) in &out {
        if *proto == 1 && p.len() >= 8 && p[0] == 8 {
            icmp_echo_reply(*src_ip, p);
        }
    }
    // TCP keepalive: any conn opted in via SO_KEEPALIVE that hasn't heard
    // from its peer in 15s gets a bare ACK probe (seq = snd_una-1 — the
    // classic keepalive segment real stacks send).
    {
        let probes: Vec<([u8; 6], [u8; 4], u16, u16, u32, u32, u16, u16)> = {
            let mut t = TCP_SOCKS.lock();
            let mut v = Vec::new();
            for k in t.values_mut() {
                if k.ka
                    && k.state == TcpState::Open
                    && now_ms().saturating_sub(k.ka_rx) > 15_000
                {
                    k.ka_rx = now_ms(); // one probe per idle window
                    v.push((k.mac, k.rip, k.lport, k.rport,
                        k.snd_una.wrapping_sub(1), k.rcv_nxt, rx_win(k), k.cid));
                }
            }
            v
        };
        for (mac, rip, lp, rp, seq, ack, win, _cid) in probes {
            send_tcp(mac, rip, lp, rp, seq, ack, TCP_ACK, &[], win);
        }
    }
    // retransmit: the oldest unacked segment past its RTO resends — this
    // is what makes nowait writes and FINs reliable, not just hopeful
    {
        let now = now_ms();
        let mut resend: Vec<([u8; 6], [u8; 4], u16, u16, u32, u32, u8, Vec<u8>, u16)> =
            Vec::new();
        {
            let mut t = TCP_SOCKS.lock();
            for k in t.values_mut() {
                if k.state != TcpState::Open {
                    continue;
                }
                if let Some(u) = k.unacked.front_mut() {
                    if now.saturating_sub(u.tx_ms) >= 400 {
                        u.tx_ms = now;
                        resend.push((
                            k.mac, k.rip, k.lport, k.rport, u.seq, k.rcv_nxt,
                            u.flags, u.payload.clone(), rx_win(k),
                        ));
                    }
                }
            }
        }
        for (mac, rip, lp, rp, seq, ackn, fl, pay, win) in resend {
            sprintln!("[net] tcp retransmit :{} -> :{} {}B", lp, rp, pay.len());
            send_tcp(mac, rip, lp, rp, seq, ackn, fl, &pay, win);
        }
    }
    out
}

/// Build an echo reply for a received request and send it — to the wire
/// peer (mac from the ARP cache — absent = unreachable, drop) or straight
/// back into lo when the requester is us.
fn icmp_echo_reply(src_ip: [u8; 4], req: &[u8]) {
    let mut rep = Vec::with_capacity(req.len());
    rep.push(0); // echo reply
    rep.push(0);
    rep.extend_from_slice(&[0u8; 2]);
    rep.extend_from_slice(&req[4..]); // id + seq + data verbatim
    let c = csum(&rep);
    put16(&mut rep[2..], c);
    if is_loopback(src_ip) {
        send_ip_src(LOOPBACK_IP, [0; 6], src_ip, 1, &rep);
    } else {
        let mac = {
            let c = ARP_CACHE.lock();
            c.iter().find(|e| e.0 == src_ip).map(|e| e.1)
        };
        if let Some(mac) = mac {
            send_ip(mac, src_ip, 1, &rep);
        }
    }
}

/// ICMP 3/3 port-unreachable, sent when a UDP datagram hits a port nobody
/// owns — the real response a host gives, and what a tracer probe to an
/// unbound port on ourselves answers with. `orig_udp` is the offending
/// UDP segment (header included); the quote rebuilds its IPv4 header since
/// handle_frame has already stripped it (proto/ports/addresses all exact).
fn icmp_port_unreach(sender: [u8; 4], orig_udp: &[u8]) {
    if sender == [0, 0, 0, 0] || is_bcast(sender) || (sender[0] == 224) {
        return; // never send errors to bcast/mcast/unspecified sources
    }
    let mut icmp = Vec::with_capacity(8 + 20 + 8);
    icmp.push(3); // destination unreachable
    icmp.push(3); // port unreachable
    icmp.extend_from_slice(&[0u8; 2]);
    icmp.extend_from_slice(&[0u8; 4]); // unused
    // quote: reconstructed IPv4 header of the offending packet
    icmp.push(0x45);
    icmp.push(0);
    icmp.extend_from_slice(&((20 + orig_udp.len()) as u16).to_be_bytes());
    icmp.extend_from_slice(&[0u8; 4]);
    icmp.push(64);
    icmp.push(17);
    icmp.extend_from_slice(&[0u8; 2]);
    icmp.extend_from_slice(&sender);
    icmp.extend_from_slice(&if is_loopback(sender) { LOOPBACK_IP } else { our_ip() });
    icmp.extend_from_slice(&orig_udp[..orig_udp.len().min(8)]);
    let c = csum(&icmp);
    put16(&mut icmp[2..], c);
    if is_loopback(sender) {
        send_ip_src(LOOPBACK_IP, [0; 6], sender, 1, &icmp);
    } else {
        let mac = {
            let c = ARP_CACHE.lock();
            c.iter().find(|e| e.0 == sender).map(|e| e.1)
        };
        if let Some(mac) = mac {
            send_ip(mac, sender, 1, &icmp);
        }
    }
}

/// If an ICMP error (type 11 time-exceeded or type 3 unreachable) quotes
/// one of our tracer probes, return (probe_dport, orig_dst). The quoted
/// original IPv4 header starts at byte 8 of the ICMP payload.
fn icmp_probe_ports(p: &[u8]) -> Option<(u16, [u8; 4])> {
    if p.len() < 36 || (p[0] != 11 && p[0] != 3) {
        return None;
    }
    let ip = &p[8..];
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    let ihl = ((ip[0] & 0xF) as usize) * 4;
    if ip.len() < ihl + 8 {
        return None;
    }
    let sport = be16(&ip[ihl..]);
    let dport = be16(&ip[ihl + 2..]);
    if sport != TRACER_SPORT {
        return None;
    }
    let dst: [u8; 4] = ip[16..20].try_into().ok()?;
    Some((dport, dst))
}

const TRACER_SPORT: u16 = 0x8342;

/// Traceroute: UDP probes to `dst` port 33434+ttl with rising TTLs.
/// Returns per-hop (ttl, Some((hop_ip, rtt_ms)) on ICMP-11, reached=true
/// when the target itself answers ICMP 3/3). Each hop waits `per_ms`.
pub fn net_trace(
    dst: [u8; 4],
    max_hops: u8,
    per_ms: u64,
) -> Vec<(u8, Option<([u8; 4], u64)>, bool)> {
    let mut hops = Vec::new();
    let Some(mac) = next_hop(dst, 1500) else {
        return hops;
    };
    for ttl in 1..=max_hops.min(30) {
        let dport = 33434u16.wrapping_add(ttl as u16);
        let t0 = now_ms();
        send_udp_ttl(mac, dst, TRACER_SPORT, dport, b"cosmos-trace", ttl);
        let mut hit: Option<([u8; 4], bool)> = None;
        while now_ms() - t0 < per_ms && hit.is_none() {
            for (src_ip, proto, p) in pump_rx() {
                if proto != 1 {
                    dispatch(src_ip, proto, p); // feed real sockets mid-run
                    continue;
                }
                let Some((dp, odst)) = icmp_probe_ports(&p) else {
                    continue;
                };
                if dp == dport && odst == dst {
                    hit = Some((src_ip, p[0] == 3));
                }
            }
            if hit.is_none() {
                wait_irq();
            }
        }
        let reached = hit.map(|h| h.1).unwrap_or(false);
        hops.push((ttl, hit.map(|(ip, _)| (ip, now_ms() - t0)), reached));
        if reached {
            break;
        }
    }
    hops
}

fn send_frame(dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Result<(), ()> {
    if !is_up() {
        return Err(()); // interface administratively down
    }
    let Some(n) = NET.lock().clone() else { return Err(()) };
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&n.mac);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    TX_PKTS.fetch_add(1, Ordering::Relaxed);
    TX_BYTES.fetch_add(f.len() as u64, Ordering::Relaxed);
    n.send(&f)
}

fn send_arp_request(target: [u8; 4]) {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes()); // htype eth
    p.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype ipv4
    p.push(6);
    p.push(4);
    p.extend_from_slice(&1u16.to_be_bytes()); // op request
    if let Some(n) = NET.lock().clone() {
        p.extend_from_slice(&n.mac);
    } else {
        return;
    }
    p.extend_from_slice(&our_ip());
    p.extend_from_slice(&[0u8; 6]);
    p.extend_from_slice(&target);
    let _ = send_frame([0xFF; 6], 0x0806, &p);
}

fn send_arp_reply(dst_mac: [u8; 6], dst_ip: [u8; 4]) {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&0x0800u16.to_be_bytes());
    p.push(6);
    p.push(4);
    p.extend_from_slice(&2u16.to_be_bytes()); // op reply
    if let Some(n) = NET.lock().clone() {
        p.extend_from_slice(&n.mac);
    } else {
        return;
    }
    p.extend_from_slice(&our_ip());
    p.extend_from_slice(&dst_mac);
    p.extend_from_slice(&dst_ip);
    let _ = send_frame(dst_mac, 0x0806, &p);
}

fn send_icmp_echo(dst_mac: [u8; 6], dst_ip: [u8; 4], id: u16, seq: u16, payload: &[u8]) {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // echo request
    icmp.push(0);
    icmp.extend_from_slice(&[0u8; 2]); // csum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = csum(&icmp);
    put16(&mut icmp[2..], c);
    send_ip(dst_mac, dst_ip, 1, &icmp);
}

/// Handle one ethernet frame: ARP cache/reply, or deliver an IPv4 payload.
/// Returns Some((ip_proto, transport_payload)) when the frame carried IPv4
/// addressed to our IP.
fn handle_frame(f: &[u8]) -> Option<([u8; 4], u8, Vec<u8>)> {
    if f.len() < 14 {
        return None;
    }
    let et = be16(&f[12..]);
    match et {
        0x0806 => {
            if f.len() < 42 {
                return None;
            }
            let p = &f[14..];
            let op = be16(&p[6..]);
            let sender_mac: [u8; 6] = p[8..14].try_into().ok()?;
            let sender_ip: [u8; 4] = p[14..18].try_into().ok()?;
            let target_ip: [u8; 4] = p[24..28].try_into().ok()?;
            // cache the sender
            let mut c = ARP_CACHE.lock();
            if let Some(e) = c.iter_mut().find(|e| e.0 == sender_ip) {
                e.1 = sender_mac;
            } else {
                c.push((sender_ip, sender_mac));
            }
            drop(c);
            if op == 1 && target_ip == our_ip() {
                send_arp_reply(sender_mac, sender_ip);
            }
            None
        }
        0x0800 => {
            let ip = &f[14..];
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((ip[0] & 0xF) as usize) * 4;
            if ip.len() < ihl {
                return None;
            }
            let dst: [u8; 4] = ip[16..20].try_into().ok()?;
            // unicast to us, or broadcast (DHCP replies arrive before we
            // own an address)
            if dst != our_ip() && dst != [255, 255, 255, 255] {
                return None;
            }
            let src: [u8; 4] = ip[12..16].try_into().ok()?;
            Some((src, ip[9], ip[ihl..].to_vec()))
        }
        _ => None,
    }
}

/// Resolve an IPv4 address to a MAC via ARP. Polls up to `ms` milliseconds.
fn arp_resolve(ip: [u8; 4], ms: u64) -> Option<[u8; 6]> {
    if is_loopback(ip) {
        return Some([0; 6]); // lo has no link layer
    }
    {
        let c = ARP_CACHE.lock();
        if let Some(e) = c.iter().find(|e| e.0 == ip) {
            return Some(e.1);
        }
    }
    let deadline = now_ms() + ms;
    send_arp_request(ip);
    loop {
        let _ = pump_rx();
        {
            let c = ARP_CACHE.lock();
            if let Some(e) = c.iter().find(|e| e.0 == ip) {
                return Some(e.1);
            }
        }
        if now_ms() >= deadline {
            return None;
        }
        wait_irq();
    }
}

/// Dump the ARP cache as text lines (for `arp`).
/// Remove an ARP cache entry (`arp -d`). Returns true when one was deleted.
pub fn arp_del(ip: [u8; 4]) -> bool {
    let mut c = ARP_CACHE.lock();
    let n = c.len();
    c.retain(|(i, _)| *i != ip);
    c.len() != n
}

pub fn arp_stat() -> String {
    let c = ARP_CACHE.lock();
    let mut s = String::from("ip              mac\n");
    for (ip, mac) in c.iter() {
        s.push_str(&alloc::format!(
            "{}.{}.{}.{}\t{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            ip[0], ip[1], ip[2], ip[3],
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));
    }
    if c.is_empty() {
        s.push_str("(empty)\n");
    }
    s
}

/// `ping <ip>`: ARP-resolve, send one ICMP echo request, wait for the reply.
/// Returns rtt in milliseconds, or None on timeout/unreachable.
pub fn ping(ip: [u8; 4], timeout_ms: u64) -> Option<u64> {
    if NET.lock().is_none() {
        sprintln!("[net] ping: no device");
        return None;
    }
    let me = our_ip();
    let on_net = ip[0] == me[0] && ip[1] == me[1] && ip[2] == me[2];
    let arp_for = if on_net { ip } else { GW_IP };
    let dst_mac = arp_resolve(arp_for, 1500)?;
    sprintln!(
        "[net] arp {}.{}.{}.{} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        arp_for[0], arp_for[1], arp_for[2], arp_for[3],
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
    );
    let id = 0xC050u16;
    let seq = 1u16;
    let payload = b"cosmos-ping-payload-0123456789abcdef";
    let t0 = now_ms();
    send_icmp_echo(dst_mac, ip, id, seq, payload);
    loop {
        for (_src_ip, proto, p) in pump_rx() {
            if proto == 1 && p.len() >= 8 && p[0] == 0 && be16(&p[4..]) == id && be16(&p[6..]) == seq {
                return Some(now_ms() - t0);
            }
        }
        if now_ms() - t0 >= timeout_ms {
            return None;
        }
        wait_irq();
    }
}

fn send_ip(dst_mac: [u8; 6], dst_ip: [u8; 4], proto: u8, payload: &[u8]) {
    // a packet to a 127/8 address originates from the loopback address —
    // same rule as Linux's route-local delivery, so peers see 127.0.0.1
    let src = if dst_ip[0] == 127 { LOOPBACK_IP } else { our_ip() };
    send_ip_src(src, dst_mac, dst_ip, proto, payload);
}

fn send_ip_src(src_ip: [u8; 4], dst_mac: [u8; 6], dst_ip: [u8; 4], proto: u8, payload: &[u8]) {
    send_ip_src_ttl(src_ip, dst_mac, dst_ip, proto, 64, payload)
}

fn send_ip_src_ttl(
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    proto: u8,
    ttl: u8,
    payload: &[u8],
) {
    if is_loopback(dst_ip) {
        // lo: no ethernet, no ARP — the datagram re-enters rx as-is
        LOOPBACK_Q.lock().push_back((src_ip, proto, payload.to_vec()));
        LO_TX_PKTS.fetch_add(1, Ordering::Relaxed);
        LO_TX_BYTES.fetch_add(payload.len() as u64, Ordering::Relaxed);
        return;
    }
    let mut ip = Vec::with_capacity(20 + payload.len());
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&1u16.to_be_bytes());
    ip.extend_from_slice(&[0u8; 2]);
    ip.push(ttl);
    ip.push(proto);
    ip.extend_from_slice(&[0u8; 2]);
    ip.extend_from_slice(&src_ip);
    ip.extend_from_slice(&dst_ip);
    let c = csum(&ip);
    put16(&mut ip[10..], c);
    ip.extend_from_slice(payload);
    let _ = send_frame(dst_mac, 0x0800, &ip);
}

/// UDP send (IPv4 UDP checksum is optional — 0 means "none").
fn send_udp(dst_mac: [u8; 6], dst_ip: [u8; 4], sport: u16, dport: u16, payload: &[u8]) {
    send_udp_ttl(dst_mac, dst_ip, sport, dport, payload, 64)
}

fn send_udp_ttl(
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
    ttl: u8,
) {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0u8; 2]); // checksum disabled (valid in IPv4)
    udp.extend_from_slice(payload);
    let src = if dst_ip[0] == 127 { LOOPBACK_IP } else { our_ip() };
    send_ip_src_ttl(src, dst_mac, dst_ip, 17, ttl, &udp);
}

/// Skip a DNS name (labels or a compression pointer) starting at `i`.
/// Returns index just past it.
fn dns_skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *m.get(i)?;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(i + 2); // compression pointer
        }
        i += 1 + l as usize;
    }
}

/// `resolve <hostname>`: real DNS A-record query to the slirp resolver
/// (10.0.2.3:53) over real UDP. Returns the first A record.
pub fn dns_query(name: &str, timeout_ms: u64) -> Option<[u8; 4]> {
    // nsswitch order: /etc/hosts file first, then wire DNS — same as a
    // real resolver. Lines: `a.b.c.d name [alias...]` (+ `#` comments).
    if let Ok(h) = crate::vfs::read_all("/etc/hosts") {
        if let Ok(text) = core::str::from_utf8(&h) {
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("");
                let mut f = line.split_whitespace();
                let Some(ip) = f.next() else { continue };
                let mut oct = ip.split('.');
                let mut v = [0u8; 4];
                let mut ok = true;
                for o in v.iter_mut() {
                    match oct.next().and_then(|s| s.parse::<u8>().ok()) {
                        Some(n) => *o = n,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok || oct.next().is_some() {
                    continue;
                }
                if f.any(|a| a == name) {
                    sprintln!("[net] hosts: '{}' -> {}.{}.{}.{}", name, v[0], v[1], v[2], v[3]);
                    return Some(v);
                }
            }
        }
    }
    const DNS: [u8; 4] = [10, 0, 2, 3];
    const SPORT: u16 = 43210;
    let txid = 0xC05Au16;
    // build query: hdr + qname labels + qtype A + qclass IN
    let mut q = Vec::new();
    q.extend_from_slice(&txid.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0u8; 6]); // an/ns/ar = 0
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN

    // ride the socket abstraction: bind, sendto, recvfrom
    udp_open(SPORT).ok()?;
    udp_send(SPORT, DNS, 53, &q).ok()?;
    sprintln!("[net] dns query '{}' -> 10.0.2.3:53", name);

    let t0 = now_ms();
    let out = loop {
        let Some((_src_ip, sport, m)) = udp_recv(SPORT, timeout_ms) else {
            break None;
        };
        let m = m.as_slice();
        if sport != 53 || m.len() < 12 {
            if now_ms() - t0 >= timeout_ms {
                break None;
            }
            continue;
        }
        if be16(&m[0..]) != txid || m[2] & 0x80 == 0 {
            if now_ms() - t0 >= timeout_ms {
                break None;
            }
            continue; // not our reply
        }
        let ancount = be16(&m[6..]) as usize;
        let qdcount = be16(&m[4..]) as usize;
        let mut i = 12;
        let mut bad = false;
        for _ in 0..qdcount {
            match dns_skip_name(m, i) {
                Some(ni) => i = ni + 4,
                None => bad = true,
            }
            if bad {
                break;
            }
        }
        if bad {
            break None;
        }
        let mut found: Option<[u8; 4]> = None;
        for _ in 0..ancount {
            match dns_skip_name(m, i) {
                Some(ni) => i = ni,
                None => {
                    bad = true;
                    break;
                }
            }
            if m.len() < i + 10 {
                bad = true;
                break;
            }
            let rtype = be16(&m[i..]);
            let rdlen = be16(&m[i + 8..]) as usize;
            if rtype == 1 && rdlen == 4 && m.len() >= i + 10 + 4 {
                found = Some(m[i + 10..i + 14].try_into().unwrap());
                break;
            }
            i += 10 + rdlen;
        }
        if bad {
            break None;
        }
        if let Some(ip) = found {
            sprintln!(
                "[net] dns '{}' -> {}.{}.{}.{}",
                name, ip[0], ip[1], ip[2], ip[3]
            );
            break Some(ip);
        }
        if now_ms() - t0 >= timeout_ms {
            break None;
        }
    };
    udp_close(SPORT);
    out
}

// ---------------------------------------------------------------------------
// TCP — minimal real implementation: handshake, seq/ack tracking,
// stop-and-wait retransmit, FIN teardown. Enough for HTTP over slirp.
// ---------------------------------------------------------------------------

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

fn tcp_csum(src: [u8; 4], dst: [u8; 4], seg: &[u8]) -> u16 {
    // pseudo-header: src,dst,zero,proto,len  +  segment
    let mut ph = Vec::with_capacity(12 + seg.len());
    ph.extend_from_slice(&src);
    ph.extend_from_slice(&dst);
    ph.push(0);
    ph.push(6);
    ph.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    ph.extend_from_slice(seg);
    csum(&ph)
}

fn send_tcp(
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    win: u16,
) {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(0x50); // data offset 5 (no options)
    seg.push(flags);
    seg.extend_from_slice(&win.to_be_bytes()); // advertised rx window
    seg.extend_from_slice(&[0u8; 2]); // checksum
    seg.extend_from_slice(&[0u8; 2]); // urg
    seg.extend_from_slice(payload);
    let src = if dst_ip[0] == 127 { LOOPBACK_IP } else { our_ip() };
    let c = tcp_csum(src, dst_ip, &seg);
    put16(&mut seg[16..], c);
    send_ip(dst_mac, dst_ip, 6, &seg);
}

struct TcpSeg {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn parse_tcp(p: &[u8]) -> Option<TcpSeg> {
    if p.len() < 20 {
        return None;
    }
    let doff = ((p[12] >> 4) as usize) * 4;
    if p.len() < doff {
        return None;
    }
    Some(TcpSeg {
        sport: be16(&p[0..]),
        dport: be16(&p[2..]),
        seq: u32::from_be_bytes(p[4..8].try_into().ok()?),
        ack: u32::from_be_bytes(p[8..12].try_into().ok()?),
        flags: p[13],
        payload: p[doff..].to_vec(),
    })
}

/// Blocking minimal HTTP GET: `http_get(ip, "example.com", "/")`.
/// Returns the response bytes (header + body prefix). Real TCP through
/// slirp to the live internet.
/// GET over a real TCP socket — now just a consumer of the socket layer,
/// like dns_query rides UdpSock.
pub fn http_get(dst_ip: [u8; 4], host: &str, port: u16, path: &str) -> Option<Vec<u8>> {
    const SPORT: u16 = 49200;
    tcp_open(SPORT, dst_ip, port, 3000).ok()?;
    // Host header carries the port only when non-default (HTTP/1.0/1.1 rules)
    let hosthdr = if port == 80 {
        alloc::format!("{}", host)
    } else {
        alloc::format!("{}:{}", host, port)
    };
    let req = alloc::format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, hosthdr
    );
    if tcp_send(SPORT, req.as_bytes(), 4000).is_err() {
        tcp_close(SPORT);
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let deadline = now_ms() + 8000;
    while now_ms() < deadline {
        match tcp_recv(SPORT, 1000) {
            Some(chunk) => out.extend_from_slice(&chunk),
            None => break, // peer closed (FIN/RST)
        }
    }
    tcp_close(SPORT);
    sprintln!("[net] tcp closed, {} bytes received", out.len());
    if out.is_empty() { None } else { Some(out) }
}

/// `netstat`-style dump of the socket tables.
pub fn sockstat() -> String {
    let mut s = String::new();
    for (p, q) in SOCKS.lock().iter() {
        s.push_str(&alloc::format!("udp  :{} ({} queued)\n", p, q.len()));
    }
    for (p, k) in TCP_SOCKS.lock().iter() {
        s.push_str(&alloc::format!(
            "tcp  :{} -> {}.{}.{}.{}:{} {:?}\n",
            p, k.rip[0], k.rip[1], k.rip[2], k.rip[3], k.rport, k.state
        ));
    }
    for p in LISTENERS.lock().iter() {
        s.push_str(&alloc::format!("tcp  :{} LISTEN\n", p));
    }
    if s.is_empty() {
        s.push_str("no sockets open\n");
    }
    s
}

/// (mac, ip) for `ifconfig`-style reporting.
pub fn info() -> Option<([u8; 6], [u8; 4])> {
    NET.lock().as_ref().map(|n| (n.mac, our_ip()))
}

/// Linux-style `/proc/net/tcp` dump: hex little-endian addr:port + state code.
pub fn net_tcp() -> String {
    fn hexaddr(ip: [u8; 4], port: u16) -> String {
        alloc::format!(
            "{:02X}{:02X}{:02X}{:02X}:{:04X}",
            ip[3], ip[2], ip[1], ip[0], port
        )
    }
    fn stcode(s: &TcpState) -> u8 {
        match s {
            TcpState::Open => 0x01,
            TcpState::SynSent => 0x02,
            TcpState::SynRecv => 0x03,
            TcpState::Closed => 0x07,
        }
    }
    let lip = our_ip();
    let mut s = String::from("  sl  local_address rem_address   st tx_queue rx_queue\n");
    let mut i = 0u32;
    for (p, k) in TCP_SOCKS.lock().iter() {
        let txq: usize = k.unacked.iter().map(|u| u.payload.len()).sum();
        s.push_str(&alloc::format!(
            "  {:>2}: {} {} {:02X} {:08X}:{:08X}\n",
            i,
            hexaddr(lip, *p),
            hexaddr(k.rip, k.rport),
            stcode(&k.state),
            txq, // real unacked bytes, like /proc/net/tcp's tx_queue
            k.q.iter().map(|c| c.len()).sum::<usize>(),
        ));
        i += 1;
    }
    for p in LISTENERS.lock().iter() {
        s.push_str(&alloc::format!(
            "  {:>2}: {} 00000000:0000 0A 00000000:00000000\n",
            i,
            hexaddr(lip, *p)
        ));
        i += 1;
    }
    s
}

/// Linux-style `/proc/net/udp` dump.
/// Socket ownership table for `netstat -p` and /proc/net/owners:
/// one line per socket as "{tcp|udp|listen} {lport} {owner-pid}".
pub fn net_owners() -> String {
    let mut s = String::new();
    for (_, k) in TCP_SOCKS.lock().iter() {
        s.push_str(&alloc::format!("tcp {} {}\n", k.lport, k.owner));
    }
    for (p, o) in UDP_OWNERS.lock().iter() {
        s.push_str(&alloc::format!("udp {} {}\n", p, o));
    }
    for (p, o) in LISTEN_OWNERS.lock().iter() {
        s.push_str(&alloc::format!("listen {} {}\n", p, o));
    }
    s
}

pub fn net_udp() -> String {
    let lip = our_ip();
    let mut s = String::from("  sl  local_address rem_address   st tx_queue rx_queue\n");
    for (i, (p, _)) in SOCKS.lock().iter().enumerate() {
        s.push_str(&alloc::format!(
            "  {:>2}: {:02X}{:02X}{:02X}{:02X}:{:04X} 00000000:0000 07 00000000:00000000\n",
            i, lip[3], lip[2], lip[1], lip[0], p
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// DHCP — real DISCOVER/OFFER/REQUEST/ACK to configure CUR_IP.
// ---------------------------------------------------------------------------

const DHCP_XID: u32 = 0xC050_D00D;

fn dhcp_packet(msg_type: u8, offered: Option<[u8; 4]>, server: Option<[u8; 4]>) -> Vec<u8> {
    let n = NET.lock().clone().expect("net dev");
    let mut p = Vec::with_capacity(300);
    p.push(1); // op BOOTREQUEST
    p.push(1); // htype eth
    p.push(6); // hlen
    p.push(0); // hops
    p.extend_from_slice(&DHCP_XID.to_be_bytes());
    p.extend_from_slice(&[0u8; 2]); // secs
    p.extend_from_slice(&0x8000u16.to_be_bytes()); // broadcast flag
    p.extend_from_slice(&[0u8; 4]); // ciaddr
    p.extend_from_slice(&[0u8; 4]); // yiaddr (server fills)
    p.extend_from_slice(&[0u8; 4]); // siaddr
    p.extend_from_slice(&[0u8; 4]); // giaddr
    p.extend_from_slice(&n.mac);
    p.extend_from_slice(&[0u8; 10]); // chaddr pad
    p.extend_from_slice(&[0u8; 64]); // sname
    p.extend_from_slice(&[0u8; 128]); // file
    p.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    p.extend_from_slice(&[53, 1, msg_type]); // DHCP message type
    if let Some(ip) = offered {
        p.extend_from_slice(&[50, 4]); // requested IP
        p.extend_from_slice(&ip);
    }
    if let Some(ip) = server {
        p.extend_from_slice(&[54, 4]); // server id
        p.extend_from_slice(&ip);
    }
    p.extend_from_slice(&[55, 3, 1, 3, 6]); // param req: subnet, router, dns
    p.push(255); // end
    while p.len() < 300 {
        p.push(0);
    }
    p
}

fn dhcp_send(payload: &[u8]) {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&68u16.to_be_bytes()); // client port
    udp.extend_from_slice(&67u16.to_be_bytes()); // server port
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0u8; 2]);
    udp.extend_from_slice(payload);
    send_ip_src(
        [0, 0, 0, 0],
        [0xFF; 6],
        [255, 255, 255, 255],
        17,
        &udp,
    );
}

/// Parse a DHCP reply: (msg_type, yiaddr, server_id) or None.
fn dhcp_parse(udp: &[u8]) -> Option<(u8, [u8; 4], Option<[u8; 4]>)> {
    if udp.len() < 244 {
        return None;
    }
    if udp[0] != 2 || udp[2] != 6 {
        return None; // BOOTREPLY, eth
    }
    if u32::from_be_bytes(udp[4..8].try_into().ok()?) != DHCP_XID {
        return None;
    }
    if &udp[236..240] != &[99, 130, 83, 99] {
        return None;
    }
    let yiaddr: [u8; 4] = udp[16..20].try_into().ok()?;
    let mut msg = 0u8;
    let mut server = None;
    let mut i = 240;
    while i + 2 <= udp.len() {
        let (opt, len) = (udp[i], udp[i + 1] as usize);
        if opt == 255 {
            break;
        }
        if i + 2 + len > udp.len() {
            break;
        }
        match opt {
            53 if len == 1 => msg = udp[i + 2],
            54 if len == 4 => server = udp[i + 2..i + 6].try_into().ok(),
            _ => {}
        }
        i += 2 + len;
    }
    Some((msg, yiaddr, server))
}

fn dhcp_recv(want_type: u8, deadline: u64) -> Option<([u8; 4], Option<[u8; 4]>)> {
    while now_ms() < deadline {
        for (_src_ip, proto, p) in pump_rx() {
            if proto != 17 || p.len() < 8 {
                continue;
            }
            if be16(&p[0..]) != 67 || be16(&p[2..]) != 68 {
                continue;
            }
            if let Some((msg, yiaddr, server)) = dhcp_parse(&p[8..]) {
                if msg == want_type {
                    return Some((yiaddr, server));
                }
            }
        }
        wait_irq();
    }
    None
}

/// Real DHCP lease. On success updates `our_ip()` and logs the lease.
pub fn dhcp() -> Option<[u8; 4]> {
    // DISCOVER -> OFFER
    dhcp_send(&dhcp_packet(1, None, None));
    let (offer, server) = dhcp_recv(2, now_ms() + 3000)?;
    sprintln!(
        "[net] dhcp offer {}.{}.{}.{}",
        offer[0], offer[1], offer[2], offer[3]
    );
    // REQUEST -> ACK
    dhcp_send(&dhcp_packet(3, Some(offer), server));
    let (ack_ip, _) = dhcp_recv(5, now_ms() + 3000)?;
    *CUR_IP.lock() = ack_ip;
    routes_invalidate(); // rebuild synthesized routes on the new lease
    sprintln!(
        "[net] dhcp lease {}.{}.{}.{}",
        ack_ip[0], ack_ip[1], ack_ip[2], ack_ip[3]
    );
    Some(ack_ip)
}

// ---------------------------------------------------------------------------
// UDP socket abstraction — spec's "basic socket abstraction". A socket is a
// bound local port with a received-datagram queue; dns_query rides on it.
// ---------------------------------------------------------------------------

const MAX_SOCK_Q: usize = 32;
static SOCKS: Mutex<BTreeMap<u16, VecDeque<([u8; 4], u16, Vec<u8>)>>> =
    Mutex::new(BTreeMap::new());
/// Port -> number of bound holders; >1 only via SO_REUSEADDR joins
/// (udp_open_share). The port's queue dies when the count hits 0.
static UDP_SHARES: Mutex<BTreeMap<u16, u32>> = Mutex::new(BTreeMap::new());

/// Bind a local UDP port. Err(-1) if already bound.
pub fn udp_open(lport: u16) -> Result<(), i64> {
    let mut s = SOCKS.lock();
    if s.contains_key(&lport) {
        return Err(-1);
    }
    s.insert(lport, VecDeque::new());
    UDP_SHARES.lock().insert(lport, 1);
    UDP_OWNERS
        .lock()
        .insert(lport, crate::task::with_current(|t| t.id));
    Ok(())
}

/// Second+ binder joining an existing UDP port under SO_REUSEADDR:
/// incoming datagrams land in the shared queue — whichever task reads
/// first wins, like a one-member REUSEPORT group.
pub fn udp_open_share(lport: u16) -> Result<(), i64> {
    let mut sh = UDP_SHARES.lock();
    if !SOCKS.lock().contains_key(&lport) {
        return Err(-1);
    }
    *sh.entry(lport).or_insert(0) += 1;
    Ok(())
}

/// sockfd close path: decrement the share count; the queue (and port)
/// only dies when the last binder leaves.
pub fn udp_close_one(lport: u16) {
    let mut sh = UDP_SHARES.lock();
    match sh.get(&lport).copied() {
        Some(n) if n > 1 => {
            sh.insert(lport, n - 1);
        }
        _ => {
            sh.remove(&lport);
            drop(sh);
            SOCKS.lock().remove(&lport);
            UDP_OWNERS.lock().remove(&lport);
        }
    }
}

pub fn udp_close(lport: u16) {
    SOCKS.lock().remove(&lport);
    UDP_SHARES.lock().remove(&lport);
    UDP_OWNERS.lock().remove(&lport);
}

/// MSG_PEEK for UDP sockets: copy the front datagram's (src_ip, sport,
/// payload) WITHOUT popping it.
pub fn udp_peek(lport: u16) -> Option<([u8; 4], u16, Vec<u8>)> {
    SOCKS.lock().get(&lport).and_then(|q| q.front().cloned())
}

/// Send a datagram from `lport` to `dst_ip:dst_port` (real ARP next-hop).
pub fn udp_send(lport: u16, dst_ip: [u8; 4], dport: u16, payload: &[u8]) -> Result<(), i64> {
    udp_send_ttl(lport, dst_ip, dport, payload, 64)
}

/// `udp_send` with an explicit TTL — SO_IP_TTL / traceroute-grade probes.
pub fn udp_send_ttl(
    lport: u16,
    dst_ip: [u8; 4],
    dport: u16,
    payload: &[u8],
    ttl: u8,
) -> Result<(), i64> {
    if !SOCKS.lock().contains_key(&lport) {
        return Err(-2); // not bound
    }
    let Some(mac) = next_hop(dst_ip, 1500) else {
        return Err(-3);
    };
    send_udp_ttl(mac, dst_ip, lport, dport, payload, ttl);
    Ok(())
}

/// Blocking recvfrom: returns (src_ip, src_port, payload). Datagrams for the
/// bound port are consumed from the wire in order; others are dropped (the
/// stack is cooperative — at most one task waits on packets at a time).
pub fn udp_recv(lport: u16, timeout_ms: u64) -> Option<([u8; 4], u16, Vec<u8>)> {
    // already-queued datagram first
    if let Some(d) = SOCKS.lock().get_mut(&lport).and_then(|q| q.pop_front()) {
        return Some(d);
    }
    // one non-blocking pump even at timeout=0 — poll-style callers (nc -u,
    // nc -lu) must still move NIC-ring packets into the socket queues
    for (src_ip, proto, p) in pump_rx() {
        dispatch(src_ip, proto, p);
    }
    if let Some(d) = SOCKS.lock().get_mut(&lport).and_then(|q| q.pop_front()) {
        return Some(d);
    }
    let deadline = now_ms() + timeout_ms;
    while now_ms() < deadline {
        for (src_ip, proto, p) in pump_rx() {
            dispatch(src_ip, proto, p);
        }
        if let Some(d) = SOCKS.lock().get_mut(&lport).and_then(|q| q.pop_front()) {
            return Some(d);
        }
        wait_irq();
    }
    None
}

pub fn udp_bound(lport: u16) -> bool {
    SOCKS.lock().contains_key(&lport)
}

// ---------------------------------------------------------------------------
// Socket dispatch — every packet a wait loop pumps feeds the socket tables
// (UDP dgram -> SOCKS queue, TCP seg -> TCP_SOCKS feed). Returns false for
// traffic no socket claimed (ICMP replies, broadcast UDP, unmatched TCP) so
// raw consumers (ping, dhcp) still see it.
// ---------------------------------------------------------------------------

fn dispatch(src_ip: [u8; 4], proto: u8, p: Vec<u8>) -> bool {
    match proto {
        17 if p.len() >= 8 => {
            let dport = be16(&p[2..]);
            let mut socks = SOCKS.lock();
            match socks.get_mut(&dport) {
                Some(q) => {
                    if q.len() < MAX_SOCK_Q {
                        q.push_back((src_ip, be16(&p[0..]), p[8..].to_vec()));
                    }
                    true
                }
                None => {
                    drop(socks);
                    icmp_port_unreach(src_ip, &p); // real host answer: ICMP 3/3
                    false
                }
            }
        }
        6 => {
            let Some(s) = parse_tcp(&p) else {
                return false;
            };
            let mut t = TCP_SOCKS.lock();
            // accepted conns are matched by (rip, rport, lport) — the map
            // key is synthetic so many clients can share one listener port
            match t
                .values_mut()
                .find(|k| k.rip == src_ip && k.rport == s.sport && k.lport == s.dport)
            {
                Some(k) => {
                    tcp_feed(k, &s);
                    return true;
                }
                None => {}
            }
            drop(t);
            // inbound SYN on a listening port -> open a server-side conn
            if s.flags & TCP_SYN != 0 && s.flags & TCP_ACK == 0
                && LISTENERS.lock().contains(&s.dport)
            {
                accept_syn(&s, src_ip);
                return true;
            }
            // unclaimed TCP port: RST the peer — a real ECONNREFUSED,
            // not a silent drop (also refuse our own lo probes)
            if s.flags & TCP_RST == 0 {
                tcp_rst(src_ip, &s);
            }
            false
        }
        _ => false,
    }
}

/// Reply to a segment aimed at an unclaimed port (RFC 793 reset rules):
/// ACK'd segs get a bare RST(seq=their ack); non-ACK get RST|ACK(seq=0,
/// ack=their consumed seq). Best-effort ARP (0ms — never RST-wait).
fn tcp_rst(src_ip: [u8; 4], s: &TcpSeg) {
    let Some(mac) = next_hop(src_ip, 0) else { return };
    let consume = s.payload.len() as u32
        + if s.flags & (TCP_SYN | TCP_FIN) != 0 { 1 } else { 0 };
    if s.flags & TCP_ACK != 0 {
        send_tcp(mac, src_ip, s.dport, s.sport, s.ack, 0, TCP_RST, &[], 65535);
    } else {
        send_tcp(
            mac,
            src_ip,
            s.dport,
            s.sport,
            0,
            s.seq.wrapping_add(consume),
            TCP_RST | TCP_ACK,
            &[],
            65535,
        );
    }
}

// ---------------------------------------------------------------------------
// TCP socket layer — the real stream abstraction. Kernel consumers (http_get)
// and userspace (SYS_NET_TCP_*) share it.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum TcpState {
    SynSent,
    SynRecv, // inbound SYN answered; waiting for the peer's ACK
    Open,
    Closed,
}

pub struct TcpSock {
    cid: u16, // TCP_SOCKS map key (== lport for outbound; synthetic for accepted)
    lport: u16,
    rip: [u8; 4],
    rport: u16,
    mac: [u8; 6],
    snd_nxt: u32, // next seq we transmit
    snd_una: u32, // lowest unacked seq (retransmit frontier)
    rcv_nxt: u32, // next rx seq we accept in-order
    state: TcpState,
    q: VecDeque<Vec<u8>>, // in-order payload chunks
    unacked: VecDeque<UnAck>, // transmitted, awaiting peer ACK (retransmit queue)
    rst: bool,            // peer sent RST (read path surfaces ECONNRESET)
    owner: u32,           // task id that opened/accepted it (0 = kernel side)
    wr_off: bool,         // shutdown(SHUT_WR): FIN sent, no more sends
    ka: bool,             // SO_KEEPALIVE: probe the peer after 15s idle
    ka_rx: u64,           // last rx (or probe) timestamp — keepalive clock
}

/// A transmitted segment awaiting ACK — retransmitted by tcp_tick.
pub struct UnAck {
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
    tx_ms: u64, // last transmit time (RTO clock)
}

/// Advertised receive window: shrinks as the in-order queue fills — real
/// backpressure; peers stop sending when our app doesn't read.
fn rx_win(k: &TcpSock) -> u16 {
    let buffered: usize = k.q.iter().map(|c| c.len()).sum();
    32768u32.saturating_sub(buffered as u32).min(65535) as u16
}

static TCP_SOCKS: Mutex<BTreeMap<u16, TcpSock>> = Mutex::new(BTreeMap::new());

// Inbound connections: ports accepting SYNs, and the conns that completed
// their handshake and are waiting for tcp_accept to pick them up.
static LISTENERS: Mutex<alloc::collections::BTreeSet<u16>> =
    Mutex::new(alloc::collections::BTreeSet::new());
static LISTEN_OWNERS: Mutex<BTreeMap<u16, u32>> = Mutex::new(BTreeMap::new());
static UDP_OWNERS: Mutex<BTreeMap<u16, u32>> = Mutex::new(BTreeMap::new());
static ACCEPTED: Mutex<BTreeMap<u16, VecDeque<(u16, [u8; 4], u16)>>> =
    Mutex::new(BTreeMap::new());
static NEXT_CID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x8000);

fn tcp_feed(k: &mut TcpSock, s: &TcpSeg) {
    k.ka_rx = now_ms(); // any segment from the peer resets the idle clock
    match k.state {
        TcpState::SynRecv => {
            if s.flags & TCP_RST != 0 {
                k.rst = true;
                k.state = TcpState::Closed;
            } else if s.flags & TCP_ACK != 0 && s.ack == k.snd_nxt {
                k.snd_una = s.ack;
                k.state = TcpState::Open;
                if s.seq == k.rcv_nxt && !s.payload.is_empty() {
                    k.q.push_back(s.payload.clone());
                    k.rcv_nxt += s.payload.len() as u32;
                    send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_ACK, &[], rx_win(k));
                }
                ACCEPTED
                    .lock()
                    .entry(k.lport)
                    .or_default()
                    .push_back((k.cid, k.rip, k.rport));
            }
        }
        TcpState::SynSent => {
            if s.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK && s.ack == k.snd_nxt {
                k.rcv_nxt = s.seq + 1;
                k.snd_una = s.ack;
                k.state = TcpState::Open;
                send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_ACK, &[], rx_win(k));
            } else if s.flags & TCP_RST != 0 {
                k.rst = true;
                k.state = TcpState::Closed;
            }
        }
        TcpState::Open => {
            if s.flags & TCP_RST != 0 {
                k.rst = true;
                k.state = TcpState::Closed;
                return;
            }
            if s.ack > k.snd_una {
                k.snd_una = s.ack;
                // drain the retransmit queue: cumulatively-acked segs
                while let Some(u) = k.unacked.front() {
                    let end = u.seq.wrapping_add(u.payload.len() as u32).wrapping_add(
                        if u.flags & TCP_FIN != 0 { 1 } else { 0 },
                    );
                    if s.ack >= end {
                        k.unacked.pop_front();
                    } else {
                        break;
                    }
                }
            }
            if s.seq == k.rcv_nxt && !s.payload.is_empty() {
                k.q.push_back(s.payload.clone());
                k.rcv_nxt += s.payload.len() as u32;
            }
            if s.flags & TCP_FIN != 0 {
                k.rcv_nxt += 1;
                k.state = TcpState::Closed;
            }
            // ack whatever we consumed (dup acks are fine)
            send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_ACK, &[], rx_win(k));
        }
        TcpState::Closed => {}
    }
}

/// SYN handshake -> Open. Err(-1) lport bound, Err(-2) no route/timeout/refused.
pub fn tcp_open(lport: u16, rip: [u8; 4], rport: u16, timeout_ms: u64) -> Result<(), i64> {
    if TCP_SOCKS.lock().contains_key(&lport) {
        return Err(-1);
    }
    let Some(mac) = next_hop(rip, 1500) else {
        return Err(-101); // EHOSTUNREACH: no route
    };
    let isn = (now_ms() as u32).wrapping_add(lport as u32) ^ 0xC05A_0000;
    TCP_SOCKS.lock().insert(
        lport,
        TcpSock {
            lport,
            rip,
            rport,
            mac,
            snd_nxt: isn + 1,
            snd_una: isn,
            rcv_nxt: 0,
            state: TcpState::SynSent,
            q: VecDeque::new(),
            unacked: VecDeque::new(),
            rst: false,
            cid: lport,
            owner: crate::task::with_current(|t| t.id),
            wr_off: false,
            ka: false,
            ka_rx: now_ms(),
        },
    );
    let deadline = now_ms() + timeout_ms;
    let mut last_syn = 0u64;
    let mut open = false;
    while now_ms() < deadline {
        if now_ms() - last_syn >= 1000 {
            send_tcp(mac, rip, lport, rport, isn, 0, TCP_SYN, &[], 65535);
            last_syn = now_ms();
        }
        for (src_ip, proto, p) in pump_rx() {
            dispatch(src_ip, proto, p);
        }
        match TCP_SOCKS.lock().get(&lport).map(|k| k.state) {
            Some(TcpState::Open) => {
                open = true;
                break;
            }
            Some(TcpState::Closed) => break, // RST
            _ => {}
        }
        wait_irq();
    }
    if open {
        sprintln!(
            "[net] tcp established -> {}.{}.{}.{}:{}",
            rip[0], rip[1], rip[2], rip[3], rport
        );
        Ok(())
    } else {
        // RST'd (state Closed) = refused; plain deadline = timed out
        let refused = TCP_SOCKS
            .lock()
            .get(&lport)
            .map(|k| k.state == TcpState::Closed)
            .unwrap_or(false);
        TCP_SOCKS.lock().remove(&lport);
        if refused {
            Err(-111) // ECONNREFUSED
        } else {
            Err(-110) // ETIMEDOUT
        }
    }
}

/// Mark `lport` as listening for inbound TCP connections.
pub fn tcp_listen(lport: u16) -> Result<(), i64> {
    if TCP_SOCKS.lock().contains_key(&lport) || !LISTENERS.lock().insert(lport) {
        return Err(-1);
    }
    LISTEN_OWNERS
        .lock()
        .insert(lport, crate::task::with_current(|t| t.id));
    Ok(())
}

pub fn tcp_unlisten(lport: u16) {
    LISTENERS.lock().remove(&lport);
    LISTEN_OWNERS.lock().remove(&lport);
    ACCEPTED.lock().remove(&lport);
}

/// Answer an inbound SYN: send SYN+ACK and park the conn in SynRecv.
fn accept_syn(s: &TcpSeg, src_ip: [u8; 4]) {
    let Some(mac) = next_hop(src_ip, 1000) else {
        return;
    };
    let mut cid = NEXT_CID.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u16;
    // skip keys that collide with real lports in the table
    while TCP_SOCKS.lock().contains_key(&cid) {
        cid = NEXT_CID.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u16;
    }
    let isn = (now_ms() as u32).wrapping_add(cid as u32) ^ 0x50EA_0000;
    TCP_SOCKS.lock().insert(
        cid,
        TcpSock {
            cid,
            lport: s.dport,
            rip: src_ip,
            rport: s.sport,
            mac,
            snd_nxt: isn + 1,
            snd_una: isn,
            rcv_nxt: s.seq + 1,
            state: TcpState::SynRecv,
            q: VecDeque::new(),
            unacked: VecDeque::new(),
            rst: false,
            owner: 0,
            wr_off: false,
            ka: false,
            ka_rx: now_ms(),
        },
    );
    send_tcp(mac, src_ip, s.dport, s.sport, isn, s.seq + 1, TCP_SYN | TCP_ACK, &[], 65535);
}

/// Wait for an accepted conn on a listener. Returns (cid, peer ip, peer port).
pub fn tcp_accept(lport: u16, timeout_ms: u64) -> Option<(u16, [u8; 4], u16)> {
    let deadline = now_ms() + timeout_ms;
    loop {
        for (src_ip, proto, p) in pump_rx() {
            dispatch(src_ip, proto, p);
        }
        if let Some(x) = ACCEPTED
            .lock()
            .get_mut(&lport)
            .and_then(|q| q.pop_front())
        {
            let me = crate::task::with_current(|t| t.id);
            if let Some(k) = TCP_SOCKS.lock().get_mut(&x.0) {
                k.owner = me;
            }
            return Some(x);
        }
        if now_ms() >= deadline {
            return None;
        }
        wait_irq();
    }
}

/// Send a chunk (<=1400), retransmitting every 800ms until the peer's ack
/// covers it. Err(-1) not open, Err(-2) peer went away/timeout.
pub fn tcp_send(lport: u16, data: &[u8], timeout_ms: u64) -> Result<(), i64> {
    let deadline = now_ms() + timeout_ms;
    let mut last_tx = 0u64;
    let (seq_at_send, sent_len) = {
        let mut t = TCP_SOCKS.lock();
        let Some(k) = t.get_mut(&lport) else {
            return Err(-1);
        };
        if k.state != TcpState::Open {
            return Err(-1);
        }
        let n = data.len().min(1400);
        (k.snd_nxt, n)
    };
    // send window full -> wait for ACKs to drain the queue, like a real
    // blocking send() under backpressure
    let mut enqueued = false;
    while !enqueued && now_ms() < deadline {
        {
            let mut t = TCP_SOCKS.lock();
            let Some(k) = t.get_mut(&lport) else {
                return Err(-2);
            };
            if k.state == TcpState::Closed {
                return Err(-2);
            }
            if k.unacked.len() < 32 {
                k.unacked.push_back(UnAck {
                    seq: seq_at_send,
                    flags: TCP_ACK | TCP_PSH,
                    payload: data[..sent_len].to_vec(),
                    tx_ms: now_ms(),
                });
                enqueued = true;
            }
        }
        if !enqueued {
            for (src_ip, proto, p) in pump_rx() {
                dispatch(src_ip, proto, p);
            }
            wait_irq();
        }
    }
    if !enqueued {
        return Err(-2);
    }
    while now_ms() < deadline {
        if now_ms() - last_tx >= 800 {
            let t = TCP_SOCKS.lock();
            if let Some(k) = t.get(&lport) {
                send_tcp(k.mac, k.rip, k.lport, k.rport, seq_at_send, k.rcv_nxt, TCP_ACK | TCP_PSH, &data[..sent_len], rx_win(k));
            }
            last_tx = now_ms();
        }
        for (src_ip, proto, p) in pump_rx() {
            dispatch(src_ip, proto, p);
        }
        {
            let mut t = TCP_SOCKS.lock();
            let Some(k) = t.get_mut(&lport) else {
                return Err(-2);
            };
            if k.snd_una >= seq_at_send + sent_len as u32 {
                k.snd_nxt = seq_at_send + sent_len as u32;
                return Ok(());
            }
            if k.state == TcpState::Closed {
                return Err(-2);
            }
        }
        wait_irq();
    }
    Err(-2)
}

/// Blocking recv: next in-order payload chunk, or None on orderly close
/// (peer FIN/RST or timeout with nothing buffered).
pub fn tcp_recv(lport: u16, timeout_ms: u64) -> Option<Vec<u8>> {
    let deadline = now_ms() + timeout_ms;
    loop {
        {
            let mut t = TCP_SOCKS.lock();
            let k = t.get_mut(&lport)?;
            if let Some(d) = k.q.pop_front() {
                return Some(d);
            }
            if k.state == TcpState::Closed {
                return None;
            }
        }
        // pump before the deadline check so recv(0) still forwards packets
        for (src_ip, proto, p) in pump_rx() {
            dispatch(src_ip, proto, p);
        }
        if let Some(d) = TCP_SOCKS.lock().get_mut(&lport).and_then(|k| k.q.pop_front()) {
            return Some(d);
        }
        if now_ms() >= deadline {
            return None;
        }
        wait_irq();
    }
}

/// FIN + drop the socket (close is fire-and-forget — the peer's side is
/// already Closed or will be once our FIN lands).
pub fn tcp_close(lport: u16) {
    if let Some(k) = TCP_SOCKS.lock().remove(&lport) {
        send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_FIN | TCP_ACK, &[], rx_win(&k));
    }
}

// ---- socket-fd support (kernel/src/sockfd.rs rides these) ----

/// One non-blocking rx pump+dispatch so socket-fd readiness and reads see
/// packets that arrived since the last blocking call.
pub fn pump_once() {
    for (src_ip, proto, p) in pump_rx() {
        dispatch(src_ip, proto, p);
    }
}

/// True when no UDP socket, TCP conn or listener occupies `lport`.
pub fn lport_free(lport: u16) -> bool {
    !udp_bound(lport)
        && !TCP_SOCKS.lock().contains_key(&lport)
        && !LISTENERS.lock().contains(&lport)
}

/// UDP datagrams queued for `lport`?
pub fn udp_ready(lport: u16) -> bool {
    SOCKS
        .lock()
        .get(&lport)
        .map(|q| !q.is_empty())
        .unwrap_or(false)
}

/// TCP fd-read state: Some(true)=data queued, Some(false)=open but empty,
/// None=conn gone (EOF — reads return 0).
pub fn tcp_read_ready(cid: u16) -> Option<bool> {
    let t = TCP_SOCKS.lock();
    let k = t.get(&cid)?;
    if !k.q.is_empty() {
        Some(true)
    } else if k.state == TcpState::Closed {
        None
    } else {
        Some(false)
    }
}

/// Did the peer RST this conn? Distinguishes ECONNRESET reads from EOF.
/// None = conn gone entirely.
pub fn tcp_was_rst(cid: u16) -> Option<bool> {
    TCP_SOCKS.lock().get(&cid).map(|k| k.rst)
}

/// A completed inbound handshake is queued for accept on `lport`?
pub fn tcp_accept_ready(lport: u16) -> bool {
    ACCEPTED
        .lock()
        .get(&lport)
        .map(|q| !q.is_empty())
        .unwrap_or(false)
}

/// Fire a single data segment and return without waiting for the ack — the
/// O_NONBLOCK write path for socket fds. Err(-1) no conn, Err(-2) closed.
pub fn tcp_send_nowait(cid: u16, data: &[u8]) -> Result<usize, i64> {
    let (seq, mac, rip, lport, rport, ack, win) = {
        let mut t = TCP_SOCKS.lock();
        let Some(k) = t.get_mut(&cid) else { return Err(-1) };
        if k.state != TcpState::Open {
            return Err(-2);
        }
        if k.unacked.len() >= 32 {
            return Err(-11); // send window full — EAGAIN
        }
        (k.snd_nxt, k.mac, k.rip, k.lport, k.rport, k.rcv_nxt, rx_win(k))
    };
    let n = data.len().min(1400);
    send_tcp(mac, rip, lport, rport, seq, ack, TCP_ACK | TCP_PSH, &data[..n], win);
    if let Some(k) = TCP_SOCKS.lock().get_mut(&cid) {
        k.unacked.push_back(UnAck {
            seq,
            flags: TCP_ACK | TCP_PSH,
            payload: data[..n].to_vec(),
            tx_ms: now_ms(),
        });
        k.snd_nxt = seq.wrapping_add(n as u32);
    }
    Ok(n)
}

/// Real FIN on the wire without dropping the socket — shutdown(SHUT_WR).
/// The peer sees EOF once it drains what we already sent; our reads keep
/// working until close. Idempotent (one FIN).
pub fn tcp_shutdown_wr(cid: u16) {
    let mut t = TCP_SOCKS.lock();
    let Some(k) = t.get_mut(&cid) else { return };
    if k.wr_off || k.state == TcpState::Closed {
        return;
    }
    k.wr_off = true;
    k.unacked.push_back(UnAck {
        seq: k.snd_nxt,
        flags: TCP_FIN | TCP_ACK,
        payload: Vec::new(),
        tx_ms: now_ms(),
    });
    send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_FIN | TCP_ACK, &[], rx_win(k));
    k.snd_nxt = k.snd_nxt.wrapping_add(1); // FIN consumes one sequence number
}

/// MSG_PEEK: copy up to `cap` bytes of the front chunk WITHOUT consuming
/// it — the next read returns the same data.
pub fn tcp_peek_some(cid: u16, cap: usize) -> Option<Vec<u8>> {
    let t = TCP_SOCKS.lock();
    let k = t.get(&cid)?;
    let front = k.q.front()?;
    let n = front.len().min(cap);
    Some(front[..n].to_vec())
}

/// Set SO_KEEPALIVE on a conn — probes start counting from now.
pub fn tcp_set_keepalive(cid: u16, on: bool) {
    if let Some(k) = TCP_SOCKS.lock().get_mut(&cid) {
        k.ka = on;
        k.ka_rx = now_ms();
    }
}

/// Nonblocking partial read: at most `cap` bytes of the front queued chunk;
/// the remainder stays queued for the next read. None = nothing buffered.
pub fn tcp_recv_some(cid: u16, cap: usize) -> Option<Vec<u8>> {
    let mut t = TCP_SOCKS.lock();
    let k = t.get_mut(&cid)?;
    let front = k.q.front_mut()?;
    let n = front.len().min(cap);
    let d: Vec<u8> = front.drain(..n).collect();
    if front.is_empty() {
        k.q.pop_front();
    }
    Some(d)
}

pub fn init() {
    if virtio_net::init() {
        match dhcp() {
            Some(_) => {}
            None => sprintln!("[net] dhcp failed; static ip {}.{}.{}.{}", DEFAULT_IP[0], DEFAULT_IP[1], DEFAULT_IP[2], DEFAULT_IP[3]),
        }
        let ip = our_ip();
        sprintln!("[net] up: ip {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    }
}
