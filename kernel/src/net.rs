//! Minimal IPv4 stack on virtio-net: ethernet + ARP + ICMP echo.
//! Guest IP 10.0.2.15 (QEMU user-net convention), gateway 10.0.2.2.
//! `ping(ip)` performs a real ARP resolve + ICMP echo request/reply.
use crate::sprintln;
use crate::virtio_net::{self, NET};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

/// Fallback IP when DHCP fails (slirp's static-assignment convention).
pub const DEFAULT_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];

/// Current configured IPv4 — set by DHCP at init, defaults to `DEFAULT_IP`.
static CUR_IP: Mutex<[u8; 4]> = Mutex::new(DEFAULT_IP);
pub fn our_ip() -> [u8; 4] {
    *CUR_IP.lock()
}

static ARP_CACHE: Mutex<Vec<([u8; 4], [u8; 6])>> = Mutex::new(Vec::new());

/// Sleep until the next IRQ (timer ticks ~10ms) so waits burn no CPU and
/// `now_ms()` advances. Syscall context runs IF=0 (interrupt gate), so we
/// enable interrupts only for the hlt window — no locks held here, and IRQ
/// handlers never lock.
fn wait_irq() {
    unsafe { core::arch::asm!("sti; hlt; cli", options(nomem, nostack)) };
}

/// Next-hop MAC for `ip`: same-subnet addresses resolve directly, anything
/// else goes via the gateway (real routing, not ARP-for-the-world).
fn next_hop(ip: [u8; 4], timeout_ms: u64) -> Option<[u8; 6]> {
    let me = our_ip();
    let on_net = ip[0] == me[0] && ip[1] == me[1] && ip[2] == me[2];
    arp_resolve(if on_net { ip } else { GW_IP }, timeout_ms)
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
    for f in virtio_net::take_rx() {
        if let Some(p) = handle_frame(&f) {
            out.push(p);
        }
    }
    if let Some(n) = NET.lock().clone() {
        let mut v = Vec::new();
        n.drain_rx(&mut v);
        for f in v {
            if let Some(p) = handle_frame(&f) {
                out.push(p);
            }
        }
    }
    out
}

fn send_frame(dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Result<(), ()> {
    let Some(n) = NET.lock().clone() else { return Err(()) };
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&n.mac);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < 60 {
        f.resize(60, 0);
    }
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
    send_ip_src(our_ip(), dst_mac, dst_ip, proto, payload);
}

fn send_ip_src(src_ip: [u8; 4], dst_mac: [u8; 6], dst_ip: [u8; 4], proto: u8, payload: &[u8]) {
    let mut ip = Vec::with_capacity(20 + payload.len());
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&1u16.to_be_bytes());
    ip.extend_from_slice(&[0u8; 2]);
    ip.push(64);
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
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0u8; 2]); // checksum disabled (valid in IPv4)
    udp.extend_from_slice(payload);
    send_ip(dst_mac, dst_ip, 17, &udp);
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
) {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(0x50); // data offset 5 (no options)
    seg.push(flags);
    seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    seg.extend_from_slice(&[0u8; 2]); // checksum
    seg.extend_from_slice(&[0u8; 2]); // urg
    seg.extend_from_slice(payload);
    let c = tcp_csum(our_ip(), dst_ip, &seg);
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
pub fn http_get(dst_ip: [u8; 4], host: &str, path: &str) -> Option<Vec<u8>> {
    const SPORT: u16 = 49200;
    tcp_open(SPORT, dst_ip, 80, 3000).ok()?;
    let req = alloc::format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
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

/// (mac, ip) for `ifconfig`-style reporting.
pub fn info() -> Option<([u8; 6], [u8; 4])> {
    NET.lock().as_ref().map(|n| (n.mac, our_ip()))
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

/// Bind a local UDP port. Err(-1) if already bound.
pub fn udp_open(lport: u16) -> Result<(), i64> {
    let mut s = SOCKS.lock();
    if s.contains_key(&lport) {
        return Err(-1);
    }
    s.insert(lport, VecDeque::new());
    Ok(())
}

pub fn udp_close(lport: u16) {
    SOCKS.lock().remove(&lport);
}

/// Send a datagram from `lport` to `dst_ip:dst_port` (real ARP next-hop).
pub fn udp_send(lport: u16, dst_ip: [u8; 4], dport: u16, payload: &[u8]) -> Result<(), i64> {
    if !SOCKS.lock().contains_key(&lport) {
        return Err(-2); // not bound
    }
    let Some(mac) = next_hop(dst_ip, 1500) else {
        return Err(-3);
    };
    send_udp(mac, dst_ip, lport, dport, payload);
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
                None => false,
            }
        }
        6 => {
            let Some(s) = parse_tcp(&p) else {
                return false;
            };
            let mut t = TCP_SOCKS.lock();
            let Some(k) = t
                .values_mut()
                .find(|k| k.rip == src_ip && k.rport == s.sport && k.lport == s.dport)
            else {
                return false;
            };
            tcp_feed(k, &s);
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// TCP socket layer — the real stream abstraction. Kernel consumers (http_get)
// and userspace (SYS_NET_TCP_*) share it.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum TcpState {
    SynSent,
    Open,
    Closed,
}

pub struct TcpSock {
    lport: u16,
    rip: [u8; 4],
    rport: u16,
    mac: [u8; 6],
    snd_nxt: u32, // next seq we transmit
    snd_una: u32, // lowest unacked seq (retransmit frontier)
    rcv_nxt: u32, // next rx seq we accept in-order
    state: TcpState,
    q: VecDeque<Vec<u8>>, // in-order payload chunks
}

static TCP_SOCKS: Mutex<BTreeMap<u16, TcpSock>> = Mutex::new(BTreeMap::new());

fn tcp_feed(k: &mut TcpSock, s: &TcpSeg) {
    match k.state {
        TcpState::SynSent => {
            if s.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK && s.ack == k.snd_nxt {
                k.rcv_nxt = s.seq + 1;
                k.snd_una = s.ack;
                k.state = TcpState::Open;
                send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_ACK, &[]);
            } else if s.flags & TCP_RST != 0 {
                k.state = TcpState::Closed;
            }
        }
        TcpState::Open => {
            if s.flags & TCP_RST != 0 {
                k.state = TcpState::Closed;
                return;
            }
            if s.ack > k.snd_una {
                k.snd_una = s.ack;
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
            send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_ACK, &[]);
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
        return Err(-2);
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
        },
    );
    let deadline = now_ms() + timeout_ms;
    let mut last_syn = 0u64;
    let mut open = false;
    while now_ms() < deadline {
        if now_ms() - last_syn >= 1000 {
            send_tcp(mac, rip, lport, rport, isn, 0, TCP_SYN, &[]);
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
        TCP_SOCKS.lock().remove(&lport);
        Err(-2)
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
    while now_ms() < deadline {
        if now_ms() - last_tx >= 800 {
            let t = TCP_SOCKS.lock();
            if let Some(k) = t.get(&lport) {
                send_tcp(k.mac, k.rip, k.lport, k.rport, seq_at_send, k.rcv_nxt, TCP_ACK | TCP_PSH, &data[..sent_len]);
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
        if now_ms() >= deadline {
            return None;
        }
        for (src_ip, proto, p) in pump_rx() {
            dispatch(src_ip, proto, p);
        }
        wait_irq();
    }
}

/// FIN + drop the socket (close is fire-and-forget — the peer's side is
/// already Closed or will be once our FIN lands).
pub fn tcp_close(lport: u16) {
    if let Some(k) = TCP_SOCKS.lock().remove(&lport) {
        send_tcp(k.mac, k.rip, k.lport, k.rport, k.snd_nxt, k.rcv_nxt, TCP_FIN | TCP_ACK, &[]);
    }
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
