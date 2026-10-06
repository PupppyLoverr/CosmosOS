//! Minimal IPv4 stack on virtio-net: ethernet + ARP + ICMP echo.
//! Guest IP 10.0.2.15 (QEMU user-net convention), gateway 10.0.2.2.
//! `ping(ip)` performs a real ARP resolve + ICMP echo request/reply.
use crate::sprintln;
use crate::virtio_net::{self, NET};
use alloc::vec::Vec;
use spin::Mutex;

pub const OUR_IP: [u8; 4] = [10, 0, 2, 15];

static ARP_CACHE: Mutex<Vec<([u8; 4], [u8; 6])>> = Mutex::new(Vec::new());

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
/// Net is polled, not interrupt-driven: virtio-net IRQs are not wired up.
/// Returns (ip_proto, transport_payload) for IPv4 frames addressed to us.
fn pump_rx() -> Vec<(u8, Vec<u8>)> {
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
    p.extend_from_slice(&OUR_IP);
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
    p.extend_from_slice(&OUR_IP);
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
fn handle_frame(f: &[u8]) -> Option<(u8, Vec<u8>)> {
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
            if op == 1 && target_ip == OUR_IP {
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
            if dst != OUR_IP {
                return None;
            }
            Some((ip[9], ip[ihl..].to_vec()))
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
        core::hint::spin_loop();
    }
}

/// `ping <ip>`: ARP-resolve, send one ICMP echo request, wait for the reply.
/// Returns rtt in milliseconds, or None on timeout/unreachable.
pub fn ping(ip: [u8; 4], timeout_ms: u64) -> Option<u64> {
    if NET.lock().is_none() {
        sprintln!("[net] ping: no device");
        return None;
    }
    let dst_mac = arp_resolve(ip, 1500)?;
    sprintln!(
        "[net] arp {}.{}.{}.{} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        ip[0], ip[1], ip[2], ip[3],
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
    );
    let id = 0xC050u16;
    let seq = 1u16;
    let payload = b"cosmos-ping-payload-0123456789abcdef";
    let t0 = now_ms();
    send_icmp_echo(dst_mac, ip, id, seq, payload);
    loop {
        for (proto, p) in pump_rx() {
            if proto == 1 && p.len() >= 8 && p[0] == 0 && be16(&p[4..]) == id && be16(&p[6..]) == seq {
                return Some(now_ms() - t0);
            }
        }
        if now_ms() - t0 >= timeout_ms {
            return None;
        }
        core::hint::spin_loop();
    }
}

fn send_ip(dst_mac: [u8; 6], dst_ip: [u8; 4], proto: u8, payload: &[u8]) {
    let mut ip = Vec::with_capacity(20 + payload.len());
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&1u16.to_be_bytes());
    ip.extend_from_slice(&[0u8; 2]);
    ip.push(64);
    ip.push(proto);
    ip.extend_from_slice(&[0u8; 2]);
    ip.extend_from_slice(&OUR_IP);
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

    let mac = arp_resolve(DNS, 1500)?;
    send_udp(mac, DNS, SPORT, 53, &q);
    sprintln!("[net] dns query '{}' -> 10.0.2.3:53", name);

    let t0 = now_ms();
    loop {
        for (proto, p) in pump_rx() {
            if proto != 17 || p.len() < 8 + 12 {
                continue;
            }
            let sport = be16(&p[0..]);
            let dport = be16(&p[2..]);
            if sport != 53 || dport != SPORT {
                continue;
            }
            let m = &p[8..];
            if be16(&m[0..]) != txid || m[2] & 0x80 == 0 {
                continue; // not our reply
            }
            let ancount = be16(&m[6..]) as usize;
            let qdcount = be16(&m[4..]) as usize;
            let mut i = 12;
            for _ in 0..qdcount {
                i = dns_skip_name(m, i)? + 4;
            }
            for _ in 0..ancount {
                i = dns_skip_name(m, i)?;
                if m.len() < i + 10 {
                    return None;
                }
                let rtype = be16(&m[i..]);
                let rdlen = be16(&m[i + 8..]) as usize;
                if rtype == 1 && rdlen == 4 && m.len() >= i + 10 + 4 {
                    let ip: [u8; 4] = m[i + 10..i + 14].try_into().ok()?;
                    sprintln!(
                        "[net] dns '{}' -> {}.{}.{}.{}",
                        name, ip[0], ip[1], ip[2], ip[3]
                    );
                    return Some(ip);
                }
                i += 10 + rdlen;
            }
        }
        if now_ms() - t0 >= timeout_ms {
            return None;
        }
        core::hint::spin_loop();
    }
}

/// (mac, ip) for `ifconfig`-style reporting.
pub fn info() -> Option<([u8; 6], [u8; 4])> {
    NET.lock().as_ref().map(|n| (n.mac, OUR_IP))
}

pub fn init() {
    if virtio_net::init() {
        sprintln!("[net] up: ip {}.{}.{}.{}", OUR_IP[0], OUR_IP[1], OUR_IP[2], OUR_IP[3]);
    }
}
