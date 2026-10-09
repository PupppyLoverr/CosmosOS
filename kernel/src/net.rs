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

// /proc/net/snmp + netstat -s counters: pre/post-filter inbound, egress by
// proto, and ICMP echo subcounts. All relaxed — observability only.
pub static IP_IN_RECV: AtomicU64 = AtomicU64::new(0);
pub static IP_IN_DELIV: AtomicU64 = AtomicU64::new(0);
pub static IP_OUT_REQ: AtomicU64 = AtomicU64::new(0);
pub static ICMP_IN: AtomicU64 = AtomicU64::new(0);
pub static ICMP_OUT: AtomicU64 = AtomicU64::new(0);
pub static TCP_IN: AtomicU64 = AtomicU64::new(0);
pub static TCP_OUT: AtomicU64 = AtomicU64::new(0);
pub static UDP_IN: AtomicU64 = AtomicU64::new(0);
pub static UDP_OUT: AtomicU64 = AtomicU64::new(0);
pub static ICMP_IN_ECHOREQ: AtomicU64 = AtomicU64::new(0);
pub static ICMP_OUT_ECHOREQ: AtomicU64 = AtomicU64::new(0);
pub static ICMP_IN_ECHOREP: AtomicU64 = AtomicU64::new(0);
pub static ICMP_OUT_ECHOREP: AtomicU64 = AtomicU64::new(0);

// net.ipv4 tunables (writable via /proc/sys/net/ipv4/*)
static ICMP_IGNORE_ALL: AtomicU64 = AtomicU64::new(0);

/// Real wire MTU (`ip link set eth0 mtu N`, `/proc/net/mtu`). Datagrams
/// larger than this are dropped at the egress funnel — the stack has no
/// IP fragmentation, so oversize sends die like a DF datagram — plus a
/// real EMSGSIZE at the UDP socket API.
static IFACE_MTU: AtomicU64 = AtomicU64::new(1500);
/// TX drops caused by the MTU gate — surfaces as TX-DRP in
/// /proc/net/dev, `ip -s link` and `ifconfig -s`.
static IP_MTU_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn iface_mtu() -> u64 {
    IFACE_MTU.load(Ordering::Relaxed)
}

/// `ip link set mtu` semantics: 68..=65535 (RFC 791 minimum).
pub fn set_mtu(n: u64) -> bool {
    if (68..=65535).contains(&n) {
        IFACE_MTU.store(n, Ordering::Relaxed);
        true
    } else {
        false
    }
}

pub fn net_mtu() -> String {
    alloc::format!("{}\n", iface_mtu())
}

/// `net.ipv4.ip_default_ttl` — real default TTL stamped into every IPv4
/// packet that leaves without an explicit per-send override.
static DEF_TTL: AtomicU64 = AtomicU64::new(64);

fn def_ttl() -> u8 {
    DEF_TTL.load(Ordering::Relaxed) as u8
}

pub fn set_def_ttl(v: u64) {
    DEF_TTL.store(v.clamp(1, 255), Ordering::Relaxed);
}

pub fn net_def_ttl() -> String {
    alloc::format!("{}\n", DEF_TTL.load(Ordering::Relaxed))
}

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
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0:{:>8}{:>8}    0    0    0     0          0         0 {:>8}{:>8}    0 {:>4}    0     0       0          0\n    lo:{:>8}{:>8}    0    0    0     0          0         0 {:>8}{:>8}    0    0    0     0       0          0\n",
        RX_BYTES.load(Ordering::Relaxed),
        RX_PKTS.load(Ordering::Relaxed),
        TX_BYTES.load(Ordering::Relaxed),
        TX_PKTS.load(Ordering::Relaxed),
        IP_MTU_DROPS.load(Ordering::Relaxed),
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

/// (ip, mac, permanent) — wire-learned entries are dynamic; `arp -s`/
/// `/proc/net/arp` `add` installs permanent ones that traffic doesn't
/// refresh.
/// A learned (or pinned) neighbour entry. `learned_ms` feeds the NUD
/// state shown by `ip neigh`: PERMANENT for static entries, REACHABLE
/// while the answer is fresh (< 30 s), STALE past that — like a real
/// neighbour table.
struct ArpEnt {
    ip: [u8; 4],
    mac: [u8; 6],
    perm: bool,
    learned_ms: u64,
}
static ARP_CACHE: Mutex<Vec<ArpEnt>> = Mutex::new(Vec::new());

/// NUD state name for `ip neigh` output.
fn arp_state(e: &ArpEnt) -> &'static str {
    if e.perm {
        "PERMANENT"
    } else if now_ms() - e.learned_ms < 30_000 {
        "REACHABLE"
    } else {
        "STALE"
    }
}

/// Loopback (`lo`): 127.0.0.0/8 and our own address deliver back into the
/// stack instead of the wire. Queued, not dispatched inline — TX paths may
/// run inside spin-lock scopes (TCP lock during a FIN), and inline
/// delivery would recurse into the same locks.
pub const LOOPBACK_IP: [u8; 4] = [127, 0, 0, 1];
fn is_loopback(ip: [u8; 4]) -> bool {
    ip[0] == 127 || ip == our_ip()
}
// rx tuples: (src_ip, proto, payload, ttl) — ttl is the packet's real
// IPv4 TTL at ingress (lo packets carry the nominal def_ttl()).
static LOOPBACK_Q: Mutex<VecDeque<([u8; 4], u8, Vec<u8>, u64)>> = Mutex::new(VecDeque::new());

/// Packed per-packet metadata riding the rx tuple: `ttl | tos<<8 |
/// srcmac48<<16`. The full 64-bit word carries everything the
/// firewall needs off the wire frame.
fn pkt_meta(ttl: u8, tos: u8, mac: [u8; 6]) -> u64 {
    let m = mac.iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    ttl as u64 | ((tos as u64) << 8) | (m << 16)
}
fn meta_ttl(m: u64) -> u8 {
    m as u8
}
fn meta_tos(m: u64) -> u8 {
    (m >> 8) as u8
}
fn meta_mac(m: u64) -> [u8; 6] {
    let v = m >> 16;
    let b = v.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}
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
        // 'flush' rebuilds the table from defaults (lo + connected + gw) —
        // same effect as `ip route flush` on an unpopulated box.
        Some("flush") => {
            *ROUTES.lock() = Some(default_routes());
            return true;
        }
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

// ---------------------------------------------------------------------------
// iptables — real INPUT-chain packet filter. Rules live in FW; every packet
// reaching dispatch() is checked and matching ones are silently dropped
// (real -j DROP semantics: no ICMP reply, no RST, no delivery).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FwRule {
    proto: u8,            // 0 = any; 1 icmp, 6 tcp, 17 udp
    dport: u16,           // 0 = any (tcp/udp destination port)
    dports: Vec<u16>,     // `-m multiport --dports a,b,..` — empty = not used
    src: [u8; 4],         // [0;4] = anywhere
    smask: [u8; 4],
    src_range: Option<(u32, u32)>, // `-m iprange --src-range a-b` (be u32 bounds)
    sport: u16,           // `--sport` source-port match: 0 = any
    len_lo: u32,          // `-m length --length A[:B]` — payload-size match
    len_hi: u32,          // (len_hi == 0 => unlimited upper bound)
    iface: u8,            // `-i` in-interface: 0 = any, 1 = eth0, 2 = lo
    oiface: u8,           // `-o` out-interface: same encoding
    state: u8,            // 0 = any; bit0 = NEW, bit1 = ESTABLISHED
    ttl_mode: u8,         // `-m ttl`: 0 = any, 1 = --ttl-eq, 2 = --ttl-lt, 3 = --ttl-gt
    ttl_v: u8,            // operand N for the ttl match
    tos_v: u8,            // `-m tos --tos V[/M]` — DS-byte match value
    tos_mask: u8,         // 0 = unused; else the mask both sides share
    smac: Option<[u8; 6]>,// `-m mac --mac-source` — L2 sender (INPUT)
    dscp: u8,             // `-m dscp --dscp N` — 0xff = unused
    icmp_type: u8,        // `-m icmp --icmp-type N` — 0xff = unused
    limit_pps: u16,       // 0 = unlimited; `-m limit --limit N/s` cap on rule hits
    comment: String,      // `-m comment --comment` — real per-rule annotation
    limit_burst: u16,     // bucket depth (real iptables default 5)
    lim_tokens: u16,      // match-time bucket (packet units)
    lim_ms: u64,          // last bucket refill
    // 0 = DROP, 1 = LOG (audit + fall through), 2 = REJECT, 3 = ACCEPT,
    // 4 = RETURN (leave this chain — real `-j RETURN`).
    target: u8,
    // Non-empty = jump to the named user chain (`-j NAME`, target 0).
    // Falling off a user chain's end returns to the caller, like real
    // iptables; a jump to a missing chain can't be created (ctl-time
    // validation), and depth is capped against loops.
    jump: String,
    hits: u64,
    bytes: u64,
}

static FW: Mutex<Vec<FwRule>> = Mutex::new(Vec::new());

/// User-defined chains (`iptables -N`): evaluated by jump targets from
/// builtin or other user chains; `X` deletes empty unreferenced ones.
static FW_USER: Mutex<BTreeMap<String, Vec<FwRule>>> =
    Mutex::new(BTreeMap::new());

/// INPUT chain policy: false = ACCEPT (default-allow), true = DROP.
static FW_POLICY: Mutex<bool> = Mutex::new(false);

/// OUTPUT chain: locally-generated datagrams are evaluated at egress
/// (send_ip_src_ttl) before they leave — wire and loopback alike.
static FW_OUT: Mutex<Vec<FwRule>> = Mutex::new(Vec::new());
static FW_OUT_POLICY: Mutex<bool> = Mutex::new(false);

/// Real conntrack: a per-flow table fed by every packet in BOTH
/// directions (tx via `ct_observe_tx`, rx via `ct_update`). A flow is
/// ESTABLISHED once packets have been seen both ways — the inbound SYN
/// is NEW, our SYN-ACK flips the entry, and everything after is
/// ESTABLISHED. UDP flows establish on the first reply datagram; ICMP
/// flows key on the echo id.
struct CtEnt {
    proto: u8,
    a_ip: [u8; 4],
    a_port: u16,
    b_ip: [u8; 4],
    b_port: u16,
    seen_reply: bool,
    last_ms: u64,
}
static CT: Mutex<Vec<CtEnt>> = Mutex::new(Vec::new());

/// Per-flow idle lifetime, like conntrack's per-protocol timeouts.
/// Entries past their lifetime are real evictions — the flow forgets
/// its state and the next packet is NEW again.
fn ct_timeout(e: &CtEnt) -> u64 {
    match e.proto {
        1 => 60_000,
        17 => 120_000,
        6 => {
            if e.seen_reply {
                300_000
            } else {
                120_000
            }
        }
        _ => 120_000,
    }
}

/// Drop every flow past its idle timeout.
fn ct_expire(ct: &mut Vec<CtEnt>) {
    let now = now_ms();
    ct.retain(|e| now - e.last_ms < ct_timeout(e));
}

/// Update the flow table for one packet and return its state bits
/// (1 = NEW, 2 = ESTABLISHED). `sport/dport` are the packet's transport
/// ports (0 when absent; ICMP uses the echo id as both ports).
fn ct_update(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, proto: u8) -> u8 {
    let now = now_ms();
    let mut ct = CT.lock();
    ct_expire(&mut *ct);
    for e in ct.iter_mut() {
        if e.proto != proto {
            continue;
        }
        let fwd = e.a_ip == src && e.b_ip == dst && e.a_port == sport && e.b_port == dport;
        let rev = e.b_ip == src && e.a_ip == dst && e.b_port == sport && e.a_port == dport;
        if fwd || rev {
            if rev {
                e.seen_reply = true;
            }
            e.last_ms = now;
            return if e.seen_reply { 2 } else { 1 };
        }
    }
    ct.push(CtEnt {
        proto,
        a_ip: src,
        a_port: sport,
        b_ip: dst,
        b_port: dport,
        seen_reply: false,
        last_ms: now,
    });
    if ct.len() > 512 {
        ct.remove(0); // drop the oldest entry — flows are cheap, memory isn't
    }
    1
}

/// Transport ports for a packet: tcp/udp read their headers; ICMP uses
/// the echo id (types 0/8) so replies pair with requests like a real
/// conntrack flow. Everything else = (0, 0).
fn pkt_ports(proto: u8, p: &[u8]) -> (u16, u16) {
    if (proto == 6 || proto == 17) && p.len() >= 4 {
        (be16(&p[0..]), be16(&p[2..]))
    } else if proto == 1 && p.len() >= 6 && (p[0] == 0 || p[0] == 8) {
        let id = be16(&p[4..]);
        (id, id)
    } else {
        (0, 0)
    }
}

/// Observe an outbound frame for conntrack: parse the IPv4/transport
/// tuple off the wire frame and update the flow (marks the reply
/// direction seen for flows the peer started).
fn ct_observe_tx(f: &[u8]) {
    if f.len() < 14 + 20 || be16(&f[12..]) != 0x0800 {
        return;
    }
    let ip = &f[14..];
    if ip[0] >> 4 != 4 {
        return;
    }
    let proto = ip[9];
    let ihl = ((ip[0] & 0xF) as usize) * 4;
    if ip.len() < ihl + 4 {
        return;
    }
    let src: [u8; 4] = ip[12..16].try_into().unwrap_or([0; 4]);
    let dst: [u8; 4] = ip[16..20].try_into().unwrap_or([0; 4]);
    let (sport, dport) = if proto == 6 || proto == 17 {
        (be16(&ip[ihl..]), be16(&ip[ihl + 2..]))
    } else if proto == 1 && ip.len() >= ihl + 6 && (ip[ihl] == 0 || ip[ihl] == 8) {
        let id = be16(&ip[ihl + 4..]);
        (id, id)
    } else {
        (0, 0)
    };
    let _ = ct_update(src, dst, sport, dport, proto);
}

/// INPUT-chain verdict for this packet: 0 = let it through (no rule
/// matched, ACCEPT target, or policy ACCEPT), 1 = drop, 2 = reject
/// (caller sends the refusal: RST for TCP, ICMP 3/3 otherwise).
/// `plen` is the IPv4 payload length — it feeds the real per-rule
/// byte counter shown by `iptables -L -v`. `st` is the packet's
/// conntrack state bits from `ct_update` (1 NEW / 2 ESTABLISHED).
fn fw_verdict(
    chain: &Mutex<Vec<FwRule>>,
    policy: &Mutex<bool>,
    inbound: bool,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
    st: u8,
    iface: u8,
    plen: u64,
    ttl: u8,
    tos: u8,
    smac: [u8; 6],
    itype: u8,
) -> u8 {
    let mut fw = chain.lock();
    match fw_eval(&mut *fw, inbound, src, dst, proto, sport, dport, st, iface, plen, ttl, tos, smac, itype, 0) {
        // 255 = walked off the end of the builtin chain: policy decides
        255 => {
            if *policy.lock() {
                1
            } else {
                0
            }
        }
        v => v,
    }
}

/// Walk one rule vector against a packet. Verdicts: 0 = ACCEPT (let it
/// through), 1 = DROP, 2 = REJECT, 255 = fell off the end of this chain
/// (for a builtin chain the caller applies the policy; for a jumped-to
/// user chain it means RETURN — resume the parent chain). `-j LOG`
/// audits and falls through; `-j <name>` evaluates the named user
/// chain on a snapshot (counters written back); `-j RETURN` ends the
/// current chain early.
fn fw_eval(
    chain: &mut Vec<FwRule>,
    inbound: bool,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
    st: u8,
    iface: u8,
    plen: u64,
    ttl: u8,
    tos: u8,
    smac: [u8; 6],
    itype: u8,
    depth: u8,
) -> u8 {
    for r in chain.iter_mut() {
        if r.proto != 0 && r.proto != proto {
            continue;
        }
        // `--sport`: real source-port match (icmp packets carry 0,
        // so a sport rule on udp/tcp can never match icmp — same as
        // Linux).
        if r.sport != 0 && r.sport != sport {
            continue;
        }
        // `-i`/`-o`: the iface the packet arrived/leaves on (1 eth0,
        // 2 lo). The ctl layer already rejects -o on INPUT and -i on
        // OUTPUT, so here one field check covers both directions.
        if r.iface != 0 && r.iface != iface {
            continue;
        }
        if r.oiface != 0 && r.oiface != iface {
            continue;
        }
        if r.dport != 0 && r.dport != dport {
            continue;
        }
        // `-m length --length`: real match on the packet's transport
        // payload length (plen is bytes as seen at the hook).
        if r.len_hi != 0 && (plen < r.len_lo as u64 || plen > r.len_hi as u64) {
            continue;
        }
        // `-m ttl --ttl-eq/--ttl-lt/--ttl-gt`: the packet's real IPv4
        // TTL as it arrived (ingress) or was stamped (egress).
        match r.ttl_mode {
            1 if ttl != r.ttl_v => continue,
            2 if ttl >= r.ttl_v => continue,
            3 if ttl <= r.ttl_v => continue,
            _ => {}
        }
        // `-m tos --tos v[/m]`: real DS-byte match — the mask applies
        // to both sides, exactly like real iptables value[/mask].
        if r.tos_mask != 0 && (tos & r.tos_mask) != (r.tos_v & r.tos_mask) {
            continue;
        }
        // `-m mac --mac-source`: real L2 sender match. lo packets carry
        // no MAC (zeros), and the ctl layer rejects this on OUTPUT —
        // same as Linux (-m mac is an ingress-only match).
        if let Some(m) = r.smac {
            if m != smac {
                continue;
            }
        }
        // `-m dscp --dscp N`: DSCP = the top 6 bits of the DS byte.
        if r.dscp != 0xff && (tos >> 2) != r.dscp {
            continue;
        }
        // `-m icmp --icmp-type N`: the first ICMP payload byte.
        // Non-ICMP packets carry the 0xff sentinel and never match.
        if r.icmp_type != 0xff && itype != r.icmp_type {
            continue;
        }
        // `-m multiport --dports`: real set match on the dest port
        if !r.dports.is_empty() && !r.dports.contains(&dport) {
            continue;
        }
        if r.state != 0 && r.state & st == 0 {
            continue;
        }
        if r.src != [0; 4] {
            let m = u32::from_be_bytes(src) & u32::from_be_bytes(r.smask)
                == u32::from_be_bytes(r.src) & u32::from_be_bytes(r.smask);
            if !m {
                continue;
            }
        }
        // `-m iprange --src-range a-b`: real range containment check
        if let Some((lo, hi)) = r.src_range {
            let s = u32::from_be_bytes(src);
            if s < lo || s > hi {
                continue;
            }
        }
        // `-m limit`: a token bucket on the rule match itself — packets
        // over the rate skip this rule and fall through to the next
        // rule/policy, exactly like real iptables.
        if r.limit_pps != 0 {
            let now = now_ms();
            let refill =
                ((now - r.lim_ms) * r.limit_pps as u64 / 1000).min(255) as u16;
            if refill != 0 {
                r.lim_tokens = (r.lim_tokens + refill).min(r.limit_burst);
                r.lim_ms = now;
            }
            if r.lim_tokens == 0 {
                continue; // over the limit — rule does not match
            }
            r.lim_tokens -= 1;
        }
        r.hits += 1;
        r.bytes += plen;
        if !r.jump.is_empty() {
            // -j <chain>: evaluate the user chain on a snapshot (the
            // FW_USER map can't be re-locked while we hold entries),
            // then write the counters back. Falling off its end =
            // RETURN to this chain; a terminal verdict applies to the
            // packet outright — real iptables semantics.
            if depth >= 16 {
                continue; // loop guard — treat as no-match
            }
            let mut snap = FW_USER.lock().get(&r.jump).cloned().unwrap_or_default();
            let v = fw_eval(&mut snap, inbound, src, dst, proto, sport, dport, st, iface, plen, ttl, tos, smac, itype, depth + 1);
            if let Some(u) = FW_USER.lock().get_mut(&r.jump) {
                *u = snap;
            }
            if v == 255 {
                continue;
            }
            return v;
        }
        if r.target == 1 {
            // -j LOG: audit the packet into the kernel log and fall
            // through to the next rule — the packet is NOT dropped.
            // real iface name in the audit line (lo traffic logs IN=lo)
            let ifname = if iface == 2 { "lo" } else { "eth0" };
            let iface = if inbound { ifname } else { "" };
            let oface = if inbound { "" } else { ifname };
            let pname = match proto { 1 => "icmp", 6 => "tcp", 17 => "udp", n => {
                sprintln!("[fw] IN={} OUT={} SRC={}.{}.{}.{} DST={}.{}.{}.{} LEN={} PROTO={}",
                    iface, oface, src[0], src[1], src[2], src[3],
                    dst[0], dst[1], dst[2], dst[3], plen, n);
                continue;
            }};
            sprintln!("[fw] IN={} OUT={} SRC={}.{}.{}.{} DST={}.{}.{}.{} LEN={} PROTO={} DPT={}",
                iface, oface, src[0], src[1], src[2], src[3],
                dst[0], dst[1], dst[2], dst[3], plen, pname, dport);
            continue;
        }
        if r.target == 3 {
            return 0; // -j ACCEPT: terminal — skips the rest of the chain
        }
        if r.target == 4 {
            return 255; // -j RETURN: leave this chain now
        }
        return if r.target == 2 { 2 } else { 1 };
    }
    255
}

/// OUTPUT -j REJECT: the refusal can't reach a remote — synthesize the
/// exact reply the peer would have sent and queue it on the rx path so
/// the local socket sees an instant refusal (RST for TCP, ICMP 3/3
/// port-unreachable for everything else).
fn out_reject(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, payload: &[u8]) {
    if proto == 6 {
        if let Some(s) = parse_tcp(payload) {
            let mut seg = Vec::with_capacity(20);
            seg.extend_from_slice(&s.dport.to_be_bytes());
            seg.extend_from_slice(&s.sport.to_be_bytes());
            seg.extend_from_slice(&s.ack.to_be_bytes());
            seg.extend_from_slice(&0u32.to_be_bytes());
            seg.push(0x50); // data offset 5
            seg.push(TCP_RST);
            seg.extend_from_slice(&65535u16.to_be_bytes());
            seg.extend_from_slice(&[0u8; 4]); // csum + urg
            let src = if dst_ip[0] == 127 { LOOPBACK_IP } else { dst_ip };
            let me = if is_loopback(src_ip) { LOOPBACK_IP } else { our_ip() };
            let c = tcp_csum(src, me, &seg);
            put16(&mut seg[16..], c);
            LOOPBACK_Q.lock().push_back((src, 6, seg, pkt_meta(def_ttl(), 0, [0; 6])));
        }
    } else {
        // ICMP 3/3 from the destination we "tried" to reach, quoting the
        // offending datagram's header + first 8 payload bytes.
        let mut icmp = Vec::with_capacity(8 + 20 + 8);
        icmp.push(3);
        icmp.push(3);
        icmp.extend_from_slice(&[0u8; 2]);
        icmp.extend_from_slice(&[0u8; 4]);
        icmp.push(0x45);
        icmp.push(0);
        icmp.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        icmp.extend_from_slice(&[0u8; 4]);
        icmp.push(64);
        icmp.push(proto);
        icmp.extend_from_slice(&[0u8; 2]);
        let me = if is_loopback(src_ip) { LOOPBACK_IP } else { our_ip() };
        icmp.extend_from_slice(&me);
        icmp.extend_from_slice(&dst_ip);
        icmp.extend_from_slice(&payload[..payload.len().min(8)]);
        let c = csum(&icmp);
        put16(&mut icmp[2..], c);
        let src = if dst_ip[0] == 127 { LOOPBACK_IP } else { dst_ip };
        LOOPBACK_Q.lock().push_back((src, 1, icmp, pkt_meta(def_ttl(), 0, [0; 6])));
    }
}

/// `/proc/net/iptables` — `iptables -L -n` listing (INPUT + OUTPUT chains).
pub fn net_iptables() -> String {
    let mut out = String::new();
    fmt_fw_chain(&mut out, "INPUT", &FW, &FW_POLICY);
    out.push('\n');
    fmt_fw_chain(&mut out, "OUTPUT", &FW_OUT, &FW_OUT_POLICY);
    // User-defined chains after the builtins — real -L order. Header
    // carries the reference count like the Linux listing.
    let names: Vec<String> = FW_USER.lock().keys().cloned().collect();
    for n in names {
        out.push('\n');
        out.push_str(&alloc::format!(
            "Chain {} ({} references)\nnum  pkts bytes target  prot  source       destination\n",
            n,
            fw_refs(&n)
        ));
        let v = FW_USER.lock().get(&n).cloned().unwrap_or_default();
        for (i, r) in v.iter().enumerate() {
            fmt_fw_rule(&mut out, i, r);
        }
    }
    out
}

/// Canonical `iptables-save` dump (`/proc/net/iptsave`): `*filter` …
/// `COMMIT` — `iptables -S`/`iptables-save` read it, `iptables-restore`
/// feeds the -A lines back through the ctl path, so the round-trip is
/// the same grammar on both legs.
pub fn net_iptsave() -> String {
    let mut out = String::from("*filter\n");
    let def = |out: &mut String, name: &str, pol: bool, ch: &Mutex<Vec<FwRule>>| {
        let (p, b) = ch
            .lock()
            .iter()
            .fold((0u64, 0u64), |(p, b), r| (p + r.hits, b + r.bytes));
        out.push_str(&alloc::format!(
            ":{} {} [{}:{}]\n",
            name,
            if pol { "DROP" } else { "ACCEPT" },
            p,
            b
        ));
    };
    def(&mut out, "INPUT", *FW_POLICY.lock(), &FW);
    def(&mut out, "OUTPUT", *FW_OUT_POLICY.lock(), &FW_OUT);
    let names: Vec<String> = FW_USER.lock().keys().cloned().collect();
    for n in &names {
        out.push_str(&alloc::format!(":{} - [0:0]\n", n));
    }
    // `[pkts:bytes] -A CHAIN spec` — the real `-c` counter prefix.
    for r in FW.lock().iter() {
        out.push_str(&alloc::format!("[{}:{}] -A INPUT", r.hits, r.bytes));
        fmt_fw_spec(&mut out, r);
        out.push('\n');
    }
    for r in FW_OUT.lock().iter() {
        out.push_str(&alloc::format!("[{}:{}] -A OUTPUT", r.hits, r.bytes));
        fmt_fw_spec(&mut out, r);
        out.push('\n');
    }
    for n in &names {
        let v = FW_USER.lock().get(n).cloned().unwrap_or_default();
        for r in v.iter() {
            out.push_str(&alloc::format!("[{}:{}] -A {}", r.hits, r.bytes, n));
            fmt_fw_spec(&mut out, r);
            out.push('\n');
        }
    }
    out.push_str("COMMIT\n");
    out
}

/// One rule in `-A <chain> <spec>` restore syntax — the exact inverse
/// of `fw_parse_spec` via the terminal's `ipt_rule_from_args` flags.
fn fmt_fw_spec(out: &mut String, r: &FwRule) {
    if r.proto != 0 {
        out.push_str(&alloc::format!(
            " -p {}",
            match r.proto {
                1 => String::from("icmp"),
                6 => String::from("tcp"),
                17 => String::from("udp"),
                n => alloc::format!("{}", n),
            }
        ));
    }
    if r.src != [0; 4] {
        let plen: u32 = r.smask.iter().map(|b| b.count_ones()).sum();
        out.push_str(&alloc::format!(
            " -s {}.{}.{}.{}/{}",
            r.src[0], r.src[1], r.src[2], r.src[3], plen
        ));
    }
    if r.iface != 0 {
        out.push_str(if r.iface == 2 { " -i lo" } else { " -i eth0" });
    }
    if r.oiface != 0 {
        out.push_str(if r.oiface == 2 { " -o lo" } else { " -o eth0" });
    }
    if r.sport != 0 {
        out.push_str(&alloc::format!(" --sport {}", r.sport));
    }
    if r.len_hi != 0 {
        if r.len_lo == r.len_hi {
            out.push_str(&alloc::format!(" -m length --length {}", r.len_lo));
        } else {
            out.push_str(&alloc::format!(
                " -m length --length {}:{}",
                r.len_lo, r.len_hi
            ));
        }
    }
    if let Some((lo, hi)) = r.src_range {
        let (lo, hi) = (lo.to_be_bytes(), hi.to_be_bytes());
        out.push_str(&alloc::format!(
            " -m iprange --src-range {}.{}.{}.{}-{}.{}.{}.{}",
            lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]
        ));
    }
    if !r.dports.is_empty() {
        let mut csv = String::new();
        for (i, p) in r.dports.iter().enumerate() {
            if i > 0 {
                csv.push(',');
            }
            csv.push_str(&alloc::format!("{}", p));
        }
        out.push_str(&alloc::format!(" -m multiport --dports {}", csv));
    } else if r.dport != 0 {
        out.push_str(&alloc::format!(" --dport {}", r.dport));
    }
    if r.state != 0 {
        out.push_str(&alloc::format!(
            " -m state --state {}{}{}",
            if r.state & 1 != 0 { "NEW" } else { "" },
            if r.state == 3 { "," } else { "" },
            if r.state & 2 != 0 { "ESTABLISHED" } else { "" }
        ));
    }
    if r.ttl_mode != 0 {
        let op = match r.ttl_mode {
            1 => "--ttl-eq",
            2 => "--ttl-lt",
            _ => "--ttl-gt",
        };
        out.push_str(&alloc::format!(" -m ttl {} {}", op, r.ttl_v));
    }
    if r.tos_mask != 0 {
        if r.tos_mask == 0xff {
            out.push_str(&alloc::format!(" -m tos --tos {}", r.tos_v));
        } else {
            out.push_str(&alloc::format!(" -m tos --tos {}/{}", r.tos_v, r.tos_mask));
        }
    }
    if let Some(m) = r.smac {
        out.push_str(&alloc::format!(
            " -m mac --mac-source {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ));
    }
    if r.dscp != 0xff {
        out.push_str(&alloc::format!(" -m dscp --dscp {}", r.dscp));
    }
    if r.icmp_type != 0xff {
        out.push_str(&alloc::format!(" -m icmp --icmp-type {}", r.icmp_type));
    }
    if r.limit_pps != 0 {
        out.push_str(&alloc::format!(" -m limit --limit {}/s", r.limit_pps));
        if r.limit_burst != 5 {
            out.push_str(&alloc::format!(" --limit-burst {}", r.limit_burst));
        }
    }
    if !r.comment.is_empty() {
        out.push_str(&alloc::format!(" -m comment --comment \"{}\"", r.comment));
    }
    out.push_str(&alloc::format!(
        " -j {}",
        if !r.jump.is_empty() {
            r.jump.clone()
        } else {
            String::from(match r.target {
                1 => "LOG",
                2 => "REJECT",
                3 => "ACCEPT",
                4 => "RETURN",
                _ => "DROP",
            })
        }
    ));
}

fn fmt_fw_chain(
    out: &mut String,
    name: &str,
    chain: &Mutex<Vec<FwRule>>,
    policy: &Mutex<bool>,
) {
    out.push_str(&alloc::format!(
        "Chain {} (policy {})\nnum  pkts bytes target  prot  source       destination\n",
        name,
        if *policy.lock() { "DROP" } else { "ACCEPT" }
    ));
    for (i, r) in chain.lock().iter().enumerate() {
        fmt_fw_rule(out, i, r);
    }
}

/// One `-L` rule row: num, pkts, bytes, target (builtin verb or the
/// jumped-to chain name), proto, source, matcher detail.
fn fmt_fw_rule(out: &mut String, i: usize, r: &FwRule) {
    let tgt = if !r.jump.is_empty() {
        r.jump.clone()
    } else {
        String::from(match r.target {
            1 => "LOG",
            2 => "REJECT",
            3 => "ACCEPT",
            4 => "RETURN",
            _ => "DROP",
        })
    };
    let proto = match r.proto {
        1 => String::from("icmp"),
        6 => String::from("tcp"),
        17 => String::from("udp"),
        n => alloc::format!("{}", n),
    };
    let src = if r.src == [0; 4] {
        String::from("0.0.0.0/0")
    } else {
        let plen = r.smask.iter().map(|b| b.count_ones()).sum::<u32>();
        alloc::format!("{}.{}.{}.{}/{}", r.src[0], r.src[1], r.src[2], r.src[3], plen)
    };
    let mut extra = if r.dport != 0 {
        alloc::format!("  {} dpt:{}", proto, r.dport)
    } else {
        String::new()
    };
    if !r.dports.is_empty() {
        let mut csv = String::new();
        for (i, p) in r.dports.iter().enumerate() {
            if i > 0 {
                csv.push(',');
            }
            csv.push_str(&alloc::format!("{}", p));
        }
        extra.push_str(&alloc::format!(" multiport dpts:{}", csv));
    }
    if let Some((lo, hi)) = r.src_range {
        let fmt = |v: u32| {
            let b = v.to_be_bytes();
            alloc::format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        };
        extra.push_str(&alloc::format!(
            " iprange src-range:{}-{}",
            fmt(lo),
            fmt(hi)
        ));
    }
    if r.state != 0 {
        extra.push_str(&alloc::format!(
            "  state {}",
            match r.state {
                1 => "NEW",
                2 => "ESTABLISHED",
                _ => "NEW,ESTABLISHED",
            }
        ));
    }
    if r.iface != 0 {
        extra.push_str(if r.iface == 2 { "  in:lo" } else { "  in:eth0" });
    }
    if r.oiface != 0 {
        extra.push_str(if r.oiface == 2 { "  out:lo" } else { "  out:eth0" });
    }
    if r.sport != 0 {
        extra.push_str(&alloc::format!("  spt:{}", r.sport));
    }
    if r.tos_mask != 0 {
        extra.push_str(&alloc::format!("  tos match 0x{:02x}/0x{:02x}", r.tos_v, r.tos_mask));
    }
    if let Some(m) = r.smac {
        extra.push_str(&alloc::format!(
            "  MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ));
    }
    if r.dscp != 0xff {
        extra.push_str(&alloc::format!("  DSCP 0x{:02x}", r.dscp));
    }
    if r.icmp_type != 0xff {
        extra.push_str(&alloc::format!("  icmptype {}", r.icmp_type));
    }
    if r.len_hi != 0 {
        if r.len_lo == r.len_hi {
            extra.push_str(&alloc::format!("  length {}", r.len_lo));
        } else {
            extra.push_str(&alloc::format!("  length {}:{}", r.len_lo, r.len_hi));
        }
    }
    if r.limit_pps != 0 {
        extra.push_str(&alloc::format!(
            "  limit: avg {}/sec burst {}",
            r.limit_pps, r.limit_burst
        ));
    }
    if !r.comment.is_empty() {
        extra.push_str(&alloc::format!(" /* {} */", r.comment));
    }
    out.push_str(&alloc::format!(
        "{:<4} {:<5} {:<6} {:<8} {:<6} {:<12} 0.0.0.0/0{}\n",
        i + 1,
        r.hits,
        r.bytes,
        tgt,
        proto,
        src,
        extra
    ));
}

/// `/proc/net/snmp` — Linux-format IP/ICMP/TCP/UDP counters for `netstat -s`.
/// InReceives counts everything arriving (incl. packets the INPUT filter then
/// drops); InDelivers is what survived filtering.
pub fn net_snmp() -> String {
    alloc::format!(
        "Ip: Forwarding DefaultTTL InReceives InDelivers OutRequests\n\
         Ip: 2 64 {} {} {}\n\
         Icmp: InMsgs OutMsgs InEchoReqs OutEchoReps InEchoReps OutEchoReqs\n\
         Icmp: {} {} {} {} {} {}\n\
         Tcp: InSegs OutSegs\n\
         Tcp: {} {}\n\
         Udp: InDatagrams OutDatagrams\n\
         Udp: {} {}\n",
        IP_IN_RECV.load(Ordering::Relaxed),
        IP_IN_DELIV.load(Ordering::Relaxed),
        IP_OUT_REQ.load(Ordering::Relaxed),
        ICMP_IN.load(Ordering::Relaxed),
        ICMP_OUT.load(Ordering::Relaxed),
        ICMP_IN_ECHOREQ.load(Ordering::Relaxed),
        ICMP_OUT_ECHOREP.load(Ordering::Relaxed),
        ICMP_IN_ECHOREP.load(Ordering::Relaxed),
        ICMP_OUT_ECHOREQ.load(Ordering::Relaxed),
        TCP_IN.load(Ordering::Relaxed),
        TCP_OUT.load(Ordering::Relaxed),
        UDP_IN.load(Ordering::Relaxed),
        UDP_OUT.load(Ordering::Relaxed),
    )
}

/// `/proc/net/nf_conntrack` — the REAL conntrack flow table (CT),
/// Linux two-tuple format: orig direction then reply direction,
/// `[UNREPLIED]` when the flow never saw a return packet. Entries are
/// born on the first packet of a flow in either direction — this is
/// the same table `-m state` matches against.
pub fn net_conntrack() -> String {
    let mut out = String::new();
    let mut ct = CT.lock();
    // a read is a real expiry pass too, like conntrack's lazy gc
    ct_expire(&mut *ct);
    let now = now_ms();
    for e in ct.iter() {
        let pname = match e.proto {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            _ => "ip",
        };
        let a = alloc::format!("{}.{}.{}.{}", e.a_ip[0], e.a_ip[1], e.a_ip[2], e.a_ip[3]);
        let b = alloc::format!("{}.{}.{}.{}", e.b_ip[0], e.b_ip[1], e.b_ip[2], e.b_ip[3]);
        out.push_str(&alloc::format!(
            "{:<8} {:<2} {:<11} timeout={} src={} dst={} sport={} dport={} src={} dst={} sport={} dport={}{}\n",
            pname, e.proto,
            if e.seen_reply { "ESTABLISHED" } else { "NEW" },
            (ct_timeout(e) - (now - e.last_ms)) / 1000,
            a, b, e.a_port, e.b_port,
            b, a, e.b_port, e.a_port,
            if e.seen_reply { "" } else { " [UNREPLIED]" },
        ));
    }
    out
}

/// `/proc/net/nf_conntrack` write grammar (the `conntrack` tool's ops):
///   "F"  flush the whole table
///   "D <proto> <src> <dst> <sport> <dport>"  delete one flow (orig tuple)
pub fn ct_ctl(line: &str) -> bool {
    let mut f = line.split_whitespace();
    match f.next() {
        Some("F") => {
            CT.lock().clear();
            true
        }
        Some("D") => {
            let proto: u8 = match f.next().unwrap_or("") {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                s => s.parse().unwrap_or(255),
            };
            let (Some(src), Some(dst)) = (f.next().and_then(parse_ip), f.next().and_then(parse_ip))
            else {
                return false;
            };
            let sport: u16 = f.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let dport: u16 = f.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let mut ct = CT.lock();
            let before = ct.len();
            ct.retain(|e| !(e.proto == proto && e.a_ip == src && e.b_ip == dst
                && e.a_port == sport && e.b_port == dport));
            ct.len() != before
        }
        _ => false,
    }
}

/// `/proc/net/arp` — Linux-format ARP cache (type 0x1 ether, flags 0x2
/// complete, mask `*`, dev eth0) — same entries `arp` prints.
pub fn net_arp() -> String {
    let mut s = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    for e in ARP_CACHE.lock().iter() {
        s.push_str(&alloc::format!(
            "{:<17}0x1         0x{:<2}        {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}     *        eth0\n",
            alloc::format!("{}.{}.{}.{}", e.ip[0], e.ip[1], e.ip[2], e.ip[3]),
            if e.perm { 6 } else { 2 }, // ATF_COM|ATF_PERM vs ATF_COM
            e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4], e.mac[5],
        ));
    }
    s
}

/// `/proc/net/neigh` — the neighbour table in `ip neigh` format, with
/// real NUD states derived from each entry's learned time.
pub fn net_neigh() -> String {
    let mut s = String::new();
    for e in ARP_CACHE.lock().iter() {
        s.push_str(&alloc::format!(
            "{}.{}.{}.{} dev eth0 lladdr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} used {} {}\n",
            e.ip[0], e.ip[1], e.ip[2], e.ip[3],
            e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4], e.mac[5],
            (now_ms() - e.learned_ms) / 1000,
            arp_state(e),
        ));
    }
    s
}

/// `/proc/net/fib_trie` — the main routing table as a Linux-format
/// prefix tree: one `+-- <net>` grouping per distinct route, with the
/// leaf prefixes and their route attributes nested under it. Local
/// routes (127/8, our own /32, broadcasts) show under `Local:`.
pub fn net_fib_trie() -> String {
    let mut g = ROUTES.lock();
    let r = g.get_or_insert_with(default_routes);
    let dot = |ip: [u8; 4]| alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    let plen = |m: [u8; 4]| {
        (u32::from_be_bytes(m)).count_ones()
    };
    // the kernel's fixed local delivery rules, like Linux's Local table
    let mut out = String::from("Local:\n");
    out.push_str(" +-- 127.0.0.0/8\n");
    out.push_str("    |-- 127.0.0.0\n       /8 host LOCAL\n");
    out.push_str("    |-- 127.255.255.255\n       /32 host LOCAL\n");
    let ip = our_ip();
    out.push_str(&alloc::format!(
        " +-- {}.{}.{}.{}/32\n    |-- {}.{}.{}.{}\n       /32 host LOCAL\n",
        ip[0], ip[1], ip[2], ip[3], ip[0], ip[1], ip[2], ip[3]
    ));
    // each ROUTES entry becomes its own leaf chain (flat table = flat trie)
    out.push_str("Main:\n");
    for rt in r.iter() {
        let p = plen(rt.mask);
        let base = dot(rt.dest);
        let gw = dot(rt.gw);
        let via = if rt.gw == [0; 4] {
            alloc::format!("link dev {}", rt.dev)
        } else {
            alloc::format!("via {} dev {}", gw, rt.dev)
        };
        let scope = if rt.gw == [0; 4] { "link" } else { "universe" };
        out.push_str(&alloc::format!(" +-- {}/{}\n", base, p));
        out.push_str(&alloc::format!(
            "    |-- {}\n       /{} {} UNICAST {}\n",
            base, p, scope, via
        ));
        if rt.gw == [0; 4] && rt.dev == "eth0" {
            // connected nets get a subnet broadcast, like Linux's LOCAL
            let b = dot([
                rt.dest[0] | !rt.mask[0],
                rt.dest[1] | !rt.mask[1],
                rt.dest[2] | !rt.mask[2],
                rt.dest[3] | !rt.mask[3],
            ]);
            out.push_str(&alloc::format!(
                "    |-- {}\n       /32 host LOCAL dev {}\n",
                b, rt.dev
            ));
        }
    }
    out
}

/// `/proc/sys/net/ipv4/icmp_echo_ignore_all` — 0/1 sysctl body.
pub fn net_icmp_ignore_all() -> String {
    alloc::format!(
        "{}\n",
        ICMP_IGNORE_ALL.load(Ordering::Relaxed)
    )
}

/// sysctl write: `icmp_echo_ignore_all` — silences the echo responder.
pub fn set_icmp_ignore_all(v: u64) {
    ICMP_IGNORE_ALL.store(v, Ordering::Relaxed);
}

/// Which chain a ctl line targets: a builtin or a registered user chain.
enum ChainSel {
    In,
    Out,
    User(String),
}

/// Chain token → selector. Builtin names always resolve; a user name
/// resolves only when registered — anything else is left for the proto
/// parser, which is how the no-chain compat form (`A 6 dport 80 drop`)
/// keeps landing on INPUT.
fn fw_chain_sel(t: &str) -> Option<ChainSel> {
    match t {
        "IN" | "INPUT" => Some(ChainSel::In),
        "OUT" | "OUTPUT" => Some(ChainSel::Out),
        "FORWARD" => None, // reserved builtin — no forwarding plane here
        n if FW_USER.lock().contains_key(n) => Some(ChainSel::User(String::from(n))),
        _ => None,
    }
}

/// Run `f` on the rules Vec behind a selector; None for a user chain
/// that vanished between name resolution and use.
fn fw_with_chain<R>(c: &ChainSel, f: impl FnOnce(&mut Vec<FwRule>) -> R) -> Option<R> {
    match c {
        ChainSel::In => Some(f(&mut FW.lock())),
        ChainSel::Out => Some(f(&mut FW_OUT.lock())),
        ChainSel::User(n) => FW_USER.lock().get_mut(n).map(f),
    }
}

/// `iptables -N` name validation: ≤28 chars (the real netfilter limit),
/// not numeric, not a builtin name, spec keyword, proto or target word —
/// any of those would shadow the rule grammar in a ctl line.
fn fw_name_ok(n: &str) -> bool {
    const RSVD: &[&str] = &[
        "IN", "OUT", "INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING",
        "icmp", "tcp", "udp", "all", "*", "dport", "multiport", "range", "src",
        "state", "limit", "lburst", "log", "reject", "accept", "return", "drop",
        "iif", "oif", "sport", "length", "comment", "ttl", "tos", "mac",
        "dscp", "icmpt",
    ];
    !n.is_empty()
        && n.len() <= 28
        && n.parse::<u64>().is_err()
        && !RSVD.iter().any(|r| r.eq_ignore_ascii_case(n))
}

/// Number of rules anywhere that jump to `name` — the `-X` reference
/// guard and the "(N references)" chain header in the listing.
fn fw_refs(name: &str) -> usize {
    let mut n = FW
        .lock()
        .iter()
        .chain(FW_OUT.lock().iter())
        .filter(|r| r.jump == name)
        .count();
    let u = FW_USER.lock();
    for v in u.values() {
        n += v.iter().filter(|r| r.jump == name).count();
    }
    n
}

/// `/proc/net/iptables` write grammar (kernel side of the `iptables` cmd).
/// Chain words: `IN`/`INPUT`, `OUT`/`OUTPUT`, or any registered user
/// chain name; absent = INPUT (compat with the no-chain emit form).
///   "F [chain]"  flush all chains, or one
///   "Z [chain]"  zero rule counters (all chains, or one)
///   "N <name>"   create a user chain           "X [name]"  delete empty unreferenced chain(s)
///   "E <o> <n>"  rename a user chain           "P [chain] <v>"  builtin policy only
///   "A|I <ch> [n] <proto> <spec>"  append/insert rule
///   "R <ch> <n> <proto> <spec>"    replace rule
///   "D <ch> <n>" | "D <ch> <proto> <spec>"     delete by position / by spec
/// Returns false on a parse miss.
/// Post-op chain token resolution shared by D/R/P/A/I: the token may
/// name a builtin or registered user chain; otherwise it stays as the
/// operand (proto/policy) on the INPUT chain.
fn fw_chain_tok<'a>(f: &mut core::str::SplitWhitespace<'a>) -> (ChainSel, Option<&'a str>) {
    let t = f.next();
    match t.and_then(fw_chain_sel) {
        Some(c) => (c, f.next()),
        None => (ChainSel::In, t),
    }
}

pub fn iptables_ctl(line: &str) -> bool {
    let mut f = line.split_whitespace();
    match f.next() {
        // `F` bare flushes every chain incl. user chains (real iptables
        // -F semantics); `F <chain>` flushes just that one.
        Some("F") => match f.next() {
            None => {
                FW.lock().clear();
                FW_OUT.lock().clear();
                for v in FW_USER.lock().values_mut() {
                    v.clear();
                }
                true
            }
            Some(t) => match fw_chain_sel(t) {
                Some(c) => fw_with_chain(&c, |v| {
                    v.clear();
                    true
                })
                .unwrap_or(false),
                None => false,
            },
        },
        Some("Z") => match f.next() {
            None => {
                let z = |v: &mut Vec<FwRule>| {
                    for r in v.iter_mut() {
                        r.hits = 0;
                        r.bytes = 0;
                    }
                };
                z(&mut FW.lock());
                z(&mut FW_OUT.lock());
                for v in FW_USER.lock().values_mut() {
                    z(v);
                }
                true
            }
            Some(t) => match fw_chain_sel(t) {
                Some(c) => fw_with_chain(&c, |v| {
                    for r in v.iter_mut() {
                        r.hits = 0;
                        r.bytes = 0;
                    }
                    true
                })
                .unwrap_or(false),
                None => false,
            },
        },
        // `N <name>` — create an empty user chain (must not exist).
        Some("N") => match f.next() {
            Some(n) if fw_name_ok(n) => {
                let mut u = FW_USER.lock();
                if u.contains_key(n) {
                    false
                } else {
                    u.insert(String::from(n), Vec::new());
                    true
                }
            }
            _ => false,
        },
        // `X <name>` — delete an empty user chain nothing jumps to;
        // bare `X` removes every chain that qualifies (real iptables).
        Some("X") => match f.next() {
            Some(n) => {
                let ok = FW_USER.lock().get(n).map(|v| v.is_empty()) == Some(true)
                    && fw_refs(n) == 0;
                ok && FW_USER.lock().remove(n).is_some()
            }
            None => {
                let names: Vec<String> = FW_USER
                    .lock()
                    .iter()
                    .filter(|(_, v)| v.is_empty())
                    .map(|(n, _)| n.clone())
                    .collect();
                for n in names {
                    if fw_refs(&n) == 0 {
                        FW_USER.lock().remove(&n);
                    }
                }
                true
            }
        },
        // `Q <ch> <proto> <spec>` — check-rule-exists (`iptables -C`):
        // same parse as spec-delete, returns whether a rule matches.
        Some("Q") => {
            let (ch, t) = fw_chain_tok(&mut f);
            let Some(pr) = fw_proto_tok(t) else {
                return false;
            };
            let Some(want) = fw_parse_spec(&mut f, pr) else {
                return false;
            };
            if !fw_dir_ok(&ch, &want) {
                return false;
            }
            fw_with_chain(&ch, |v| v.iter().any(|r| fw_rule_eq(r, &want)))
                .unwrap_or(false)
        }
        // `C <ch> <pkts> <bytes>` — counter restore (`iptables-restore
        // -c`): applies to the last rule of the named chain, which is
        // the one the preceding `-A` line just appended.
        Some("C") => {
            let (ch, p) = fw_chain_tok(&mut f);
            let (Some(p), Some(b)) = (
                p.and_then(|s| s.parse::<u64>().ok()),
                f.next().and_then(|s| s.parse::<u64>().ok()),
            ) else {
                return false;
            };
            fw_with_chain(&ch, |v| match v.last_mut() {
                Some(r) => {
                    r.hits = p;
                    r.bytes = b;
                    true
                }
                None => false,
            })
            .unwrap_or(false)
        }
        // `E <old> <new>` — rename a user chain; jumps keep working
        // because netfilter refs the chain, not the name — so rewrite
        // every jump field equal to `old`.
        Some("E") => {
            let (Some(o), Some(n)) = (f.next(), f.next()) else {
                return false;
            };
            if !fw_name_ok(n) || FW_USER.lock().contains_key(n) {
                return false;
            }
            let Some(v) = FW_USER.lock().remove(o) else {
                return false;
            };
            FW_USER.lock().insert(String::from(n), v);
            for r in FW.lock().iter_mut().chain(FW_OUT.lock().iter_mut()) {
                if r.jump == o {
                    r.jump = String::from(n);
                }
            }
            for v in FW_USER.lock().values_mut() {
                for r in v.iter_mut() {
                    if r.jump == o {
                        r.jump = String::from(n);
                    }
                }
            }
            true
        }
        // `D <chain> <n>` positional or `D <chain> <proto> <spec>` —
        // spec deletes the FIRST rule whose matcher+target equals it.
        Some("D") => {
            let (ch, t) = fw_chain_tok(&mut f);
            // Positional vs spec: a bare number with nothing after it is a
            // rule number; a proto token (numeric or named) followed by
            // more spec words is a spec delete.
            if t.and_then(|s| s.parse::<usize>().ok()).is_some()
                && f.clone().next().is_none()
            {
                let n: usize = t.and_then(|s| s.parse().ok()).unwrap_or(0);
                return fw_with_chain(&ch, |fw| {
                    if n == 0 || n > fw.len() {
                        false
                    } else {
                        fw.remove(n - 1);
                        true
                    }
                })
                .unwrap_or(false);
            }
            let Some(proto) = fw_proto_tok(t) else {
                return false;
            };
            let Some(want) = fw_parse_spec(&mut f, proto) else {
                return false;
            };
            if !fw_dir_ok(&ch, &want) {
                return false;
            }
            fw_with_chain(&ch, |fw| match fw.iter().position(|r| fw_rule_eq(r, &want)) {
                Some(i) => {
                    fw.remove(i);
                    true
                }
                None => false,
            })
            .unwrap_or(false)
        }
        // `R <chain> <n> <proto> <spec>` — real `iptables -R`: replaces
        // the 1-based rule wholesale (the replaced rule's counters reset).
        Some("R") => {
            let (ch, t) = fw_chain_tok(&mut f);
            let n: usize = t.and_then(|s| s.parse().ok()).unwrap_or(0);
            let Some(proto) = fw_proto_tok(f.next()) else {
                return false;
            };
            let Some(r) = fw_parse_spec(&mut f, proto) else {
                return false;
            };
            if !fw_dir_ok(&ch, &r) {
                return false; // -o on INPUT / -i on OUTPUT
            }
            if !r.jump.is_empty() && !FW_USER.lock().contains_key(&r.jump) {
                return false; // -j to a chain that doesn't exist
            }
            fw_with_chain(&ch, |fw| {
                if n == 0 || n > fw.len() {
                    false
                } else {
                    fw[n - 1] = r;
                    true
                }
            })
            .unwrap_or(false)
        }
        // `P <chain> <v>` — policy is a builtin-chain concept; setting
        // one on a user chain is an error, like real iptables.
        Some("P") => {
            let t = f.next();
            let (ch, t) = match t.and_then(fw_chain_sel) {
                Some(c @ (ChainSel::In | ChainSel::Out)) => (c, f.next()),
                Some(ChainSel::User(_)) => return false,
                None => (ChainSel::In, t),
            };
            let pol = if matches!(ch, ChainSel::Out) {
                &FW_OUT_POLICY
            } else {
                &FW_POLICY
            };
            match t {
                Some("ACCEPT") => {
                    *pol.lock() = false;
                    true
                }
                Some("DROP") => {
                    *pol.lock() = true;
                    true
                }
                _ => false,
            }
        }
        // `A` appends, `I <n>` inserts at 1-based position n — real
        // iptables -I ordering semantics, on any chain.
        Some(op @ ("A" | "I")) => {
            let (ch, t) = fw_chain_tok(&mut f);
            let (ins, t) = if op == "I" {
                (
                    Some(t.and_then(|s| s.parse().ok()).unwrap_or(1).max(1)),
                    f.next(),
                )
            } else {
                (None, t)
            };
            let Some(proto) = fw_proto_tok(t) else {
                return false;
            };
            let Some(r) = fw_parse_spec(&mut f, proto) else {
                return false;
            };
            if !fw_dir_ok(&ch, &r) {
                return false; // -o on INPUT / -i on OUTPUT
            }
            if !r.jump.is_empty() && !FW_USER.lock().contains_key(&r.jump) {
                return false; // -j to a chain that doesn't exist
            }
            fw_with_chain(&ch, |fw| {
                match ins {
                    Some(n) => {
                        let pos = (n - 1).min(fw.len());
                        fw.insert(pos, r);
                    }
                    None => fw.push(r),
                }
            })
            .is_some()
        }
        _ => false,
    }
}

/// Protocol token shared by the A/I/R/D rule ops.
fn fw_proto_tok(t: Option<&str>) -> Option<u8> {
    match t {
        Some("*") | Some("all") => Some(0),
        Some("icmp") => Some(1),
        Some("tcp") => Some(6),
        Some("udp") => Some(17),
        Some(n) => Some(n.parse().unwrap_or(0)),
        None => None,
    }
}

/// `-i`/`-o` interface name → internal code (0 = wildcard). Real
/// iptables accepts any name and the rule just never matches on
/// missing hardware — here unknown names are a parse error so a typo
/// can't silently install a dead rule.
fn fw_ifx(s: &str) -> Option<u8> {
    match s {
        "+" | "any" => Some(0),
        "eth0" => Some(1),
        "lo" => Some(2),
        _ => None,
    }
}

/// Real direction-vs-chain rule: `-o` is meaningless on INPUT and `-i`
/// on OUTPUT (iptables rejects both at add time). User chains take
/// either — they can be jumped to from both builtins.
fn fw_dir_ok(ch: &ChainSel, r: &FwRule) -> bool {
    match ch {
        ChainSel::In => r.oiface == 0,
        ChainSel::Out => r.iface == 0 && r.smac.is_none(),
        ChainSel::User(_) => true,
    }
}

/// Rule-spec tail parser (`dport`/`multiport`/`range`/`src`/`state`/
/// `limit`/`lburst`/target words) shared by the A/I/R/D ops — returns
/// None on any token it doesn't understand, like real iptables.
fn fw_parse_spec<'a, I: Iterator<Item = &'a str>>(f: &mut I, proto: u8) -> Option<FwRule> {
    let mut r = FwRule {
        proto,
        dport: 0,
        dports: Vec::new(),
        src: [0; 4],
        smask: [0; 4],
        src_range: None,
        sport: 0,
        len_lo: 0,
        len_hi: 0,
        iface: 0,
        oiface: 0,
        state: 0,
        ttl_mode: 0,
        ttl_v: 0,
        tos_v: 0,
        tos_mask: 0,
        smac: None,
        dscp: 0xff,
        icmp_type: 0xff,
        limit_pps: 0,
        comment: String::new(),
        limit_burst: 5,
        lim_tokens: 5,
        lim_ms: 0,
        target: 0,
        jump: String::new(),
        hits: 0,
        bytes: 0,
    };
    let mut ok = true;
    while let Some(k) = f.next() {
        match k {
            "dport" => {
                r.dport = f.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                if r.dport == 0 {
                    ok = false;
                }
            }
            // `--sport <n>` — real source-port match on tcp/udp.
            "sport" => {
                r.sport = f.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                if r.sport == 0 {
                    ok = false;
                }
            }
            // `-m length --length <a>[:<b>]` — real packet-size match
            // on the transport payload length.
            "length" => {
                let spec = f.next().unwrap_or("");
                let (a, b) = match spec.split_once(':') {
                    Some((a, b)) => (a, b),
                    None => (spec, spec), // bare N => exact length
                };
                match (a.parse::<u32>(), b.parse::<u32>()) {
                    (Ok(lo), Ok(hi)) if lo <= hi => {
                        r.len_lo = lo;
                        r.len_hi = hi;
                    }
                    _ => ok = false,
                }
            }
            // `-m iprange --src-range <a>-<b>`
            "range" => {
                let spec = f.next().unwrap_or("");
                match spec.split_once('-') {
                    Some((a, b)) => match (parse_ip(a), parse_ip(b)) {
                        (Some(lo), Some(hi)) => {
                            let (lo, hi) =
                                (u32::from_be_bytes(lo), u32::from_be_bytes(hi));
                            if lo <= hi {
                                r.src_range = Some((lo, hi));
                            } else {
                                ok = false;
                            }
                        }
                        _ => ok = false,
                    },
                    None => ok = false,
                }
            }
            // `-m multiport --dports a,b,..` (15 max, like Linux)
            "multiport" => {
                r.dports = f
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|s| s.parse::<u16>().ok())
                    .take(15)
                    .collect();
                if r.dports.is_empty() {
                    ok = false;
                }
            }
            "src" => {
                let spec = f.next().unwrap_or("");
                let (ip, plen) = match spec.split_once('/') {
                    Some((d, p)) => (d, p.parse::<u32>().unwrap_or(32)),
                    None => (spec, 32),
                };
                if plen > 32 {
                    ok = false;
                    break;
                }
                let mask = if plen == 0 { 0u32 } else { u32::MAX << (32 - plen) };
                match parse_ip(ip) {
                    Some(ip) => {
                        r.src = ip;
                        r.smask = mask.to_be_bytes();
                    }
                    None => ok = false,
                }
            }
            // `-i <if>`/`-o <if>` — real iface match (lo|eth0; `+`/`any`
            // = wildcard). Direction-vs-chain validity is checked by the
            // ctl ops, which know the target chain.
            "iif" => match fw_ifx(f.next().unwrap_or("")) {
                Some(x) => r.iface = x,
                None => ok = false,
            },
            "oif" => match fw_ifx(f.next().unwrap_or("")) {
                Some(x) => r.oiface = x,
                None => ok = false,
            },
            // `-m state --state NEW|ESTABLISHED[,...]` — real
            // conntrack-state match against the live flow tables.
            "state" => {
                let mut m = 0u8;
                for s in f.next().unwrap_or("").split(',') {
                    match s {
                        "NEW" => m |= 1,
                        "ESTABLISHED" => m |= 2,
                        "RELATED" => m |= 2, // lo/tracked ~= established here
                        _ => {}
                    }
                }
                if m == 0 {
                    ok = false;
                } else {
                    r.state = m;
                }
            }
            // `-m limit --limit N/s` — cap this rule's match rate;
            // `limit N` + optional `lburst B`.
            "limit" => {
                let v = f.next().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                if v == 0 {
                    ok = false;
                } else {
                    r.limit_pps = v;
                }
            }
            // `-m comment --comment` — stored on the rule like real
            // iptables (shows in -L/-S, ignored by the matcher).
            "comment" => {
                r.comment = String::from(f.next().unwrap_or(""));
            }
            // `-m ttl --ttl-{eq,lt,gt} N` — wire token `ttl <op>:<N>`.
            "ttl" => {
                let spec = f.next().unwrap_or("");
                if let Some((op, n)) = spec.split_once(':') {
                    r.ttl_v = n.parse().unwrap_or(0);
                    r.ttl_mode = match op {
                        "eq" => 1,
                        "lt" => 2,
                        "gt" => 3,
                        _ => 0,
                    };
                    if r.ttl_mode == 0 {
                        ok = false;
                    }
                } else {
                    ok = false;
                }
            }
            // `-m tos --tos <v>[/<m>]` — DS-byte match; the value and
            // mask parse dec or 0xNN hex (real iptables form).
            "tos" => {
                let spec = f.next().unwrap_or("");
                let (v, m) = match spec.split_once('/') {
                    Some((a, b)) => (a, b),
                    None => (spec, "0xff"),
                };
                let pv = |s: &str| -> Option<u8> {
                    if let Some(h) = s.strip_prefix("0x") {
                        u8::from_str_radix(h, 16).ok()
                    } else {
                        s.parse().ok()
                    }
                };
                match (pv(v), pv(m)) {
                    (Some(vv), Some(mm)) => {
                        r.tos_v = vv;
                        r.tos_mask = mm;
                        if mm == 0 {
                            ok = false;
                        }
                    }
                    _ => ok = false,
                }
            }
            // `-m dscp --dscp <n>` — DiffServ codepoint (tos>>2).
            "dscp" => {
                r.dscp = f.next().unwrap_or("").parse().unwrap_or(0xff);
                if r.dscp > 63 {
                    ok = false;
                }
            }
            // `-m icmp --icmp-type <n>` — ICMP type byte match.
            "icmpt" => {
                r.icmp_type = f.next().unwrap_or("").parse().unwrap_or(0xff);
                if r.icmp_type == 0xff {
                    ok = false;
                }
            }
            // `-m mac --mac-source aa:bb:cc:dd:ee:ff` — L2 sender.
            "mac" => {
                let spec = f.next().unwrap_or("");
                let mut m = [0u8; 6];
                let mut good = !spec.is_empty();
                let mut n = 0usize;
                for b in spec.split(':') {
                    if n >= 6 || b.len() != 2 {
                        good = false;
                        break;
                    }
                    match u8::from_str_radix(b, 16) {
                        Ok(x) => m[n] = x,
                        Err(_) => {
                            good = false;
                            break;
                        }
                    }
                    n += 1;
                }
                if !good || n != 6 {
                    ok = false;
                } else {
                    r.smac = Some(m);
                }
            }
            "lburst" => {
                let v = f.next().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                if v == 0 {
                    ok = false;
                } else {
                    r.limit_burst = v;
                    r.lim_tokens = v;
                }
            }
            "log" => r.target = 1,    // "... log" marks -j LOG
            "reject" => r.target = 2, // -j REJECT: refusal goes back
            "accept" => r.target = 3, // -j ACCEPT: terminal allow
            "return" => r.target = 4, // -j RETURN: leave the chain
            "drop" => r.target = 0,
            // any other trailing word is a `-j <name>` user-chain jump —
            // the ctl ops reject it if the chain isn't registered.
            n => r.jump = String::from(n),
        }
    }
    ok.then_some(r)
}

/// Spec-equality for `D <spec>`: matcher fields + target, ignoring
/// counters and live limiter state.
fn fw_rule_eq(a: &FwRule, b: &FwRule) -> bool {
    a.proto == b.proto
        && a.dport == b.dport
        && a.dports == b.dports
        && a.src == b.src
        && a.smask == b.smask
        && a.src_range == b.src_range
        && a.sport == b.sport
        && a.len_lo == b.len_lo
        && a.len_hi == b.len_hi
        && a.iface == b.iface
        && a.oiface == b.oiface
        && a.tos_v == b.tos_v
        && a.tos_mask == b.tos_mask
        && a.smac == b.smac
        && a.dscp == b.dscp
        && a.icmp_type == b.icmp_type
        && a.state == b.state
        && a.ttl_mode == b.ttl_mode
        && a.ttl_v == b.ttl_v
        && a.limit_pps == b.limit_pps
        && a.comment == b.comment
        && a.limit_burst == b.limit_burst
        && a.target == b.target
        && a.jump == b.jump
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
fn pump_rx() -> Vec<([u8; 4], u8, Vec<u8>, u64)> {
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
    // protocol counters: InReceives counts everything that arrived (incl.
    // packets the INPUT filter is about to drop), InDelivers post-filter.
    for (_, proto, p, _) in &out {
        IP_IN_RECV.fetch_add(1, Ordering::Relaxed);
        match *proto {
            1 => {
                ICMP_IN.fetch_add(1, Ordering::Relaxed);
                if p.len() >= 1 {
                    if p[0] == 8 {
                        ICMP_IN_ECHOREQ.fetch_add(1, Ordering::Relaxed);
                    } else if p[0] == 0 {
                        ICMP_IN_ECHOREP.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            6 => { TCP_IN.fetch_add(1, Ordering::Relaxed); }
            17 => { UDP_IN.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }
    // iptables INPUT: every inbound packet is evaluated once here at ingress —
    // wire, slirp-forwarded, and loopback alike — before dispatch, raw
    // consumers (ping/dhcp), or the ICMP echo responder can see it.
    out.retain(|(src_ip, proto, p, meta)| {
        let (sport, dport) = pkt_ports(*proto, p);
        // each packet updates the real conntrack flow table, then the
        // INPUT chain sees that packet's own NEW/ESTABLISHED state. The
        // dst half of the tuple is the interface address the packet
        // arrived for — 127.0.0.1 on lo, our address everywhere else —
        // so loopback flows pair with their tx counterparts.
        let dst = if is_loopback(*src_ip) { LOOPBACK_IP } else { our_ip() };
        let st = ct_update(*src_ip, dst, sport, dport, *proto);
        // Arrival iface: loopback-queued packets always carry a local
        // source (127/8 or our own address); wire packets don't.
        let ifx = if is_loopback(*src_ip) { 2u8 } else { 1 };
        let itype = if *proto == 1 && !p.is_empty() { p[0] } else { 0xff };
        let v = fw_verdict(&FW, &FW_POLICY, true, *src_ip, dst, *proto, sport, dport, st, ifx, p.len() as u64, meta_ttl(*meta), meta_tos(*meta), meta_mac(*meta), itype);
        if v == 2 {
            // -j REJECT: a real refusal goes back — TCP_RST for TCP
            // (same wire shape as the unclaimed-port responder),
            // ICMP 3/3 port-unreachable for everything else.
            if *proto == 6 {
                if let Some(s) = parse_tcp(p) {
                    tcp_rst(*src_ip, &s);
                }
            } else {
                icmp_port_unreach(*src_ip, p);
            }
        }
        v == 0
    });
    IP_IN_DELIV.fetch_add(out.len() as u64, Ordering::Relaxed);
    // ICMP: answer echo requests like a real host — wire or loopback;
    // net.ipv4.icmp_echo_ignore_all silences the responder.
    let ignore_all = ICMP_IGNORE_ALL.load(Ordering::Relaxed) != 0;
    for (src_ip, proto, p, _) in &out {
        if *proto == 1 && p.len() >= 8 && p[0] == 8 && !ignore_all {
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
                // RTO from the RFC6298 estimator (400ms before the
                // handshake's first RTT sample lands)
                let rto = tcp_rto(k);
                if let Some(u) = k.unacked.front_mut() {
                    if now.saturating_sub(u.tx_ms) >= rto {
                        u.tx_ms = now;
                        u.rtx = true;
                        k.rtx += 1;
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
    ICMP_OUT_ECHOREP.fetch_add(1, Ordering::Relaxed);
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
            c.iter().find(|e| e.ip == src_ip).map(|e| e.mac)
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
            c.iter().find(|e| e.ip == sender).map(|e| e.mac)
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
    first_hop: u8,
    max_hops: u8,
    per_ms: u64,
    base_port: u16,
    probes: u8,
) -> Vec<(u8, Option<([u8; 4], u64)>, bool)> {
    let mut hops = Vec::new();
    let Some(mac) = next_hop(dst, 1500) else {
        return hops;
    };
    let first = first_hop.max(1).min(30);
    let probes = probes.max(1).min(10);
    for ttl in first..=max_hops.min(30).max(first) {
        // `-p`: the UDP probe base port is real — dport = base + ttl,
        // and the ICMP matcher keys on the quoted dport so a non-
        // default base still matches. `-q`: `probes` real datagrams
        // leave per hop; the first answer back is the reported RTT.
        let dport = base_port.wrapping_add(ttl as u16);
        let t0 = now_ms();
        for _ in 0..probes {
            send_udp_ttl(mac, dst, TRACER_SPORT, dport, b"cosmos-trace", ttl);
        }
        let mut hit: Option<([u8; 4], bool)> = None;
        while now_ms() - t0 < per_ms && hit.is_none() {
            for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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

/// Match an ICMP time-exceeded/unreachable that quotes one of our
/// echo-probe packets (the quoted inner packet is ICMP, not UDP —
/// `icmp_probe_ports` can't see it). Returns (echo_seq, orig_dst).
fn icmp_probe_echo(p: &[u8]) -> Option<(u16, [u8; 4])> {
    if p.len() >= 36 && (p[0] == 11 || p[0] == 3) {
        let ip = &p[8..];
        if ip.len() >= 20 && ip[0] >> 4 == 4 && ip[9] == 1 {
            let ihl = ((ip[0] & 0xF) as usize) * 4;
            if ip.len() >= ihl + 8 && ip[ihl] == 8 {
                let seq = be16(&ip[ihl + 6..]);
                let dst: [u8; 4] = ip[16..20].try_into().ok()?;
                return Some((seq, dst));
            }
        }
    }
    None
}

const TRACER_EID: u16 = 0x7ACE;

/// Traceroute over ICMP echo probes (`traceroute -I`): a real echo
/// request whose seq carries the ttl; hops answer ICMP-11 quoting it,
/// the target answers an echo reply.
pub fn net_trace_icmp(
    dst: [u8; 4],
    first_hop: u8,
    max_hops: u8,
    per_ms: u64,
    probes: u8,
) -> Vec<(u8, Option<([u8; 4], u64)>, bool)> {
    let mut hops = Vec::new();
    let Some(mac) = next_hop(dst, 1500) else {
        return hops;
    };
    let first = first_hop.max(1).min(30);
    let probes = probes.max(1).min(10);
    for ttl in first..=max_hops.min(30).max(first) {
        let t0 = now_ms();
        for _ in 0..probes {
            send_icmp_echo_ttl(mac, dst, TRACER_EID, ttl as u16, ttl, b"cosmos-trace-icmp");
        }
        let mut hit: Option<([u8; 4], bool)> = None;
        while now_ms() - t0 < per_ms && hit.is_none() {
            for (src_ip, proto, p, _pkt_meta) in pump_rx() {
                if proto != 1 {
                    dispatch(src_ip, proto, p);
                    continue;
                }
                if p.len() >= 8 && p[0] == 0 && src_ip == dst
                    && be16(&p[4..]) == TRACER_EID
                {
                    hit = Some((src_ip, true)); // target's own echo reply
                    break;
                }
                if let Some((seq, odst)) = icmp_probe_echo(&p) {
                    if seq == ttl as u16 && odst == dst {
                        hit = Some((src_ip, false)); // time-exceeded hop
                    }
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

/// Match an ICMP time-exceeded quoting one of our TCP SYN probes — same
/// excerpt layout as `icmp_probe_ports` but accepts proto 6.
fn icmp_probe_tcp(p: &[u8]) -> Option<(u16, [u8; 4])> {
    if p.len() < 36 || p[0] != 11 {
        return None;
    }
    let ip = &p[8..];
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 6 {
        return None;
    }
    let ihl = ((ip[0] & 0xF) as usize) * 4;
    if ip.len() < ihl + 4 {
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

/// Traceroute over TCP SYN probes (`traceroute -T`): real SYN segments
/// with rising TTLs toward `dport_probe`. Intermediate hops answer ICMP
/// time-exceeded quoting the segment; the target answers its own
/// SYN-ACK or RST (visible on the raw rx stream) — `reached`.
pub fn net_trace_tcp(
    dst: [u8; 4],
    first_hop: u8,
    max_hops: u8,
    per_ms: u64,
    dport_probe: u16,
    probes: u8,
) -> Vec<(u8, Option<([u8; 4], u64)>, bool)> {
    let mut hops = Vec::new();
    let Some(mac) = next_hop(dst, 1500) else {
        return hops;
    };
    let first = first_hop.max(1).min(30);
    let probes = probes.max(1).min(10);
    for ttl in first..=max_hops.min(30).max(first) {
        let isn = (now_ms() as u32) ^ 0x7ACE_0000;
        let t0 = now_ms();
        for _ in 0..probes {
            send_tcp_ttl(mac, dst, TRACER_SPORT, dport_probe, isn, 0, TCP_SYN, &[], 65535, ttl);
        }
        let mut hit: Option<([u8; 4], bool)> = None;
        while now_ms() - t0 < per_ms && hit.is_none() {
            for (src_ip, proto, p, _pkt_meta) in pump_rx() {
                if proto == 6 {
                    // The target's own answer (SYN-ACK or RST) to our
                    // probe port — real tcptraceroute stops here.
                    if src_ip == dst && p.len() >= 4 && be16(&p[2..]) == TRACER_SPORT {
                        hit = Some((src_ip, true));
                        break;
                    }
                    dispatch(src_ip, proto, p);
                    continue;
                }
                if proto != 1 {
                    dispatch(src_ip, proto, p);
                    continue;
                }
                if let Some((dp, odst)) = icmp_probe_tcp(&p) {
                    if dp == dport_probe && odst == dst {
                        hit = Some((src_ip, false));
                    }
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
    crate::pcap::log_frame(&f); // TX frames hit the capture too (tcpdump sees both directions)
    ct_observe_tx(&f);          // and the conntrack flow table
    if !tc_shape(f.len()) {
        return Ok(()); // qdisc dropped the frame (backlog overflow)
    }
    n.send(&f)
}

/// Token-bucket traffic shaper on the TX path (`tc qdisc add dev eth0 root
/// tbf rate <bps>`). Tokens accumulate at `rate_bps`; a frame that can't be
/// paid for waits — a real TBF delays — and is dropped once the wait would
/// exceed 2 s (backlog overflow semantics).
struct Tbf {
    rate_bps: u64, // bytes per second
    tokens: u64,
    last_ms: u64,
    pkts: u64,
    bytes: u64,
    drops: u64,
}
static TC_QDISC: Mutex<Option<Tbf>> = Mutex::new(None);

fn tc_shape(len: usize) -> bool {
    let mut g = TC_QDISC.lock();
    let Some(t) = g.as_mut() else { return true };
    let mut now = now_ms();
    let burst = t.rate_bps.max(1514); // ~1s of credits, at least one MTU
    t.tokens = (t.tokens + (now - t.last_ms) * t.rate_bps / 1000).min(burst);
    t.last_ms = now;
    let need = len as u64;
    if t.tokens >= need {
        t.tokens -= need;
        t.pkts += 1;
        t.bytes += need;
        return true;
    }
    // Delay until the bucket refills; drop if the wait exceeds 2 s.
    let deficit = need - t.tokens;
    let wait = deficit * 1000 / t.rate_bps.max(1) + 1;
    if wait > 2000 {
        t.drops += 1;
        return false; // backlog overflow — frame is dropped (no send)
    }
    let until = now + wait;
    while now_ms() < until {
        // syscall context runs IF=0 — halt with IRQs on for one tick so
        // PIT fires and now_ms() advances (same as every net wait loop).
        wait_irq();
    }
    now = now_ms();
    t.last_ms = now;
    t.tokens = 0;
    t.pkts += 1;
    t.bytes += need;
    true
}

/// `/proc/net/tc` — Linux `tc -s qdisc`-style stats.
pub fn tc_show() -> String {
    let g = TC_QDISC.lock();
    match g.as_ref() {
        Some(t) => alloc::format!(
            "qdisc tbf root dev eth0 rate {}bps burst {}b\n  Sent {} bytes {} pkt (dropped {}, overlimits 0)\n",
            t.rate_bps, t.rate_bps.max(1514), t.bytes, t.pkts, t.drops
        ),
        None => String::from("qdisc noqueue dev eth0 (no shaping configured)\n"),
    }
}

/// `/proc/net/tc` write grammar: `"add qdisc tbf rate <Bps>"`,
/// `"add qdisc tbf rate <bps>[k|m]"`, `"del"`/`"clear"` remove shaping.
pub fn tc_ctl(line: &str) -> bool {
    let f: Vec<&str> = line.split_whitespace().collect();
    match f.as_slice() {
        ["del"] | ["clear"] => {
            *TC_QDISC.lock() = None;
            true
        }
        ["add", "qdisc", "tbf", "rate", rate] => {
            let (num, mult) = if let Some(r) = rate.strip_suffix('k') {
                (r, 1000u64)
            } else if let Some(r) = rate.strip_suffix('m') {
                (r, 1_000_000u64)
            } else {
                (*rate, 1u64)
            };
            let Ok(base) = num.parse::<u64>() else { return false };
            let rate_bps = base * mult;
            if rate_bps == 0 {
                return false;
            }
            *TC_QDISC.lock() = Some(Tbf {
                rate_bps,
                tokens: rate_bps.max(1514),
                last_ms: now_ms(),
                pkts: 0,
                bytes: 0,
                drops: 0,
            });
            true
        }
        _ => false,
    }
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

/// `arping`: send a real ARP who-has for `dst` and wait for the reply.
/// Returns (mac packed in the low 48 bits of u64, rtt_ms). The probe goes
/// on the wire regardless of cache state — a real arping.
pub fn net_arping(dst: [u8; 4], per_ms: u64) -> Option<(u64, u64)> {
    let t0 = now_ms();
    send_arp_request(dst);
    while now_ms() - t0 < per_ms.max(50) {
        let _ = pump_rx(); // drains the ring; ARP replies update ARP_CACHE
        if let Some(e) = ARP_CACHE.lock().iter().find(|e| e.ip == dst) {
            let m = e.mac;
            let mac = (m[0] as u64) << 40 | (m[1] as u64) << 32 | (m[2] as u64) << 24
                | (m[3] as u64) << 16 | (m[4] as u64) << 8 | m[5] as u64;
            return Some((mac, now_ms() - t0));
        }
        wait_irq();
    }
    None
}

/// Gratuitous ARP: a broadcast REPLY announcing our own ip/mac — the
/// `arping -U` announce. Nobody asked; everyone updates their cache.
pub fn send_arp_gratuitous() {
    send_arp_reply([0xFF; 6], our_ip());
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

fn send_icmp_echo_ttl(dst_mac: [u8; 6], dst_ip: [u8; 4], id: u16, seq: u16, ttl: u8, payload: &[u8]) {
    send_icmp_echo_src(our_ip(), dst_mac, dst_ip, id, seq, ttl, payload);
}

/// Echo request with an explicit source address (`ping -I <iface>` —
/// the iface picks the source IP; routing still follows the dst).
fn send_icmp_echo_src(src_ip: [u8; 4], dst_mac: [u8; 6], dst_ip: [u8; 4], id: u16, seq: u16, ttl: u8, payload: &[u8]) {
    send_icmp_echo_qos(src_ip, dst_mac, dst_ip, id, seq, 0, ttl, payload)
}

/// Echo request carrying a real IPv4 TOS/DSCP byte (`ping -Q`).
fn send_icmp_echo_qos(src_ip: [u8; 4], dst_mac: [u8; 6], dst_ip: [u8; 4], id: u16, seq: u16, tos: u8, ttl: u8, payload: &[u8]) {
    ICMP_OUT_ECHOREQ.fetch_add(1, Ordering::Relaxed);
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // echo request
    icmp.push(0);
    icmp.extend_from_slice(&[0u8; 2]); // csum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = csum(&icmp);
    put16(&mut icmp[2..], c);
    send_ip_src_qos(src_ip, dst_mac, dst_ip, 1, tos, ttl, &icmp);
}

/// Handle one ethernet frame: ARP cache/reply, or deliver an IPv4 payload.
/// Returns Some((ip_proto, transport_payload)) when the frame carried IPv4
/// addressed to our IP.
fn handle_frame(f: &[u8]) -> Option<([u8; 4], u8, Vec<u8>, u64)> {
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
            // cache the sender (dynamic entries refresh; static ones hold)
            let mut c = ARP_CACHE.lock();
            if let Some(e) = c.iter_mut().find(|e| e.ip == sender_ip) {
                if !e.perm {
                    e.mac = sender_mac;
                    e.learned_ms = now_ms();
                }
            } else {
                c.push(ArpEnt {
                    ip: sender_ip,
                    mac: sender_mac,
                    perm: false,
                    learned_ms: now_ms(),
                });
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
            // The real IPv4 TTL (ip[8]), DS byte (ip[1]) and L2
            // sender (f[6..12]) ride the tuple — `-m ttl`/`-m tos`/
            // `-m mac` match on what arrived on the wire.
            let smac: [u8; 6] = f[6..12].try_into().ok()?;
            Some((src, ip[9], ip[ihl..].to_vec(), pkt_meta(ip[8], ip[1], smac)))
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
        if let Some(e) = c.iter().find(|e| e.ip == ip) {
            return Some(e.mac);
        }
    }
    let deadline = now_ms() + ms;
    send_arp_request(ip);
    loop {
        let _ = pump_rx();
        {
            let c = ARP_CACHE.lock();
            if let Some(e) = c.iter().find(|e| e.ip == ip) {
                return Some(e.mac);
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
    c.retain(|e| e.ip != ip);
    c.len() != n
}

/// `/proc/net/arp` write grammar (same convention as /proc/net/route):
///   "add <ip> <mac>"  installs a PERMANENT entry (arp -s)
///   "del <ip>"        drops an entry (arp -d / ip neigh del)
///   "flush"           empties the cache (ip neigh flush)
pub fn arp_ctl(line: &str) -> bool {
    let mut f = line.split_whitespace();
    match f.next() {
        Some("add") => {
            let (Some(ip), Some(macs)) = (f.next(), f.next()) else {
                return false;
            };
            let Some(ip) = parse_ip(ip) else { return false };
            let o: Vec<u8> = macs
                .split(':')
                .filter_map(|h| u8::from_str_radix(h, 16).ok())
                .collect();
            if o.len() != 6 {
                return false;
            }
            let mac: [u8; 6] = [o[0], o[1], o[2], o[3], o[4], o[5]];
            let mut c = ARP_CACHE.lock();
            if let Some(e) = c.iter_mut().find(|e| e.ip == ip) {
                e.mac = mac;
                e.perm = true;
                e.learned_ms = now_ms();
            } else {
                c.push(ArpEnt {
                    ip,
                    mac,
                    perm: true,
                    learned_ms: now_ms(),
                });
            }
            true
        }
        Some("del") => f.next().and_then(parse_ip).map(arp_del).unwrap_or(false),
        Some("flush") => {
            ARP_CACHE.lock().clear();
            true
        }
        // "announce" — emit a gratuitous ARP reply for our own address
        // (arping -U). Real broadcast frame on the wire.
        Some("announce") => {
            send_arp_gratuitous();
            true
        }
        _ => false,
    }
}

pub fn arp_stat() -> String {
    let c = ARP_CACHE.lock();
    let mut s = String::from("ip              mac\n");
    for e in c.iter() {
        s.push_str(&alloc::format!(
            "{}.{}.{}.{}\t{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}{}\n",
            e.ip[0], e.ip[1], e.ip[2], e.ip[3],
            e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4], e.mac[5],
            if e.perm { "\tPERM" } else { "" }
        ));
    }
    if c.is_empty() {
        s.push_str("(empty)\n");
    }
    s
}

/// `ping <ip>`: ARP-resolve, send one ICMP echo request, wait for the reply.
/// Returns rtt in milliseconds, or None on timeout/unreachable.
/// `ttl` stamps the echo request's IPv4 TTL; 0 = ip_default_ttl.
pub fn ping_ttl(ip: [u8; 4], timeout_ms: u64, ttl: u8) -> Option<u64> {
    ping_ttl_if(ip, timeout_ms, ttl, 36, 0, 0)
}

/// `ping_ttl` with an explicit ICMP payload size (`ping -s N` — the
/// real -s semantics: N bytes of patterned payload, so the wire
/// datagram is 20+8+N). Capped at 1450 — no IP fragmentation.
pub fn ping_ttl_sz(ip: [u8; 4], timeout_ms: u64, ttl: u8, size: usize) -> Option<u64> {
    ping_ttl_if(ip, timeout_ms, ttl, size, 0, 0)
}

/// `ping -I <iface>`: the iface chooses the source address (lo →
/// 127.0.0.1, eth0 → our IP). Routing still follows the destination,
/// like real ping — so `-I lo <remote>` sends a wire packet nobody can
/// answer (timeout), and `-I eth0 <127.x>` is unroutable (EINVAL).
pub fn ping_ttl_if(ip: [u8; 4], timeout_ms: u64, ttl: u8, size: usize, iface: u8, tos: u8) -> Option<u64> {
    ping_ttl_pat(ip, timeout_ms, ttl, size, iface, tos, None)
}

/// `ping -p` — like ping_ttl_if but the ICMP payload is the caller's
/// byte pattern repeated (`iputils` fills 0x10.. when -p is absent).
pub fn ping_ttl_pat(ip: [u8; 4], timeout_ms: u64, ttl: u8, size: usize, iface: u8, tos: u8, pat: Option<&[u8]>) -> Option<u64> {
    if NET.lock().is_none() {
        sprintln!("[net] ping: no device");
        return None;
    }
    if iface == 1 && ip[0] == 127 {
        return None; // can't route loopback out eth0 (real: EINVAL)
    }
    let src = if iface == 2 { LOOPBACK_IP } else { our_ip() };
    let me = our_ip();
    let on_net = ip[0] == me[0] && ip[1] == me[1] && ip[2] == me[2];
    let arp_for = if on_net { ip } else { GW_IP };
    // Broadcast ping (`ping -b`): the echo request leaves on the
    // broadcast MAC — no ARP lookup (there's nothing to resolve).
    let dst_mac = if ip == [255; 4] {
        [0xFFu8; 6]
    } else {
        arp_resolve(arp_for, 1500)?
    };
    sprintln!(
        "[net] arp {}.{}.{}.{} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        arp_for[0], arp_for[1], arp_for[2], arp_for[3],
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
    );
    let id = 0xC050u16;
    let seq = 1u16;
    let size = size.clamp(1, 1450);
    // Default fill is the iputils pattern (0x10,0x11,..); `ping -p`
    // repeats the caller's pattern instead — verifiable on the wire.
    let payload: Vec<u8> = match pat {
        Some(p) if !p.is_empty() => (0..size).map(|i| p[i % p.len()]).collect(),
        _ => (0..size).map(|i| 0x10 + (i % 56) as u8).collect(),
    };
    let t0 = now_ms();
    send_icmp_echo_qos(src, dst_mac, ip, id, seq, tos, if ttl == 0 { def_ttl() } else { ttl }, &payload);
    loop {
        for (_src_ip, proto, p, _pkt_meta) in pump_rx() {
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
    send_ip_src_ttl(src_ip, dst_mac, dst_ip, proto, def_ttl(), payload)
}

fn send_ip_src_ttl(
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    proto: u8,
    ttl: u8,
    payload: &[u8],
) {
    send_ip_src_qos(src_ip, dst_mac, dst_ip, proto, 0, ttl, payload)
}

/// The real egress funnel — `tos` stamps the IPv4 DS byte (`ping -Q`,
/// IP_TOS); `ttl` stamps the TTL. Everything wire-bound funnels
/// through here so the OUTPUT chain, MTU gate and lo shortcut apply
/// to every datagram uniformly.
fn send_ip_src_qos(
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    proto: u8,
    tos: u8,
    ttl: u8,
    payload: &[u8],
) {
    IP_OUT_REQ.fetch_add(1, Ordering::Relaxed);
    match proto {
        1 => ICMP_OUT.fetch_add(1, Ordering::Relaxed),
        6 => TCP_OUT.fetch_add(1, Ordering::Relaxed),
        17 => UDP_OUT.fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
    // iptables OUTPUT: every locally-generated datagram is evaluated
    // here at the egress funnel — wire, lo, and ARP-free sends alike.
    let (osport, odport) = pkt_ports(proto, payload);
    // Egress iface: destinations on a local address leave via lo.
    let oifx = if is_loopback(dst_ip) { 2u8 } else { 1 };
    let itype = if proto == 1 && !payload.is_empty() { payload[0] } else { 0xff };
    let v = fw_verdict(&FW_OUT, &FW_OUT_POLICY, false, src_ip, dst_ip, proto, osport, odport, 0, oifx, payload.len() as u64, ttl, tos, [0; 6], itype);
    if v == 2 {
        out_reject(src_ip, dst_ip, proto, payload);
        return;
    }
    if v == 1 {
        return; // -j DROP: the datagram never leaves
    }
    if is_loopback(dst_ip) {
        // lo: no ethernet, no ARP — the datagram re-enters rx as-is,
        // carrying the stamped TTL/TOS so `-m ttl`/`-m tos` see it;
        // no link layer means no sender MAC.
        LOOPBACK_Q.lock().push_back((src_ip, proto, payload.to_vec(), pkt_meta(ttl, tos, [0; 6])));
        LO_TX_PKTS.fetch_add(1, Ordering::Relaxed);
        LO_TX_BYTES.fetch_add(payload.len() as u64, Ordering::Relaxed);
        return;
    }
    // Real egress MTU: oversize datagrams are dropped and counted (no
    // IP fragmentation — same fate as a DF send past the wire MTU).
    if 20 + payload.len() as u64 > iface_mtu() {
        IP_MTU_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut ip = Vec::with_capacity(20 + payload.len());
    ip.push(0x45);
    ip.push(tos); // DS field — real TOS/DSCP byte on the wire
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
    send_udp_ttl(dst_mac, dst_ip, sport, dport, payload, def_ttl())
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

/// Real DNS cache: wire answers are stored with the TTL the server
/// sent — a hit answers without leaving the guest. 64-entry cap,
/// oldest-expiry eviction, lazily pruned on lookup.
struct DnsEnt {
    name: String,
    ip: [u8; 4],
    expiry_ms: u64,
}
static DNS_CACHE: Mutex<Vec<DnsEnt>> = Mutex::new(Vec::new());
static DNS_HITS: AtomicU64 = AtomicU64::new(0);
static DNS_MISSES: AtomicU64 = AtomicU64::new(0);

/// The resolver's upstream: `nameserver <ip>` from /etc/resolv.conf,
/// falling back to the slirp resolver.
pub fn dns_server() -> [u8; 4] {
    if let Ok(b) = crate::vfs::read_all("/etc/resolv.conf") {
        if let Ok(t) = core::str::from_utf8(&b) {
            for l in t.lines() {
                let l = l.split('#').next().unwrap_or("");
                let mut f = l.split_whitespace();
                if f.next() == Some("nameserver") {
                    if let Some(ip) = f.next().and_then(parse_ip) {
                        return ip;
                    }
                }
            }
        }
    }
    [10, 0, 2, 3]
}

/// `/proc/net/dns` — cache statistics + live entries with TTL left.
pub fn net_dns_stats() -> String {
    let mut c = DNS_CACHE.lock();
    let now = now_ms();
    c.retain(|e| e.expiry_ms > now);
    let mut out = alloc::format!(
        "hits {}\nmisses {}\nentries {}\n",
        DNS_HITS.load(Ordering::Relaxed),
        DNS_MISSES.load(Ordering::Relaxed),
        c.len()
    );
    for e in c.iter() {
        out.push_str(&alloc::format!(
            "{} {}.{}.{}.{} ttl={}\n",
            e.name,
            e.ip[0], e.ip[1], e.ip[2], e.ip[3],
            (e.expiry_ms - now) / 1000
        ));
    }
    out
}

/// `/proc/net/dns` write ops: `F` flushes the cache (resolvectl
/// flush-caches).
pub fn dns_ctl(op: &str) -> bool {
    match op.trim() {
        "F" => {
            DNS_CACHE.lock().clear();
            true
        }
        _ => false,
    }
}

/// `resolve <hostname>`: real DNS A-record query over real UDP.
/// nsswitch: /etc/hosts first, then the cache, then the wire.
/// Returns the first A record.
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
    // Cache check: the name is normalized lowercase; a live entry
    // answers without touching the wire. Stale entries are pruned
    // here so the table can't fill with dead names.
    let lc = name.to_lowercase();
    {
        let now = now_ms();
        let mut c = DNS_CACHE.lock();
        c.retain(|e| e.expiry_ms > now);
        if let Some(e) = c.iter().find(|e| e.name == lc) {
            DNS_HITS.fetch_add(1, Ordering::Relaxed);
            sprintln!("[net] dns '{}' -> {}.{}.{}.{} (cached, ttl={}s)",
                name, e.ip[0], e.ip[1], e.ip[2], e.ip[3],
                (e.expiry_ms - now) / 1000);
            return Some(e.ip);
        }
    }
    DNS_MISSES.fetch_add(1, Ordering::Relaxed);
    let dns = dns_server();
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
    udp_send(SPORT, dns, 53, &q).ok()?;
    sprintln!("[net] dns query '{}' -> {}.{}.{}.{}:53",
        name, dns[0], dns[1], dns[2], dns[3]);

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
        let mut found: Option<([u8; 4], u32)> = None;
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
            let ttl = u32::from_be_bytes(m[i + 4..i + 8].try_into().unwrap());
            let rdlen = be16(&m[i + 8..]) as usize;
            if rtype == 1 && rdlen == 4 && m.len() >= i + 10 + 4 {
                found = Some((m[i + 10..i + 14].try_into().unwrap(), ttl));
                break;
            }
            i += 10 + rdlen;
        }
        if bad {
            break None;
        }
        if let Some((ip, ttl)) = found {
            sprintln!(
                "[net] dns '{}' -> {}.{}.{}.{} (ttl={}s)",
                name, ip[0], ip[1], ip[2], ip[3], ttl
            );
            // TTL 0 means "do not cache" — honor it exactly.
            if ttl > 0 {
                let mut c = DNS_CACHE.lock();
                c.retain(|e| e.name != lc);
                if c.len() >= 64 {
                    let (idx, _) = c.iter().enumerate()
                        .min_by_key(|(_, e)| e.expiry_ms)
                        .unwrap_or((0, &DnsEnt { name: String::new(), ip: [0; 4], expiry_ms: 0 }));
                    c.remove(idx);
                }
                c.push(DnsEnt {
                    name: lc.clone(),
                    ip,
                    expiry_ms: now_ms() + ttl as u64 * 1000,
                });
            }
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
    send_tcp_ttl(dst_mac, dst_ip, sport, dport, seq, ack, flags, payload, win, def_ttl())
}

/// send_tcp with an explicit IP TTL — TCP traceroute probes stamp a
/// rising TTL like the UDP/ICMP variants.
#[allow(clippy::too_many_arguments)]
fn send_tcp_ttl(
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    win: u16,
    ttl: u8,
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
    send_ip_src_ttl(src, dst_mac, dst_ip, 6, ttl, &seg);
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

/// `/proc/net/tcpinfo` — per-conn TCP internals for `ss -i`: the
/// RFC6298 rtt/rttvar estimates, current RTO, retransmit count, and
/// live queue depths. One line: lport rport st srtt rttvar rto rtx
/// unackedB rxqB.
pub fn net_tcpinfo() -> String {
    let mut s = String::from("lport rport st srtt rttvar rto rtx unacked rxq\n");
    for k in TCP_SOCKS.lock().values() {
        let txq: usize = k.unacked.iter().map(|u| u.payload.len()).sum();
        s.push_str(&alloc::format!(
            "{} {} {} {} {} {} {} {} {}\n",
            k.lport,
            k.rport,
            match k.state {
                TcpState::Open => "estab",
                TcpState::SynSent => "syn-sent",
                TcpState::SynRecv => "syn-recv",
                TcpState::Closed => "closed",
            },
            k.srtt,
            k.rttvar,
            tcp_rto(k),
            k.rtx,
            txq,
            k.q.iter().map(|c| c.len()).sum::<usize>(),
        ));
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
        for (_src_ip, proto, p, _pkt_meta) in pump_rx() {
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
    udp_send_ttl(lport, dst_ip, dport, payload, def_ttl())
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
    // Real EMSGSIZE: datagram + headers past the wire MTU can't send.
    if 28 + payload.len() as u64 > iface_mtu() {
        return Err(-90);
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
    for (src_ip, proto, p, _pkt_meta) in pump_rx() {
        dispatch(src_ip, proto, p);
    }
    if let Some(d) = SOCKS.lock().get_mut(&lport).and_then(|q| q.pop_front()) {
        return Some(d);
    }
    let deadline = now_ms() + timeout_ms;
    while now_ms() < deadline {
        for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
    syn_ms: u64,          // outbound SYN tx time — first RTT sample
    srtt: u64,            // smoothed RTT estimate ms (0 = none yet)
    rttvar: u64,          // RTT variation ms — RFC6298 estimator
    rtx: u32,             // total retransmitted segments (ss -i retrans)
}

/// A transmitted segment awaiting ACK — retransmitted by tcp_tick.
pub struct UnAck {
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
    tx_ms: u64, // last transmit time (RTO clock)
    rtx: bool,  // already retransmitted — Karn's algorithm skips it for RTT samples
}

/// Retransmit timeout from the RFC6298 estimator; 400ms until the
/// handshake's first sample lands (the pre-estimator default).
fn tcp_rto(k: &TcpSock) -> u64 {
    if k.srtt == 0 {
        400
    } else {
        (k.srtt + (4 * k.rttvar).max(200)).clamp(200, 60_000)
    }
}

/// Feed one RTT sample (ms) into the RFC6298 srtt/rttvar estimator.
fn tcp_rtt_sample(k: &mut TcpSock, sample: u64) {
    let sample = sample.max(1);
    if k.srtt == 0 {
        k.srtt = sample;
        k.rttvar = sample / 2;
    } else {
        let d = k.srtt.abs_diff(sample);
        k.rttvar = (3 * k.rttvar + d) / 4;
        k.srtt = (7 * k.srtt + sample) / 8;
    }
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
                // handshake RTT: the estimator's first sample
                tcp_rtt_sample(k, now_ms().saturating_sub(k.syn_ms));
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
                // drain the retransmit queue: cumulatively-acked segs;
                // each ACKed never-retransmitted seg feeds one RTT
                // sample (Karn's algorithm — retransmits are skipped).
                let mut sampled = false;
                while let Some(u) = k.unacked.front() {
                    let end = u.seq.wrapping_add(u.payload.len() as u32).wrapping_add(
                        if u.flags & TCP_FIN != 0 { 1 } else { 0 },
                    );
                    if s.ack >= end {
                        if !u.rtx && !sampled {
                            tcp_rtt_sample(k, now_ms().saturating_sub(u.tx_ms));
                            sampled = true;
                        }
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
            syn_ms: now_ms(),
            srtt: 0,
            rttvar: 0,
            rtx: 0,
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
        for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
            syn_ms: 0,
            srtt: 0,
            rttvar: 0,
            rtx: 0,
        },
    );
    send_tcp(mac, src_ip, s.dport, s.sport, isn, s.seq + 1, TCP_SYN | TCP_ACK, &[], 65535);
}

/// Wait for an accepted conn on a listener. Returns (cid, peer ip, peer port).
pub fn tcp_accept(lport: u16, timeout_ms: u64) -> Option<(u16, [u8; 4], u16)> {
    let deadline = now_ms() + timeout_ms;
    loop {
        for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
                    rtx: false,
                });
                enqueued = true;
            }
        }
        if !enqueued {
            for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
        for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
        for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
    for (src_ip, proto, p, _pkt_meta) in pump_rx() {
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
            rtx: false,
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
        rtx: false,
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
