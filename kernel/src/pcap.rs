//! libpcap-format packet capture: every raw ethernet frame through pump_rx
//! is serialized into a bounded in-memory pcap file image. A terminal
//! `pcap` command flushes it to disk via SYS_PCAP.
use alloc::vec::Vec;
use spin::Mutex;

const CAP_BYTES: usize = 256 * 1024; // whole capture buffer

static PCAP: Mutex<Pcap> = Mutex::new(Pcap {
    on: false,
    ms0: 0,
    pkts: 0,
    dropped: 0,
    buf: Vec::new(),
});

struct Pcap {
    on: bool,
    ms0: u64, // capture start (rel. timestamps from here)
    pkts: u64,
    dropped: u64,
    buf: Vec<u8>, // pcap file image (global header + records)
}

fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn write_global_header(b: &mut Vec<u8>) {
    put32(b, 0xa1b2c3d4); // magic
    put16(b, 2);
    put16(b, 4); // version
    put32(b, 0); // tz
    put32(b, 0); // sigfigs
    put32(b, 65535); // snaplen
    put32(b, 1); // LINKTYPE_ETHERNET
}

/// Log one raw ethernet frame. Called from net::pump_rx for every frame.
pub fn log_frame(frame: &[u8]) {
    let mut p = PCAP.lock();
    if !p.on {
        return;
    }
    p.pkts += 1;
    // per-packet record: ts_sec, ts_usec, incl_len, orig_len + data
    let need = 16 + frame.len();
    if p.buf.len() + need > CAP_BYTES {
        p.dropped += 1;
        return;
    }
    let rel = crate::timer::uptime_ms().saturating_sub(p.ms0);
    put32(&mut p.buf, (rel / 1000) as u32);
    put32(&mut p.buf, ((rel % 1000) * 1000) as u32);
    put32(&mut p.buf, frame.len() as u32);
    put32(&mut p.buf, frame.len() as u32);
    p.buf.extend_from_slice(frame);
}

/// op 0: start (clears buffer). op 1: stop. op 2: stats -> pkts<<32|dropped.
/// op 3: is-on. op 4: copy file image into out (returns byte count or -cap).
pub fn sys_pcap(op: u64, out: &mut [u8]) -> i64 {
    let mut p = PCAP.lock();
    match op {
        0 => {
            p.buf.clear();
            write_global_header(&mut p.buf);
            p.pkts = 0;
            p.dropped = 0;
            p.ms0 = crate::timer::uptime_ms();
            p.on = true;
            0
        }
        1 => {
            p.on = false;
            0
        }
        2 => ((p.pkts as u64) << 32 | p.dropped as u64) as i64,
        3 => p.on as i64,
        4 => {
            if out.len() < p.buf.len() {
                -(p.buf.len() as i64)
            } else {
                out[..p.buf.len()].copy_from_slice(&p.buf);
                p.buf.len() as i64
            }
        }
        _ => -4,
    }
}
