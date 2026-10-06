//! selftest: scripted end-to-end checks exercising every kernel subsystem.
//! Prints "[selftest] PASS <name>" / "[selftest] FAIL <name>" lines on serial;
//! finishes with "[selftest] DONE ok=<n> fail=<m>" so the host smoke test can
//! score the run without a GUI.
#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ustd::*;

static mut PASS: u32 = 0;
static mut FAIL: u32 = 0;

fn check(name: &str, ok: bool) {
    if ok {
        unsafe { PASS += 1 };
        println!("[selftest] PASS {}", name);
    } else {
        unsafe { FAIL += 1 };
        println!("[selftest] FAIL {}", name);
    }
}

fn metric(name: &str, v: u64) {
    println!("METRIC {}={}", name, v);
}

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[selftest] starting");

    // --- fs: create/write/read/stat/rename/remove/mkdir/readdir ---
    check("mkdir", mkdir("/test").is_ok() || stat("/test").map(|s| s.is_dir == 1).unwrap_or(false));
    check("write_all", write_all("/test/hello.txt", b"hello cosmos").is_ok());
    let data = read_all("/test/hello.txt").unwrap_or_default();
    check("read_all", data == b"hello cosmos");
    check("stat", stat("/test/hello.txt").map(|s| s.size == 12).unwrap_or(false));
    let fd = open("/test/hello.txt", O_RDONLY).unwrap_or(-1);
    let mut buf = [0u8; 5];
    let n = read(fd, &mut buf).unwrap_or(0);
    check("open+read", fd >= 0 && n == 5 && &buf == b"hello");
    seek(fd, 6, shared::SEEK_SET).ok();
    let n2 = read(fd, &mut buf).unwrap_or(0);
    check("seek", n2 == 5 && &buf == b"cosmo");
    close(fd);
    // append mode
    let fd2 = open("/test/hello.txt", O_WRONLY | O_APPEND).unwrap_or(-1);
    check("append-write", fd2 >= 0 && write(fd2, b"!").map(|v| v == 1).unwrap_or(false));
    close(fd2);
    let data = read_all("/test/hello.txt").unwrap_or_default();
    check("append-persisted", data == b"hello cosmos!");
    check("rename", rename("/test/hello.txt", "/test/hi.txt").is_ok());
    check("rename-moved", stat("/test/hi.txt").is_ok() && stat("/test/hello.txt").is_err());
    let ents = readdir("/test").unwrap_or_default();
    check("readdir", ents.iter().any(|e| &e.name[..e.name_len as usize] == b"hi.txt"));
    // cwd
    check("chdir", chdir("/test"));
    check("getcwd", getcwd() == "/test");
    check("cwd-relative", stat("hi.txt").is_ok());
    chdir("/");
    check("remove", remove("/test/hi.txt").is_ok());
    check("remove-gone", stat("/test/hi.txt").is_err());

    // --- memory ---
    let mi = meminfo();
    check("meminfo", mi.total_kb > 512 * 1024 && mi.used_kb > 0 && mi.used_kb < mi.total_kb);
    let p = mmap(0x50000);
    check("mmap", p.is_some());
    if let Some(p) = p {
        unsafe {
            core::ptr::write_bytes(p, 0xAB, 0x50000);
            check("mmap-touch", *p.add(0x40000) == 0xAB);
        }
    }

    // --- time ---
    let t0 = uptime_ms();
    sleep_ms(120);
    let t1 = uptime_ms();
    check("sleep", t1.saturating_sub(t0) >= 100);
    let dt = datetime();
    check("datetime", dt.year >= 2024 && dt.month >= 1 && dt.month <= 12);

    // --- processes ---
    let n0 = proclist(64).len();
    match spawn("/bin/cosmos-selftest-child", "") {
        Ok(pid) => {
            check("spawn", pid > 0);
            let code = waitpid(pid, 30000).unwrap_or(-1);
            check("waitpid-exit7", code == 7);
        }
        Err(_) => check("spawn", false),
    }
    let n1 = proclist(64).len();
    check("proclist", n0 >= 1 && n1 >= 1);

    // --- ipc: own port send/recv round trip ---
    let port = ipc_listen("selftest:echo");
    check("ipc-listen", port != 0);
    check("ipc-send", ipc_send(port, b"ping").is_ok());
    let mut mbuf = [0u8; 64];
    let n = ipc_recv(port, &mut mbuf, 1000).unwrap_or(0);
    check("ipc-recv", n == 4 && &mbuf[..4] == b"ping");
    let n2 = ipc_recv(port, &mut mbuf, 100).unwrap_or(999);
    check("ipc-timeout", n2 == 0);
    ipc_close(port);

    // --- shm ---
    let shm = shm_create(0x2000);
    check("shm-create", shm.is_some());
    if let Some(id) = shm {
        let ptr = shm_map(id);
        check("shm-map", ptr.is_some());
        if let Some(p) = ptr {
            unsafe {
                core::ptr::write_bytes(p, 0x5A, 0x2000);
                check("shm-write", *p == 0x5A);
            }
        }
        shm_drop(id);
    }

    // --- fb claim (should be available in selftest mode; winserver not running) ---
    let fbi = fb_info();
    check("fb-info", fbi.is_some());
    if let Some(f) = fbi {
        check("fb-dims", f.width >= 640 && f.height >= 480 && f.stride >= f.width);
        unsafe {
            let p = f.addr as *mut u32;
            *p = 0x00FF00FF; // top-left pixel magenta — proof of write access
        }
    }

    // --- networking: virtio-net up + real ARP/ICMP to the QEMU gateway ---
    let ni = ustd::net_info();
    check("net-info", ni.is_some());
    if let Some((mac, ip)) = ni {
        check("net-mac", mac.iter().any(|&b| b != 0));
        check("net-ip", ip == [10, 0, 2, 15]);
        // ping the user-net gateway (10.0.2.2) — real ARP + ICMP round trip
        let gw = 0x0A000202u32; // 10.0.2.2
        let t0 = ustd::uptime_ms();
        let ping = ustd::net_ping(gw, 3000);
        check("ping-gw", ping.is_some());
        if ping.is_some() {
            metric("ping-gw-rtt-ms", ustd::uptime_ms().saturating_sub(t0));
        }
        // real DNS over real UDP to slirp's resolver (10.0.2.3:53)
        let t0 = ustd::uptime_ms();
        let dns = ustd::net_dns("example.com");
        check("dns-resolve", dns.is_some());
        if dns.is_some() {
            metric("dns-rtt-ms", ustd::uptime_ms().saturating_sub(t0));
        }
        // real TCP/80 HTTP GET to the live internet via slirp
        let t0 = ustd::uptime_ms();
        let http = ustd::net_http("example.com");
        let http_ok = http
            .as_ref()
            .map(|b| b.windows(5).any(|w| w == b"HTTP/"))
            .unwrap_or(false);
        check("http-example", http_ok);
        if http_ok {
            metric("http-bytes", http.unwrap().len() as u64);
            metric("http-total-ms", ustd::uptime_ms().saturating_sub(t0));
        }
        // userspace UDP socket: hand-built DNS wire query through
        // bind -> sendto -> recvfrom to slirp's real resolver
        let sock_ok = (|| {
            let s = ustd::UdpSock::open(54321)?;
            let mut q = alloc::vec::Vec::new();
            q.extend_from_slice(&0xBEEFu16.to_be_bytes()); // txid
            q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
            q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
            q.extend_from_slice(&[0u8; 6]);
            for l in "example.org".split('.') {
                q.push(l.len() as u8);
                q.extend_from_slice(l.as_bytes());
            }
            q.push(0);
            q.extend_from_slice(&1u16.to_be_bytes()); // A
            q.extend_from_slice(&1u16.to_be_bytes()); // IN
            s.send_to([10, 0, 2, 3], 53, &q)?;
            let (_ip, sport, resp) = s.recv_from(3000)?;
            if sport != 53 || resp.len() < 12 {
                return None;
            }
            if u16::from_be_bytes([resp[0], resp[1]]) != 0xBEEF || resp[2] & 0x80 == 0 {
                return None;
            }
            Some(())
        })()
        .is_some();
        check("udp-socket", sock_ok);
        // userspace TCP socket: connect+send+recv an HTTP GET through the
        // same kernel socket layer http_get now rides on
        let tcp_ok = (|| {
            let ip = ustd::net_dns("example.com")?;
            let s = ustd::TcpSock::connect(49300, ip, 80)?;
            s.send(b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
            let mut out = alloc::vec::Vec::new();
            let deadline = ustd::uptime_ms() + 8000;
            while ustd::uptime_ms() < deadline {
                match s.recv(1000) {
                    Some(c) => out.extend_from_slice(&c),
                    None => break,
                }
            }
            if out.windows(5).any(|w| w == b"HTTP/") {
                Some(out.len())
            } else {
                None
            }
        })();
        check("tcp-socket", tcp_ok.is_some());
        if let Some(n) = tcp_ok {
            metric("tcp-sock-bytes", n as u64);
        }
        // netstat dump should list our closed-test sockets or none
        let st = ustd::net_stat();
        check("netstat", st.contains("udp") || st.contains("tcp") || st.contains("no sockets"));
    } else {
        check("net-mac", false);
        check("net-ip", false);
        check("ping-gw", false);
        check("dns-resolve", false);
        check("http-example", false);
        check("udp-socket", false);
        check("tcp-socket", false);
        check("netstat", false);
    }

    // kernel clipboard round-trip
    let payload = b"selftest-clipboard";
    ustd::clip_set(payload);
    check("clipboard", ustd::clip_get() == payload);

    // procfs: live kernel data under /proc (read-only pseudo-files)
    let mi = ustd::read_all("/proc/meminfo").unwrap_or_default();
    check("proc-meminfo", mi.windows(8).any(|w| w == b"MemTotal"));
    check("proc-meminfo-ro", ustd::write_all("/proc/x", b"no").is_err());
    let up = ustd::read_all("/proc/uptime").unwrap_or_default();
    let up = String::from_utf8_lossy(&up);
    check("proc-uptime", up.trim_end().split(' ').next().map(|s| {
        let mut it = s.split('.');
        it.next().and_then(|v| v.parse::<u64>().ok()).is_some()
    }).unwrap_or(false));
    let ents = ustd::readdir("/proc").unwrap_or_default();
    check("proc-listdir", ents.iter().any(|e| &e.name[..e.name_len as usize] == b"meminfo"));

    // codec roundtrips: our DEFLATE encoder -> our inflater must reproduce
    // the exact bytes on patterned and high-entropy data
    let mut pat = Vec::new();
    for i in 0..3000u32 {
        pat.extend_from_slice(alloc::format!("line {} ababab\n", i % 97).as_bytes());
    }
    let def = ustd::deflate::deflate(&pat);
    check("deflate-shrink", def.len() * 3 < pat.len());
    check("inflate-roundtrip", ustd::inflate::inflate(&def).map(|d| d == pat).unwrap_or(false));
    let mut rnd = Vec::with_capacity(8192);
    let mut s = 0x12345u64;
    for _ in 0..8192 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rnd.push((s >> 33) as u8);
    }
    check("inflate-entropy", ustd::inflate::inflate(&ustd::deflate::deflate(&rnd))
        .map(|d| d == rnd).unwrap_or(false));
    // gzip container roundtrip: body offset + inflate + CRC/ISIZE trailer
    let gz = ustd::deflate::gzip_data(&pat);
    check("gzip-roundtrip", ustd::inflate::gzip_body(&gz)
        .and_then(|o| ustd::inflate::inflate(&gz[o..gz.len() - 8]))
        .map(|d| {
            d == pat
                && u32::from_le_bytes([gz[gz.len()-8], gz[gz.len()-7], gz[gz.len()-6], gz[gz.len()-5]])
                    == ustd::inflate::crc32(&pat)
                && u32::from_le_bytes([gz[gz.len()-4], gz[gz.len()-3], gz[gz.len()-2], gz[gz.len()-1]])
                    as usize == pat.len()
        })
        .unwrap_or(false));
    // zlib container roundtrip
    let zl = ustd::deflate::zlib_data(&pat);
    check("zlib-roundtrip", ustd::inflate::zlib_body(&zl)
        .and_then(|b| ustd::inflate::inflate(b))
        .map(|d| d == pat)
        .unwrap_or(false));

    // ---- /dev pseudo-FS ----
    {
        check("dev-dir-list", ustd::readdir("/dev")
            .map(|es| ["null", "zero", "full", "random", "urandom"]
                .iter()
                .all(|n| es.iter().any(|e| &e.name[..e.name_len as usize] == n.as_bytes())))
            .unwrap_or(false));
        check("dev-null-eof", ustd::read_all("/dev/null")
            .map(|d| d.is_empty())
            .unwrap_or(false));
        check("dev-zero", ustd::read_all("/dev/zero")
            .map(|d| !d.is_empty() && d.iter().all(|b| *b == 0))
            .unwrap_or(false));
        check("dev-random-bits", {
            let a = ustd::read_all("/dev/urandom").unwrap_or_default();
            !a.is_empty() && a.iter().any(|b| *b != 0)
        });
        check("dev-full-enospc", {
            match ustd::open("/dev/full", ustd::O_RDWR) {
                Ok(fd) => {
                    let r = ustd::write(fd, b"x");
                    ustd::close(fd);
                    r.is_err()
                }
                Err(_) => false,
            }
        });
    }

    // ---- sha1 known-answer + /dev/vda BPB ----
    check("sha1-abc", {
        // RFC 3174 KAT: sha1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let h = ustd::sha1(b"abc");
        h == [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
              0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d]
    });
    check("dev-vda-bpb", {
        match ustd::open("/dev/vda", ustd::O_RDONLY) {
            Ok(fd) => {
                let mut b = [0u8; 512];
                let r = ustd::read(fd, &mut b);
                ustd::close(fd);
                // FAT32 BPB: jump opcode + nonzero bytes/sector at [11]
                matches!(r, Ok(512)) && (b[0] == 0xeb || b[0] == 0xe9)
                    && u16::from_le_bytes([b[11], b[12]]) == 512
            }
            Err(_) => false,
        }
    });
    check("proc-pid-status", {
        // /proc/<pid>/status names a live process (selftest is pid!=0)
        // pid 2 is this selftest in the flagged boot
        ustd::read_all("/proc/2/status")
            .map(|d| {
                let s = String::from_utf8_lossy(&d);
                s.contains("Name:\tcosmos-selftest") && s.contains("VmSize:")
            })
            .unwrap_or(false)
    });
    check("proc-pid-dirlist", {
        ustd::readdir("/proc")
            .map(|es| es.iter().any(|e| e.is_dir != 0 && &e.name[..e.name_len as usize] == b"1"))
            .unwrap_or(false)
    });

    // ---- getpid + nice scheduling ----
    check("getpid-real", {
        let pid = ustd::getpid();
        pid > 0 && ustd::read_all(&alloc::format!("/proc/{}/status", pid))
            .map(|d| String::from_utf8_lossy(&d).contains("cosmos-selftest"))
            .unwrap_or(false)
    });
    check("nice-clamp", {
        // -20..19 clamp: 99 -> 19 stored, visible via /proc status
        ustd::set_nice(0, 99);
        let pid = ustd::getpid();
        let ok = ustd::read_all(&alloc::format!("/proc/{}/status", pid))
            .map(|d| String::from_utf8_lossy(&d).contains("Nice:\t19"))
            .unwrap_or(false);
        ustd::set_nice(0, 0);
        ok
    });
    check("nice-bad-pid", ustd::set_nice(0xFFFF_FFFE, 0) == -1000);
    check("vrun-charge", {
        // scheduler charges virtual runtime while we burn cpu:
        // stay Running for >=40ms so PIT ticks land between reads
        let pid = ustd::getpid();
        let v0 = vrun_of(pid);
        let t0 = ustd::uptime_ms();
        let mut acc = 0u64;
        while ustd::uptime_ms() - t0 < 40 {
            for i in 0..10_000u64 {
                acc = acc.wrapping_add(i ^ (acc << 1));
            }
        }
        core::hint::black_box(acc);
        vrun_of(pid) > v0
    });

    // ---- md5 known-answer ----
    check("md5-abc", {
        // RFC 1321 KAT: md5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let h = ustd::md5(b"abc");
        h == [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
              0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72]
    });

    // ---- strace: trace ourselves, run a syscall, drain records ----
    check("strace-self", {
        let pid = ustd::getpid();
        let ok = ustd::strace(0, pid, &mut []) == 0;
        let mut saw_uptime = false;
        if ok {
            let _ = ustd::uptime_ms(); // one syscall that must land in the ring
            let mut buf = [0u8; 56 * 16];
            let n = ustd::strace(2, pid, &mut buf);
            if n >= 56 {
                for rec in buf[..n as usize].chunks_exact(56) {
                    let nr = u64::from_le_bytes(rec[0..8].try_into().unwrap());
                    if nr == shared::SYS_UPTIME_MS {
                        saw_uptime = true;
                    }
                }
            }
            ustd::strace(1, pid, &mut []);
        }
        saw_uptime
    });

    // ---- /proc/iostat exists and counts real file IO ----
    check("proc-iostat", {
        ustd::read_all("/proc/iostat")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.contains("reads") && s.contains("writes")
            })
            .unwrap_or(false)
    });

    // ---- signals: STOP freezes a task, CONT resumes it, KILL reaps it ----
    check("sig-stop-cont", {
        let ok = match ustd::spawn("/bin/cosmos-calc", "") {
            Ok(pid) => {
                let stopped = ustd::kill2(pid, 19) == 0
                    && ustd::read_all(&alloc::format!("/proc/{}/status", pid))
                        .map(|d| String::from_utf8_lossy(&d).contains("T (stopped)"))
                        .unwrap_or(false);
                let resumed = ustd::kill2(pid, 18) == 0
                    && ustd::read_all(&alloc::format!("/proc/{}/status", pid))
                        .map(|d| String::from_utf8_lossy(&d).contains("R (running)"))
                        .unwrap_or(false);
                let _ = ustd::kill2(pid, 9);
                stopped && resumed
            }
            Err(_) => false,
        };
        ok
    });

    let (pass, fail) = unsafe { (PASS, FAIL) };
    println!("[selftest] DONE ok={} fail={}", pass, fail);
    fail as i64
}


fn vrun_of(pid: u32) -> u64 {
    ustd::read_all(&alloc::format!("/proc/{}/status", pid))
        .ok()
        .and_then(|d| {
            let s = String::from_utf8_lossy(&d).into_owned();
            s.lines()
                .find(|l| l.starts_with("Vrun:\t"))
                .and_then(|l| l[6..].trim().parse::<u64>().ok())
        })
        .unwrap_or(0)
}
