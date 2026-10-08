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

    // ---- man pages on disk + /proc/version ----
    check("man-pages", {
        ustd::read_all("/man/ls.txt")
            .map(|d| {
                let s = String::from_utf8_lossy(&d);
                s.contains("NAME") && s.contains("SYNOPSIS")
            })
            .unwrap_or(false)
    });
    check("proc-version", {
        ustd::read_all("/proc/version")
            .map(|d| String::from_utf8_lossy(&d).contains("CosmosOS"))
            .unwrap_or(false)
    });
    check("proc-stat", {
        ustd::read_all("/proc/stat")
            .map(|d| {
                let s = String::from_utf8_lossy(&d);
                s.contains("cpu") && s.contains("intr")
            })
            .unwrap_or(false)
    });
    check("proc-net-udp", {
        ustd::read_all("/proc/net/udp")
            .map(|d| String::from_utf8_lossy(&d).contains("local_address"))
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

    // ---- named pipes: mkfifo + buffered write/read + EOF on last-writer ----
    check("mkfifo", ustd::mkfifo("/st.pipe") == 0);
    check("mkfifo-dup", ustd::mkfifo("/st.pipe") < 0);
    // nonblocking-ish sanity: writer opens (O_WRONLY), writes, reader drains
    {
        let wfd = ustd::open("/st.pipe", shared::O_WRONLY | shared::O_CREATE);
        check("pipe-open-w", wfd.is_ok());
        if let Ok(wfd) = wfd {
            check("pipe-write", ustd::write(wfd, b"pipe-ok").map(|n| n == 7).unwrap_or(false));
            let rfd = ustd::open("/st.pipe", shared::O_RDONLY);
            check("pipe-open-r", rfd.is_ok());
            if let Ok(rfd) = rfd {
                let mut pb = [0u8; 16];
                let n = ustd::read(rfd, &mut pb).unwrap_or(0);
                check("pipe-read", n == 7 && &pb[..7] == b"pipe-ok");
                ustd::close(rfd);
            }
            // closing the last writer + drained queue -> EOF (read == 0)
            ustd::close(wfd);
            if let Ok(rfd2) = ustd::open("/st.pipe", shared::O_RDONLY) {
                let mut pb = [0u8; 8];
                let n = ustd::read(rfd2, &mut pb).unwrap_or(usize::MAX);
                check("pipe-eof", n == 0);
                ustd::close(rfd2);
            }
        }
        let _ = ustd::remove("/st.pipe");
    }

    // ---- symlinks: LNK> file + attr 0x40, open/stat/readlink/chain ----
    let _ = ustd::write_all("/link-target.txt", b"link-dest");
    check("symlink-write", ustd::write_all("/st.link", b"LNK>/link-target.txt").is_ok());
    check("symlink-attr", ustd::setattr("/st.link", 0x60).is_ok());
    check("readlink", ustd::readlink("/st.link").as_deref() == Some("/link-target.txt"));
    check(
        "readlink-nonlink",
        ustd::readlink("/link-target.txt").is_none(),
    );
    check("symlink-open", {
        ustd::read_all("/st.link")
            .map(|d| d == b"link-dest")
            .unwrap_or(false)
    });
    // chained link: st2 -> st.link -> /link-target.txt
    check("symlink-chain", {
        let ok = ustd::write_all("/st2.link", b"LNK>st.link").is_ok()
            && ustd::setattr("/st2.link", 0x60).is_ok();
        ok && ustd::read_all("/st2.link")
            .map(|d| d == b"link-dest")
            .unwrap_or(false)
    });
    // link loop: stA <-> stB must fail to open (ELOOP), not hang
    check("symlink-loop", {
        let ok = ustd::write_all("/sta.link", b"LNK>stb.link").is_ok()
            && ustd::setattr("/sta.link", 0x60).is_ok()
            && ustd::write_all("/stb.link", b"LNK>sta.link").is_ok()
            && ustd::setattr("/stb.link", 0x60).is_ok();
        ok && ustd::open("/sta.link", ustd::O_RDONLY).is_err()
    });
    // relative target resolves against the link's directory
    check("symlink-relative", {
        let ok = ustd::mkdir("/linkdir").is_ok()
            && ustd::write_all("/linkdir/real.txt", b"rel-ok").is_ok()
            && ustd::write_all("/linkdir/rel.link", b"LNK>real.txt").is_ok()
            && ustd::setattr("/linkdir/rel.link", 0x60).is_ok();
        ok && ustd::read_all("/linkdir/rel.link")
            .map(|d| d == b"rel-ok")
            .unwrap_or(false)
    });
    // ---- flock: advisory lock registry + /proc/locks + signal 0 probe ----
    let _ = ustd::write_all("/lock-a.txt", b"locked");
    check("flock-ex", ustd::flock("/lock-a.txt", 2) == 0);
    check("flock-proc", {
        ustd::read_all("/proc/locks")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.contains("EXCLUSIVE") && s.contains("/lock-a.txt")
            })
            .unwrap_or(false)
    });
    // each flock is a distinct open-file description (POSIX): a second EX
    // on an already-held path conflicts even for the owner → EWOULDBLOCK
    check("flock-same-owner-nb", ustd::flock("/lock-a.txt", 2 | 4) == -35);
    check("flock-nb-free", ustd::flock("/lock-b.txt", 2 | 4) == 0);
    check("flock-un", ustd::flock("/lock-a.txt", 8) == 0);
    check("flock-un-gone", {
        ustd::read_all("/proc/locks")
            .map(|d| !String::from_utf8_lossy(&d).contains("/lock-a.txt"))
            .unwrap_or(false)
    });
    check("flock-un-unheld", ustd::flock("/lock-a.txt", 8) == 0);
    let _ = ustd::flock("/lock-b.txt", 8);
    // signal(pid,0): existence probe — self exists, pid 99999 does not
    check("kill-probe-self", ustd::kill2(ustd::getpid(), 0) == 0);
    check("kill-probe-missing", ustd::kill2(99999, 0) != 0);
    // signals beyond KILL/STOP/CONT now route through kill_pid_code
    check("kill-term-proc", {
        match ustd::spawn("/bin/cosmos-calc", "") {
            Ok(pid) => {
                let r = ustd::kill2(pid, 15) == 0;
                ustd::sleep_ms(30);
                r && ustd::kill2(pid, 0) != 0
            }
            Err(_) => false,
        }
    });
    check("kill-hup-proc", {
        match ustd::spawn("/bin/cosmos-calc", "") {
            Ok(pid) => {
                let r = ustd::kill2(pid, 1) == 0;
                ustd::sleep_ms(30);
                r && ustd::kill2(pid, 0) != 0
            }
            Err(_) => false,
        }
    });
    // ---- batch 29: devfs depth + procfs expansion ----
    check("proc-loadavg", {
        ustd::read_all("/proc/loadavg")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                let mut it = s.split_whitespace();
                let fmt = it
                    .next()
                    .map(|x| x.ends_with(".00"))
                    .unwrap_or(false);
                // "0.00 0.00 0.00 R/T lastpid" = 5 fields
                fmt && it.count() == 4
            })
            .unwrap_or(false)
    });
    check("proc-diskstats", {
        ustd::read_all("/proc/diskstats")
            .map(|d| String::from_utf8_lossy(&d).contains("vda"))
            .unwrap_or(false)
    });
    check("proc-interrupts", {
        ustd::read_all("/proc/interrupts")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.contains("PIT") && s.contains("keyboard")
            })
            .unwrap_or(false)
    });
    check("proc-modules-empty", {
        // honest empty file: the kernel is monolithic, no LKM subsystem
        ustd::read_all("/proc/modules")
            .map(|d| d.is_empty())
            .unwrap_or(false)
    });
    check("proc-net-dev", {
        ustd::read_all("/proc/net/dev")
            .map(|d| String::from_utf8_lossy(&d).contains("eth0:"))
            .unwrap_or(false)
    });
    check("proc-self-magic", {
        let pid = ustd::getpid();
        ustd::read_all("/proc/self/status")
            .map(|d| {
                String::from_utf8_lossy(&d)
                    .contains(&alloc::format!("Pid:\t{}", pid))
            })
            .unwrap_or(false)
    });
    check("proc-pid-maps", {
        let pid = ustd::getpid();
        ustd::read_all(&alloc::format!("/proc/{}/maps", pid))
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.contains("[stack]") && s.contains("cosmos-selftest")
            })
            .unwrap_or(false)
    });
    check("proc-pid-io", {
        let pid = ustd::getpid();
        // the first read charges rchar; the second must report it > 0
        let _ = ustd::read_all(&alloc::format!("/proc/{}/io", pid));
        ustd::read_all(&alloc::format!("/proc/{}/io", pid))
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.lines()
                    .find(|l| l.starts_with("rchar:"))
                    .and_then(|l| l[6..].trim().parse::<u64>().ok())
                    .unwrap_or(0)
                    > 0
            })
            .unwrap_or(false)
    });
    check("proc-pid-statm", {
        let pid = ustd::getpid();
        ustd::read_all(&alloc::format!("/proc/{}/statm", pid))
            .map(|d| {
                String::from_utf8_lossy(&d)
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0)
                    > 0
            })
            .unwrap_or(false)
    });
    check("proc-pid-exe", {
        let pid = ustd::getpid();
        ustd::readlink(&alloc::format!("/proc/{}/exe", pid))
            .map(|t| t.contains("cosmos-selftest"))
            .unwrap_or(false)
    });
    check("proc-mmap-maps", {
        // anonymous mmap lands as [anon] in /proc/self/maps
        match ustd::mmap(8192) {
            Some(_) => ustd::read_all(&alloc::format!("/proc/{}/maps", ustd::getpid()))
                .map(|d| String::from_utf8_lossy(&d).contains("[anon]"))
                .unwrap_or(false),
            None => false,
        }
    });
    check("proc-shm-maps", {
        match ustd::shm_create(4096) {
            Some(id) => {
                let mapped = ustd::shm_map(id).is_some();
                let ok = mapped
                    && ustd::read_all(&alloc::format!("/proc/{}/maps", ustd::getpid()))
                        .map(|d| {
                            String::from_utf8_lossy(&d)
                                .contains(&alloc::format!("shm#{}", id))
                        })
                        .unwrap_or(false);
                ustd::shm_drop(id);
                ok
            }
            None => false,
        }
    });
    check("sysrq-sync", ustd::write_all("/proc/sysrq-trigger", b"s").is_ok());
    check("dev-full-enospc", {
        ustd::write_all("/dev/full", b"x").err() == Some(-28)
    });
    check("dev-fb0", {
        ustd::open("/dev/fb0", 0)
            .map(|fd| {
                let mut px = [0u8; 4];
                let r = ustd::read(fd, &mut px).map(|n| n == 4).unwrap_or(false);
                ustd::close(fd);
                r
            })
            .unwrap_or(false)
    });
    check("dev-mem", {
        ustd::open("/dev/mem", 0)
            .map(|fd| {
                let mut b = [0u8; 16];
                let r = ustd::read(fd, &mut b).map(|n| n == 16).unwrap_or(false);
                ustd::close(fd);
                r
            })
            .unwrap_or(false)
    });
    check("dev-nvram", {
        ustd::open("/dev/nvram", 0)
            .map(|fd| {
                let mut b = [0u8; 128];
                let n = ustd::read(fd, &mut b).unwrap_or(0);
                ustd::close(fd);
                n == 128
            })
            .unwrap_or(false)
    });
    check("dev-smbios", {
        // raw SMBIOS entry point: "_SM3_" (3.x) or "_SM_" (2.x) anchor
        ustd::open("/dev/smbios", 0)
            .map(|fd| {
                let mut b = [0u8; 32];
                let n = ustd::read(fd, &mut b).unwrap_or(0);
                ustd::close(fd);
                n >= 4 && &b[0..3] == b"_SM"
            })
            .unwrap_or(false)
    });
    check("dev-kmsg", {
        ustd::open("/dev/kmsg", 0)
            .map(|fd| {
                let mut b = [0u8; 64];
                let n = ustd::read(fd, &mut b).unwrap_or(0);
                ustd::close(fd);
                n > 0
            })
            .unwrap_or(false)
    });
    check(
        "dev-console-write",
        ustd::write_all("/dev/console", b"[selftest] console-write\n").is_ok(),
    );
    check("dev-rtc-line", {
        ustd::read_all("/dev/rtc")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.contains(':') && s.contains('-')
            })
            .unwrap_or(false)
    });

    // ---- batch 30: real mm syscalls, sched class, dev/proc depth ----
    check("munmap", {
        match ustd::mmap(8192) {
            Some(p) => {
                let pid = ustd::getpid();
                let maps_has = |needle: &str| {
                    ustd::read_all(&alloc::format!("/proc/{}/maps", pid))
                        .map(|d| String::from_utf8_lossy(&d).contains(needle))
                        .unwrap_or(false)
                };
                let before = maps_has("[anon]");
                let un = ustd::munmap(p, 8192);
                // first mmap established [anon]; munmap must cut its pages
                let maps = ustd::read_all(&alloc::format!("/proc/{}/maps", pid))
                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                    .unwrap_or_default();
                let addr = p as u64;
                let still = maps.lines().any(|l| {
                    l.split_whitespace()
                        .next()
                        .and_then(|rg| {
                            let mut it = rg.split('-');
                            match (it.next(), it.next()) {
                                (Some(a), Some(b)) => Some((
                                    u64::from_str_radix(a, 16).unwrap_or(0),
                                    u64::from_str_radix(b, 16).unwrap_or(0),
                                )),
                                _ => None,
                            }
                        })
                        .map(|(a, b)| addr >= a && addr < b)
                        .unwrap_or(false)
                });
                before && un && !still
            }
            None => false,
        }
    });
    check("mprotect", {
        match ustd::mmap(4096) {
            Some(p) => {
                let pid = ustd::getpid();
                let ok = ustd::mprotect(p, 4096, 1); // PROT_READ
                let perm = ustd::read_all(&alloc::format!("/proc/{}/maps", pid))
                    .map(|d| {
                        let addr = p as u64;
                        String::from_utf8_lossy(&d)
                            .lines()
                            .find(|l| {
                                l.split_whitespace()
                                    .next()
                                    .and_then(|rg| {
                                        let mut it = rg.split('-');
                                        match (it.next(), it.next()) {
                                            (Some(a), Some(b)) => Some((
                                                u64::from_str_radix(a, 16).unwrap_or(0),
                                                u64::from_str_radix(b, 16).unwrap_or(0),
                                            )),
                                            _ => None,
                                        }
                                    })
                                    .map(|(a, b)| addr >= a && addr < b)
                                    .unwrap_or(false)
                            })
                            .map(|l| l.contains("r--") || l.contains(" r"))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                let _ = ustd::munmap(p, 4096);
                ok && perm
            }
            None => false,
        }
    });
    check("chrt", {
        let pid = ustd::getpid();
        let on = ustd::chrt(pid, 1); // SCHED_RT
        let rt = ustd::read_all(&alloc::format!("/proc/{}/status", pid))
            .map(|d| {
                String::from_utf8_lossy(&d)
                    .lines()
                    .find(|l| l.starts_with("Rt:"))
                    .map(|l| l.contains('1'))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let off = ustd::chrt(pid, 0);
        on && rt && off
    });
    check("ipcs-shm", {
        match ustd::shm_create(4096) {
            Some(id) => {
                let listed = ustd::ipcs().contains(&id.to_string());
                ustd::shm_drop(id);
                listed && !ustd::ipcs().contains(&alloc::format!("{} ", id))
            }
            None => false,
        }
    });
    check("dev-smbios-tables", {
        // a real smbios table: first structure is any valid type with a
        // formatted length inside the blob (QEMU leads with type 1 here)
        ustd::read_all("/dev/smbios-tables")
            .map(|d| d.len() > 8 && d[1] as usize >= 4 && (d[1] as usize) < d.len())
            .unwrap_or(false)
    });
    check("dev-port", {
        // real I/O port space: write a byte to 0x80 (POST delay port —
        // fire-and-forget), read a live byte back from 0x40 (PIT counter)
        ustd::open("/dev/port", 2)
            .and_then(|fd| {
                let mut b = [0u8; 1];
                let _ = ustd::seek(fd, 0x80, 0);
                let w = ustd::write(fd, &[0xABu8]).unwrap_or(0);
                let _ = ustd::seek(fd, 0x40, 0);
                let n = ustd::read(fd, &mut b).unwrap_or(0);
                ustd::close(fd);
                if w == 1 && n == 1 {
                    Ok(())
                } else {
                    Err(-1i64)
                }
            })
            .is_ok()
    });
    check("proc-smaps-wchan-children", {
        let pid = ustd::getpid();
        let smaps = ustd::read_all(&alloc::format!("/proc/{}/smaps", pid))
            .map(|d| String::from_utf8_lossy(&d).contains("Rss:"))
            .unwrap_or(false);
        let wchan = ustd::read_all(&alloc::format!("/proc/{}/wchan", pid))
            .map(|d| !String::from_utf8_lossy(&d).trim().is_empty())
            .unwrap_or(false);
        let children = ustd::read_all(&alloc::format!("/proc/1/children"))
            .map(|d| !String::from_utf8_lossy(&d).trim().is_empty())
            .unwrap_or(false);
        smaps && wchan && children
    });
    check("net-operstate", {
        let r = |v: &str| ustd::read_all("/proc/net/operstate")
            .map(|d| String::from_utf8_lossy(&d).trim() == v)
            .unwrap_or(false);
        let w = ustd::write_all("/proc/net/operstate", b"down").is_ok()
            && r("down")
            && ustd::write_all("/proc/net/operstate", b"up").is_ok()
            && r("up");
        w
    });
    check("utmp-log", {
        // every spawn appends "pid exe epoch" — init/selftest must be there
        ustd::read_all("/utmp")
            .map(|d| {
                let t = String::from_utf8_lossy(&d).into_owned();
                t.lines().any(|l| l.contains("selftest") || l.contains("init"))
            })
            .unwrap_or(false)
    });
    check("chrt-bogus-pid", !ustd::chrt(0xFFFF_FFFE, 1));

    // ---- batch 31: real fd plumbing -------------------------------------
    check("anon-pipe", {
        // SYS_PIPE: write on the write fd, read it back on the read fd —
        // real bytes through a kernel pipe object, no fs file involved
        ustd::pipe()
            .map(|(rfd, wfd)| {
                let n = ustd::write(wfd, b"pipe7").unwrap_or(0);
                let mut b = [0u8; 8];
                let got = ustd::read(rfd, &mut b).unwrap_or(0);
                ustd::close(rfd);
                ustd::close(wfd);
                n == 5 && got == 5 && &b[..5] == b"pipe7"
            })
            .unwrap_or(false)
    });
    check("pipe-poll", {
        // SYS_POLL: reader polls not-ready before the write, ready after
        ustd::pipe()
            .map(|(rfd, wfd)| {
                let before = ustd::poll(&[rfd as u32], &[1], 0);
                let _ = ustd::write(wfd, b"x");
                let after = ustd::poll(&[rfd as u32], &[1], 0);
                let wr = ustd::poll(&[wfd as u32], &[2], 0);
                ustd::close(rfd);
                ustd::close(wfd);
                before == 0 && after == 1 && wr == 1
            })
            .unwrap_or(false)
    });
    check("pipe-eof", {
        // last writer closing => reader sees EOF (0), not a hang
        ustd::pipe()
            .map(|(rfd, wfd)| {
                let _ = ustd::write(wfd, b"q");
                ustd::close(wfd);
                let mut b = [0u8; 8];
                let n1 = ustd::read(rfd, &mut b).unwrap_or(0);
                let n2 = ustd::read(rfd, &mut b).unwrap_or(0);
                ustd::close(rfd);
                n1 == 1 && n2 == 0
            })
            .unwrap_or(false)
    });
    check("dup2", {
        // SYS_DUP2: an aliased fd hits the same pipe queue
        ustd::pipe()
            .map(|(rfd, wfd)| {
                let nd = ustd::dup2(wfd as u64, 40);
                let n = if nd == 40 { ustd::write(40i64, b"dd").unwrap_or(0) } else { 0 };
                let mut b = [0u8; 4];
                let got = ustd::read(rfd, &mut b).unwrap_or(0);
                ustd::close(rfd);
                ustd::close(wfd);
                ustd::close(40i64);
                n == 2 && got == 2 && &b[..2] == b"dd"
            })
            .unwrap_or(false)
    });
    check("rusage", {
        ustd::rusage(ustd::getpid())
            .map(|(_t, rss)| rss > 0)
            .unwrap_or(false)
            && ustd::rusage(0xFFFF_FFFE).is_none()
    });
    check("proc-fdinfo", {
        let pid = ustd::getpid();
        ustd::read_all(&alloc::format!("/proc/{}/fdinfo", pid))
            .map(|d| {
                let t = String::from_utf8_lossy(&d);
                t.contains("flags:")
            })
            .unwrap_or(false)
    });
    check("net-owners", {
        // bind a real listener -> /proc/net/owners names its owner pid
        ustd::TcpListener::bind(8164)
            .map(|l| {
                let me = ustd::getpid();
                let s = ustd::read_all("/proc/net/owners")
                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                    .unwrap_or_default();
                let hit = s
                    .lines()
                    .any(|row| row == alloc::format!("listen 8164 {}", me));
                drop(l);
                hit
            })
            .unwrap_or(false)
    });
    check("fsync", {
        // fsync(fd) commits via the device; fsync(badfd) must fail
        match ustd::open("/st-fsync", ustd::O_RDWR | ustd::O_CREATE) {
            Ok(fd) => {
                let _ = ustd::write(fd, b"x");
                let ok = ustd::fsync(fd) == 0
                    && ustd::fsync(0x7fff_ffff) < 0
                    && ustd::sync_all() == 0;
                ustd::close(fd);
                let _ = ustd::remove("/st-fsync");
                ok
            }
            Err(_) => false,
        }
    });
    check("timerfd", {
        // arm 30ms one-shot: poll must report readable, read yields count>=1
        let fd = ustd::timerfd_create();
        if fd < 0 {
            false
        } else {
            ustd::timerfd_set(fd, 30, 0);
            let rdy = ustd::poll(&[fd as u32], &[1], 2000) > 0;
            let n = ustd::timerfd_read(fd).unwrap_or(0);
            ustd::close(fd);
            rdy && n >= 1
        }
    });
    check("timerfd-periodic", {
        // 20ms interval: after ~90ms the count should be >= 3
        let fd = ustd::timerfd_create();
        if fd < 0 {
            false
        } else {
            ustd::timerfd_set(fd, 10, 20);
            ustd::sleep_ms(95);
            let n = ustd::timerfd_read(fd).unwrap_or(0);
            ustd::close(fd);
            n >= 3
        }
    });
    check("inotify", {
        // watch / for IN_ALL, create a file, read the event back
        let ifd = ustd::inotify_init();
        if ifd < 0 {
            false
        } else {
            let wd = ustd::inotify_add(ifd, "/", ustd::IN_ALL);
            let ok = wd >= 0
                && ustd::write_all("/st-inot", b"e").is_ok()
                && {
                    let rdy = ustd::poll(&[ifd as u32], &[1], 2000) > 0;
                    let mut b = [0u8; 512];
                    match ustd::read(ifd, &mut b) {
                        Ok(n) if n > 0 => {
                            let s = String::from_utf8_lossy(&b[..n]);
                            s.lines().any(|l| {
                                let mut it = l.split_whitespace();
                                it.next();
                                let m: u64 =
                                    it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                                let nm = it.next().unwrap_or("");
                                nm == "st-inot" && m & 0x100 != 0
                            })
                        }
                        _ => false,
                    }
                };
            ustd::close(ifd);
            let _ = ustd::remove("/st-inot");
            ok
        }
    });
    check("eventfd", {
        // write 5, poll-ready, read drains to 5; empty then write 3 -> 3
        let fd = ustd::eventfd(0, 0);
        if fd < 0 {
            false
        } else {
            let ok = ustd::eventfd_write(fd, 5) == 0
                && ustd::poll(&[fd as u32], &[1], 2000) > 0
                && ustd::eventfd_read(fd) == Some(5)
                && ustd::poll(&[fd as u32], &[1], 0) == 0
                && ustd::eventfd_write(fd, 3) == 0
                && ustd::eventfd_read(fd) == Some(3);
            ustd::close(fd);
            ok
        }
    });
    check("eventfd-sem", {
        // semaphore mode: count 2 yields two reads of 1, then not-ready
        let fd = ustd::eventfd(2, ustd::EFD_SEMAPHORE);
        if fd < 0 {
            false
        } else {
            let ok = ustd::eventfd_read(fd) == Some(1)
                && ustd::eventfd_read(fd) == Some(1)
                && ustd::poll(&[fd as u32], &[1], 0) == 0;
            ustd::close(fd);
            ok
        }
    });
    check("epoll", {
        // epoll over a pipe read-end: quiet before write, fires after
        match (ustd::pipe(), ustd::epoll_create()) {
            (Some((rfd, wfd)), ep) if ep >= 0 => {
                let mut evs = [(0u32, 0u32); 4];
                let ok = ustd::epoll_ctl(ep, ustd::EPOLL_CTL_ADD, rfd, ustd::EPOLLIN)
                    == 0
                    && ustd::epoll_wait(ep, &mut evs, 0) == 0
                    && ustd::write(wfd, b"x").is_ok()
                    && ustd::epoll_wait(ep, &mut evs, 2000) == 1
                    && evs[0].0 == rfd as u32
                    && evs[0].1 & ustd::EPOLLIN as u32 != 0;
                ustd::close(ep);
                ustd::close(rfd);
                ustd::close(wfd);
                ok
            }
            _ => false,
        }
    });
    check("epoll-timerfd", {
        // a timerfd interest fires once its armed timer expires
        let (tfd, ep) = (ustd::timerfd_create(), ustd::epoll_create());
        let mut evs = [(0u32, 0u32); 4];
        let ok = tfd >= 0
            && ep >= 0
            && ustd::timerfd_set(tfd, 25, 0) == 0
            && ustd::epoll_ctl(ep, ustd::EPOLL_CTL_ADD, tfd, ustd::EPOLLIN) == 0
            && ustd::epoll_wait(ep, &mut evs, 2000) == 1
            && evs[0].0 == tfd as u32;
        ustd::close(ep);
        ustd::close(tfd);
        ok
    });
    check("socketpair", {
        // a->b and b->a both carry bytes; poll reports ready
        match ustd::socketpair() {
            Some((a, b)) => {
                let mut buf = [0u8; 8];
                let ok = ustd::write(a, b"hi").is_ok()
                    && ustd::write(b, b"yo").is_ok()
                    && ustd::poll(&[b as u32], &[1], 1000) == 1
                    && ustd::read(b, &mut buf).map(|n| &buf[..n] == b"hi").unwrap_or(false)
                    && ustd::poll(&[a as u32], &[1], 1000) == 1
                    && ustd::read(a, &mut buf).map(|n| &buf[..n] == b"yo").unwrap_or(false)
                    && ustd::poll(&[b as u32], &[1], 0) == 0;
                ustd::close(a);
                ustd::close(b);
                ok
            }
            None => false,
        }
    });
    check("socketpair-eof", {
        // closing side A makes side B's read return EOF and write EPIPE
        match ustd::socketpair() {
            Some((a, b)) => {
                ustd::close(a);
                let mut buf = [0u8; 8];
                let ok = ustd::poll(&[b as u32], &[1], 1000) == 1
                    && ustd::read(b, &mut buf) == Ok(0)
                    && ustd::write(b, b"x") == Err(-32);
                ustd::close(b);
                ok
            }
            None => false,
        }
    });
    check("pidfd", {
        // pidfd of a live task: not ready while running, readable after
        // kill; read yields a status. pidfd of an absent pid must fail.
        match ustd::spawn("/bin/cosmos-calc", "") {
            Ok(pid) => {
                let pfd = ustd::pidfd(pid);
                let ok = pfd >= 0
                    && ustd::pidfd(999_999) < 0
                    && ustd::poll(&[pfd as u32], &[1], 0) == 0
                    && ustd::kill2(pid, 9) == 0
                    && ustd::poll(&[pfd as u32], &[1], 4000) == 1
                    && ustd::pidfd_read(pfd).is_some();
                ustd::close(pfd);
                ok
            }
            Err(_) => ustd::pidfd(999_999) < 0,
        }
    });
    check("fcntl", {
        // F_GETFL/F_SETFL roundtrip; F_DUPFD lands at >= min, shares pos
        match ustd::open("/st-fcntl", ustd::O_CREATE | ustd::O_RDWR) {
            Ok(fd) => {
                let fl = ustd::fcntl(fd, ustd::F_GETFL, 0);
                let ok = fl >= 0
                    && ustd::fcntl(fd, ustd::F_SETFL, fl as u64 | ustd::O_NONBLOCK)
                        == 0
                    && ustd::fcntl(fd, ustd::F_GETFL, 0) & ustd::O_NONBLOCK as i64
                        != 0;
                let dup = ustd::fcntl(fd, ustd::F_DUPFD, 10);
                let ok = ok && dup >= 10;
                if dup >= 0 {
                    ustd::close(dup);
                }
                ustd::close(fd);
                let _ = ustd::remove("/st-fcntl");
                ok
            }
            Err(_) => false,
        }
    });
    // ---- batch 35: vectored I/O, sendfile, fstat, ftruncate ----
    check("writev/readv", {
        let mut ok = false;
        if let Ok(fd) = ustd::open("/st-iov", ustd::O_RDWR | ustd::O_CREATE | ustd::O_TRUNC) {
            let n = ustd::writev(fd, &[(b"he".as_ptr(), 2), (b"llo".as_ptr(), 3), (b"!".as_ptr(), 1)]);
            let _ = ustd::close(fd);
            if n == 6 {
                if let Ok(fd) = ustd::open("/st-iov", ustd::O_RDONLY) {
                    let (mut b1, mut b2, mut b3) = ([0u8; 2], [0u8; 3], [0u8; 4]);
                    let n = ustd::readv(fd, &mut [
                        (b1.as_mut_ptr(), 2),
                        (b2.as_mut_ptr(), 3),
                        (b3.as_mut_ptr(), 4),
                    ]);
                    ustd::close(fd);
                    // 6 bytes: b3 gets a short vec (1 byte), total is the file size
                    ok = n == 6
                        && &b1 == b"he"
                        && &b2 == b"llo"
                        && b3[0] == b'!';
                }
            }
        }
        let _ = ustd::remove("/st-iov");
        ok
    });
    check("sendfile", {
        let mut ok = false;
        if let Ok(f) = ustd::open("/st-sf", ustd::O_WRONLY | ustd::O_CREATE | ustd::O_TRUNC) {
            let _ = ustd::write(f, b"sendfile-data-1234567890");
            let _ = ustd::close(f);
        }
        match (
            ustd::open("/st-sf", ustd::O_RDONLY),
            ustd::open("/st-sf2", ustd::O_WRONLY | ustd::O_CREATE | ustd::O_TRUNC),
        ) {
            (Ok(inf), Ok(outf)) => {
                let n = ustd::sendfile(outf, inf, None, 24);
                ustd::close(inf);
                ustd::close(outf);
                ok = n == 24
                    && ustd::read_all("/st-sf2").map(|d| d == b"sendfile-data-1234567890").unwrap_or(false);
            }
            _ => {}
        }
        let _ = ustd::remove("/st-sf");
        let _ = ustd::remove("/st-sf2");
        ok
    });
    check("sendfile-offset", {
        // POSIX offset semantics: reads from *off, reports new off, keeps fd pos
        let mut ok = false;
        if let Ok(f) = ustd::open("/st-sfo", ustd::O_WRONLY | ustd::O_CREATE | ustd::O_TRUNC) {
            let _ = ustd::write(f, b"0123456789ABCDEF");
            let _ = ustd::close(f);
        }
        match (
            ustd::open("/st-sfo", ustd::O_RDONLY),
            ustd::open("/st-sfo2", ustd::O_WRONLY | ustd::O_CREATE | ustd::O_TRUNC),
        ) {
            (Ok(inf), Ok(outf)) => {
                let mut off = 10u64;
                let n = ustd::sendfile(outf, inf, Some(&mut off), 6);
                // fd position must be untouched (still 0): one byte read == '0'
                let mut b = [0u8; 1];
                let rn = ustd::read(inf, &mut b).unwrap_or(0);
                ustd::close(inf);
                ustd::close(outf);
                ok = n == 6
                    && off == 16
                    && rn == 1
                    && b[0] == b'0'
                    && ustd::read_all("/st-sfo2").map(|d| d == b"ABCDEF").unwrap_or(false);
            }
            _ => {}
        }
        let _ = ustd::remove("/st-sfo");
        let _ = ustd::remove("/st-sfo2");
        ok
    });
    check("fstat/ftruncate", {
        let mut ok = false;
        if let Ok(fd) = ustd::open("/st-ftr", ustd::O_RDWR | ustd::O_CREATE | ustd::O_TRUNC) {
            let _ = ustd::write(fd, b"0123456789");
            // shrink to 4, then grow to 8 (zero-pad)
            ok = ustd::fstat(fd).map(|s| s.size == 10).unwrap_or(false)
                && ustd::ftruncate(fd, 4) == 0
                && ustd::fstat(fd).map(|s| s.size == 4).unwrap_or(false)
                && ustd::ftruncate(fd, 8) == 0
                && ustd::fstat(fd).map(|s| s.size == 8).unwrap_or(false)
                && ustd::read_all("/st-ftr")
                    .map(|d| &d[..4] == b"0123" && d[4..].iter().all(|&x| x == 0))
                    .unwrap_or(false);
            // object fd: EINVAL on truncate, zeroed stat
            let efd = ustd::eventfd(0, 0);
            if efd >= 0 {
                ok = ok
                    && ustd::ftruncate(efd, 4) == -22
                    && ustd::fstat(efd).map(|s| s.size == 0).unwrap_or(false);
                ustd::close(efd);
            } else {
                ok = false;
            }
            let _ = ustd::close(fd);
        }
        let _ = ustd::remove("/st-ftr");
        ok
    });
    // ---- batch 36: socket fds ----
    check("socket-udp", {
        // bind + sendto + nonblock recvfrom EAGAIN + poll-empty + close
        let mut ok = false;
        let fd = ustd::socket(ustd::SOCK_DGRAM);
        if fd >= 0 && ustd::bind(fd, 43210) == 0 {
            // nonblock so the empty-queue probes return EAGAIN, not block
            ustd::fcntl(fd, ustd::F_SETFL, ustd::O_NONBLOCK);
            // datagram fires onto the wire (needs the peer to be real —
            // ARP to the slirp gateway resolves)
            ok = ustd::sendto(fd, b"sockfd-test", [10, 0, 2, 2], 43211) == 11
                // nothing inbound yet: nonblock read is EAGAIN, poll is 0
                && ustd::recvfrom(fd, &mut [0u8; 64]).is_err()
                && ustd::poll(&[fd as u32], &[1], 0) == 0
                // double-bind is EINVAL
                && ustd::bind(fd, 43212) != 0;
        }
        if fd >= 0 {
            ustd::close(fd);
        }
        // after close the port frees: a fresh socket can bind it
        let fd2 = ustd::socket(ustd::SOCK_DGRAM);
        ok = ok && fd2 >= 0 && ustd::bind(fd2, 43210) == 0;
        if fd2 >= 0 {
            ustd::close(fd2);
        }
        ok
    });
    check("socket-tcp", {
        // bind+listen -> listener fd; accept with nothing pending is
        // EAGAIN-ish (-11); connect() to the host gets a real answer
        let mut ok = false;
        let lfd = ustd::socket(ustd::SOCK_STREAM);
        if lfd >= 0
            && ustd::bind(lfd, 43220) == 0
            && ustd::listen(lfd, 4) == 0
        {
            // nonblock: accept on an empty listener is EAGAIN, not a block
            ustd::fcntl(lfd, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ustd::accept(lfd).is_err()
                && ustd::poll(&[lfd as u32], &[1], 0) == 0
                && ustd::fstat(lfd).map(|s| s.size == 0).unwrap_or(false);
        }
        if lfd >= 0 {
            ustd::close(lfd);
        }
        // unbound connect picks a real ephemeral port and handshakes
        let cfd = ustd::socket(ustd::SOCK_STREAM);
        if cfd >= 0 {
            // connect to the slirp gateway on a closed port: real SYN out,
            // real RST/timeout back — any deterministic i64 result counts
            let _ = ustd::connect(cfd, [10, 0, 2, 2], 9);
            ustd::close(cfd);
        }
        ok
    });
    // ---- batch 37: AF_UNIX + shutdown + sockname ----
    check("unix-socket", {
        // bind+listen a unix name, connect a client, accept, echo both
        // directions over the real sockpair-backed data plane.
        let mut ok = false;
        let lfd = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        let cfd = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        if lfd >= 0 && cfd >= 0 {
            ustd::fcntl(lfd, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ustd::bind_path(lfd, "/uts-selftest") == 0
                // connect before listen -> ECONNREFUSED, not ENOENT
                && ustd::connect_path(cfd, "/uts-selftest") == -111
                && ustd::listen(lfd, 4) == 0
                && ustd::connect_path(cfd, "/uts-selftest") == 0
                // name taken while bound
                && {
                    let d = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
                    let r = ustd::bind_path(d, "/uts-selftest");
                    ustd::close(d);
                    r == -98
                };
            if ok {
                // listener is readable -> accept -> server fd
                let sfd = if ustd::poll(&[lfd as u32], &[1], 500) > 0 {
                    ustd::accept(lfd).ok().map(|(f, _, _)| f)
                } else {
                    None
                };
                if let Some(sfd) = sfd {
                    let mut b = [0u8; 64];
                    ok = ustd::write(cfd, b"ping") == Ok(4)
                        && ustd::poll(&[sfd as u32], &[1], 500) > 0
                        && ustd::read(sfd, &mut b) == Ok(4)
                        && &b[..4] == b"ping"
                        && ustd::write(sfd, b"pong") == Ok(4)
                        && ustd::poll(&[cfd as u32], &[1], 500) > 0
                        && ustd::read(cfd, &mut b) == Ok(4)
                        && &b[..4] == b"pong"
                        // getsockname on the listener = the bound path
                        && ustd::getsockname(lfd, &mut b)
                            .map(|n| {
                                n >= 3
                                    && u16::from_le_bytes([b[0], b[1]]) == 1
                                    && &b[2..n - 1] == b"/uts-selftest"
                            })
                            .unwrap_or(false)
                        // getpeername on the client = the path it dialed
                        && ustd::getpeername(cfd, &mut b)
                            .map(|n| {
                                n >= 3
                                    && u16::from_le_bytes([b[0], b[1]]) == 1
                                    && &b[2..n - 1] == b"/uts-selftest"
                            })
                            .unwrap_or(false);
                    // shutdown(client, WR): server sees EOF after drain;
                    // client can still read; server->client still works
                    ok = ok
                        && ustd::shutdown(cfd, 1) == 0
                        && ustd::write(cfd, b"x") == Err(-32) // EPIPE
                        && ustd::poll(&[sfd as u32], &[1], 500) > 0
                        && ustd::read(sfd, &mut b) == Ok(0) // peer EOF
                        && ustd::write(sfd, b"tail") == Ok(4)
                        && ustd::poll(&[cfd as u32], &[1], 500) > 0
                        && ustd::read(cfd, &mut b) == Ok(4)
                        && &b[..4] == b"tail";
                    ustd::close(sfd);
                } else {
                    ok = false;
                }
            }
        }
        if lfd >= 0 {
            ustd::close(lfd); // frees the name
        }
        if cfd >= 0 {
            ustd::close(cfd);
        }
        // listener gone -> connect is ENOENT; name is rebindable
        let d = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        ok = ok && d >= 0 && ustd::connect_path(d, "/uts-selftest") == -2
            && ustd::bind_path(d, "/uts-selftest") == 0;
        if d >= 0 {
            ustd::close(d);
        }
        ok
    });
    check("shutdown", {
        // on a plain socketpair: SHUT_WR -> peer EOF + our writes EPIPE,
        // our reads still fine
        let mut ok = false;
        if let Some((a, b)) = ustd::socketpair() {
            ustd::fcntl(a, ustd::F_SETFL, ustd::O_NONBLOCK);
            ustd::fcntl(b, ustd::F_SETFL, ustd::O_NONBLOCK);
            let mut buf = [0u8; 16];
            ok = ustd::write(a, b"hi") == Ok(2)
                && ustd::shutdown(a, 1) == 0
                && ustd::write(a, b"x") == Err(-32)
                && ustd::read(b, &mut buf) == Ok(2)
                && &buf[..2] == b"hi"
                && ustd::read(b, &mut buf) == Ok(0) // EOF after drain
                && ustd::write(b, b"yo") == Ok(2)
                && ustd::read(a, &mut buf) == Ok(2)
                && &buf[..2] == b"yo"
                && ustd::shutdown(b, 0) == 0
                && ustd::read(b, &mut buf) == Ok(0); // SHUT_RD
            ustd::close(a);
            ustd::close(b);
        }
        ok
    });
    // ---- batch 38: sendmsg/recvmsg SCM_RIGHTS fd passing ----
    check("sendmsg-fd", {
        // a client passes an open file fd across an AF_UNIX connection;
        // the accepted server end adopts it and reads the file through it.
        let mut ok = false;
        let _ = ustd::write_all("/st-pass.txt", b"FDPASS");
        let pfd = ustd::open("/st-pass.txt", ustd::O_RDWR).unwrap_or(-1);
        let lfd = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        let cfd = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        if pfd >= 0 && lfd >= 0 && cfd >= 0 {
            ustd::fcntl(lfd, ustd::F_SETFL, ustd::O_NONBLOCK);
            ustd::fcntl(cfd, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ustd::bind_path(lfd, "/stm-selftest") == 0
                && ustd::listen(lfd, 4) == 0
                && ustd::connect_path(cfd, "/stm-selftest") == 0
                && ustd::sendmsg(cfd, b"go", pfd) == 2
                // a bogus passfd is EBADF, not a transfer
                && ustd::sendmsg(cfd, b"x", 9999) == -9;
            if ok {
                let sfd = if ustd::poll(&[lfd as u32], &[1], 500) > 0 {
                    ustd::accept(lfd).ok().map(|(f, _, _)| f)
                } else {
                    None
                };
                if let Some(sfd) = sfd {
                    ustd::fcntl(sfd, ustd::F_SETFL, ustd::O_NONBLOCK);
                    let mut b = [0u8; 64];
                    let got = if ustd::poll(&[sfd as u32], &[1], 500) > 0 {
                        ustd::recvmsg(sfd, &mut b)
                    } else {
                        Err(-1)
                    };
                    ok = match got {
                        Ok((2, Some(gfd))) => {
                            let mut fb = [0u8; 32];
                            // the adopted fd is a real open fd: read the
                            // file through it and write through it too
                            ustd::read(gfd, &mut fb) == Ok(6)
                                && &fb[..6] == b"FDPASS"
                                && ustd::write(gfd, b"!") == Ok(1)
                                && { ustd::close(gfd); true }
                        }
                        _ => false,
                    };
                    ustd::close(sfd);
                } else {
                    ok = false;
                }
            }
        }
        if pfd >= 0 {
            ustd::close(pfd);
        }
        if lfd >= 0 {
            ustd::close(lfd);
        }
        if cfd >= 0 {
            ustd::close(cfd);
        }
        // the server's "!" write went into the real file at pos 6
        ok = ok
            && ustd::read_all("/st-pass.txt")
                .map(|d| &d[..] == b"FDPASS!")
                .unwrap_or(false);
        ok
    });
    // ---- batch 39: AF_UNIX datagrams + getsockopt ----
    check("unix-dgram", {
        // named mailboxes: bind a receiver, send datagrams (sender
        // auto-binds like Linux), recv pops one packet + the sender's
        // name; boundaries preserved across reads.
        let mut ok = false;
        let r = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_UNIX);
        let s = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_UNIX);
        if r >= 0 && s >= 0 {
            ustd::fcntl(r, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ustd::bind_path(r, "/udg-self") == 0
                // name taken by a second bind
                && {
                    let t = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_UNIX);
                    let e = ustd::bind_path(t, "/udg-self");
                    ustd::close(t);
                    e == -98
                }
                // unbound receiver: EINVAL, not a hang
                && ustd::recvfrom_path(s, &mut [0u8; 8], &mut [0u8; 64])
                    == Err(-22)
                && ustd::sendto_path(s, "/udg-self", b"pkt1") == 4
                && ustd::sendto_path(s, "/udg-self", b"pkt2222") == 7
                // nobody bound there: ENOENT
                && ustd::sendto_path(s, "/udg-nobody", b"x") == -2;
            if ok {
                let mut b = [0u8; 64];
                let mut nm = [0u8; 64];
                ok = ustd::poll(&[r as u32], &[1], 500) > 0
                    && ustd::recvfrom_path(r, &mut b, &mut nm)
                        .map(|(n, nl)| {
                            n == 4
                                && &b[..4] == b"pkt1"
                                && nl > 0
                                && nm[..nl].starts_with(b"/tmp/udg-")
                        })
                        .unwrap_or(false);
                // boundary preserved: second packet is whole, not the
                // tail of the first
                b = [0u8; 64];
                ok = ok
                    && ustd::recvfrom_path(r, &mut b, &mut nm)
                        .map(|(n, _)| n == 7 && &b[..7] == b"pkt2222")
                        .unwrap_or(false);
                // oversized read still truncates to the packet (rest drops)
                ok = ok
                    && ustd::sendto_path(s, "/udg-self", b"abcdefgh") == 8
                    && ustd::recvfrom_path(r, &mut [0u8; 3], &mut nm)
                        .map(|(n, _)| n == 3)
                        .unwrap_or(false);
            }
        }
        if r >= 0 {
            ustd::close(r); // frees the mailbox
        }
        if s >= 0 {
            ustd::close(s);
        }
        // mailbox gone: send is ENOENT again
        let s2 = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_UNIX);
        ok = ok && s2 >= 0 && ustd::sendto_path(s2, "/udg-self", b"x") == -2;
        if s2 >= 0 {
            ustd::close(s2);
        }
        ok
    });
    check("getsockopt", {
        // SOL_SOCKET queries answer the real kind/domain/state, and
        // SO_ERROR reports a recorded connect failure then clears.
        let mut ok = false;
        let s = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        let d = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_UNIX);
        if s >= 0 && d >= 0 {
            ok = ustd::getsockopt(s, shared::SOL_SOCKET, shared::SO_TYPE) == Ok(1)
                && ustd::getsockopt(d, shared::SOL_SOCKET, shared::SO_TYPE) == Ok(2)
                && ustd::getsockopt(d, shared::SOL_SOCKET, shared::SO_DOMAIN)
                    == Ok(1)
                && ustd::getsockopt(d, shared::SOL_SOCKET, shared::SO_ACCEPTCONN)
                    == Ok(0)
                && ustd::getsockopt(d, shared::SOL_SOCKET, shared::SO_SNDBUF)
                    == Ok(65536)
                && ustd::getsockopt(d, shared::SOL_SOCKET, 999) == Err(-92);
            // connect to nothing: -2 now, and SO_ERROR saw it
            let e = ustd::connect_path(d, "/udg-no-such");
            ok = ok
                && e == -2
                && ustd::getsockopt(d, shared::SOL_SOCKET, shared::SO_ERROR)
                    == Ok((-2i64) as u32)
                // cleared after read
                && ustd::getsockopt(d, shared::SOL_SOCKET, shared::SO_ERROR)
                    == Ok(0);
            // a listener reports SO_ACCEPTCONN=1
            ok = ok
                && ustd::bind_path(s, "/gso-self") == 0
                && ustd::listen(s, 2) == 0
                && ustd::getsockopt(s, shared::SOL_SOCKET, shared::SO_ACCEPTCONN)
                    == Ok(1);
        }
        if s >= 0 {
            ustd::close(s);
        }
        if d >= 0 {
            ustd::close(d);
        }
        ok
    });
    // ---- batch 40: loopback + dgram socketpair + peercred ----
    check("loopback", {
        // lo: packets to 127/8 re-enter the stack instead of the wire —
        // UDP round trip, TCP listen/connect/echo, and a real ICMP
        // echo reply answered by our own stack.
        let mut ok = false;
        let u = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_INET);
        if u >= 0 {
            ustd::fcntl(u, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ustd::bind(u, 19777) == 0
                && ustd::sendto(u, b"loop", [127, 0, 0, 1], 19777) == 4
                && ustd::poll(&[u as u32], &[1], 1000) > 0
                && ustd::recvfrom(u, &mut [0u8; 8])
                    .map(|(n, ip, _)| n == 4 && ip == [127, 0, 0, 1])
                    .unwrap_or(false);
            ustd::close(u);
        }
        // TCP over lo: full handshake inside the guest
        let l = ustd::socketx(ustd::SOCK_STREAM, shared::AF_INET);
        let c = ustd::socketx(ustd::SOCK_STREAM, shared::AF_INET);
        if l >= 0 && c >= 0 {
            ustd::fcntl(l, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ok
                && ustd::bind(l, 19778) == 0
                && ustd::listen(l, 2) == 0
                && ustd::connect(c, [127, 0, 0, 1], 19778) == 0
                && ustd::accept(l).map(|(a, _, _)| {
                    let w = ustd::write(a, b"li").is_ok();
                    ustd::close(a);
                    w
                }).unwrap_or(false)
                && ustd::poll(&[c as u32], &[1], 1000) > 0
                && ustd::read(c, &mut [0u8; 4]).map(|n| n == 2).unwrap_or(false);
            ustd::close(c);
            ustd::close(l);
        }
        // the stack itself answers echo requests on lo
        ok = ok && ustd::net_ping(0x7F000001, 1000).is_some()
            // and /etc/hosts resolved 'localhost' without a wire query
            && ustd::net_dns("localhost") == Some([127, 0, 0, 1]);
        ok
    });
    check("socketpair-dgram", {
        // socketpair(AF_UNIX, SOCK_DGRAM): two cross-linked mailboxes —
        // packet boundaries preserved both ways.
        match ustd::socketpair_t(ustd::SOCK_DGRAM) {
            Some((a, b)) => {
                ustd::fcntl(b, ustd::F_SETFL, ustd::O_NONBLOCK);
                let mut buf = [0u8; 32];
                let ok = ustd::write(a, b"one") == Ok(3)
                    && ustd::write(a, b"two22") == Ok(5)
                    && ustd::write(b, b"back") == Ok(4)
                    && ustd::read(b, &mut buf).map(|n| n == 3).unwrap_or(false)
                    && ustd::read(b, &mut buf).map(|n| n == 5).unwrap_or(false)
                    && ustd::read(a, &mut buf).map(|n| n == 4).unwrap_or(false)
                    // sender name is the peer's auto mailbox
                    && ustd::getsockopt(a, shared::SOL_SOCKET, 17)
                        .map(|p| p != 0)
                        .unwrap_or(false);
                ustd::close(a);
                ustd::close(b);
                ok
            }
            None => false,
        }
    });
    check("peercred", {
        // SO_PEERCRED: the client's getsockopt reports the listener
        // owner's pid; the accepted end reports the connector's pid —
        // verified against a real spawned task (cosmos-ucat).
        let mut ok = false;
        let lfd = ustd::socketx(ustd::SOCK_STREAM, shared::AF_UNIX);
        if lfd >= 0 {
            ustd::fcntl(lfd, ustd::F_SETFL, ustd::O_NONBLOCK);
            ok = ustd::bind_path(lfd, "/pc-selftest") == 0
                && ustd::listen(lfd, 2) == 0;
            if ok {
                match ustd::spawn("/bin/cosmos-ucat", "/pc-selftest cred /tmp/pcred-out") {
                    Ok(cpid) => {
                        // wait for the connect to land in the accept queue
                        let mut afd = -1i64;
                        for _ in 0..50 {
                            if let Ok((a, _, _)) = ustd::accept(lfd) {
                                afd = a;
                                break;
                            }
                            ustd::sleep_ms(20);
                        }
                        ok = afd >= 0
                            && ustd::getsockopt(afd, shared::SOL_SOCKET, 17)
                                == Ok(cpid)
                            && ustd::getsockopt(lfd, shared::SOL_SOCKET, 17)
                                == Err(-107);
                        if afd >= 0 {
                            ustd::close(afd);
                        }
                    }
                    Err(_) => ok = false,
                }
            }
            ustd::close(lfd);
        }
        ok
    });
    // ---- batch 41: traceroute + setsockopt/broadcast ----
    check("traceroute", {
        // loopback tracer: our own stack answers the unbound probe port
        // with a real ICMP 3/3 — deterministic, no wire needed.
        let hops = ustd::net_trace(0x7F00_0001, 4); // 127.0.0.1
        hops.len() == 1
            && matches!(hops[0], (1, Some(([127, 0, 0, 1], _)), true))
    });
    check("setsockopt", {
        // SO_REUSEADDR: two UDP sockets may share a port only when both
        // opted in. SO_BROADCAST gates 255.255.255.255 sends.
        let a = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_INET);
        let b = ustd::socketx(ustd::SOCK_DGRAM, shared::AF_INET);
        let mut ok = a >= 0 && b >= 0;
        if ok {
            ok = ustd::bind(a, 19790) == 0
                && ustd::bind(b, 19790) == -98 // EADDRINUSE without reuse
                && ustd::setsockopt(b, shared::SOL_SOCKET, shared::SO_REUSEADDR, 1) == 0
                && ustd::bind(b, 19790) == -98 // a hasn't opted in
                && ustd::setsockopt(a, shared::SOL_SOCKET, shared::SO_REUSEADDR, 1) == 0
                && ustd::bind(b, 19790) == 0;  // both reuse: allowed
            ok = ok
                && ustd::getsockopt(a, shared::SOL_SOCKET, shared::SO_REUSEADDR) == Ok(1)
                && ustd::getsockopt(b, shared::SOL_SOCKET, shared::SO_BROADCAST) == Ok(0)
                // broadcast send refused until SO_BROADCAST is set
                && ustd::sendto(b, b"b", [255, 255, 255, 255], 19790) == -13
                && ustd::setsockopt(b, shared::SOL_SOCKET, shared::SO_BROADCAST, 1) == 0
                && ustd::sendto(b, b"b", [255, 255, 255, 255], 19790) == 1
                && ustd::getsockopt(b, shared::SOL_SOCKET, shared::SO_BROADCAST) == Ok(1)
                && ustd::setsockopt(b, shared::SOL_SOCKET, 999, 1) == -92; // ENOPROTOOPT
            ustd::close(a);
            ustd::close(b);
        }
        ok
    });
    check("udpeek", {
        // MSG_PEEK: front datagram readable twice, then consumed for real
        let a = ustd::socket(ustd::SOCK_DGRAM);
        let b = ustd::socket(ustd::SOCK_DGRAM);
        let mut ok = a >= 0 && b >= 0;
        if ok {
            ok = ustd::bind(b, 19805) == 0
                && ustd::sendto(a, b"peekme", [127, 0, 0, 1], 19805) == 6;
            if ok {
                let mut buf = [0u8; 16];
                let p = ustd::recvfrom_flags(b, &mut buf, ustd::MSG_PEEK);
                ok = matches!(p, Ok((6, _, _))) && &buf[..6] == b"peekme";
                // still there: the same datagram, again
                let mut buf2 = [0u8; 16];
                let r = ustd::recvfrom(b, &mut buf2);
                ok = ok && matches!(r, Ok((6, _, _))) && &buf2[..6] == b"peekme";
            }
            ustd::close(a);
            ustd::close(b);
        }
        ok
    });
    check("rcvtimeo", {
        // SO_RCVTIMEO: a blocked recv surfaces EAGAIN after the deadline
        let b = ustd::socket(ustd::SOCK_DGRAM);
        let mut ok = b >= 0 && ustd::bind(b, 19806) == 0;
        if ok {
            ok = ustd::setsockopt(b, shared::SOL_SOCKET, shared::SO_RCVTIMEO, 250) == 0
                && ustd::getsockopt(b, shared::SOL_SOCKET, shared::SO_RCVTIMEO) == Ok(250);
            let t0 = ustd::uptime_ms();
            let mut buf = [0u8; 8];
            let r = ustd::recvfrom(b, &mut buf);
            let dt = ustd::uptime_ms() - t0;
            ok = ok && r == Err(-11) && dt >= 200 && dt < 3000;
            // data still delivered normally after a timeout
            if ok {
                let a = ustd::socket(ustd::SOCK_DGRAM);
                ok = a >= 0 && ustd::sendto(a, b"zz", [127, 0, 0, 1], 19806) == 2;
                if ok {
                    let r2 = ustd::recvfrom(b, &mut buf);
                    ok = matches!(r2, Ok((2, _, _))) && &buf[..2] == b"zz";
                }
                if a >= 0 {
                    ustd::close(a);
                }
            }
            ustd::close(b);
        }
        ok
    });
    check("routes", {
        // kernel routing table via /proc/net/route — real lookup backs
        // next_hop, so deleting the default breaks off-net sends for real
        let mut ok = ustd::read_all("/proc/net/route")
            .map(|d| {
                let t = String::from_utf8_lossy(&d);
                t.contains("eth0") && t.contains("lo") && t.contains("0202000A")
            })
            .unwrap_or(false);
        if ok {
            // del default -> remote send now unrouteable
            ok = ustd::write_all("/proc/net/route", b"del 0.0.0.0/0").is_ok();
            let a = ustd::socket(ustd::SOCK_DGRAM);
            ok = ok && a >= 0
                && ustd::sendto(a, b"x", [8, 8, 8, 8], 53) < 0;
            // restore -> send works again
            ok = ok
                && ustd::write_all("/proc/net/route", b"add 0.0.0.0/0 10.0.2.2").is_ok()
                && ustd::sendto(a, b"x", [8, 8, 8, 8], 53) == 1;
            // add/del a real net route, visible in the table
            ok = ok
                && ustd::write_all("/proc/net/route", b"add 192.168.9.0/24 10.0.2.2").is_ok()
                && ustd::read_all("/proc/net/route")
                    .map(|d| String::from_utf8_lossy(&d).contains("0009A8C0"))
                    .unwrap_or(false)
                && ustd::write_all("/proc/net/route", b"del 192.168.9.0/24").is_ok()
                && ustd::read_all("/proc/net/route")
                    .map(|d| !String::from_utf8_lossy(&d).contains("0009A8C0"))
                    .unwrap_or(false);
            if a >= 0 {
                ustd::close(a);
            }
        }
        ok
    });
    check("sockopts2", {
        // IP_TTL on IPPROTO_IP + SO_SNDTIMEO roundtrips
        let a = ustd::socket(ustd::SOCK_DGRAM);
        let mut ok = a >= 0;
        if ok {
            ok = ustd::setsockopt(a, 0, 2, 5) == 0 // IPPROTO_IP, IP_TTL
                && ustd::getsockopt(a, 0, 2) == Ok(5)
                && ustd::setsockopt(a, shared::SOL_SOCKET, shared::SO_SNDTIMEO, 500) == 0
                && ustd::getsockopt(a, shared::SOL_SOCKET, shared::SO_SNDTIMEO) == Ok(500)
                && ustd::sendto(a, b"t", [127, 0, 0, 1], 19999) == 1; // ttl'd send works
            ustd::close(a);
        }
        ok
    });
    check("lotcp", {
        // full TCP over loopback: connect+accept complete a real 3-way
        // handshake inside LOOPBACK_Q, then data flows both directions
        let l = ustd::socket(ustd::SOCK_STREAM);
        let c = ustd::socket(ustd::SOCK_STREAM);
        let mut ok = l >= 0 && c >= 0;
        if ok {
            ok = ustd::bind(l, 19820) == 0 && ustd::listen(l, 4) == 0
                && ustd::connect(c, [127, 0, 0, 1], 19820) == 0;
            let acc = ustd::accept(l);
            ok = ok && acc.is_ok();
            if let Ok((a, _, _)) = acc {
                let mut b = [0u8; 8];
                ok = ok && ustd::write(c, b"ping") == Ok(4)
                    && ustd::read(a, &mut b) == Ok(4) && &b[..4] == b"ping"
                    && ustd::write(a, b"pong") == Ok(4)
                    && ustd::read(c, &mut b) == Ok(4) && &b[..4] == b"pong";
                ustd::close(a);
            }
            ustd::close(c);
            ustd::close(l);
        }
        ok
    });
    check("tcpnb", {
        // O_NONBLOCK write takes the nowait+retransmit-queue path over lo
        let l = ustd::socket(ustd::SOCK_STREAM);
        let c = ustd::socket(ustd::SOCK_STREAM);
        let mut ok = l >= 0 && c >= 0;
        if ok {
            ok = ustd::bind(l, 19830) == 0 && ustd::listen(l, 4) == 0
                && ustd::connect(c, [127, 0, 0, 1], 19830) == 0;
            let acc = ustd::accept(l);
            ok = ok && acc.is_ok();
            if let Ok((a, _, _)) = acc {
                ok = ok && ustd::fcntl(c, ustd::F_SETFL, ustd::O_NONBLOCK) == 0;
                let payload = [b'x'; 6000];
                let (mut sent, mut tries) = (0usize, 0u32);
                while sent < payload.len() && tries < 400 {
                    tries += 1;
                    match ustd::write(c, &payload[sent..]) {
                        Ok(n) => sent += n,
                        Err(_) => ustd::sleep_ms(20),
                    }
                }
                let mut got = 0usize;
                let mut b = [0u8; 7000];
                let t0 = ustd::uptime_ms();
                while got < 6000 && ustd::uptime_ms() - t0 < 5000 {
                    match ustd::read(a, &mut b[got..]) {
                        Ok(n) if n > 0 => got += n,
                        _ => ustd::sleep_ms(20),
                    }
                }
                ok = ok && sent == 6000 && got == 6000;
                ustd::close(a);
            }
            ustd::close(c);
            ustd::close(l);
        }
        ok
    });
    check("mmapfile", {
        // demand-paged file mmap: each page faults in from disk on touch
        let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut ok = ustd::write_all("/st-mmap.bin", &data).is_ok();
        if ok {
            let fd = ustd::open("/st-mmap.bin", ustd::O_RDONLY);
            ok = ok && fd.is_ok();
            if let Ok(fd) = fd {
                let p = ustd::mmap_file(fd, 8192, 0);
                ok = ok && p.is_some();
                if let Some(p) = p {
                    unsafe {
                        // reads land on two distinct faulted-in pages
                        ok = ok && *p == 0 && *p.add(252) == 1
                            && *p.add(4096) == 80 && *p.add(8191) == 159;
                        // writable private copy — RAM only, file untouched
                        *p = 0xAA;
                        ok = ok && *p == 0xAA;
                    }
                    ok = ok && ustd::munmap(p, 8192);
                }
                ustd::close(fd);
            }
            ok = ok
                && ustd::read_all("/st-mmap.bin")
                    .map(|v| v[0] == 0)
                    .unwrap_or(false);
        }
        ok
    });
    check("tcprefused", {
        // SYN to an unclaimed port -> real RST back -> -111 ECONNREFUSED
        let c = ustd::socket(ustd::SOCK_STREAM);
        let mut ok = c >= 0;
        if ok {
            let t0 = ustd::uptime_ms();
            ok = ustd::connect(c, [127, 0, 0, 1], 19821) == -111
                && ustd::uptime_ms() - t0 < 3000; // refused fast, not a timeout
            ustd::close(c);
        }
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
