//! selftest: scripted end-to-end checks exercising every kernel subsystem.
//! Prints "[selftest] PASS <name>" / "[selftest] FAIL <name>" lines on serial;
//! finishes with "[selftest] DONE ok=<n> fail=<m>" so the host smoke test can
//! score the run without a GUI.
#![no_std]
#![no_main]

extern crate alloc;
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
    } else {
        check("net-mac", false);
        check("net-ip", false);
        check("ping-gw", false);
        check("dns-resolve", false);
        check("http-example", false);
        check("udp-socket", false);
        check("tcp-socket", false);
    }

    let (pass, fail) = unsafe { (PASS, FAIL) };
    println!("[selftest] DONE ok={} fail={}", pass, fail);
    fail as i64
}
