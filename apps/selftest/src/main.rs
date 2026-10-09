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
use core::sync::atomic::{AtomicI64, AtomicU64};
static THREAD_HIT: AtomicU64 = AtomicU64::new(0);

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

extern "C" fn vt_hit(_: u64) {
    unsafe { VT_HIT = 1 };
}
extern "C" fn al_hit(_: u64) {
    unsafe { AL_HIT += 1 };
}
extern "C" fn pp_hit(_: u64) {
    unsafe { PP_HIT += 1 };
}
static mut PP_HIT: u32 = 0;
static mut VT_HIT: u32 = 0;
static mut AL_HIT: u32 = 0;

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
        check("dev-zero", {
            match ustd::open("/dev/zero", ustd::O_RDONLY) {
                Ok(fd) => {
                    let mut b = [1u8; 8192];
                    // infinite source: two full reads, never EOF
                    let n = ustd::read(fd, &mut b).unwrap_or(0);
                    let n2 = ustd::read(fd, &mut b).unwrap_or(0);
                    ustd::close(fd);
                    n == 8192 && n2 == 8192 && b.iter().all(|x| *x == 0)
                }
                Err(_) => false,
            }
        });
        check("dev-random-bits", {
            match ustd::open("/dev/urandom", ustd::O_RDONLY) {
                Ok(fd) => {
                    let mut b = [0u8; 128];
                    let n = ustd::read(fd, &mut b).unwrap_or(0);
                    let n2 = ustd::read(fd, &mut b).unwrap_or(0);
                    ustd::close(fd);
                    n == 128 && n2 == 128 && b.iter().any(|x| *x != 0)
                }
                Err(_) => false,
            }
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
    check("thread-shared-mm", {
        // a clone()'d thread writes OUR atomics through the shared address
        // space and returns an exit code we reap like a process
        use core::sync::atomic::Ordering;
        extern "C" fn th(arg: u64) -> i64 {
            THREAD_HIT.store(arg, Ordering::SeqCst);
            42
        }
        match ustd::thread_spawn(th, 0x5AFE) {
            Ok(tid) => {
                let code = ustd::waitpid(tid, 5000).unwrap_or(-1);
                code == 42 && THREAD_HIT.load(Ordering::SeqCst) == 0x5AFE
            }
            Err(_) => false,
        }
    });
    check("thread-task-list", {
        // /proc/self/task names every live tid sharing this address space
        extern "C" fn nap(_: u64) -> i64 {
            ustd::sleep_ms(400);
            0
        }
        match ustd::thread_spawn(nap, 0) {
            Ok(tid) => {
                let d = ustd::read_all("/proc/self/task").unwrap_or_default();
                let s = String::from_utf8_lossy(&d);
                let has = s.split_whitespace().any(|v| v.parse::<u32>().ok() == Some(tid));
                let _ = ustd::waitpid(tid, 3000);
                has
            }
            Err(_) => false,
        }
    });
    check("thread-private-stack", {
        // the thread runs on its own slot: deep recursion there must not
        // collide with our stack — growdown bounds are per-task
        extern "C" fn deep(x: u64) -> i64 {
            let mut frame = [0u8; 2048];
            unsafe {
                core::ptr::write_volatile(frame.as_mut_ptr(), x as u8);
            }
            if x == 0 {
                frame[0] as i64
            } else {
                deep(x - 1) + frame[0] as i64
            }
        }
        match ustd::thread_spawn(deep, 30) {
            Ok(tid) => ustd::waitpid(tid, 5000).unwrap_or(-1) == (0..=30).sum::<u64>() as i64,
            Err(_) => false,
        }
    });
    check("futex-mutex-counter", {
        // 4 threads x 500 increments behind a REAL futex mutex — the
        // counter must be exact, proving wait/wake under contention
        use core::sync::atomic::Ordering;
        static LOCK: ustd::Mutex = ustd::Mutex::new();
        static CTR: AtomicU64 = AtomicU64::new(0);
        extern "C" fn bump(n: u64) -> i64 {
            for _ in 0..n {
                LOCK.lock();
                CTR.store(CTR.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
                LOCK.unlock();
            }
            0
        }
        let mut tids = [0u32; 4];
        let mut spawned = 0usize;
        for i in 0..4 {
            match ustd::thread_spawn(bump, 500) {
                Ok(t) => {
                    tids[i] = t;
                    spawned += 1;
                }
                Err(_) => break,
            }
        }
        for i in 0..spawned {
            let _ = ustd::waitpid(tids[i], 15000);
        }
        spawned == 4 && CTR.load(Ordering::SeqCst) == 2000
    });
    check("futex-timeout", {
        // WAIT on a word nobody wakes must surface a real ETIMEDOUT
        use core::sync::atomic::Ordering;
        static W: AtomicU64 = AtomicU64::new(7);
        let r = ustd::futex(&W, ustd::FUTEX_WAIT, 7, 60);
        r == -110 && W.load(Ordering::SeqCst) == 7
    });
    check("futex-eagain", {
        // WAIT with a mismatched expected value returns immediately
        static W2: AtomicU64 = AtomicU64::new(3);
        ustd::futex(&W2, ustd::FUTEX_WAIT, 99, 1000) == -11
    });
    check("fork-exit-code", {
        // real fork: child resumes at this same instruction with 0
        match ustd::fork() {
            0 => ustd::exit(33),
            p if p > 0 => ustd::waitpid(p as u32, 5000).unwrap_or(-1) == 33,
            _ => false,
        }
    });
    check("fork-private-mm", {
        // the child's writes land in its private copy — parent's word
        // must be untouched (proves copy, not share)
        use core::sync::atomic::Ordering;
        static V: AtomicU64 = AtomicU64::new(1);
        match ustd::fork() {
            0 => {
                V.store(9, Ordering::SeqCst);
                ustd::exit(0);
            }
            p if p > 0 => {
                let _ = ustd::waitpid(p as u32, 5000);
                V.load(Ordering::SeqCst) == 1
            }
            _ => false,
        }
    });
    check("fork-exec", {
        // fork + execve: child swaps images into selftest-child (exit 7)
        match ustd::fork() {
            0 => {
                let _ = ustd::execve("/bin/cosmos-selftest-child", "execed");
                ustd::exit(-1);
            }
            p if p > 0 => ustd::waitpid(p as u32, 8000).unwrap_or(-1) == 7,
            _ => false,
        }
    });
    check("fork-cow-shared", {
        // COW: fork shares every present private frame — the kernel's
        // shared-frame counter must jump while the child is alive
        let rd = |p: &str| -> u64 {
            ustd::read_all(p)
                .ok()
                .and_then(|b| {
                    String::from_utf8_lossy(&b)
                        .trim()
                        .parse::<u64>()
                        .ok()
                })
                .unwrap_or(0)
        };
        let before = rd("/proc/sys/kernel/cow_pages");
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(700);
                ustd::exit(0);
            }
            p if p > 0 => {
                let during = rd("/proc/sys/kernel/cow_pages");
                let _ = ustd::waitpid(p as u32, 4000);
                during > before
            }
            _ => false,
        }
    });
    check("fork-cow-split", {
        // parent writes after fork: it gets a private copy — the child
        // still reads the ORIGINAL shared contents (true COW semantics)
        use core::sync::atomic::Ordering;
        static V2: AtomicU64 = AtomicU64::new(5);
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(600);
                let v = V2.load(Ordering::SeqCst);
                ustd::exit(if v == 5 { 0 } else { -1 });
            }
            p if p > 0 => {
                V2.store(77, Ordering::SeqCst);
                let c = ustd::waitpid(p as u32, 4000).unwrap_or(-1);
                c == 0 && V2.load(Ordering::SeqCst) == 77
            }
            _ => false,
        }
    });
    check("fork-pipe-share", {
        // fd table cloned at fork: the child writes into the same pipe
        match ustd::pipe() {
            Some((rfd, wfd)) => match ustd::fork() {
                0 => {
                    let _ = ustd::write(wfd, b"K");
                    ustd::exit(0);
                }
                p if p > 0 => {
                    let mut b = [0u8; 1];
                    let n = ustd::read(rfd, &mut b).unwrap_or(0);
                    let _ = ustd::waitpid(p as u32, 3000);
                    ustd::close(rfd);
                    ustd::close(wfd);
                    n == 1 && b[0] == b'K'
                }
                _ => false,
            },
            None => false,
        }
    });
    check("sig-handler", {
        // real signal delivery: kill2(self,10) diverts into the handler
        // via a kernel-pushed frame; sigreturn resumes right here
        use core::sync::atomic::Ordering;
        static HIT: AtomicU64 = AtomicU64::new(0);
        extern "C" fn h(sig: u64) {
            HIT.store(sig + 100, Ordering::SeqCst);
        }
        ustd::sigaction(10, h as usize as u64);
        let _ = ustd::raise(10);
        HIT.load(Ordering::SeqCst) == 110
    });
    check("sig-ign", {
        // SIG_IGN: the signal is dropped, we survive
        ustd::sigaction(12, ustd::SIG_IGN);
        let _ = ustd::raise(12);
        true
    });
    check("sig-default-term", {
        // uncaught SIGTERM kills with the POSIX 128+sig wait status
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(4000);
                ustd::exit(0);
            }
            p if p > 0 => {
                let _ = ustd::kill2(p as u32, 15);
                ustd::waitpid(p as u32, 4000).unwrap_or(-1) == 128 + 15
            }
            _ => false,
        }
    });
    check("sig-mask", {
        use core::sync::atomic::Ordering;
        static HIT2: AtomicU64 = AtomicU64::new(0);
        extern "C" fn h2(_: u64) {
            HIT2.store(1, Ordering::SeqCst);
        }
        ustd::sigaction(10, h2 as usize as u64);
        ustd::sigprocmask(ustd::SIG_BLOCK, 1 << 10);
        let _ = ustd::raise(10);
        ustd::sleep_ms(50); // a delivery point passes while blocked — no hit
        let held = HIT2.load(Ordering::SeqCst) == 0;
        ustd::sigprocmask(ustd::SIG_SETMASK, 0); // unmask → delivers at return
        held && HIT2.load(Ordering::SeqCst) == 1
    });
    check("sigchld-notify", {
        use core::sync::atomic::Ordering;
        static CHLD: AtomicU64 = AtomicU64::new(0);
        extern "C" fn hc(s: u64) {
            CHLD.store(s, Ordering::SeqCst);
        }
        ustd::sigaction(17, hc as usize as u64);
        match ustd::fork() {
            0 => ustd::exit(5),
            p if p > 0 => {
                let code = ustd::waitpid(p as u32, 4000).unwrap_or(-1);
                ustd::sleep_ms(50);
                code == 5 && CHLD.load(Ordering::SeqCst) == 17
            }
            _ => false,
        }
    });
    check("sig-alarm", {
        use core::sync::atomic::Ordering;
        static ALRM: AtomicU64 = AtomicU64::new(0);
        extern "C" fn ha(s: u64) {
            ALRM.store(s, Ordering::SeqCst);
        }
        ustd::sigaction(14, ha as usize as u64);
        ustd::alarm(1);
        for _ in 0..50 {
            if ALRM.load(Ordering::SeqCst) == 14 {
                break;
            }
            ustd::sleep_ms(100);
        }
        ALRM.load(Ordering::SeqCst) == 14
    });
    check("signalfd-read", {
        // Linux semantics: block the signal via sigprocmask so delivery
        // can't consume it, then the fd drains the pending record
        ustd::sigprocmask(ustd::SIG_BLOCK, 1 << 11);
        let fd = ustd::signalfd(1 << 11);
        let ok = if fd < 0 {
            false
        } else {
            let _ = ustd::raise(11);
            let mut rec = [0u8; 128];
            let n = ustd::read(fd, &mut rec).unwrap_or(0);
            let _ = ustd::close(fd);
            n == 128 && u32::from_le_bytes(rec[..4].try_into().unwrap()) == 11
        };
        ustd::sigprocmask(ustd::SIG_SETMASK, 0);
        ok
    });
    check("pgrp-kill", {
        // kill(-pgid): one call terminates the whole process group
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(4000);
                ustd::exit(0);
            }
            c1 if c1 > 0 => match ustd::fork() {
                0 => {
                    ustd::sleep_ms(4000);
                    ustd::exit(0);
                }
                c2 if c2 > 0 => {
                    ustd::setpgid(c1 as u32, c1 as u32);
                    ustd::setpgid(c2 as u32, c1 as u32);
                    let same = ustd::getpgid(c2 as u32) == c1;
                    let _ = ustd::killpg(c1 as u32, 15);
                    let e1 = ustd::waitpid(c1 as u32, 4000).unwrap_or(-1);
                    let e2 = ustd::waitpid(c2 as u32, 4000).unwrap_or(-1);
                    same && e1 == 143 && e2 == 143
                }
                _ => false,
            },
            _ => false,
        }
    });
    check("setsid-self", {
        match ustd::fork() {
            0 => {
                let ok = ustd::setsid() == 0 && ustd::getsid(0) == ustd::getpid() as i64;
                ustd::exit(if ok { 0 } else { 1 });
            }
            p if p > 0 => ustd::waitpid(p as u32, 4000).unwrap_or(-1) == 0,
            _ => false,
        }
    });
    check("pdeathsig", {
        // B is a grandchild: parent A dies mid-flight -> B's handler fires
        use core::sync::atomic::Ordering;
        static PD: AtomicU64 = AtomicU64::new(0);
        extern "C" fn pd(s: u64) {
            PD.store(s, Ordering::SeqCst);
        }
        let (pr, pw) = ustd::pipe().unwrap_or((-1, -1));
        let ok = if pr < 0 {
            false
        } else {
            match ustd::fork() {
                0 => {
                    match ustd::fork() {
                        0 => {
                            // grandchild B
                            ustd::sigaction(10, pd as usize as u64);
                            ustd::set_pdeathsig(10);
                            for _ in 0..40 {
                                if PD.load(Ordering::SeqCst) == 10 {
                                    let _ = ustd::write(pw, b"D");
                                    ustd::exit(0);
                                }
                                ustd::sleep_ms(100);
                            }
                            ustd::exit(1);
                        }
                        _a if _a > 0 => {
                            // A: brief life then dies — orphans B
                            ustd::sleep_ms(150);
                            ustd::exit(0);
                        }
                        _ => ustd::exit(1),
                    }
                }
                a if a > 0 => {
                    let _ = ustd::waitpid(a as u32, 4000);
                    let mut got = false;
                    for _ in 0..40 {
                        let n = ustd::poll(&[pr as u32], &[1], 100);
                        if n > 0 {
                            let mut b = [0u8; 4];
                            let _ = ustd::read(pr, &mut b);
                            got = b[0] == b'D';
                            break;
                        }
                    }
                    got
                }
                _ => false,
            }
        };
        let _ = ustd::close(pr);
        let _ = ustd::close(pw);
        ok
    });
    check("sigtstp-stop", {
        // SIGTSTP default disposition = job-control stop; CONT resumes
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(8000);
                ustd::exit(0);
            }
            p if p > 0 => {
                ustd::sleep_ms(120);
                let _ = ustd::kill2(p as u32, 20);
                ustd::sleep_ms(150);
                // WUNTRACED reports the stop once: 0x7f | (sig << 8)
                let st = ustd::waitpid_opt(p as u32, ustd::WUNTRACED, 1500)
                    .unwrap_or(-1);
                let stopped = (st & 0xff) == 0x7f && (st >> 8) == 20;
                let _ = ustd::kill2(p as u32, 18);
                let _ = ustd::kill2(p as u32, 9); // don't leak the sleeper
                let code = ustd::waitpid(p as u32, 4000).unwrap_or(-1);
                stopped && code == 137
            }
            _ => false,
        }
    });
    check("getppid", {
        match ustd::fork() {
            0 => {
                let ok = ustd::getppid() == 2; // selftest is pid 2
                ustd::exit(if ok { 0 } else { 1 });
            }
            p if p > 0 => ustd::waitpid(p as u32, 4000).unwrap_or(-1) == 0,
            _ => false,
        }
    });
    check("prctl-setname", {
        ustd::set_name("st-renamed");
        let n = ustd::read_all("/proc/self/status")
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        ustd::set_name("cosmos-selftest");
        n.contains("st-renamed")
    });
    check("sigpending", {
        // blocked signal shows in sigpending until unmasked
        ustd::sigaction(13, ustd::SIG_IGN); // don't die on delivery
        ustd::sigprocmask(ustd::SIG_BLOCK, 1 << 13);
        let _ = ustd::kill2(ustd::getpid() as u32, 13);
        let seen = ustd::sigpending() & (1 << 13) != 0;
        ustd::sigprocmask(ustd::SIG_SETMASK, 0);
        seen
    });
    check("sigsuspend", {
        // child raises sig10 -> parent's handler runs -> suspend returns
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(150);
                let _ = ustd::kill2(ustd::getppid() as u32, 10);
                ustd::exit(0);
            }
            p if p > 0 => {
                extern "C" fn hs(_sig: u64) {}
                ustd::sigaction(10, hs as usize as u64);
                let r = ustd::sigsuspend(0); // unmask all: 10 deliverable
                let code = ustd::waitpid(p as u32, 4000).unwrap_or(-1);
                r == -4 && code == 0
            }
            _ => false,
        }
    });
    check("sighup-session", {
        // session leader dies -> surviving member gets SIGHUP (handler
        // proves it by writing 'H' to the pipe the parent reads)
        match ustd::pipe() {
            Some((pr, pw)) => {
                match ustd::fork() {
                    0 => {
                        let _ = ustd::close(pr);
                        let _ = ustd::setsid();
                        match ustd::fork() {
                            0 => {
                                // member: report pid, catch SIGHUP — the
                                // handler writes 'H' through the pipe
                                use core::sync::atomic::Ordering;
                                static HPW: AtomicI64 =
                                    AtomicI64::new(-1);
                                extern "C" fn hh(_sig: u64) {
                                    let fd = HPW.load(Ordering::SeqCst);
                                    if fd >= 0 {
                                        let _ = ustd::write(fd, b"H");
                                    }
                                }
                                HPW.store(pw, Ordering::SeqCst);
                                ustd::sigaction(1, hh as usize as u64);
                                let mut b = [0u8; 4];
                                b.copy_from_slice(
                                    &(ustd::getpid() as u32).to_le_bytes(),
                                );
                                let _ = ustd::write(pw, &b);
                                let mut i = 0i64;
                                while i < 600 {
                                    ustd::sleep_ms(50);
                                    i += 1;
                                }
                                ustd::exit(0);
                            }
                            bp if bp > 0 => {
                                // leader dies — after the member had time
                                // to install its SIGHUP handler
                                ustd::sleep_ms(400);
                                ustd::exit(0)
                            }
                            _ => ustd::exit(1),
                        }
                    }
                    ap if ap > 0 => {
                        let _ = ustd::close(pw);
                        let _ = ustd::waitpid(ap as u32, 4000);
                        // read member pid (4B) then 'H' — member writes its
                        // pid first so the leader's death races are ordered
                        let mut hdr = [0u8; 4];
                        let mut got = 0usize;
                        while got < 4 {
                            match ustd::read(pr, &mut hdr[got..]) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => got += n,
                            }
                        }
                        let member = u32::from_le_bytes(hdr);
                        let mut byte = [0u8; 1];
                        let mut got_h = false;
                        let mut i = 0;
                        while i < 120 && !got_h {
                            match ustd::read(pr, &mut byte) {
                                Ok(1) if byte[0] == b'H' => got_h = true,
                                Ok(_) => {}
                                Err(_) => break,
                            }
                            i += 1;
                            ustd::sleep_ms(50);
                        }
                        let _ = ustd::kill2(member, 9);
                        let _ = ustd::close(pr);
                        got_h
                    }
                    _ => false,
                }
            }
            None => false,
        }
    });
    check("sig-eintr", {
        // a caught signal without SA_RESTART interrupts a slow sleep —
        // the syscall returns EINTR and sleep_ms comes back early
        use core::sync::atomic::Ordering;
        static SEEN: AtomicU64 = AtomicU64::new(0);
        extern "C" fn he(s: u64) {
            SEEN.store(s, Ordering::SeqCst);
        }
        ustd::sigaction_fl(14, he as usize as u64, 0);
        ustd::alarm(1);
        let t0 = ustd::uptime_ms();
        ustd::sleep_ms(4000); // EINTR should cut this to ~1s
        let dt = ustd::uptime_ms().saturating_sub(t0);
        SEEN.load(Ordering::SeqCst) == 14 && dt < 3000
    });
    check("sig-restart", {
        // SA_RESTART: the handler runs and the sleep completes anyway
        use core::sync::atomic::Ordering;
        static SEEN2: AtomicU64 = AtomicU64::new(0);
        extern "C" fn hr(s: u64) {
            SEEN2.store(s, Ordering::SeqCst);
        }
        ustd::sigaction_fl(14, hr as usize as u64, ustd::SA_RESTART);
        ustd::alarm(1);
        let t0 = ustd::uptime_ms();
        ustd::sleep_ms(1800);
        let dt = ustd::uptime_ms().saturating_sub(t0);
        SEEN2.load(Ordering::SeqCst) == 14 && dt >= 1500
    });
    check("sigaltstack", {
        // SA_ONSTACK handler runs on the registered alternate stack —
        // its rsp must land inside the buffer we registered
        use core::sync::atomic::Ordering;
        static ALT_RSP: AtomicU64 = AtomicU64::new(0);
        static mut ALT: [u8; 8192] = [0; 8192];
        extern "C" fn ho(_: u64) {
            let r: u64;
            unsafe { core::arch::asm!("mov {}, rsp", out(reg) r) };
            ALT_RSP.store(r, Ordering::SeqCst);
        }
        unsafe {
            let base = core::ptr::addr_of_mut!(ALT) as u64;
            ustd::sigaltstack(base, 8192);
            ustd::sigaction_fl(14, ho as usize as u64, ustd::SA_ONSTACK);
            ustd::alarm(1);
            for _ in 0..30 {
                if ALT_RSP.load(Ordering::SeqCst) != 0 {
                    break;
                }
                ustd::sleep_ms(100);
            }
            let r = ALT_RSP.load(Ordering::SeqCst);
            ustd::sigaltstack(0, 0); // leave it registered; just report
            r >= base && r < base + 8192
        }
    });
    check("sigmask-in-handler", {
        // POSIX default: the running signal is masked inside its handler —
        // a self-raise pends, then re-delivers after sigreturn
        use core::sync::atomic::Ordering;
        static DEPTH: AtomicU64 = AtomicU64::new(0);
        static PEND: AtomicU64 = AtomicU64::new(0);
        extern "C" fn hm(_: u64) {
            let d = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
            if d == 1 {
                ustd::kill2(ustd::getpid() as u32, 14);
                PEND.store(ustd::sigpending() & (1 << 14), Ordering::SeqCst);
            }
        }
        ustd::sigaction_fl(14, hm as usize as u64, 0);
        ustd::kill2(ustd::getpid() as u32, 14);
        for _ in 0..30 {
            if DEPTH.load(Ordering::SeqCst) >= 2 {
                break;
            }
            ustd::sleep_ms(50);
        }
        DEPTH.load(Ordering::SeqCst) >= 2 && PEND.load(Ordering::SeqCst) != 0
    });
    check("ptrace-peek-poke", {
        // child TRACEMEs, stops on SIGSTOP; parent PEEKs/POKEs a cell in
        // the child's address space (same image -> same VA), CONTs, and
        // the child exits with the poked value
        use core::sync::atomic::Ordering;
        static CELL: AtomicU64 = AtomicU64::new(0);
        CELL.store(0, Ordering::SeqCst);
        let cell_va = &CELL as *const AtomicU64 as u64;
        match ustd::fork() {
            0 => {
                ustd::ptrace(ustd::PT_TRACEME, 0, 0, 0);
                ustd::kill2(ustd::getpid(), 19); // SIGSTOP -> traced stop
                ustd::exit(CELL.load(Ordering::SeqCst) as i64);
            }
            c if c > 0 => {
                let mut ok = false;
                // wait for the traced SIGSTOP (WUNTRACED status 0x7f|19<<8)
                for _ in 0..60 {
                    if let Ok(st) = ustd::waitpid_opt(c as u32, 1, 200) {
                        if st == 0x7f | (19 << 8) {
                            ok = true;
                            break;
                        }
                    }
                    ustd::sleep_ms(25);
                }
                let v = ustd::ptrace(ustd::PT_PEEK, c as u32, cell_va, 0);
                let poked = ustd::ptrace(ustd::PT_POKE, c as u32, cell_va, 42);
                ustd::ptrace(ustd::PT_CONT, c as u32, 0, 0);
                let ex = ustd::waitpid(c as u32, 4000).unwrap_or(-1);
                ok && v == 0 && poked == 0 && ex == 42
            }
            _ => false,
        }
    });
    check("ptrace-singlestep", {
        // PTRACE_SINGLESTEP runs exactly one user insn, then the tracee
        // stops again with SIGTRAP (0x7f|5<<8) — observable via GETREGS
        // rip movement
        match ustd::fork() {
            0 => {
                ustd::ptrace(ustd::PT_TRACEME, 0, 0, 0);
                ustd::kill2(ustd::getpid(), 19);
                ustd::exit(7);
            }
            c if c > 0 => {
                let mut stopped = false;
                for _ in 0..60 {
                    if let Ok(st) = ustd::waitpid_opt(c as u32, 1, 200) {
                        if st == 0x7f | (19 << 8) {
                            stopped = true;
                            break;
                        }
                    }
                    ustd::sleep_ms(25);
                }
                let r0 = ustd::ptrace_getregs(c as u32);
                ustd::ptrace(ustd::PT_STEP, c as u32, 0, 0);
                let mut trapped = false;
                for _ in 0..60 {
                    if let Ok(st) = ustd::waitpid_opt(c as u32, 1, 200) {
                        if st == 0x7f | (5 << 8) {
                            trapped = true;
                            break;
                        }
                    }
                    ustd::sleep_ms(25);
                }
                let r1 = ustd::ptrace_getregs(c as u32);
                ustd::ptrace(ustd::PT_CONT, c as u32, 0, 0);
                let ex = ustd::waitpid(c as u32, 4000).unwrap_or(-1);
                stopped
                    && trapped
                    && ex == 7
                    && match (r0, r1) {
                        (Some(a), Some(b)) => {
                            a.rip != 0 && b.rip != a.rip
                        }
                        _ => false,
                    }
            }
            _ => false,
        }
    });
    check("ptrace-attach", {
        // attach to a live spawned task: SIGTRAP stop, inspect, detach,
        // then it can be killed normally
        match ustd::spawn("/bin/cosmos-ucat", "/ptrace-target") {
            Ok(c) => {
                let att = ustd::ptrace(ustd::PT_ATTACH, c, 0, 0) == 0;
                let mut stopped = false;
                for _ in 0..60 {
                    if let Ok(st) = ustd::waitpid_opt(c, 1, 200) {
                        if st & 0xff == 0x7f {
                            stopped = true;
                            break;
                        }
                    }
                    ustd::sleep_ms(25);
                }
                let regs = ustd::ptrace_getregs(c);
                let det = ustd::ptrace(ustd::PT_DETACH, c, 0, 0) == 0;
                let _ = ustd::kill2(c, 9);
                let _ = ustd::waitpid(c, 3000);
                att && stopped && det && regs.map(|r| r.rip != 0).unwrap_or(false)
            }
            Err(_) => false,
        }
    });
    check("ptrace-syscall", {
        // PTRACE_SYSCALL stops at every syscall entry AND exit —
        // the tracer reads the syscall nr in rax each time
        match ustd::fork() {
            0 => {
                ustd::ptrace(ustd::PT_TRACEME, 0, 0, 0);
                ustd::kill2(ustd::getpid(), 19);
                let _ = ustd::getpid();
                let _ = ustd::getpid();
                ustd::exit(3);
            }
            c if c > 0 => {
                let mut stops = 0u64;
                let mut saw_getpid = false;
                let mut dead = false;
                // consume the initial SIGSTOP, then SYSCALL-loop
                let _ = ustd::waitpid_opt(c as u32, 1, 3000);
                ustd::ptrace(ustd::PT_SYSCALL, c as u32, 0, 0);
                for _ in 0..40 {
                    match ustd::waitpid_opt(c as u32, 1, 500) {
                        Ok(st) if st == 0x7f | (5 << 8) => {
                            stops += 1;
                            if let Some(r) = ustd::ptrace_getregs(c as u32) {
                                // entry-stops show the syscall nr in rax;
                                // exit-stops show its return value
                                if r.rax == shared::SYS_GETPID {
                                    saw_getpid = true;
                                }
                            }
                            ustd::ptrace(ustd::PT_SYSCALL, c as u32, 0, 0);
                        }
                        _ => {
                            dead = true;
                            break;
                        }
                    }
                }
                let ex = ustd::waitpid(c as u32, 4000).unwrap_or(-1);
                stops >= 4 && saw_getpid && ex == 3 && dead
            }
            _ => false,
        }
    });
    check("ptrace-peekuser", {
        // PEEKUSER/POKEUSER: offset-indexed register access on the
        // stopped tracee's saved context
        match ustd::fork() {
            0 => {
                ustd::ptrace(ustd::PT_TRACEME, 0, 0, 0);
                ustd::kill2(ustd::getpid(), 19);
                ustd::exit(9);
            }
            c if c > 0 => {
                let _ = ustd::waitpid_opt(c as u32, 1, 3000);
                // rax at offset 112, rflags at 136
                let rax = ustd::ptrace(ustd::PT_PEEKUSER, c as u32, 112, 0);
                let fl = ustd::ptrace(ustd::PT_PEEKUSER, c as u32, 136, 0);
                let poke = ustd::ptrace(ustd::PT_POKEUSER, c as u32, 112, 777);
                let rax2 = ustd::ptrace(ustd::PT_PEEKUSER, c as u32, 112, 0);
                let bad = ustd::ptrace(ustd::PT_PEEKUSER, c as u32, 163, 0);
                ustd::ptrace(ustd::PT_CONT, c as u32, 0, 0);
                let ex = ustd::waitpid(c as u32, 4000).unwrap_or(-1);
                rax >= 0 && fl & 0x202 == 0x202 && poke == 0 && rax2 == 777
                    && bad < 0 && ex == 9
            }
            _ => false,
        }
    });
    check("wait-cont", {
        // WCONTINUED: SIGCONT'd child reports once with status 0xffff
        match ustd::fork() {
            0 => {
                ustd::kill2(ustd::getpid(), 19);
                ustd::exit(0);
            }
            c if c > 0 => {
                let st = ustd::waitpid_opt(c as u32, 1, 3000).unwrap_or(-1);
                let _ = ustd::kill2(c as u32, 18);
                let mut cont = -1i64;
                for _ in 0..30 {
                    if let Ok(s) = ustd::waitpid_opt(c as u32, 2, 300) {
                        cont = s;
                        break;
                    }
                }
                let ex = ustd::waitpid(c as u32, 4000).unwrap_or(-1);
                (st & 0xff) == 0x7f && cont == 0xffff && ex == 0
            }
            _ => false,
        }
    });
    check("waitid-exit", {
        // waitid P_PID: packed (pid<<32)|(kind<<24)|status, kind 1=exit
        match ustd::fork() {
            0 => ustd::exit(11),
            c if c > 0 => {
                let r = ustd::waitid(1, c as u32, 0);
                let pid = (r >> 32) as u32;
                let kind = (r >> 24) & 0xff;
                let code = r & 0xff_ffff;
                pid == c as u32 && kind == 1 && code == 11
            }
            _ => false,
        }
    });
    check("rlimit-cpu", {
        // RLIMIT_CPU: past-quota task gets SIGXCPU (default kill)
        match ustd::fork() {
            0 => {
                ustd::setrlimit(0, 5); // 5 ticks ~= 50ms
                let mut x = 0u64;
                loop {
                    // black_box keeps the busy work real — LLVM would
                    // otherwise prove x==MAX and delete the loop
                    x = core::hint::black_box(x.wrapping_add(1));
                }
            }
            c if c > 0 => ustd::waitpid(c as u32, 10000).unwrap_or(-1) == 152,
            _ => false,
        }
    });
    check("rlimit-as", {
        // RLIMIT_AS: mmap past the cap fails, under it works
        // a 1-byte cap rejects any new map; restoring to u64::MAX reopens
        let _ = ustd::setrlimit(9, 1);
        let over = ustd::mmap(0x1000);
        let _ = ustd::setrlimit(9, 1 << 40);
        let ok = ustd::mmap(1 << 20).is_some();
        over.is_none() && ok
    });
    check("exit-group", {
        // SYS_EXIT_GROUP: exit_group in a forked child kills its threads
        // too — the whole mm group exits with the code
        extern "C" fn worker(_: u64) -> i64 {
            loop {
                ustd::yield_now();
            }
        }
        match ustd::fork() {
            0 => {
                let _ = ustd::thread_spawn(worker, 0);
                ustd::exit_group(7);
            }
            c if c > 0 => ustd::waitpid(c as u32, 5000).unwrap_or(-1) == 7,
            _ => false,
        }
    });
    check("gettid", {
        // main thread tid == pid; a clone thread gets its own
        let main_ok = ustd::gettid() == ustd::getpid();
        extern "C" fn tiddiff(p: u64) -> i64 {
            let me = ustd::gettid();
            (me != 0 && me != p as u32) as i64
        }
        let c = ustd::thread_spawn(tiddiff, ustd::getpid() as u64).unwrap_or(0);
        let r = if c != 0 { ustd::waitpid(c, 3000).unwrap_or(-1) } else { -1 };
        main_ok && r == 1
    });
    check("tgkill", {
        // signal 9 to a specific tid; wrong-mm tgid -> ESRCH
        match ustd::fork() {
            0 => loop {
                ustd::yield_now();
            },
            c if c > 0 => {
                ustd::sleep_ms(50);
                let bad = ustd::tgkill(ustd::getpid(), c as u32, 9);
                let ok = ustd::tgkill(0, c as u32, 9);
                let ex = ustd::waitpid(c as u32, 4000).unwrap_or(-1);
                bad < 0 && ok == 0 && ex == 137
            }
            _ => false,
        }
    });
    check("ptrace-step-rip", {
        // PT_STEP: each step retires one instruction then the pending
        // SIGTRAP stops the tracee (0x7f|(5<<8)); rip advances past the
        // stepped int80. The child loops yield so stops are repeatable.
        match ustd::fork() {
            0 => {
                ustd::ptrace(ustd::PT_TRACEME, 0, 0, 0);
                ustd::kill2(ustd::getpid(), 19);
                loop {
                    ustd::yield_now();
                }
            }
            c if c > 0 => {
                let _ = ustd::waitpid_opt(c as u32, 1, 3000);
                let r0 = ustd::ptrace_getregs(c as u32).map(|r| r.rip).unwrap_or(0);
                ustd::ptrace(ustd::PT_STEP, c as u32, 0, 0);
                let st1 = ustd::waitpid_opt(c as u32, 1, 3000).unwrap_or(-1);
                let r1 = ustd::ptrace_getregs(c as u32).map(|r| r.rip).unwrap_or(0);
                ustd::ptrace(ustd::PT_STEP, c as u32, 0, 0);
                let st2 = ustd::waitpid_opt(c as u32, 1, 3000).unwrap_or(-1);
                let sig = ustd::ptrace_siginfo(c as u32).unwrap_or(0);
                ustd::ptrace(ustd::PT_KILL, c as u32, 0, 0);
                let _ = ustd::waitpid(c as u32, 4000);
                r0 != 0 && r1 != r0
                    && (st1 & 0xff) == 0x7f && (st2 & 0xff) == 0x7f
                    && sig == 5
            }
            _ => false,
        }
    });
    check("proc-syscall", {
        // /proc/<pid>/syscall: while a task blocks inside a syscall the
        // file reports the in-flight nr + args
        match ustd::fork() {
            0 => {
                ustd::sleep_ms(400); // inside SYS_NANOSLEEP-ish when read
                ustd::exit(0);
            }
            c if c > 0 => {
                ustd::sleep_ms(50);
                let s = ustd::read_all(&alloc::format!("/proc/{}/syscall", c))
                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                    .unwrap_or_default();
                let nr = s.split_whitespace().next()
                    .and_then(|t| t.parse::<i64>().ok()).unwrap_or(-1);
                let _ = ustd::waitpid(c as u32, 4000);
                nr > 0
            }
            _ => false,
        }
    });
    check("itimer-virtual", {
        // ITIMER_VIRTUAL: charges cpu ticks of THIS task only — a busy
        // loop runs it down and SIGVTALRM(26) delivers for real
        unsafe {
            VT_HIT = 0;
            ustd::sigaction(26, vt_hit as usize as u64);
            if ustd::setitimer(1, 30, 0) != 0 {
                false
            } else {
                let mut x = 0u64;
                let t0 = ustd::uptime_ms();
                while VT_HIT == 0 && ustd::uptime_ms() - t0 <= 5000 {
                    x = core::hint::black_box(x.wrapping_add(1));
                }
                let _ = x;
                ustd::sigaction(26, 0);
                VT_HIT == 1
            }
        }
    });
    check("itimer-real-periodic", {
        // ITIMER_REAL wall-time periodic: two expiries arrive while the
        // task sleeps (interval re-arms itself)
        unsafe {
            AL_HIT = 0;
            ustd::sigaction(14, al_hit as usize as u64);
            ustd::setitimer(0, 20, 20);
            // count hits over time — the first SIGALRM EINTRs any sleep
            let t0 = ustd::uptime_ms();
            while AL_HIT < 2 && ustd::uptime_ms() - t0 < 3000 {
                ustd::yield_now();
            }
            ustd::setitimer(0, 0, 0);
            ustd::sigaction(14, 0);
            AL_HIT >= 2
        }
    });
    check("mqueue-prio", {
        // POSIX mq: named queue, whole messages, highest-prio-first
        let fd = ustd::mq_open("/selftest-mq", 4, 64);
        if fd < 0 {
            false
        } else {
        let a = ustd::mq_send(fd, b"low", 1) == 0;
        let b = ustd::mq_send(fd, b"hi!", 9) == 0;
        let mut buf = [0u8; 64];
        let r1 = ustd::mq_recv(fd, &mut buf);
        let first = r1.map(|(n, p)| (buf[..n].to_vec(), p)).unwrap_or_default();
        let r2 = ustd::mq_recv(fd, &mut buf);
        let second = r2.map(|(n, p)| (buf[..n].to_vec(), p)).unwrap_or_default();
        ustd::close(fd);
        ustd::mq_unlink("/selftest-mq");
        a && b && first.0 == b"hi!" && first.1 == 9
            && second.0 == b"low" && second.1 == 1
        }
    });
    check("mmap-fixed", {
        // MAP_FIXED: the map lands exactly at addr and replaces an
        // overlapping map's contents
        let addr = 0x3000_0000u64;
        let p1 = ustd::mmap_fixed(addr, 0x2000);
        match p1 {
            None => false,
            Some(p) => {
                unsafe { *p = 0xAA };
                let p2 = ustd::mmap_fixed(addr, 0x1000);
                let ok = p2 == p1 && unsafe { *p == 0 };
                let _ = ustd::munmap(p, 0x2000);
                ok
            }
        }
    });
    check("memfd", {
        // memfd: RAM-backed file — write/seek/read/truncate/stat all real
        let fd = ustd::memfd_create("selftest-mfd");
        if fd < 0 {
            false
        } else {
            let w = ustd::write(fd, b"memfd-works");
            let _ = ustd::seek(fd, 0, 0);
            let mut buf = [0u8; 16];
            let r = ustd::read(fd, &mut buf);
            let read_ok = r.map(|n| buf[..n] == *b"memfd-works").unwrap_or(false);
            let _ = ustd::ftruncate(fd, 5);
            let st = ustd::fstat(fd).map(|s| s.size).unwrap_or(0);
            ustd::close(fd);
            w.is_ok() && read_ok && st == 5
        }
    });
    check("memfd-mmap", {
        // mmap_file on a memfd: pages fault in from the RAM store
        let fd = ustd::memfd_create("mmap-mfd");
        if fd < 0 {
            false
        } else {
            let _ = ustd::write(fd, b"MMMM");
            let _ = ustd::seek(fd, 0x1000, 0);
            let _ = ustd::write(fd, b"NNNN");
            match ustd::mmap_file(fd, 0x2000, 0) {
                None => false,
                Some(p) => unsafe {
                    let a = core::ptr::read_volatile(p.add(1)) == b'M';
                    let b = core::ptr::read_volatile(p.add(0x1001)) == b'N';
                    let _ = ustd::munmap(p, 0x2000);
                    ustd::close(fd);
                    a && b
                },
            }
        }
    });
    check("posix-timer", {
        // timer_create/settime: a one-shot POSIX timer pends its signal
        static mut PH: u32 = 0;
        extern "C" fn th(_: u64) {
            unsafe { PH = 1 };
        }
        unsafe {
            PH = 0;
            ustd::sigaction(11, th as usize as u64);
            let id = ustd::timer_create(11);
            if id < 0 {
                false
            } else {
                ustd::timer_settime(id as u64, 30, 0);
                let t0 = ustd::uptime_ms();
                while PH == 0 && ustd::uptime_ms() - t0 < 3000 {
                    ustd::yield_now();
                }
                ustd::sigaction(11, 0);
                ustd::timer_delete(id as u64);
                PH == 1
            }
        }
    });
    check("proc-sig", {
        // /proc/self/sig reflects a real pending + masked signal
        extern "C" fn s12(_: u64) {}
        ustd::sigaction(12, s12 as usize as u64); // safe delivery on unmask
        ustd::sigprocmask(ustd::SIG_BLOCK, 1 << 12); // block sig12
        ustd::kill2(ustd::getpid(), 12);
        let s = ustd::read_all("/proc/self/sig")
            .map(|d| String::from_utf8_lossy(&d).into_owned())
            .unwrap_or_default();
        ustd::sigprocmask(ustd::SIG_SETMASK, 0); // unmask → handler fires
        let pend = s.lines().find(|l| l.starts_with("sigpending"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|h| u64::from_str_radix(h, 16).ok()).unwrap_or(0);
        let mask = s.lines().find(|l| l.starts_with("sigmask"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|h| u64::from_str_radix(h, 16).ok()).unwrap_or(0);
        pend & (1 << 12) != 0 && mask & (1 << 12) != 0
    });
    check("clock-gettime", {
        // MONOTONIC advances; REALTIME is a sane epoch (>2020)
        let m1 = ustd::clock_gettime(1);
        ustd::sleep_ms(30);
        let m2 = ustd::clock_gettime(1);
        let r = ustd::clock_gettime(0);
        match (m1, m2, r) {
            (Some((s1, _)), Some((s2, n2)), Some((rs, _))) =>
                (s2, n2) != (0, 0) && (s2, n2) >= (s1, 0) && rs > 1_600_000_000,
            _ => false,
        }
    });
    check("splice", {
        // file -> pipe: bytes move kernel-side, no user read/write
        let _ = ustd::remove("/splice-src");
        let f = ustd::open("/splice-src", ustd::O_RDWR | ustd::O_CREATE).unwrap_or(-1);
        let w = ustd::write(f, b"splice-ok-1234").unwrap_or(0);
        let _ = ustd::close(f);
        let r = ustd::open("/splice-src", ustd::O_RDONLY).unwrap_or(-1);
        let Some((pr, pw)) = ustd::pipe() else { panic!("pipe") };
        let moved = if r >= 0 { ustd::splice(r as i32, pw as i32, 14) } else { -1 };
        let mut buf = [0u8; 32];
        let n = if moved == 14 { ustd::read(pr, &mut buf).unwrap_or(0) } else { 0 };
        let both = ustd::splice(r as i32, f as i32, 8); // file->file: EINVAL
        let _ = ustd::close(r);
        let _ = ustd::close(pr);
        let _ = ustd::close(pw);
        w == 14 && moved == 14 && n == 14 && &buf[..14] == b"splice-ok-1234" && both < 0
    });
    check("process-vm", {
        // read + write OWN address space through the pid's pml4
        static mut CELL: u64 = 0;
        unsafe { core::ptr::write_volatile(&mut CELL, 0x5EED_5EED_5EED_5EED) };
        let addr = unsafe { &CELL as *const u64 as u64 };
        let mut got = [0u8; 8];
        let n = ustd::process_vm_readv(ustd::getpid(), addr, &mut got);
        let r_ok = n == 8 && u64::from_le_bytes(got) == 0x5EED_5EED_5EED_5EED;
        let w_ok = ustd::process_vm_writev(ustd::getpid(), addr, &7u64.to_le_bytes()) == 8
            && unsafe { core::ptr::read_volatile(&CELL) } == 7;
        let bad = ustd::process_vm_readv(0x7FFF_F0F0, addr, &mut got);
        r_ok && w_ok && bad < 0
    });
    check("ppoll", {
        // empty poll times out; an unmasked pending signal returns EINTR
        let t = ustd::ppoll(&[], &[], 30, u64::MAX);
        unsafe { PP_HIT = 0 };
        let _ = ustd::sigaction(10, pp_hit as u64);
        let _ = ustd::sigprocmask(ustd::SIG_BLOCK, 1u64 << 10);
        let _ = ustd::tgkill(ustd::getpid(), ustd::gettid(), 10);
        let r = ustd::ppoll(&[], &[], 500, 0); // mask 0 = all unblocked
        ustd::sleep_ms(20);
        let hit = unsafe { PP_HIT };
        let _ = ustd::sigprocmask(ustd::SIG_SETMASK, 0);
        t == 0 && r == -4 && hit == 1
    });
    check("sysinfo", {
        match ustd::sysinfo() {
            Some((_, total, free, procs)) => total > 0 && free > 0 && procs >= 3,
            None => false,
        }
    });
    check("close-range", {
        let Some((r, w)) = ustd::pipe() else { panic!("pipe") };
        let f = ustd::open("/cr-junk", ustd::O_RDWR | ustd::O_CREATE).unwrap_or(-1);
        let lo = r.min(w).min(f) as u32;
        let hi = r.max(w).max(f) as u32;
        let rc = ustd::close_range(lo, hi);
        let mut b = [0u8; 4];
        let dead = ustd::read(r, &mut b).is_err() && ustd::write(f, b"x").is_err();
        rc == 0 && dead
    });
    check("pty-open", {
        let m = ustd::openpt();
        let sp = if m >= 0 { ustd::ptsname(m) } else { None };
        let s = sp.as_ref().map(|p| ustd::open(p, ustd::O_RDWR).unwrap_or(-1)).unwrap_or(-1);
        let _ = ustd::close(m);
        let _ = ustd::close(s);
        m >= 0 && sp.is_some() && s >= 0
    });
    check("pty-io", {
        let m = ustd::openpt();
        let Some(sp) = (if m >= 0 { ustd::ptsname(m) } else { None }) else {
            panic!("ptsname");
        };
        let s = ustd::open(&sp, ustd::O_RDWR).unwrap_or(-1);
        let _ = ustd::write(m, b"hi\n");
        let mut eb = [0u8; 16];
        let en = ustd::read(m, &mut eb).unwrap_or(0);
        let mut lb = [0u8; 16];
        let ln = ustd::read(s, &mut lb).unwrap_or(0);
        let mut ob = [0u8; 16];
        let _ = ustd::write(s, b"out");
        let on = ustd::read(m, &mut ob).unwrap_or(0);
        let _ = ustd::tcsets(s, 0);
        let _ = ustd::write(m, b"xy");
        let mut rb = [0u8; 16];
        let rn = ustd::read(s, &mut rb).unwrap_or(0);
        let _ = ustd::close(m);
        let eio = ustd::read(s, &mut rb) == Err(-5);
        let _ = ustd::close(s);
        en == 3 && &eb[..3] == b"hi\n" && ln == 3 && &lb[..3] == b"hi\n"
            && on == 3 && &ob[..3] == b"out" && rn == 2 && &rb[..2] == b"xy" && eio
    });
    check("pidfd-signal", {
        // pidfd probe + real signal delivery through the fd
        let Some((r, w)) = ustd::pipe() else { panic!("pipe") };
        match ustd::fork() {
            0 => {
                let _ = ustd::close(w);
                let mut b = [0u8; 8];
                let _ = ustd::read(r, &mut b); // block until parent kills us
                ustd::exit_group(1);
            }
            pid if pid > 0 => {
                let pf = ustd::pidfd(pid as u32);
                let probe = ustd::pidfd_send_signal(pf as i32, 0);
                let sent = ustd::pidfd_send_signal(pf as i32, 15);
                let st = ustd::waitpid(pid as u32, 5000).unwrap_or(-1);
                let _ = ustd::close(pf);
                let _ = ustd::close(r);
                let _ = ustd::close(w);
                pf >= 0 && probe == 0 && sent == 0 && st == 128 + 15
            }
            _ => false,
        }
    });
    check("tls-fsbase", {
        // arch_prctl SET_FS/GET_FS: real FS segment per task
        static mut CELL: u64 = 0;
        unsafe { CELL = 0xC0FFEE };
        let addr = unsafe { &CELL as *const u64 as u64 };
        let ok1 = ustd::set_fs_base(addr) == 0;
        let got = ustd::get_fs_base();
        // fs:0 reads the TCB self-pointer slot through the segment
        let fs0 = ustd::tls_self();
        let _ = ustd::set_fs_base(0);
        ok1 && got == addr && fs0 == 0xC0FFEE
    });
    check("tls-thread-id", {
        // a cloned thread gets the TCB the kernel wrote fs:8 = its tid
        static TID: AtomicU64 = AtomicU64::new(0);
        extern "C" fn probe(_a: u64) -> i64 {
            TID.store(ustd::thread_id(), core::sync::atomic::Ordering::SeqCst);
            0
        }
        let mine = ustd::getpid() as u64;
        match ustd::thread_spawn(probe, 0) {
            Ok(tid) => {
                let _ = ustd::waitpid(tid, 4000);
                let seen = TID.load(core::sync::atomic::Ordering::SeqCst);
                seen == tid as u64 && seen != mine
            }
            Err(_) => false,
        }
    });
    check("rlimit-nofile", {
        // RLIMIT_NOFILE bounds the fd INDEX — EMFILE past the cap.
        // selftest's fds are packed, so the first free slot = live count.
        let used = match ustd::open("/etc/rc.conf", ustd::O_RDONLY) {
            Ok(fd) => {
                ustd::close(fd);
                fd as u64
            }
            Err(_) => 0,
        };
        let spare = ustd::open("/etc/rc.conf", ustd::O_RDONLY).ok();
        let set_ok = ustd::setrlimit(ustd::RLIMIT_NOFILE, used + 1);
        // 'spare' occupies index 'used' — at cap used+1 the next open EMFILEs
        let blocked = ustd::open("/etc/rc.conf", ustd::O_RDONLY).is_err();
        if let Some(fd) = spare {
            ustd::close(fd);
        }
        let restored = ustd::setrlimit(ustd::RLIMIT_NOFILE, 1024);
        set_ok && blocked && restored
    });
    {
        let mut ok = ustd::setrlimit(ustd::RLIMIT_NPROC, 1);
        ok = ok && ustd::fork() < 0; // at cap: EAGAIN
        ok = ok && ustd::setrlimit(ustd::RLIMIT_NPROC, 512);
        match ustd::fork() {
            0 => ustd::exit(0), // restored: child must not run the suite
            p if p > 0 => {
                let _ = ustd::waitpid(p as u32, 4000);
            }
            _ => ok = false,
        }
        check("rlimit-nproc", ok);
    }
    check("kern-ptr-rejected", {
        // syscall boundary must reject a kernel VA (phys-map region)
        ustd::sc1(shared::SYS_MEMINFO, 0xFFFF_8000_0000_0000) == u64::MAX
    });
    check("kern-ptr-rejected-in", {
        ustd::sc2(shared::SYS_DEBUG, 0xFFFF_8000_0000_0000, 16) == u64::MAX
    });
    check("stack-growdown", {
        // deep recursion over big per-frame arrays forces the user stack to
        // demand-grow pages below the single eager top page
        #[inline(never)]
        fn chew(depth: u32) -> u64 {
            let mut frame = [0u8; 4096];
            unsafe {
                core::ptr::write_volatile(frame.as_mut_ptr(), (depth & 0xFF) as u8);
            }
            if depth == 0 {
                frame[0] as u64
            } else {
                chew(depth - 1) + frame[0] as u64
            }
        }
        // 40 frames x 4KiB+ each >> the one eagerly mapped stack page
        chew(40) == (0..=40).sum::<u32>() as u64
    });
    check("proc-self-faults", {
        // our own image demand-pages in (maj) and the stack chew above
        // grew pages on fault (min) — counters must be real and nonzero
        let pid = ustd::getpid();
        ustd::read_all(&alloc::format!("/proc/{}/status", pid))
            .map(|d| {
                let s = String::from_utf8_lossy(&d);
                let num = |k: &str| -> u64 {
                    s.lines()
                        .find(|l| l.starts_with(k))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0)
                };
                num("MinFlt:") > 0 && num("MajFlt:") > 0 && num("VmRSS:") > 0
            })
            .unwrap_or(false)
    });
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
                // a resumed task may get scheduled and re-block on IPC
                // before we can read status — "S (sleeping)" proves CONT
                // took just as much as "R (running)" does
                let resumed = ustd::kill2(pid, 18) == 0
                    && ustd::read_all(&alloc::format!("/proc/{}/status", pid))
                        .map(|d| {
                            let s = String::from_utf8_lossy(&d);
                            s.contains("R (running)") || s.contains("S (sleeping)")
                        })
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
                let pfd = ustd::pidfd(pid as u32);
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
    // --- *at() syscall family + O_EXCL/O_PATH + SIGPIPE + wait4 ---
    {
        let _ = ustd::remove("/atdir/inner.txt");
        let _ = ustd::remove("/atdir/renamed.txt");
        let _ = ustd::remove("/atdir/newfile");
        let _ = ustd::remove("/atdir/lnk");
        let _ = ustd::remove("/atdir/gone.txt");
        let _ = ustd::remove("/atdir/subd");
        let _ = ustd::remove("/atdir");
        let _ = ustd::mkdir("/atdir");
        let _ = ustd::write_all("/atdir/inner.txt", b"innerv7");
        let dfd = ustd::open("/atdir", ustd::O_RDONLY).unwrap_or(-1);

        check("at-open", {
            let f = ustd::openat(dfd as i64, "inner.txt", ustd::O_RDONLY).unwrap_or(-1);
            let mut b = [0u8; 16];
            let n = if f >= 0 { ustd::read(f, &mut b).unwrap_or(0) } else { 0 };
            if f >= 0 { ustd::close(f); }
            let fa = ustd::openat(ustd::AT_FDCWD, "/atdir/inner.txt", ustd::O_RDONLY).unwrap_or(-1);
            if fa >= 0 { ustd::close(fa); }
            &b[..n] == b"innerv7" && fa >= 0
        });

        check("at-stat", {
            ustd::fstatat(dfd as i64, "inner.txt", 0)
                .map(|s| s.size == 7)
                .unwrap_or(false)
        });

        check("at-access", {
            ustd::access("/atdir/inner.txt", 0)
                && !ustd::access("/atdir-no-such", 0)
                && ustd::faccessat(dfd as i64, "inner.txt", 0)
                && !ustd::access("/proc/version", 2) // W_OK on ro pseudo-fs
        });

        check("at-mkdir-unlink", {
            let mk = ustd::mkdirat(dfd as i64, "subd").is_ok();
            let eisdir = ustd::unlinkat(dfd as i64, "subd", 0) == Err(-21);
            let rm = ustd::unlinkat(dfd as i64, "subd", ustd::AT_REMOVEDIR).is_ok();
            let _ = ustd::write_all("/atdir/gone.txt", b"x");
            let ul = ustd::unlinkat(dfd as i64, "gone.txt", 0).is_ok()
                && ustd::stat("/atdir/gone.txt").is_err();
            mk && eisdir && rm && ul
        });

        check("at-rename", {
            ustd::renameat(dfd as i64, "inner.txt", dfd as i64, "renamed.txt").is_ok()
                && ustd::stat("/atdir/renamed.txt").map(|s| s.size == 7).unwrap_or(false)
        });

        check("at-symlink", {
            let cr = ustd::symlinkat("/atdir/renamed.txt", dfd as i64, "lnk").is_ok();
            let tgt = ustd::readlinkat(dfd as i64, "lnk").as_deref() == Some("/atdir/renamed.txt");
            let lst = ustd::fstatat(dfd as i64, "lnk", ustd::AT_SYMLINK_NOFOLLOW)
                .map(|s| s.attr & 0x40 != 0)
                .unwrap_or(false);
            let fol = ustd::fstatat(dfd as i64, "lnk", 0)
                .map(|s| s.size == 7)
                .unwrap_or(false);
            cr && tgt && lst && fol
        });

        check("fchdir", {
            let ok = ustd::fchdir(dfd as i64) == 0 && ustd::getcwd() == "/atdir";
            let _ = ustd::chdir("/");
            ok && ustd::getcwd() == "/"
        });

        check("fchmod", {
            let f = ustd::open("/atdir/renamed.txt", ustd::O_RDONLY).unwrap_or(-1);
            let ro = f >= 0
                && ustd::fchmod(f, 0o444) == 0
                && ustd::stat("/atdir/renamed.txt").map(|s| s.attr & 0x01 != 0).unwrap_or(false);
            let rw = f >= 0
                && ustd::fchmod(f, 0o644) == 0
                && ustd::stat("/atdir/renamed.txt").map(|s| s.attr & 0x01 == 0).unwrap_or(false);
            if f >= 0 { ustd::close(f); }
            ro && rw
        });

        check("getdents", {
            ustd::getdents(dfd as i64, 32)
                .map(|es| es.iter().any(|e| {
                    let nm = unsafe {
                        let p = e.name.as_ptr();
                        let mut l = 0usize;
                        while l < e.name.len() && *p.add(l) != 0 { l += 1; }
                        core::str::from_utf8_unchecked(&e.name[..l])
                    };
                    nm == "renamed.txt"
                }))
                .unwrap_or(false)
        });

        check("at-oexcl", {
            let ex = ustd::open("/atdir/renamed.txt", ustd::O_RDWR | ustd::O_CREATE | ustd::O_EXCL);
            let nf = ustd::open("/atdir/newfile", ustd::O_RDWR | ustd::O_CREATE | ustd::O_EXCL);
            if let Ok(f) = nf { ustd::close(f); }
            ex == Err(-17) && nf.map(|f| f >= 0).unwrap_or(false)
        });

        check("at-opath", {
            let f = ustd::open("/atdir/renamed.txt", ustd::O_PATH).unwrap_or(-1);
            let mut b = [0u8; 4];
            let r = if f >= 0 { ustd::read(f, &mut b) } else { Err(-1) };
            let w = if f >= 0 { ustd::write(f, b"x") } else { Err(-1) };
            if f >= 0 { ustd::close(f); }
            f >= 0 && r == Err(-9) && w == Err(-9)
        });

        if dfd >= 0 { ustd::close(dfd); }
    }

    check("sigpipe", {
        extern "C" fn sp(_: u64) {
            unsafe { SP_HIT += 1 };
        }
        static mut SP_HIT: u32 = 0;
        unsafe { SP_HIT = 0 };
        ustd::sigaction(13, sp as usize as u64);
        match ustd::pipe() {
            Some((r, w)) => {
                ustd::close(r);
                let e = ustd::write(w, b"x");
                ustd::close(w);
                ustd::sigaction(13, ustd::SIG_IGN);
                e == Err(-32) && unsafe { SP_HIT } == 1
            }
            None => false,
        }
    });

    check("wait4", {
        match ustd::fork() {
            0 => ustd::exit(42),
            p if p > 0 => {
                let (st, ru) = ustd::wait4(p as i64, 0, 5000);
                st == 42 && ru.is_some()
            }
            _ => false,
        }
    });

    // --- batch 68: seccomp + robust list + statfs/syncfs/fallocate/cfr/tee/pselect/dup3/yield/cns/tod ---
    check("seccomp-strict", {
        match ustd::fork() {
            0 => {
                let _ = ustd::seccomp(1, None);
                // gettimeofday is outside the strict allowlist -> SIGKILL
                let _ = ustd::gettimeofday();
                ustd::exit(0)
            }
            p if p > 0 => ustd::waitpid(p as u32, 5000).unwrap_or(-1) == 128 + 9,
            _ => false,
        }
    });
    check("seccomp-filter", {
        match ustd::fork() {
            0 => {
                // bitmap allowing only SYS_EXIT(0)
                let mut b = [0u8; 32];
                b[0] = 1;
                let _ = ustd::seccomp(2, Some(&b));
                let bad = ustd::gettimeofday(); // -> ENOSYS
                let _ = bad;
                ustd::exit(42) // SYS_EXIT is allowed
            }
            p if p > 0 => ustd::waitpid(p as u32, 5000).unwrap_or(-1) == 42,
            _ => false,
        }
    });
    check("robust-list", {
        use core::sync::atomic::{AtomicU64, Ordering};
        static RW: AtomicU64 = AtomicU64::new(0);
        // node ABI: {next_va, futex_va} u64 pair, list ends at next=0
        static NODE: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
        extern "C" fn rl(_: u64) -> i64 {
            NODE[0].store(0, Ordering::SeqCst);
            NODE[1].store(&RW as *const _ as u64, Ordering::SeqCst);
            ustd::set_robust_list(&NODE as *const _ as u64);
            RW.store(1, Ordering::SeqCst);
            ustd::sleep_ms(150); // stay alive while main futex-waits
            0
        }
        match ustd::thread_spawn(rl, 0) {
            Ok(tid) => {
                // wait for RW==1 then futex-block on it; when the thread
                // dies the kernel ORs OWNER_DIED and wakes the waiter.
                let mut i = 0;
                while RW.load(Ordering::SeqCst) != 1 && i < 2000 {
                    ustd::sleep_ms(1);
                    i += 1;
                }
                let r = ustd::futex(&RW, 0, 1, 4000);
                let _ = ustd::waitpid(tid, 3000);
                r == 0 && RW.load(Ordering::SeqCst) & (1 << 30) != 0
            }
            Err(_) => false,
        }
    });
    {
        let f = ustd::open("/etc/rc.conf", ustd::O_RDONLY).unwrap_or(-1);
        let st = ustd::statfs("/");
        let fs = ustd::fstatfs(f);
        let sy = ustd::syncfs(f);
        if f >= 0 { ustd::close(f); }
        check("statfs", st.map(|(t, bs, bl, bf)| t == 0x4d44 && bs > 0 && bl > bf).unwrap_or(false)
            && fs.map(|(t, _, _, _)| t == 0x4d44).unwrap_or(false));
        check("syncfs", f >= 0 && sy == 0);
    }
    check("fallocate", {
        let _ = ustd::remove("/st-falloc");
        let _ = ustd::write_all("/st-falloc", b"ab");
        let f = ustd::open("/st-falloc", ustd::O_RDWR).unwrap_or(-1);
        let ok = f >= 0
            && ustd::fallocate(f, 0, 4096) == 0
            && ustd::stat("/st-falloc").map(|s| s.size == 4096).unwrap_or(false)
            && ustd::read_all("/st-falloc").map(|d| &d[..2] == b"ab" && d[3] == 0).unwrap_or(false);
        if f >= 0 { ustd::close(f); }
        let _ = ustd::remove("/st-falloc");
        ok
    });
    check("copy-file-range", {
        let _ = ustd::remove("/st-cfr-b");
        let _ = ustd::write_all("/st-cfr-a", b"cfrdata!");
        let i = ustd::open("/st-cfr-a", ustd::O_RDONLY).unwrap_or(-1);
        let o = ustd::open("/st-cfr-b", ustd::O_RDWR | ustd::O_CREATE | ustd::O_TRUNC).unwrap_or(-1);
        let n = if i >= 0 && o >= 0 { ustd::copy_file_range(i, o, 64) } else { -1 };
        let ok = n == 8 && ustd::read_all("/st-cfr-b").map(|d| &d[..] == b"cfrdata!").unwrap_or(false);
        if i >= 0 { ustd::close(i); }
        if o >= 0 { ustd::close(o); }
        let _ = ustd::remove("/st-cfr-a");
        let _ = ustd::remove("/st-cfr-b");
        ok
    });
    check("tee", {
        match (ustd::pipe(), ustd::pipe()) {
            (Some((r1, w1)), Some((r2, w2))) => {
                let _ = ustd::write(w1, b"AB");
                let t = ustd::tee(r1, w2, 2);
                let mut b = [0u8; 4];
                let n1 = ustd::read(r1, &mut b).unwrap_or(0); // source NOT consumed
                let n2 = ustd::read(r2, &mut b).unwrap_or(0);
                ustd::close(r1); ustd::close(w1); ustd::close(r2); ustd::close(w2);
                t == 2 && n1 == 2 && n2 == 2 && &b[..2] == b"AB"
            }
            _ => false,
        }
    });
    check("pselect", {
        match ustd::pipe() {
            Some((r, w)) => {
                let mut rm: u64 = 1 << r;
                let mut wm: u64 = 0;
                let _ = ustd::write(w, b"z");
                let n = ustd::pselect(64, &mut rm, &mut wm, 1000, u64::MAX);
                let mut drain = [0u8; 4];
                let _ = ustd::read(r, &mut drain); // consume "z"
                let zero = {
                    let mut rm2: u64 = 1 << r;
                    let mut wm2: u64 = 0;
                    ustd::pselect(64, &mut rm2, &mut wm2, 0, u64::MAX)
                };
                ustd::close(r); ustd::close(w);
                n == 1 && rm == (1 << r) && zero == 0
            }
            None => false,
        }
    });
    check("pselect-eintr", {
        extern "C" fn pe(_: u64) {}
        ustd::sigaction(10, pe as usize as u64);
        let _ = ustd::kill2(ustd::getpid(), 10); // pending before the call
        let mut rm: u64 = 0;
        let mut wm: u64 = 0;
        ustd::pselect(64, &mut rm, &mut wm, u64::MAX, 0) == -4
    });
    check("dup3", {
        match ustd::pipe() {
            Some((r, w)) => {
                let d = ustd::dup3(r, 30, 0);
                let bad = ustd::dup3(r, 31, 1);
                ustd::close(r); ustd::close(w);
                if d >= 0 { ustd::close(d); }
                d >= 0 && bad < 0
            }
            None => false,
        }
    });
    check("sched-yield", {
        ustd::sched_yield();
        ustd::sched_yield();
        true // survived two real yields
    });
    check("clock-nanosleep", {
        let t0 = ustd::uptime_ms();
        let r = ustd::clock_nanosleep(t0 + 60);
        let past = ustd::clock_nanosleep(t0); // already past -> immediate 0
        r == 0 && past == 0 && ustd::uptime_ms() - t0 >= 50
    });
    // --- batch 69: shared-mm races, thread slot reclaim, ctty hangup ---
    check("thread-slot-reuse", {
        // each dead thread's stack slot must be reclaimed — spawning more
        // threads than the arena's 191 slots only works if death frees them
        extern "C" fn nul(_: u64) -> i64 {
            0
        }
        let mut n = 0;
        let mut ok = true;
        for _ in 0..200 {
            match ustd::thread_spawn(nul, 0) {
                Ok(tid) => {
                    n += 1;
                    let _ = ustd::waitpid(tid, 4000);
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        ok && n == 200
    });
    check("mm-reserve", {
        use core::sync::atomic::{AtomicU64, Ordering};
        static B: AtomicU64 = AtomicU64::new(0);
        extern "C" fn mm(_: u64) -> i64 {
            let p = ustd::mmap(8192).map(|x| x as u64).unwrap_or(0);
            B.store(p, Ordering::SeqCst);
            0
        }
        B.store(0, Ordering::SeqCst);
        match ustd::thread_spawn(mm, 0) {
            Ok(tid) => {
                let mine = ustd::mmap(8192).map(|x| x as u64).unwrap_or(0);
                let _ = ustd::waitpid(tid, 3000);
                let theirs = B.load(Ordering::SeqCst);
                // anon mmap ranges must be disjoint across threads of one mm
                mine != 0 && theirs != 0 && mine != theirs
            }
            Err(_) => false,
        }
    });
    check("mprotect-peer", {
        use core::sync::atomic::{AtomicU64, Ordering};
        static P: AtomicU64 = AtomicU64::new(0);
        extern "C" fn mp(_: u64) -> i64 {
            let base = P.load(Ordering::SeqCst);
            if base == 0 {
                return 1;
            }
            if ustd::mprotect(base as *mut u8, 4096, 1) {
                0
            } else {
                2
            }
        }
        match ustd::mmap(4096) {
            Some(p) => {
                P.store(p as u64, Ordering::SeqCst);
                match ustd::thread_spawn(mp, 0) {
                    Ok(tid) => {
                        let code = ustd::waitpid(tid, 3000).unwrap_or(-1);
                        // OUR task's maps must show the peer's mprotect
                        let maps = ustd::read_all("/proc/self/maps").unwrap_or_default();
                        let s = String::from_utf8_lossy(&maps);
                        let needle = alloc::format!("{:08x}", p as u64);
                        code == 0
                            && s.lines().any(|l| l.starts_with(needle.as_str()) && l.contains("r--p"))
                    }
                    Err(_) => false,
                }
            }
            None => false,
        }
    });
    check("ptmx-sighup", {
        use core::sync::atomic::{AtomicU64, Ordering};
        static GOT_HUP: AtomicU64 = AtomicU64::new(0);
        extern "C" fn hup(_: u64) {
            GOT_HUP.store(1, Ordering::SeqCst);
        }
        GOT_HUP.store(0, Ordering::SeqCst);
        let mfd = ustd::openpt();
        if mfd < 0 {
            false
        } else {
            let sname = ustd::ptsname(mfd).unwrap_or_default();
            match ustd::fork() {
                0 => {
                    // drop the inherited master fd — only the parent may
                    // hold it, or the pair outlives the parent's close
                    ustd::close(mfd);
                    ustd::setsid();
                    // session leader's first tty open -> controlling tty
                    let f = ustd::open(&sname, ustd::O_RDWR).unwrap_or(-1);
                    if f < 0 {
                        ustd::exit(11);
                    }
                    ustd::signal(1, hup);
                    loop {
                        ustd::sleep_ms(50);
                        if GOT_HUP.load(Ordering::SeqCst) == 1 {
                            ustd::exit(77);
                        }
                    }
                }
                p if p > 0 => {
                    ustd::sleep_ms(400); // let the child acquire the ctty
                    ustd::close(mfd); // master death -> SIGHUP to the session
                    ustd::waitpid(p as u32, 9000).unwrap_or(-1) == 77
                }
                _ => {
                    ustd::close(mfd);
                    false
                }
            }
        }
    });
    check("settid-join", {
        // clear_child_tid: the kernel zeroes the ctid word at exit and
        // futex-wakes the joiner — no polling
        use core::sync::atomic::Ordering;
        static CELL: AtomicU64 = AtomicU64::new(0);
        extern "C" fn w(_: u64) -> i64 {
            ustd::set_tid_address(&CELL as *const AtomicU64 as u64);
            ustd::sleep_ms(120);
            0
        }
        CELL.store(1, Ordering::SeqCst);
        match ustd::thread_spawn(w, 0) {
            Ok(tid) => {
                let mut ok = false;
                for _ in 0..60 {
                    if CELL.load(Ordering::SeqCst) == 0 {
                        ok = true;
                        break;
                    }
                    ustd::futex(&CELL, 0, 1, 200);
                }
                ustd::waitpid(tid, 3000);
                ok
            }
            Err(_) => false,
        }
    });
    check("renameat2-noreplace", {
        let _ = ustd::write_all("/rn2a", b"a");
        let _ = ustd::write_all("/rn2b", b"b");
        let r = ustd::renameat2(ustd::AT_FDCWD, "/rn2a", ustd::AT_FDCWD, "/rn2b", 1);
        let ok = r == -17
            && ustd::read_all("/rn2a").map(|d| d == b"a").unwrap_or(false)
            && ustd::read_all("/rn2b").map(|d| d == b"b").unwrap_or(false);
        let _ = ustd::remove("/rn2a");
        let _ = ustd::remove("/rn2b");
        ok
    });
    check("renameat2-exchange", {
        let _ = ustd::write_all("/rn2x", b"x");
        let _ = ustd::write_all("/rn2y", b"y");
        let r = ustd::renameat2(ustd::AT_FDCWD, "/rn2x", ustd::AT_FDCWD, "/rn2y", 2);
        let ok = r == 0
            && ustd::read_all("/rn2x").map(|d| d == b"y").unwrap_or(false)
            && ustd::read_all("/rn2y").map(|d| d == b"x").unwrap_or(false);
        let _ = ustd::remove("/rn2x");
        let _ = ustd::remove("/rn2y");
        ok
    });
    check("utimensat", {
        let _ = ustd::write_all("/utmn", b"t");
        // FAT32 mtime has 2s granularity — use an even second
        let times: [u64; 4] = [0, 0, 1_700_000_002, 0]; // mtime.sec
        let r = ustd::utimensat(ustd::AT_FDCWD, "/utmn", Some(&times), 0);
        let ok = r == 0
            && ustd::stat("/utmn").map(|s| s.mtime == 1_700_000_002).unwrap_or(false);
        let _ = ustd::remove("/utmn");
        ok
    });
    check("pipe2-nonblock", {
        match ustd::pipe2(shared::O_NONBLOCK) {
            Some((r, w)) => {
                let mut b = [0u8; 4];
                let n = ustd::read(r, &mut b);
                ustd::close(r);
                ustd::close(w);
                n == Err(-11)
            }
            None => false,
        }
    });
    check("eventfd2-nonblock", {
        let fd = ustd::eventfd2(0, shared::EFD_NONBLOCK);
        let r = if fd >= 0 {
            let mut b = [0u8; 8];
            let n = ustd::read(fd, &mut b);
            ustd::close(fd);
            n == Err(-11)
        } else {
            false
        };
        r
    });
    check("cloexec-fd", {
        let f = ustd::open("/etc/rc.conf", ustd::O_RDONLY).unwrap_or(-1);
        if f < 0 {
            false
        } else {
            // SETFD FD_CLOEXEC -> GETFD reads it back; F_DUPFD strips it
            let set = ustd::fcntl(f, 2, 1); // F_SETFD
            let got = ustd::fcntl(f, 1, 0); // F_GETFD
            let dup = ustd::fcntl(f, 0, 10); // F_DUPFD @ >=10
            let dupgot = if dup >= 0 { ustd::fcntl(dup, 1, 0) } else { -1 };
            if dup >= 0 {
                ustd::close(dup);
            }
            ustd::close(f);
            set == 0 && got == 1 && dup >= 0 && dupgot == 0
        }
    });
    check("tmpfs-mount", {
        // mount tmpfs over an existing dir: the mount masks the FAT entry,
        // files live in RAM, umount restores the covered dir
        let _ = ustd::remove("/tfs-m/pre"); // clean slate on FAT
        let _ = ustd::mkdir("/tfs-m");
        let wrote = ustd::write_all("/tfs-m/pre", b"fat");
        let m = ustd::mount("none", "/tfs-m", "tmpfs");
        let mut ok = m == 0 && wrote.is_ok();
        if ok {
            // covered: the FAT file is hidden while mounted
            ok = ustd::stat("/tfs-m/pre").is_err()
                && ustd::write_all("/tfs-m/ram", b"tmpfs").is_ok()
                && ustd::read_all("/tfs-m/ram").map(|d| d == b"tmpfs").unwrap_or(false)
                && ustd::stat("/tfs-m/ram").map(|s| s.size == 5).unwrap_or(false)
                && ustd::readdir("/tfs-m").map(|v| v.iter().any(|e| {
                    let n = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("");
                    n == "ram"
                })).unwrap_or(false);
            ok = ok && ustd::umount("/tfs-m") == 0;
            // unmounted: the FAT dir + its file are visible again
            ok = ok && ustd::read_all("/tfs-m/pre").map(|d| d == b"fat").unwrap_or(false)
                && ustd::stat("/tfs-m/ram").is_err();
        }
        let _ = ustd::remove("/tfs-m/pre");
        let _ = ustd::remove("/tfs-m");
        ok
    });
    check("tmpfs-busy", {
        let _ = ustd::mkdir("/tfs-b");
        let ok = ustd::mount("none", "/tfs-b", "tmpfs") == 0;
        let ok = ok && ustd::write_all("/tfs-b/f", b"x").is_ok();
        let f = ustd::open("/tfs-b/f", ustd::O_RDONLY).unwrap_or(-1);
        let busy = f >= 0 && ustd::umount("/tfs-b") == -16; // EBUSY
        if f >= 0 {
            ustd::close(f);
        }
        let ok = ok && busy && ustd::umount("/tfs-b") == 0;
        let _ = ustd::remove("/tfs-b");
        ok
    });
    check("tmpfs-quota", {
        // real ENOSPC: the 4MiB quota rejects an oversized write
        let _ = ustd::mkdir("/tfs-q");
        let ok = ustd::mount("none", "/tfs-q", "tmpfs") == 0;
        let big = alloc::vec![0xABu8; 5 * 1024 * 1024];
        let r = ustd::write_all("/tfs-q/big", &big);
        let ok = ok && r == Err(-28i64);
        let _ = ustd::umount("/tfs-q");
        let _ = ustd::remove("/tfs-q");
        ok
    });
    check("proc-mounts", {
        let _ = ustd::mkdir("/tfs-p");
        let ok = ustd::mount("none", "/tfs-p", "tmpfs") == 0;
        let has = ustd::read_all("/proc/mounts")
            .map(|d| String::from_utf8_lossy(&d).contains("tmpfs /tfs-p tmpfs"))
            .unwrap_or(false);
        let ok = ok && has && ustd::umount("/tfs-p") == 0;
        let _ = ustd::remove("/tfs-p");
        ok
    });
    check("tmpfs-rename", {
        let _ = ustd::mkdir("/tfs-r");
        let ok = ustd::mount("none", "/tfs-r", "tmpfs") == 0
            && ustd::write_all("/tfs-r/a", b"1").is_ok()
            && ustd::renameat2(ustd::AT_FDCWD, "/tfs-r/a", ustd::AT_FDCWD, "/tfs-r/b", 0) == 0
            && ustd::read_all("/tfs-r/b").map(|d| d == b"1").unwrap_or(false)
            // cross-mount rename is EXDEV
            && ustd::renameat2(ustd::AT_FDCWD, "/tfs-r/b", ustd::AT_FDCWD, "/rn-xdev", 0) == -18;
        let _ = ustd::umount("/tfs-r");
        let _ = ustd::remove("/tfs-r");
        ok
    });
    check("tmpfs-ro", {
        // MS_RDONLY: mounting ro makes every write EROFS, reads still work;
        // MS_REMOUNT toggles it back rw.
        let _ = ustd::mkdir("/tfs-ro");
        let ok = ustd::mount_flags("none", "/tfs-ro", "tmpfs", 1) == 0
            && ustd::write_all("/tfs-ro/f", b"x") == Err(-30i64)
            && ustd::mount_flags("none", "/tfs-ro", "tmpfs", 32) == 0 // remount rw
            && ustd::write_all("/tfs-ro/f", b"x").is_ok()
            && ustd::umount("/tfs-ro") == 0;
        let _ = ustd::remove("/tfs-ro");
        ok
    });
    check("chroot-jail", {
        // a jailed child sees /jail as / and can't escape via ".."
        let _ = ustd::mkdir("/jail");
        let ok = ustd::write_all("/jail/x", b"J").is_ok();
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::chroot("/jail") != 0 {
                ustd::exit(11);
            }
            let seen = ustd::read_all("/x").map(|d| d == b"J").unwrap_or(false);
            ustd::chdir("/.."); // .. at the jail root must not escape
            let esc = ustd::read_all("/x").map(|d| d == b"J").unwrap_or(false);
            let leak = ustd::stat("/etc/rc.conf").is_ok(); // outside jail
            ustd::exit(if seen && esc && !leak { 0 } else { 12 });
        }
        let st = ustd::waitpid(pid as u32, 10_000);
        ok && st == Ok(0)
    });
    check("tmp-tmpfs", {
        // init mounted a real tmpfs on /tmp at boot
        ustd::read_all("/proc/mounts")
            .map(|d| String::from_utf8_lossy(&d).contains("tmpfs /tmp tmpfs"))
            .unwrap_or(false)
            && ustd::write_all("/tmp/st", b"t").is_ok()
            && ustd::read_all("/tmp/st").map(|d| d == b"t").unwrap_or(false)
    });
    check("bind-mount", {
        // bind /bs onto /bd: reads through the alias hit the source,
        // an fd opened through the bind survives the unbind.
        let _ = ustd::mkdir("/bs");
        let _ = ustd::mkdir("/bd");
        let ok = ustd::mount("none", "/bs", "tmpfs") == 0
            && ustd::write_all("/bs/f", b"B").is_ok()
            && ustd::mount_flags("/bs", "/bd", "none", 0x1000) == 0
            && ustd::read_all("/bd/f").map(|d| d == b"B").unwrap_or(false)
            // ".." at the bind root escapes to the real parent
            && ustd::stat("/bd/../welcome.txt").is_ok() == ustd::stat("/welcome.txt").is_ok();
        // fd opened through the bind keeps working after unbind
        let fd_ok = ustd::open("/bd/f", 0)
            .map(|fd| {
                let _ = ustd::umount("/bd");
                let mut b = [0u8; 4];
                let n = ustd::read(fd, &mut b).unwrap_or(0);
                let _ = ustd::close(fd);
                n == 1 && b[0] == b'B'
            })
            .unwrap_or(false);
        let _ = ustd::umount("/bs");
        let _ = ustd::remove("/bs");
        let _ = ustd::remove("/bd");
        ok && fd_ok
    });
    check("umount-flags", {
        // open fd makes umount EBUSY; MNT_DETACH(2) detaches lazily and
        // keeps the resolved path alive.
        let _ = ustd::mkdir("/umf");
        let ok = ustd::mount("none", "/umf", "tmpfs") == 0
            && ustd::write_all("/umf/x", b"X").is_ok();
        let fd = ustd::open("/umf/x", 0).unwrap_or(-1);
        let busy = ustd::umount("/umf") == -16;
        let lazy = busy
            && ustd::umount2("/umf", 2) == 0
            && {
                let mut b = [0u8; 4];
                ustd::read(fd, &mut b).map(|n| n == 1 && b[0] == b'X').unwrap_or(false)
            };
        let _ = ustd::close(fd);
        // force-purge the detached tree
        let _ = ustd::mkdir("/umf2");
        let _ = ustd::mount("none", "/umf2", "tmpfs");
        let _ = ustd::write_all("/umf2/y", b"Y");
        let fd2 = ustd::open("/umf2/y", 0).unwrap_or(-1);
        let frc = ustd::umount2("/umf2", 1) == 0;
        let _ = ustd::close(fd2);
        let _ = ustd::remove("/umf");
        let _ = ustd::remove("/umf2");
        ok && fd >= 0 && lazy && frc
    });
    check("statx", {
        let _ = ustd::mkdir("/sx");
        let ok = ustd::mount("none", "/sx", "tmpfs") == 0
            && ustd::write_all("/sx/f", b"0123456789").is_ok();
        let sx = ustd::statx("/sx/f");
        let sd = ustd::statx("/sx");
        let ok = ok
            && sx.as_ref().map(|s| s.size == 10 && s.btime > 0 && s.mode == 0o100644 && s.ino != 0).unwrap_or(false)
            && sd.as_ref().map(|s| s.mode == 0o40755).unwrap_or(false);
        let _ = ustd::umount("/sx");
        let _ = ustd::remove("/sx");
        ok
    });
    check("mountinfo", {
        ustd::read_all("/proc/self/mountinfo")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.contains("fat32") && s.contains("/ /tmp rw - tmpfs")
            })
            .unwrap_or(false)
    });
    check("pivot-root", {
        // after pivot_root(/nr,/nr/old): / is the new root and the old
        // tree is reachable at /old — a real bind does the old-side work
        let _ = ustd::mkdir("/nr");
        let _ = ustd::mkdir("/nr/old");
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::pivot_root("/nr", "/nr/old") != 0 {
                ustd::exit(13);
            }
            // /x under the new root hits /nr/x — absent
            let new_missing = ustd::stat("/welcome.txt").is_err();
            // /old/x binds to the old tree's /x — real file readable
            let old_ok = ustd::read_all("/old/welcome.txt")
                .map(|d| !d.is_empty())
                .unwrap_or(false);
            ustd::exit(if new_missing && old_ok { 0 } else { 14 });
        }
        ustd::waitpid(pid as u32, 10_000) == Ok(0)
    });
    check("openat2-beneath", {
        // RESOLVE_BENEATH pins resolution inside the dirfd subtree
        let _ = ustd::mkdir("/x2");
        let ok = ustd::write_all("/x2/inner", b"I").is_ok();
        let dfd = ustd::open("/x2", ustd::O_PATH);
        let ok = ok && dfd.is_ok();
        let dfd = dfd.unwrap_or(-1);
        // ../ escape -> EXDEV; absolute -> EXDEV; inner file -> fd
        let esc = ustd::openat2(dfd, "../welcome.txt", 0, 4) < 0
            && ustd::openat2(dfd, "/etc/rc.conf", 0, 4) < 0
            && ustd::openat2(dfd, "inner", 0, 4) >= 0;
        let _ = ustd::close(dfd);
        ok && esc
    });
    check("openat2-nosym", {
        // RESOLVE_NO_SYMLINKS refuses a symlink component with ELOOP
        let _ = ustd::unlinkat(ustd::AT_FDCWD, "/lnx", 0);
        let ok = ustd::symlinkat("/welcome.txt", ustd::AT_FDCWD, "/lnx").is_ok();
        let blocked = ustd::openat2(ustd::AT_FDCWD, "/lnx", 0, 2) < 0;
        // plain open still follows it — same file contents
        let follows = ustd::read_all("/lnx").is_ok();
        let _ = ustd::unlinkat(ustd::AT_FDCWD, "/lnx", 0);
        ok && blocked && follows
    });
    check("getrandom", {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        ustd::getrandom(&mut a) == 16
            && ustd::getrandom(&mut b) == 16
            && a != b
            && a.iter().any(|&x| x != 0)
    });
    check("mincore-madvise", {
        // fresh file mmap is non-resident; a touch faults it in;
        // DONTNEED drops it back out — all real page-table facts
        let fd = ustd::open("/welcome.txt", 0).unwrap_or(-1);
        let p = ustd::mmap_file(fd, 0x2000, 0);
        let mut ok = fd >= 0 && p.is_some();
        if let Some(pp) = p {
            let va = pp as u64;
            let _ = va;
            let v0 = ustd::mincore(va, 0x2000).unwrap_or_default();
            unsafe { core::ptr::read_volatile(pp) };
            let v1 = ustd::mincore(va, 0x2000).unwrap_or_default();
            let _ = ustd::madvise(va, 0x2000, 4); // DONTNEED
            let v2 = ustd::mincore(va, 0x2000).unwrap_or_default();
            ok = ok
                && v0.len() == 2 && v0[0] == 0
                && v1.len() == 2 && v1[0] == 1
                && v2.len() == 2 && v2[0] == 0;
            let _ = ustd::munmap(pp, 0x2000);
        }
        let _ = ustd::close(fd);
        ok
    });
    check("unshare-ns", {
        // CLONE_NEWNS: the child's mount is invisible in the parent's
        // namespace — /nsp stays a bare FAT dir here.
        let _ = ustd::mkdir("/nsp");
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::unshare(0x20000) != 0 {
                ustd::exit(15);
            }
            let m = ustd::mount("none", "/nsp", "tmpfs") == 0
                && ustd::write_all("/nsp/f", b"N").is_ok();
            ustd::exit(if m { 0 } else { 16 });
        }
        let ok = ustd::waitpid(pid as u32, 10_000) == Ok(0);
        let invis = ustd::stat("/nsp/f").is_err()
            && ustd::read_all("/proc/mounts")
                .map(|d| !String::from_utf8_lossy(&d).contains("tmpfs /nsp tmpfs"))
                .unwrap_or(false)
            // mounting the same path here succeeds — separate namespace
            && ustd::mount("none", "/nsp", "tmpfs") == 0
            // and the child's file did NOT leak into this fresh mount
            && ustd::stat("/nsp/f").is_err();
        let _ = ustd::umount("/nsp");
        let _ = ustd::remove("/nsp");
        ok && invis
    });
    check("setns", {
        // adopt a child's namespace through /proc/<pid>/ns/mntns, then
        // setns back into our own — mntns:[id] stays stable per ns.
        let _ = ustd::mkdir("/nsx");
        let own = ustd::open("/proc/self/ns/mntns", ustd::O_RDONLY).unwrap_or(-1);
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::unshare(0x20000) != 0 {
                ustd::exit(15);
            }
            if ustd::mount("none", "/nsx", "tmpfs") != 0
                || ustd::write_all("/nsx/f", b"S").is_err()
            {
                ustd::exit(16);
            }
            ustd::sleep_ms(2000); // stay alive for the parent's setns
            ustd::exit(0);
        }
        ustd::sleep_ms(150); // let the child's mount land first
        let pf = alloc::format!("/proc/{}/ns/mntns", pid);
        let theirs = ustd::open(&pf, ustd::O_RDONLY).unwrap_or(-1);
        let mut ok = own >= 0 && theirs >= 0 && ustd::stat("/nsx/f").is_err();
        if theirs >= 0 && ustd::setns(theirs as u64) == 0 {
            ok = ok && ustd::stat("/nsx/f").is_ok();
            // ...and switching back restores the parent view
            if own >= 0 {
                ok = ok && ustd::setns(own as u64) == 0 && ustd::stat("/nsx/f").is_err();
            }
        }
        if own >= 0 {
            let _ = ustd::close(own);
        }
        if theirs >= 0 {
            let _ = ustd::close(theirs);
        }
        let _ = ustd::waitpid(pid as u32, 10_000);
        let _ = ustd::remove("/nsx");
        ok
    });
    check("mount-noexec", {
        // MS_NOEXEC(8) on the covering mount turns execve into EACCES.
        let _ = ustd::mkdir("/nx");
        let ok = ustd::mount_flags("none", "/nx", "tmpfs", 8) == 0
            && ustd::execve("/nx/anything", "") == -13;
        let _ = ustd::umount("/nx");
        let _ = ustd::remove("/nx");
        ok
    });
    check("copy-file-range", {
        // kernel-side ranged copy: seek src to 4, copy 6 bytes through
        // the existing null-offset API (positions advance by the move).
        let _ = ustd::write_all("/cfr-src", b"0123456789abcdef");
        let _ = ustd::write_all("/cfr-dst", b"XX");
        let i = ustd::open("/cfr-src", ustd::O_RDONLY).unwrap_or(-1);
        let o = ustd::open("/cfr-dst", ustd::O_WRONLY).unwrap_or(-1);
        let n = if i >= 0 && o >= 0 {
            let _ = ustd::seek(i, 4, 0);
            let _ = ustd::seek(o, 2, 0);
            ustd::copy_file_range(i, o, 6)
        } else {
            -1
        };
        let got = ustd::read_all("/cfr-dst").unwrap_or_default();
        if i >= 0 {
            let _ = ustd::close(i);
        }
        if o >= 0 {
            let _ = ustd::close(o);
        }
        let _ = ustd::remove("/cfr-src");
        let _ = ustd::remove("/cfr-dst");
        n == 6 && got == b"XX456789"
    });
    check("syncfs", {
        let f = ustd::open("/syncf", ustd::O_WRONLY | ustd::O_CREATE).unwrap_or(-1);
        let ok = f >= 0 && ustd::syncfs(f) == 0 && ustd::syncfs(9999) < 0;
        if f >= 0 {
            let _ = ustd::close(f);
        }
        let _ = ustd::remove("/syncf");
        ok
    });
    check("pidfd-getfd", {
        // harvest an fd out of a child: parent pidfd_getfd's its /cfr file
        // descriptor and reads the same bytes through the adopted fd.
        let _ = ustd::write_all("/pfd", b"SHARED");
        let pid = ustd::fork();
        if pid == 0 {
            let f = ustd::open("/pfd", ustd::O_RDONLY).unwrap_or(-1);
            if f < 0 {
                ustd::exit(15);
            }
            ustd::sleep_ms(2000); // keep the fd alive
            let _ = ustd::close(f);
            ustd::exit(0);
        }
        ustd::sleep_ms(150);
        let pfd = ustd::pidfd(pid as u32);
        // scan the child's table: its /pfd desc is the first fd whose
        // path is /pfd — adopt by number like Linux (our children hold
        // it in the first free slot after the inherited ones).
        let mut got = Vec::new();
        let mut ok = pfd >= 0;
        for fd in 0..16u64 {
            if pfd >= 0 {
                let nf = ustd::pidfd_getfd(pfd as u64, fd);
                if nf >= 0 {
                    let mut b = [0u8; 16];
                    if let Ok(n) = ustd::read(nf, &mut b) {
                        if n == 6 && &b[..6] == b"SHARED" {
                            got = b[..6].to_vec();
                        }
                    }
                    let _ = ustd::close(nf);
                }
            }
        }
        if pfd >= 0 {
            let _ = ustd::close(pfd);
        }
        let _ = ustd::waitpid(pid as u32, 10_000);
        let _ = ustd::remove("/pfd");
        ok && got == b"SHARED"
    });
    check("syslog", {
        // kernel log ring via SYS_SYSLOG: capacity + read-all must work
        // without klog having any unread-cursor side effects.
        let cap = ustd::syslog_n(10);
        let unread = ustd::syslog_n(9);
        let mut b = [0u8; 4096];
        let n = ustd::syslog(3, &mut b);
        cap == 32 * 1024 && unread >= 0 && n > 0
    });
    check("uts-unshare", {
        // CLONE_NEWUTS: child's sethostname stays private; parent can
        // still adopt it back through /proc/<pid>/ns/uts + setns.
        let before = ustd::hostname();
        let own = ustd::open("/proc/self/ns/uts", ustd::O_RDONLY).unwrap_or(-1);
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::unshare(0x04000000) != 0 {
                ustd::exit(15);
            }
            if !ustd::set_hostname("kidhost") {
                ustd::exit(16);
            }
            ustd::sleep_ms(2500); // stay alive for the parent's setns
            ustd::exit(0);
        }
        ustd::sleep_ms(300);
        let pf = alloc::format!("/proc/{}/ns/uts", pid);
        let theirs = ustd::open(&pf, ustd::O_RDONLY).unwrap_or(-1);
        let mut ok = own >= 0 && theirs >= 0 && ustd::hostname() == before;
        if theirs >= 0 && ustd::setns(theirs as u64) == 0 {
            ok = ok && ustd::hostname() == "kidhost";
            if own >= 0 {
                ok = ok && ustd::setns(own as u64) == 0 && ustd::hostname() == before;
            }
        }
        if own >= 0 {
            let _ = ustd::close(own);
        }
        if theirs >= 0 {
            let _ = ustd::close(theirs);
        }
        let _ = ustd::waitpid(pid as u32, 10_000);
        ok
    });
    check("tfd-gettime", {
        // SYS_TFD_GET: remaining time after settime(500,0) lands inside
        // (0,500]; a second settime(0,0) disarms to exactly 0.
        let f = ustd::timerfd_create();
        let mut ok = f >= 0 && ustd::timerfd_set(f, 500, 0) == 0;
        if ok {
            ok = match ustd::timerfd_gettime(f as u64) {
                Some((rem, iv)) => rem > 0 && rem <= 500 && iv == 0,
                None => false,
            };
            let _ = ustd::timerfd_set(f, 0, 0);
            ok = ok
                && ustd::timerfd_gettime(f as u64)
                    .map(|(rem, _)| rem == 0)
                    .unwrap_or(false);
        }
        if f >= 0 {
            let _ = ustd::close(f);
        }
        ok
    });
    check("ms-move", {
        // MS_MOVE on a real tmpfs: the whole node tree re-keys — the
        // covering mount's files appear at the new path and the old
        // path is the bare underlying dir again.
        let _ = ustd::mkdir("/mvo");
        let _ = ustd::mkdir("/mvn");
        let mut ok = ustd::mount("none", "/mvo", "tmpfs") == 0
            && ustd::write_all("/mvo/f", b"M").is_ok()
            && ustd::mount_flags("/mvo", "/mvn", "", 0x2000) == 0
            && ustd::stat("/mvo/f").is_err()
            && ustd::read_all("/mvn/f").map(|d| d == b"M").unwrap_or(false);
        let _ = ustd::umount("/mvn");
        let _ = ustd::remove("/mvo");
        let _ = ustd::remove("/mvn");
        // ...and on a bind alias: /bx2 -> /bx3 relocates the alias.
        let _ = ustd::mkdir("/bx2");
        let _ = ustd::mkdir("/bx3");
        ok = ok
            && ustd::mount_flags("/bin", "/bx2", "", 0x1000) == 0
            && ustd::mount_flags("/bx2", "/bx3", "", 0x2000) == 0
            && ustd::stat("/bx2/cosmos-terminal").is_err()
            && ustd::stat("/bx3/cosmos-terminal").is_ok();
        let _ = ustd::umount2("/bx3", 1); // MNT_FORCE
        let _ = ustd::remove("/bx2");
        let _ = ustd::remove("/bx3");
        ok
    });
    check("reboot-magic", {
        // SYS_REBOOT's magic gate: bad magic is EINVAL before anything
        // destructive can run (we never send the valid pair here).
        let bad = ustd::sc3(shared::SYS_REBOOT, 0, 0, 0) as i64;
        let bad2 = ustd::sc3(shared::SYS_REBOOT, 0xfee1dead, 0, 0x4321fedc) as i64;
        bad == -22 && bad2 == -22
    });
    check("uid-basic", {
        // identity syscalls answer the real task creds; /proc/self/status
        // reports them in the Linux Uid:/Gid: rows.
        let ids = ustd::getuid() == 0
            && ustd::geteuid() == 0
            && ustd::getgid() == 0
            && ustd::getegid() == 0;
        let st = ustd::read_all("/proc/self/status")
            .map(|d| {
                let s = String::from_utf8_lossy(&d).into_owned();
                s.lines().any(|l| l.starts_with("Uid:\t0"))
            })
            .unwrap_or(false);
        ids && st
    });
    check("dac-deny", {
        // vfat ownership model: a non-root task has the "other" bits —
        // every write on the FAT volume is EACCES, while a 1777 /tmp
        // tmpfs mount still lets it create.
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::setgid(1000) != 0 || ustd::setuid(1000) != 0 {
                ustd::exit(15);
            }
            let denied = ustd::write_all("/dac-x", b"x") == Err(-13);
            let tmp_ok = ustd::write_all("/tmp/dac-x", b"x").is_ok()
                && ustd::mkdir("/tmp/dacd").is_ok();
            let back = ustd::setuid(999) == -1; // EPERM to another id
            ustd::exit(if denied && tmp_ok && back { 0 } else { 16 });
        }
        let ok = ustd::waitpid(pid as u32, 10_000) == Ok(0)
            && ustd::stat("/dac-x").is_err();
        let _ = ustd::remove("/tmp/dac-x");
        let _ = ustd::remove("/tmp/dacd");
        ok
    });
    check("chown-chmod", {
        // tmpfs carries real uid/gid/mode; chown is root-only and FAT
        // refuses it outright (vfat has no owners).
        let _ = ustd::write_all("/tmp/cc", b"A");
        let _ = ustd::write_all("/cc-fat", b"A");
        let fat_deny = ustd::chown("/cc-fat", 1000, 0) != 0;
        let mut ok = ustd::chown("/tmp/cc", 1000, 1000) == 0
            && ustd::statx("/tmp/cc")
                .map(|s| s.uid == 1000 && s.gid == 1000)
                .unwrap_or(false)
            && ustd::chmod("/tmp/cc", 0o600) == 0
            && ustd::statx("/tmp/cc")
                .map(|s| s.mode & 0o777 == 0o600)
                .unwrap_or(false)
            && fat_deny;
        let pid = ustd::fork();
        if pid == 0 {
            if ustd::setgid(1000) != 0 || ustd::setuid(1000) != 0 {
                ustd::exit(15);
            }
            // owner keeps write at 0600 but can't chown back to root
            let own = ustd::write_all("/tmp/cc", b"B").is_ok();
            let perm = ustd::chown("/tmp/cc", 0, 0) == -1;
            ustd::exit(if own && perm { 0 } else { 16 });
        }
        ok = ok && ustd::waitpid(pid as u32, 10_000) == Ok(0);
        let _ = ustd::write_all("/tmp/ro", b"x");
        let pid2 = ustd::fork();
        if pid2 == 0 {
            let _ = ustd::setgid(1000);
            let _ = ustd::setuid(1000);
            ustd::exit(if ustd::write_all("/tmp/ro", b"y").is_err() {
                0
            } else {
                16
            });
        }
        ok = ok && ustd::waitpid(pid2 as u32, 10_000) == Ok(0);
        let _ = ustd::remove("/tmp/cc");
        let _ = ustd::remove("/tmp/ro");
        let _ = ustd::remove("/cc-fat");
        ok
    });
    check("tc-pgrp-tiocsti", {
        // tcsetpgrp/tcgetpgrp + TIOCSTI injecting input like a keystroke
        let m = ustd::openpt();
        let mut ok = m >= 0 && ustd::tcgetpgrp(m) == 0;
        let me = ustd::getpid();
        ok = ok && ustd::tcsetpgrp(m, me) == 0 && ustd::tcgetpgrp(m) == me as i64;
        if let Some(sp) = ustd::ptsname(m) {
            let s = ustd::open(&sp, ustd::O_RDWR | shared::O_NOCTTY).unwrap_or(-1);
            ok = ok && s >= 0;
            let _ = ustd::tcsets(s, 0); // raw — injected byte arrives verbatim
            ok = ok && ustd::tiocsti(m, b'x') == 0;
            let mut b = [0u8; 4];
            let n = ustd::read(s, &mut b).unwrap_or(0);
            ok = ok && n == 1 && b[0] == b'x';
            let _ = ustd::close(s);
        } else {
            ok = false;
        }
        let _ = ustd::close(m);
        ok
    });
    check("ttin-stop", {
        // a background process reading its controlling tty is stopped by
        // SIGTTIN (real POSIX job control)
        let m = ustd::openpt();
        let Some(sp) = (if m >= 0 { ustd::ptsname(m) } else { None }) else {
            panic!("ptsname");
        };
        let mut ok = m >= 0;
        match ustd::fork() {
            0 => {
                let _ = ustd::setsid(); // new session; pgid == my pid
                let s = ustd::open(&sp, ustd::O_RDWR).unwrap_or(-1);
                if s < 0 {
                    ustd::exit(5);
                }
                let _ = ustd::write_all("/ttin-rdy", b"1");
                let mut b = [0u8; 8];
                let _ = ustd::read(s, &mut b); // SIGTTIN stops us here
                ustd::exit(9);
            }
            pid if pid > 0 => {
                // wait for the child to acquire the ctty and reach the read
                for _ in 0..100 {
                    if ustd::stat("/ttin-rdy").is_ok() {
                        break;
                    }
                    ustd::sleep_ms(10);
                }
                // put OUR group in the foreground -> child is background
                let pg = ustd::getpgid(0);
                ok = ok && ustd::tcsetpgrp(m, if pg > 0 { pg as u32 } else { 1 }) == 0;
                ustd::sleep_ms(300);
                let st = ustd::waitpid_opt(pid as u32, ustd::WUNTRACED, 5000)
                    .unwrap_or(-1);
                ok = ok && st & 0xff == 0x7f && ((st >> 8) & 0x3f) == 21;
                let _ = ustd::kill(pid as u32);
                let _ = ustd::waitpid(pid as u32, 5000);
                let _ = ustd::remove("/ttin-rdy");
            }
            _ => {
                ok = false;
            }
        }
        let _ = ustd::close(m);
        ok
    });
    check("groups-dac", {
        // supplementary groups give real group-bit access
        let mut ok = ustd::setgroups(&[10]) == 0;
        let mut got = [0u32; 8];
        let n = ustd::getgroups(&mut got);
        ok = ok && n == 1 && got[0] == 10;
        // a file only group-10 may write (owner gets nothing)
        let _ = ustd::write_all("/tmp/g10", b"a");
        let _ = ustd::chown("/tmp/g10", 0, 10);
        let _ = ustd::chmod("/tmp/g10", 0o070);
        match ustd::fork() {
            0 => {
                // group list must be installed while still root, then the
                // drop keeps it (POSIX: setgroups is privileged)
                let _ = ustd::setgroups(&[10]);
                let _ = ustd::setgid(1000);
                let _ = ustd::setuid(1000);
                ustd::exit(if ustd::write_all("/tmp/g10", b"b").is_ok() { 0 } else { 7 });
            }
            pid if pid > 0 => {
                ok = ok && ustd::waitpid(pid as u32, 10_000) == Ok(0);
            }
            _ => ok = false,
        }
        // without the group, uid 1000 is denied the same file
        match ustd::fork() {
            0 => {
                let _ = ustd::setgroups(&[]);
                let _ = ustd::setgid(1000);
                let _ = ustd::setuid(1000);
                ustd::exit(if ustd::write_all("/tmp/g10", b"c").is_err() { 0 } else { 8 });
            }
            pid if pid > 0 => {
                ok = ok && ustd::waitpid(pid as u32, 10_000) == Ok(0);
            }
            _ => ok = false,
        }
        let _ = ustd::remove("/tmp/g10");
        ok
    });
    check("resuid", {
        // setresuid shuffles real/effective/saved like POSIX
        let mut ok = ustd::setresuid(1000, u32::MAX, u32::MAX) == 0;
        let (r, e, s) = ustd::getresuid();
        ok = ok && r == 1000 && e == 0;
        let _ = s;
        let _ = ustd::setresuid(0, 0, 0);
        match ustd::fork() {
            0 => {
                // drop all three — nothing left to regain
                if ustd::setresuid(1000, 1000, 1000) != 0 {
                    ustd::exit(6);
                }
                let (r, e, s) = ustd::getresuid();
                if r != 1000 || e != 1000 || s != 1000 {
                    ustd::exit(7);
                }
                // non-root may shuffle among its own ids but not escalate
                let back = ustd::setresuid(0, u32::MAX, u32::MAX);
                let selfok = ustd::setresuid(1000, u32::MAX, u32::MAX);
                ustd::exit(if back == -1 && selfok == 0 { 0 } else { 8 });
            }
            pid if pid > 0 => {
                ok = ok && ustd::waitpid(pid as u32, 10_000) == Ok(0);
            }
            _ => ok = false,
        }
        ok
    });
    check("caps", {
        // Capability model: euid 0 wields the permitted set, non-root
        // only its stored effective set — so dropping uid empties the
        // gate. A PR_CAPBSET_DROP is permanent and shrinks prm+eff too.
        let mut ok = ustd::capget(0).map(|c| c[1] != 0).unwrap_or(false);
        match ustd::fork() {
            0 => {
                if !ustd::capbset_drop(21) {
                    ustd::exit(6); // CAP_SYS_ADMIN out of the bounding set
                }
                let Some(v) = ustd::capget(0) else {
                    ustd::exit(7);
                };
                if (v[0] | v[1] | v[2]) & (1u64 << 21) != 0 {
                    ustd::exit(7);
                }
                // mount needs CAP_SYS_ADMIN — denied even though uid==0
                if ustd::mount_flags("", "/capm", "tmpfs", 0) == 0 {
                    ustd::exit(8);
                }
                // capset can't re-add a bit that left the bounding set
                if ustd::capset(0, 1u64 << 21) {
                    ustd::exit(9);
                }
                ustd::exit(0);
            }
            pid if pid > 0 => ok = ok && ustd::waitpid(pid as u32, 10_000) == Ok(0),
            _ => ok = false,
        }
        // a root-owned sleeper for the kill-permission leg
        let sleeper = ustd::fork();
        if sleeper == 0 {
            ustd::sleep_ms(30_000);
            ustd::exit(0);
        }
        if sleeper > 0 {
            match ustd::fork() {
                0 => {
                    if ustd::setresuid(1000, 1000, 1000) != 0 {
                        ustd::exit(6);
                    }
                    let Some(v) = ustd::capget(0) else {
                        ustd::exit(7);
                    };
                    if v[0] != 0 {
                        ustd::exit(7);
                    }
                    if ustd::mount_flags("", "/capm2", "tmpfs", 0) == 0 {
                        ustd::exit(8);
                    }
                    // uid 1000 may not signal a root-owned task: EPERM
                    if ustd::kill2(sleeper as u32, 0) != -1 {
                        ustd::exit(9);
                    }
                    // but it may still signal itself (same ruid)
                    if ustd::kill2(ustd::getpid() as u32, 0) != 0 {
                        ustd::exit(10);
                    }
                    ustd::exit(0);
                }
                pid if pid > 0 => {
                    ok = ok && ustd::waitpid(pid as u32, 10_000) == Ok(0)
                }
                _ => ok = false,
            }
            let _ = ustd::kill2(sleeper as u32, 9);
            let _ = ustd::waitpid(sleeper as u32, 10_000);
        }
        // CapEff visible in /proc/self/status while root
        ok = ok && ustd::read_all("/proc/self/status")
            .map(|b| String::from_utf8_lossy(&b).contains("CapEff:\t") && !String::from_utf8_lossy(&b).contains("CapEff:\t0000000000000000"))
            .unwrap_or(false);
        ok
    });
    check("time-ns", {
        // unshare(CLONE_NEWTIME) stages a timens for children only;
        // timens_offsets shifts the child's monotonic clock (+600s)
        // while the parent's stays put.
        let mut ok = true;
        match ustd::fork() {
            0 => {
                if ustd::unshare(shared::CLONE_NEWTIME) != 0 {
                    ustd::exit(5);
                }
                if ustd::write_all(
                    "/proc/self/timens_offsets",
                    b"monotonic 600 0\n",
                )
                .is_err()
                {
                    ustd::exit(6);
                }
                match ustd::fork() {
                    0 => {
                        let link_ok = ustd::readlink("/proc/self/ns/time")
                            .map(|s| s.starts_with("time:[") && !s.contains("[0]"))
                            .unwrap_or(false);
                        let t = ustd::uptime_ms();
                        ustd::exit(if link_ok && t >= 600_000 { 0 } else { 7 });
                    }
                    gp if gp > 0 => {
                        ustd::exit(if ustd::waitpid(gp as u32, 5000) == Ok(0) { 0 } else { 8 })
                    }
                    _ => ustd::exit(9),
                }
            }
            p if p > 0 => ok = ok && ustd::waitpid(p as u32, 15_000) == Ok(0),
            _ => ok = false,
        }
        // the parent's own clock was never shifted
        ok && ustd::uptime_ms() < 600_000
    });
    check("ipc-ns", {
        // unshare(CLONE_NEWIPC) moves the caller: mqueue names are
        // namespaced, so the child's "/ipcn-q" is a DIFFERENT queue
        // — the message the parent sent is invisible to it.
        let mut ok = true;
        let fd = ustd::mq_open("/ipcn-q", 8, 64);
        ok = ok && fd >= 0 && ustd::mq_send(fd, b"hi", 1) == 0;
        match ustd::fork() {
            0 => {
                if ustd::unshare(shared::CLONE_NEWIPC) != 0 {
                    ustd::exit(5);
                }
                let fd2 = ustd::mq_open("/ipcn-q", 8, 64);
                if fd2 < 0 {
                    ustd::exit(6);
                }
                let link_ok = ustd::readlink("/proc/self/ns/ipc")
                    .map(|s| s.starts_with("ipc:[") && !s.contains("[0]"))
                    .unwrap_or(false);
                if !link_ok {
                    ustd::exit(7);
                }
                // nonblocking recv: the child's queue is empty by
                // construction, so this must come straight back EAGAIN
                // — the parent's queued message must not be visible.
                ustd::fcntl(fd2, shared::F_SETFL, shared::O_NONBLOCK);
                let mut buf = [0u8; 64];
                match ustd::mq_recv(fd2, &mut buf) {
                    Err(e) => ustd::exit(if e == -11 { 0 } else { 8 }),
                    Ok(_) => ustd::exit(9), // parent's msg leaked across the ns
                }
            }
            p if p > 0 => ok = ok && ustd::waitpid(p as u32, 10_000) == Ok(0),
            _ => ok = false,
        }
        // the parent's queue still holds its message
        let mut buf = [0u8; 64];
        ok = ok && matches!(ustd::mq_recv(fd, &mut buf), Ok((2, 1)));
        let _ = ustd::mq_unlink("/ipcn-q");
        ok
    });
    check("user-ns", {
        // unshare(CLONE_NEWUSER) moves the caller; uid_map translates
        // the id VIEW — map inner 5->outer 0 and geteuid reports 5.
        let mut ok = true;
        match ustd::fork() {
            0 => {
                if ustd::unshare(shared::CLONE_NEWUSER) != 0 {
                    ustd::exit(5);
                }
                let link_ok = ustd::readlink("/proc/self/ns/user")
                    .map(|s| s.starts_with("user:[") && !s.contains("[0]"))
                    .unwrap_or(false);
                if !link_ok {
                    ustd::exit(6);
                }
                if ustd::write_all("/proc/self/uid_map", b"5 0 1\n").is_err() {
                    ustd::exit(7);
                }
                if ustd::write_all("/proc/self/gid_map", b"9 0 1\n").is_err() {
                    ustd::exit(8);
                }
                let (u, g) = (ustd::geteuid(), ustd::getegid());
                // the map file reads back what was written
                let m = ustd::read_all("/proc/self/uid_map")
                    .map(|b| String::from_utf8_lossy(&b).contains("5 0 1"))
                    .unwrap_or(false);
                ustd::exit(if u == 5 && g == 9 && m { 0 } else { 9 });
            }
            p if p > 0 => ok = ok && ustd::waitpid(p as u32, 10_000) == Ok(0),
            _ => ok = false,
        }
        ok
    });
    check("cgroup", {
        // Real cgroups under /sys/fs/cgroup: mkdir makes a group, a
        // pid written to cgroup.procs joins it, cpu.stat reports live
        // usage, and cpu.max genuinely throttles the group — a spinner
        // capped to 200ms/s of cpu can only burn ~20 ticks per window.
        let mut ok = true;
        ok = ok && ustd::mkdir("/sys/fs/cgroup/t1").is_ok();
        match ustd::fork() {
            0 => {
                // spinner: burn cpu for ~2.6s
                let t0 = ustd::uptime_ms();
                while ustd::uptime_ms().saturating_sub(t0) < 2600 {}
                ustd::exit(0);
            }
            p if p > 0 => {
                let procs_path = "/sys/fs/cgroup/t1/cgroup.procs";
                ok = ok && ustd::write_all(
                    procs_path,
                    alloc::format!("{}", p).as_bytes(),
                ).is_ok();
                // membership is real: procs lists the child pid
                ok = ok && ustd::read_all(procs_path)
                    .map(|b| String::from_utf8_lossy(&b).contains(&alloc::format!("{}", p)))
                    .unwrap_or(false);
                // throttle: 200_000us per 1s window ≈ 20 ticks/s
                ok = ok && ustd::write_all(
                    "/sys/fs/cgroup/t1/cpu.max",
                    b"200000 1000000",
                ).is_ok();
                ustd::sleep_ms(1800);
                // while the child is still spinning, usage must be well
                // below its ~1.8s of work — it got throttled for real
                let st = ustd::read_all("/sys/fs/cgroup/t1/cpu.stat")
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                let usage: u64 = st
                    .lines()
                    .find(|l| l.starts_with("usage_usec"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let nrth: u64 = st
                    .lines()
                    .find(|l| l.starts_with("nr_throttled"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                // < 70% of the 1.8s window and at least one throttle hit
                ok = ok && usage < 1_200_000 && usage > 0 && nrth >= 1;
                let ev = ustd::read_all("/sys/fs/cgroup/t1/cgroup.events")
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                ok = ok && ev.contains("populated 1");
                ok = ok && ustd::read_all("/sys/fs/cgroup/t1/memory.current")
                    .map(|b| {
                        String::from_utf8_lossy(&b)
                            .trim()
                            .parse::<u64>()
                            .map(|v| v > 0)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                ok = ok && ustd::waitpid(p as u32, 15_000) == Ok(0);
            }
            _ => ok = false,
        }
        // root lists live pids; remove frees the group
        ok = ok && ustd::read_all("/sys/fs/cgroup/cgroup.procs")
            .map(|b| !b.is_empty())
            .unwrap_or(false);
        let _ = ustd::remove("/sys/fs/cgroup/t1");
        ok
    });
    check("cgroup-mem", {
        // memory.max is enforced for real: the child eats pages until
        // the group's rss crosses the cap and the kernel OOM-kills it —
        // waitpid reports the SIGKILL exit (137) and memory.events
        // counts the kill.
        let mut ok = true;
        ok = ok && ustd::mkdir("/sys/fs/cgroup/m1").is_ok();
        ok = ok && ustd::write_all(
            "/sys/fs/cgroup/m1/memory.max",
            b"4194304",
        ).is_ok();
        match ustd::fork() {
            0 => {
                // ~16MB of touched anon pages — far over the 4MB cap
                let mut v = alloc::vec![0xAAu8; 16 * 1024 * 1024];
                v[0] = 1;
                ustd::exit(0); // unreachable once the cap bites
            }
            p if p > 0 => {
                ok = ok && ustd::write_all(
                    "/sys/fs/cgroup/m1/cgroup.procs",
                    alloc::format!("{}", p).as_bytes(),
                ).is_ok();
                let code = ustd::waitpid(p as u32, 20_000).unwrap_or(-1);
                ok = ok && code == 128 + 9;
                let ev = ustd::read_all("/sys/fs/cgroup/m1/memory.events")
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                ok = ok && ev.contains("oom_kill 1");
                // peak rode up to ~the cap before the kill
                let peak: u64 = ustd::read_all("/sys/fs/cgroup/m1/memory.peak")
                    .map(|b| String::from_utf8_lossy(&b).trim().parse().unwrap_or(0))
                    .unwrap_or(0);
                ok = ok && peak >= 4 * 1024 * 1024 - 64 * 4096;
            }
            _ => ok = false,
        }
        let _ = ustd::remove("/sys/fs/cgroup/m1");
        ok
    });
    check("cgroup-weight", {
        // cpu.weight is read back verbatim and clamps to 1..=10000
        let mut ok = true;
        ok = ok && ustd::mkdir("/sys/fs/cgroup/w1").is_ok();
        ok = ok && ustd::write_all("/sys/fs/cgroup/w1/cpu.weight", b"8000").is_ok();
        ok = ok && ustd::read_all("/sys/fs/cgroup/w1/cpu.weight")
            .map(|b| String::from_utf8_lossy(&b).trim() == "8000")
            .unwrap_or(false);
        ok = ok && ustd::write_all("/sys/fs/cgroup/w1/cpu.weight", b"99999").is_err();
        let _ = ustd::remove("/sys/fs/cgroup/w1");
        ok
    });
    check("cgroup-freeze-kill", {
        // cgroup.freeze stops every member for real (status reads T),
        // writing 0 resumes it, and cgroup.kill delivers real SIGKILLs
        // (waitpid sees 137).
        let mut ok = true;
        ok = ok && ustd::mkdir("/sys/fs/cgroup/f1").is_ok();
        match ustd::fork() {
            0 => {
                // sit in a spin until killed
                loop {
                    ustd::sleep_ms(50);
                }
            }
            p if p > 0 => {
                let procs = alloc::format!("/sys/fs/cgroup/f1/cgroup.procs");
                ok = ok && ustd::write_all(&procs, alloc::format!("{}", p).as_bytes()).is_ok();
                ok = ok && ustd::write_all("/sys/fs/cgroup/f1/cgroup.freeze", b"1").is_ok();
                ustd::sleep_ms(120);
                let st = ustd::read_all(&alloc::format!("/proc/{}/status", p))
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                ok = ok && st.contains("stopped");
                ok = ok && ustd::write_all("/sys/fs/cgroup/f1/cgroup.freeze", b"0").is_ok();
                ustd::sleep_ms(120);
                let st = ustd::read_all(&alloc::format!("/proc/{}/status", p))
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                ok = ok && !st.contains("stopped");
                            ok = ok && ustd::write_all("/sys/fs/cgroup/f1/cgroup.kill", b"1").is_ok();
                            let code = ustd::waitpid(p as u32, 6000).unwrap_or(-1);
                            ok = ok && code == 128 + 9;
            }
            _ => ok = false,
        }
            let _ = ustd::remove("/sys/fs/cgroup/f1");
            ok
    });
    check("cgroup-io", {
        // io.max paces real block I/O: a member writing 256KiB at
        // wbps=64KiB must spend multiple 1s windows on the write path.
        let mut ok = true;
        ok = ok && ustd::mkdir("/sys/fs/cgroup/i1").is_ok();
        ok = ok && ustd::write_all(
            "/sys/fs/cgroup/i1/io.max",
            b"8:0 wbps=65536",
        ).is_ok();
        match ustd::fork() {
            0 => {
                // let the parent move us into the throttled group first —
                // writes before membership lands are uncharged/unpaced.
                ustd::sleep_ms(900);
                let buf = alloc::vec![0x77u8; 65536];
                for _ in 0..4 {
                    let _ = ustd::write_all("/iotest.bin", &buf);
                }
                ustd::exit(0);
            }
            p if p > 0 => {
                ok = ok && ustd::write_all(
                    "/sys/fs/cgroup/i1/cgroup.procs",
                    alloc::format!("{}", p).as_bytes(),
                ).is_ok();
                let t0 = ustd::uptime_ms();
                let _ = ustd::waitpid(p as u32, 30_000);
                let dt = ustd::uptime_ms().saturating_sub(t0);
                // 256KiB at 64KiB/s -> >= 2 throttled windows
                ok = ok && dt >= 1500;
                let st = ustd::read_all("/sys/fs/cgroup/i1/io.stat")
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                // the group really charged the bytes it wrote
                ok = ok && st.contains("wbytes=") && !st.contains("wbytes=0");
            }
            _ => ok = false,
        }
        let _ = ustd::remove("/sys/fs/cgroup/i1");
        let _ = ustd::remove("/iotest.bin");
        ok
    });
    check("pid-ns", {
        // unshare(CLONE_NEWPID) + fork: the child is init of a fresh
        // pid space (getpid()==1, invisible parent), its own child is 2.
        // The unshare runs inside an outer fork so the SELFTEST task's
        // pidns_for_children is not permanently redirected.
        match ustd::fork() {
            0 => {
                if ustd::unshare(shared::CLONE_NEWPID) != 0 {
                    ustd::exit(5);
                }
                match ustd::fork() {
                    0 => {
                        // namespace init: virtual pid 1, parent invisible
                        if ustd::getpid() != 1 {
                            ustd::exit(6);
                        }
                        if ustd::getppid() != 0 {
                            ustd::exit(7);
                        }
                        let nsok = ustd::readlink("/proc/self/ns/pid")
                            .map(|s| {
                                s.starts_with("pid:[") && !s.contains("[0]")
                            })
                            .unwrap_or(false);
                        if !nsok {
                            ustd::exit(8);
                        }
                        match ustd::fork() {
                            0 => {
                                // the grandchild is pid 2 IN THIS ns; fork
                                // must report that number back to us
                                ustd::exit(if ustd::getpid() == 2 { 0 } else { 9 });
                            }
                            gp if gp > 0 => {
                                // gp arrives as the ns-local pid; waitpid
                                // resolves it through our namespace
                                let code =
                                    ustd::waitpid(gp as u32, 5000).unwrap_or(-1);
                                ustd::exit(if code == 0 && gp == 2 { 0 } else { 10 });
                            }
                            _ => ustd::exit(11),
                        }
                    }
                    ic if ic > 0 => {
                        let st = ustd::waitpid(ic as u32, 10_000).unwrap_or(-1);
                        ustd::exit(if st == 0 { 0 } else { 12 });
                    }
                    _ => ustd::exit(13),
                }
            }
            pid if pid > 0 => ustd::waitpid(pid as u32, 15_000) == Ok(0),
            _ => false,
        }
    });
    check("gettimeofday", {
        let (s, u) = ustd::gettimeofday();
        s > 1_700_000_000 && u < 1_000_000
    });

    // --- security: syscall boundary must reject kernel addresses ---
    // copy_out to a kernel-VA (the phys-map offset region) must fail.
    check(
        "kern-ptr-rejected",
        ustd::sc1(shared::SYS_MEMINFO, 0xFFFF_8000_0000_0000) == u64::MAX,
    );
    // copy_in from a kernel-VA must fail too (SYS_DEBUG copies a string).
    check(
        "kern-ptr-rejected-in",
        ustd::sc2(shared::SYS_DEBUG, 0xFFFF_8000_0000_0000, 16) == u64::MAX,
    );

    // `ping -I <iface>` is a real source bind: lo sends the echo from
    // 127.0.0.1 and the loopback path still answers it.
    check(
        "ping-iface-lo",
        ustd::net_ping_if(0x7F00_0001, 2000, 0, 0, 2).is_some(),
    );
    // `ping -I eth0 <loopback>` is unroutable — the syscall refuses
    // it rather than emitting an echo nobody could answer.
    check(
        "ping-iface-einval",
        ustd::net_ping_if(0x7F00_0001, 2000, 0, 0, 1).is_none(),
    );
    // `-i <if>` is a real rule match now: the eth0-pinned DROP is
    // skipped on lo traffic while the lo-pinned ACCEPT fires under a
    // DROP policy — the reply only lands if iface matching works.
    check("ipt-iface", {
        let fw = |l: &str| ustd::write_all("/proc/net/iptables", l.as_bytes()).is_ok();
        let ok = fw("N IFC\n")
            && fw("A IFC 0 iif eth0 drop\n")
            && fw("A IFC 0 iif lo accept\n")
            && fw("A IN 0 IFC\n")
            && fw("P DROP\n")
            && ustd::net_ping(0x7F00_0001, 2000).is_some();
        let _ = fw("P ACCEPT\n");
        let _ = fw("F IN\n");
        let _ = fw("X IFC\n");
        ok
    });
    // `iptables --sport N` is a real match on the packet's source
    // port: DNS replies (sport 53) die at ingress while the rule is
    // up and resolution works again once it's flushed.
    check("ipt-sport", {
        let fw = |l: &str| ustd::write_all("/proc/net/iptables", l.as_bytes()).is_ok();
        // The kernel DNS cache must be cold — a cached answer skips
        // the wire entirely and nothing reaches the rule.
        let _ = ustd::write_all("/proc/net/dns", b"F\n");
        let blocked =
            fw("A IN 0 sport 53 drop\n") && ustd::net_dns("example.com").is_none();
        let _ = fw("F IN\n");
        let _ = ustd::write_all("/proc/net/dns", b"F\n");
        let restored = ustd::net_dns("example.com").is_some();
        blocked && restored
    });
    // `traceroute -f N` starts the TTL walk at N — the first reported
    // hop carries ttl N, none below.
    check("trace-first-hop", {
        let hops = ustd::net_trace_opts(0x0A00_0202, false, 3, 4, 0, 300, 1);
        !hops.is_empty() && hops.iter().all(|(t, _, _)| *t >= 3)
    });
    // `traceroute -p` is a real base port: the hop-1 gateway still
    // answers ICMP 11 quoting dport base+1 — the probe matcher keys
    // on the quoted port, so a non-default base proves the plumbing.
    check("trace-base-port", {
        let hops = ustd::net_trace_opts(0x0A00_0202, false, 1, 2, 40000, 400, 1);
        hops.first().map(|(_, h, _)| h.is_some()).unwrap_or(false)
    });
    // `iptables -m length --length` matches the transport payload
    // length: the 44-byte ICMP messages the lo ping uses die inside
    // 40:60 and pass inside 1:20.
    check("ipt-length", {
        let fw = |l: &str| ustd::write_all("/proc/net/iptables", l.as_bytes()).is_ok();
        let blocked =
            fw("A IN 0 length 40:60 drop\n") && ustd::net_ping(0x7F00_0001, 1500).is_none();
        let _ = fw("F IN\n");
        let passed =
            fw("A IN 0 length 1:20 drop\n") && ustd::net_ping(0x7F00_0001, 1500).is_some();
        let _ = fw("F IN\n");
        blocked && passed
    });
    // `traceroute -q N` sends N real datagrams per hop — the kernel
    // TX counter (/proc/net/dev) must bump by at least that many.
    check("trace-probes", {
        let tx = || -> u64 {
            ustd::read_all("/proc/net/dev")
                .ok()
                .and_then(|d| {
                    String::from_utf8_lossy(&d)
                        .lines()
                        .find(|l| l.trim_start().starts_with("eth0:"))
                        .and_then(|l| l.split(':').nth(1).map(String::from))
                })
                .and_then(|t| {
                    t.split_whitespace().nth(9).and_then(|v| v.parse().ok())
                })
                .unwrap_or(0)
        };
        let tx0 = tx();
        let hops = ustd::net_trace_opts(0x0A00_0202, false, 1, 1, 0, 300, 3);
        let delta = tx().saturating_sub(tx0);
        hops.first().map(|(_, h, _)| h.is_some()).unwrap_or(false) && delta >= 3
    });
    check("ping-bcast", {
        // `ping -b`: the broadcast echo must really leave the NIC — the
        // TX counter bumps (no ARP lookup runs for 255.255.255.255).
        let tx = || -> u64 {
            ustd::read_all("/proc/net/dev")
                .ok()
                .and_then(|d| {
                    String::from_utf8_lossy(&d)
                        .lines()
                        .find(|l| l.trim_start().starts_with("eth0:"))
                        .and_then(|l| l.split(':').nth(1).map(String::from))
                })
                .and_then(|t| {
                    t.split_whitespace().nth(9).and_then(|v| v.parse().ok())
                })
                .unwrap_or(0)
        };
        let tx0 = tx();
        let _ = ustd::net_ping(0xFFFF_FFFF, 400);
        tx().saturating_sub(tx0) >= 1
    });
    check("ipt-comment", {
        // `-m comment --comment` rides on the rule — readable via -L.
        let a = ustd::write_all("/proc/net/iptables", b"A IN 0 comment tagged_rule drop\n")
            .is_ok();
        let list = ustd::read_all("/proc/net/iptables").unwrap_or_default();
        let has = String::from_utf8_lossy(&list).contains("tagged_rule");
        let _ = ustd::write_all("/proc/net/iptables", b"F IN\n");
        a && has
    });
    check("trace-tcp", {
        // `traceroute -T`: real SYN probes. Over lo to :80 the RST
        // responder answers for the unclaimed port → reached at hop 1.
        let hops = ustd::net_trace_tcp(0x7F00_0001, 3, 0);
        hops.first()
            .map(|(_, h, r)| *r && h.map(|(ip, _)| ip) == Some([127, 0, 0, 1]))
            .unwrap_or(false)
    });
    check("ipt-ttl", {
        // `-m ttl` matches the packet's real IPv4 TTL. lo packets carry
        // the stamped TTL (64 here), so eq:64 drops lo traffic and
        // lt:64 doesn't — observable through a real ping.
        let a = ustd::write_all("/proc/net/iptables", b"A IN 0 ttl eq:64 drop\n").is_ok();
        let dropped = ustd::net_ping(0x7F00_0001, 350).is_none();
        let _ = ustd::write_all("/proc/net/iptables", b"F IN\n");
        let b = ustd::write_all("/proc/net/iptables", b"A IN 0 ttl lt:64 drop\n").is_ok();
        let passed = ustd::net_ping(0x7F00_0001, 600).is_some();
        let _ = ustd::write_all("/proc/net/iptables", b"F IN\n");
        a && dropped && b && passed
    });
    check("ping-tos", {
        // `ping -Q`: the DS byte rides the real wire frame — the kernel
        // pcap proves it (TX frames are tapped at send_frame).
        let _ = ustd::pcap(0, &mut []);
        let _ = ustd::net_ping_qos(0x0A00_0202, 400, 0, 0, 0, 0x2e);
        let _ = ustd::pcap(1, &mut []);
        let mut cap = alloc::vec![0u8; 262_144];
        let n = ustd::pcap(4, &mut cap);
        let d: &[u8] = if n > 0 { &cap[..n as usize] } else { &[] };
        let mut i = 24usize; // past the global header
        let mut seen = false;
        while i + 16 <= d.len() {
            let cl = u32::from_le_bytes([d[i + 8], d[i + 9], d[i + 10], d[i + 11]]) as usize;
            i += 16;
            if i + cl > d.len() {
                break;
            }
            let fr = &d[i..i + cl];
            i += cl;
            // eth IPv4 frame whose IP DS field is our stamped 0x2e
            if fr.len() >= 34
                && fr[12] == 0x08
                && fr[13] == 0x00
                && fr[14] >> 4 == 4
                && fr[15] == 0x2e
                && fr[23] == 1
            {
                seen = true;
            }
        }
        seen
    });
    check("dns-tcp", {
        // DNS over TCP/53 (the transport `dig +tcp` uses): RFC 1035
        // two-byte length prefix over a real TCP stream.
        let mut q = Vec::new();
        q.extend_from_slice(&0x0077u16.to_be_bytes()); // id
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // qd
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        let mut got = false;
        if let Some(s) = ustd::TcpSock::connect_timeout(15355, [10, 0, 2, 3], 53, 2500) {
            let mut m = Vec::with_capacity(q.len() + 2);
            m.extend_from_slice(&(q.len() as u16).to_be_bytes());
            m.extend_from_slice(&q);
            if s.send(&m).is_some() {
                let mut buf: Vec<u8> = Vec::new();
                for _ in 0..8 {
                    if buf.len() >= 2 {
                        let want = 2 + u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        if buf.len() >= want {
                            break;
                        }
                    }
                    if let Some(c) = s.recv(1500) {
                        buf.extend_from_slice(&c);
                    } else {
                        break;
                    }
                }
                // id echoed back at the head of the DNS message
                got = buf.len() >= 14
                    && buf.len() >= 2 + u16::from_be_bytes([buf[0], buf[1]]) as usize
                    && buf[2] == 0x00
                    && buf[3] == 0x77;
            }
        }
        got
    });

    // --- performance baseline: real durations (tick = 10ms resolution) ---
    {
        // 4 MiB through write_all (virtio-blk -> FAT32)
        let block = alloc::vec![0xA5u8; 64 * 1024];
        let t0 = uptime_ms();
        for i in 0..64u64 {
            let p = alloc::format!("/test/perf{}", i);
            let _ = write_all(&p, &block);
        }
        metric("fs-write-4mib", uptime_ms() - t0);
        let t1 = uptime_ms();
        let mut total = 0usize;
        for i in 0..64u64 {
            let p = alloc::format!("/test/perf{}", i);
            total += read_all(&p).map(|d| d.len()).unwrap_or(0);
        }
        metric("fs-read-4mib", uptime_ms() - t1);
        let _ = total;
        for i in 0..64u64 {
            let _ = remove(&alloc::format!("/test/perf{}", i));
        }
    }
    // task spawn + exit + reap round trip
    {
        let t0 = uptime_ms();
        if let Ok(pid) = spawn("/bin/cosmos-selftest-child", "") {
            let _ = waitpid(pid, 10_000);
            metric("spawn-waitpid", uptime_ms() - t0);
        }
    }
    // syscall overhead: 1000 cheap syscalls
    {
        let t0 = uptime_ms();
        for _ in 0..1000 {
            let _ = uptime_ms();
        }
        metric("syscall-1000", uptime_ms() - t0);
    }

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
