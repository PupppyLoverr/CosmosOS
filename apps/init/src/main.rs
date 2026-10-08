//! init: first userspace process + service supervisor. Spawns the window
//! server (or the selftest harness when /selftest.flag exists), then runs
//! a real init loop: waitpid_any() reaps children instantly, services from
//! /etc/rc.conf respawn on death with a 5-per-minute throttle.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ustd::{println, sleep_ms, spawn};

struct Svc {
    name: String,
    path: String,
    pid: u32,
    deaths: u32,
    window_start: u64,
    dead: bool,
}

/// Parse `service <name> <path>` lines out of rc.conf text.
fn parse_rc(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        if f.next() == Some("service") {
            if let (Some(n), Some(p)) = (f.next(), f.next()) {
                out.push((String::from(n), String::from(p)));
            }
        }
    }
    out
}

#[unsafe(no_mangle)]
extern "C" fn user_main(args_ptr: u64, args_len: u64) -> i64 {
    let args = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize))
    };
    let selftest = args.contains("selftest") || ustd::stat("/selftest.flag").is_ok();
    println!("[init] cosmos init (selftest={})", selftest);

    // /tmp is a real tmpfs mount when the dir exists (or can be made).
    // Best-effort: keep going if the mount fails.
    let _ = ustd::mkdirat(ustd::AT_FDCWD, "/tmp");
    match ustd::mount("tmpfs", "/tmp", "tmpfs") {
        0 => {
            println!("[init] tmpfs on /tmp");
            // real /tmp semantics: world-writable + sticky
            let _ = ustd::chmod("/tmp", 0o1777);
        }
        e => println!("[init] tmpfs on /tmp failed: {}", e),
    }

    let mut services: Vec<Svc> = Vec::new();
    if selftest {
        match spawn("/bin/cosmos-selftest", "") {
            Ok(pid) => println!("[init] selftest pid={}", pid),
            Err(_) => println!("[init] FAILED to spawn selftest"),
        }
    } else {
        // service table from /etc/rc.conf; the window server is the
        // fallback when the file is missing or lists nothing
        let entries = ustd::read_all("/etc/rc.conf")
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .map(|t| parse_rc(&t))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                alloc::vec![(String::from("winserver"), String::from("/bin/cosmos-winserver"))]
            });
        for (name, path) in entries {
            match spawn(&path, "") {
                Ok(pid) => {
                    println!("[init] {} pid={}", name, pid);
                    services.push(Svc {
                        name,
                        path,
                        pid,
                        deaths: 0,
                        window_start: 0,
                        dead: false,
                    });
                }
                Err(_) => println!("[init] FAILED to spawn {}", name),
            }
        }
    }

    // real init loop: block on child death, respawn supervised services.
    // throttle: 5 deaths inside 60s -> stop respawning that service.
    loop {
        match ustd::waitpid_any(30_000) {
            Ok((pid, status)) => {
                let Some(s) = services.iter_mut().find(|s| s.pid == pid) else {
                    continue; // not a supervised child (e.g. selftest)
                };
                let now = ustd::uptime_ms();
                if now.saturating_sub(s.window_start) > 60_000 {
                    s.deaths = 0;
                    s.window_start = now;
                }
                s.deaths += 1;
                if s.deaths > 5 {
                    s.dead = true;
                    println!(
                        "[init] {} died (status {}), 5+ deaths/60s — not respawning",
                        s.name, status
                    );
                    continue;
                }
                println!("[init] {} died (status {}), respawning", s.name, status);
                sleep_ms(2000);
                match spawn(&s.path, "") {
                    Ok(np) => s.pid = np,
                    Err(_) => {
                        s.dead = true;
                        println!("[init] {} respawn failed — service dead", s.name);
                    }
                }
            }
            Err(()) => {
                // timeout — sanity pass: a service child we somehow missed
                // (or that exited before we started waiting)
                for s in services.iter_mut().filter(|s| !s.dead) {
                    let alive = ustd::proclist(64).iter().any(|p| p.pid == s.pid);
                    if !alive {
                        println!("[init] {} (pid {}) missing — respawning", s.name, s.pid);
                        sleep_ms(2000);
                        match spawn(&s.path, "") {
                            Ok(np) => s.pid = np,
                            Err(_) => s.dead = true,
                        }
                    }
                }
            }
        }
    }
}
