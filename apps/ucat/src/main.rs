//! ucat — AF_UNIX stream client: `cosmos-ucat <sockpath> <msg> [out] [--passfd <file>]`.
//! Connects to a listening unix socket, sends `msg` — via sendmsg when
//! `--passfd` is given, carrying that open file to the peer (SCM_RIGHTS),
//! then half-closes the write side (real shutdown(SHUT_WR) — the peer
//! reads EOF), collects the reply until EOF/timeout, then writes it to
//! `out` (or prints it). Exit 0 = got data back; 2 = connect/send failed
//! or timed out silent.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use ustd::println;

#[unsafe(no_mangle)]
extern "C" fn user_main(args_ptr: u64, args_len: u64) -> i64 {
    let args = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
            args_ptr as *const u8,
            args_len as usize,
        ))
    };
    let mut it = args.split_whitespace();
    let (Some(path), Some(msg)) = (it.next(), it.next()) else {
        println!("usage: ucat <sockpath> <msg> [out_file] [--passfd <file>]");
        return 64;
    };
    let mut out: Option<&str> = None;
    let mut passfd: i64 = -1;
    while let Some(a) = it.next() {
        if a == "--passfd" {
            match it.next() {
                Some(p) => {
                    match ustd::open(p, ustd::O_RDWR) {
                        Ok(f) => passfd = f,
                        Err(e) => {
                            println!("ucat: passfd {} err {}", p, e);
                            return 2;
                        }
                    }
                }
                None => {
                    println!("usage: ucat <sockpath> <msg> [out_file] [--passfd <file>]");
                    return 64;
                }
            }
        } else if out.is_none() {
            out = Some(a);
        }
    }
    let s = match ustd::UnixFd::connect(path) {
        Ok(s) => s,
        Err(e) => {
            println!("ucat: connect {} failed ({})", path, e);
            return 2;
        }
    };
    // sendmsg carries an open fd to the peer when --passfd was used
    let r = if passfd >= 0 {
        ustd::sendmsg(s.0, msg.as_bytes(), passfd)
    } else {
        s.write(msg.as_bytes()).map(|n| n as i64).unwrap_or(-1)
    };
    if r < 0 {
        println!("ucat: send err {}", r);
        return 2;
    }
    if passfd >= 0 {
        println!("ucat: sent fd {}", passfd);
    }
    // real half-close: server sees our bytes then EOF
    ustd::shutdown(s.0, 1);
    let mut got: Vec<u8> = Vec::new();
    let deadline = ustd::uptime_ms() + 4000;
    loop {
        if ustd::poll(&[s.0 as u32], &mut [1], 400) <= 0 {
            if ustd::uptime_ms() > deadline {
                break;
            }
            continue;
        }
        let mut buf = [0u8; 1024];
        match s.read(&mut buf) {
            Ok(0) => break,             // server closed after echoing
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => {
                if ustd::uptime_ms() > deadline {
                    break;
                }
            }
        }
        if ustd::uptime_ms() > deadline {
            break;
        }
    }
    if let Some(f) = out {
        let _ = ustd::write_all(f, &got);
    } else {
        println!("ucat: got {}", String::from_utf8_lossy(&got));
    }
    if passfd >= 0 {
        ustd::close(passfd);
    }
    if got.is_empty() {
        2
    } else {
        0
    }
}
