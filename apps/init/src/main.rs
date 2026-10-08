//! init: first userspace process. Spawns the window server (or the selftest
//! harness when /selftest.flag exists on the data disk), then reaps forever.
#![no_std]
#![no_main]

use ustd::{println, sleep_ms, spawn};

#[unsafe(no_mangle)]
extern "C" fn user_main(args_ptr: u64, args_len: u64) -> i64 {
    let args = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize))
    };
    let selftest = args.contains("selftest") || ustd::stat("/selftest.flag").is_ok();
    println!("[init] cosmos init (selftest={})", selftest);

    if selftest {
        match spawn("/bin/cosmos-selftest", "") {
            Ok(pid) => println!("[init] selftest pid={}", pid),
            Err(_) => println!("[init] FAILED to spawn selftest"),
        }
    } else {
        match spawn("/bin/cosmos-winserver", "") {
            Ok(pid) => println!("[init] winserver pid={}", pid),
            Err(_) => println!("[init] FAILED to spawn winserver"),
        }
    }

    // babysit loop
    loop {
        sleep_ms(5000);
        if !selftest {
            let alive = ustd::proclist(64)
                .iter()
                .any(|p| p.is_user == 1 && contains(&p.name, b"winserver"));
            if !alive {
                println!("[init] winserver died -- respawning");
                let _ = spawn("/bin/cosmos-winserver", "");
            }
        }
    }
}

fn contains(name: &[u8; 32], needle: &[u8]) -> bool {
    name.windows(needle.len()).any(|w| w == needle)
}
