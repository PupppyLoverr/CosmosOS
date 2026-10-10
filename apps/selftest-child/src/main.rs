//! exits with code 7 after printing its args — used by selftest's spawn/waitpid check
#![no_std]
#![no_main]
use ustd::println;

#[unsafe(no_mangle)]
extern "C" fn user_main(args_ptr: u64, args_len: u64) -> i64 {
    let args = unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize)) };
    println!("[selftest-child] args='{}' exiting 7", args);
    if args.contains("linger") {
        // mrelease target: stay alive (sleeping) until the parent
        // drops our address space — the next fault then kills us
        loop {
            ustd::sleep_ms(1000);
        }
    }
    7
}
