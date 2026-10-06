#![no_std]
#![no_main]
use ustd::println;

#[unsafe(no_mangle)]
extern "C" fn user_main(_a: u64, _b: u64) -> i64 {
    println!("[sysmon] stub");
    0
}
