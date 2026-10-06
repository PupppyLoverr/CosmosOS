//! CosmosOS kernel — x86_64, UEFI boot via bootloader_api.
//! Own scheduler, userspace (ring 3), syscalls, vfs, ipc, shm, virtio-blk.
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod elf;
mod fb;
mod gdt;
mod idt;
mod input;
mod ipc;
mod mem;
mod pci;
mod serial;
mod shm;
mod syscall;
mod task;
mod timer;
mod vfs;
mod virtio;

use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::panic::PanicInfo;

const CONFIG: BootloaderConfig = {
    let mut c = BootloaderConfig::new_default();
    c.kernel_stack_size = 256 * 1024;
    c.mappings.physical_memory = Some(bootloader_api::config::Mapping::Dynamic);
    c.mappings.framebuffer = bootloader_api::config::Mapping::Dynamic;
    c
};

entry_point!(main, config = &CONFIG);

fn main(boot_info: &'static mut BootInfo) -> ! {
    serial::init();
    sprintln!("CosmosOS kernel v0.1 — booting");

    mem::init(&boot_info.memory_regions, {
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("physical_memory_offset must be mapped (CONFIG.mappings.physical_memory)")
    });

    // framebuffer (dynamic map — translate vaddr -> phys via our mapper)
    if let Some(fbi) = boot_info.framebuffer.take() {
        let info = fbi.info();
        let phys = mem::translate(fbi.buffer().as_ptr() as u64).unwrap_or(0);
        let fmt = match info.pixel_format {
            bootloader_api::info::PixelFormat::Bgr => 0u8,
            _ => 1u8,
        };
        fb::set(phys, info.width as u32, info.height as u32, info.stride as u32, fmt);
        sprintln!(
            "[fb] {}x{} stride={} fmt={} phys={:#x}",
            info.width, info.height, info.stride, fmt, phys
        );
    } else {
        sprintln!("[fb] no framebuffer");
    }

    gdt::init();
    idt::init();
    ipc::init();
    shm::init();
    task::init();
    timer::init_pit();
    timer::init_rtc();

    // devices
    virtio::init();
    vfs::init();
    input::init();

    // unmask IRQs: PIC1 -> timer(0) kbd(1) cascade(2); PIC2 -> mouse(4)
    unsafe {
        idt::PICS.lock().write_masks(0b1111_1000, 0b1110_1111);
    }

    // spawn the userspace init process
    match task::spawn_user("/bin/cosmos-init", "", 0) {
        Ok(pid) => sprintln!("[boot] init spawned pid={}", pid),
        Err(e) => sprintln!("[boot] FAILED to spawn init: {}", e),
    }

    sprintln!("KERNEL BOOT OK");
    unsafe { core::arch::asm!("sti") };
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    sprintln!("KERNEL PANIC: {}", info);
    loop {
        x86_64::instructions::hlt();
    }
}
