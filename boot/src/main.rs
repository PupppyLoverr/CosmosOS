//! cosmos-boot: wraps the `bootloader` crate to produce bootable disk images.
//! Usage: cosmos-boot <kernel-elf> <out-dir>
use std::path::PathBuf;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: cosmos-boot <kernel-elf> <out-dir>");
        exit(2);
    }
    let kernel = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);
    std::fs::create_dir_all(&out_dir).unwrap();

    let uefi_path = out_dir.join("cosmos-uefi.img");
    let mut uefi = bootloader::UefiBoot::new(&kernel);
    uefi.create_disk_image(&uefi_path).expect("uefi image");
    println!("wrote {}", uefi_path.display());

    let bios_path = out_dir.join("cosmos-bios.img");
    let mut bios = bootloader::BiosBoot::new(&kernel);
    bios.create_disk_image(&bios_path).expect("bios image");
    println!("wrote {}", bios_path.display());
}
