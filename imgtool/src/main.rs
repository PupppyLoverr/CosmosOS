//! cosmos-imgtool: builds the CosmosOS data disk (FAT32 volume image).
//! Usage: cosmos-imgtool <out.img> <imgroot-dir> [app-elf ...]
//!
//! Layout produced inside the image:
//!   /bin/<appname>        userspace ELF executables
//!   /system/...           files copied from imgroot/
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const IMAGE_SIZE: u64 = 128 * 1024 * 1024; // 128 MiB data volume

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: cosmos-imgtool <out.img> <imgroot> [app-elf ...]");
        std::process::exit(2);
    }
    let out = PathBuf::from(&args[1]);
    let imgroot = PathBuf::from(&args[2]);
    let apps: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();

    // Create a zeroed image file.
    {
        let mut f = File::create(&out).expect("create image");
        f.set_len(IMAGE_SIZE).expect("resize image");
        f.seek(SeekFrom::Start(0)).unwrap();
        f.flush().unwrap();
    }

    let file = fs::OpenOptions::new().read(true).write(true).open(&out).unwrap();
    fatfs::format_volume(
        &mut StdIoWrapper { inner: file },
        fatfs::FormatVolumeOptions::new()
            .volume_label(*b"COSMOSDATA ")
            .fat_type(fatfs::FatType::Fat32)
            .bytes_per_cluster(1024), // ~131k clusters -> valid FAT32 on 128MiB
    )
    .expect("format fat32");

    let file = fs::OpenOptions::new().read(true).write(true).open(&out).unwrap();
    let fs = fatfs::FileSystem::new(StdIoWrapper { inner: file }, fatfs::FsOptions::new())
        .expect("mount image");
    let root = fs.root_dir();

    // /bin with app ELFs
    let bin = root.create_dir("bin").expect("mkdir /bin");
    for app in &apps {
        let name = app.file_name().unwrap().to_str().unwrap().to_string();
        // skip library artifacts / deps noise: only copy real ELF executables
        let bytes = fs::read(app).expect("read app");
        if bytes.len() < 4 || &bytes[0..4] != b"\x7fELF" {
            continue;
        }
        let mut f = bin.create_file(&name).expect("create app file");
        f.write_all(&bytes).expect("write app");
        println!("  /bin/{} ({} bytes)", name, bytes.len());
    }

    // copy imgroot recursively
    if imgroot.exists() {
        copy_tree(&root, &imgroot).expect("copy imgroot");
    }
    println!("wrote {}", out.display());
}

struct StdIoWrapper {
    inner: File,
}
impl io::Read for StdIoWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl io::Write for StdIoWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl io::Seek for StdIoWrapper {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

fn copy_tree(dir: &fatfs::Dir<StdIoWrapper>, src: &Path) -> io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name().to_str().unwrap().to_string();
        if entry.file_type()?.is_dir() {
            let sub = dir.create_dir(&name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
            copy_tree(&sub, &entry.path())?;
        } else {
            let mut f = dir.create_file(&name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
            f.write_all(&fs::read(entry.path())?)?;
        }
    }
    Ok(())
}
