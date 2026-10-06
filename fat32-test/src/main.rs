use cosmos_fat32::{BlockDevice, Fat32};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

struct Dev { f: File }
impl BlockDevice for Dev {
    fn read_sector(&mut self, lba: u64, buf: &mut [u8]) -> cosmos_fat32::Result<()> {
        self.f.seek(SeekFrom::Start(lba * 512)).map_err(|_| cosmos_fat32::Error::Io)?;
        self.f.read_exact(&mut buf[..512]).map_err(|_| cosmos_fat32::Error::Io)
    }
    fn write_sector(&mut self, lba: u64, buf: &[u8]) -> cosmos_fat32::Result<()> {
        self.f.seek(SeekFrom::Start(lba * 512)).map_err(|_| cosmos_fat32::Error::Io)?;
        self.f.write_all(&buf[..512]).map_err(|_| cosmos_fat32::Error::Io)?;
        self.f.flush().map_err(|_| cosmos_fat32::Error::Io)
    }
}

fn main() {
    let f = File::options().read(true).write(true).open("../dist/cosmos-data.img").unwrap();
    let mut fs = Fat32::mount(Dev { f }).unwrap();
    println!("mounted. root:");
    for e in fs.readdir("/").unwrap() { println!("  {:?} dir={} size={}", e.name, e.is_dir, e.size); }
    println!("bin:");
    for e in fs.readdir("/bin").unwrap() { println!("  {:?} dir={} size={}", e.name, e.is_dir, e.size); }
    let d = fs.read_file("/bin/cosmos-init").unwrap();
    println!("read {} bytes, magic={:?}", d.len(), &d[..4]);
    println!("stat welcome: {:?}", fs.stat("/welcome.txt").unwrap().size);
    println!("create /foo.txt: {:?}", fs.create_file("/foo.txt"));
    println!("write foo: {:?}", fs.write_file("/foo.txt", b"xyz"));
    println!("read foo: {:?}", fs.read_file("/foo.txt"));
    println!("remove foo: {:?}", fs.remove("/foo.txt"));
    println!("mkdir /test: {:?}", fs.mkdir("/test"));
    println!("create /test/hello.txt: {:?}", fs.create_file("/test/hello.txt"));
    println!("write: {:?}", fs.write_file("/test/hello.txt", b"hello cosmos"));
    println!("read: {:?}", fs.read_file("/test/hello.txt"));
    println!("readdir /test: {:?}", fs.readdir("/test"));
    println!("stat: {:?}", fs.stat("/test/hello.txt"));
    println!("rename: {:?}", fs.rename("/test/hello.txt", "/test/hi.txt"));
    println!("exists old/new: {} {}", fs.exists("/test/hello.txt"), fs.exists("/test/hi.txt"));
    println!("remove: {:?}", fs.remove("/test/hi.txt"));
    println!("exists after: {}", fs.exists("/test/hi.txt"));
    println!("remove /test: {:?}", fs.remove("/test"));
}
