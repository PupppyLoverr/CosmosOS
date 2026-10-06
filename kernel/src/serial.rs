//! COM1 serial logging (16550 UART). Kernel debug console.
use spin::Mutex;
use uart_16550::SerialPort;
use core::fmt;

pub static SERIAL: Mutex<Option<SerialPort>> = Mutex::new(None);

pub fn init() {
    let mut port = unsafe { SerialPort::new(0x3F8) };
    port.init();
    *SERIAL.lock() = Some(port);
}

pub fn write_str(s: &str) {
    let mut g = SERIAL.lock();
    if let Some(p) = g.as_mut() {
        use core::fmt::Write;
        let _ = p.write_str(s);
    }
}

/// Raw byte write (userspace SYS_DEBUG output).
pub fn write_byte(b: u8) {
    let mut g = SERIAL.lock();
    if let Some(p) = g.as_mut() {
        p.send(b);
    }
}

pub struct SerialWriter;
impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    let _ = SerialWriter.write_fmt(args);
}

#[macro_export]
macro_rules! sprint {
    ($($arg:tt)*) => { $crate::serial::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! sprintln {
    () => { $crate::sprint!("\n") };
    ($($arg:tt)*) => { $crate::sprint!("{}\n", format_args!($($arg)*)) };
}
