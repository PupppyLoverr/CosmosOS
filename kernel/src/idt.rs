//! IDT: exceptions, hardware IRQs, syscall gate.
use crate::gdt;
use crate::sprintln;
use crate::task;
use core::arch::naked_asm;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

pub const PIC1_OFF: u8 = 0x20;
pub const PIC2_OFF: u8 = 0x28;
pub static PICS: Mutex<ChainedPics> = Mutex::new(unsafe { ChainedPics::new(PIC1_OFF, PIC2_OFF) });

pub const IRQ_TIMER: u8 = PIC1_OFF + 0;
pub const IRQ_KBD: u8 = PIC1_OFF + 1;
pub const IRQ_MOUSE: u8 = PIC1_OFF + 12;
pub const IRQ_VIRTIO: u8 = PIC1_OFF + 11;
pub const INT_SYSCALL: u8 = 0x80;

static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

/// Full 64-bit CPU context saved by our irq stubs.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CpuContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // pushed by CPU:
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

pub fn init() {
    unsafe {
        // exceptions
        IDT.divide_error.set_handler_fn(divide_err);
        IDT.debug.set_handler_fn(debug_exc);
        IDT.breakpoint.set_handler_fn(bp_exc);
        IDT.overflow.set_handler_fn(of_exc);
        IDT.bound_range_exceeded.set_handler_fn(br_exc);
        IDT.invalid_opcode.set_handler_fn(ud_exc);
        IDT.device_not_available.set_handler_fn(nm_exc);
        IDT.double_fault
            .set_handler_fn(df_exc)
            .set_stack_index(gdt::DF_IST_INDEX);
        IDT.invalid_tss.set_handler_fn(gen_exc_code);
        IDT.segment_not_present.set_handler_fn(gen_exc_code);
        IDT.stack_segment_fault.set_handler_fn(gen_exc_code);
        IDT.general_protection_fault.set_handler_fn(gp_exc);
        IDT.page_fault.set_handler_fn(pf_exc);
        IDT.alignment_check.set_handler_fn(gen_exc_code);
        IDT.machine_check.set_handler_fn(mc_exc);
        IDT.simd_floating_point.set_handler_fn(simd_exc);

        // irqs
        IDT[IRQ_TIMER].set_handler_addr(x86_64::VirtAddr::new(timer_isr as u64));
        IDT[IRQ_KBD].set_handler_fn(kbd_irq);
        IDT[IRQ_MOUSE].set_handler_fn(mouse_irq);
        IDT[IRQ_VIRTIO].set_handler_fn(virtio_irq);
        IDT[INT_SYSCALL]
            .set_handler_addr(x86_64::VirtAddr::new(syscall_isr as u64))
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);

        IDT.load();
        // remap + unmask PICs
        PICS.lock().initialize();
        let mut m = PICS.lock();
        m.write_masks(0xFF, 0xFF);
        sprintln!("[idt] loaded, pics remapped");
    }
}

// ---------------- exceptions ----------------
macro_rules! exc {
    ($name:ident, $msg:expr) => {
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame) {
            sprintln!("\n[exc] {} rip={:#x} cs={:#x}", $msg, frame.instruction_pointer.as_u64(), frame.code_segment.0);
            task::kill_current_or_halt($msg);
        }
    };
}
exc!(divide_err, "divide error");
exc!(debug_exc, "debug");
exc!(bp_exc, "breakpoint");
exc!(of_exc, "overflow");
exc!(br_exc, "bound range");
exc!(ud_exc, "invalid opcode");
exc!(nm_exc, "device not available");
exc!(simd_exc, "simd fault");
extern "x86-interrupt" fn gen_exc_code(frame: InterruptStackFrame, ec: u64) {
    sprintln!("\n[exc] fault ec={:#x} rip={:#x} cs={:#x}", ec, frame.instruction_pointer.as_u64(), frame.code_segment.0);
    task::kill_current_or_halt("fault w/ code");
}

extern "x86-interrupt" fn mc_exc(frame: InterruptStackFrame) -> ! {
    sprintln!("\n[exc] MACHINE CHECK rip={:#x}", frame.instruction_pointer.as_u64());
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn df_exc(frame: InterruptStackFrame, ec: u64) -> ! {
    sprintln!(
        "\n[exc] DOUBLE FAULT ec={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}",
        ec,
        frame.instruction_pointer.as_u64(),
        frame.code_segment.0,
        frame.cpu_flags,
        frame.stack_pointer.as_u64(),
        frame.stack_segment.0
    );
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn gp_exc(frame: InterruptStackFrame, ec: u64) {
    sprintln!(
        "\n[exc] GP FAULT ec={:#x} rip={:#x} cs={:#x} rsp={:#x} ss={:#x}",
        ec,
        frame.instruction_pointer.as_u64(),
        frame.code_segment.0,
        frame.stack_pointer.as_u64(),
        frame.stack_segment.0
    );
    task::kill_current_or_halt("gp fault");
}

extern "x86-interrupt" fn pf_exc(frame: InterruptStackFrame, ec: PageFaultErrorCode) {
    let cr2 = x86_64::registers::control::Cr2::read_raw();
    sprintln!(
        "\n[exc] PAGE FAULT addr={:#x} ec={:?} rip={:#x} cs={:#x} rsp={:#x} ss={:#x}",
        cr2,
        ec,
        frame.instruction_pointer.as_u64(),
        frame.code_segment.0,
        frame.stack_pointer.as_u64(),
        frame.stack_segment.0
    );
    task::kill_current_or_halt("page fault");
}

// ---------------- irq stubs ----------------
/// Timer IRQ entry: pushes all regs, calls scheduler (may switch tasks), restores.
#[unsafe(naked)]
extern "C" fn timer_isr() {
    naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        "call timer_handler",
        "mov rsp, rax",           // scheduler may have switched stacks
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
    );
}

/// timer_handler(ctx_ptr) -> the rsp to restore (possibly a different task's).
#[unsafe(no_mangle)]
extern "C" fn timer_handler(ctx: *mut CpuContext) -> u64 {
    let rsp = task::on_tick(ctx);
    let mut p = PICS.lock();
    unsafe { p.notify_end_of_interrupt(IRQ_TIMER) };
    rsp
}

extern "x86-interrupt" fn kbd_irq(_f: InterruptStackFrame) {
    crate::input::on_kbd_irq();
    let mut p = PICS.lock();
    unsafe { p.notify_end_of_interrupt(IRQ_KBD) };
}

extern "x86-interrupt" fn mouse_irq(_f: InterruptStackFrame) {
    crate::input::on_mouse_irq();
    let mut p = PICS.lock();
    unsafe { p.notify_end_of_interrupt(IRQ_MOUSE) };
}

extern "x86-interrupt" fn virtio_irq(_f: InterruptStackFrame) {
    crate::virtio::on_irq();
    let mut p = PICS.lock();
    unsafe { p.notify_end_of_interrupt(IRQ_VIRTIO) };
}

/// int 0x80 syscall gate. Same register save/restore as timer; eax=nr,
/// rdi..r9 args. rax carries the return value back.
#[unsafe(naked)]
extern "C" fn syscall_isr() {
    naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        "call syscall_handler",
        "mov rax, [rsp + 14*8]",   // handler may have rewritten saved rax
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "add rsp, 8",              // skip saved rax (already loaded)
        "iretq",
    );
}

#[unsafe(no_mangle)]
extern "C" fn syscall_handler(ctx: *mut CpuContext) {
    crate::syscall::dispatch(unsafe { &mut *ctx });
}
