//! GDT + TSS: ring-3 entry and IST stacks.
use crate::sprintln;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{PrivilegeLevel, VirtAddr};

pub const DF_IST_INDEX: u16 = 0;

static mut DF_STACK: [u8; 64 * 1024] = [0; 64 * 1024];
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new();

pub static mut KERNEL_CS: SegmentSelector = SegmentSelector::new(0, PrivilegeLevel::Ring0);
pub static mut USER_DS: SegmentSelector = SegmentSelector::new(0, PrivilegeLevel::Ring3);
pub static mut USER_CS: SegmentSelector = SegmentSelector::new(0, PrivilegeLevel::Ring3);

pub fn init() {
    unsafe {
        let df_top = VirtAddr::from_ptr(&raw const DF_STACK) + DF_STACK.len() as u64;
        TSS.interrupt_stack_table[DF_IST_INDEX as usize] = df_top;

        let kcs = GDT.append(Descriptor::kernel_code_segment());
        let _kds = GDT.append(Descriptor::kernel_data_segment());
        let uds = GDT.append(Descriptor::user_data_segment());
        let ucs = GDT.append(Descriptor::user_code_segment());
        let tss_sel = GDT.append(Descriptor::tss_segment(&TSS));

        KERNEL_CS = kcs;
        USER_DS = SegmentSelector(uds.0 | PrivilegeLevel::Ring3 as u16);
        USER_CS = SegmentSelector(ucs.0 | PrivilegeLevel::Ring3 as u16);

        GDT.load();
        use x86_64::instructions::segmentation::Segment;
        x86_64::instructions::segmentation::CS::set_reg(kcs);
        x86_64::instructions::tables::load_tss(tss_sel);
        sprintln!("[gdt] loaded, tss sel={:#x}", tss_sel.0);
    }
}

/// Called on every context switch into ring-3 so interrupts/syscalls
/// land on the task's own kernel stack.
pub fn set_rsp0(addr: u64) {
    unsafe {
        TSS.privilege_stack_table[0] = VirtAddr::new(addr);
    }
}
