//! Tasks (kernel threads + ring-3 processes) and the preemptive scheduler.
use crate::idt::CpuContext;
use crate::{gdt, ipc, mem, shm, vfs, sprintln};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{PageTable, PhysFrame};
use x86_64::PhysAddr;

pub static TICKS: AtomicU64 = AtomicU64::new(0);
pub static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

pub const USER_STACK_TOP: u64 = 0x7F00_0000;
pub const USER_STACK_PAGES: u64 = 64; // 256 KiB
pub const USER_MMAP_BASE: u64 = 0x2000_0000;
pub const USER_ARG_PAGE: u64 = 0x7EFF_F000;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum State {
    Running,
    Blocked, // until wake_at ticks
    Stopped, // SIGSTOP — never scheduled until SIGCONT
    Dead,
}

#[derive(Clone)]
pub struct FileDesc {
    pub path: String,
    pub pos: u64,
    pub flags: u64,
}

/// One `/proc/<pid>/maps` line: a live tracked mapping in the task's
/// user address space. `perm`: R=1, W=2, X=4.
pub struct MapEnt {
    pub start: u64,
    pub end: u64,
    pub perm: u8,
    pub name: String,
}

/// A file-backed mmap region: VA range -> (path, file offset of `start`).
/// Pages are NOT mapped at mmap(2) time — the #PF handler fills each one
/// from the file on first touch (real demand paging).
pub struct FileMap {
    pub start: u64,
    pub end: u64,
    pub path: String, // "" = demand-zero (bss sentinel)
    pub off: u64,
    pub perm: u8, // R1W2X4 — the demand pager maps with these flags
}

pub struct Task {
    pub id: u32,
    pub name: String,
    pub is_user: bool,
    pub state: State,
    pub saved_rsp: u64, // points at CpuContext on this task's kernel stack
    pub kstack: u64,    // base (low addr) of kernel stack
    pub kstack_top: u64,
    pub pml4: Option<PhysFrame>,
    pub wake_at: u64,
    pub exit_code: i64,
    pub parent: u32,
    pub fds: Vec<Option<FileDesc>>,
    pub cwd: String,
    pub ports: Vec<u32>,
    pub shm: Vec<u32>,
    pub frames: Vec<u64>, // owned physical frames (kernel stack frames)
    pub mem_bytes: u64,
    pub waiting_on: u32, // pid we're wait_pid'ing on, 0 = none
    pub wait_port: u32,  // port id we're blocked receiving on, 0 = none
    pub borrowed: Vec<u64>, // phys frames mapped in but owned by shm objects
    pub mmap_next: u64,  // next anonymous mmap vaddr
    pub arg_page: u64,   // vaddr of arg page (0 if none)
    pub sleep_deadline: u64, // SYS_SLEEP_MS restart target (0 = not sleeping)
    pub wait_timeout: u64,   // tick deadline for timed waits (0 = none)
    pub cpu_ticks: u64,      // PIT ticks this task has run (per-task CPU time)
    pub argv: String,        // spawn arg string (for /proc/<pid>/cmdline)
    pub nice: i8,            // -20 (highest prio) ..= 19 (lowest); 0 = normal
    pub rt: bool,            // SCHED_RT: runnable rt tasks preempt all non-rt tasks
    pub vrun: u64,           // virtual runtime (scaled by nice) for fair scheduling
    pub trace: bool,         // syscall tracing on (strace -p)
    pub trbuf: Vec<u64>,     // packed trace records, 7 u64s each: nr,a1..a5,ret
    pub umask: u32,          // file-creation mask (POSIX); inherited across spawn
    pub exe: String,         // full path the task was spawned from (/proc/<pid>/exe)
    pub maps: Vec<MapEnt>,   // tracked user-space mappings
    pub filemaps: Vec<FileMap>, // file-backed regions for demand paging
    pub rbytes: u64,         // bytes read via vfs (/proc/<pid>/io)
    pub wbytes: u64,         // bytes written via vfs
}

pub struct Sched {
    pub tasks: Vec<Box<Task>>,
    pub cur: usize,
    pub next_pid: u32,
}

pub static SCHED: Mutex<Option<Sched>> = Mutex::new(None);
pub static IDLE_TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    let (cr3, _f) = Cr3::read();
    KERNEL_CR3.store(cr3.start_address().as_u64(), Ordering::Relaxed);
    let boot = Task {
        id: 0,
        name: String::from("kernel"),
        argv: String::new(),
        is_user: false,
        state: State::Running,
        saved_rsp: 0,
        kstack: 0,
        kstack_top: 0,
        pml4: None,
        wake_at: 0,
        exit_code: 0,
        parent: 0,
        fds: Vec::new(),
        cwd: String::from("/"),
        ports: Vec::new(),
        shm: Vec::new(),
        frames: Vec::new(),
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        borrowed: Vec::new(),
        mmap_next: USER_MMAP_BASE,
        arg_page: 0,
        sleep_deadline: 0,
        wait_timeout: 0,
        cpu_ticks: 0,
        nice: 0,
        rt: false,
        vrun: 0,
        trace: false,
        trbuf: Vec::new(),
        umask: 0o022,
        exe: String::from("kernel"),
        maps: Vec::new(),
        filemaps: Vec::new(),
        rbytes: 0,
        wbytes: 0,
    };
    *SCHED.lock() = Some(Sched { tasks: vec![Box::new(boot)], cur: 0, next_pid: 1 });
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}
pub fn uptime_ms() -> u64 {
    ticks() * 10
}

/// Timer tick: advance time, pick next runnable, switch stacks.
/// Returns the rsp to restore (in rax to the asm stub).
extern "C" fn sched_tick(saved: u64) -> u64 {
    TICKS.fetch_add(1, Ordering::Relaxed);
    crate::timer::bump_ticks();
    crate::timerfd::tick(); // expire /timerfd objects (~10ms per tick)
    let mut g = match SCHED.try_lock() {
        Some(g) => g,
        None => return saved, // scheduler busy in a syscall — defer
    };
    let s = g.as_mut().unwrap();
    s.tasks[s.cur].saved_rsp = saved;
    s.tasks[s.cur].cpu_ticks += 1; // the outgoing task owned this interval
    // charge virtual runtime: weight = 40 - nice (-20..=19 -> 60..=21)
    {
        let t = &mut s.tasks[s.cur];
        t.vrun += 4000 / (40 - t.nice as i64) as u64;
    }
    // wake sleepers (sleep + timed waits)
    for t in s.tasks.iter_mut() {
        if t.state == State::Blocked && t.wake_at <= ticks() {
            t.state = State::Running;
        }
    }
    // wake port receivers whose queues filled
    crate::ipc::wake_receivers(s);
    let n = s.tasks.len();
    // CFS-lite: run the runnable task with the smallest virtual runtime;
    // runnable SCHED_RT tasks preempt every non-rt task first.
    // Scan starts just past `cur` so equal keys still round-robin.
    let mut best: Option<((u8, u64), usize)> = None;
    for off in 1..=n {
        let i = (s.cur + off) % n;
        let t = &s.tasks[i];
        if t.state == State::Running {
            let key = (if t.rt { 0u8 } else { 1u8 }, t.vrun);
            match best {
                Some((k, _)) if key >= k => {}
                _ => best = Some((key, i)),
            }
        }
    }
    let next = match best {
        Some((_, i)) => i,
        None => {
            IDLE_TICKS.fetch_add(1, Ordering::Relaxed);
            return saved; // stay on current (idle) context
        }
    };
    s.cur = next;
    activate(&s.tasks[next]);
    s.tasks[next].saved_rsp
}

fn activate(t: &Task) {
    if t.is_user {
        gdt::set_rsp0(t.kstack_top);
        if let Some(p) = t.pml4 {
            unsafe {
                Cr3::write(p, Cr3Flags::empty());
            }
        }
    } else {
        // kernel threads run on the kernel page table
        let kcr3 = KERNEL_CR3.load(Ordering::Relaxed);
        unsafe {
            Cr3::write(PhysFrame::from_start_address(PhysAddr::new(kcr3)).unwrap(), Cr3Flags::empty());
        }
    }
}

/// Called from the timer handler with the pushed CpuContext address.
/// Returns the rsp to resume on (possibly another task's stack).
pub fn on_tick(ctx: *mut CpuContext) -> u64 {
    sched_tick(ctx as u64)
}

/// Cooperative yield/block: called from syscall path with ctx == pushed regs.
/// Does NOT return on the old task; when rescheduled it returns to the
/// syscall stub pop-path on this stack with ctx.rax = return value.
pub fn yield_ctx(ctx: *mut CpuContext) -> ! {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    s.tasks[s.cur].saved_rsp = ctx as u64;
    let n = s.tasks.len();
    // runnable rt tasks first, then anyone runnable
    for want_rt in [true, false] {
        for i in 1..=n {
            let t = &s.tasks[(s.cur + i) % n];
            if t.state == State::Running && t.rt == want_rt {
                s.cur = (s.cur + i) % n;
                activate(&s.tasks[s.cur]);
                let rsp = s.tasks[s.cur].saved_rsp;
                drop(g);
                unsafe { switch_tail(rsp) }
            }
        }
    }
    // nothing else to run — stay
    drop(g);
    unsafe { switch_tail(ctx as u64) }
}

/// Jump to a suspended task's saved context and resume it.
#[unsafe(naked)]
unsafe extern "C" fn switch_tail(rsp: u64) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
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

// ---------------------------------------------------------------------------
// spawning
// ---------------------------------------------------------------------------
const KSTACK_PAGES: u64 = 32; // 128 KiB

fn alloc_kstack(frames_out: &mut Vec<u64>) -> (u64, u64) {
    let (base, frames) = mem::alloc_kstack(KSTACK_PAGES).expect("kstack");
    frames_out.extend(frames);
    (base, base + KSTACK_PAGES * 0x1000)
}

/// Spawn a userspace process from an ELF executable path.
pub fn spawn_user(path: &str, args: &str, parent: u32) -> Result<u32, u64> {
    // demand-loading reads only the header window up front — PT_LOAD
    // contents page in lazily from the image file on first touch
    let mut hdr = vec![0u8; 96 * 1024];
    let (file_size, hdrn) = match vfs::stat_path(path) {
        Ok(st) => {
            let want = (st.size as usize).min(hdr.len());
            match vfs::read_range(path, 0, &mut hdr[..want]) {
                Ok(n) => (st.size as u64, n),
                Err(_) => (0, 0),
            }
        }
        Err(_) => (0, 0),
    };
    let data = match vfs::read_all(path) {
        Ok(d) => Some(d),
        Err(e) => {
            crate::sprintln!("[spawn] read_all {} failed: {}", path, e);
            if file_size == 0 {
                return Err(!0u64);
            }
            None
        }
    };

    // Allocate the kernel stack FIRST: it is mapped into the kernel's shared
    // upper page tables. If the PML4 were copied before these mappings exist,
    // the new task's PDPT slot (index 170 region) would be empty and ring-3
    // interrupt delivery onto TSS.rsp0 would double-fault.
    let mut kframes = Vec::new();
    let (kbase, ktop) = alloc_kstack(&mut kframes);

    // create the task's page table (copies kernel entries incl. the kstack PDPT)
    let pml4 = match create_user_pml4() {
        Some(p) => p,
        None => {
            crate::sprintln!("[spawn] create_user_pml4 failed");
            free_frames(&kframes);
            return Err(!0u64);
        }
    };
    let mut frames: Vec<u64> = Vec::new();
    frames.push(pml4.start_address().as_u64());

    let mut umaps: Vec<MapEnt> = Vec::new();
    let mut filemaps: Vec<FileMap> = Vec::new();
    // try the demand-paged load first; on any fallback condition read the
    // whole image and map it eagerly (headers beyond the window, weird
    // alignment, pseudo-fs path)
    let lazy_ok = data.is_none() || hdr.len() > 0;
    let entry = if lazy_ok {
        match crate::elf::load_into_lazy(
            pml4,
            path,
            &hdr[..hdrn],
            file_size,
            &mut frames,
            &mut umaps,
            &mut filemaps,
        ) {
            Ok(e) => Some(e),
            Err(_) => None,
        }
    } else {
        None
    };
    let entry = match entry {
        Some(e) => e,
        None => {
            let data = match data {
                Some(d) => d,
                None => match vfs::read_all(path) {
                    Ok(d) => d,
                    Err(e) => {
                        crate::sprintln!("[spawn] read_all {} failed: {}", path, e);
                        free_frames(&frames);
                        free_frames(&kframes);
                        return Err(!0u64);
                    }
                },
            };
            umaps.clear();
            filemaps.clear();
            // an eager reload re-maps the same VAs — demand state is fresh
            match crate::elf::load_into(pml4, &data, &mut frames, &mut umaps) {
                Ok(e) => e,
                Err(_) => {
                    crate::sprintln!("[spawn] elf load {} failed", path);
                    free_frames(&frames);
                    free_frames(&kframes);
                    return Err(!0u64);
                }
            }
        }
    };
    for m in umaps.iter_mut() {
        m.name = String::from(path);
    }

    // user stack
    let stack_frames = crate::elf::map_user_range(
        pml4,
        USER_STACK_TOP - USER_STACK_PAGES * 0x1000,
        USER_STACK_PAGES * 0x1000,
        &mut frames,
    )
    .ok_or(!0u64)?;
    let _ = stack_frames;
    umaps.push(MapEnt {
        start: USER_STACK_TOP - USER_STACK_PAGES * 0x1000,
        end: USER_STACK_TOP,
        perm: 1 | 2,
        name: String::from("[stack]"),
    });

    // args page
    let argf = crate::elf::map_user_range(pml4, USER_ARG_PAGE, 0x1000, &mut frames).ok_or(!0u64)?;
    umaps.push(MapEnt {
        start: USER_ARG_PAGE,
        end: USER_ARG_PAGE + 0x1000,
        perm: 1 | 2,
        name: String::from("[args]"),
    });
    let abytes = args.as_bytes();
    let n = abytes.len().min(0xF00);
    unsafe {
        let dst = mem::phys_to_virt(argf[0]) as *mut u8;
        core::ptr::copy_nonoverlapping(abytes.as_ptr(), dst, n);
        *dst.add(n) = 0;
    }

    // fabricate the initial user-mode frame at the top of the kernel stack
    let ctx = (ktop - core::mem::size_of::<CpuContext>() as u64) as *mut CpuContext;
    unsafe {
        core::ptr::write(ctx, CpuContext::default());
        let c = &mut *ctx;
        c.rip = entry;
        c.cs = unsafe { gdt::USER_CS.0 as u64 };
        c.rflags = 0x202;
        c.rsp = USER_STACK_TOP - 8;
        c.ss = unsafe { gdt::USER_DS.0 as u64 };
        c.rdi = USER_ARG_PAGE;
        c.rsi = n as u64;
    }
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let pid = s.next_pid;
    s.next_pid += 1;
    let name = path.rsplit('/').next().unwrap_or(path);
    let t = Task {
        id: pid,
        name: String::from(name),
        argv: String::from(args),
        is_user: true,
        state: State::Running,
        saved_rsp: ctx as u64,
        kstack: kbase,
        kstack_top: ktop,
        pml4: Some(pml4),
        wake_at: 0,
        exit_code: 0,
        parent,
        fds: Vec::new(),
        cwd: String::from("/"),
        ports: Vec::new(),
        shm: Vec::new(),
        frames: kframes,
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        borrowed: Vec::new(),
        mmap_next: USER_MMAP_BASE,
        arg_page: USER_ARG_PAGE,
        sleep_deadline: 0,
        wait_timeout: 0,
        cpu_ticks: 0,
        nice: 0,
        rt: false,
        vrun: s.tasks[s.cur].vrun,
        trace: false,
        trbuf: Vec::new(),
        umask: s.tasks.iter().find(|t| t.id == parent).map(|t| t.umask).unwrap_or(0o022),
        exe: String::from(path),
        maps: umaps,
        filemaps,
        rbytes: 0,
        wbytes: 0,
    };
    s.tasks.push(Box::new(t));
    sprintln!("[task] spawned pid={} '{}' entry={:#x}", pid, name, entry);
    Ok(pid)
}

/// Spawn a kernel-space thread.
pub fn spawn_kernel(name: &str, func: extern "C" fn() -> !) -> u32 {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let pid = s.next_pid;
    s.next_pid += 1;
    let mut kframes = Vec::new();
    let (kbase, ktop) = alloc_kstack(&mut kframes);
    // fabricated kernel iret frame: full CpuContext; ring-0 iretq consumes
    // only rip/cs/rflags so rsp/ss are inert slots
    let ctx = (ktop - 160) as *mut CpuContext;
    unsafe {
        core::ptr::write(ctx, CpuContext::default());
        let c = &mut *ctx;
        c.rip = func as u64;
        c.cs = unsafe { gdt::KERNEL_CS.0 as u64 };
        c.rflags = 0x202;
        c.rsp = ktop; // ring0 iret doesn't consume rsp; stub sets via pop-iretq
        c.ss = 0x10;
    }
    s.tasks.push(Box::new(Task {
        id: pid,
        name: String::from(name),
        argv: String::new(),
        is_user: false,
        state: State::Running,
        saved_rsp: ctx as u64,
        kstack: kbase,
        kstack_top: ktop,
        pml4: None,
        wake_at: 0,
        exit_code: 0,
        parent: 0,
        fds: Vec::new(),
        cwd: String::from("/"),
        ports: Vec::new(),
        shm: Vec::new(),
        frames: kframes,
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        borrowed: Vec::new(),
        mmap_next: 0,
        arg_page: 0,
        sleep_deadline: 0,
        wait_timeout: 0,
        cpu_ticks: 0,
        nice: 0,
        rt: false,
        vrun: s.tasks[s.cur].vrun,
        trace: false,
        trbuf: Vec::new(),
        umask: 0o022,
        exe: String::from("kernel-thread"),
        maps: Vec::new(),
        filemaps: Vec::new(),
        rbytes: 0,
        wbytes: 0,
    }));
    pid
}

/// User frames are all freed via elf::free_user_space; Task::frames only
/// tracks kernel stack frames (kernel-virtual mappings, not in user tree).
fn kframes_too(all: &Vec<u64>) -> Vec<u64> {
    // kstack frames were appended last (after all user mappings + PT frames)
    let n = all.len();
    let k = KSTACK_PAGES as usize;
    if n >= k {
        all[n - k..].to_vec()
    } else {
        Vec::new()
    }
}

/// Create a fresh user PML4: shares kernel upper entries, own low tree.
pub fn create_user_pml4() -> Option<PhysFrame> {
    let frame = mem::alloc_frame()?;
    let user_l4 = unsafe { &mut *(mem::phys_to_virt(frame.start_address().as_u64()) as *mut PageTable) };
    user_l4.zero();
    // copy kernel PML4 entries (they're supervisor pages — user can't touch them)
    let (kframe, _) = Cr3::read();
    let kl4 = unsafe { &*(mem::phys_to_virt(kframe.start_address().as_u64()) as *const PageTable) };
    for i in 1..512 {
        if !kl4[i].is_unused() {
            user_l4[i] = kl4[i].clone();
        }
    }
    // entry 0 gets a fresh PDPT for user space (0..512 GiB)
    let pdpt = mem::alloc_frame()?;
    let pdpt_t = unsafe { &mut *(mem::phys_to_virt(pdpt.start_address().as_u64()) as *mut PageTable) };
    pdpt_t.zero();
    use x86_64::structures::paging::PageTableFlags as F;
    user_l4[0].set_addr(pdpt.start_address(), F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE);
    Some(frame)
}

pub fn free_frames(frames: &[u64]) {
    for &f in frames {
        mem::free_frame(f);
    }
}

/// Kill the current task if it's a user process; halt the CPU if kernel/fatal.
pub fn kill_current_or_halt(reason: &str) -> ! {
    sprintln!("[task] fault '{}' — killing current task", reason);
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let idx = s.cur;
    if !s.tasks[idx].is_user {
        sprintln!("[task] kernel task faulted — halting");
        loop {
            x86_64::instructions::hlt();
        }
    }
    kill_at(s, idx, -1);
    drop(g);
    // run the scheduler to move on (int 32 = the timer vector); if nothing
    // is runnable yet, idle with interrupts on until a tick switches away
    park_dead_task();
}

fn kill_at(s: &mut Sched, idx: usize, code: i64) {
    let dead_cur = idx == s.cur;
    let mut t = s.tasks.remove(idx);
    t.state = State::Dead;
    t.exit_code = code;
    // no field on the tombstone may ever re-mark it schedulable
    t.wake_at = u64::MAX;
    t.wait_port = 0;
    // wake any waiters (only live ones); u32::MAX = wait(-1) any-child
    for o in s.tasks.iter_mut() {
        if o.waiting_on == t.id || (o.waiting_on == u32::MAX && t.parent == o.id) {
            o.waiting_on = 0;
            if o.state != State::Dead {
                o.state = State::Running;
            }
        }
    }
    t.waiting_on = 0;
    // release ports, shm objects (frees their frames when refcount hits 0),
    // and any flock-style file locks this task held
    ipc::close_task_ports(&mut t);
    shm::drop_task_shm(&mut t);
    crate::locks::release_pid(t.id);
    // release fd-table objects (pipe roles, inotify/timerfd objects) — a
    // dead task must not pin e.g. a pipe's writer count, or readers block
    // forever waiting for an EOF that can never come
    for slot in t.fds.iter_mut() {
        if let Some(f) = slot.take() {
            crate::vfs::release_desc(&f);
        }
    }
    if let Some(pml4) = t.pml4 {
        // walk the user tree; free every leaf+PT frame except shm-borrowed ones
        let borrowed = core::mem::take(&mut t.borrowed);
        let freed = crate::elf::free_user_space(pml4);
        for f in freed {
            if !borrowed.contains(&f) {
                mem::free_frame(f);
            }
        }
        // Keep the pml4 frame: CR3 still points at it until the scheduler
        // activates another task, so freeing it here could unmap the parked
        // exit path if the frame got reallocated.
        t.frames.push(pml4.start_address().as_u64());
    }
    // Kernel-stack frames stay in the tombstone: the dying task may still be
    // running on its own kstack while exit_current parks the CPU, and IRQ
    // stubs keep pushing contexts onto it until the scheduler switches away.
    let id = t.id;
    let name = t.name.clone();
    s.tasks.push(t); // keep as tombstone for wait_pid
    // s.cur bookkeeping after the remove: if the CURRENT task died, point
    // s.cur at its tombstone so the next sched_tick records the int-32
    // context on the dead entry instead of clobbering a live task's
    // saved_rsp; if an earlier task died, s.cur shifts down one.
    if dead_cur {
        s.cur = s.tasks.len() - 1;
    } else if idx < s.cur {
        s.cur -= 1;
    }
    if s.cur >= s.tasks.len() {
        s.cur = 0;
    }
    sprintln!("[task] pid={} '{}' exited code={}", id, name, code);
}

pub fn exit_current(code: i64) -> ! {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let idx = s.cur;
    kill_at(s, idx, code);
    drop(g);
    park_dead_task();
}

/// Give up the CPU after the current task died. `int 32` re-runs the
/// scheduler immediately; if no task is runnable it returns, and we idle on
/// the (still-allocated) tombstone stack with interrupts ENABLED so the next
/// timer IRQ retries and eventually switches away. Parking with IF=0 would
/// freeze the machine: no IRQ could ever wake the CPU.
fn park_dead_task() -> ! {
    unsafe {
        core::arch::asm!("int 32");
    }
    loop {
        x86_64::instructions::interrupts::enable_and_hlt();
    }
}

/// Current task index/id helpers
pub fn current_id() -> u32 {
    let g = SCHED.lock();
    g.as_ref().map(|s| s.tasks[s.cur].id).unwrap_or(0)
}

pub fn with_current<R>(f: impl FnOnce(&mut Task) -> R) -> R {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    f(&mut s.tasks[s.cur])
}

pub fn task_count() -> usize {
    let g = SCHED.lock();
    g.as_ref()
        .map(|s| s.tasks.iter().filter(|t| t.state != State::Dead).count())
        .unwrap_or(0)
}

/// Exit code of `pid` once dead, or None while running/absent.
pub fn child_exit(pid: u32) -> Option<i64> {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    s.tasks
        .iter()
        .find(|t| t.id == pid)
        .and_then(|t| if t.state == State::Dead { Some(t.exit_code) } else { None })
}

/// POSIX wait(-1): first dead child of `pid`, reaped (removed) on return.
pub fn child_exit_any(pid: u32) -> Option<(u32, i64)> {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let idx = s
        .tasks
        .iter()
        .position(|t| t.parent == pid && t.state == State::Dead)?;
    let t = s.tasks.remove(idx);
    Some((t.id, t.exit_code))
}

/// True when `pid` has at least one child (live or zombie).
pub fn has_children(pid: u32) -> bool {
    let g = SCHED.lock();
    g.as_ref()
        .map(|s| s.tasks.iter().any(|t| t.parent == pid))
        .unwrap_or(false)
}

/// Whether a task id exists at all (dead or alive).
pub fn exists(pid: u32) -> bool {
    let g = SCHED.lock();
    g.as_ref().map(|s| s.tasks.iter().any(|t| t.id == pid)).unwrap_or(false)
}

/// True when `pid` has exited (still a zombie) or no longer exists at all —
/// the pidfd readiness condition.
pub fn dead_or_gone(pid: u32) -> bool {
    let g = SCHED.lock();
    g.as_ref()
        .map(|s| !s.tasks.iter().any(|t| t.id == pid && t.state != State::Dead))
        .unwrap_or(false)
}

/// Kill task `pid` (userspace only). Returns false if absent/kernel.
pub fn kill_pid(pid: u32) -> bool {
    kill_pid_code(pid, -9)
}

/// Kill task `pid` recording `code` as its exit status (used by signal()
/// to report the POSIX 128+sig wait-status for signal termination).
fn kill_pid_code(pid: u32, code: i64) -> bool {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let Some(idx) = s.tasks.iter().position(|t| t.id == pid && t.state != State::Dead) else {
        return false;
    };
    // init (pid 1) and winserver are vital; refuse to kill them.
    if s.tasks[idx].id == 1 || s.tasks[idx].name == "cosmos-winserver" || !s.tasks[idx].is_user {
        return false;
    }
    let was_cur = idx == s.cur;
    kill_at(s, idx, code);
    drop(g);
    if was_cur {
        park_dead_task();
    }
    true
}

pub fn proclist(buf: &mut [shared::ProcInfo]) -> usize {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    let mut n = 0;
    for t in s.tasks.iter() {
        if n >= buf.len() {
            break;
        }
        if t.state == State::Dead {
            continue;
        }
        let p = &mut buf[n];
        p.pid = t.id;
        p.is_user = t.is_user as u32;
        p.mem_kb = t.mem_bytes / 1024;
        p.cpu_ticks = t.cpu_ticks;
        let nb = t.name.as_bytes();
        let l = nb.len().min(31);
        p.name[..l].copy_from_slice(&nb[..l]);
        p.name[l] = 0;
        n += 1;
    }
    n
}

/// Alive task ids (for /proc/<pid> dir enumeration).
pub fn pids() -> Vec<u32> {
    let g = SCHED.lock();
    g.as_ref()
        .map(|s| {
            s.tasks
                .iter()
                .filter(|t| t.state != State::Dead)
                .map(|t| t.id)
                .collect()
        })
        .unwrap_or_default()
}

/// (user-task ticks, all-task ticks) across live tasks — feeds /proc/stat.
pub fn cpu_sums() -> (u64, u64) {
    let g = SCHED.lock();
    g.as_ref()
        .map(|s| {
            let mut user = 0u64;
            let mut all = 0u64;
            for t in s.tasks.iter() {
                if t.state == State::Dead {
                    continue;
                }
                if t.is_user {
                    user += t.cpu_ticks;
                }
                all += t.cpu_ticks;
            }
            (user, all)
        })
        .unwrap_or((0, 0))
}

/// (name, argv, mem_bytes, cpu_ticks, is_user, state, nice, vrun) for /proc/<pid>/*.
pub fn pid_info(pid: u32) -> Option<(String, String, u64, u64, bool, &'static str, i8, u64, u32)> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    s.tasks.iter().find(|t| t.id == pid).map(|t| {
        (
            t.name.clone(),
            t.argv.clone(),
            t.mem_bytes,
            t.cpu_ticks,
            t.is_user,
            match t.state {
                State::Running => "R (running)",
                State::Blocked => "S (sleeping)",
                State::Stopped => "T (stopped)",
                State::Dead => "Z (dead)",
            },
            t.nice,
            t.vrun,
            t.parent,
        )
    })
}

/// `/proc/<pid>/cwd` body: the task's current working directory.
pub fn pid_cwd(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    s.tasks.iter().find(|t| t.id == pid).map(|t| t.cwd.clone())
}

/// `/proc/<pid>/fds` body: one line per open fd (fd: path).
pub fn fd_list(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut out = String::new();
    for (i, f) in t.fds.iter().enumerate() {
        if let Some(f) = f {
            out.push_str(&alloc::format!("{}: {}\n", i, f.path));
        }
    }
    Some(out)
}

/// /proc/<pid>/fdinfo: the real open-file table with position + flags.
pub fn fd_info(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut out = String::new();
    for (i, f) in t.fds.iter().enumerate() {
        if let Some(f) = f {
            out.push_str(&alloc::format!(
                "fd: {}\tpos: {}\tflags: {:#o}\tpath: {}\n",
                i, f.pos, f.flags, f.path
            ));
        }
    }
    Some(out)
}

/// SYS_RUSAGE: real per-task resource usage — cpu ticks so far and
/// current mapped bytes as maxrss (we have no historic peak counter).
pub fn rusage(pid: u32) -> Option<(u64, u64)> {
    let g = SCHED.lock();
    let t = g.as_ref()?.tasks.iter().find(|t| t.id == pid)?;
    Some((t.cpu_ticks, t.mem_bytes / 1024))
}


/// SYS_NICE: set scheduling priority (-20 high ..= 19 low, clamped).
/// pid 0 = caller. Returns the stored nice value or -1000 (no such pid).
pub fn set_nice(pid: u32, nice: i64) -> i64 {
    let pid = if pid == 0 { current_id() } else { pid };
    let n = nice.clamp(-20, 19) as i8;
    let mut g = SCHED.lock();
    let s = match g.as_mut() {
        Some(s) => s,
        None => return -1000,
    };
    match s.tasks.iter_mut().find(|t| t.id == pid && t.state != State::Dead) {
        Some(t) => {
            t.nice = n;
            n as i64
        }
        None => -1000,
    }
}

// ---- syscall tracing (strace -p) ----
// Records are packed flat into `trbuf`, 7 u64s per record:
// [nr, a1..a5, ret]. Capped at 128 records between drains.

const TRACE_MAX_RECS: usize = 128;

fn with_pid_mut<F: FnOnce(&mut Task) -> i64>(pid: u32, f: F) -> i64 {
    let mut g = SCHED.lock();
    match g.as_mut() {
        Some(s) => match s.tasks.iter_mut().find(|t| t.id == pid && t.state != State::Dead) {
            Some(t) => f(t),
            None => -3,
        },
        None => -1,
    }
}

pub fn trace_start(pid: u32) -> i64 {
    with_pid_mut(pid, |t| {
        t.trace = true;
        t.trbuf.clear();
        0
    })
}

pub fn trace_stop(pid: u32) -> i64 {
    with_pid_mut(pid, |t| {
        t.trace = false;
        0
    })
}

/// Serialize all pending records as little-endian u64s and clear the ring.
pub fn trace_drain(pid: u32, out: &mut Vec<u8>) -> i64 {
    with_pid_mut(pid, |t| {
        for v in t.trbuf.iter() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        t.trbuf.clear();
        0
    })
}

/// Called at the end of every syscall dispatch; no-op when untraced or full.
pub fn trace_rec(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, ret: u64) {
    with_current(|t| {
        if t.trace && t.trbuf.len() < TRACE_MAX_RECS * 7 {
            t.trbuf
                .extend_from_slice(&[nr, a1, a2, a3, a4, a5, ret]);
        }
    });
}

/// POSIX-lite signals: 1/2/3/6/9/15 terminate (wait-status 128+sig),
/// 0 probes, 19 STOP, 18 CONT. Vital tasks (init, winserver, kernel
/// threads) refuse all signals.
pub fn signal(pid: u32, sig: u64) -> i64 {
    match sig {
        0 => {
            // probe: exists, live, killable
            let g = SCHED.lock();
            match g.as_ref() {
                Some(s) => match s.tasks.iter().find(|t| t.id == pid) {
                    Some(t)
                        if t.is_user && t.state != State::Dead && t.id != 1
                            && t.name != "cosmos-winserver" =>
                    {
                        0
                    }
                    _ => -1,
                },
                None => -1,
            }
        }
        // terminating signals: exit status = 128+sig like POSIX wait-status
        1 | 2 | 3 | 6 | 9 | 15 => {
            if kill_pid_code(pid, 128 + sig as i64) {
                0
            } else {
                -1
            }
        }
        _ => with_pid_mut(pid, |t| {
            if !t.is_user {
                return -1;
            }
            match sig {
                19 => {
                    if t.state != State::Dead {
                        t.state = State::Stopped;
                        // a stopped waiter must not wake on its old condition
                        t.waiting_on = 0;
                        t.wait_port = 0;
                    }
                    0
                }
                18 => {
                    if t.state == State::Stopped {
                        t.state = State::Running;
                    }
                    0
                }
                _ => -22, // EINVAL
            }
        }),
    }
}

/// Record a user-space mapping for `/proc/<pid>/maps` (mmap, shm, fb).
pub fn record_map(pid: u32, start: u64, end: u64, perm: u8, name: &str) {
    let mut g = SCHED.lock();
    if let Some(s) = g.as_mut() {
        if let Some(t) = s.tasks.iter_mut().find(|t| t.id == pid) {
            t.maps.push(MapEnt { start, end, perm, name: String::from(name) });
        }
    }
}

/// `/proc/<pid>/maps` — Linux-format lines: `start-end rwxp 00000000 00:00 0 name`.
pub fn pid_maps(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut out = String::new();
    for m in &t.maps {
        out.push_str(&alloc::format!(
            "{:08x}-{:08x} {}{}{}p 00000000 00:00 0          {}\n",
            m.start,
            m.end,
            if m.perm & 1 != 0 { 'r' } else { '-' },
            if m.perm & 2 != 0 { 'w' } else { '-' },
            if m.perm & 4 != 0 { 'x' } else { '-' },
            m.name
        ));
    }
    Some(out)
}

/// `/proc/<pid>/io` — real vfs byte counters.
pub fn pid_io(pid: u32) -> Option<(u64, u64)> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    s.tasks.iter().find(|t| t.id == pid).map(|t| (t.rbytes, t.wbytes))
}

/// `/proc/<pid>/exe` link target — the path the task was spawned from.
pub fn pid_exe(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    s.tasks.iter().find(|t| t.id == pid).map(|t| t.exe.clone())
}

/// `/proc/<pid>/statm`: size resident shared text lib data dirty, in pages.
/// Resident == size here: user pages are never paged out.
pub fn pid_statm(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut size = 0u64;
    let mut shared = 0u64;
    for m in &t.maps {
        size += (m.end - m.start) / 0x1000;
        if m.name.starts_with("shm") || m.name == "[fb]" {
            shared += (m.end - m.start) / 0x1000;
        }
    }
    Some(alloc::format!("{} {} {} 0 0 {} 0\n", size, size, shared, size))
}

/// Account `n` bytes of vfs I/O to the calling task (/proc/<pid>/io).
pub fn io_charge(read: bool, n: u64) {
    with_current(|t| {
        if read {
            t.rbytes += n;
        } else {
            t.wbytes += n;
        }
    });
}

/// Load-average snapshot: runnable tasks (state Running) / total / highest pid.
/// A point-in-time sample — no decay, but real counts.
pub fn loadavg() -> (usize, usize, u32) {
    let g = SCHED.lock();
    match g.as_ref() {
        Some(s) => {
            let run = s.tasks.iter().filter(|t| t.state == State::Running).count();
            (run, s.tasks.len(), s.next_pid.saturating_sub(1))
        }
        None => (0, 0, 0),
    }
}

/// Set/clear the SCHED_RT class on a task (SYS_CHRT).
pub fn set_rt(pid: u32, rt: bool) -> bool {
    let mut g = SCHED.lock();
    match g.as_mut().and_then(|s| s.tasks.iter_mut().find(|t| t.id == pid)) {
        Some(t) => {
            t.rt = rt;
            true
        }
        None => false,
    }
}

/// Whether a task runs in the rt class (/proc/<pid>/status).
pub fn pid_rt(pid: u32) -> Option<bool> {
    let g = SCHED.lock();
    g.as_ref()?.tasks.iter().find(|t| t.id == pid).map(|t| t.rt)
}

/// `/proc/<pid>/wchan` — the kernel function the task sleeps in ("0" if running).
pub fn pid_wchan(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let w = match t.state {
        State::Running => "run",
        State::Stopped => "signal",
        State::Dead => "exited",
        State::Blocked => {
            if t.waiting_on != 0 {
                "waitpid"
            } else if t.wait_port != 0 {
                "port_recv"
            } else if t.sleep_deadline != 0 {
                "hrtimer_nanosleep"
            } else {
                "schedule_timeout"
            }
        }
    };
    Some(alloc::format!("{}\n", w))
}

/// `/proc/<pid>/children` — space-separated child pids.
pub fn children_of(pid: u32) -> Vec<u32> {
    let g = SCHED.lock();
    match g.as_ref() {
        Some(s) => s.tasks.iter().filter(|t| t.parent == pid).map(|t| t.id).collect(),
        None => Vec::new(),
    }
}

/// `/proc/<pid>/smaps` — maps plus real per-region sizes.
pub fn pid_smaps(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut out = String::new();
    for m in &t.maps {
        let kb = (m.end - m.start) / 1024;
        out.push_str(&alloc::format!(
            "{:08x}-{:08x} {}{}{}p 00000000 00:00 0          {}\nSize:                {} kB\nRss:                 {} kB\nPss:                 {} kB\n",
            m.start,
            m.end,
            if m.perm & 1 != 0 { 'r' } else { '-' },
            if m.perm & 2 != 0 { 'w' } else { '-' },
            if m.perm & 4 != 0 { 'x' } else { '-' },
            m.name,
            kb,
            kb, // never paged out: rss == size
            if m.name.starts_with("shm") { kb / 2 } else { kb },
        ));
    }
    Some(out)
}


/// Does `va` fall inside a file-backed mmap? Returns (path, file offset
/// of the containing page).
pub fn filemap_hit(va: u64) -> Option<(String, u64)> {
    with_current(|t| {
        let page = va & !0xFFFu64;
        t.filemaps
            .iter()
            .find(|f| page >= f.start && page < f.end)
            .map(|f| (f.path.clone(), f.off + (page - f.start)))
    })
}

/// Page-fault driven demand paging: fills one user page from the mapped
/// file (zero-padded past EOF) and maps it. true = the fault is
/// satisfied and the instruction may retry.
pub fn demand_page(va: u64) -> bool {
    let (pml4, hit) = with_current(|t| {
        let page = va & !0xFFFu64;
        (
            t.pml4,
            t.filemaps
                .iter()
                .find(|f| page >= f.start && page < f.end)
                .map(|f| (f.path.clone(), f.off + (page - f.start), f.perm)),
        )
    });
    let (Some(pml4), Some((path, file_off, perm))) = (pml4, hit) else {
        return false;
    };
    let mut scratch = Vec::new();
    let phys = crate::elf::map_user_page_flags(
        pml4,
        va & !0xFFF,
        perm & 2 != 0,
        perm & 4 != 0,
        &mut scratch,
    );
    let Some(phys) = phys else {
        sprintln!("[demand] map fail va={:#x}", va);
        return false;
    };
    if scratch.is_empty() {
        return false; // already mapped — this was a real fault
    }
    // the demand-alloc'd frame belongs to the task (freed at exit)
    with_current(|t| t.frames.push(phys));
    let mut buf = [0u8; 4096];
    let fill = if path.is_empty() {
        Ok(0) // bss sentinel: pure zero page
    } else {
        crate::vfs::read_range_pf(&path, file_off, &mut buf)
    };
    match fill {
        Ok(_) => {
            let dst = crate::mem::phys_to_virt(phys) as *mut u8;
            // buf is zero-initialized — a full-page copy also zeroes the
            // tail past EOF (no stale frame bytes reach userspace)
            unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, 0x1000) };
            true
        }
        Err(e) => {
            sprintln!("[demand] read err {} path={} off={}", e, path, file_off);
            false
        }
    }
}

/// sti;hlt;cli — wait one IRQ window inside exception/syscall context
/// where interrupts are off. The demand pager's FS-lock retry uses it so
/// a preempted lock holder gets rescheduled instead of deadlocking us.
pub fn wait_irq() {
    unsafe { core::arch::asm!("sti; hlt; cli", options(nomem, nostack)) };
}
