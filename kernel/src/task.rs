//! Tasks (kernel threads + ring-3 processes) and the preemptive scheduler.
use crate::idt::CpuContext;
use crate::{gdt, ipc, mem, shm, vfs, sprintln};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{PageTable, PhysFrame};
use x86_64::PhysAddr;

/// POSIX capability bits (Linux CAP_* numbering).
pub const CAP_CHOWN: u64 = 1;
pub const CAP_DAC_OVERRIDE: u64 = 1 << 1;
pub const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
pub const CAP_FOWNER: u64 = 1 << 3;
pub const CAP_KILL: u64 = 1 << 5;
pub const CAP_SETGID: u64 = 1 << 6;
pub const CAP_SETUID: u64 = 1 << 7;
pub const CAP_SETPCAP: u64 = 1 << 8;
pub const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
pub const CAP_SYS_RAWIO: u64 = 1 << 17;
pub const CAP_SYS_CHROOT: u64 = 1 << 18;
pub const CAP_SYS_PTRACE: u64 = 1 << 19;
pub const CAP_SYS_ADMIN: u64 = 1 << 21;
pub const CAP_SYS_NICE: u64 = 1 << 23;
pub const CAP_SYS_TIME: u64 = 1 << 25;
pub const CAP_SYS_BOOT: u64 = 1 << 27;
pub const CAP_SYSLOG: u64 = 1 << 34;
/// Linux CAP_LAST_CAP — every defined bit (no ambient set modelled).
pub const CAP_ALL: u64 = (1u64 << 41) - 1;

pub static TICKS: AtomicU64 = AtomicU64::new(0);
pub static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

pub const USER_STACK_TOP: u64 = 0x7F00_0000;
pub const USER_STACK_PAGES: u64 = 64; // 256 KiB
pub const USER_STACK_MIN: u64 = USER_STACK_TOP - USER_STACK_PAGES * 0x1000;
/// Arena of private thread stack slots just below the main stack:
/// 64-page (256KiB) slots, grow-down on fault like the main stack.
pub const THREAD_STK_MIN: u64 = 0x7C00_0000;
pub const THREAD_STK_MAX: u64 = USER_STACK_MIN;
pub const THREAD_STK_PAGES: u64 = 64;
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
#[derive(Clone)]
pub struct MapEnt {
    pub start: u64,
    pub end: u64,
    pub perm: u8,
    pub name: String,
}

/// A file-backed mmap region: VA range -> (path, file offset of `start`).
/// Pages are NOT mapped at mmap(2) time — the #PF handler fills each one
/// from the file on first touch (real demand paging).
#[derive(Clone)]
pub struct FileMap {
    pub start: u64,
    pub end: u64,
    pub path: String, // "" = demand-zero (bss sentinel)
    pub off: u64,
    pub perm: u8, // R1W2X4 — the demand pager maps with these flags
}

/// One POSIX timer (timer_create): decays on wall ticks, pends `sig`.
pub struct PTimer {
    pub id: u64,
    pub cur: u64, // ticks until fire; 0 = disarmed
    pub int: u64, // reload interval ticks; 0 = one-shot
    pub sig: u64,
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
    /// chroot jail root — physical prefix a task can't escape; "/"
    /// means unjailed. vfs::normalize clamps `..` at this prefix.
    pub root: String,
    /// Mount namespace — tmpfs mounts + bind aliases + lazily-detached
    /// trees. Shared via Arc: fork/clone keep the SAME namespace until
    /// unshare(CLONE_NEWNS) deep-copies it into a fresh Arc.
    pub ns: alloc::sync::Arc<spin::Mutex<MountNs>>,
    /// UTS namespace (hostname scope) — shared like the mount table
    /// until unshare(CLONE_NEWUTS) copies it.
    pub uts: alloc::sync::Arc<spin::Mutex<UtsNs>>,
    pub ports: Vec<u32>,
    pub shm: Vec<u32>,
    pub frames: Vec<u64>, // owned physical frames (kernel stack frames)
    pub mem_bytes: u64,
    pub waiting_on: u32, // pid we're wait_pid'ing on, 0 = none
    pub wait_port: u32,  // port id we're blocked receiving on, 0 = none
    pub wait_futex: u64, // phys-page key of the futex word we block on, 0 = none
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
    pub min_flt: u64,       // minor faults: zero-fill/bss/stack demand pages
    pub maj_flt: u64,       // major faults: pages read in from the image file
    pub stack_min: u64,     // this task's demand-grow stack region (0 = none)
    pub stack_max: u64,
    pub rbytes: u64,         // bytes read via vfs (/proc/<pid>/io)
    pub wbytes: u64,         // bytes written via vfs
    pub sigpending: u64,        // pending userspace-signal bitmask
    pub sighandlers: [u64; 32], // 0=SIG_DFL 1=SIG_IGN else handler VA
    pub sigrest_mapped: bool,   // sigreturn trampoline page installed
    pub sigmask: u64,           // blocked-signal bitmask (sigprocmask)
    pub alarm_at: u64,          // SIGALRM deadline (ms ticks; 0 = disarmed)
    pub pgid: u32,              // process-group id (kill(-pgid) targets it)
    /// Real/effective user+group ids — every task starts 0 (root);
    /// su/setuid are the only ways down.
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    /// saved ids (setresuid/setresgid third slot; setuid writes them for
    /// root so a non-root process may restore its effective id)
    pub suid: u32,
    pub sgid: u32,
    /// supplementary group list (setgroups/getgroups)
    pub groups: Vec<u32>,
    /// POSIX capabilities: permitted = what euid==0 wields, effective =
    /// what a non-root task holds (capset-granted), bounding = the
    /// irrecoverable ceiling (PR_CAPBSET_DROP). prm ⊆ bnd is enforced.
    pub cap_eff: u64,
    pub cap_prm: u64,
    pub cap_bnd: u64,
    /// PID namespace this task lives in (0 = the initial namespace).
    pub pid_ns: u64,
    /// virtual pid inside `pid_ns` (0 in the global namespace — `id`
    /// is the answer there). First member of a namespace is 1.
    pub nspid: u32,
    /// Linux's pidns_for_children: ns id staged by unshare/setns —
    /// children land there while the task itself keeps its own ns.
    pub child_ns: u64,    /// Time namespace membership + staged child timens (children-only
    /// entry like pidns — unshare/setns never move the caller).
    pub time_ns: u64,
    pub child_tns: u64,
    /// IPC namespace (SysV shm + POSIX mqueue views are scoped to it).
    pub ipc_ns: u64,
    /// User namespace (uid_map/gid_map id translations).
    pub user_ns: u64,
    /// cgroup id under /sys/fs/cgroup (0 = root group).
    pub cgroup: u64,
    pub sid: u32,               // session id (setsid detaches)
    pub ctty: u64,              // controlling tty: /dev/pts/{id} index (0 = none)
    pub ctid_va: u64,           // clear_child_tid: user u64 zeroed+futex-woken on exit
    pub pdeathsig: u8,          // PR_SET_PDEATHSIG: signal on parent's death
    pub stop_notified: bool,    // this stop already reported to waitpid
    pub stop_sig: u8,           // signal that stopped it (for WUNTRACED)
    pub sigsuspend_saved: u64,  // pre-suspend mask; u64::MAX = not in sigsuspend
    pub sigsuspend_seq: u64,    // sig_seq at arm time
    pub sig_seq: u64,           // bumped each time maybe_deliver consumes a pending bit
    pub fs_base: u64,           // IA32_FS_BASE — userspace TLS pointer
    pub rlim_nofile: u64,       // RLIMIT_NOFILE: fd-table bound
    pub rlim_nproc: u64,        // RLIMIT_NPROC: live user-task bound
    pub rlim_stack: u64,        // RLIMIT_STACK bytes (advisory for new spawns)
    pub rlim_cpu: u64,          // RLIMIT_CPU: ticks before SIGXCPU
    pub rlim_as: u64,           // RLIMIT_AS: total mapped bytes bound
    pub cur_syscall: u64,       // nr of the syscall this task is inside (MAX = none)
    pub sc_args: [u64; 5],      // its arg registers (for /proc/<pid>/syscall)
    pub itimers: [[u64; 2]; 3], // setitimer: [REAL, VIRTUAL, PROF] = [cur,int] ticks, cur 0 = disarmed
    pub ptimers: Vec<PTimer>,   // POSIX timer_create timers (not inherited)
    pub poll_saved_mask: u64,   // ppoll: sigmask before the ppoll swap (MAX = none)
    pub seccomp_mode: u8,       // 0 none, 1 strict (read/write/exit only), 2 allowlist
    pub seccomp_allow: [u64; 4],// bitmap of allowed syscall nrs (mode 2)
    pub robust_list: u64,       // userspace head of {next, futex_va} nodes
    pub poll_dl: u64,           // poll/epoll/ppoll absolute timeout deadline (0 = none);
                                // persists across int80 re-entry so finite timeouts fire
    pub cont_pending: bool,     // continued (SIGCONT/ptrace) since last wait report
    pub sig: SigState,          // sa_flags, altstack, handler masking, EINTR
}

/// Signal-semantic state beyond the raw handler/mask fields: per-signal
/// sa_flags, the registered alternate stack, the sigmask save stack used
/// while a handler runs, and the flag that turns a signal-woken blocked
/// syscall into a real EINTR return.
#[derive(Clone, Copy)]
pub struct SigState {
    pub sa_flags: [u8; 32],      // SA_RESTART/SA_ONSTACK/SA_NODEFER
    pub sigstack_sp: u64,        // registered alternate stack base (low addr)
    pub sigstack_size: u64,      // bytes; <2048 counts as unregistered
    pub sigstack_flags: u64,     // SS_DISABLE disables it
    pub sigmask_stack: [u64; 8], // sigmask saved while a handler runs
    pub sigmask_depth: u8,
    pub last_sig: u8,            // signal most recently run through a frame
    pub wake_eintr: bool,        // a signal woke our blocked syscall -> EINTR
    pub traced: bool,            // this task is ptrace'd — stops on signals
    pub tracer: u32,             // task id allowed to inspect/control it
    pub syscall_trace: bool,     // PTRACE_SYSCALL: stop on syscall boundaries
    pub sc_phase: u8,            // 0=disarmed 1=entry-stop pending 2=exit-stop pending
}

impl SigState {
    pub const fn new() -> Self {
        Self {
            sa_flags: [0; 32],
            sigstack_sp: 0,
            sigstack_size: 0,
            sigstack_flags: 0,
            sigmask_stack: [0; 8],
            sigmask_depth: 0,
            last_sig: 0,
            wake_eintr: false,
            traced: false,
            tracer: 0,
            syscall_trace: false,
            sc_phase: 0,
        }
    }

    /// fork inherits dispositions and the registered altstack; the handler
    /// mask stack and pending-EINTR state do not carry over.
    pub fn for_fork(&self) -> Self {
        let mut n = *self;
        n.sigmask_depth = 0;
        n.last_sig = 0;
        n.wake_eintr = false;
        n.traced = false; // ptrace linkage is never inherited
        n.tracer = 0;
        n.syscall_trace = false;
        n.sc_phase = 0;
        n
    }

    /// A clone'd thread shares dispositions but the alternate stack is
    /// per-thread — a fresh thread starts with it unregistered.
    pub fn for_thread(&self) -> Self {
        let mut n = self.for_fork();
        n.sigstack_sp = 0;
        n.sigstack_size = 0;
        n.sigstack_flags = 0;
        n
    }
}

pub struct Sched {
    pub tasks: Vec<Box<Task>>,
    pub cur: usize,
    pub next_pid: u32,
}

pub static SCHED: Mutex<Option<Sched>> = Mutex::new(None);

/// Address-space (mm) reference counts keyed by pml4 physical frame.
/// Cloned threads share their creator's pml4 — user space is torn down
/// only when the last sharer exits.
static MM_REFS: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());

fn mm_inc(phys: u64) {
    *MM_REFS.lock().entry(phys).or_insert(0) += 1;
}

/// Decrement the mm refcount; true when this was the last sharer.
fn mm_dec_last(phys: u64) -> bool {
    let mut g = MM_REFS.lock();
    match g.get_mut(&phys) {
        Some(n) => {
            *n -= 1;
            if *n == 0 {
                g.remove(&phys);
                true
            } else {
                false
            }
        }
        None => true,
    }
}
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
        root: String::from("/"),
        ns: global_ns(),
        uts: global_uts(),
        ports: Vec::new(),
        shm: Vec::new(),
        frames: Vec::new(),
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        wait_futex: 0,
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
        min_flt: 0,
        maj_flt: 0,
        stack_min: 0,
        stack_max: 0,
        rbytes: 0,
        wbytes: 0,
        sigpending: 0,
        sighandlers: [0; 32],
        sigrest_mapped: false,
        sigmask: 0,
        alarm_at: 0,
        pgid: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            groups: Vec::new(),
            cap_eff: 0,
            cap_prm: CAP_ALL,
            cap_bnd: CAP_ALL,
            pid_ns: 0,
            nspid: 0,
            child_ns: 0,
            time_ns: 0,
            child_tns: 0,
            ipc_ns: 0,
            user_ns: 0,
            cgroup: 0,
        sid: 0,
        ctty: 0,
        ctid_va: 0,
        pdeathsig: 0,
        stop_notified: false,
        stop_sig: 0,
        sigsuspend_saved: u64::MAX,
        sigsuspend_seq: 0,
        sig_seq: 0,
        fs_base: 0,
        rlim_nofile: 1024,
        rlim_nproc: 512,
        rlim_stack: 256 * 1024,
        rlim_cpu: u64::MAX,
        rlim_as: u64::MAX,
        cur_syscall: u64::MAX,
        sc_args: [0; 5],
        itimers: [[0; 2]; 3],
        ptimers: Vec::new(),
        poll_saved_mask: u64::MAX,
        seccomp_mode: 0,
        seccomp_allow: [0; 4],
        robust_list: 0,
        poll_dl: 0,
        cont_pending: false,
        sig: SigState::new(),
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
    let out_idx = s.cur;
    s.tasks[s.cur].saved_rsp = saved;
    s.tasks[s.cur].cpu_ticks += 1; // the outgoing task owned this interval
    crate::cgroup::charge(s.tasks[s.cur].cgroup);
    // charge virtual runtime: weight = 40 - nice (-20..=19 -> 60..=21),
    // further scaled by the task's cgroup cpu.weight (weight 100 = ×1;
    // 10000 = nearly no vrun -> wins CPU, 1 = 100x slower -> starved)
    {
        let t = &mut s.tasks[s.cur];
        let w = crate::cgroup::weight_of(t.cgroup).max(1);
        t.vrun += (4000 / (40 - t.nice as i64) as u64) * 100 / w;
    }
    // wake sleepers (sleep + timed waits) and decay itimers
    for (i, t) in s.tasks.iter_mut().enumerate() {
        if t.state == State::Blocked && t.wake_at <= ticks() {
            t.state = State::Running;
        }
        if t.alarm_at != 0 && t.alarm_at <= ticks() {
            t.alarm_at = 0;
            t.sigpending |= 1 << 14; // SIGALRM
            wake_for_signal(t, 14);
        }
        // setitimer decay: REAL runs on wall ticks; VIRTUAL/PROF charge
        // only the task that held the cpu this tick (i == s.cur)
        let ran = i == s.cur;
        for k in 0..3 {
            if t.itimers[k][0] == 0 {
                continue;
            }
            if k != 0 && !ran {
                continue;
            }
            t.itimers[k][0] -= 1;
            if t.itimers[k][0] == 0 {
                t.itimers[k][0] = t.itimers[k][1]; // 0 = one-shot
                let sig = [14usize, 26, 27][k]; // ALRM/VTALRM/PROF
                t.sigpending |= 1 << sig;
                wake_for_signal(t, sig);
            }
        }
        // POSIX timers (timer_create): wall-clock decay like ITIMER_REAL
        let mut fire: u64 = 0;
        for pt in t.ptimers.iter_mut() {
            if pt.cur == 0 {
                continue;
            }
            pt.cur -= 1;
            if pt.cur == 0 {
                pt.cur = pt.int;
                if pt.sig > 0 && pt.sig < 64 {
                    fire |= 1 << pt.sig;
                }
            }
        }
        let mut f = fire;
        while f != 0 {
            let sig = f.trailing_zeros() as usize;
            f &= !(1 << sig);
            t.sigpending |= 1 << sig;
            wake_for_signal(t, sig);
        }
        // RLIMIT_CPU: exceeded cpu_ticks quota pends a real SIGXCPU —
        // default disposition kills the task when it next resumes
        if t.is_user
            && t.state != State::Dead
            && t.cpu_ticks > t.rlim_cpu
            && t.sigpending & (1 << 24) == 0
        {
            t.sigpending |= 1 << 24; // SIGXCPU
            wake_for_signal(t, 24);
        }
    }
    // wake port receivers whose queues filled
    crate::ipc::wake_receivers(s);
    // CFS-lite: run the runnable task with the smallest virtual runtime;
    // runnable SCHED_RT tasks preempt every non-rt task first.
    // Scan starts just past `cur` so equal keys still round-robin.
    // Re-picks when signal delivery killed the chosen task.
    loop {
        let n = s.tasks.len();
        let mut best: Option<((u8, u64), usize)> = None;
        for off in 1..=n {
            let i = (s.cur + off) % n;
            let t = &s.tasks[i];
            // cgroup cpu.max: a group past quota is unschedulable
            // until its 1s window rolls
            if t.state == State::Running && !crate::cgroup::throttled(t.cgroup) {
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
                if s.tasks[out_idx].state == State::Running
                    && !crate::cgroup::throttled(s.tasks[out_idx].cgroup)
                {
                    return saved; // stay on current (idle) context
                }
                // the interrupted task was stopped/killed by delivery —
                // park on whatever is still runnable instead
                if let Some(i) =
                    s.tasks.iter().position(|t| t.state == State::Running && !crate::cgroup::throttled(t.cgroup))
                {
                    s.cur = i;
                    activate(&s.tasks[i]);
                    return s.tasks[i].saved_rsp;
                }
                return saved;
            }
        };
        s.cur = next;
        activate(&s.tasks[next]);
        let rsp = s.tasks[next].saved_rsp;
        maybe_deliver(s, next, rsp as *mut CpuContext);
        if s.tasks[s.cur].state != State::Dead
            && s.tasks[s.cur].state != State::Stopped
        {
            return rsp;
        }
        // delivery killed or stopped it — scan again
    }
}

fn activate(t: &Task) {
    if t.is_user {
        // TLS: every user task owns its FS base; CR4.FSGSBASE stays off
        // so the only writer is arch_prctl and this field stays true
        unsafe {
            x86_64::registers::model_specific::Msr::new(0xC000_0100)
                .write(t.fs_base);
        }
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
    'outer: loop {
        let n = s.tasks.len();
        // runnable rt tasks first, then anyone runnable
        for want_rt in [true, false] {
            for i in 1..=n {
                let t = &s.tasks[(s.cur + i) % n];
                if t.state == State::Running && t.rt == want_rt {
                    s.cur = (s.cur + i) % n;
                    activate(&s.tasks[s.cur]);
                    let rsp = s.tasks[s.cur].saved_rsp;
                    maybe_deliver(s, s.cur, rsp as *mut CpuContext);
                    // a fatal signal killed the pick during delivery —
                    // never resume a corpse: scan again
                    if s.tasks[s.cur].state == State::Dead
                        || s.tasks[s.cur].state == State::Stopped
                    {
                        continue 'outer;
                    }
                    drop(g);
                    unsafe { switch_tail(rsp) }
                }
            }
        }
        // nothing else to run — stay, unless the yielding task itself
        // was stopped/killed by its own signal delivery: then park on
        // any runnable task (a stopped ctx may not resume)
        if s.tasks[s.cur].state != State::Running {
            if let Some(i) =
                s.tasks.iter().position(|t| t.state == State::Running && !crate::cgroup::throttled(t.cgroup))
            {
                s.cur = i;
                activate(&s.tasks[i]);
                let rsp = s.tasks[i].saved_rsp;
                drop(g);
                unsafe { switch_tail(rsp) }
            }
        }
        drop(g);
        unsafe { switch_tail(ctx as u64) }
    }
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
    {
        let g = SCHED.lock();
        let s = g.as_ref().unwrap();
        let lim = s.tasks[s.cur].rlim_nproc;
        if lim != u64::MAX
            && s.tasks
                .iter()
                .filter(|t| t.is_user && t.state != State::Dead)
                .count() as u64
                >= lim
        {
            return Err(!0u64 - 10); // -11 EAGAIN
        }
    }
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

    // user stack: only the top page is mapped eagerly; the region below
    // demand-grows down to USER_STACK_MIN on first touch (#PF)
    let stack_lo = USER_STACK_TOP - 0x1000;
    let stack_frames = crate::elf::map_user_range(pml4, stack_lo, 0x1000, &mut frames)
        .ok_or(!0u64)?;
    let _ = stack_frames;
    umaps.push(MapEnt {
        start: stack_lo,
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
    let pid = match alloc_pid(s) {
        Some(p) => p,
        None => return Err(11),
    };
    let name = path.rsplit('/').next().unwrap_or(path);
    // children land in the parent's pidns_for_children (child_ns) when
    // set, else share the parent's namespace; a nonzero ns allocates a
    // virtual pid from that ns's counter.
    let par_ns = s
        .tasks
        .iter()
        .find(|t| t.id == parent)
        .map(|t| if t.child_ns != 0 { t.child_ns } else { t.pid_ns })
        .unwrap_or(0);
    let (pns, pnsv) = (par_ns, alloc_nspid(par_ns));
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
        root: String::from("/"),
        ns: global_ns(),
        uts: global_uts(),
        ports: Vec::new(),
        shm: Vec::new(),
        frames: kframes,
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        wait_futex: 0,
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
        min_flt: 0,
        maj_flt: 0,
        stack_min: USER_STACK_MIN,
        stack_max: USER_STACK_TOP,
        rbytes: 0,
        wbytes: 0,
        sigpending: 0,
        sighandlers: [0; 32],
        sigrest_mapped: false,
        sigmask: 0,
        alarm_at: 0,
        // POSIX: the child lands in the parent's process group + session
        pgid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.pgid).unwrap_or(0),
        uid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.uid).unwrap_or(0),
        gid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.gid).unwrap_or(0),
        euid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.euid).unwrap_or(0),
        egid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.egid).unwrap_or(0),
        suid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.suid).unwrap_or(0),
        sgid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.sgid).unwrap_or(0),
        groups: s.tasks.iter().find(|t| t.id == parent).map(|t| t.groups.clone()).unwrap_or_default(),
        cap_eff: s.tasks.iter().find(|t| t.id == parent).map(|t| t.cap_eff).unwrap_or(0),
        cap_prm: s.tasks.iter().find(|t| t.id == parent).map(|t| t.cap_prm).unwrap_or(CAP_ALL),
        cap_bnd: s.tasks.iter().find(|t| t.id == parent).map(|t| t.cap_bnd).unwrap_or(CAP_ALL),
        pid_ns: pns,
        nspid: pnsv,
        child_ns: s.tasks.iter().find(|t| t.id == parent).map(|t| t.child_ns).unwrap_or(0),
        time_ns: s.tasks.iter().find(|t| t.id == parent).map(|t| t.time_ns).unwrap_or(0),
        child_tns: s.tasks.iter().find(|t| t.id == parent).map(|t| t.child_tns).unwrap_or(0),
        ipc_ns: s.tasks.iter().find(|t| t.id == parent).map(|t| t.ipc_ns).unwrap_or(0),
        user_ns: s.tasks.iter().find(|t| t.id == parent).map(|t| t.user_ns).unwrap_or(0),
        cgroup: s.tasks.iter().find(|t| t.id == parent).map(|t| t.cgroup).unwrap_or(0),
        sid: s.tasks.iter().find(|t| t.id == parent).map(|t| t.sid).unwrap_or(0),
        ctty: s.tasks.iter().find(|t| t.id == parent).map(|t| t.ctty).unwrap_or(0),
        ctid_va: 0,
        pdeathsig: 0,
        stop_notified: false,
        stop_sig: 0,
        sigsuspend_saved: u64::MAX,
        sigsuspend_seq: 0,
        sig_seq: 0,
        fs_base: 0,
        rlim_nofile: 1024,
        rlim_nproc: 512,
        rlim_stack: 256 * 1024,
        rlim_cpu: u64::MAX,
        rlim_as: u64::MAX,
        cur_syscall: u64::MAX,
        sc_args: [0; 5],
        itimers: [[0; 2]; 3],
        ptimers: Vec::new(),
        poll_saved_mask: u64::MAX,
        seccomp_mode: 0,
        seccomp_allow: [0; 4],
        robust_list: 0,
        poll_dl: 0,
        cont_pending: false,
        sig: SigState::new(),
    };
    mm_inc(pml4.start_address().as_u64());
    s.tasks.push(Box::new(t));
    sprintln!("[task] spawned pid={} '{}' entry={:#x}", pid, name, entry);
    Ok(pid)
}

/// kernel.pid_max-aware pid allocation: ids grow monotonically until
/// they would exceed pid_max, then wrap-scan [1, pid_max] for a free
/// slot. EAGAIN (None) when the table is also at kernel.threads-max.
fn alloc_pid(s: &mut Sched) -> Option<u32> {
    let live = s.tasks.iter().filter(|t| t.state != State::Dead).count() as u64;
    if live >= crate::sysctl::threads_max() {
        return None;
    }
    let cap = crate::sysctl::pid_max();
    if s.next_pid as u64 <= cap {
        let pid = s.next_pid;
        s.next_pid += 1;
        return Some(pid);
    }
    (1..=cap as u32).find(|c| !s.tasks.iter().any(|t| t.id == *c))
}

/// fs.file-nr: live open descriptors across every task — the number
/// Linux reports as /proc/sys/fs/file-nr's first field.
pub fn live_fd_count() -> u64 {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return 0 };
    s.tasks
        .iter()
        .filter(|t| t.state != State::Dead)
        .map(|t| t.fds.iter().flatten().count() as u64)
        .sum()
}

/// Spawn a kernel-space thread.
pub fn spawn_kernel(name: &str, func: extern "C" fn() -> !) -> u32 {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let pid = match alloc_pid(s) {
        Some(p) => p,
        None => return 0,
    };
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
        root: String::from("/"),
        ns: global_ns(),
        uts: global_uts(),
        ports: Vec::new(),
        shm: Vec::new(),
        frames: kframes,
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        wait_futex: 0,
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
        min_flt: 0,
        maj_flt: 0,
        stack_min: 0,
        stack_max: 0,
        rbytes: 0,
        wbytes: 0,
        sigpending: 0,
        sighandlers: [0; 32],
        sigrest_mapped: false,
        sigmask: 0,
        alarm_at: 0,
        pgid: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            groups: Vec::new(),
            cap_eff: 0,
            cap_prm: CAP_ALL,
            cap_bnd: CAP_ALL,
            pid_ns: 0,
            nspid: 0,
            child_ns: 0,
            time_ns: 0,
            child_tns: 0,
            ipc_ns: 0,
            user_ns: 0,
            cgroup: 0,
        sid: 0,
        ctty: 0,
        ctid_va: 0,
        pdeathsig: 0,
        stop_notified: false,
        stop_sig: 0,
        sigsuspend_saved: u64::MAX,
        sigsuspend_seq: 0,
        sig_seq: 0,
        fs_base: 0,
        rlim_nofile: 1024,
        rlim_nproc: 512,
        rlim_stack: 256 * 1024,
        rlim_cpu: u64::MAX,
        rlim_as: u64::MAX,
        cur_syscall: u64::MAX,
        sc_args: [0; 5],
        itimers: [[0; 2]; 3],
        ptimers: Vec::new(),
        poll_saved_mask: u64::MAX,
        seccomp_mode: 0,
        seccomp_allow: [0; 4],
        robust_list: 0,
        poll_dl: 0,
        cont_pending: false,
        sig: SigState::new(),
    }));
    pid
}

/// SYS_CLONE: start a thread inside the caller's address space — shares
/// the pml4 (mm refcount +1) but gets its own kernel stack and a private
/// 256KiB user-stack slot in the thread arena, demand-grown on fault.
/// (entry, arg): the thread starts at `entry` with `arg` in rdi.
pub fn clone_user(entry: u64, arg: u64, tls: u64, ctid: u64) -> Option<u32> {
    // RLIMIT_NPROC: live user-task count against the caller's limit
    {
        let g = SCHED.lock();
        let s = g.as_ref().unwrap();
        let lim = s.tasks[s.cur].rlim_nproc;
        if lim != u64::MAX
            && s.tasks
                .iter()
                .filter(|t| t.is_user && t.state != State::Dead)
                .count() as u64
                >= lim
        {
            return None;
        }
    }
    // entry must be a plausible user text address (below the thread arena)
    if entry == 0 || entry >= THREAD_STK_MIN || entry & 0xFFFF_8000_0000_0000 != 0 {
        return None;
    }
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let pml4 = s.tasks[s.cur].pml4?;
    // find a free slot: an unmapped top page marks the slot unused
    let mut slot = THREAD_STK_MIN;
    let stack_top = loop {
        if slot + THREAD_STK_PAGES * 0x1000 > THREAD_STK_MAX {
            return None;
        }
        let top = slot + THREAD_STK_PAGES * 0x1000;
        if crate::elf::translate(pml4, top - 0x1000).is_none() {
            break top;
        }
        slot += THREAD_STK_PAGES * 0x1000;
    };
    // eager top page: marks the slot busy AND gives the thread somewhere
    // to land; deeper pages demand-grow on #PF like the main stack
    let mut scratch = Vec::new();
    crate::elf::map_user_page_flags(pml4, stack_top - 0x1000, true, false, &mut scratch)?;
    if scratch.is_empty() {
        return None;
    }
    let mut kframes = Vec::new();
    let (kbase, ktop) = alloc_kstack(&mut kframes);
    let ctx = (ktop - core::mem::size_of::<CpuContext>() as u64) as *mut CpuContext;
    unsafe {
        core::ptr::write(ctx, CpuContext::default());
        let c = &mut *ctx;
        c.rip = entry;
        c.cs = gdt::USER_CS.0 as u64;
        c.rflags = 0x202;
        c.rsp = stack_top - 8;
        c.ss = gdt::USER_DS.0 as u64;
        c.rdi = arg;
    }
    let pid = match alloc_pid(s) {
        Some(p) => p,
        None => return None,
    };
    // snapshot the parent's mm-facing state BEFORE mutating the list
    let cur = &mut s.tasks[s.cur];
    let parent = cur.id;
    let name = alloc::format!("{}:t{}", cur.name, pid);
    let mut maps = cur.maps.clone();
    maps.push(MapEnt {
        start: slot,
        end: stack_top,
        perm: 1 | 2,
        name: String::from("[tstack]"),
    });
    let filemaps = cur.filemaps.clone();
    let fds = cur.fds.clone();
    // each copied desc is a new holder of its kernel object (pipe role,
    // sockpair side counts); destructive objects stay live via the
    // last-reference scan in release_desc
    for f in fds.iter().flatten() {
        crate::vfs::acquire_desc(f);
    }
    let cwd = cur.cwd.clone();
    let root = cur.root.clone();
    let nsr = cur.ns.clone();
    let utsr = cur.uts.clone();
    let creds = (cur.uid, cur.gid, cur.euid, cur.egid);
    let (sids, grps, caps) = (
        (cur.suid, cur.sgid),
        cur.groups.clone(),
        (cur.cap_eff, cur.cap_prm, cur.cap_bnd),
    );
    let cns = if cur.child_ns != 0 { cur.child_ns } else { cur.pid_ns };
    let (pns, pnsv) = (cns, alloc_nspid(cns));
    let ctns = if cur.child_tns != 0 { cur.child_tns } else { cur.time_ns };
    let borrowed = cur.borrowed.clone();
    let shm_ids = cur.shm.clone();
    let (nice, rt, vrun, umask, exe, pfs, rnf, rnp, rstk, rcu, ras) = (
        cur.nice,
        cur.rt,
        cur.vrun,
        cur.umask,
        cur.exe.clone(),
        cur.fs_base,
        cur.rlim_nofile,
        cur.rlim_nproc,
        cur.rlim_stack,
        cur.rlim_cpu,
        cur.rlim_as,
    );
    for id in &shm_ids {
        shm::acquire(*id);
    }
    let t = Task {
        id: pid,
        name,
        argv: String::new(),
        is_user: true,
        state: State::Running,
        saved_rsp: ctx as u64,
        kstack: kbase,
        kstack_top: ktop,
        pml4: Some(pml4),
        wake_at: 0,
        exit_code: 0,
        parent,
        fds,
        cwd,
        root,
        ns: nsr,
        uts: utsr,
        uid: creds.0,
        gid: creds.1,
        euid: creds.2,
        egid: creds.3,
        suid: sids.0,
        sgid: sids.1,
        groups: grps,
        cap_eff: caps.0,
        cap_prm: caps.1,
        cap_bnd: caps.2,
        time_ns: ctns,
        child_tns: cur.child_tns,
        ipc_ns: cur.ipc_ns,
        user_ns: cur.user_ns,
        cgroup: cur.cgroup,
        pid_ns: pns,
        nspid: pnsv,
        child_ns: cur.child_ns,
        ports: Vec::new(),
        shm: shm_ids,
        frames: kframes,
        mem_bytes: 0,
        waiting_on: 0,
        wait_port: 0,
        wait_futex: 0,
        borrowed,
        mmap_next: s.tasks[s.cur].mmap_next,
        arg_page: USER_ARG_PAGE,
        sleep_deadline: 0,
        wait_timeout: 0,
        cpu_ticks: 0,
        nice,
        rt,
        vrun,
        trace: false,
        trbuf: Vec::new(),
        umask,
        exe,
        maps,
        filemaps,
        min_flt: 0,
        maj_flt: 0,
        stack_min: slot,
        stack_max: stack_top,
        rbytes: 0,
        wbytes: 0,
        sigpending: 0,
        sighandlers: s.tasks[s.cur].sighandlers,
        sigrest_mapped: s.tasks[s.cur].sigrest_mapped,
        sigmask: s.tasks[s.cur].sigmask,
        alarm_at: 0,
        pgid: s.tasks[s.cur].pgid,
        sid: s.tasks[s.cur].sid,
        ctty: s.tasks[s.cur].ctty,
        ctid_va: ctid,
        pdeathsig: 0,
        stop_notified: false,
        stop_sig: 0,
        sigsuspend_saved: u64::MAX,
        sigsuspend_seq: 0,
        sig_seq: 0,
        fs_base: if tls != 0 { tls } else { pfs },
        rlim_nofile: rnf,
        rlim_nproc: rnp,
        rlim_stack: rstk,
        rlim_cpu: rcu,
        rlim_as: ras,
        cur_syscall: u64::MAX,
        sc_args: [0; 5],
        itimers: [[0; 2]; 3],
        ptimers: Vec::new(),
        poll_saved_mask: u64::MAX,
        seccomp_mode: 0,
        seccomp_allow: [0; 4],
        robust_list: 0,
        poll_dl: 0,
        cont_pending: false,
        sig: s.tasks[s.cur].sig.for_thread(),
    };
    mm_inc(pml4.start_address().as_u64());
    if ctid != 0 {
        // CLONE_CHILD_SETTID: the tid lands at the child's ctid address
        if let Some(pa) = crate::elf::translate_user(pml4, ctid) {
            unsafe { *(crate::mem::phys_to_virt(pa) as *mut u64) = pid as u64 };
        }
    }
    s.tasks.push(Box::new(t));
    if tls != 0 {
        // CLONE_SETTLS contract: store the child tid at fs:8 — same mm,
        // so translate through the shared page table and write the frame
        if let Some(pp) = crate::elf::translate_user(pml4, tls + 8) {
            unsafe {
                core::ptr::write_unaligned(
                    mem::phys_to_virt(pp) as *mut u64,
                    pid as u64,
                );
            }
        }
    }
    sprintln!("[task] cloned pid={} entry={:#x} stk={:#x}", pid, entry, stack_top);
    Some(pid)
}

/// Sigreturn trampoline page — sits just under the thread-stack arena,
/// clear of every other VA region. Contents: `mov rax, SYS_SIGRETURN;
/// int 0x80` — a handler's return address points here.
pub const SIGREST_VA: u64 = 0x7BFF_F000;

/// Grow task `t`'s demand-paged stack by one page. Returns true only when
/// a fresh page was actually mapped — an already-present page means this
/// was a real protection fault, not growth.
fn stack_grow(t: &mut Task, page: u64) -> bool {
    let Some(pml4) = t.pml4 else { return false };
    if crate::elf::translate_user(pml4, page).is_some() {
        return false;
    }
    let mut scratch = Vec::new();
    let Some(phys) = crate::elf::map_user_page_flags(pml4, page, true, false, &mut scratch)
    else {
        return false;
    };
    t.frames.push(phys);
    t.min_flt += 1;
    if let Some(m) = t.maps.iter_mut().find(|m| m.name == "[stack]") {
        m.start = m.start.min(page);
    }
    true
}

/// Deliver one pending signal to task `idx` by rewriting the user-mode
/// ctx it is about to resume on: the interrupted CpuContext is pushed
/// onto the user stack and rip diverts to the registered handler, whose
/// return address is the sigreturn trampoline (sigreturn restores the
/// frame). Default dispositions act here too — SIG_IGN drops, SIGCONT
/// resumes silently, anything else uncaught terminates with 128+sig.
/// Called with SCHED held, just before a ring-3 ctx resumes.
/// Wake a Blocked task for an incoming signal. POSIX: a signal that will
/// run a handler interrupts the blocked syscall — it returns EINTR unless
/// the handler was installed with SA_RESTART (block_reenter consumes
/// `wake_eintr`). Masked or handler-less signals just wake the task; the
/// disposition is decided in maybe_deliver.
pub fn wake_for_signal(t: &mut Task, sig: usize) {
    if t.state != State::Blocked {
        return;
    }
    let will_handle =
        t.sighandlers[sig] > 1 && (t.sigmask >> sig) & 1 == 0;
    if will_handle && (t.sig.sa_flags[sig] & shared::SA_RESTART) == 0 {
        t.sig.wake_eintr = true;
    }
    t.state = State::Running;
    t.waiting_on = 0;
    t.wait_port = 0;
    t.wait_futex = 0;
}

/// #DB handler hook: a traced task completing a single-step gets a real
/// SIGTRAP — pending it and returning true so the exception handler can
/// resume (the traced-stop fires at the next delivery point).
pub fn db_hit() -> bool {
    let mut g = SCHED.lock();
    if let Some(s) = g.as_mut() {
        let t = &mut s.tasks[s.cur];
        if t.sig.traced {
            t.sigpending |= 1 << 5; // SIGTRAP
            return true;
        }
    }
    false
}

pub fn maybe_deliver(s: &mut Sched, idx: usize, ctx: *mut CpuContext) {
    let t = &mut s.tasks[idx];
    if !t.is_user || t.sigpending == 0 {
        return;
    }
    let c = unsafe { &mut *ctx };
    if c.cs & 3 != 3 {
        return; // suspended inside the kernel — deliver on a later resume
    }
    let deliverable = t.sigpending & !t.sigmask;
    if deliverable == 0 {
        return; // everything pending is blocked — stays queued
    }
    let sig = deliverable.trailing_zeros() as usize;
    // A signal that woke a blocked syscall carries its EINTR intent in
    // the handler frame (byte below the context) — the task flag clears
    // here so the handler's own syscalls are unaffected; sigreturn
    // re-arms it for the interrupted ctx's next block_reenter.
    let eintr_frame = t.sig.wake_eintr;
    t.sig.wake_eintr = false;
    t.sig_seq = t.sig_seq.wrapping_add(1); // a pending signal is being consumed
    if t.sig.traced && t.sig.tracer != 0 && sig != 9 {
        // ptrace signal-delivery stop: park BEFORE the disposition runs;
        // the bit stays pending — PTRACE_CONT decides suppress vs deliver
        t.state = State::Stopped;
        t.stop_sig = sig as u8;
        t.waiting_on = 0;
        t.wait_port = 0;
        t.wait_futex = 0;
        return;
    }
    let handler = t.sighandlers[sig];
    if handler == 1 {
        t.sigpending &= !(1 << sig);
        return; // SIG_IGN
    }
    if handler == 0 && (sig == 18 || sig == 17) {
        t.sigpending &= !(1 << sig);
        return; // SIGCONT resumes / SIGCHLD default-ignores: no frame
    }
    if handler == 0 && (19..=22).contains(&sig) {
        // default disposition of job-control signals: stop the task
        t.sigpending &= !(1 << sig);
        if t.state != State::Dead {
            t.state = State::Stopped;
            t.stop_sig = sig as u8;
            t.waiting_on = 0;
            t.wait_port = 0;
            t.wait_futex = 0;
        }
        return;
    }
    if handler == 0 {
        t.sigpending &= !(1 << sig);
        // uncaught terminating signal — POSIX wait status 128+sig
        kill_at(s, idx, 128 + sig as i64);
        return;
    }
    let Some(pml4) = t.pml4 else { return };
    if !t.sigrest_mapped {
        // lazily install the sigreturn trampoline page for this mm
        let mut sc = Vec::new();
        if crate::elf::map_user_page_flags(pml4, SIGREST_VA, false, true, &mut sc).is_none() {
            return;
        }
        let Some(pp) = crate::elf::translate_user(pml4, SIGREST_VA) else {
            return;
        };
        let tramp: [u8; 9] = [
            0x48, 0xC7, 0xC0, shared::SYS_SIGRETURN as u8, 0, 0, 0, 0xCD, 0x80,
        ];
        unsafe {
            core::ptr::copy_nonoverlapping(tramp.as_ptr(), mem::phys_to_virt(pp) as *mut u8, 9);
        }
        t.sigrest_mapped = true;
    }
    // frame: 160B saved CpuContext then the 8B trampoline return address;
    // handler entry rsp = base+160 (≡ 8 mod 16 like a real call site).
    // SA_ONSTACK puts the frame at the top of the registered alternate
    // stack instead — unless we're already running on it (nested handlers
    // continue downward, POSIX-style).
    let on_alt = c.rsp >= t.sig.sigstack_sp
        && c.rsp < t.sig.sigstack_sp + t.sig.sigstack_size;
    let use_alt = t.sig.sa_flags[sig] & shared::SA_ONSTACK != 0
        && t.sig.sigstack_size >= 2048
        && t.sig.sigstack_flags & shared::SS_DISABLE == 0
        && !on_alt;
    // The 168B footprint (160B ctx + 8B trampoline ret) must end strictly
    // below the interrupted rsp: reserving only 168 lets base+160 land
    // exactly on c.rsp when rsp ≡ 8 (mod 16), clobbering the caller's
    // return address with the trampoline — resume then ret's back into
    // sigreturn forever. Reserve 176 so base+168 <= c.rsp always.
    let base = if use_alt {
        let top = t.sig.sigstack_sp + t.sig.sigstack_size;
        ((top.wrapping_sub(176)) & !0xF) + 8
    } else {
        ((c.rsp.wrapping_sub(176)) & !0xF) + 8
    };
    let mut segv = false;
    for page in [(base - 8) & !0xFFF, (base + 167) & !0xFFF] {
        match crate::elf::translate_user(pml4, page) {
            None => {
                // sys_sigaltstack pre-faults registered alt stacks and
                // stack pages grow via the same task-scoped path — an
                // unmapped frame target here is a genuine bad stack.
                if !(page >= t.stack_min && page < t.stack_max && stack_grow(t, page)) {
                    segv = true;
                    break;
                }
            }
            Some(p) => {
                cow_split(pml4, page, p & !0xFFF); // split shared stack pages
            }
        }
    }
    if segv {
        kill_at(s, idx, 128 + 11); // undeliverable = SIGSEGV
        return;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ctx as *const u8, 160) };
    let mut ok = true;
    for (i, w) in bytes.chunks_exact(8).enumerate() {
        let va = base + (i * 8) as u64;
        match crate::elf::translate_user(pml4, va) {
            Some(p) => unsafe {
                *(mem::phys_to_virt(p) as *mut u64) =
                    u64::from_le_bytes(w.try_into().unwrap());
            },
            None => {
                ok = false;
                break;
            }
        }
    }
    if ok {
        match crate::elf::translate_user(pml4, base + 160) {
            Some(p) => unsafe {
                *(mem::phys_to_virt(p) as *mut u64) = SIGREST_VA;
            },
            None => ok = false,
        }
    }
    if ok {
        match crate::elf::translate_user(pml4, base - 8) {
            Some(p) => unsafe {
                *(mem::phys_to_virt(p) as *mut u64) = eintr_frame as u64;
            },
            None => ok = false,
        }
    }
    if !ok {
        kill_at(s, idx, 128 + 11);
        return;
    }
    c.rdi = sig as u64; // handler arg
    c.rsi = 0;
    c.rip = handler;
    c.rsp = base + 160;
    // POSIX: the delivered signal is masked inside its own handler unless
    // SA_NODEFER; the pre-handler mask is stacked and sigreturn pops it.
    if (t.sig.sigmask_depth as usize) < 8 {
        t.sig.sigmask_stack[t.sig.sigmask_depth as usize] = t.sigmask;
        t.sig.sigmask_depth += 1;
    }
    if t.sig.sa_flags[sig] & shared::SA_NODEFER == 0 {
        t.sigmask |= 1 << sig;
    }
    t.sig.last_sig = sig as u8;
    t.sigpending &= !(1 << sig);
}

/// Copy-on-write bookkeeping: (owner pml4 phys, va page) -> shared phys
/// with the exec bit packed into bit 63. fork() records every writable
/// page it demotes to read-only in both tables — the first write fault
/// in either mm splits the page.
static MM_COW: Mutex<alloc::collections::BTreeMap<(u64, u64), u64>> =
    Mutex::new(alloc::collections::BTreeMap::new());

fn cow_lookup(pml4: u64, page: u64) -> Option<u64> {
    MM_COW.lock().get(&(pml4, page)).copied()
}
fn cow_insert(pml4: u64, page: u64, packed: u64) {
    MM_COW.lock().insert((pml4, page), packed);
}
/// Forget the COW record for one unmapped page.
pub fn cow_unmap(pml4: u64, page: u64) {
    MM_COW.lock().remove(&(pml4, page));
}
/// Forget every COW record in [lo,hi) — unmapped/mprotect-split ranges.
pub fn cow_unmap_range(pml4: u64, lo: u64, hi: u64) {
    let mut m = MM_COW.lock();
    let mut a = lo;
    while a < hi {
        m.remove(&(pml4, a));
        a += 0x1000;
    }
}
/// Drop all COW records owned by a pml4 being torn down — a stale entry
/// would alias whatever address space the freed pml4 frame gets reused
/// for next.
pub fn cow_drop_mm(pml4: u64) {
    MM_COW.lock().retain(|(p, _), _| *p != pml4);
}

/// Resolve a write fault on a COW page in the CURRENT task's table:
/// last mapper claims the shared frame in place, otherwise the page is
/// copied into a fresh frame and the shared ref released. true = retry.
pub fn cow_resolve(va: u64) -> bool {
    let page = va & !0xFFF;
    let Some((pml4, packed)) =
        with_current(|t| t.pml4.map(|p| (p, cow_lookup(p.start_address().as_u64(), page))))
    else {
        return false;
    };
    let Some(packed) = packed else { return false };
    let phys = packed & !(1u64 << 63);
    let exec = packed >> 63 != 0;
    let pp = pml4.start_address().as_u64();
    if mem::cow_count(phys) <= 1 {
        // sole mapper left — promote the existing page back to writable
        mem::cow_claim(phys);
        let _ = crate::elf::protect_user_page(pml4, page, true, exec);
    } else {
        let Some(nf) = mem::alloc_frame() else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                mem::phys_to_virt(phys) as *const u8,
                mem::phys_to_virt(nf.start_address().as_u64()) as *mut u8,
                0x1000,
            );
        }
        let _ = crate::elf::unmap_user_page(pml4, page);
        crate::elf::map_phys_user_flags(
            pml4,
            page,
            nf.start_address().as_u64(),
            true,
            exec,
            &mut Vec::new(),
        );
        mem::free_frame(phys); // release our share (still mapped elsewhere)
        with_current(|t| {
            t.frames.push(nf.start_address().as_u64());
        });
    }
    cow_unmap(pp, page);
    with_current(|t| t.maj_flt += 1);
    unsafe { x86_64::instructions::tlb::flush_all() };
    true
}

/// Break COW sharing on `page` in `pml4` — used by mprotect when turning
/// a shared-RO frame writable: split into a private copy first so the
/// other mm keeps its own contents. true = the page is private now.
pub fn cow_split(pml4: PhysFrame, page: u64, phys: u64) -> bool {
    let pp = pml4.start_address().as_u64();
    let n = mem::cow_count(phys);
    let was_tracked = MM_COW.lock().contains_key(&(pp, page));
    if n <= 1 && !was_tracked {
        return false; // already private
    }
    // a recorded page was logically writable (or executable) before it
    // was shared — splitting restores that writability, same as the
    // write-fault path in cow_resolve; callers re-protect if needed
    let x = MM_COW
        .lock()
        .get(&(pp, page))
        .map(|p| p >> 63 != 0)
        .unwrap_or(false);
    if n <= 1 {
        mem::cow_claim(phys);
        crate::elf::protect_user_page(pml4, page, true, x);
    } else {
        let Some(nf) = mem::alloc_frame() else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                mem::phys_to_virt(phys) as *const u8,
                mem::phys_to_virt(nf.start_address().as_u64()) as *mut u8,
                0x1000,
            );
        }
        let _ = crate::elf::unmap_user_page(pml4, page);
        crate::elf::map_phys_user_flags(
            pml4,
            page,
            nf.start_address().as_u64(),
            true,
            x,
            &mut Vec::new(),
        );
        mem::free_frame(phys);
    }
    cow_unmap(pp, page);
    true
}

/// SYS_FORK: duplicate the calling task into a child resuming at the same
/// userspace instruction with rax=0. Copy-on-write: every present private
/// page is mapped READ-ONLY into the child and shared via COW_REFS; the
/// parent's own writable pages are demoted too, so a first write on
/// either side faults and copies just that page. Read-only pages are
/// shared outright (refcounted, never promoted). Borrowed (shm/fb)
/// frames stay genuinely shared. Returns Some(pid) to the parent.
pub fn fork_current(parent_ctx: &CpuContext) -> Option<u32> {
    {
        let g = SCHED.lock();
        let s = g.as_ref().unwrap();
        let lim = s.tasks[s.cur].rlim_nproc;
        if lim != u64::MAX
            && s.tasks
                .iter()
                .filter(|t| t.is_user && t.state != State::Dead)
                .count() as u64
                >= lim
        {
            return None;
        }
    }
    // kernel stack FIRST so the new pml4 inherits the kernel PDPT with it
    let mut kframes = Vec::new();
    let (kbase, ktop) = alloc_kstack(&mut kframes);
    let cpml4 = create_user_pml4()?;
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let pid = match alloc_pid(s) {
        Some(p) => p,
        None => return None,
    };
    let cur = &mut s.tasks[s.cur];
    let pml4 = cur.pml4?;
    let parent = cur.id;

    // share every present user page with the child — no copies
    let pphys4 = pml4.start_address().as_u64();
    let cphys4 = cpml4.start_address().as_u64();
    let mut cborrowed: Vec<u64> = Vec::new();
    let mut pt_scratch: Vec<u64> = Vec::new(); // intermediate PT frames of the child
    let mut cowm: Vec<(u64, u64)> = Vec::new(); // (va, phys|exec<<63)
    let mut ok = true;
    for (va, pphys, w, x) in crate::elf::collect_user_pages(pml4) {
        if cur.borrowed.contains(&pphys) {
            if !crate::elf::map_phys_user_flags(cpml4, va, pphys, w, x, &mut pt_scratch) {
                ok = false;
                break;
            }
            cborrowed.push(pphys);
            continue;
        }
        // already COW-shared by an earlier fork (nested fork) — the va
        // record carries the original permissions
        let prior = cow_lookup(pphys4, va);
        let is_cow = w || prior.is_some();
        if !crate::elf::map_phys_user_flags(cpml4, va, pphys, false, x, &mut pt_scratch) {
            ok = false;
            break;
        }
        mem::cow_share(pphys);
        if is_cow {
            let packed = prior.unwrap_or(pphys | ((x as u64) << 63));
            cowm.push((va, packed));
            if w {
                // demote the parent page too — first write on either
                // side faults through cow_resolve
                let _ = crate::elf::protect_user_page(pml4, va, false, x);
            }
        }
    }
    if ok {
        for (va, packed) in &cowm {
            cow_insert(pphys4, *va, *packed);
            cow_insert(cphys4, *va, *packed);
        }
        unsafe { x86_64::instructions::tlb::flush_all() }; // we demoted live ptes
    }
    if !ok {
        // unwind: restore parent perms/records, free the child's shares
        for (va, packed) in &cowm {
            let x = packed >> 63 != 0;
            let _ = crate::elf::protect_user_page(pml4, *va, true, x);
            cow_unmap(pphys4, *va);
        }
        unsafe { x86_64::instructions::tlb::flush_all() };
        let freed = crate::elf::free_user_space(cpml4);
        for f in freed {
            if !cborrowed.contains(&f) {
                mem::free_frame(f);
            }
        }
        cow_drop_mm(cphys4);
        mem::free_frame(cpml4.start_address().as_u64());
        free_frames(&kframes);
        return None;
    }
    let _ = pt_scratch; // owned by the child table tree now

    let fds = cur.fds.clone();
    for f in fds.iter().flatten() {
        crate::vfs::acquire_desc(f);
    }
    let shm_ids = cur.shm.clone();
    for id in &shm_ids {
        shm::acquire(*id);
    }
    let (name, argv, cwd, root, nsr, utsr) = (
        cur.name.clone(),
        cur.argv.clone(),
        cur.cwd.clone(),
        cur.root.clone(),
        cur.ns.clone(),
        cur.uts.clone(),
    );
    let creds = (cur.uid, cur.gid, cur.euid, cur.egid);
    let (sids, grps) = ((cur.suid, cur.sgid), cur.groups.clone());
    let cns = if cur.child_ns != 0 { cur.child_ns } else { cur.pid_ns };
    let (pns, pnsv) = (cns, alloc_nspid(cns));
    let ctns = if cur.child_tns != 0 { cur.child_tns } else { cur.time_ns };
    let (maps, filemaps) = (cur.maps.clone(), cur.filemaps.clone());
    let (nice, umask, exe) = (cur.nice, cur.umask, cur.exe.clone());
    let (smin, smax, mnext, apage) = (cur.stack_min, cur.stack_max, cur.mmap_next, cur.arg_page);

    // the child resumes right after the int-80 with rax=0
    let ctx = (ktop - core::mem::size_of::<CpuContext>() as u64) as *mut CpuContext;
    unsafe {
        core::ptr::write(ctx, *parent_ctx);
        (*ctx).rax = 0;
    }
    let t = Task {
        id: pid,
        name,
        argv,
        is_user: true,
        state: State::Running,
        saved_rsp: ctx as u64,
        kstack: kbase,
        kstack_top: ktop,
        pml4: Some(cpml4),
        wake_at: 0,
        exit_code: 0,
        parent,
        fds,
        cwd,
        root,
        ns: nsr,
        uts: utsr,
        uid: cur.uid,
        gid: cur.gid,
        euid: cur.euid,
        egid: cur.egid,
        suid: cur.suid,
        sgid: cur.sgid,
        groups: cur.groups.clone(),
        cap_eff: cur.cap_eff,
        cap_prm: cur.cap_prm,
        cap_bnd: cur.cap_bnd,
        time_ns: ctns,
        child_tns: cur.child_tns,
        ipc_ns: cur.ipc_ns,
        user_ns: cur.user_ns,
        cgroup: cur.cgroup,
        pid_ns: pns,
        nspid: pnsv,
        child_ns: cur.child_ns,
        ports: Vec::new(),
        shm: shm_ids,
        frames: kframes,
        mem_bytes: cur.mem_bytes,
        waiting_on: 0,
        wait_port: 0,
        wait_futex: 0,
        borrowed: cborrowed,
        mmap_next: mnext,
        arg_page: apage,
        sleep_deadline: 0,
        wait_timeout: 0,
        cpu_ticks: 0,
        nice,
        rt: false,
        vrun: cur.vrun,
        trace: false,
        trbuf: Vec::new(),
        umask,
        exe,
        maps,
        filemaps,
        min_flt: 0,
        maj_flt: 0,
        stack_min: smin,
        stack_max: smax,
        rbytes: 0,
        wbytes: 0,
        sigpending: 0,
        sighandlers: cur.sighandlers,
        sigrest_mapped: cur.sigrest_mapped,
        sigmask: cur.sigmask,
        alarm_at: 0,
        pgid: cur.pgid,
        sid: cur.sid,
        ctty: cur.ctty,
        ctid_va: 0,
        pdeathsig: 0,
        stop_notified: false,
        stop_sig: 0,
        sigsuspend_saved: u64::MAX,
        sigsuspend_seq: 0,
        sig_seq: 0,
        fs_base: s.tasks[s.cur].fs_base,
        rlim_nofile: s.tasks[s.cur].rlim_nofile,
        rlim_nproc: s.tasks[s.cur].rlim_nproc,
        rlim_stack: s.tasks[s.cur].rlim_stack,
        rlim_cpu: s.tasks[s.cur].rlim_cpu,
        rlim_as: s.tasks[s.cur].rlim_as,
        cur_syscall: u64::MAX,
        sc_args: [0; 5],
        itimers: [[0; 2]; 3],
        ptimers: Vec::new(),
        poll_saved_mask: u64::MAX,
        seccomp_mode: 0,
        seccomp_allow: [0; 4],
        robust_list: 0,
        poll_dl: 0,
        cont_pending: false,
        sig: s.tasks[s.cur].sig.for_fork(),
    };
    mm_inc(cpml4.start_address().as_u64());
    s.tasks.push(Box::new(t));
    sprintln!("[task] forked pid={} from pid={}", pid, parent);
    Some(pid)
}

/// SYS_EXECVE: replace the calling task's image. Builds the whole new
/// user space on a fresh pml4 first — any failure keeps the old image
/// running and returns false, so exec is never half-applied. fds stay
/// open (POSIX), shm segments detach, the old mm frees only when this
/// task was its last user.
pub fn exec_current(ctx: &mut CpuContext, path: &str, args: &str) -> bool {
    // ---- stage the new image ----
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
    if file_size == 0 {
        return false;
    }
    let data = vfs::read_all(path).ok();
    let Some(pml4n) = create_user_pml4() else {
        return false;
    };
    let mut frames: Vec<u64> = vec![pml4n.start_address().as_u64()];
    let mut umaps: Vec<MapEnt> = Vec::new();
    let mut filemaps: Vec<FileMap> = Vec::new();
    let entry = match crate::elf::load_into_lazy(
        pml4n,
        path,
        &hdr[..hdrn],
        file_size,
        &mut frames,
        &mut umaps,
        &mut filemaps,
    ) {
        Ok(e) => Some(e),
        Err(_) => None,
    };
    let entry = match (entry, data) {
        (Some(e), _) => e,
        (None, Some(d)) => {
            umaps.clear();
            filemaps.clear();
            match crate::elf::load_into(pml4n, &d, &mut frames, &mut umaps) {
                Ok(e) => e,
                Err(_) => {
                    free_frames(&frames);
                    return false;
                }
            }
        }
        (None, None) => {
            free_frames(&frames);
            return false;
        }
    };
    for m in umaps.iter_mut() {
        m.name = String::from(path);
    }
    // fresh main stack: eager top page, demand-grown down
    let stack_lo = USER_STACK_TOP - 0x1000;
    if crate::elf::map_user_range(pml4n, stack_lo, 0x1000, &mut frames).is_none() {
        free_frames(&frames);
        return false;
    }
    umaps.push(MapEnt {
        start: stack_lo,
        end: USER_STACK_TOP,
        perm: 1 | 2,
        name: String::from("[stack]"),
    });
    let Some(argf) = crate::elf::map_user_range(pml4n, USER_ARG_PAGE, 0x1000, &mut frames) else {
        free_frames(&frames);
        return false;
    };
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
    let _ = frames; // owned by the new table tree now

    // ---- swap the mm under SCHED ----
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let t = &mut s.tasks[s.cur];
    let Some(old) = t.pml4 else {
        return false;
    };
    let old_phys = old.start_address().as_u64();
    shm::drop_task_shm(t); // POSIX exec detaches shared memory
    let borrowed = core::mem::take(&mut t.borrowed);
    if mm_dec_last(old_phys) {
        let freed = crate::elf::free_user_space(old);
        for f in freed {
            if !borrowed.contains(&f) {
                mem::free_frame(f);
            }
        }
        cow_drop_mm(old_phys);
        mem::free_frame(old_phys);
    }
    // if threads share the old mm they keep it; we just moved out
    t.pml4 = Some(pml4n);
    mm_inc(pml4n.start_address().as_u64());
    t.maps = umaps;
    t.filemaps = filemaps;
    t.mmap_next = USER_MMAP_BASE;
    t.stack_min = USER_STACK_MIN;
    t.stack_max = USER_STACK_TOP;
    t.arg_page = USER_ARG_PAGE;
    t.min_flt = 0;
    t.maj_flt = 0;
    t.mem_bytes = 0;
    t.sigpending = 0;
    // POSIX: caught handlers revert to SIG_DFL across exec; IGN stays
    t.sighandlers = t.sighandlers.map(|h| if h == 1 { 1 } else { 0 });
    t.sigrest_mapped = false;
    t.sigmask = 0;
    t.alarm_at = 0;
    t.exe = String::from(path);
    t.argv = String::from(args);
    t.name = String::from(path.rsplit('/').next().unwrap_or(path));

    // rewrite the live syscall frame: iret lands at the new entry
    ctx.r15 = 0;
    ctx.r14 = 0;
    ctx.r13 = 0;
    ctx.r12 = 0;
    ctx.r11 = 0;
    ctx.r10 = 0;
    ctx.r9 = 0;
    ctx.r8 = 0;
    ctx.rdi = USER_ARG_PAGE;
    ctx.rsi = n as u64;
    ctx.rbp = 0;
    ctx.rbx = 0;
    ctx.rdx = 0;
    ctx.rcx = 0;
    ctx.rax = 0;
    ctx.rip = entry;
    ctx.cs = unsafe { gdt::USER_CS.0 as u64 };
    ctx.rflags = 0x202;
    ctx.rsp = USER_STACK_TOP - 8;
    ctx.ss = unsafe { gdt::USER_DS.0 as u64 };
    sprintln!("[task] pid={} exec {}", t.id, path);
    true
}

/// Apply `f` to every live task sharing the given mm (pml4 phys frame).
/// Callers must NOT hold SCHED — this locks it itself.
pub fn for_mm_peers(pml4_phys: u64, f: impl Fn(&mut Task)) {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else { return };
    for t in s.tasks.iter_mut() {
        if t.state != State::Dead
            && t.pml4.map(|p| p.start_address().as_u64()) == Some(pml4_phys)
        {
            f(t);
        }
    }
}

/// Reserve `pages` in the mm shared by every task on `pml4_phys` —
/// base = the highest peer's mmap_next, then every peer's cursor is
/// advanced past base + guard. Two threads of one mm can never hand
/// out the same anonymous range. Returns the reserved base VA.
pub fn mm_reserve(pml4_phys: u64, pages: u64) -> u64 {
    // One FRAME_ALLOC scope feeds both checks: CommitLimit =
    // totalram * vm.overcommit_ratio% under vm.overcommit_memory=2
    // (strict accounting), and the vm.min_free_kbytes watermark —
    // a user reservation that would leave less than min_free free
    // fails with ENOMEM, like Linux's zone watermark.
    let (commit_limit, free_headroom) = {
        let g = mem::FRAME_ALLOC.lock();
        let (tot, used) = g
            .as_ref()
            .map(|a| (a.total_bytes(), a.used_bytes()))
            .unwrap_or((0, 0));
        let cl = if crate::sysctl::vm_overcommit_memory() == 2 {
            tot * crate::sysctl::vm_overcommit_ratio() / 100
        } else {
            u64::MAX
        };
        let free = tot
            .saturating_sub(used)
            .saturating_sub(crate::sysctl::min_free_kbytes().saturating_mul(0x400));
        (cl, free)
    };
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else {
        return 0;
    };
    let mut base = 0u64;
    let mut committed = 0u64;
    for t in s.tasks.iter() {
        if t.state != State::Dead {
            committed =
                committed.saturating_add(t.mmap_next.saturating_sub(USER_MMAP_BASE));
            if t.pml4.map(|p| p.start_address().as_u64()) == Some(pml4_phys)
                && t.mmap_next > base
            {
                base = t.mmap_next;
            }
        }
    }
    if base == 0 {
        return 0;
    }
    if committed.saturating_add(pages.saturating_mul(0x1000)) > commit_limit {
        return 0;
    }
    if pages.saturating_mul(0x1000) > free_headroom {
        return 0; // ENOMEM: below the vm.min_free_kbytes watermark
    }
    // kernel.randomize_va_space >= 2: an entropy-fed gap slides every
    // reservation's base like Linux mmap ASLR (0=off, 1=mild compat).
    let gap = if crate::sysctl::randomize_va_space() >= 2 {
        let mut b = [0u8; 8];
        if crate::virtio_rng::fill(&mut b) == 0 {
            0
        } else {
            ((u64::from_le_bytes(b) & 0x1FF) + 1) * 0x1000
        }
    } else {
        0
    };
    let end = base + pages * 0x1000 + 0x1000 + gap; // guard page
    for t in s.tasks.iter_mut() {
        if t.pml4.map(|p| p.start_address().as_u64()) == Some(pml4_phys) {
            t.mmap_next = t.mmap_next.max(end);
        }
    }
    base
}

/// SIGHUP-style broadcast: mark `sig` pending on every live userspace
/// task whose controlling terminal is pty id `ctty` (hangup broadcast
/// when a ptmx master dies). Single SCHED pass — safe to call from any
/// context that does not already hold the scheduler lock.
pub fn signal_ctty(ctty: u64, sig: u64) -> u64 {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else {
        return 0;
    };
    let mut n = 0u64;
    for t in s.tasks.iter_mut() {
        if t.ctty == ctty
            && t.is_user
            && t.state != State::Dead
            && t.id != 1
            && t.name != "cosmos-winserver"
        {
            t.sigpending |= 1 << sig;
            wake_for_signal(t, sig as usize);
            n += 1;
        }
    }
    n
}

/// Does ANY live task still hold an fd on `path`? Object fds (pipes,
/// sockets, event objects) are refcounted by live references — a thread
/// inherits a dup'd table, so teardown must skip objects another task
/// still holds.
pub fn fd_path_in_use(path: &str) -> bool {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return false };
    s.tasks.iter().any(|t| {
        t.state != State::Dead
            && t.fds
                .iter()
                .any(|f| f.as_ref().map(|d| d.path == path).unwrap_or(false))
    })
}

/// `path` is a *prefix* match: any live fd whose path sits at or under it.
/// Used by umount's EBUSY check (open handles below the mount).
pub fn fd_path_prefix_in_use(prefix: &str) -> bool {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return false };
    s.tasks.iter().any(|t| {
        t.state != State::Dead
            && t.fds.iter().any(|f| {
                f.as_ref()
                    .map(|d| d.path.starts_with(prefix))
                    .unwrap_or(false)
            })
    })
}

/// A mount namespace: tmpfs mount table, bind alias table, and the
/// lazy-detached prefixes (umount2 MNT_DETACH survivors) of one shared
/// view. The initial namespace is the global one; unshare copies it.
static NEXT_NS_ID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

#[derive(Clone)]
pub struct MountNs {
    /// Stable inode-style id shown by /proc/<pid>/ns/mntns.
    pub id: u64,
    /// (mount path, opts) — MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC.
    pub tmpfs: Vec<(String, u64)>,
    /// (target, source, opts) bind aliases — longest-target-prefix first.
    pub binds: Vec<(String, String, u64)>,
    /// Prefixes whose tmpfs node trees outlive their mount point.
    pub detached: Vec<String>,
}

impl MountNs {
    fn new() -> Self {
        MountNs {
            id: NEXT_NS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            tmpfs: Vec::new(),
            binds: Vec::new(),
            detached: Vec::new(),
        }
    }
}

impl Default for MountNs {
    fn default() -> Self {
        Self::new()
    }
}

/// A UTS namespace: the nodename (hostname) lives here so
/// unshare(CLONE_NEWUTS) can give a container its own identity.
#[derive(Clone)]
pub struct UtsNs {
    /// Stable inode-style id shown by /proc/<pid>/ns/uts.
    pub id: u64,
    pub hostname: String,
}

static GLOBAL_UTS: spin::Once<alloc::sync::Arc<spin::Mutex<UtsNs>>> = spin::Once::new();

pub fn global_uts() -> alloc::sync::Arc<spin::Mutex<UtsNs>> {
    GLOBAL_UTS
        .call_once(|| {
            alloc::sync::Arc::new(spin::Mutex::new(UtsNs {
                id: NEXT_NS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
                hostname: String::from("cosmos"),
            }))
        })
        .clone()
}

/// The current task's UTS namespace.
pub fn uts_of() -> alloc::sync::Arc<spin::Mutex<UtsNs>> {
    let mut g = SCHED.lock();
    match g.as_mut() {
        Some(s) => s.tasks[s.cur].uts.clone(),
        None => global_uts(),
    }
}

/// The UTS namespace owned by `pid` — setns's uts adopt source.
pub fn uts_arc_of(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<UtsNs>>> {
    let mut g = SCHED.lock();
    let s = g.as_mut()?;
    s.tasks
        .iter()
        .find(|t| t.id == pid && t.state != State::Dead)
        .map(|t| t.uts.clone())
}

/// setns for UTS: swap the current task into `arc`.
pub fn set_uts(arc: alloc::sync::Arc<spin::Mutex<UtsNs>>) {
    with_current(|t| t.uts = arc);
}

static GLOBAL_NS: spin::Once<alloc::sync::Arc<spin::Mutex<MountNs>>> = spin::Once::new();

/// The initial mount namespace — every task's ns starts shared with it.
pub fn global_ns() -> alloc::sync::Arc<spin::Mutex<MountNs>> {
    GLOBAL_NS
        .call_once(|| alloc::sync::Arc::new(spin::Mutex::new(MountNs::default())))
        .clone()
}

/// The CURRENT task's mount namespace (global fallback pre-scheduler).
pub fn ns_of() -> alloc::sync::Arc<spin::Mutex<MountNs>> {
    let mut g = SCHED.lock();
    match g.as_mut() {
        Some(s) => s.tasks[s.cur].ns.clone(),
        None => global_ns(),
    }
}

/// CLONE_NEWNS: deep-copy the mount tables into a private namespace —
/// later mounts/binds/unmounts by this task don't touch the parent's.
pub fn unshare_ns() {
    with_current(|t| {
        let mut copy = t.ns.lock().clone();
        // a new namespace object gets a fresh mntns id
        copy.id = NEXT_NS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        t.ns = alloc::sync::Arc::new(spin::Mutex::new(copy));
    });
}

/// unshare(CLONE_NEWUTS): the task's nodename becomes private.
pub fn unshare_uts() {
    with_current(|t| {
        let mut copy = t.uts.lock().clone();
        copy.id = NEXT_NS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        t.uts = alloc::sync::Arc::new(spin::Mutex::new(copy));
    });
}

/// A PID namespace. `id` is the /proc/<pid>/ns/pid inode-style number;
/// `parent` is the enclosing ns (0 = the initial namespace, which has
/// no registry entry — the global `Task.id` space is its pid space).
pub struct PidNs {
    pub id: u64,
    pub parent: u64,
    /// next virtual pid to hand out inside this namespace
    pub next_vpid: u32,
}

/// Pid-namespace registry: id -> the shared object (nsfd pins keep it
/// alive for setns-adoption).
static PIDNS: spin::Mutex<BTreeMap<u64, alloc::sync::Arc<spin::Mutex<PidNs>>>> =
    spin::Mutex::new(BTreeMap::new());

/// Allocate the next virtual pid inside namespace `ns` (0 = global —
/// returns 0, the global `id` is used instead).
pub fn alloc_nspid(ns: u64) -> u32 {
    if ns == 0 {
        return 0;
    }
    let arc = {
        let g = PIDNS.lock();
        g.get(&ns).cloned()
    };
    match arc {
        Some(a) => {
            let mut n = a.lock();
            let v = n.next_vpid;
            n.next_vpid = n.next_vpid.saturating_add(1);
            v
        }
        None => 0,
    }
}

/// unshare(CLONE_NEWPID): children of this task land in a fresh pid
/// namespace parented on the task's current one (the caller itself
/// stays put — Linux semantics).
pub fn unshare_pidns() {
    let me_ns = with_current(|t| t.pid_ns);
    let id = NEXT_NS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let ns = alloc::sync::Arc::new(spin::Mutex::new(PidNs {
        id,
        parent: me_ns,
        next_vpid: 1,
    }));
    PIDNS.lock().insert(id, ns);
    with_current(|t| t.child_ns = id);
}

/// setns for pid namespaces: adopt `ns` as pidns_for_children (the
/// caller's own namespace never moves — Linux semantics).
pub fn set_pidns_for_children(arc: alloc::sync::Arc<spin::Mutex<PidNs>>) {
    let id = arc.lock().id;
    with_current(|t| t.child_ns = id);
}

/// The pid-ns id `pid` lives in (0 for the initial ns or dead tasks).
pub fn pid_ns_of(pid: u32) -> u64 {
    let g = SCHED.lock();
    match g.as_ref() {
        Some(s) => s
            .tasks
            .iter()
            .find(|t| t.id == pid && t.state != State::Dead)
            .map(|t| t.pid_ns)
            .unwrap_or(0),
        None => 0,
    }
}

/// The pid-ns object owned by `pid` — for /proc/<pid>/ns/pid pinning.
/// Time namespace — `timens` on Linux. Members' monotonic/boottime
/// clock reads are shifted by `off_ticks` (10ms units). Entry is
/// children-only: unshare/setns stage `child_tns`, never move the
/// caller — matching the pidns model.
pub struct TimeNs {
    pub id: u64,
    pub parent: u64,
    pub off_ticks: i64,
}
static TIMENS: spin::Mutex<BTreeMap<u64, alloc::sync::Arc<spin::Mutex<TimeNs>>>> =
    spin::Mutex::new(BTreeMap::new());
static NEXT_TNS: AtomicU64 = AtomicU64::new(1);

/// IPC namespace — SysV shm and POSIX mqueue views are scoped to it.
/// unshare(CLONE_NEWIPC) moves the caller immediately (unlike pidns).
pub struct IpcNs {
    pub id: u64,
}
static IPCNS: spin::Mutex<BTreeMap<u64, alloc::sync::Arc<spin::Mutex<IpcNs>>>> =
    spin::Mutex::new(BTreeMap::new());
static NEXT_INS: AtomicU64 = AtomicU64::new(1);

/// unshare(CLONE_NEWTIME): stage a fresh timens for future children.
pub fn unshare_timens() {
    let me = with_current(|t| t.time_ns);
    let id = NEXT_TNS.fetch_add(1, Ordering::Relaxed);
    TIMENS.lock().insert(
        id,
        alloc::sync::Arc::new(spin::Mutex::new(TimeNs {
            id,
            parent: me,
            off_ticks: 0,
        })),
    );
    with_current(|t| t.child_tns = id);
}

/// setns on a timens object stages it as the caller's child timens.
pub fn set_timens_for_children(arc: alloc::sync::Arc<spin::Mutex<TimeNs>>) {
    let id = arc.lock().id;
    with_current(|t| t.child_tns = id);
}

/// The timens arc `pid` lives in — for `/proc/<pid>/ns/time` fds.
pub fn timens_arc_of(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<TimeNs>>> {
    let g = SCHED.lock();
    let id = g
        .as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid && t.state != State::Dead))
        .map(|t| t.time_ns)?;
    TIMENS.lock().get(&id).cloned()
}

/// The timens `pid`'s children will land in (staged child_tns, falling
/// back to its own — what `/proc/<pid>/ns/time_for_children` reports).
pub fn timens_children_arc(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<TimeNs>>> {
    let g = SCHED.lock();
    let (tns, ctn) = g
        .as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid && t.state != State::Dead))
        .map(|t| (t.time_ns, t.child_tns))?;
    TIMENS.lock().get(&if ctn != 0 { ctn } else { tns }).cloned()
}

/// The timens id `pid` lives in (0 = initial or dead).
pub fn time_ns_of(pid: u32) -> u64 {
    let g = SCHED.lock();
    g.as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid))
        .map(|t| t.time_ns)
        .unwrap_or(0)
}

/// Staged child timens id (0 when none — callers fall back to time_ns).
pub fn child_tns_of(pid: u32) -> u64 {
    let g = SCHED.lock();
    g.as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid))
        .map(|t| t.child_tns)
        .unwrap_or(0)
}

/// PIT ticks shifted by the caller's timens offset — the monotonic /
/// boottime clock every per-task time read goes through.
pub fn ticks_ns() -> u64 {
    let id = with_current(|t| t.time_ns);
    let off = if id == 0 {
        0
    } else {
        TIMENS.lock().get(&id).map(|n| n.lock().off_ticks).unwrap_or(0)
    };
    (ticks() as i64 + off).max(0) as u64
}

/// uptime_ms for the current task (timens-shifted).
pub fn uptime_ms_ns() -> u64 {
    ticks_ns() * 10
}

/// Write `timens_offsets` text — "monotonic <sec> <nsec>" / "boottime
/// <sec> <nsec>" lines fold into one tick offset applied to the caller's
/// staged child timens (or its own ns when none is staged).
pub fn timens_offsets_write(text: &str) -> i64 {
    let mut off: Option<i64> = None;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(_key) = it.next() else { continue };
        let s: i64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(-1);
        let ns: i64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(-1);
        if s < 0 || ns < 0 {
            return -22; // EINVAL
        }
        off = Some(s * 100 + ns / 10_000_000);
    }
    let Some(off) = off else { return -22 };
    let id = with_current(|t| if t.child_tns != 0 { t.child_tns } else { t.time_ns });
    match TIMENS.lock().get(&id) {
        Some(n) => {
            n.lock().off_ticks = off;
            0
        }
        None => -22,
    }
}

/// Offsets (in ticks) of `pid`'s staged-or-own timens — the content of
/// `/proc/<pid>/timens_offsets`.
pub fn timens_offsets_read(pid: u32) -> Option<i64> {
    let g = SCHED.lock();
    let (tns, ctn) = g
        .as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid && t.state != State::Dead))
        .map(|t| (t.time_ns, t.child_tns))?;
    TIMENS
        .lock()
        .get(&if ctn != 0 { ctn } else { tns })
        .map(|n| n.lock().off_ticks)
        .or(Some(0))
}

/// unshare(CLONE_NEWIPC): move the caller into a fresh IPC namespace
/// (Linux moves the caller for IPC — unlike the pidns staging model).
pub fn unshare_ipcns() {
    let id = NEXT_INS.fetch_add(1, Ordering::Relaxed);
    IPCNS.lock().insert(
        id,
        alloc::sync::Arc::new(spin::Mutex::new(IpcNs { id })),
    );
    with_current(|t| t.ipc_ns = id);
}

/// setns on an IPC-ns object — moves the caller into it directly.
pub fn set_ipcns(arc: alloc::sync::Arc<spin::Mutex<IpcNs>>) {
    let id = arc.lock().id;
    with_current(|t| t.ipc_ns = id);
}

/// The IPC-ns arc `pid` lives in — for `/proc/<pid>/ns/ipc` fds.
pub fn ipcns_arc_of(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<IpcNs>>> {
    let g = SCHED.lock();
    let id = g
        .as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid && t.state != State::Dead))
        .map(|t| t.ipc_ns)?;
    IPCNS.lock().get(&id).cloned()
}

/// The IPC-ns id `pid` lives in (0 = initial or dead).
pub fn ipc_ns_of(pid: u32) -> u64 {
    let g = SCHED.lock();
    g.as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid))
        .map(|t| t.ipc_ns)
        .unwrap_or(0)
}

/// The current task's IPC-ns id — shm/mqueue visibility keys on this.
pub fn cur_ipc_ns() -> u64 {
    with_current(|t| t.ipc_ns)
}

/// User namespace — owns uid_map/gid_map tables that translate id
/// views inside the ns. unshare(CLONE_NEWUSER) moves the caller
/// immediately (Linux semantics), unlike the pidns/timens staging.
pub struct UserNs {
    pub id: u64,
    /// real euid of the creator — the ns's owner.
    pub owner: u32,
    /// (inner, outer, len) ranges — display mapping inside the ns.
    pub uid_map: Vec<(u32, u32, u32)>,
    pub gid_map: Vec<(u32, u32, u32)>,
}
static USERNS: spin::Mutex<BTreeMap<u64, alloc::sync::Arc<spin::Mutex<UserNs>>>> =
    spin::Mutex::new(BTreeMap::new());
static NEXT_UNS: AtomicU64 = AtomicU64::new(1);

/// unshare(CLONE_NEWUSER): caller moves into a fresh userns owned by
/// its real euid (maps start empty — writes to uid_map/gid_map fill
/// them, like Linux's one-shot map writes).
pub fn unshare_userns() {
    let (id, owner) = (NEXT_UNS.fetch_add(1, Ordering::Relaxed), with_current(|t| t.euid));
    USERNS.lock().insert(
        id,
        alloc::sync::Arc::new(spin::Mutex::new(UserNs {
            id,
            owner,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        })),
    );
    with_current(|t| t.user_ns = id);
}

/// How many user namespaces `euid` created — the count
/// user.max_user_namespaces caps (the Linux ucounts analogue).
pub fn userns_count_by(euid: u32) -> usize {
    USERNS
        .lock()
        .values()
        .filter(|u| u.lock().owner == euid)
        .count()
}

/// setns on a userns object — caller moves in directly.
pub fn set_userns(arc: alloc::sync::Arc<spin::Mutex<UserNs>>) {
    let id = arc.lock().id;
    with_current(|t| t.user_ns = id);
}

/// The userns arc `pid` lives in — for `/proc/<pid>/ns/user` fds.
pub fn userns_arc_of(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<UserNs>>> {
    let g = SCHED.lock();
    let id = g
        .as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid && t.state != State::Dead))
        .map(|t| t.user_ns)?;
    USERNS.lock().get(&id).cloned()
}

/// The userns id `pid` lives in (0 = the initial userns).
pub fn user_ns_of(pid: u32) -> u64 {
    let g = SCHED.lock();
    g.as_ref()
        .and_then(|s| s.tasks.iter().find(|t| t.id == pid))
        .map(|t| t.user_ns)
        .unwrap_or(0)
}

/// Translate an outer uid through a userns map — returns the inner id,
/// or 65534 (Linux's overflow "nobody") when unmapped / ns 0.
pub fn map_uid_in(ns_id: u64, outer: u32, is_gid: bool) -> u32 {
    if ns_id == 0 {
        return outer;
    }
    USERNS
        .lock()
        .get(&ns_id)
        .map(|n| {
            let n = n.lock();
            let m = if is_gid { &n.gid_map } else { &n.uid_map };
            for &(inner, start, len) in m.iter() {
                if outer >= start && outer < start + len {
                    return inner + (outer - start);
                }
            }
            65534
        })
        .unwrap_or(outer)
}

/// Append "(inner outer len)" lines to the caller's userns map —
/// Linux semantics: only allowed on your own ns while the map is
/// still empty (one-shot). which: false = uid_map, true = gid_map.
pub fn userns_map_write(text: &str, is_gid: bool, for_pid: u32) -> i64 {
    let (my_ns, my_euid) = with_current(|t| (t.user_ns, t.euid));
    let ns_id = {
        let g = SCHED.lock();
        match g
            .as_ref()
            .and_then(|s| s.tasks.iter().find(|t| t.id == for_pid && t.state != State::Dead))
        {
            Some(t) => t.user_ns,
            None => return -3, // ESRCH
        }
    };
    if ns_id == 0 {
        return -1; // EPERM — the initial userns has no maps
    }
    // caller may only touch its own ns's map, or a ns it owns
    // (Linux: write with CAP_SETUID in the ns — ownership is the
    // closest real proxy).
    {
        let g = USERNS.lock();
        let owner = g.get(&ns_id).map(|n| n.lock().owner).unwrap_or(u32::MAX);
        if ns_id != my_ns && my_euid != owner {
            return -1; // EPERM
        }
    }
    let mut rows: Vec<(u32, u32, u32)> = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (a, b, c) = (
            it.next().and_then(|v| v.parse::<u32>().ok()),
            it.next().and_then(|v| v.parse::<u32>().ok()),
            it.next().and_then(|v| v.parse::<u32>().ok()),
        );
        let (Some(a), Some(b), Some(c)) = (a, b, c) else { return -22 };
        rows.push((a, b, c));
    }
    if rows.is_empty() {
        return -22;
    }
        let g = USERNS.lock();
    let Some(n) = g.get(&ns_id) else { return -22 };
    let mut n = n.lock();
    let m = if is_gid { &mut n.gid_map } else { &mut n.uid_map };
    if !m.is_empty() {
        return -1; // EPERM — one-shot like Linux
    }
    *m = rows;
    0
}

/// Render a userns map file (Linux format, one "inner outer len" per
/// line). Empty map = empty file.
pub fn userns_map_read(ns_id: u64, is_gid: bool) -> String {
    if ns_id == 0 {
        return String::new();
    }
    USERNS
        .lock()
        .get(&ns_id)
        .map(|n| {
            let n = n.lock();
            let m = if is_gid { &n.gid_map } else { &n.uid_map };
            let mut s = String::new();
            for &(inner, outer, len) in m.iter() {
                s.push_str(&alloc::format!("{} {} {}\n", inner, outer, len));
            }
            s
        })
        .unwrap_or_default()
}

/// In-ns DAC capability: a task whose euid maps to inner 0 gets the
/// DAC capability set against resources its userns owns (Linux's
/// "full caps in your user namespace" rule), but never global caps.
/// DAC_SET: CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, SETUID,
/// SETGID — the file-permission/su family.
pub const CAP_NS_DAC: u64 = CAP_CHOWN
    | CAP_DAC_OVERRIDE
    | CAP_DAC_READ_SEARCH
    | CAP_FOWNER
    | CAP_SETUID
    | CAP_SETGID;
/// capable_in_ns for the CURRENT task — takes SCHED; never call from
/// inside a with_current closure (use capable_in_ns(t, ...) there).
pub fn capable_ns_dac(cap: u64) -> bool {
    with_current(|t| capable_in_ns(t, cap))
}

pub fn capable_in_ns(t: &Task, cap: u64) -> bool {
    if caps_eff_of(t) & cap != 0 {
        return true;
    }
    t.user_ns != 0 && cap & !CAP_NS_DAC == 0 && map_uid_in(t.user_ns, t.euid, false) == 0
}

pub fn pidns_arc_of(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<PidNs>>> {
    let ns = {
        let g = SCHED.lock();
        let s = g.as_ref()?;
        s.tasks
            .iter()
            .find(|t| t.id == pid && t.state != State::Dead)
            .map(|t| t.pid_ns)?
    };
    PIDNS.lock().get(&ns).cloned()
}

/// The pid-ns id the current task lives in (0 = initial namespace).
pub fn cur_pid_ns() -> u64 {
    with_current(|t| t.pid_ns)
}

/// getpid(): the caller's pid AS SEEN IN ITS OWN NAMESPACE — inside a
/// pid namespace that's `nspid` (1 for the ns's init).
pub fn current_pid() -> u32 {
    with_current(|t| if t.pid_ns == 0 { t.id } else { t.nspid })
}

/// getppid(): the parent's pid in the caller's namespace — 0 when the
/// parent lives outside it (Linux: ns-init's parent is invisible).
pub fn parent_pid_view() -> u64 {
    // one SCHED lock: look up the caller and its parent in the same pass
    // (with_current would deadlock — SCHED is a non-reentrant spin mutex)
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return 0 };
    let cur = s.tasks[s.cur].id;
    let me = match s.tasks.iter().find(|t| t.id == cur) {
        Some(t) => t,
        None => return 0,
    };
    if me.parent == 0 {
        return 0;
    }
    match s
        .tasks
        .iter()
        .find(|p| p.id == me.parent && p.state != State::Dead)
    {
        Some(p) if p.pid_ns == me.pid_ns => {
            if p.pid_ns == 0 { p.id as u64 } else { p.nspid as u64 }
        }
        Some(_) => 0, // parent lives outside this namespace
        None => 0,
    }
}

/// Translate a user-supplied pid into a global task id for syscall use:
/// - arg <= 0 stays as-is (process-group and broadcast semantics are
///   carried on global pgids)
/// - inside a namespace: only in-ns nspids resolve; anything else is
///   invisible (ESRCH via u32::MAX)
/// - global callers pass through.
pub fn visible_pid(arg: i64) -> u32 {
    if arg <= 0 {
        return arg as u32;
    }
    let ns = cur_pid_ns();
    if ns == 0 {
        return arg as u32;
    }
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return u32::MAX };
    // Dead tasks stay resolvable: a blocking wait re-executes the
    // syscall AFTER its child died, and the zombie's pid must still
    // translate (nspids are never recycled, so the tombstone's number
    // is unambiguous).
    s.tasks
        .iter()
        .find(|t| t.pid_ns == ns && t.nspid == arg as u32)
        .map(|t| t.id)
        .unwrap_or(u32::MAX)
}

/// What fork/clone should REPORT to the caller for child `gid`: inside
/// a namespace the answer is the child's virtual pid (Linux: fork
/// returns the pid in the caller's namespace).
pub fn reported_child_pid(gid: u32) -> u32 {
    let ns = cur_pid_ns();
    if ns == 0 {
        return gid;
    }
    let g = SCHED.lock();
    match g.as_ref() {
        Some(s) => s
            .tasks
            .iter()
            .find(|t| t.id == gid && t.pid_ns == ns)
            .map(|t| t.nspid)
            .unwrap_or(gid),
        None => gid,
    }
}

/// pidfd_getfd's descriptor harvest: copy descriptor `fd` out of task
/// `pid` when `me` has ptrace-style authority over it (itself, its
/// parent, or its attached tracer). Caller acquires + adopts the copy.
pub fn fd_clone_from(pid: u32, fd: usize, me: u32) -> Option<FileDesc> {
    let mut g = SCHED.lock();
    let s = g.as_mut()?;
    let t = s.tasks.iter().find(|t| t.id == pid && t.state != State::Dead)?;
    if pid != me && t.parent != me && t.sig.tracer != me {
        return None; // EPERM: no inspect authority over that task
    }
    t.fds.get(fd).cloned().flatten()
}

/// Insert a descriptor into the current task's table (RLIMIT_NOFILE
/// gate). Returns the new fd number. Caller must acquire_desc first —
/// adopt_fd owns the already-acquired reference.
pub fn adopt_fd(desc: FileDesc) -> Option<usize> {
    with_current(|t| {
        let limit = (t.rlim_nofile as usize)
            .min(crate::sysctl::fs_nr_open() as usize)
            .min(t.fds.len());
        let mut slot = None;
        for i in 0..limit {
            if t.fds[i].is_none() {
                slot = Some(i);
                break;
            }
        }
        let i = slot?;
        t.fds[i] = Some(desc);
        Some(i)
    })
}

/// The mount-namespace object owned by `pid` — setns's adoption source.
pub fn ns_arc_of(pid: u32) -> Option<alloc::sync::Arc<spin::Mutex<MountNs>>> {
    let mut g = SCHED.lock();
    let s = g.as_mut()?;
    s.tasks
        .iter()
        .find(|t| t.id == pid && t.state != State::Dead)
        .map(|t| t.ns.clone())
}

/// setns: swap the current task into namespace `arc` (from ns_arc_of).
pub fn set_ns(arc: alloc::sync::Arc<spin::Mutex<MountNs>>) {
    with_current(|t| t.ns = arc);
}

/// Mount options of the longest-prefix mount covering `path` in the
/// current namespace — tmpfs mounts and bind mounts alike.
pub fn mount_opts(path: &str) -> u64 {
    let ns = ns_of();
    let g = ns.lock();
    let mut best_len = 0usize;
    let mut best = 0u64;
    for m in &g.tmpfs {
        if crate::tmpfs::under(&m.0, path) && m.0.len() >= best_len {
            best_len = m.0.len();
            best = m.1;
        }
    }
    for b in &g.binds {
        if crate::tmpfs::under(&b.0, path) && b.0.len() >= best_len {
            best_len = b.0.len();
            best = b.2;
        }
    }
    best
}

/// Any live task whose cwd is under `prefix` — also makes a mount busy.
pub fn cwd_under(prefix: &str) -> bool {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return false };
    s.tasks
        .iter()
        .any(|t| t.state != State::Dead && t.cwd.starts_with(prefix))
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

/// OOM-kill the current task — cgroup memory.max breach: the kill is
/// SIGKILL-flavoured (exit 137, "Killed") and diverges like
/// kill_current_or_halt.
pub fn kill_current_oom() -> ! {
    sprintln!("[cgroup] oom-kill: current task over memory.max");
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let idx = s.cur;
    crate::cgroup::note_oom_kill(s.tasks[idx].cgroup);
    kill_at(s, idx, 128 + 9);
    drop(g);
    park_dead_task();
}

fn kill_at(s: &mut Sched, idx: usize, code: i64) {
    let dead_cur = idx == s.cur;
    let mut t = s.tasks.remove(idx);
    let (t_pns, t_nspid) = (t.pid_ns, t.nspid);
    t.state = State::Dead;
    t.exit_code = code;
    // no field on the tombstone may ever re-mark it schedulable
    t.wake_at = u64::MAX;
    t.wait_port = 0;
    t.wait_futex = 0;
    // robust futex list: a dead task's registered words get OWNER_DIED
    // (bit30) OR'd in and their waiters woken — a mutex held at death
    // can't hang whoever futex-waits on it next. Node ABI: {next, va}.
    if t.robust_list != 0 {
        if let Some(pml4) = t.pml4 {
            let mut node = t.robust_list;
            for _ in 0..64 {
                if node == 0 {
                    break;
                }
                let Some(pa) = crate::elf::translate_user(pml4, node) else {
                    break;
                };
                let kv = crate::mem::phys_to_virt(pa) as *const u64;
                let (next, fva) = unsafe { (*kv, *kv.add(1)) };
                if fva != 0 {
                    if let Some(fpa) = crate::elf::translate_user(pml4, fva) {
                        let w = crate::mem::phys_to_virt(fpa) as *mut u64;
                        unsafe { *w |= 1 << 30 };
                        // wake inline: SCHED is already locked here
                        for o in s.tasks.iter_mut() {
                            if o.wait_futex == fpa {
                                o.wait_futex = 0;
                                if o.state == State::Blocked {
                                    o.state = State::Running;
                                }
                            }
                        }
                    }
                }
                node = next;
            }
        }
        t.robust_list = 0;
    }
    // clear_child_tid: a joiner futex-waits on this word — write 0 and
    // wake it inline (SCHED already held; futex_wake would self-deadlock)
    if t.ctid_va != 0 {
        if let Some(pml4) = t.pml4 {
            if let Some(pa) = crate::elf::translate_user(pml4, t.ctid_va) {
                let w = crate::mem::phys_to_virt(pa) as *mut u64;
                unsafe { *w = 0 };
                for o in s.tasks.iter_mut() {
                    if o.wait_futex == pa {
                        o.wait_futex = 0;
                        if o.state == State::Blocked {
                            o.state = State::Running;
                        }
                    }
                }
            }
        }
        t.ctid_va = 0;
    }
    // thread teardown: while mm peers still run on this pml4, unmap the
    // dead task's stack region — clone_user's slot scan can reuse it and
    // its frames go back to the allocator (free_frame is COW-refcounted,
    // so a frame also RO-mapped in a fork sibling is only released).
    if t.is_user && t.stack_min != 0 {
        if let Some(pml4) = t.pml4 {
            let pp = pml4.start_address().as_u64();
            let peers = s.tasks.iter().any(|o| {
                o.state != State::Dead
                    && o.pml4.map(|p| p.start_address().as_u64()) == Some(pp)
            });
            if peers {
                let mut page = t.stack_min;
                while page < t.stack_max {
                    if let Some(pa) = crate::elf::translate(pml4, page) {
                        crate::elf::unmap_user_page(pml4, page);
                        crate::mem::free_frame(pa & !0xFFF);
                    }
                    page += 0x1000;
                }
            }
        }
    }
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
    crate::cgroup::drop_task(t.id, t.cgroup);
    crate::locks::release_pid(t.id);
    crate::signalfd::drop_owner(t.id);
    // release fd-table objects (pipe roles, inotify/timerfd objects) — a
    // dead task must not pin e.g. a pipe's writer count, or readers block
    // forever waiting for an EOF that can never come. Another live task
    // (thread sharing a dup'd table) or one of this task's own remaining
    // dup slots keeps the object alive — only the last release destroys it.
    let mut i = 0;
    while i < t.fds.len() {
        if let Some(f) = t.fds[i].take() {
            let held = s.tasks.iter().any(|o| {
                o.state != State::Dead
                    && o.fds
                        .iter()
                        .any(|x| x.as_ref().map(|d| d.path == f.path).unwrap_or(false))
            }) || t
                .fds
                .iter()
                .any(|x| x.as_ref().map(|d| d.path == f.path).unwrap_or(false));
            crate::vfs::release_desc_locked(&f, held);
        }
        i += 1;
    }
    if let Some(pml4) = t.pml4 {
        // reclaim THIS task's own stack slot (main or thread): its pages
        // are plain PT leaves — freeing them lets a later clone reuse the
        // arena slot while the shared mm stays alive.
        let lo = t.stack_min;
        let hi = t.stack_max;
        for f in crate::elf::unmap_user_range(pml4, lo, hi) {
            if !t.borrowed.contains(&f) {
                mem::free_frame(f);
            }
        }
        cow_unmap_range(pml4.start_address().as_u64(), lo, hi);
        if mm_dec_last(pml4.start_address().as_u64()) {
            // last sharer: walk the user tree; free every leaf+PT frame
            // except shm-borrowed ones
            let borrowed = core::mem::take(&mut t.borrowed);
            let freed = crate::elf::free_user_space(pml4);
            for f in freed {
                if !borrowed.contains(&f) {
                    mem::free_frame(f);
                }
            }
            cow_drop_mm(pml4.start_address().as_u64());
        }
        // Keep the pml4 frame: CR3 still points at it until the scheduler
        // activates another task, so freeing it here could unmap the parked
        // exit path if the frame got reallocated. For an mm that survives
        // (threads still running) this is just a tombstone record.
        t.frames.push(pml4.start_address().as_u64());
    }
    // Kernel-stack frames stay in the tombstone: the dying task may still be
    // running on its own kstack while exit_current parks the CPU, and IRQ
    // stubs keep pushing contexts onto it until the scheduler switches away.
    let id = t.id;
    let name = t.name.clone();
    let parent = t.parent;
    let dead_sid = t.sid;
    s.tasks.push(t); // keep as tombstone for wait_pid
    // SIGCHLD: every death path (exit, kill, fault) notifies the parent;
    // default disposition ignores it, a registered handler interrupts
    if parent != 0 {
        if let Some(p) = s.tasks.iter_mut().find(|x| x.id == parent) {
            if p.state != State::Dead {
                p.sigpending |= 1 << 17;
                wake_for_signal(p, 17);
            }
        }
    }
    // SIGHUP: a session leader's death hangs up its whole session —
    // sid equals the leader's pid (setsid), so sid==id means we were it
    if dead_sid == id {
        for c in s.tasks.iter_mut() {
            if c.sid == id && c.id != id && c.state != State::Dead {
                c.sigpending |= 1 << 1; // SIGHUP
                wake_for_signal(c, 1);
            }
        }
    }
    // PID-ns init death (Linux): when a namespace's pid-1 dies, the
    // kernel SIGKILLs every other member of that namespace.
    if t_nspid == 1 && t_pns != 0 {
        for c in s.tasks.iter_mut() {
            if c.pid_ns == t_pns && c.state != State::Dead {
                c.sigpending |= 1 << 9;
                wake_for_signal(c, 9);
            }
        }
    }
    // orphaned children reparent to init and get their requested
    // parent-death signal
    for c in s.tasks.iter_mut() {
        if c.parent == id && c.state != State::Dead {
            c.parent = 1;
            if c.pdeathsig != 0 {
                let ds = c.pdeathsig;
                c.sigpending |= 1 << (ds as u64);
                wake_for_signal(c, ds as usize);
            }
        }
    }
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

/// SYS_EXIT_GROUP: POSIX exit_group — every thread sharing this mm dies
/// with `code`, not just the caller. Siblings are reaped first (kill_at
/// shifts task indices, so re-locate one each pass), then the caller.
pub fn exit_group(code: i64) -> ! {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let mm = s.tasks[s.cur]
        .pml4
        .map(|f| f.start_address().as_u64());
    if let Some(mm) = mm {
        loop {
            let pos = s.tasks.iter().enumerate().position(|(i, t)| {
                i != s.cur
                    && t.state != State::Dead
                    && t.pml4.map(|f| f.start_address().as_u64()) == Some(mm)
            });
            match pos {
                Some(i) => kill_at(s, i, code),
                None => break,
            }
        }
    }
    let idx = s.cur;
    kill_at(s, idx, code);
    drop(g);
    park_dead_task();
}

/// (euid, egid) of the current task — the DAC identity the VFS checks.
pub fn cred() -> (u32, u32) {
    with_current(|t| (t.euid, t.egid))
}

/// Group-membership check for DAC: effective gid OR the supplementary list.
pub fn in_group(gid: u32) -> bool {
    with_current(|t| t.egid == gid || t.groups.contains(&gid))
}

/// Supplementary groups of the current task (copy out for syscall).
pub fn groups_of() -> Vec<u32> {
    with_current(|t| t.groups.clone())
}

/// Effective set of `t`: euid 0 wields the permitted set; a non-root
/// task only what capset granted it (POSIX: euid 0->!0 clears eff,
/// !0->0 sets eff=prm — this derives both transitions).
pub fn caps_eff_of(t: &Task) -> u64 {
    if t.euid == 0 { t.cap_prm } else { t.cap_eff }
}

/// CAP_* check for the current task — all privilege gates go through
/// this rather than bare euid==0 comparisons.
pub fn capable(cap: u64) -> bool {
    with_current(|t| caps_eff_of(t) & cap != 0)
}

/// capget view of the current task: (effective, permitted, bounding).
pub fn capset3() -> (u64, u64, u64) {
    with_current(|t| (caps_eff_of(t), t.cap_prm, t.cap_bnd))
}

/// capget view of another task (/proc Cap rows and CAPGET pid>0).
pub fn pid_caps(pid: u32) -> Option<(u64, u64, u64)> {
    let g = SCHED.lock();
    g.as_ref()
        .and_then(|s| {
            s.tasks
                .iter()
                .find(|t| t.id == pid && t.state != State::Dead)
        })
        .map(|t| (caps_eff_of(t), t.cap_prm, t.cap_bnd))
}

/// capset on the current task: the new permitted set must stay inside
/// the bounding set, and effective inside permitted — anything else is
/// EPERM (the bounding set can only shrink via PR_CAPBSET_DROP).
pub fn capset_self(eff: u64, prm: u64) -> i64 {
    with_current(|t| {
        if prm & !t.cap_bnd != 0 || eff & !prm != 0 {
            return -1;
        }
        t.cap_eff = eff;
        t.cap_prm = prm;
        0
    })
}

/// prctl(PR_CAPBSET_DROP): permanently drop `cap` from the bounding
/// set — and from permitted+effective. Requires CAP_SETPCAP.
pub fn capbset_drop(cap: u32) -> i64 {
    if cap >= 41 {
        return -22;
    }
    with_current(|t| {
        if caps_eff_of(t) & CAP_SETPCAP == 0 {
            return -1;
        }
        let m = !(1u64 << cap);
        t.cap_bnd &= m;
        t.cap_prm &= m;
        t.cap_eff &= m;
        0
    })
}

/// May the current task signal `pid`? Linux: caller's ruid or euid must
/// match the target's ruid or suid, else CAP_KILL is required. Unknown
/// pid returns true — the caller's signal path reports ESRCH itself.
pub fn signal_perm(pid: u32) -> bool {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    let me = &s.tasks[s.cur];
    if caps_eff_of(me) & CAP_KILL != 0 {
        return true;
    }
    match s.tasks.iter().find(|t| t.id == pid) {
        Some(t) => {
            me.euid == t.uid
                || me.uid == t.uid
                || me.euid == t.suid
                || me.uid == t.suid
        }
        None => true,
    }
}

/// Saved/effective/real tuple for /proc + getres*.
pub fn creds6() -> (u32, u32, u32, u32, u32, u32) {
    with_current(|t| (t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid))
}

/// (uid, gid, euid, egid) — proc status dump + syscall answers.
pub fn creds() -> (u32, u32, u32, u32) {
    with_current(|t| (t.uid, t.gid, t.euid, t.egid))
}

/// creds of another task by pid — /proc/<pid>/status.
pub fn pid_creds(pid: u32) -> Option<(u32, u32, u32, u32)> {
    let mut g = SCHED.lock();
    let s = g.as_mut()?;
    let t = s.tasks.iter_mut().find(|t| t.id == pid && t.state != State::Dead)?;
    Some((t.uid, t.gid, t.euid, t.egid))
}

/// Full credential tuple of another task: (uid,euid,suid,gid,egid,sgid,groups).
pub fn pid_creds6(pid: u32) -> Option<(u32, u32, u32, u32, u32, u32, Vec<u32>)> {
    let mut g = SCHED.lock();
    let s = g.as_mut()?;
    let t = s.tasks.iter_mut().find(|t| t.id == pid && t.state != State::Dead)?;
    Some((t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid, t.groups.clone()))
}

/// tgkill(tgid, tid, sig): signal a specific thread. tgid 0 skips the
/// group check; otherwise tid must share tgid's address space.
pub fn sys_tgkill(tgid: u32, tid: u32, sig: u64) -> i64 {
    if tgid != 0 {
        let same = {
            let g = SCHED.lock();
            let s = g.as_ref().unwrap();
            let a = s.tasks.iter().find(|t| t.id == tgid)
                .and_then(|t| t.pml4).map(|f| f.start_address().as_u64());
            let b = s.tasks.iter().find(|t| t.id == tid)
                .and_then(|t| t.pml4).map(|f| f.start_address().as_u64());
            match (a, b) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
        };
        if !same {
            return -3; // ESRCH: not a thread of that group
        }
    }
    if !signal_perm(tid) {
        return -1; // EPERM
    }
    signal(tid, sig)
}

/// /proc/<pid>/sig: pending + blocked masks and the delivered-handler
/// set (like SigPnd/SigBlk/SigCgt in /proc/pid/status).
pub fn pid_sig(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    s.tasks
        .iter()
        .find(|t| t.id == pid && t.state != State::Dead)
        .map(|t| {
            let mut caught: u64 = 0;
            for (i, h) in t.sighandlers.iter().enumerate() {
                if *h > 1 {
                    caught |= 1 << i;
                }
            }
            alloc::format!(
                "sigpending {:016x}\nsigmask    {:016x}\nsighandled {:016x}\n",
                t.sigpending, t.sigmask, caught
            )
        })
}

/// /proc/<pid>/syscall: in-flight syscall nr + args, or -1 when the task
/// is running in user code.
pub fn pid_syscall(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    s.tasks
        .iter()
        .find(|t| t.id == pid && t.state != State::Dead)
        .map(|t| {
            if t.cur_syscall == u64::MAX {
                alloc::format!("-1\n")
            } else {
                alloc::format!(
                    "{} {} {} {} {} {}\n",
                    t.cur_syscall,
                    t.sc_args[0],
                    t.sc_args[1],
                    t.sc_args[2],
                    t.sc_args[3],
                    t.sc_args[4]
                )
            }
        })
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

/// WUNTRACED: a stopped-and-not-yet-reported child of `pid`.
/// Returns (cpid, status) with the POSIX encoding 0x7f | (sig << 8).
pub fn child_stopped_any(pid: u32) -> Option<(u32, i64)> {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let t = s.tasks.iter_mut().find(|t| {
        (t.parent == pid || t.sig.tracer == pid)
            && t.state == State::Stopped
            && !t.stop_notified
    })?;
    t.stop_notified = true;
    Some((t.id, 0x7f | ((t.stop_sig as i64) << 8)))
}

/// Same for a specific child pid.
pub fn child_stopped_one(pid: u32, cpid: u32) -> Option<(u32, i64)> {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let t = s.tasks.iter_mut().find(|t| {
        t.id == cpid
            && (t.parent == pid || t.sig.tracer == pid)
            && t.state == State::Stopped
            && !t.stop_notified
    })?;
    t.stop_notified = true;
    Some((t.id, 0x7f | ((t.stop_sig as i64) << 8)))
}

/// WCONTINUED: a child that was continued since its last report —
/// status is the POSIX WIFCONTINUED encoding 0xffff.
pub fn child_cont_any(pid: u32) -> Option<(u32, i64)> {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let t = s
        .tasks
        .iter_mut()
        .find(|t| (t.parent == pid || t.sig.tracer == pid) && t.cont_pending)?;
    t.cont_pending = false;
    Some((t.id, 0xffff))
}

/// Same for a specific child pid.
pub fn child_cont_one(pid: u32, cpid: u32) -> Option<(u32, i64)> {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let t = s.tasks.iter_mut().find(|t| {
        t.id == cpid && (t.parent == pid || t.sig.tracer == pid) && t.cont_pending
    })?;
    t.cont_pending = false;
    Some((t.id, 0xffff))
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
        .map(|s| s.tasks.iter().any(|t| t.parent == pid || t.sig.tracer == pid))
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
pub fn kill_pid_code(pid: u32, code: i64) -> bool {
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

/// cpu_ticks of one task (for cgroup cpu.stat).
pub fn cpu_ticks_of(pid: u32) -> Option<u64> {
    let g = SCHED.lock();
    g.as_ref()?
        .tasks
        .iter()
        .find(|t| t.id == pid)
        .map(|t| t.cpu_ticks)
}

/// Sum of every task's cpu_ticks (root cgroup usage_usec).
pub fn total_cpu_ticks() -> u64 {
    let g = SCHED.lock();
    g.as_ref()
        .map(|s| s.tasks.iter().map(|t| t.cpu_ticks).sum())
        .unwrap_or(0)
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
    if n < 0 && !capable(CAP_SYS_NICE) {
        return -1; // EPERM: lowering nice below 0 needs CAP_SYS_NICE
    }
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

/// Freeze or thaw every pid in `pids`: frozen members go Stopped
/// (skipped by the pick loop like SIGSTOP), thawed ones return to
/// Running. One SCHED hold for the whole group. Returns members moved.
pub fn freeze_pids(pids: &[u32], freeze: bool) -> usize {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else { return 0 };
    let mut n = 0;
    for t in s.tasks.iter_mut() {
        if !pids.contains(&t.id) || t.state == State::Dead {
            continue;
        }
        match (freeze, t.state) {
            // a frozen task that was Blocked keeps its wait bookkeeping;
            // thawed back to Running it re-enters the syscall and
            // re-blocks if the condition still holds — same resume
            // model SIGCONT already uses
            (true, State::Running) | (true, State::Blocked) => {
                t.state = State::Stopped;
                n += 1;
            }
            (false, State::Stopped) => {
                t.state = State::Running;
                n += 1;
            }
            _ => {}
        }
    }
    n
}

pub fn with_pid_mut<F: FnOnce(&mut Task) -> i64>(pid: u32, f: F) -> i64 {
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

/// setsid: caller leaves its session/group and starts a new one.
/// Fails (like POSIX) when the caller is already a group leader.
pub fn sys_setsid() -> i64 {
    with_current(|t| {
        if t.pgid == t.id {
            return -1; // EPERM: already a leader
        }
        t.sid = t.id;
        t.pgid = t.id;
        t.ctty = 0; // a fresh session has no controlling terminal yet
        0
    })
}

/// setpgid(pid, pgid): 0s mean "self"/"same as pid". Target must be a
/// live userspace task.
pub fn sys_setpgid(pid: u32, pgid: u32) -> i64 {
    let target = if pid == 0 { with_current(|t| t.id) } else { pid };
    with_pid_mut(target, |t| {
        if !t.is_user {
            return -3;
        }
        t.pgid = if pgid == 0 { target } else { pgid };
        0
    })
}

/// getpgid(pid): 0 = self.
pub fn sys_getpgid(pid: u32) -> i64 {
    let target = if pid == 0 { with_current(|t| t.id) } else { pid };
    with_pid_mut(target, |t| t.pgid as i64)
}

/// getsid(pid): 0 = self.
pub fn sys_getsid(pid: u32) -> i64 {
    let target = if pid == 0 { with_current(|t| t.id) } else { pid };
    with_pid_mut(target, |t| t.sid as i64)
}

/// prctl(op, arg): only PR_SET_PDEATHSIG(1) — the signal delivered to
/// this task when its parent dies.
pub fn sys_prctl(op: u64, arg: u64) -> i64 {
    match op {
        1 => {
            if arg >= 32 {
                return -22;
            }
            with_current(|t| {
                t.pdeathsig = arg as u8;
                0
            })
        }
        24 => capbset_drop(arg as u32), // PR_CAPBSET_DROP
        _ => -22,
    }
}

/// Consume the lowest pending signal of `pid` that `mask` allows — used
/// by signalfd reads. None = nothing deliverable (or no such task).
pub fn take_pending_sig(pid: u32, mask: u64) -> Option<u32> {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    let t = s.tasks.iter_mut().find(|t| t.id == pid && t.is_user)?;
    let avail = t.sigpending & mask;
    if avail == 0 {
        return None;
    }
    let sig = avail.trailing_zeros();
    t.sigpending &= !(1 << sig);
    Some(sig)
}

/// Is any of `pid`'s pending signals visible through `mask`? (poll support)
pub fn has_pending_sig(pid: u32, mask: u64) -> bool {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    s.tasks
        .iter()
        .find(|t| t.id == pid)
        .map(|t| t.sigpending & mask != 0)
        .unwrap_or(false)
}

/// POSIX-lite signals: 1/2/3/6/9/15 terminate (wait-status 128+sig),
/// 0 probes, 19 STOP, 18 CONT. Vital tasks (init, winserver, kernel
/// threads) refuse all signals.
pub fn signal(pid: u32, sig: u64) -> i64 {
    // POSIX kill(-pgid): a negative pid signals every member of the group
    if (pid as i32) < 0 {
        let pgid = (-(pid as i32)) as u32;
        let pids: Vec<u32> = {
            let g = SCHED.lock();
            let s = g.as_ref().unwrap();
            s.tasks
                .iter()
                .filter(|t| {
                    t.pgid == pgid
                        && t.is_user
                        && t.state != State::Dead
                        && t.id != 1
                        && t.name != "cosmos-winserver"
                })
                .map(|t| t.id)
                .collect()
        };
        if pids.is_empty() {
            return -3; // ESRCH: no such group
        }
        let mut any = false;
        for p in pids {
            if signal_perm(p) && signal(p, sig) == 0 {
                any = true;
            }
        }
        return if any { 0 } else { -3 };
    }
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
        // SIGKILL stays unconditional — it can never be caught/deferred
        9 => {
            if kill_pid_code(pid, 128 + 9) {
                0
            } else {
                -1
            }
        }
        18 | 19 => with_pid_mut(pid, |t| {
            if !t.is_user {
                return -1;
            }
            match sig {
                19 => {
                    if t.state != State::Dead {
                        t.state = State::Stopped;
                        t.stop_sig = 19;
                        // a stopped waiter must not wake on its old condition
                        t.waiting_on = 0;
                        t.wait_port = 0;
                        t.wait_futex = 0;
                    }
                    0
                }
                18 => {
                    // POSIX: SIGCONT discards pending stop signals and
                    // lets waitpid report the next stop transition
                    t.sigpending &= !(0b1111 << 19);
                    t.stop_notified = false;
                    if t.state == State::Stopped {
                        t.state = State::Running;
                        t.cont_pending = true; // waitpid WCONTINUED
                    }
                    0
                }
                _ => -22,
            }
        }),
        // every other signal is deliverable: mark it pending and wake
        // the task if it's sleeping — the disposition (handler vs
        // default-kill) is decided when it next resumes in maybe_deliver
        1..=31 => with_pid_mut(pid, |t| {
            if !t.is_user || t.state == State::Dead {
                return -1;
            }
            if t.id == 1 || t.name == "cosmos-winserver" {
                return -1;
            }
            t.sigpending |= 1 << sig;
            wake_for_signal(t, sig as usize);
            0
        }),
        _ => -22,
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
pub fn pid_maps(pid: u32, hide_ptrs: bool) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut out = String::new();
    for m in &t.maps {
        let (lo, hi) = if hide_ptrs { (0, 0) } else { (m.start, m.end) };
        out.push_str(&alloc::format!(
            "{:08x}-{:08x} {}{}{}p 00000000 00:00 0          {}\n",
            lo,
            hi,
            if m.perm & 1 != 0 { 'r' } else { '-' },
            if m.perm & 2 != 0 { 'w' } else { '-' },
            if m.perm & 4 != 0 { 'x' } else { '-' },
            m.name
        ));
    }
    Some(out)
}

/// `/proc/<pid>/io` — real vfs byte counters.
/// Tids of every live task sharing pid's address space — /proc/<pid>/task.
pub fn pid_threads(pid: u32) -> Option<Vec<u32>> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let mm = s.tasks.iter().find(|t| t.id == pid)?.pml4;
    Some(
        s.tasks
            .iter()
            .filter(|t| t.state != State::Dead && t.pml4.is_some() && t.pml4 == mm)
            .map(|t| t.id)
            .collect(),
    )
}

/// (min_flt, maj_flt, resident user pages) for /proc/<pid>/status.
/// Per-task io counters (rbytes, wbytes) for cgroup io.stat on the
/// root group (which sums over live tasks).
pub fn io_bytes(pid: u32) -> Option<(u64, u64)> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    s.tasks
        .iter()
        .find(|t| t.id == pid && t.state != State::Dead)
        .map(|t| (t.rbytes, t.wbytes))
}

/// Live rss in frames for `pid` (its owned t.frames count; tombstones
/// report 0 — dead members stop counting immediately).
pub fn frames_len(pid: u32) -> Option<u64> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    s.tasks
        .iter()
        .find(|t| t.id == pid)
        .map(|t| if t.state == State::Dead { 0 } else { t.frames.len() as u64 })
}

pub fn pid_faults(pid: u32) -> Option<(u64, u64, u64)> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let rss = t.pml4.map(|p| crate::elf::count_mapped(p)).unwrap_or(0);
    Some((t.min_flt, t.maj_flt, rss))
}

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
        let cg = t.cgroup;
        if cg != 0 {
            crate::cgroup::io_charge(cg, read, n);
            // io.max: over the window's byte budget -> the task can't do
            // its next I/O until the window rolls (real pacing, like
            // cgroup v2 throttling).
            if let Some(wake) = crate::cgroup::io_wait_until(cg) {
                t.state = State::Blocked;
                t.wake_at = wake;
            }
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

/// FUTEX_WAKE: mark up to `n` blocked waiters on `key` runnable. Returns
/// how many were woken. A claimed-but-not-yet-blocked waiter still counts
/// (its commit step will see the cleared flag and not sleep).
pub fn futex_wake(key: u64, n: u64) -> u64 {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else {
        return 0;
    };
    let mut woke = 0;
    for t in s.tasks.iter_mut() {
        if t.wait_futex == key {
            t.wait_futex = 0;
            if t.state == State::Blocked {
                t.state = State::Running;
            }
            woke += 1;
            if woke >= n {
                break;
            }
        }
    }
    woke
}

/// `/proc/<pid>/limits`: Linux-format rlimit table (soft = hard here).
pub fn pid_limits(pid: u32) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let inf = |v: u64| -> String {
        if v == u64::MAX {
            alloc::string::String::from("unlimited")
        } else {
            alloc::format!("{}", v)
        }
    };
    let row = |name: &str, cur: &str, unit: &str| -> String {
        alloc::format!("{:<26}{:<21}{:<21}{}\n", name, cur, cur, unit)
    };
    let mut out = alloc::string::String::from(
        "Limit                     Soft Limit           Hard Limit           Units\n",
    );
    out.push_str(&row("Max cpu time", &inf(t.rlim_cpu), "seconds"));
    out.push_str(&row("Max stack size", &inf(t.rlim_stack), "bytes"));
    out.push_str(&row("Max address space", &inf(t.rlim_as), "bytes"));
    out.push_str(&row("Max processes", &inf(t.rlim_nproc), "processes"));
    out.push_str(&row("Max open files", &inf(t.rlim_nofile), "files"));
    Some(out)
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
            if t.wait_futex != 0 {
                return Some(String::from("futex"));
            }
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
pub fn pid_smaps(pid: u32, hide_ptrs: bool) -> Option<String> {
    let g = SCHED.lock();
    let s = g.as_ref()?;
    let t = s.tasks.iter().find(|t| t.id == pid)?;
    let mut out = String::new();
    for m in &t.maps {
        let kb = (m.end - m.start) / 1024;
        let (lo, hi) = if hide_ptrs { (0, 0) } else { (m.start, m.end) };
        out.push_str(&alloc::format!(
            "{:08x}-{:08x} {}{}{}p 00000000 00:00 0          {}\nSize:                {} kB\nRss:                 {} kB\nPss:                 {} kB\n",
            lo,
            hi,
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
    // cgroup memory.max: a demand fill would grow member rss past the
    // cap — kill the task (real OOM semantics, exit 137) instead of
    // letting the allocation land. Runs in #PF context, no locks held.
    let cg = with_current(|t| t.cgroup);
    if cg != 0 && crate::cgroup::oom_check(cg) {
        kill_current_oom(); // diverges
    }
    // present-but-read-only COW page written for the first time —
    // split or claim it before any demand-fill logic runs
    if cow_resolve(va) {
        return true;
    }
    let page = va & !0xFFFu64;
    // demand-grown user stack: an unmapped page inside THIS task's stack
    // region maps a fresh zero page (main stack or a clone's private
    // slot). The region bound is the guard — a fault outside is a real
    // overflow and falls through to kill the task.
    if with_current(|t| page >= t.stack_min && page < t.stack_max) {
        return with_current(|t| stack_grow(t, page));
    }
    let (pml4, hit) = with_current(|t| {
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
    with_current(|t| {
        t.frames.push(phys);
        if path.is_empty() {
            t.min_flt += 1;
        } else {
            t.maj_flt += 1;
        }
    });
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


fn rlim_get(pid: u32, res: u64) -> Option<u64> {
    let g = SCHED.lock();
    let s = g.as_ref().unwrap();
    s.tasks
        .iter()
        .find(|t| t.id == pid && t.state != State::Dead)
        .and_then(|t| match res {
            0 => Some(t.rlim_cpu),
            3 => Some(t.rlim_stack),
            6 => Some(t.rlim_nproc),
            7 => Some(t.rlim_nofile),
            9 => Some(t.rlim_as),
            _ => None,
        })
}

fn rlim_set(pid: u32, res: u64, v: u64) -> i64 {
    let mut g = SCHED.lock();
    let s = g.as_mut().unwrap();
    match s
        .tasks
        .iter_mut()
        .find(|t| t.id == pid && t.state != State::Dead)
    {
        Some(t) => {
            match res {
                0 => t.rlim_cpu = v,
                3 => t.rlim_stack = v,
                6 => t.rlim_nproc = v,
                7 => t.rlim_nofile = v,
                9 => t.rlim_as = v,
                _ => return -22,
            }
            0
        }
        None => -3, // ESRCH
    }
}

/// prlimit(pid, res, new_or_MAX, old_ptr_or_0): real get/set of a task's
/// resource limits. pid 0 = caller. res: 3=STACK(bytes), 6=NPROC, 7=NOFILE.
/// `new` is a value (u64::MAX = no change); `old_ptr` copies out the
/// previous limit when nonzero.
pub fn sys_prlimit(pid: u32, res: u64, new: u64, old_ptr: u64) -> i64 {
    let me = current_id();
    let who = if pid == 0 { me } else { pid };
    if old_ptr != 0 {
        let Some(v) = rlim_get(who, res) else { return -22 };
        // copy_out may fault pages in — do it after dropping SCHED
        if crate::syscall::copy_out_pub(old_ptr, &v.to_le_bytes()).is_none() {
            return -14;
        }
    }
    if new == u64::MAX {
        return 0;
    }
    // per-resource sanity caps (NOFILE used to share a global 1<<20 clamp)
    let capped = match res {
        7 => new.min(1 << 20),
        _ => new.min(1 << 40),
    };
    rlim_set(who, res, capped)
}

/// arch_prctl(op, val): op 2 = ARCH_SET_FS (validate user range),
/// op 3 = ARCH_GET_FS. TLS pointer per task — restored on activate.
pub fn sys_arch_prctl(op: u64, val: u64) -> i64 {
    match op {
        2 => {
            if val >= 0x8000_0000_0000 {
                return -22;
            }
            with_current(|t| t.fs_base = val);
            // the field only re-arms on activate; the calling task is
            // running NOW so program the MSR immediately or fs:0 faults
            unsafe {
                x86_64::registers::model_specific::Msr::new(0xC000_0100)
                    .write(val);
            }
            0
        }
        3 => with_current(|t| t.fs_base as i64),
        _ => -22,
    }
}
