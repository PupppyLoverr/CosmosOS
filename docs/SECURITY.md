# CosmosOS security model — what is actually enforced

Honest inventory, not aspirational claims. "Enforced" means the kernel
makes it impossible today; "not enforced" is listed openly.

## Enforced

- **Ring separation.** Apps run at CPL=3 on their own kernel stacks
  (TSS.rsp0). A userspace fault kills only that task
  (`kill_current_or_halt`); the kernel keeps running.
- **Per-process page tables.** Each task gets `create_user_pml4()` —
  fresh low-half tree, kernel entries shared at supervisor-only
  permissions. One process cannot map another's frames.
- **W^X in userspace.** ELF code segments map `P|U` read-only-executable;
  stack/data/mmap/shm map `P|U|W|NO_EXECUTE`. No user page is both
  writable and executable.
- **Syscall boundary validation.** `copy_in`/`copy_out` resolve user
  pointers through `translate_user`, which requires `USER_ACCESSIBLE` at
  every page-table level. A kernel virtual address passed to a syscall
  fails — verified by selftest (`kern-ptr-rejected[-in]`).
- **Input validation at boundaries.** ELF loader validates headers,
  program-header bounds, machine type, and load addresses
  (`pvaddr >= 0x1000`, `< 0x7EFF_F000` — page 0 unmapped, kernel space
  unreachable). Syscall args are range-checked (`copy_in` caps at 1 MiB,
  message sizes bounded by `WS_MSG_MAX`/port `MAX_QUEUE`).
- **Resource ownership.** IPC ports and shm objects are owned by their
  creating task; task death closes ports (`close_task_ports`) and drops
  shm (`drop_task_shm`). `SYS_IPC_OWNER=0` is the peer-died signal;
  winserver reaps orphaned windows.
- **IRQ/lock safety.** IRQ handlers never take blocking locks — scheduler
  and IPC wakeups use `try_lock`, input uses lock-free SPSC rings drained
  at the syscall bottom-half. No IRQ-context deadlock path exists.

## Not enforced (honest gaps)

- **Filesystem permissions.** FAT32 has no uid/mode bits; every process
  can read/write every file. Filesystem-level ACLs need a filesystem
  that supports them.
- **Memory quotas.** `meminfo` is informational only; a task allocating
  until OOM starves the frame allocator for everyone.
- **Syscall argument fuzzing/hardening.** Validation is hand-audited,
  not systematically fuzzed.
- **Interrupt-time userspace.** A userspace `cli` in a loop can still
  spin (preemption is timer-IRQ-driven and does switch away — so this
  is livelock-resistant, but there's no per-task CPU budget).
- **No SMEP/SMAP/SGX-style isolation.** The kernel relies on page-table
  U/S flags; supervisor-mode code can physically read user pages by
  design (that's how `copy_in` works). A kernel bug can escalate — this
  is inherent to a monolithic kernel.

## Design rules contributors must keep

- `copy_in`/`copy_out`/`copy_str` are the ONLY paths from userspace
  pointers to kernel memory — never open-code `translate`+`phys_to_virt`
  in a syscall.
- Never allocate or take a blocking lock inside an IRQ handler.
- A dying task's kernel stack and pml4 frame stay with its tombstone
  until the scheduler switches away — freeing early corrupts the parked
  exit path.
- User page-table entries for data always get `NO_EXECUTE`; executable
  pages are never `WRITABLE`. Keep W^X when adding new mappings.
