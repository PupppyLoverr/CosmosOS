# CosmosOS architecture

Boot flow, kernel subsystems, and how the desktop is put together. File
references are relative to the repo root.

## Boot chain

```
OVMF (UEFI firmware)
  -> boot/src/main.rs  cosmos-boot (UEFI app)
       * locates the kernel ELF on the ESP, loads segments
       * claims the UEFI GOP framebuffer, hands FrameBufferInfo to the kernel
       * exits boot services, jumps to kernel entry
  -> kernel/src/main.rs
       * serial log first (every subsystem prints; nothing fails silently)
       * GDT+TSS (rsp0 for ring3 IRQ delivery), IDT, PIC remap,
         PIT 100 Hz, RTC wall-clock base
       * frame allocator + mapper + kernel heap
       * PCI scan -> virtio-blk -> mount FAT32 data disk as VFS root
       * PS/2 keyboard+mouse -> lock-free SPSC rings
       * spawn init (pid 1), then idle in `loop { hlt }`
```

`init` (apps/init) spawns `winserver`, watches it, respawns on death.

## Scheduling and tasks — kernel/src/task.rs

- `Sched { tasks: Vec<Box<Task>>, cur, next_pid }` behind `SCHED: Mutex`.
- Timer IRQ (`timer_isr` in idt.rs) pushes a full `CpuContext`, calls
  `sched_tick`: bumps `TICKS`, wakes `Blocked` tasks whose `wake_at` passed,
  wakes IPC receivers (`ipc::wake_receivers`), round-robins the first
  `Running` task, `activate()` (rsp0 + CR3 switch), returns its `saved_rsp`.
  `SCHED.try_lock` — if a syscall holds the lock the tick just returns.
- Cooperative blocking: `block_reenter()` marks the task `Blocked`, sets
  `wake_at`, rewinds `ctx.rip -= 2` (re-executes int 0x80 on wake) and calls
  `yield_ctx`. Deadlines persist in `wait_timeout` so the int-0x80 restart
  doesn't push them forward forever.
- Task death: `kill_at` removes the task, keeps it as a tombstone for
  `wait_pid`, closes its ports (`ipc::close_task_ports`) and shm
  (`shm::drop_task_shm`), frees user pages except shm-borrowed frames, and
  **keeps kernel-stack frames + the pml4 frame** — the dying task is still
  running on them until the scheduler switches away.
- `exit_current`/`kill_pid`/`kill_current_or_halt` then `park_dead_task()`:
  `int 32` (re-run the scheduler now) then `loop { enable_and_hlt }`.
  Parking with IF=1 is essential — an IF=0 hlt freezes the machine
  permanently when no other task is runnable.

## Memory — kernel/src/mem.rs, shm.rs

- `RegionFrameAlloc` over the UEFI memory map; kernel heap in a dedicated
  virtual region. `meminfo()` reports (total, used, heap) for `SYS_MEMINFO`.
- Userspace gets its own pml4 (`create_user_pml4`, copies kernel slots so
  syscalls/interrupts work in-ring-3), 256 KiB user stack, mmap region for
  shm at `USER_MMAP_BASE`.
- `shm` objects: named frame sets refcounted across tasks; `SYS_SHM_MAP`
  maps them into a task's user space and records the frames in
  `t.borrowed` so teardown doesn't double-free.

## IPC — kernel/src/ipc.rs

- Ports: `SYS_IPC_LISTEN` (task-owned), `SYS_IPC_CONNECT` by name,
  `SYS_IPC_SEND`, `SYS_IPC_RECV` (blocking with tick deadline),
  `SYS_IPC_OWNER`, `SYS_IPC_CLOSE`.
- Per-port queue bounded by `MAX_QUEUE=128`; sends to a full queue drop.
- `wake_receivers` runs inside `sched_tick` under `IPC.try_lock` — IRQ
  context never takes blocking locks.
- `input::pump()` runs at the top of `syscall::dispatch` (bottom half):
  drains the PS/2 SPSC rings into the winserver input port.

## Userspace runtime — apps/ustd

- `sc0..sc5` int-0x80 wrappers, `spawn`, `exit`, `waitpid`, `sleep_ms`,
  `uptime_ms`, `meminfo`, `proclist`, fd API over the VFS, `datetime`.
- `wm` client: `connect()` (retries 200 ms), `create_window` -> shm-backed
  `Window { ptr, canvas() }`, `next_event(timeout)`, `present`, `set_title`,
  `disconnect`.
- App entry: `extern "C" fn user_main(args_ptr, args_len) -> i64`.

## Desktop — apps/winserver

- Claims the framebuffer (`SYS_FB_CLaim` equivalent — first fb user),
  builds wallpaper gradient, taskbar, pointer sprite.
- Loop: drain input port (nonblocking), drain ws request port, 1 Hz tick
  (`reap_dead` + taskbar repaint), composite throttle (~50 fps), then a
  16 ms blocking `ipc_recv`.
- Per-window events routed via the client reply port stored in
  `w.owner`; replies go out before events so a client `poll` sees
  `RSP_WIN_CREATED` before `EV_FOCUS`.
- `reap_dead`: `ipc_owner(w.owner) == 0` -> remove window + `shm_drop`.
- Hit-testing drives move/resize/focus/min/max/close + edge snapping;
  F1/F2 workspaces filter windows by `w.ws`.

## Build artifacts — build.sh, imgtool

- `cargo +nightly build` for `kernel` and `apps` workspaces
  (`-Z build-std=core,compiler_builtins,alloc`, panic=abort, LTO release).
- `cosmos-boot` (host tool) writes the UEFI ESP + kernel into
  `dist/cosmos-uefi.img`.
- `cosmos-imgtool` formats `dist/cosmos-data.img` (FAT32) from `imgroot/`
  plus every built app ELF under `/bin/` — adding an app to the workspace
  puts it on the desktop automatically if init/winserver reference it.

## Failure modes by design

- No hidden crashes: kernel logs every boot stage; a user-mode fault kills
  only that task (`kill_current_or_halt`) and prints `[task] fault ...`;
  kernel fault halts visibly with a sprintln.
- init respawns winserver; `reap_dead` collects orphaned windows; port
  owner 0 is the single source of truth for "peer died".
