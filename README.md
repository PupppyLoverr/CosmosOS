# CosmosOS

A real, bootable, interactive operating system written in Rust for x86_64.
Not a simulator, not a shell on Linux — its own kernel, scheduler, filesystem,
compositor, and apps, running on bare UEFI hardware (QEMU/OVMF).

## Quick start

```bash
./build.sh   # kernel + userspace apps -> dist/cosmos-uefi.img (boot) + cosmos-data.img (FAT32)
./run.sh     # boots QEMU/OVMF with a GTK window
./test.sh    # headless smoke test: builds selftest disk, boots, scores serial log
```

Requires: `rustup` toolchain `nightly` (`rust-src`, `llvm-tools-preview`,
`rustfmt`), `qemu-system-x86`, `ovmf`.

## What you get on boot

- UEFI boot (OVMF) → `cosmos-boot` → `cosmos-kernel` on the framebuffer.
- Desktop shell: taskbar with launcher, workspaces (F1/F2), live clock +
  memory readout, pointer.
- Windows: drag by titlebar, resize by edges, minimize/maximize/close,
  focus raise + Alt-Tab cycle, edge snapping (drag to screen edges).
- Apps (F4–F9): Terminal, Files, Text Editor, Settings, System Monitor,
  Demo (native Rust app on the app API: shm surface + input + file persistence).
- Real persistence: writes land on the FAT32 data disk and survive reboot.
- Real networking: virtio-net + IPv4/ARP/ICMP/UDP/TCP with a real DHCP
  client (DISCOVER→ACK configures the guest IP), `ping`, `resolve` (DNS/UDP
  to slirp's resolver), `httpget` (real HTTP through slirp to the live
  internet), `ifconfig`, and a userspace UDP socket API
  (`SYS_NET_UDP_*` → `ustd::UdpSock` bind/sendto/recvfrom).
- Damage-region compositing: the compositor redraws only the damaged rect
  (cursor move ≈ two 16px cells, not a ~3MB full frame).

## Terminal commands

`help ls cd pwd cat mkdir touch rm mv cp echo clear ps mem uname date`
`ping <ip> resolve <host> httpget <host> ifconfig`
`reboot shutdown exit`

## Layout

| path | what |
|---|---|
| `boot/` | UEFI loader: claims framebuffer, loads kernel ELF, jumps in |
| `kernel/` | x86_64 kernel: serial log, GDT/IDT, PIC+PIT, page/frame alloc, heap, virtio-blk, FAT32 (via `fatfs`), ELF loader, userspace tasks + preemptive scheduler, syscalls, IPC ports, shm surfaces, PS/2 input |
| `apps/ustd` | userspace support lib: syscall wrappers, `wm` client (windows/events), Canvas drawing, VGA16 font |
| `apps/*` | init, winserver (compositor + desktop shell), terminal, files, settings, editor, sysmon, demo, selftest |
| `shared/` | wire-format crate shared by kernel+apps: syscall numbers, `InputKey`/`EvKey`/`InputMouse`, window protocol constants |
| `fat32/` | read/write FAT32 impl used by `imgtool` to bake the data disk |
| `imgtool/` | host tool: builds `dist/cosmos-data.img` from `imgroot/` + built app ELFs |
| `dist/` | build output: `cosmos-uefi.img`, `cosmos-data.img` (gitignored) |

## Wire protocol (winserver)

`kind:u16 len:u16 reply:u32` header; requests `REQ_CREATE_WIN=1`,
`REQ_PRESENT=2`, `REQ_SET_TITLE=3`, `REQ_CLOSE_WIN=4`, `REQ_RESIZE_ACK=6`;
replies `RSP_WIN_CREATED=100` / `RSP_ERROR=101`; events `EV_KEY=200`,
`EV_POINTER=201`, `EV_FOCUS=202`, `EV_CLOSE=203`, `EV_RESIZE_REQ=204`.
Replies are sent before queued events on the same port. All event structs
are read with `ptr::read_unaligned` (no alignment guarantees on the wire).

## Debugging

- Everything logs to serial (`-serial`); `SERIAL="file:dist/log.txt"`.
- Headless + QMP control:
  `DISPLAY=none SERIAL="file:dist/log.txt" EXTRA="-no-reboot -qmp unix:/tmp/qmp.sock,server,nowait" ./run.sh`
  — then `send-key`, `input-send-event`, `screendump`, `info registers`,
  `x /Ngx` via QMP JSON. `system_reset` exits QEMU under `-no-reboot`.
- Kernel ELF is PIE (base `0x8000000000`) with debug info:
  `addr2line -e kernel/target/.../cosmos-kernel -f -C <rip - 0x8000000000>`.
- Userspace has no SSE (FPU state isn't saved across switches) — integer
  math only; user-facing strings are ASCII (byte-wise VGA16 font).

## Measured (QEMU, -m 1024M, KVM)

- Boot-to-desktop (`./run.sh` → `[winserver] up` on serial): ~16 s wall —
  dominated by OVMF firmware init; kernel+init+spawn is a few seconds.
- Idle RAM at fresh desktop: ~53 MiB used of 1009 MiB (frame allocator).
  With 4–5 windows open: ~105–155 MiB. Well under the 1 GiB target.
- Boot image: ~10.6 MiB; data image holds the FAT32 payload.
- Selftest: `DONE ok=39 fail=0` — 39 checks across memory, fs, IPC,
  shm, spawn/waitpid, fb, datetime, syscall-boundary negatives, and
  live networking (ARP+ICMP ping, DNS over UDP, TCP/HTTP to the internet).

## Rules in this codebase

- IRQ handlers never take blocking locks or allocate — `sched_tick` uses
  `SCHED.try_lock`, input goes through lock-free SPSC rings drained by
  `input::pump()` in syscall dispatch.
- A dying task's kernel stack + pml4 frames stay with its tombstone — they
  are still in use until the scheduler switches away. `exit_current` parks
  via `enable_and_hlt`, never `hlt` with IF=0.
- Port owner `0` (`SYS_IPC_OWNER`) means "owner died" — winserver reaps
  dead windows on its 1 Hz tick.
- The syscall gate runs IF=0 (interrupt gate): kernel-side wait loops must
  `sti;hlt;cli` (see `net::wait_irq`) or `now_ms()` stays frozen and
  deadlines never fire. Same reason IRQ handlers must not lock anything a
  lock-holder across an `sti` window could hold.
