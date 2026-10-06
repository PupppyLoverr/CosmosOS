# GPUI and React on CosmosOS — investigation & verdict

Status of the two long-term runtime requirements, investigated honestly.
Per the spec: no fake compatibility layers, no claimed support without a
running real application. This document is the deliverable.

## GPUI

**Verdict: not feasible in this milestone; the correct backend
architecture is established below.**

### What GPUI actually requires (investigated architecture)

GPUI (Zed's UI framework) is not a widget library on a generic canvas —
it is a GPU-retained scene graph with hard platform dependencies:

1. **GPU rendering pipeline.** GPUI composites via platform GPU backends:
   Metal on macOS, DirectX/Vulkan elsewhere (through `blade`/`wgpu`).
   It shades quads/glyphs/paths through real shader pipelines and samples
   texture atlases. There is no CPU-only raster fallback to port.
2. **A windowing/event integration** (`Platform` trait): window handles,
   event loops (`PlatformDispatcher`), vsync/callback timing, IME,
   clipboard, display enumeration.
3. **`std` OS services**: threads, fs, time — our userspace is `no_std`
   with a custom ustd surface.
4. **Font shaping/raster pipeline** (cosmic-text/harfbuzz stack) feeding
   the GPU atlas.

### What CosmosOS has

- A linear CPU framebuffer (no GPU device; virtio-gpu is not implemented).
- Software compositor (winserver) blitting shm surfaces — no shaders,
  no texture sampling, no 3D at all.
- `no_std` userspace; no threads inside a process; cooperative-ish
  preemptive scheduling.

### Why it cannot run

The gap isn't "write a shim". It is two missing subsystems stacked:
a GPU device + driver (virtio-gpu with a Vulkan-level command path —
even virgl assumes a guest GPU stack), *and* then a `Platform` impl
backed by that driver. Each alone is a multi-month project; both are
prerequisites before GPUI's first frame could render. Implementing a
"GPUI-compatible" CPU fallback would be exactly the fake the spec
forbids.

### The correct backend architecture (established, not faked)

```
GPUI app
  -> gpui::Platform (trait — window, dispatcher, text, clipboard)
       -> CosmosPlatform impl (NEW, when prerequisites exist)
            window ops  -> winserver wire protocol (already real)
            input       -> EV_KEY/EV_POINTER events (already real)
            rendering   -> [MISSING: GPU device abstraction]
  -> GPU device
       -> [MISSING: virtio-gpu driver + Vulkan-level command transport]
```

The honest boundary already exists: GPUI's `Platform` trait isolates all
OS contact. The two missing prerequisites, in dependency order:

1. `kernel/virtio_gpu.rs` — virtio-gpu device (2D first: resource create,
   attach-backing, transfer/flush; 3D/virgl only if shaders land).
2. A GPUI-visible display/raster backend implementing the trait's window,
   dispatcher, and (GPU or documented CPU) presentation path.

Until both exist, any "GPUI on CosmosOS" claim would be fiction.

## React

**Verdict: not feasible in this milestone; the runtime boundary is
already clean for a future web runtime.**

React needs, in order: a JavaScript engine (QuickJS/Boa-class — Boa is
pure Rust and the only realistic candidate, still `std`-heavy), a DOM +
CSS layout engine, and a rasterizer. That is a browser engine; the spec
correctly forbids attempting a Chromium replacement.

### The clean application-runtime boundary (already real)

A future web runtime is a *userspace process*, not a kernel feature.
CosmosOS already provides everything it needs externally:

- spawn/exit/waitpid (process lifecycle)
- winserver wire protocol (window + shm surface + input/focus/resize)
- fs syscalls (assets, caches, persisted state)
- net syscalls (UDP today; TCP when it lands)
- the app ABI: `user_main(args_ptr, args_len) -> i64`, `/bin/<elf>`

Concretely, `cosmos-web` would be a normal app binary bundling a JS
engine + minimal DOM renderer that draws into its shm window — the same
contract `cosmos-terminal` uses today. No kernel or protocol changes
required for a first integration. That boundary is what this milestone
leaves behind, per the spec's "prioritize the operating system and
leave a clean application-runtime boundary".

## What this milestone did ship instead

- A real app ABI + native Rust app on it (demo: window + input + file
  persistence through the real interface, not compiled-in).
- Real networking: virtio-net + ARP/ICMP (ping) — see README metrics.
- Security boundary enforcement at the syscall layer
  (`translate_user`: userspace pointers can never resolve to kernel
  mappings).
