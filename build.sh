#!/usr/bin/env bash
# CosmosOS build: kernel -> bootable disk image -> data disk with userspace apps.
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="${PROFILE:-release}"
DIST=dist
DATA_IMG="$DIST/cosmos-data.img"

echo "==> [1/4] kernel ($PROFILE)"
(cd kernel && cargo +nightly build --$PROFILE)
KERNEL_ELF="kernel/target/x86_64-unknown-none/$PROFILE/cosmos-kernel"

echo "==> [2/4] userspace apps"
(cd apps && cargo +nightly build --$PROFILE)

echo "==> [3/4] bootable disk image"
cargo +nightly build --release -p cosmos-boot
BOOT="target/release/cosmos-boot"
$BOOT "$KERNEL_ELF" "$DIST"

echo "==> [4/4] data image"
cargo +nightly build --release -p cosmos-imgtool
IMGTOOL="target/release/cosmos-imgtool"
IMGTOOL_ARGS=()
for app in apps/target/x86_64-unknown-none/$PROFILE/*; do
    [ -f "$app" ] && [ -x "$app" ] && IMGTOOL_ARGS+=("$app")
done
$IMGTOOL "$DATA_IMG" imgroot "${IMGTOOL_ARGS[@]}"

echo
echo "Build complete:"
ls -lh "$DIST"/cosmos-uefi.img "$DIST"/cosmos-bios.img "$DATA_IMG" 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
echo "Run: ./run.sh"
