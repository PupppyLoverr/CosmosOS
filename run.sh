#!/usr/bin/env bash
# Boot CosmosOS in QEMU (UEFI). Env: DISPLAY=none for headless, RAM=1024M, KVM=0 to disable kvm.
set -euo pipefail
cd "$(dirname "$0")"

OS_IMG="${OS_IMG:-dist/cosmos-uefi.img}"
DATA_IMG="${DATA_IMG:-dist/cosmos-data.img}"
RAM="${RAM:-1024M}"
DISPLAY="${DISPLAY:-gtk}"
SERIAL="${SERIAL:-stdio}"     # stdio | file:path | none
EXTRA="${EXTRA:-}"

if [ ! -f "$OS_IMG" ]; then echo "missing $OS_IMG — run ./build.sh"; exit 1; fi

# OVMF firmware
OVMF_CODE=""
for c in /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/qemu/OVMF.fd; do
    [ -f "$c" ] && OVMF_CODE="$c" && break
done
[ -z "$OVMF_CODE" ] && { echo "OVMF not found (install ovmf package)"; exit 1; }
OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
[ -f "$OVMF_VARS" ] || OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
[ -f "$OVMF_VARS" ] && cp -f "$OVMF_VARS" ./OVMF_VARS.fd

ACCEL="tcg"
[ "${KVM:-1}" = "1" ] && [ -w /dev/kvm ] && ACCEL="kvm"

SER_ARGS=(-serial "$SERIAL")
[ "$SERIAL" = "none" ] && SER_ARGS=(-serial none)

DISP_ARGS=(-display "$DISPLAY")

DATA_ARGS=()
[ -f "$DATA_IMG" ] && DATA_ARGS=(
    -drive if=none,id=data,format=raw,file="$DATA_IMG"
    -device virtio-blk-pci,drive=data,disable-modern=on
)

# user-mode net on a legacy virtio-net device (io-port driver)
NET_ARGS=(
    -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=udp::8081-:8081
    -device virtio-net-pci,netdev=n0,disable-modern=on
)

# hardware RNG for /dev/hwrng + getrandom (host /dev/urandom backend)
RNG_ARGS=(
    -object rng-random,filename=/dev/urandom,id=rng0
    -device virtio-rng-pci,rng=rng0,disable-modern=on
)

exec qemu-system-x86_64 \
    -accel "$ACCEL" \
    -machine q35 \
    -cpu qemu64 \
    -m "$RAM" \
    -smp 1 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file=./OVMF_VARS.fd \
    -drive format=raw,file="$OS_IMG" \
    "${DATA_ARGS[@]}" \
    "${NET_ARGS[@]}" \
    "${RNG_ARGS[@]}" \
    "${SER_ARGS[@]}" \
    "${DISP_ARGS[@]}" \
    $EXTRA
