#!/usr/bin/env bash
# Automated QEMU smoke test: builds with the selftest flag baked into the data
# disk, boots headless, waits for the [selftest] DONE line on serial, scores it.
set -euo pipefail
cd "$(dirname "$0")"

TIMEOUT="${TIMEOUT:-120}"
PROFILE="${PROFILE:-release}"
LOG=dist/selftest-serial.log

echo "==> building (selftest flag ON)"
touch imgroot/selftest.flag
./build.sh
rm -f imgroot/selftest.flag

echo "==> booting headless (timeout ${TIMEOUT}s)"
rm -f "$LOG"
set +e
DISPLAY=none SERIAL="file:$LOG" EXTRA="-no-reboot" timeout "$TIMEOUT" ./run.sh &
QP=$!
set -e

deadline=$((SECONDS + TIMEOUT))
result="TIMEOUT"
while [ $SECONDS -lt $deadline ]; do
    if grep -q "\[selftest\] DONE" "$LOG" 2>/dev/null; then
        result="DONE"
        break
    fi
    if grep -q "KERNEL PANIC" "$LOG" 2>/dev/null; then
        result="PANIC"
        break
    fi
    sleep 0.3
done
kill $QP 2>/dev/null || true
wait $QP 2>/dev/null || true

echo
echo "===== serial log (tail) ====="
tail -80 "$LOG" 2>/dev/null || echo "(no log)"
echo "============================="
line=$(grep "\[selftest\] DONE" "$LOG" 2>/dev/null || true)
if [ "$result" = "DONE" ] && echo "$line" | grep -q "fail=0"; then
    echo "SMOKE TEST: PASS ($line)"
    exit 0
else
    echo "SMOKE TEST: FAIL (result=$result ${line:-no-done-line})"
    exit 1
fi
