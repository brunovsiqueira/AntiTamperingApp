#!/bin/bash
#
# Automated security integration tests for AntiTamperingApp
#
# Runs detection scans on connected devices and validates results.
# Requires: adb, a connected emulator, optionally frida-tools
#
# Usage:
#   ./tools/tests/run-security-tests.sh [emulator-id]
#
# Example:
#   ./tools/tests/run-security-tests.sh emulator-5554

set -e

PACKAGE="com.bruno.antitamperingapp"
ACTIVITY="$PACKAGE/.MainActivity"
APK="app/build/outputs/apk/debug/app-debug.apk"
DEVICE="${1:-emulator-5554}"
PASS=0
FAIL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# ──────────────────────────────────────────────
# Setup
# ──────────────────────────────────────────────

echo "=========================================="
echo "AntiTamperingApp — Security Integration Tests"
echo "=========================================="
echo ""

log_info "Target device: $DEVICE"

# Check device is connected
if ! adb -s "$DEVICE" get-state >/dev/null 2>&1; then
    echo "ERROR: Device $DEVICE not found. Connect a device or emulator."
    exit 1
fi

# Build
log_info "Building APK..."
./gradlew assembleDebug -q 2>&1
if [ ! -f "$APK" ]; then
    echo "ERROR: APK not found at $APK"
    exit 1
fi
log_info "APK built: $APK"

# Install
log_info "Installing on $DEVICE..."
adb -s "$DEVICE" install -r "$APK" >/dev/null 2>&1

# ──────────────────────────────────────────────
# Helper: launch app, tap scan, return logcat
# ──────────────────────────────────────────────

run_scan() {
    local scan_type="$1" # "fast" or "deep"

    adb -s "$DEVICE" shell am force-stop "$PACKAGE" 2>/dev/null
    sleep 1
    adb -s "$DEVICE" shell am start -n "$ACTIVITY" >/dev/null 2>&1
    sleep 4
    adb -s "$DEVICE" logcat -c

    # Dump UI to find buttons
    adb -s "$DEVICE" shell "uiautomator dump && cat /sdcard/window_dump.xml" 2>/dev/null | tr '>' '\n' | grep "clickable=\"true\"" | grep "$PACKAGE\|lbe" > /tmp/buttons.txt 2>/dev/null

    # Fast = first button, Deep = second button
    if [ "$scan_type" = "fast" ]; then
        local bounds=$(head -1 /tmp/buttons.txt | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1)
    else
        local bounds=$(tail -1 /tmp/buttons.txt | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1)
    fi

    if [ -z "$bounds" ]; then
        echo "ERROR: Could not find scan button"
        return 1
    fi

    # Calculate center of button
    local x1=$(echo "$bounds" | grep -o '\[[0-9]*,' | head -1 | tr -d '[,')
    local y1=$(echo "$bounds" | grep -o ',[0-9]*\]' | head -1 | tr -d ',]')
    local x2=$(echo "$bounds" | grep -o '\[[0-9]*,' | tail -1 | tr -d '[,')
    local y2=$(echo "$bounds" | grep -o ',[0-9]*\]' | tail -1 | tr -d ',]')
    local cx=$(( (x1 + x2) / 2 ))
    local cy=$(( (y1 + y2) / 2 ))

    adb -s "$DEVICE" shell input tap "$cx" "$cy"

    # Wait for scan to complete (deep scan takes ~2s for sensors)
    if [ "$scan_type" = "deep" ]; then
        sleep 7
    else
        sleep 4
    fi

    # Return logcat output
    adb -s "$DEVICE" logcat -d -s TamperDetection 2>&1
}

# ──────────────────────────────────────────────
# Test 1: Emulator detection (Fast Scan)
# ──────────────────────────────────────────────

echo ""
log_info "Test 1: Emulator detection (Fast Scan)..."
LOGCAT=$(run_scan "fast")
VERDICT=$(echo "$LOGCAT" | grep "VERDICT:" | head -1)

if echo "$VERDICT" | grep -q "Tampered"; then
    log_pass "Emulator detected as TAMPERED (fast scan)"
else
    log_fail "Emulator NOT detected (fast scan). Verdict: $VERDICT"
fi

# Check EmulatorDetector specifically
if echo "$LOGCAT" | grep -q "\[EmulatorDetector\] DETECTED"; then
    log_pass "EmulatorDetector returned DETECTED"
else
    log_fail "EmulatorDetector did not return DETECTED"
fi

# ──────────────────────────────────────────────
# Test 2: Emulator detection (Deep Scan — with sensors)
# ──────────────────────────────────────────────

echo ""
log_info "Test 2: Emulator detection (Deep Scan)..."
LOGCAT=$(run_scan "deep")
VERDICT=$(echo "$LOGCAT" | grep "VERDICT:" | head -1)

if echo "$VERDICT" | grep -q "Tampered"; then
    log_pass "Emulator detected as TAMPERED (deep scan)"
else
    log_fail "Emulator NOT detected (deep scan). Verdict: $VERDICT"
fi

# Check specific hard signals
if echo "$LOGCAT" | grep -q "build_hardware"; then
    log_pass "Build.HARDWARE check produced evidence"
else
    log_fail "Build.HARDWARE check missing"
fi

if echo "$LOGCAT" | grep -q "sensor_string_accelerometer"; then
    log_pass "Sensor string check produced evidence"
else
    log_fail "Sensor string check missing"
fi

if echo "$LOGCAT" | grep -q "gl_renderer"; then
    log_pass "GL renderer check produced evidence"
else
    log_fail "GL renderer check missing"
fi

# Check sensor noise (only in deep scan)
if echo "$LOGCAT" | grep -q "sensor_noise_accelerometer"; then
    log_pass "Sensor noise analysis ran (deep scan)"
else
    log_fail "Sensor noise analysis did not run"
fi

# ──────────────────────────────────────────────
# Test 3: No false positives on cloning (not inside container)
# ──────────────────────────────────────────────

echo ""
log_info "Test 3: Cloning detector — no false positive on emulator..."
if echo "$LOGCAT" | grep -q "\[CloningDetector\] DETECTED"; then
    log_fail "CloningDetector false positive on emulator (should be CLEAN)"
else
    log_pass "CloningDetector correctly CLEAN on emulator"
fi

# ──────────────────────────────────────────────
# Test 4: Hooking detector — no false positive (no Frida)
# ──────────────────────────────────────────────

echo ""
log_info "Test 4: Hooking detector — no false positive without Frida..."
if echo "$LOGCAT" | grep -q "\[HookingDetector\] DETECTED"; then
    log_fail "HookingDetector false positive (no Frida attached, should be CLEAN)"
else
    log_pass "HookingDetector correctly CLEAN without Frida"
fi

# ──────────────────────────────────────────────
# Test 5: Performance — scan completes within budget
# ──────────────────────────────────────────────

echo ""
log_info "Test 5: Performance check..."
DURATION=$(echo "$LOGCAT" | grep "VERDICT:" | grep -o "duration=[0-9]*ms" | grep -o "[0-9]*")
if [ -n "$DURATION" ]; then
    if [ "$DURATION" -lt 5000 ]; then
        log_pass "Deep scan completed in ${DURATION}ms (budget: <5000ms)"
    else
        log_fail "Deep scan took ${DURATION}ms (budget: <5000ms)"
    fi
else
    log_fail "Could not parse scan duration"
fi

# ──────────────────────────────────────────────
# Test 6: All 4 detectors ran
# ──────────────────────────────────────────────

echo ""
log_info "Test 6: All 4 detectors executed..."
for detector in EmulatorDetector CloningDetector IntegrityDetector HookingDetector; do
    if echo "$LOGCAT" | grep -q "\[$detector\]"; then
        log_pass "$detector executed"
    else
        log_fail "$detector did NOT execute"
    fi
done

# ──────────────────────────────────────────────
# Test 7: Evidence count — minimum expected
# ──────────────────────────────────────────────

echo ""
log_info "Test 7: Evidence count..."
EVIDENCE_COUNT=$(echo "$LOGCAT" | grep -c "  ->")
if [ "$EVIDENCE_COUNT" -gt 0 ]; then
    log_pass "Produced $EVIDENCE_COUNT suspicious evidence items"
else
    log_fail "No suspicious evidence produced"
fi

# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

echo ""
echo "=========================================="
echo "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
