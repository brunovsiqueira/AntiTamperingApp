# Hooking Detection — Test Results

## Test 1: Emulator Without Frida — Expected CLEAN

**Result:** CLEAN — confidence 0%, 5 evidence items, 0 errors

All checks clean: no hooking libraries, no rwxp segments, Frida ports closed, no Xposed classes, no debugger.

## Test 2: Emulator With Frida Attached — Expected DETECTED

**Setup:** emulator-5556 (API 35, rootable), frida-server running, Frida attached to app PID with minimal script (just `console.log`, no hooks).

**Result:** DETECTED — confidence **100%** (2 hard signals fired)

- `hook_libraries`: Found 3 hooking library entries in /proc/self/maps (Frida agent)
- `hook_rwxp_segments`: Found 10 suspicious rwxp segments (Frida's GumJS/V8 JIT engine creates read+write+execute pages)

**Key finding:** Even with Frida doing NOTHING (no hooks, just attached), the HookingDetector catches it via:
1. Frida's libraries appearing in the process memory map
2. Frida's JIT engine creating rwxp memory pages

The rwxp check is particularly strong — Frida fundamentally needs writable+executable memory for its JavaScript engine. This cannot be avoided without completely changing Frida's architecture.

## Test 3: Physical Device Without Frida — CLEAN

**Result:** CLEAN — confidence 0%, 5 evidence items, 0 errors

All checks clean on Samsung Galaxy physical device. No false positives.

## Notes

- The /proc/self/maps check in HookingDetector looks for different strings than CloningDetector — hooking library names (frida, xposed, substrate) vs foreign package paths.
- rwxp whitelist includes `dalvik-jit-code-cache` and `dalvik-zygote-jit-code-cache` (ART's legitimate JIT).
- Frida port scan uses 200ms timeout per port to avoid blocking.
