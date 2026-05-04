# Attacker Perspective Testing — "Think Like an Attacker"

## Goal

Attempt to make all 4 detectors return CLEAN on a tampered environment (emulator + Frida). Document what the attacker can bypass and what survives.

## Test Environment

- emulator-5556 (API 35, google_apis, rootable)
- Parallel Space installed (for cloning tests)
- Frida 17.9.5 via frida-server

## Test 1: Full Bypass Script (Default Port)

**Attack:** Single Frida script attempting to bypass all 4 detectors simultaneously.

**Hooks applied:**
- Build.* → Samsung Galaxy S9 values
- SystemProperties → removed qemu indicators
- Sensor.getName/getVendor → "LSM6DSO" / "STMicroelectronics"
- GLES20.glGetString → "Adreno (TM) 630"
- File("/proc/self/maps") → redirected to /dev/null
- Stack traces → stripped cloner class names
- PackageManager → hid cloner packages
- System.getenv → hid VirtualApp env vars
- Class.forName → hid Xposed classes
- Debug.isDebuggerConnected → forced false

**Result:** TAMPERED — 2 of 4 detectors still fired

| Detector | Result | What survived |
|----------|--------|---------------|
| EmulatorDetector | CLEAN 28% (soft) | Sensor absence (step counter/significant motion), sensor noise (stddev=0.000004) |
| CloningDetector | CLEAN 23% (soft) | Package detection (Parallel Space installed) |
| IntegrityDetector | DETECTED 55% | Debug flag, installer source (bypass script crashed before reaching these) |
| HookingDetector | **DETECTED 100%** | 3 hooking libraries in /proc/self/maps, 39 rwxp segments |

## Test 2: Non-Default Frida Port (1337)

**Attack:** Started frida-server on port 1337 instead of default 27042, to bypass port scanning.

**Result:** Port scan bypassed, but detection still TAMPERED

- `hook_frida_port`: BYPASSED (port 27042/27043 closed)
- `hook_libraries`: **DETECTED** (3 libraries — Frida's .so files appear in /proc/self/maps regardless of port)
- `hook_rwxp_segments`: **DETECTED** (39 segments — Frida's JIT needs rwxp pages regardless of port)

**Takeaway:** Changing the port is trivial for the attacker but useless — the hard signals (libraries in memory, rwxp pages) don't depend on which port Frida listens on.

## Test 3: Inside Parallel Space + Frida (Combined Attack)

**Attack:** Ran our app inside Parallel Space AND attached Frida with bypass script.

**Result:** Frida crashed (access violation in Java bridge inside VirtualApp's proxied environment). The combination of VirtualApp's hooks + Frida's hooks conflicted.

**Takeaway:** Attacking from inside a virtual container with Frida is fragile. The two hooking layers interfere with each other. This is an accidental defense — the attacker's tools fight each other.

## What an Attacker CANNOT Bypass

| Check | Why it's resilient |
|-------|-------------------|
| **Sensor noise analysis** | Physical MEMS noise is a hardware characteristic. Frida can hook the sensor name/vendor but can't inject realistic Gaussian noise into the data stream. The statistical distribution of real vs emulated noise is measurably different. |
| **Sensor absence** | The emulator genuinely lacks step counter and significant motion hardware. No software hook can create a physical sensor that doesn't exist. `SensorManager.getDefaultSensor()` returns null. |
| **rwxp memory segments** | Frida's JavaScript engine (GumJS built on V8) fundamentally requires read+write+execute memory pages for JIT compilation. This is architectural — removing rwxp would break Frida's core functionality. |
| **ArtMethod hotness_count** | Reads native C++ struct at offset 14 from ArtMethod pointer. Operates below Java API hooking layer. Works inside VirtualApp containers where jmethodID is a direct pointer (0x70328210 on emulator, 0x718e72b0 inside Parallel Space). |
| **Signing certificate** | Cryptographically impossible to produce a matching SHA-256 hash without the original private signing key. Bypass requires hooking PackageManager, but HookingDetector catches Frida. |

## What an Attacker CAN Bypass

| Check | How | Effort |
|-------|-----|--------|
| Build.* properties | `Build.HARDWARE.value = "qcom"` | 1 line of Frida JS |
| System properties | Hook `SystemProperties.get()` | 5 lines |
| Sensor names/vendors | Hook `Sensor.getName()` | 5 lines |
| GL renderer | Hook `GLES20.glGetString()` | 3 lines |
| Telephony operator | Hook `getNetworkOperatorName()` | 3 lines |
| Stack traces | Hook `getStackTrace()`, filter frames | 10 lines |
| File paths (data dir, source dir) | Hook `getFilesDir()`, `getDataDir()` | 5 lines |
| Package queries | Hook `getPackageInfo()`, throw NameNotFound | 5 lines |
| Environment variables | Hook `System.getenv()` | 5 lines |
| Frida port | Start frida-server on non-default port | 1 CLI flag |
| Xposed classes | Hook `Class.forName()` | 5 lines |
| Debug.isDebuggerConnected | Hook to return false | 1 line |
| Battery values | Already simulated by modern emulators | N/A |

## What We Didn't Try (Future Attacker Improvements)

1. **strongR-frida** — patched Frida build that removes "frida" strings from memory and renames thread names. Would likely bypass `hook_libraries` check.
2. **frida-gadget** — embedded in APK, no TCP port, different injection pattern. Would bypass port scan and possibly library name detection.
3. **Kernel-level /proc filtering** — custom kernel module that strips Frida entries from /proc/self/maps before returning to userspace.
4. **Custom QEMU with realistic sensor simulation** — would defeat sensor noise analysis. Very high effort.
5. **Hooking the integrity check itself** — find `computeConfidence()` in memory, patch it to always return 0. Requires R8 deobfuscation + method address resolution.

## Test 4: Full Repackaging Attack (apktool + re-sign)

Following the attack model from "You Shall not Repackage" (Merlo et al., 2021), Steps 7-11:

**Step 7 — Decompile:** `apktool d app-debug.apk`
- All class names visible: `EmulatorDetector`, `CloningDetector`, etc.
- All detection strings visible: "ranchu", "Goldfish", "frida"
- Signing certificate hash visible in plaintext in `MainViewModel.smali`
- Note: This is a debug build (R8 disabled). Release builds would obfuscate.

**Step 8 — Static analysis:** Attacker can identify all detection points from smali code. Class names, check constants, and thresholds are all readable.

**Step 9 — Neutralize:** Skipped (testing if signature check alone catches repackaging without removing detection code).

**Step 10 — Modify:** Changed app name from "AntiTamperingApp" to "HACKED_APP" in strings.xml (simulating malicious modification).

**Step 11 — Rebuild and re-sign:**
```bash
apktool b decompiled -o repackaged-unsigned.apk
keytool -genkeypair -keystore attacker.keystore -alias attacker ...
zipalign -f 4 repackaged-unsigned.apk repackaged-aligned.apk
apksigner sign --ks attacker.keystore repackaged-aligned.apk
```

**Result:** TAMPERED 100% — `integrity_signature` hard signal fired immediately.
- Original cert: `f9c0679ec146e15dcaab36279624b851b4b74dac0a393a95735912b6cc719291`
- Attacker cert: `6e5520a3b1a5cce074ca7283e54b28a875424836124fd8c3418d7c63d7f48230`

**What this proves:** Even if the attacker doesn't touch the detection code at all, the act of re-signing with a different key is caught by the signature check. This is the strongest integrity signal — cryptographically impossible to forge without the original private key.

**What an attacker would need to do next:** Find the expected hash in smali (`f9c0679e...`), replace it with their own cert hash, rebuild again. This would bypass the signature check — but requires the attacker to identify AND modify the specific smali instruction. R8 obfuscation in release builds makes this significantly harder.

## Conclusion

Our detection has 5 resilient checks that survive even a sophisticated Frida-based attack. The remaining checks (Build properties, file paths, etc.) catch unsophisticated attacks and raise the cost for sophisticated ones. The defense-in-depth approach means an attacker must bypass ALL layers simultaneously — and even then, the hardware-based (sensor noise), architecture-based (rwxp), and crypto-based (signing certificate) checks remain standing.
