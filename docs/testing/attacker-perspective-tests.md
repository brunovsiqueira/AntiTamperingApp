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

## Test 4: Full Repackaging Attack — Debug Build (apktool + re-sign)

Following the attack model from "You Shall not Repackage" (Merlo et al., 2021), Steps 7-11:

**Step 7 — Decompile:** `apktool d app-debug.apk`
- All class names visible: `EmulatorDetector`, `CloningDetector`, etc.
- All detection strings visible: "ranchu", "Goldfish", "frida"
- Signing certificate hash visible in plaintext in `MainViewModel.smali`
- 13,267 smali files (debug build, no R8)

**Step 8 — Static analysis:** Attacker can identify all detection points from smali code. Class names, check constants, method names, and thresholds are all readable.

**Steps 9-11 — Modify, rebuild, re-sign:**
```bash
# Modify a resource (simulating malicious change)
sed -i 's/AntiTamperingApp/HACKED_APP/g' decompiled/res/values/strings.xml

# Rebuild and sign with attacker key
apktool b decompiled -o repackaged-unsigned.apk
keytool -genkeypair -keystore attacker.keystore -alias attacker -keyalg RSA -keysize 2048
zipalign -f 4 repackaged-unsigned.apk repackaged-aligned.apk
apksigner sign --ks attacker.keystore repackaged-aligned.apk
```

**Result:** TAMPERED 100% — `integrity_signature` hard signal fired immediately.
- Original cert: `f9c0679ec146e15dcaab36279624b851b4b74dac0a393a95735912b6cc719291`
- Attacker cert: `6e5520a3b1a5cce074ca7283e54b28a875424836124fd8c3418d7c63d7f48230`

## Test 5: Static Analysis — Release Build (R8 Obfuscation)

Decompiled the release APK (`assembleRelease`, R8 enabled) to compare what an attacker sees vs the debug build.

| What | Debug Build | Release Build |
|------|------------|---------------|
| APK size | 9.2 MB | 968 KB |
| Smali files | 13,267 | 1,844 |
| Internal method names (`checkBuildProperties`, `computeConfidence`) | Visible | **Obfuscated (gone)** |
| `HARD_SIGNAL_CHECKS`, `SOFT_CHECK_WEIGHTS` | Visible | **Obfuscated (gone)** |
| Public API class names (`DetectionEngine`, `EmulatorDetector`) | Visible | Visible (kept for SDK consumers) |
| Detection strings ("ranchu", "goldfish", "frida") | Visible | Visible (R8 cannot encrypt strings) |
| Signing cert hash | Visible in `MainViewModel.smali` | Visible in `a10.smali` (obfuscated file name, but string constant readable) |

**Key findings:**
- R8 obfuscates internal logic: an attacker cannot find `computeConfidence()` or `HARD_SIGNAL_CHECKS` to understand the scoring system
- Public API class names remain visible (necessary for SDK integration)
- String constants (detection patterns, cert hash) remain visible — R8 limitation. Production-grade protection would use DexGuard for string encryption.
- The `MainViewModel` class is renamed to `a10` — the cert hash is harder to locate but still findable via string search

**R8 rules follow Android official guidance:**
- Library module: `isMinifyEnabled = false` (app handles R8 for everything)
- Consumer rules: keep only public API constructors + data classes
- App rules: keep only reflection + JNI entry points
- Source: https://developer.android.com/topic/performance/app-optimization/library-optimization

## Conclusion

Our detection has 5 resilient checks that survive even a sophisticated Frida-based attack:
1. **Sensor noise** — MEMS physics, not hookable by software
2. **Sensor absence** — hardware genuinely missing
3. **rwxp segments** — Frida's JIT architectural requirement
4. **ArtMethod hotness_count** — native ART memory, below hook layer
5. **Signing certificate** — cryptographic impossibility without private key

The remaining checks (Build properties, file paths, etc.) catch unsophisticated attacks and raise the cost for sophisticated ones.

R8 obfuscation (release builds) hides internal scoring logic (`computeConfidence`, `HARD_SIGNAL_CHECKS`) but cannot encrypt string constants — that requires DexGuard (out of scope). Full repackaging attack confirmed: re-signed APK caught by signature check at 100% confidence.

The defense-in-depth approach means an attacker must bypass ALL layers simultaneously — and even then, the hardware-based (sensor noise), architecture-based (rwxp), and crypto-based (signing certificate) checks remain standing.
