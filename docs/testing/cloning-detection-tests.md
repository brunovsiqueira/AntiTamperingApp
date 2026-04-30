# Cloning Detection — Test Results

## Test Environment

| Device | ID | OS | Cloner App |
|--------|-----|-----|-----------|
| Samsung Galaxy (physical) | RQCW106J2PW | Android 14+ | Parallel Space Lite |
| Google Play AVD | emulator-5554 | API 36 | (no cloner installed) |

## Test 1: Physical Device (Normal Install, Parallel Space Installed but Not Used) — Expected CLEAN

**Result:** SECURE — Tampering likelihood: 11%

6/7 checks clean. One soft signal fired:
- `clone_packages`: Found `com.lbe.parallel.intl` installed (Parallel Space is on the device but we're NOT running inside it)

This is correct behavior — detecting that a cloner is *installed* is a weak signal (soft, weight 0.4). The app is running normally, not cloned. Score 11% is below WARNING threshold (20%).

## Test 2: Physical Device (Inside Parallel Space) — Expected TAMPERED

**Setup:**
1. Install Parallel Space Lite from Play Store
2. Open Parallel Space → "+" → add AntiTamperingApp
3. Launch app from inside Parallel Space
4. Run scan

**Result:** TAMPERED — Tampering likelihood: 100% (3 hard signals fired)

**Hard signals that fired:**
- `clone_data_dir`: `/data/data/com.lbe.parallel.intl/parallel_intl/0/com.bruno.antitamperingapp/files` — data stored inside Parallel Space's sandbox
- `clone_proc_maps`: 9 foreign paths including `libdaclient_64.so`, `libcompatible_64.so`, `base.apk`, `base.art` from `com.lbe.parallel.intl`
- `clone_art_method`: `hotness_count == 0` — ArtMethod check fired! jmethodID = `0x70328210` (valid pointer inside container, vs `0x15` index outside)

**Soft signals that also fired:**
- `clone_packages`: Found `com.lbe.parallel.intl` installed

**Key finding — ArtMethod works inside virtual containers:**
- Outside Parallel Space: jmethodID = `0x15` (index, Samsung encoding) → inconclusive
- Inside Parallel Space: jmethodID = `0x70328210` (direct pointer, VirtualApp AOSP encoding) → `hotness_count == 0` → DETECTED
- Parallel Space's VirtualApp engine uses AOSP's direct-pointer jmethodID, not Samsung's index encoding. The check fires exactly where it matters.

**Scan duration:** 21ms for CloningDetector (instant — all hard signals, no sensor sampling needed)

**Expected hard signals:**
- `clone_data_dir`: path should contain `com.lbe.parallel` instead of our package
- `clone_apk_source`: sourceDir should start with `/data/data/` not `/data/app/`
- `clone_proc_maps`: foreign .apk/.so/.dex paths from Parallel Space's directory in memory maps
- `clone_art_method`: hotness_count == 0 if jmethodID is a valid pointer on this device

**Expected soft signals:**
- `clone_stack_trace`: may contain `com.doubleagent` (Parallel Space's internal class prefix)
- `clone_env_vars`: may contain VirtualApp env vars if Parallel Space uses VirtualApp internally
- `clone_packages`: `com.lbe.parallel.intl` should be found (if PackageManager not hooked)

## Test 3: Emulator (No Cloner) — Expected CLEAN for Cloning

**Result:** _pending_

Expected: Cloning detection clean. Emulator detection should fire separately.

## Bugs Found During Testing

### Bug 1: False positive from Google Play Services font mapping (FIXED)

**Symptom:** Physical Samsung device showed TAMPERED 100% on first run (no cloner installed).

**Root cause:** `/proc/self/maps` contained:
```
/data/data/com.google.android.gms/files/fonts/opentype/Noto_COLR_Emoji_Compat-400-100_0-0_0.ttf
```
Google Play Services memory-maps emoji fonts into other apps' processes for shared rendering. Our check flagged this as "foreign package path" → hard signal → 100%.

**Initial fix:** Whitelist `com.google.android.gms`, `com.google.android.trichromelibrary`, `com.google.android.webview`.

**Problem with initial fix:** Package whitelist is fragile — Chinese devices (Huawei, Xiaomi) may have their own system services mapping files. Alternative app stores may do the same. We can't enumerate all legitimate packages.

**Better fix (implemented):** Instead of whitelisting packages, only flag foreign paths that contain **executable artifacts** (`.apk`, `.dex`, `.so`, `.odex`, `.vdex`, `.oat`, `.art`). Non-executable files (fonts, configs, data) mapped by any system service are ignored. This approach works regardless of device vendor or app store.

### Bug 2: ArtMethod SIGSEGV crash (FIXED, under investigation)

**Symptom:** App crashed with SIGSEGV at address `0x19` (25 decimal) when reading ArtMethod hotness_count on Samsung physical device. Also crashed on emulator before signal handler was added.

**Root cause:** `jmethodID` returned by `FromReflectedMethod()` is NOT a direct pointer to ArtMethod. The actual value is `0xb` (decimal 11) — a method index, not a memory address. Our code tried to read at `0xb + 14 = 0x19` (decimal 25), which is unmapped memory → SIGSEGV at fault address `0x19`.

**Fix v1:** Added SIGSEGV signal handler with `sigsetjmp`/`siglongjmp` to catch the crash and return RESULT_ERROR gracefully.

**Fix v2:** Added pointer validation — if `jmethodID < 0x10000`, it's clearly not a valid heap pointer, skip the read entirely without needing the signal handler.

**Status:** No longer crashes. Returns "inconclusive" on both Samsung physical device and Google APIs emulator.

**Root cause confirmed:** Both devices return `jmethodID = 0xb` (decimal 11). This is a method index, not a memory address. Modern ART implementations (both Samsung and Google APIs builds) use indirect jmethodID encoding where jmethodID is an index into a method table, not a direct pointer to the ArtMethod struct. The Matrioska paper (ACSAC 2024) likely tested on AOSP debug builds where jmethodID == ArtMethod*.

**Resolving the indirection would require:**
- Reading the ART internal method table (hidden, version-specific)
- Or using `art::jni::DecodeArtMethod()` which is an internal ART function

Both are significantly more fragile than the current approach and outside scope.

**Decision:** Keep the check as a positive-only signal. It safely returns "inconclusive" on devices where jmethodID is indirect, and would correctly detect virtual containers on AOSP builds where jmethodID is a direct pointer. The story of "implemented state-of-the-art technique, discovered real-world limitation, handled gracefully" is valuable for the interview.

**Impact on detection:** ArtMethod check is a positive-only signal — "inconclusive" means no opinion, not "clean". The other 6 checks still function correctly.

## Test 4: Frida Cloning Bypass Inside Parallel Space (Emulator)

**Setup:**
- emulator-5556 (API 35, google_apis, rootable)
- Parallel Space installed, AntiTamperingApp cloned inside it
- Frida attached to cloned app PID with `frida-bypass-cloning-signals.js`

**Frida hooks active:**
1. `File.<init>` — blocked `/proc/self/maps` reading
2. `getFilesDir()` — returned fake path without container package
3. `getDataDir()` — returned fake path
4. `getApplicationInfo().sourceDir` — returned `/data/app/` path
5. `getStackTrace()` — stripped cloner class names
6. `getPackageInfo()` — hid `com.lbe.parallel.intl`
7. `System.getenv()` — hid VirtualApp env vars

**Baseline (without Frida):** TAMPERED 100% — 4 signals fired (data_dir, proc_maps, packages, art_method)

**With Frida bypass:** TAMPERED 100% — **only `clone_art_method` survived**

| Signal | Without Frida | With Frida |
|--------|--------------|------------|
| clone_data_dir | DETECTED | Bypassed |
| clone_apk_source | clean | clean |
| clone_proc_maps | DETECTED (13 foreign paths) | Bypassed |
| clone_env_vars | clean | clean |
| clone_stack_trace | clean | clean |
| clone_packages | DETECTED | Bypassed |
| clone_art_method | DETECTED (hotness_count=0) | **DETECTED (hotness_count=0)** |

**Key result:** ArtMethod at `0x718e72b0` with `hotness_count=0` is the only signal Frida could not bypass. It reads native ART memory directly, below all Java API hooks. This validates the defense-in-depth architecture from the Mascara paper (Section IX-B).

## Notes

- ArtMethod check only runs on API 31–36. On unsupported versions or OEM ART variants, returns "inconclusive".
- `/proc/self/maps` is always readable by the process itself (Linux kernel guarantee).
- Known cloner package check requires `<queries>` in AndroidManifest.xml (configured for 26 packages).
- The executable-extension filtering approach for `/proc/self/maps` is more robust than package whitelisting across device vendors.
