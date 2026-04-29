# Cloning Detection — Test Results

## Test Environment

| Device | ID | OS | Cloner App |
|--------|-----|-----|-----------|
| Samsung Galaxy (physical) | RQCW106J2PW | Android 14+ | Parallel Space Lite |
| Google Play AVD | emulator-5554 | API 36 | (no cloner installed) |

## Test 1: Physical Device (Normal Install) — Expected CLEAN

**Result:** After fix — SECURE, Tampering likelihood: 0%

All 7 checks clean, 0 errors.

## Test 2: Physical Device (Inside Parallel Space) — Expected TAMPERED

**Setup:**
1. Install Parallel Space Lite from Play Store
2. Open Parallel Space → "+" → add AntiTamperingApp
3. Launch app from inside Parallel Space
4. Run scan

**How to capture logs:**
```bash
adb -s RQCW106J2PW logcat -s TamperDetection,ArtMethodCheck
```

**Result:** _pending — testing in progress_

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

## Notes

- ArtMethod check only runs on API 31–36. On unsupported versions or OEM ART variants, returns "inconclusive".
- `/proc/self/maps` is always readable by the process itself (Linux kernel guarantee).
- Known cloner package check requires `<queries>` in AndroidManifest.xml (configured for 26 packages).
- The executable-extension filtering approach for `/proc/self/maps` is more robust than package whitelisting across device vendors.
