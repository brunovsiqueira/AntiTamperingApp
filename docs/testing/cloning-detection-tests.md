# Cloning Detection — Test Results

## Test Environment

| Device | ID | OS | Cloner App |
|--------|-----|-----|-----------|
| Samsung Galaxy (physical) | RQCW106J2PW | Android 14+ | Parallel Space Lite |
| Google Play AVD | emulator-5554 | API 36 | (no cloner installed) |

## Test 1: Physical Device (Normal Install) — Expected CLEAN

**Result:** _pending — run scan and paste logs here_

Expected: all 7 checks clean, confidence 0%.

## Test 2: Physical Device (Inside Parallel Space) — Expected TAMPERED

**Setup:**
1. Install Parallel Space Lite from Play Store
2. Open Parallel Space → "+" → add AntiTamperingApp
3. Launch app from inside Parallel Space
4. Run scan

**How to capture logs:**
```bash
# In a separate terminal, start logcat BEFORE pressing scan:
adb -s RQCW106J2PW logcat -s TamperDetection
```

**Result:** _pending — paste logs here after testing_

**Expected hard signals:**
- `clone_data_dir`: path should contain `com.lbe.parallel` instead of our package
- `clone_apk_source`: sourceDir should start with `/data/data/` not `/data/app/`
- `clone_proc_maps`: foreign paths from Parallel Space's directory in memory maps
- `clone_art_method`: hotness_count == 0 if API 31+ (virtual container DexClassLoader)

**Expected soft signals:**
- `clone_stack_trace`: may contain `com.doubleagent` (Parallel Space's internal class prefix)
- `clone_env_vars`: may contain VirtualApp env vars if Parallel Space uses VirtualApp internally
- `clone_packages`: `com.lbe.parallel.intl` should be found (if PackageManager not hooked)

## Test 3: Emulator (No Cloner) — Expected CLEAN for Cloning

**Result:** _pending_

Expected: Cloning detection clean. Emulator detection should fire separately.

## Notes

- ArtMethod check only runs on API 31–36. On older devices it returns "inconclusive" (no signal, not "clean").
- `/proc/self/maps` is always readable by the process itself (Linux kernel guarantee).
- Known cloner package check requires `<queries>` in AndroidManifest.xml (already configured for 26 packages).
