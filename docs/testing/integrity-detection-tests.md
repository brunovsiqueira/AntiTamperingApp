# Integrity Detection — Test Results

## Test Environment

| Device | ID | OS | Install method |
|--------|-----|-----|---------------|
| Samsung Galaxy (physical) | RQCW106J2PW | Android 14+ | ADB install (debug APK) |
| Google Play AVD | emulator-5554 | API 36 | ADB install (debug APK) |

## Test 1: Physical Device (Debug Build, ADB Install) — Expected soft signals

**Result:** DETECTED — confidence 55%

Signals fired:
- `integrity_debug_flag`: **SUSPICIOUS** — FLAG_DEBUGGABLE is set (expected for debug build)
- `integrity_installer`: **SUSPICIOUS** — installer is null (expected for ADB install)
- `integrity_signature`: CLEAN — SHA-256 matches hardcoded debug key hash
- `integrity_dex_crc`: CLEAN — skipped (no expected CRCs configured)

**Analysis:** Correct behavior. In a debug build installed via ADB, the debug flag and missing installer are expected. The signature matches because we hardcoded the debug signing key's SHA-256. In a production release build installed from Play Store, both soft signals would be clean.

## Test 2: Emulator (Debug Build, ADB Install) — Expected soft signals

**Result:** DETECTED — confidence 55%

Same signals as physical device:
- `integrity_debug_flag`: SUSPICIOUS (debug build)
- `integrity_installer`: SUSPICIOUS (ADB install)
- `integrity_signature`: CLEAN (matches)
- `integrity_dex_crc`: CLEAN (skipped)

**Analysis:** Identical to physical device. Consistent behavior across devices.

## Test 3: Simulated Repackaged App (Wrong Signature) — Expected TAMPERED

**Setup:** Changed `expectedSigningCertSha256` to `"0000...0000"` to simulate what would happen if someone decompiled and re-signed our APK with a different key.

**Result:** DETECTED — confidence **100%** (hard signal fired)

Signals fired:
- `integrity_signature`: **SUSPICIOUS** — "Signing certificate does NOT match expected value — app was re-signed"
  - actual = `f9c0679ec146e15dcaab36279624b851b4b74dac0a393a95735912b6cc719291`
  - expected = `0000000000000000000000000000000000000000000000000000000000000000`
- `integrity_debug_flag`: SUSPICIOUS (debug build)
- `integrity_installer`: SUSPICIOUS (ADB install)

**Analysis:** Hard signal fired correctly. Signature mismatch → 100% confidence → TAMPERED. This is the primary repackaging detection mechanism. A real attacker who decompiles and re-signs would produce a different certificate hash, triggering this check.

## Test 4: Frida Bypass — Potential Future Test

**How an attacker would bypass:** Hook `PackageManager.getPackageInfo()` to return the original app's certificate bytes instead of the attacker's certificate. This requires root or Frida-gadget injection.

**What would survive:** None of the integrity checks are native-level. All can be bypassed via Frida hooks on `PackageManager`, `ApplicationInfo`, `ZipFile`. This is consistent with the finding from "You Shall not Repackage" (Merlo et al., 2021) — all client-side anti-repackaging schemes are bypassable.

**Defense-in-depth:** The IntegrityDetector catches casual repackaging (apktool + re-sign). Against a Frida-armed attacker, the HookingDetector (future) would detect Frida's presence itself.

## Notes

- Debug flag detection (`FLAG_DEBUGGABLE`) is expected to fire on debug builds. This is correct — it would be clean on release builds.
- Installer source is expected to show `null` for ADB installs. It would show `com.android.vending` for Play Store installs.
- DEX CRC check was not tested (no expected values configured). Requires two-pass build pipeline to set up properly.
- The signing certificate SHA-256 was extracted via: `apksigner verify --print-certs app-debug.apk`
