# Emulator Detection — Test Results

## Test Environment

| Device | ID | OS | Image Type |
|--------|-----|-----|-----------|
| Samsung Galaxy (physical) | RQCW106J2PW | Android 14+ | Production |
| Google Play AVD | emulator-5554 | API 36 (Android 16) | google_apis_playstore/arm64 |
| Google APIs AVD (rootable) | emulator-5556 | API 35 (Android 15) | google_apis/arm64 |

## Test 1: Physical Device — Expected SECURE

**Result:** SECURE — Tampering likelihood: 0%
- All 9 check groups returned clean
- 0 suspicious signals, 0 errors
- Confirmed: no false positives on production Samsung device

## Test 2: Google Play Emulator — Expected TAMPERED

**Result:** TAMPERED — Tampering likelihood: 100%

Hard signals fired (Tier 1 → instant 100%):
- `build_hardware`: Build.HARDWARE = "ranchu" (QEMU virtual board)
- `sensor_string_accelerometer`: "Goldfish 3-axis Accelerometer" by "The Android Open Source Project"
- `sensor_string_gyroscope`: "Goldfish 3-axis Gyroscope" by "The Android Open Source Project"
- `gl_renderer`: "Android Emulator OpenGL ES Translator (Apple M3 Pro)"
- `sysprop_ro_kernel_qemu`: ro.kernel.qemu = "1"

Additional soft signals that also fired:
- `build_fingerprint`: contains "sdk_gphone64_arm64"
- `build_device`: "emu64a"
- `build_model`: "sdk_gphone64_arm64"
- `build_product`: "sdk_gphone64_arm64"
- `sysprop_ro_hardware`: "ranchu"
- `sensor_absence_step_counter`: absent
- `sensor_absence_significant_motion`: absent
- `sensor_noise_accelerometer`: stddev=0.000004 (threshold: 0.002)
- `sensor_noise_gyroscope`: stddev=0.000000 (threshold: 0.001)

Signals that did NOT fire (false negatives on this image):
- `battery_temperature`: 25.0°C (emulator simulates realistic value)
- `battery_voltage`: 5000 mV (emulator simulates realistic value)
- `file_artifact`: QEMU files not found or blocked by SELinux
- `telephony_network_operator`: not "Android" on this image
- `build_manufacturer`: "Google" (we only check for "Genymotion")

**Scan duration:** ~2.1s (dominated by 2s sensor noise sampling)

## Test 3: Frida Bypass — Hard Signals Spoofed

**Setup:**
```bash
# Rootable emulator (emulator-5556, API 35 google_apis)
adb -s emulator-5556 root
adb -s emulator-5556 push /tmp/frida-server /data/local/tmp/
adb -s emulator-5556 shell "/data/local/tmp/frida-server -D &"

# Attach bypass script to running app
source /tmp/frida-env/bin/activate
APP_PID=$(frida-ps -D emulator-5556 | grep -i anti | awk '{print $1}')
frida -D emulator-5556 -p $APP_PID -l tools/frida-bypass-hard-signals.js
```

**What the Frida script spoofs:**
- Build.HARDWARE: "ranchu" → "qcom"
- Build.FINGERPRINT: sdk_gphone → Samsung Galaxy S9 fingerprint
- Build.DEVICE, MODEL, PRODUCT, MANUFACTURER, BRAND → Samsung values
- SystemProperties.get("ro.kernel.qemu") → "" (empty)
- Sensor.getName(): "Goldfish..." → "LSM6DSO..."
- Sensor.getVendor(): "The Android Open Source Project" → "STMicroelectronics"
- GLES20.glGetString(GL_RENDERER): "Android Emulator..." → "Adreno (TM) 630"

**Result:** WARNING — Tampering likelihood: 28%

Hard signals: 0/5 fired (all successfully spoofed)

Soft signals that still fired:
- `sensor_absence_step_counter`: absent (emulator lacks this sensor, can't be spoofed)
- `sensor_absence_significant_motion`: absent (same)
- `sensor_noise_accelerometer`: stddev=0.000004 (real MEMS noise can't be faked by Frida)
- `sensor_noise_gyroscope`: stddev=0.000000 (same)

**Key takeaway:** Frida can bypass all hard signals, but cannot fake physical sensor hardware (noise patterns, sensor presence). The soft signal fallback catches the emulator at 28% (WARNING level). An attacker would need to both spoof the Java APIs AND somehow inject realistic sensor noise to fully evade detection.

## Threshold Tuning History

| Version | TAMPERED threshold | WARNING threshold | Issue |
|---------|-------------------|-------------------|-------|
| Initial | 0.60 | 0.25 | Google Play emulator scored 59% (WARNING) despite 6/9 groups firing |
| After tuning | 0.45 | 0.20 | Fixed — 59% now correctly classified as TAMPERED |
| After two-tier | N/A (hard signals → 1.0) | 0.20 | Hard signals short-circuit to 100%. Soft scoring only as fallback |

## Bugs Found During Testing

1. **SENSOR_DELAY_FASTEST SecurityException (API 31+):** Fixed by using SENSOR_DELAY_GAME (~50Hz). No permission needed.
2. **Build.TYPE/TAGS false negatives:** Google Play emulator images use "user/release-keys" (same as real devices). Removed these checks.
3. **Battery false negatives:** Modern emulators simulate realistic battery (25°C, 5000mV). Battery check is a soft signal only.
