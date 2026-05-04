# AntiTamperingApp

Runtime environment anomaly detection module for Android. Detects emulators, app cloning/virtualization, repackaging, and hooking frameworks.

## Requirements

- **Android Studio** Meerkat (2025.1+) or newer
- **JDK** 11+
- **Android SDK** 36 (compileSdk)
- **NDK** (installed via SDK Manager — needed for ArtMethod native check)
- **CMake** 3.22.1+ (installed via SDK Manager)
- **Min SDK** 24 (Android 7.0)

### Installing NDK and CMake

In Android Studio: **Settings > Languages & Frameworks > Android SDK > SDK Tools** — check **NDK (Side by side)** and **CMake**, then click Apply.

Or via command line:
```bash
sdkmanager "ndk;27.0.12077973" "cmake;3.22.1"
```

## Build

```bash
git clone https://github.com/brunovsiqueira/AntiTamperingApp.git
cd AntiTamperingApp
./gradlew assembleDebug
```

The output APK is at `app/build/outputs/apk/debug/app-debug.apk`.

## Install and Run

```bash
# On a connected device or emulator
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.bruno.antitamperingapp/.MainActivity
```

The app shows two buttons:
- **Fast Scan** — instant checks only (~200ms)
- **Deep Scan** — includes 2-second sensor noise analysis for catching spoofed emulators

## Project Structure

```
AntiTamperingApp/
├── app/                          # Demo app (Compose UI)
│   └── MainViewModel.kt         # Wires detectors to UI
│
├── detection/                    # SDK library module
│   ├── src/main/java/.../detection/
│   │   ├── DetectionEngine.kt    # Orchestrates detectors concurrently
│   │   ├── TamperDetector.kt     # Interface for pluggable detectors
│   │   ├── DetectionResult.kt    # Result + Evidence data models
│   │   ├── TamperVerdict.kt      # Overall verdict (SECURE/WARNING/TAMPERED)
│   │   ├── detectors/
│   │   │   ├── EmulatorDetector.kt    # 9 checks (Build props, sensors, GL, battery, files, telephony)
│   │   │   ├── CloningDetector.kt     # 7 checks (paths, /proc/maps, env vars, stack, ArtMethod)
│   │   │   ├── IntegrityDetector.kt   # 4 checks (signature, debug flag, installer, DEX CRC)
│   │   │   ├── HookingDetector.kt     # 5 checks (/proc/maps libs, rwxp, Frida port, Xposed, debugger)
│   │   │   └── ArtMethodChecker.kt    # JNI bridge for ArtMethod hotness_count
│   │   ├── error/
│   │   │   └── DetectionError.kt      # Sealed class (5 error types)
│   │   └── util/
│   │       ├── SafeExec.kt            # Defensive wrapper (fail-open)
│   │       └── DetectionLogger.kt     # Unified logging (TamperDetection tag)
│   └── src/main/cpp/
│       ├── CMakeLists.txt
│       └── art_method_check.c         # Native ArtMethod struct reading
│
├── tools/                        # Frida bypass scripts for testing
│   ├── frida-bypass-hard-signals.js     # Emulator hard signal bypass
│   ├── frida-bypass-cloning-signals.js  # Cloning check bypass
│   └── frida-full-bypass.js             # All-in-one attacker simulation
│
└── docs/
    ├── adr/                      # Architecture Decision Records
    │   ├── ADR-001 ... ADR-007
    ├── testing/                  # Test results and findings
    │   ├── emulator-detection-tests.md
    │   ├── cloning-detection-tests.md
    │   ├── integrity-detection-tests.md
    │   ├── hooking-detection-tests.md
    │   └── attacker-perspective-tests.md
    └── research/
        └── paper-references.md
```

## SDK Usage

```kotlin
val engine = DetectionEngine.Builder()
    .addDetector(EmulatorDetector(
        includeSensorAnalysis = true, // false for faster results (~50ms vs ~2s)
    ))
    .addDetector(CloningDetector())
    .addDetector(IntegrityDetector(
        expectedSigningCertSha256 = "your-cert-sha256-here",
    ))
    .addDetector(HookingDetector())
    .build()

// Run all detectors concurrently
val verdict: TamperVerdict = engine.evaluate(context)

// Check result
when (verdict.status) {
    TamperStatus.SECURE  -> { /* environment is clean */ }
    TamperStatus.WARNING -> { /* some suspicious signals */ }
    TamperStatus.TAMPERED -> { /* tampering detected */ }
}

// Inspect per-category results
verdict.results.forEach { (category, result) ->
    result.evidence.filter { it.suspicious }.forEach { evidence ->
        Log.d("Security", "${evidence.checkName}: ${evidence.description}")
    }
}
```

To get your signing certificate SHA-256:
```bash
apksigner verify --print-certs app-release.apk | grep SHA-256
```

## Testing

### On a physical device (expected: SECURE)

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.bruno.antitamperingapp/.MainActivity
# Tap "Deep Scan" — should show Secure (debug flag and installer are informational)
```

### On the Android emulator (expected: TAMPERED)

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.bruno.antitamperingapp/.MainActivity
# Tap "Deep Scan" — should show Tampered with emulator signals
```

### Inside a cloner app (expected: TAMPERED)

1. Install Parallel Space from Play Store on your device
2. Open Parallel Space, add AntiTamperingApp
3. Launch the cloned instance from inside Parallel Space
4. Tap "Deep Scan" — should show Tampered with cloning signals

### With Frida attached (expected: TAMPERED — hooking detected)

Requires a rootable emulator (google_apis image, not google_play):

```bash
# Create and boot a rootable emulator
sdkmanager "system-images;android-35;google_apis;arm64-v8a"
avdmanager create avd -n frida_test -k "system-images;android-35;google_apis;arm64-v8a" -d pixel_6
emulator -avd frida_test &

# Root and install frida-server
adb root
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server -D &"

# Install and launch app
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.bruno.antitamperingapp/.MainActivity

# Attach Frida
pip install frida-tools
frida -U -p $(frida-ps -U | grep AntiTamper | awk '{print $1}') \
  -l tools/frida-bypass-hard-signals.js

# Tap "Deep Scan" — HookingDetector should catch Frida via /proc/self/maps and rwxp segments
```

### Viewing logs

```bash
adb logcat -s TamperDetection        # All detection results
adb logcat -s ArtMethodCheck          # ArtMethod native check details
adb logcat -s SafeExec                # Error handling / defensive wrapper
```

## Detection Summary

| Detector | Checks | Hard Signals |
|----------|--------|-------------|
| **EmulatorDetector** | 9 | Build.HARDWARE=ranchu, sensor "Goldfish", GL "Android Emulator", ro.kernel.qemu=1 |
| **CloningDetector** | 7 | Foreign package in data dir, APK from /data/data/, foreign paths in /proc/self/maps, ArtMethod hotness_count=0 |
| **IntegrityDetector** | 4 | Signing certificate SHA-256 mismatch |
| **HookingDetector** | 5 | Hooking libraries in /proc/self/maps, rwxp memory segments |

**Total: 25 checks** across 4 categories with two-tier scoring (hard signals = instant 100%, soft signals = weighted scoring).

## Architecture Decision Records

| ADR | Topic |
|-----|-------|
| [ADR-001](docs/adr/ADR-001-architecture-strategy-pattern.md) | Strategy pattern with pluggable detectors |
| [ADR-002](docs/adr/ADR-002-scoring-weighted-confidence.md) | Weighted confidence scoring |
| [ADR-003](docs/adr/ADR-003-error-handling-strategy.md) | Fail-open error handling |
| [ADR-004](docs/adr/ADR-004-emulator-detection-strategy.md) | Emulator detection (9 checks, sensor noise) |
| [ADR-005](docs/adr/ADR-005-cloning-detection-strategy.md) | Cloning detection (7 checks, ArtMethod) |
| [ADR-006](docs/adr/ADR-006-integrity-detection-strategy.md) | Integrity detection (signature, DEX CRC) |
| [ADR-007](docs/adr/ADR-007-hooking-detection-strategy.md) | Hooking detection (Frida, Xposed, rwxp) |
