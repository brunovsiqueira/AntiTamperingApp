# ADR-004: Emulator Detection Strategy

**Status:** Accepted
**Date:** 2026-04-26

## Context

The Incognia challenge explicitly requires detecting the "standard Android emulator (AVD / Android Emulator)." We need to decide which checks to implement, whether to use native code, and how to weight each signal.

## Research Findings

We conducted deep research validating each technique against AOSP source code, current Android Studio emulator behavior (API 35/36), academic papers, and open-source detection libraries. Key findings:

1. **All Build.* properties are trivially spoofable** via Frida (~5 lines of JS). Single-property checks are insufficient.
2. **Sensor hardware strings** ("Goldfish" name, "AOSP" vendor) are the most reliable single check for AVD, confirmed from AOSP goldfish sensor HAL source code.
3. **Battery temperature=0 + voltage=0** is hard to spoof via standard emulator tools and has near-zero false positive risk.
4. **GL Renderer** consistently returns "Android Emulator OpenGL ES Translator" on AVD. Requires headless EGL PBuffer context (no visible UI needed).
5. **Sensor noise analysis** is viable: real MEMS accelerometers show stddev 0.004-0.011 m/s² (peer-reviewed, PMC10490716); emulators show < 0.001 m/s² over a 2-second window.
6. **NDK/native code is NOT justified** for emulator detection: half the checks (sensors, battery) are Java-only APIs with no native equivalent. Breadth of signals matters more than hooking resistance for this challenge.
7. **IMEI checks are blocked** for third-party apps on API 29+. Dropped.
8. **/proc/bus/input/devices** is blocked by SELinux on API 30+. Dropped.
9. **getNetworkOperatorName() == "Android"** has zero documented false positives — no real carrier, no-SIM device, or WiFi-only tablet returns "Android" (they return "").

## Decision

Implement **9 check groups** in pure Kotlin (no NDK), split into two phases:

### Instant checks (~50ms total)
| Check | Weight | Signal |
|-------|--------|--------|
| Build property cross-validation | 0.7 | 8 properties + consistency checks |
| System properties | 0.6 | ro.kernel.qemu, ro.hardware, init.svc.qemud |
| Sensor hardware strings | 0.9 | Accelerometer/gyroscope "Goldfish" name, AOSP vendor |
| Sensor absence | 0.5 | TYPE_STEP_COUNTER / TYPE_SIGNIFICANT_MOTION missing |
| Battery anomalies | 0.85 | temperature=0 AND voltage=0 |
| GL Renderer | 0.9 | "Android Emulator OpenGL ES Translator" via PBuffer EGL |
| File system artifacts | 0.6 | /system/bin/qemu-props, /dev/qemu_pipe, /dev/goldfish_pipe |
| Telephony operator | 0.55 | getNetworkOperatorName() == "Android" |

### Extended checks (~2-3s)
| Check | Weight | Signal |
|-------|--------|--------|
| Sensor noise analysis | 0.8 | Accelerometer stddev < 0.001 m/s² over 2s sampling |

### Why two phases
The `detect()` method runs both phases. Instant checks fire first; the sensor sampling runs concurrently via a coroutine. Total wall-clock time is ~3s (dominated by sensor sampling). Internally the detector exposes `detectInstant()` for callers that need a fast result without the sampling delay.

### Confidence scoring
```
confidence = sum(triggered_weights) / sum(all_weights)
detected = confidence >= 0.35
```
A threshold of 0.35 means roughly 2-3 independent signals must fire before flagging, preventing single-check false positives.

## Alternatives Considered

- **NDK/JNI for file reads and property checks**: Rejected. Half the checks (sensors, battery) must stay in Java. The added complexity (CMake, JNI boilerplate, multi-ABI builds) is not justified when the primary detection target is casual emulator users, not Frida-armed attackers.
- **Sensor noise only (no string checks)**: Rejected. The 2-3s sampling delay is unacceptable as the sole check. Instant string checks provide immediate signal.
- **IMEI-based detection**: Rejected. Blocked for third-party apps on API 29+ (READ_PRIVILEGED_PHONE_STATE required).
- **Single Build property check**: Rejected. Trivially spoofable. Cross-validation across 8+ properties is the documented best practice (DeepID SDK, AntiFakerAndroidChecker).

## Trade-offs

- (+) 9 independent signals make bypass significantly harder — attacker must spoof all consistently.
- (+) Pure Kotlin: no NDK complexity, fully testable, lower maintenance.
- (+) Two-phase design: callers can choose instant-only for latency-sensitive paths.
- (+) Every check is permission-free (no runtime permission prompts).
- (-) Java-level checks are hookable by Frida. Accepted risk for this challenge scope.
- (-) GL Renderer check requires EGL context setup/teardown (moderate complexity). Mitigated by encapsulating in a utility method.
- (-) Sensor noise sampling adds 2-3s latency. Mitigated by running concurrently with instant checks.

## References

- AOSP goldfish device tree: https://android.googlesource.com/device/generic/goldfish/
- AOSP goldfish sensor HAL: sensor_list.cpp (confirms "Goldfish" naming)
- OWASP MASTG-TEST-0049: Testing Emulator Detection
- OWASP MASTG-KNOW-0031: Emulator Detection
- Smartphone MEMS Accelerometer Measurement Errors (PMC10490716)
- DeepID SDK Emulator Detection Guide: https://deepidsdk.com/blog/emulator-detection-guide
- strazzere/anti-emulator (GitHub reference implementation)
- gingo/android-emulator-detector (scoring-based approach)
