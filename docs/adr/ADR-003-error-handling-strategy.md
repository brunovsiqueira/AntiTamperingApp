# ADR-003: Unified Error Handling — Fail-Open with Observability

**Status:** Accepted
**Date:** 2026-04-26

## Context

Detection checks interact with the OS at many levels: file system reads, package manager queries, system property access, process inspection. Any of these can fail due to permissions, API level restrictions, SELinux policies, OEM customizations, or unexpected runtime conditions.

A crashing detection SDK is worse than no detection at all — it degrades the app experience and reveals to attackers that detection is present.

## Decision

### Fail-open, never crash

- The detection engine **never** propagates exceptions to the caller.
- Each individual check is wrapped by `SafeExec.runCatching()`, which catches all exceptions, logs them, and appends a structured error to the result.
- A detector that encounters errors still returns a `DetectionResult` with reduced confidence — it reports what it *could* determine.
- The engine wraps each detector's `detect()` call in a top-level try-catch as a final safety net.

### Unified error model

All errors are represented by `DetectionError` (sealed class) with subtypes:
- `FileAccessFailed` — cannot read a file/path
- `PermissionDenied` — missing runtime permission
- `ApiUnavailable` — API requires higher SDK version
- `Timeout` — detector exceeded time budget
- `Unexpected` — catch-all for unanticipated exceptions

Each error carries: `code` (machine-readable), `message` (human-readable), `detectorName` (attribution).

### SafeExec utility

`SafeExec.runCatching()` provides a consistent wrapper:
```kotlin
val result = SafeExec.runCatching("check_name", "DetectorName", errors) {
    // risky OS call
}
// result is null if it failed; error is already logged and appended
```

`SafeExec.withTimeout()` adds a coroutine timeout for long-running checks.

### Logging

All errors are logged via `DetectionLogger` with the `TamperDetection` tag, enabling unified filtering: `adb logcat -s TamperDetection`.

## Alternatives Considered

- **Fail-closed (crash on error):** Unacceptable for a library/SDK. A crash reveals detection presence and degrades UX.
- **Result<T> everywhere:** Idiomatic Kotlin, but the nested Result wrapping becomes verbose for 10+ checks per detector. `SafeExec` is more ergonomic.
- **Ignore errors silently:** Dangerous. An error may indicate that a critical check was bypassed. Errors must be observable.

## Trade-offs

- (+) The SDK never crashes the host app.
- (+) Every error is structured, logged, and included in the verdict for observability.
- (+) Consistent pattern across all detectors — reduces cognitive load.
- (-) Fail-open means a detector that fails all checks reports clean (0 confidence). An attacker could theoretically exploit this by causing errors. Mitigation: if a detector encounters *too many* errors, it should flag as suspicious, not clean.
- (-) Logging to logcat is observable by attackers with `adb`. In production, errors should go to a server. Acceptable for this challenge.
