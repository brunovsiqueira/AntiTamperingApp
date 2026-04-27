# ADR-005: Cloning Detection Strategy

**Status:** Accepted
**Date:** 2026-04-27

## Context

Detect when the app runs inside a virtual container (Parallel Space, Dual Space, VirtualApp, etc.). These tools load the app as a plugin inside their own process, faking the Android framework around it.

## Decision — 7 checks across 4 layers

### Layer 1: Filesystem — "Where are my files?"

**Check 1 — Data directory path** (Hard signal)
- `context.filesDir.absolutePath` should be `/data/user/0/<my_package>/files`
- Inside a container it becomes `/data/data/<container_package>/virtual/.../files`
- If the path contains another app's package name or `/virtual/`, it's definitive.
- Source: ConbeerLib (Android Security Symposium 2020), "Parallel Space Traveling" (SACMAT 2020)

**Check 2 — APK source path** (Hard signal)
- `applicationInfo.sourceDir` should start with `/data/app/` (system-managed installation)
- Containers load APKs from `/data/data/<container>/...` — that never happens legitimately.
- Source: ConbeerLib, SACMAT 2020

### Layer 2: Memory — "Where was my code loaded from?"

**Check 3 — /proc/self/maps** (Hard signal)
- The process's own memory map lists every loaded .so and .apk with full paths.
- If any path under `/data/data/` or `/data/app/` belongs to a different package, code was loaded from another app's directory.
- Always readable (Linux kernel guarantee for own process), not blocked by SELinux.
- Source: ConbeerLib (primary detection method)

### Layer 3: Runtime — "Who launched me?"

**Check 4 — Environment variables** (Soft signal)
- VirtualApp's IOUniformer.cpp sets env vars like `V_REPLACE_ITEM`, `V_SO_PATH`, `LD_PRELOAD` to manage filesystem redirection inside the container.
- These variables don't exist in normal Android execution.
- Source: VirtualApp source code (IOUniformer.cpp)

**Check 5 — Stack trace** (Soft signal)
- `Throwable().stackTrace` reveals the call chain. If cloner classes like `com.lody.virtual` or `com.doubleagent` appear, a container framework launched the app.
- Fragile (cloners can rename classes), but low cost.
- Source: ConbeerLib (8 class prefix patterns)

**Check 6 — Known cloner packages** (Soft signal)
- Query PackageManager for 17 known cloner package names.
- Weakest signal: proves a cloner is *installed*, not that we're *inside* it. Easily evaded. Android 11+ limits package visibility.
- Included for breadth, not reliability.

### Layer 4: ART internals — "How was my code compiled?"

**Check 7 — ArtMethod hotness_count** (Hard signal, positive-only)
- The ART runtime tracks how often each method runs via `hotness_count` in the ArtMethod C++ struct.
- `ActivityThread.currentActivityThread()` is called constantly by the framework → hotness_count > 0 in normal execution.
- Virtual containers load via DexClassLoader → AOT-only compilation → hotness_count == 0.
- We read this via JNI at offset 14 (verified stable across Android 12–16 in AOSP source, enforced by `ValidateFieldOrderOfJavaCppUnionClasses` test).
- **Only technique never bypassed in academic literature.** Mascara (arXiv 2010.10639) proved all other defenses bypassable; Matrioska (ACSAC 2024) achieved 99% accuracy with this technique.
- Positive-only: if hotness_count == 0 → definitive. If > 0 → inconclusive (not proof of safety).
- Guarded by API level check. Returns "inconclusive" on unsupported versions. Never crashes.

## What we chose NOT to implement (and why)

| Technique | Why excluded |
|-----------|-------------|
| UID/UserHandle checks | False positives on Work Profiles (userId 10+), Xiaomi Dual Apps (userId 999), Samsung Secure Folder |
| Permission mismatch | Mascara attack bypasses by copying all permissions |
| Broadcast delivery test | Requires manifest changes + 1-second sleep |
| `getRunningServices()` | Deprecated since API 26 |

## Scoring

Same two-tier model as EmulatorDetector:
- **Hard signal fires** (checks 1, 2, 3, 7) → confidence = 1.0
- **Only soft signals fire** (checks 4, 5, 6) → weighted scoring with 0.35 threshold

## References

- "Parallel Space Traveling" — Dai et al., ACM SACMAT 2020 (https://www.cs.ucr.edu/~heng/pubs/sacmat2020.pdf)
- "VAHunt" — Shi et al., ACM CCS 2020 (https://dl.acm.org/doi/10.1145/3372297.3423341)
- "Mascara" — Alecci et al., arXiv 2010.10639 (https://arxiv.org/abs/2010.10639)
- "Matrioska" — Zerbini et al., IEEE ACSAC 2024 (https://ieeexplore.ieee.org/document/10917506/)
- ConbeerLib — https://github.com/su-vikas/conbeerlib
- OWASP MASWE-0098 — https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0098/
- ArtMethod struct — https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h
