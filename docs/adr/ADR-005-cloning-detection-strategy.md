# ADR-005: Cloning Detection Strategy

**Status:** Accepted
**Date:** 2026-04-27

## Context

The Incognia challenge requires detecting apps running inside "cloned" versions, including Dual Space, Parallel Space, VirtualApp, 2Face, and similar virtual container apps. These tools create a virtualized Android environment inside their own process, loading the target app as a "plugin" without system-level installation.

## Research Findings

We analyzed 7 academic papers (SACMAT 2020, CCS 2020, ICSE 2021, CCS 2021, ACSAC 2024, CODASPY 2024), 3 open-source detection libraries (ConbeerLib, AppCloneDetector, AntiVirtualApp), and the VirtualApp source code itself.

### Key findings:

1. **All Java-level checks can be bypassed** by sophisticated attackers (Mascara attack, arXiv 2010.10639). But mainstream consumer cloners (Parallel Space, Dual Space) do NOT implement these bypasses as of 2025.

2. **ArtMethod `hotness_count` inspection** is the only technique that has NOT been bypassed (Matrioska, ACSAC 2024, IEEE 10917506). It operates below the API hooking layer used by virtual containers.

3. **The ArtMethod struct layout is stable** across Android 12–16 (API 31–36). The `hotness_count_` field is at offset 14 bytes in all versions. Google enforces this via `ValidateFieldOrderOfJavaCppUnionClasses` test.

4. **VirtualApp hooks 30+ libc functions** (IOUniformer.cpp) including open, stat, access, and sets identifiable environment variables (V_REPLACE_ITEM, V_SO_PATH, LD_PRELOAD).

5. **`/proc/self/maps` is always readable** by the process itself (Linux kernel guarantee, not restricted by SELinux hidepid). This is ConbeerLib's primary detection method.

6. **UID/UserHandle checks have HIGH false positive risk** — Android Work Profiles (userId 10+), Xiaomi Dual Apps (userId 999), Samsung Secure Folder all use secondary user profiles legitimately. Excluded from implementation.

## Decision

Implement **7 check groups** split into hard and soft signals:

### Hard signals (any one = definitive virtual container)

| Check | Source | Why it's definitive |
|-------|--------|-------------------|
| Data directory path contains foreign package | ConbeerLib, SACMAT 2020 | No legitimate scenario puts your data inside another app's directory |
| APK source path not under /data/app/ | ConbeerLib, SACMAT 2020 | System-installed APKs are always in /data/app/ |
| /proc/self/maps contains foreign package paths | ConbeerLib (primary method) | Memory maps show where code was actually loaded from |
| ArtMethod hotness_count == 0 for ActivityThread.currentActivityThread | Mascara (arXiv 2010.10639), Matrioska (ACSAC 2024) | Virtual containers use DexClassLoader which produces AOT-only methods with hotness_count=0 |

### Soft signals (contribute to weighted scoring)

| Check | Source | Why it's soft |
|-------|--------|-------------|
| VirtualApp environment variables present | VirtualApp source (IOUniformer.cpp) | Could theoretically appear in other contexts |
| Stack trace contains cloner class prefixes | ConbeerLib (8 patterns) | Fragile — cloners can rename classes |
| Known cloner packages installed | Industry practice | Easily evaded, Android 11+ limits queries |

### ArtMethod implementation approach

- Implemented in native C via JNI (~30 lines)
- Reads `uint16_t` at offset 14 from the ArtMethod pointer obtained via `FromReflectedMethod()`
- Guarded by API level check (only runs on API 31–36 where layout is confirmed)
- Returns "inconclusive" (not "clean") on unsupported API levels — positive-only signal
- Wrapped in SafeExec to never crash on unexpected struct layouts

### What we explicitly chose NOT to implement

- **UID/UserHandle checks**: High false positive on work profiles, Xiaomi dual apps (SACMAT 2020)
- **Permission mismatch**: Bypassed by Mascara (copies all permissions)
- **Broadcast receiver delivery test**: Requires manifest changes and 1-second sleep (ConbeerLib)
- **Running services check**: `getRunningServices()` deprecated since API 26

## Trade-offs

- (+) 7 checks across 3 layers: filesystem, runtime, and ART internals
- (+) ArtMethod check is state-of-the-art (ACSAC 2024) — demonstrates research awareness
- (+) Hard signals have near-zero false positive rates
- (+) Positive-only ArtMethod: if it detects = definitive, if it doesn't = no opinion
- (-) ArtMethod requires NDK/JNI (small native file). Justified by being the only undefeated technique.
- (-) ArtMethod offset could theoretically change in future Android versions. Mitigated by API level guard and graceful degradation.
- (-) Java-level checks are hookable. Accepted — they catch mainstream consumer cloners.

## References

- Dai et al., "Parallel Space Traveling," ACM SACMAT 2020 — https://www.cs.ucr.edu/~heng/pubs/sacmat2020.pdf
- Shi et al., "VAHunt," ACM CCS 2020 — https://dl.acm.org/doi/10.1145/3372297.3423341
- Alecci et al., "Mascara," arXiv 2010.10639 — https://arxiv.org/abs/2010.10639
- Zerbini et al., "Matrioska," IEEE ACSAC 2024 — https://ieeexplore.ieee.org/document/10917506/
- Song et al., "VPDroid," ICSE 2021 — https://arxiv.org/abs/2103.03511
- ConbeerLib — https://github.com/su-vikas/conbeerlib
- AntiVirtualApp — https://github.com/nicehash/AntiVirtualApp
- OWASP MASWE-0098 — https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0098/
- ArtMethod struct (AOSP main) — https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h
