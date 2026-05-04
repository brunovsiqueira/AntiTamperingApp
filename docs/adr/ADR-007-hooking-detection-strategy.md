# ADR-007: Hooking Detection Strategy

**Status:** Accepted
**Date:** 2026-05-04

## Context

Hooking frameworks (Frida, Xposed, Magisk) allow attackers to intercept and modify app behavior at runtime. This undermines all other detectors — an attacker can hook PackageManager to bypass signature checks, hook Context to fake file paths, etc. Detecting the hooking tool itself is the meta-defense.

## Research Findings

### Academic papers

**ARAP (IEEE TSE 2024, arXiv 2408.11080):** Largest study — 117K apps, 1,515 anti-analysis features across 5 categories. 99.6% of benign apps use at least one anti-runtime analysis technique. However, Promon (2024) found only 2% of top apps actually detect Frida.

**"Android's Cat-and-Mouse Game" (IEEE ISSRE 2024):** 108K benign + 11K malicious apps. 68.1% of Play Store apps use evasion techniques. Anti-hooking methods: stack traces for Xposed, running processes for Frida server, TCP port 27042, /proc/self/maps for hook libraries.

**"Unmasking the Veiled" (ACM AsiaCCS 2024):** Identified specific patterns: `HOOK-PROC_ART-MAPS` (scan maps for frida-agent) and `HOOK-FRIDA-FILE`. 26.2% of malware inspects /proc/self/maps for hooking tools.

### OWASP standards

**MASVS-RESILIENCE-4:** "The app implements anti-dynamic analysis mechanisms" — debugging detection, dynamic instrumentation detection, method hooking detection.
- https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/

**MASTG-TEST-0048:** Testing detection of reverse engineering tools.
- https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/

### Key insight from the arms race

Every detection can be bypassed. `strongR-frida` renames libraries and patches thread names. The goal is raising cost, not being unbeatable. Multiple orthogonal checks force an attacker to bypass ALL simultaneously.

## Decision — 5 checks

### Hard signals

**Check 1 — /proc/self/maps for hooking libraries** (Hard signal)
- Scan process memory map for `frida`, `xposed`, `substrate`, `gadget`, `lspd` strings.
- Different from CloningDetector's /proc/self/maps check (which looks for foreign package paths, not hooking tool names).
- Source: ARAP (AsiaCCS 2024 HOOK-PROC_ART-MAPS pattern), muellerberndt/frida-detection, OWASP MASTG-TEST-0048

**Check 2 — rwxp memory segments** (Hard signal)
- Scan /proc/self/maps for read+write+execute memory regions not belonging to ART's JIT cache.
- Frida's JS engine (GumJS/V8) fundamentally needs rwxp pages. This is the hardest check to evade.
- Must whitelist `[anon:dalvik-jit-code-cache]` (ART's own JIT).
- Source: ARAP, practical security research

### Soft signals

**Check 3 — Frida port scan** (Soft signal)
- Connect to localhost ports 27042/27043 with D-Bus AUTH handshake.
- Easy to evade (non-default port, frida-gadget uses no port).
- Source: OWASP MASTG-TEST-0048, muellerberndt/frida-detection

**Check 4 — Xposed class detection** (Soft signal)
- `Class.forName("de.robv.android.xposed.XposedBridge")` — if it loads, Xposed is active.
- LSPosed can hook Class.forName itself, but that creates a recursive detection opportunity.
- Source: ISSRE 2024, Jabb0/XposedDetector

**Check 5 — Active debugger detection** (Soft signal)
- `Debug.isDebuggerConnected()` — JDWP debugger attached right now.
- `/proc/self/status` TracerPid != 0 — ptrace debugger attached.
- Different from IntegrityDetector's FLAG_DEBUGGABLE (build-time flag vs runtime state).
- Source: ARAP (Anti-Debugging category), OWASP MASTG-TEST-0046

## What we chose NOT to implement

| Technique | Why excluded |
|-----------|-------------|
| Native direct syscalls for /proc reading | Would strengthen detection but adds significant NDK complexity. Our existing native code (ArtMethod) is already architecture-specific. Acceptable for challenge scope to use Java file reading. |
| Frida thread name enumeration (gmain, gum-js-loop) | Moderate false positive risk (gmain is a GLib thread name). Covered indirectly by /proc/self/maps. |
| Root/Magisk detection (su binary, mount namespace) | Complementary signal but not directly about hooking. Root enables hooking but doesn't prove it's happening. Out of scope for this detector. |
| Named pipe detection (/proc/self/fd) | Covered by /proc/self/maps check. Marginal additional value. |

## Scoring

Same two-tier model:
- **Hard signal fires** (hooking libraries in maps, rwxp segments) → confidence = 1.0
- **Only soft signals** (Frida port, Xposed class, debugger) → weighted scoring

## References

- ARAP (arXiv 2408.11080): https://arxiv.org/abs/2408.11080
- Cat-and-Mouse (ISSRE 2024): https://diaowenrui.github.io/paper/issre24-li.pdf
- Unmasking the Veiled (AsiaCCS 2024): https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf
- OWASP MASVS-RESILIENCE-4: https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/
- OWASP MASTG-TEST-0048: https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/
- muellerberndt/frida-detection: https://github.com/muellerberndt/frida-detection
- darvincisec/DetectFrida: https://github.com/darvincisec/DetectFrida
- Promon 2024 report (2% detect Frida): https://promon.io/resources/downloads/app-threat-report-hooking-framework-frida-2024
- strongR-frida (evasion tool): https://github.com/hzzheyang/strongR-frida-android
