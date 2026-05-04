# ADR-006: Integrity Detection Strategy

**Status:** Accepted
**Date:** 2026-05-04

## Context

The Incognia challenge mentions "repackaged builds" as a threat. Repackaging = decompile APK (apktool), modify code/resources, re-sign with attacker's key, redistribute. Client-side integrity detection lets the app verify at runtime that it hasn't been tampered with, without needing a server call.

## Research Findings

### Academic papers

**"You Shall not Repackage!" (Merlo et al., Computers & Security, 2021)** analyzed 6 anti-repackaging schemes (Dex Encryption, SSN, AppIS, SDC, BombDroid, NRP). All were bypassed via code deletion, binary patching, or Frida instrumentation. Key takeaway: no single client-side check is sufficient, but layered checks raise the cost significantly.
- https://arxiv.org/abs/2009.04718

**"ARMAND" (Merlo et al., Pervasive & Mobile Computing, 2021)** proposed multi-pattern detection across Java and native code with 6 bomb types. 92.2% success on 30K apps. Too complex for our scope but validates the multi-layer approach.
- https://arxiv.org/abs/2012.09292

### OWASP standards

**MASVS-RESILIENCE-2:** "The app implements anti-tampering mechanisms" — requires checking application package signature, DEX and native code integrity, and resource integrity.
- https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/

**MASTG-TEST-0038:** App signing verification.
- https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/

**MASTG-TEST-0047:** File integrity checks (classes.dex CRC, APK hash).
- https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/

## Decision — 4 checks

### Hard signals

**Check 1 — Signing certificate SHA-256** (Hard signal)
- At runtime, ask `PackageManager` for the app's signing certificate, compute SHA-256, compare against hardcoded expected hash.
- A repackaged app MUST be re-signed with the attacker's key (they don't have ours). The hash will differ. Cryptographically impossible to forge.
- Only bypass: hook `PackageManager.getPackageInfo()` via Frida (requires root).
- Google Play App Signing note: must use the app signing key hash (from Play Console), not the upload key.
- For our challenge: use the debug signing key's SHA-256.
- Source: OWASP MASTG-TEST-0038, MASVS-RESILIENCE-2

**Check 2 — Debug flag** (Hard signal)
- `ApplicationInfo.FLAG_DEBUGGABLE` is never set in release builds.
- Repackaged apps commonly have `debuggable=true` (attacker enables it for analysis).
- Binary and deterministic — zero false positives on release builds.
- For our challenge: we run debug builds, so this flag WILL be set. We'll detect but report it as informational, not suspicious in debug mode.
- Source: OWASP MASTG-TEST-0039, MASWE-0067

### Soft signals

**Check 3 — Installer source** (Soft signal)
- `PackageManager.getInstallSourceInfo()` — was the app installed from Play Store (`com.android.vending`) or sideloaded (null)?
- HIGH false positive risk for enterprise/MDM deployments (installer = MDM agent package, not Play Store).
- Easily spoofed on rooted devices (`pm install -i com.android.vending`).
- Supplementary signal only, never a hard gate.
- Source: OWASP MASTG-TEST-0047

**Check 4 — DEX file CRC** (Soft signal)
- Read `classes.dex` CRC from the APK ZIP at runtime, compare against expected value stored in resources.
- Catches code modification but has caveats: two-pass build needed, attacker can update stored CRC, breaks with AAB/Play App Signing (Google modifies DEX during processing).
- For our challenge (debug APK): works fine. For production: needs careful build pipeline work.
- Source: OWASP MASTG-TEST-0047, Nomtek blog (https://www.nomtek.com/blog/enhanced-android-security)

## What we chose NOT to implement

| Technique | Why excluded |
|-----------|-------------|
| Full APK hash | Chicken-and-egg problem worse than DEX CRC. Breaks with AAB. |
| Native .so HMAC | Requires complex build pipeline + per-ABI computation. Out of scope. |
| Logic bombs (ARMAND) | Build-time code transformation pipeline. Too complex for challenge. |
| Dex encryption | Hardcoded keys found via Frida (bypassed in "You Shall not Repackage"). |

## Scoring

Same two-tier model:
- **Hard signal fires** (signature mismatch, debug flag on release build) → confidence = 1.0
- **Only soft signals fire** (installer, DEX CRC) → weighted scoring

## References

- "You Shall not Repackage!" — Merlo et al., 2021: https://arxiv.org/abs/2009.04718
- "ARMAND" — Merlo et al., 2021: https://arxiv.org/abs/2012.09292
- OWASP MASVS-RESILIENCE-2: https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/
- OWASP MASTG-TEST-0038: https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/
- OWASP MASTG-TEST-0047: https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/
- DEX CRC integrity check (Sindee.Dev): https://medium.com/@sindee.dev/code-integrity-checking-in-android-part-1-check-checksum-of-dex-file-9b2c200075bd
- Enhanced Android Security (Nomtek): https://www.nomtek.com/blog/enhanced-android-security
- App signing (Android Developers): https://developer.android.com/studio/publish/app-signing
- MARVEL anti-repackaging via virtualization: https://dl.acm.org/doi/fullHtml/10.1145/3485832.3488021
- Android App Repackaging Detection survey (2026): https://www.sciencedirect.com/science/article/pii/S2772918426000019
- Runtime code integrity checks guide (2025): https://www.shahidraza.me/2025/08/09/method_hooking_root_android.html
