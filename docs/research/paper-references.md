# Research References

All academic papers, OWASP standards, and key sources used in this project.

## Academic Papers

### Emulator Detection
- **"Proteus: Detecting Android Emulators from Instruction-Level Profiles"** — Sahin et al., RAID 2018
  https://link.springer.com/chapter/10.1007/978-3-030-00470-5_1
- **"Morpheus: Automatically Generating Heuristics to Detect Android Emulators"** — ACSAC 2014
  https://sefcom.asu.edu/publications/morpheus-acsac2014.pdf
- **"Rethinking Anti-Emulation Techniques"** — Computers & Security, Vol. 83, 2019 (QEMU race conditions, SIMD misalignment)
  https://www.sciencedirect.com/science/article/abs/pii/S0167404818310216
- **Smartphone MEMS Accelerometer Measurement Errors** — PMC10490716, 2023 (sensor noise thresholds: 0.004-0.011 m/s²)

### App Cloning / Virtual Containers
- **"Parallel Space Traveling: A Security Analysis of App-Level Virtualization in Android"** — Dai et al., ACM SACMAT 2020
  https://www.cs.ucr.edu/~heng/pubs/sacmat2020.pdf
- **"VAHunt: Warding Off New Repackaged Android Malware in App-Virtualization's Clothing"** — Shi et al., ACM CCS 2020
  https://dl.acm.org/doi/10.1145/3372297.3423341
- **"Mascara: A Novel Attack Leveraging Android Virtualization"** — Alecci et al., arXiv 2020. Proposes ArtMethod hotness_count as defense (Section IX-B)
  https://ar5iv.labs.arxiv.org/html/2010.10639 | DOI: 10.48550/arXiv.2010.10639
- **"Matrioska: A User-Centric Defense Against Virtualization-Based Repackaging Malware"** — Zerbini et al., IEEE ACSAC 2024
  DOI: 10.1109/ACSAC61953.2024.00037 | Source: https://github.com/samudoria/Matrioska
- **"MARVEL: Mobile-app Anti-Repackaging for Virtual Environments Locking"** — ACM ACSAC 2021
  https://dl.acm.org/doi/fullHtml/10.1145/3485832.3488021

### Repackaging / Integrity
- **"You Shall not Repackage! Demystifying Anti-Repackaging on Android"** — Merlo et al., Computers & Security, 2021. Analyzed 6 schemes, all bypassed.
  https://arxiv.org/abs/2009.04718
- **"ARMAND: Anti-Repackaging through Multi-pattern Anti-tampering based on Native Detection"** — Merlo et al., Pervasive & Mobile Computing, 2021. 92.2% success on 30K apps.
  https://arxiv.org/abs/2012.09292
- **"Android App Repackaging Detection: A Comprehensive Survey"** — ScienceDirect, Jan 2026
  https://www.sciencedirect.com/science/article/pii/S2772918426000019

### Hooking / Anti-Instrumentation
- **"ARAP: Demystifying Anti Runtime Analysis Code in Android Apps"** — Suo et al., IEEE TSE, 2024. 117K apps, 1515 anti-analysis features. 99.6% of benign apps use ARA.
  https://arxiv.org/abs/2408.11080
- **"Android's Cat-and-Mouse Game: Understanding Evasion Techniques"** — Li et al., IEEE ISSRE 2024. 108K benign + 11K malicious apps.
  https://diaowenrui.github.io/paper/issre24-li.pdf
- **"Unmasking the Veiled: A Comprehensive Analysis of Android Evasive Malware"** — Ruggia et al., ACM AsiaCCS 2024. Identified HOOK-PROC_ART-MAPS and HOOK-FRIDA-FILE patterns.
  https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf
- **Promon App Threat Report 2024** — Only 2% of top apps detect Frida
  https://promon.io/resources/downloads/app-threat-report-hooking-framework-frida-2024

## OWASP Standards

- **MASVS-RESILIENCE-2** — Anti-tampering: signature check, DEX integrity, resource integrity
  https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/
- **MASVS-RESILIENCE-4** — Anti-dynamic analysis: debugging detection, instrumentation detection
  https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/
- **MASWE-0098** — App Virtualization Environment Detection Not Implemented
  https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0098/
- **MASTG-TEST-0038** — App signing verification
  https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/
- **MASTG-TEST-0047** — File integrity checks
  https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/
- **MASTG-TEST-0048** — Reverse engineering tools detection
  https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/

## AOSP Source References

- **ArtMethod struct layout** — Verified stable offset 14 for hotness_count across Android 12-16
  https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h
- **Goldfish device tree** — Emulator sensor HAL, system properties, file artifacts
  https://android.googlesource.com/device/generic/goldfish/

## Open Source Detection Libraries

- **ConbeerLib** — Virtual container detection (Android Security Symposium 2020)
  https://github.com/su-vikas/conbeerlib
- **muellerberndt/frida-detection** — Frida detection via /proc/self/maps + D-Bus
  https://github.com/muellerberndt/frida-detection
- **darvincisec/DetectFrida** — Native Frida detection
  https://github.com/darvincisec/DetectFrida
- **DeepID SDK** — Emulator detection guide (sensor fingerprinting, cross-validation)
  https://deepidsdk.com/blog/emulator-detection-guide

## Bypass / Attacker Tools (used for testing)

- **strongR-frida** — Patched Frida with removed identifiable strings
  https://github.com/hzzheyang/strongR-frida-android
