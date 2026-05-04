package com.bruno.antitamperingapp.detection.detectors

import android.content.Context
import android.os.Debug
import com.bruno.antitamperingapp.detection.DetectionCategory
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.Evidence
import com.bruno.antitamperingapp.detection.TamperDetector
import com.bruno.antitamperingapp.detection.error.DetectionError
import com.bruno.antitamperingapp.detection.util.SafeExec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Detects runtime hooking and instrumentation frameworks (Frida, Xposed, etc.).
 *
 * This is the "meta-defense" — if an attacker uses Frida to bypass other detectors,
 * this detector catches the tool itself.
 *
 * 5 checks:
 * - /proc/self/maps for hooking library names
 * - rwxp memory segments (JIT/instrumentation indicator)
 * - Frida default port scan
 * - Xposed class detection
 * - Active debugger detection
 *
 * See ADR-007 for research, trade-offs, and references.
 */
class HookingDetector : TamperDetector {

    override val name: String = "HookingDetector"
    override val category: DetectionCategory = DetectionCategory.HOOKING
    override val weight: Float = 1.0f

    override suspend fun detect(context: Context): DetectionResult {
        val errors = mutableListOf<DetectionError>()
        val evidence = mutableListOf<Evidence>()

        checkProcMapsForHookingLibs(evidence, errors)
        checkRwxpSegments(evidence, errors)
        checkFridaPorts(evidence, errors)
        checkXposedClasses(evidence, errors)
        checkDebuggerAttached(evidence, errors)

        return buildResult(evidence, errors)
    }

    // ──────────────────────────────────────────────
    // Check 1: /proc/self/maps for hooking libraries
    // Hard signal
    //
    // Source: ARAP (arXiv 2408.11080), AsiaCCS 2024
    //         (HOOK-PROC_ART-MAPS pattern),
    //         muellerberndt/frida-detection,
    //         OWASP MASTG-TEST-0048
    //
    // Different from CloningDetector's maps check:
    // - CloningDetector looks for foreign package paths
    // - This looks for instrumentation tool library names
    // ──────────────────────────────────────────────

    private fun checkProcMapsForHookingLibs(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_HOOK_LIBS, name, errors) {
            val foundLibs = mutableListOf<String>()

            try {
                BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        val lower = line.lowercase()
                        for (pattern in HOOKING_LIB_PATTERNS) {
                            if (lower.contains(pattern)) {
                                foundLibs.add(line.substringAfterLast(" ").trim())
                                break
                            }
                        }
                        line = reader.readLine()
                    }
                }
            } catch (e: Exception) {
                errors.add(
                    DetectionError.FileAccessFailed(
                        detectorName = name,
                        path = "/proc/self/maps",
                        cause = e,
                    )
                )
            }

            val suspicious = foundLibs.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_HOOK_LIBS,
                    description = if (suspicious) {
                        "Found ${foundLibs.size} hooking library(ies) in process memory"
                    } else {
                        "No hooking libraries detected in /proc/self/maps"
                    },
                    rawValue = if (suspicious) {
                        foundLibs.distinct().take(5).joinToString("\n")
                    } else {
                        "(clean)"
                    },
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 2: rwxp memory segments
    // Hard signal
    //
    // Source: ARAP (arXiv 2408.11080), practical research
    //
    // Frida's JS engine (GumJS/V8) needs read+write+execute
    // pages for JIT compilation. Normal apps should only have
    // ART's own JIT cache with rwxp.
    // ──────────────────────────────────────────────

    private fun checkRwxpSegments(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_RWXP, name, errors) {
            val suspiciousSegments = mutableListOf<String>()

            try {
                BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        // rwxp = read+write+execute+private — suspicious for JIT injection
                        if (line.contains("rwxp")) {
                            // Whitelist ART's own JIT code cache — this is legitimate
                            // Source: ART runtime creates these for compiled code
                            if (!line.contains("dalvik-jit-code-cache") &&
                                !line.contains("dalvik-zygote-jit-code-cache")
                            ) {
                                suspiciousSegments.add(line.trim())
                            }
                        }
                        line = reader.readLine()
                    }
                }
            } catch (e: Exception) {
                errors.add(
                    DetectionError.FileAccessFailed(
                        detectorName = name,
                        path = "/proc/self/maps",
                        cause = e,
                    )
                )
            }

            val suspicious = suspiciousSegments.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_RWXP,
                    description = if (suspicious) {
                        "Found ${suspiciousSegments.size} suspicious rwxp memory segment(s) — " +
                            "possible JIT-based instrumentation (Frida GumJS/V8)"
                    } else {
                        "No suspicious rwxp segments (only ART JIT cache, which is normal)"
                    },
                    rawValue = if (suspicious) {
                        suspiciousSegments.take(3).joinToString("\n")
                    } else {
                        "(clean)"
                    },
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 3: Frida default port scan
    // Soft signal
    //
    // Source: OWASP MASTG-TEST-0048,
    //         muellerberndt/frida-detection
    //
    // frida-server defaults to port 27042.
    // Easy to evade (non-default port, frida-gadget
    // uses no port). But catches default setups.
    // ──────────────────────────────────────────────

    private suspend fun checkFridaPorts(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        withContext(Dispatchers.IO) {
            SafeExec.runCatching(CHECK_FRIDA_PORT, name, errors) {
                val openPorts = mutableListOf<Int>()

                for (port in FRIDA_PORTS) {
                    try {
                        Socket().use { socket ->
                            socket.connect(InetSocketAddress("127.0.0.1", port), 200)
                            openPorts.add(port)
                        }
                    } catch (_: Exception) {
                        // Port not open — expected
                    }
                }

                val suspicious = openPorts.isNotEmpty()
                evidence.add(
                    Evidence(
                        checkName = CHECK_FRIDA_PORT,
                        description = if (suspicious) {
                            "Frida default port(s) open: $openPorts"
                        } else {
                            "Frida default ports (27042, 27043) not open"
                        },
                        rawValue = if (suspicious) openPorts.joinToString(", ") else "(closed)",
                        suspicious = suspicious,
                    )
                )
            }
        }
    }

    // ──────────────────────────────────────────────
    // Check 4: Xposed class detection
    // Soft signal
    //
    // Source: ISSRE 2024 (Cat-and-Mouse),
    //         Jabb0/XposedDetector
    //
    // Xposed loads XposedBridge.jar into every process.
    // If the class loads, Xposed is active.
    // LSPosed can hook Class.forName itself — but that
    // creates a recursive detection opportunity.
    // ──────────────────────────────────────────────

    private fun checkXposedClasses(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_XPOSED, name, errors) {
            val foundClasses = mutableListOf<String>()

            for (className in XPOSED_CLASSES) {
                try {
                    Class.forName(className)
                    foundClasses.add(className)
                } catch (_: ClassNotFoundException) {
                    // Expected — class not present
                }
            }

            val suspicious = foundClasses.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_XPOSED,
                    description = if (suspicious) {
                        "Xposed framework classes loaded: ${foundClasses.joinToString(", ")}"
                    } else {
                        "No Xposed framework classes detected"
                    },
                    rawValue = if (suspicious) foundClasses.joinToString(", ") else "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 5: Active debugger detection
    // Soft signal
    //
    // Source: ARAP (Anti-Debugging category),
    //         OWASP MASTG-TEST-0046
    //
    // Different from IntegrityDetector's FLAG_DEBUGGABLE:
    // - FLAG_DEBUGGABLE = build-time flag ("was built as debuggable")
    // - isDebuggerConnected = runtime state ("is JDWP debugger attached NOW")
    // - TracerPid = runtime state ("is ptrace debugger attached NOW")
    // ──────────────────────────────────────────────

    private fun checkDebuggerAttached(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_DEBUGGER, name, errors) {
            // JDWP debugger (Android Studio, jdb)
            val jdwpAttached = Debug.isDebuggerConnected()

            // ptrace-based debugger (gdb, lldb, strace)
            // TracerPid != 0 means something is tracing us
            // Source: /proc/self/status, OWASP MASTG-TEST-0046
            val tracerPid = readTracerPid()

            val suspicious = jdwpAttached || tracerPid > 0

            evidence.add(
                Evidence(
                    checkName = CHECK_DEBUGGER,
                    description = when {
                        jdwpAttached && tracerPid > 0 ->
                            "Both JDWP debugger and ptrace tracer (PID=$tracerPid) attached"
                        jdwpAttached ->
                            "JDWP debugger attached (Android Studio or similar)"
                        tracerPid > 0 ->
                            "Process is being traced (TracerPid=$tracerPid) — possible debugger or Frida"
                        else ->
                            "No debugger or tracer attached"
                    },
                    rawValue = "jdwp=$jdwpAttached tracerPid=$tracerPid",
                    suspicious = suspicious,
                )
            )
        }
    }

    private fun readTracerPid(): Int {
        return try {
            val status = File("/proc/self/status").readText()
            val match = Regex("TracerPid:\\s+(\\d+)").find(status)
            match?.groupValues?.get(1)?.toIntOrNull() ?: 0
        } catch (_: Exception) {
            0
        }
    }

    // ──────────────────────────────────────────────
    // Result Building
    // ──────────────────────────────────────────────

    private fun buildResult(
        evidence: List<Evidence>,
        errors: List<DetectionError>,
    ): DetectionResult {
        val confidence = computeConfidence(evidence)
        return DetectionResult(
            detected = confidence >= DETECTION_THRESHOLD,
            confidence = confidence,
            evidence = evidence,
            errors = errors,
        )
    }

    private fun computeConfidence(evidence: List<Evidence>): Float {
        val hardSignalFired = evidence.any { ev ->
            ev.suspicious && ev.checkName in HARD_SIGNAL_CHECKS
        }
        if (hardSignalFired) return 1.0f

        var triggeredWeight = 0f
        val totalWeight = SOFT_CHECK_WEIGHTS.values.sum()
        if (totalWeight == 0f) return 0f

        for ((checkName, weight) in SOFT_CHECK_WEIGHTS) {
            val checkEvidence = evidence.filter { it.checkName == checkName }
            if (checkEvidence.any { it.suspicious }) {
                triggeredWeight += weight
            }
        }

        return (triggeredWeight / totalWeight).coerceIn(0f, 1f)
    }

    companion object {
        private const val DETECTION_THRESHOLD = 0.35f

        // Check name constants
        private const val CHECK_HOOK_LIBS = "hook_libraries"
        private const val CHECK_RWXP = "hook_rwxp_segments"
        private const val CHECK_FRIDA_PORT = "hook_frida_port"
        private const val CHECK_XPOSED = "hook_xposed_classes"
        private const val CHECK_DEBUGGER = "hook_debugger"

        // Hard signals
        private val HARD_SIGNAL_CHECKS = setOf(
            CHECK_HOOK_LIBS,    // Hooking library in process memory
            CHECK_RWXP,         // Suspicious rwxp segments (JIT injection)
        )

        // Soft signal weights
        private val SOFT_CHECK_WEIGHTS = mapOf(
            CHECK_FRIDA_PORT to 0.7f,
            CHECK_XPOSED to 0.8f,
            CHECK_DEBUGGER to 0.6f,
        )

        // Frida default ports
        // Source: Frida docs, muellerberndt/frida-detection
        private val FRIDA_PORTS = listOf(27042, 27043)

        // Patterns to detect in /proc/self/maps
        // Source: ARAP (HOOK-PROC_ART-MAPS), darvincisec/DetectFrida,
        //         muellerberndt/frida-detection, OWASP MASTG-TEST-0048
        private val HOOKING_LIB_PATTERNS = listOf(
            "frida",            // Frida agent/gadget/server
            "gadget",           // frida-gadget (may be renamed but often keeps "gadget")
            "xposed",           // Xposed framework libraries
            "substrate",        // Cydia Substrate
            "lspd",             // LSPosed daemon
            "edxposed",         // EdXposed
            "libgadget",        // Common frida-gadget naming
        )

        // Xposed classes to check via Class.forName
        // Source: ISSRE 2024, Jabb0/XposedDetector
        private val XPOSED_CLASSES = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "de.robv.android.xposed.XC_MethodHook",
        )
    }
}
