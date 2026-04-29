package com.bruno.antitamperingapp.detection.detectors

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.bruno.antitamperingapp.detection.DetectionCategory
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.Evidence
import com.bruno.antitamperingapp.detection.TamperDetector
import com.bruno.antitamperingapp.detection.error.DetectionError
import com.bruno.antitamperingapp.detection.util.SafeExec
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * Detects whether the app is running inside a virtual container / cloning app
 * (e.g., Parallel Space, Dual Space, VirtualApp, 2Face).
 *
 * Uses 7 check groups across 3 layers:
 * - **Filesystem layer**: Data directory path, APK source path
 * - **Runtime layer**: /proc/self/maps, environment variables, stack traces, installed packages
 * - **ART internals layer**: ArtMethod hotness_count (state-of-the-art, ACSAC 2024)
 *
 * See ADR-005 for full research, trade-offs, and references.
 */
class CloningDetector : TamperDetector {

    override val name: String = "CloningDetector"
    override val category: DetectionCategory = DetectionCategory.CLONING
    override val weight: Float = 1.0f

    private val artMethodChecker = ArtMethodChecker()

    override suspend fun detect(context: Context): DetectionResult {
        val errors = mutableListOf<DetectionError>()
        val evidence = mutableListOf<Evidence>()

        checkDataDirectoryPath(context, evidence, errors)
        checkApkSourcePath(context, evidence, errors)
        checkProcSelfMaps(context, evidence, errors)
        checkEnvironmentVariables(evidence, errors)
        checkStackTrace(evidence, errors)
        checkKnownClonerPackages(context, evidence, errors)
        checkArtMethodHotness(evidence, errors)

        return buildResult(evidence, errors)
    }

    // ──────────────────────────────────────────────
    // Check 1: Data Directory Path Analysis
    // Hard signal — foreign package in path = definitive
    //
    // Source: ConbeerLib (Android Security Symposium 2020),
    //         "Parallel Space Traveling" (SACMAT 2020)
    // ──────────────────────────────────────────────

    private fun checkDataDirectoryPath(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_DATA_DIR, name, errors) {
            val filesPath = context.filesDir.absolutePath
            val packageName = context.packageName

            // Check for known virtual container path segments
            // Source: ConbeerLib storage dir check, VirtualApp VEnvironment.java
            val containsVirtualSegment = VIRTUAL_PATH_SEGMENTS.any {
                filesPath.contains(it, ignoreCase = true)
            }

            // Check if the path contains a foreign package name as parent directory
            // Normal: /data/user/0/com.bruno.antitamperingapp/files
            // Cloned: /data/data/com.lbe.parallel.intl/parallel_intl/0/com.bruno.antitamperingapp/files
            val containsForeignPackage = filesPath.contains("/data/data/") &&
                !filesPath.startsWith("/data/data/$packageName")

            val suspicious = containsVirtualSegment || containsForeignPackage

            evidence.add(
                Evidence(
                    checkName = CHECK_DATA_DIR,
                    description = if (suspicious) {
                        "Data directory path indicates virtual container: '$filesPath'"
                    } else {
                        "Data directory path appears normal"
                    },
                    rawValue = filesPath,
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 2: APK Source Path Anomaly
    // Hard signal — APK loaded from /data/data/ = definitive
    //
    // Source: ConbeerLib, "Parallel Space Traveling" (SACMAT 2020)
    // ──────────────────────────────────────────────

    private fun checkApkSourcePath(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_APK_SOURCE, name, errors) {
            val sourceDir = context.applicationInfo.sourceDir ?: ""

            // Normal: /data/app/~~hash~~/com.example.app-hash/base.apk
            // Virtual container: /data/data/<container_pkg>/virtual/.../base.apk
            // Source: ConbeerLib /proc/self/maps analysis, SACMAT 2020
            val isNormalPath = sourceDir.startsWith("/data/app/") ||
                sourceDir.startsWith("/system/")
            val suspicious = sourceDir.isNotEmpty() && !isNormalPath

            evidence.add(
                Evidence(
                    checkName = CHECK_APK_SOURCE,
                    description = if (suspicious) {
                        "APK loaded from non-standard path (virtual container): '$sourceDir'"
                    } else {
                        "APK source path is standard"
                    },
                    rawValue = sourceDir,
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 3: /proc/self/maps Analysis
    // Hard signal — foreign package paths in memory maps = definitive
    //
    // Source: ConbeerLib (primary detection method),
    //         Android Security Symposium 2020
    //
    // /proc/self/maps is always readable by the process itself
    // (Linux kernel guarantee, not restricted by SELinux hidepid)
    // ──────────────────────────────────────────────

    private fun checkProcSelfMaps(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_PROC_MAPS, name, errors) {
            val packageName = context.packageName
            val foreignPaths = mutableListOf<String>()

            try {
                BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        // Extract the file path (last field after spaces)
                        // Source: ConbeerLib ConBeer.java checkProcMaps()
                        val path = line.substringAfterLast(" ").trim()

                        if (path.startsWith("/data/data/") || path.startsWith("/data/app/") ||
                            path.startsWith("/data/user/")
                        ) {
                            if (!path.contains(packageName) && !isWhitelistedPath(path)) {
                                foreignPaths.add(path)
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

            val suspicious = foreignPaths.isNotEmpty()
            val distinctForeign = foreignPaths.distinct().take(5) // Limit for readability

            evidence.add(
                Evidence(
                    checkName = CHECK_PROC_MAPS,
                    description = if (suspicious) {
                        "Found ${foreignPaths.size} foreign paths in /proc/self/maps " +
                            "(code loaded from another app's directory)"
                    } else {
                        "No foreign paths in /proc/self/maps"
                    },
                    rawValue = if (suspicious) {
                        distinctForeign.joinToString("\n")
                    } else {
                        "(clean)"
                    },
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 4: Environment Variables
    // Soft signal — VirtualApp-specific env vars
    //
    // Source: VirtualApp source code IOUniformer.cpp,
    //         ConbeerLib Constants.java
    // ──────────────────────────────────────────────

    private fun checkEnvironmentVariables(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_ENV_VARS, name, errors) {
            val foundVars = mutableListOf<String>()

            // Environment variables set by VirtualApp's IOUniformer.cpp
            // Source: VirtualApp/lib/src/main/jni/Foundation/IOUniformer.cpp
            for (varName in VIRTUALAPP_ENV_VARS) {
                val value = try {
                    System.getenv(varName)
                } catch (_: Exception) {
                    null
                }
                if (value != null) {
                    foundVars.add("$varName=$value")
                }
            }

            // LD_PRELOAD pointing to a container's data directory
            // Source: ConbeerLib checkEnvironment(), VirtualApp sets LD_PRELOAD to libva++.so
            val ldPreload = try {
                System.getenv("LD_PRELOAD")
            } catch (_: Exception) {
                null
            }
            if (ldPreload != null && (ldPreload.contains("/data/data/") || ldPreload.contains("/data/app/"))) {
                foundVars.add("LD_PRELOAD=$ldPreload")
            }

            val suspicious = foundVars.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_ENV_VARS,
                    description = if (suspicious) {
                        "Found ${foundVars.size} virtual container environment variable(s)"
                    } else {
                        "No virtual container environment variables found"
                    },
                    rawValue = if (suspicious) foundVars.joinToString("; ") else "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 5: Stack Trace Analysis
    // Soft signal — cloner class prefixes in call stack
    //
    // Source: ConbeerLib Constants.java BLACKLISTED_STACKS
    // ──────────────────────────────────────────────

    private fun checkStackTrace(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_STACK_TRACE, name, errors) {
            val stackTrace = Throwable().stackTrace
            val suspiciousFrames = mutableListOf<String>()

            for (frame in stackTrace) {
                val className = frame.className
                // Source: ConbeerLib Constants.java BLACKLISTED_STACKS
                if (CLONER_CLASS_PREFIXES.any { className.startsWith(it) }) {
                    suspiciousFrames.add(className)
                }
            }

            val suspicious = suspiciousFrames.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_STACK_TRACE,
                    description = if (suspicious) {
                        "Found cloner classes in call stack: ${suspiciousFrames.distinct().take(3)}"
                    } else {
                        "No cloner classes in call stack"
                    },
                    rawValue = if (suspicious) {
                        suspiciousFrames.distinct().joinToString(", ")
                    } else {
                        "(clean)"
                    },
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 6: Known Cloner Package Detection
    // Soft signal — easily evaded + Android 11+ limits
    //
    // Requires <queries> in AndroidManifest.xml
    // ──────────────────────────────────────────────

    private fun checkKnownClonerPackages(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_CLONER_PACKAGES, name, errors) {
            val pm = context.packageManager
            val foundPackages = mutableListOf<String>()

            for (pkg in KNOWN_CLONER_PACKAGES) {
                val installed = try {
                    pm.getPackageInfo(pkg, 0)
                    true
                } catch (_: PackageManager.NameNotFoundException) {
                    false
                } catch (_: Exception) {
                    false
                }
                if (installed) {
                    foundPackages.add(pkg)
                }
            }

            val suspicious = foundPackages.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_CLONER_PACKAGES,
                    description = if (suspicious) {
                        "Found ${foundPackages.size} known cloner app(s) installed"
                    } else {
                        "No known cloner apps detected"
                    },
                    rawValue = if (suspicious) foundPackages.joinToString(", ") else "(none)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 7: ArtMethod hotness_count Inspection
    // Hard signal (positive-only) — state-of-the-art
    //
    // Source: Mascara paper (arXiv 2010.10639),
    //         Matrioska (ACSAC 2024, IEEE 10917506)
    //
    // hotness_count == 0 for a frequently-called framework
    // method → AOT-only compilation → virtual container.
    // hotness_count > 0 → inconclusive (does NOT rule out
    // virtualization, just means this check didn't trigger).
    // ──────────────────────────────────────────────

    private fun checkArtMethodHotness(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_ART_METHOD, name, errors) {
            when (val result = artMethodChecker.check()) {
                is ArtMethodChecker.CheckResult.Detected -> {
                    evidence.add(
                        Evidence(
                            checkName = CHECK_ART_METHOD,
                            description = result.detail,
                            rawValue = "hotness_count=0",
                            suspicious = true,
                        )
                    )
                }
                is ArtMethodChecker.CheckResult.Normal -> {
                    evidence.add(
                        Evidence(
                            checkName = CHECK_ART_METHOD,
                            description = "ArtMethod hotness_count > 0 (normal execution pattern)",
                            rawValue = "hotness_count>0",
                            suspicious = false,
                        )
                    )
                }
                is ArtMethodChecker.CheckResult.Inconclusive -> {
                    evidence.add(
                        Evidence(
                            checkName = CHECK_ART_METHOD,
                            description = "ArtMethod check inconclusive: ${result.reason}",
                            rawValue = result.reason,
                            suspicious = false, // Inconclusive = no signal, not "clean"
                        )
                    )
                }
            }
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

    /**
     * Checks if a foreign path in /proc/self/maps is from a known legitimate source.
     * Some system services (notably Google Play Services) memory-map files from their
     * own data directory into other apps' processes. These are not virtual containers.
     */
    private fun isWhitelistedPath(path: String): Boolean {
        return PROC_MAPS_WHITELISTED_PACKAGES.any { path.contains(it) }
    }

    /**
     * Two-tier confidence (same approach as EmulatorDetector):
     * - Tier 1: Hard signals → confidence = 1.0
     * - Tier 2: Soft signal weighted scoring
     */
    private fun computeConfidence(evidence: List<Evidence>): Float {
        val hardSignalFired = evidence.any { ev ->
            ev.suspicious && ev.checkName in HARD_SIGNAL_CHECKS
        }
        if (hardSignalFired) return 1.0f

        var triggeredWeight = 0f
        val totalWeight = SOFT_CHECK_WEIGHTS.values.sum()
        if (totalWeight == 0f) return 0f

        for ((group, weight) in SOFT_CHECK_WEIGHTS) {
            val groupEvidence = evidence.filter { it.checkName.startsWith(group) }
            if (groupEvidence.isEmpty()) continue

            val suspiciousCount = groupEvidence.count { it.suspicious }
            val totalCount = groupEvidence.size

            if (suspiciousCount > 0) {
                val ratio = suspiciousCount.toFloat() / totalCount.toFloat()
                triggeredWeight += weight * ratio
            }
        }

        return (triggeredWeight / totalWeight).coerceIn(0f, 1f)
    }

    companion object {
        private const val DETECTION_THRESHOLD = 0.35f

        // ── Check name constants ──
        private const val CHECK_DATA_DIR = "clone_data_dir"
        private const val CHECK_APK_SOURCE = "clone_apk_source"
        private const val CHECK_PROC_MAPS = "clone_proc_maps"
        private const val CHECK_ENV_VARS = "clone_env_vars"
        private const val CHECK_STACK_TRACE = "clone_stack_trace"
        private const val CHECK_CLONER_PACKAGES = "clone_packages"
        private const val CHECK_ART_METHOD = "clone_art_method"

        // ── Tier 1: Hard signals ──
        private val HARD_SIGNAL_CHECKS = setOf(
            CHECK_DATA_DIR,     // Foreign package in data path
            CHECK_APK_SOURCE,   // APK loaded from /data/data/ instead of /data/app/
            CHECK_PROC_MAPS,    // Foreign package paths in memory maps
            CHECK_ART_METHOD,   // ArtMethod hotness_count == 0 (ACSAC 2024)
        )

        // ── Tier 2: Soft signals ──
        private val SOFT_CHECK_WEIGHTS = mapOf(
            CHECK_ENV_VARS to 0.7f,
            CHECK_STACK_TRACE to 0.6f,
            CHECK_CLONER_PACKAGES to 0.4f,
        )

        // Packages whose paths legitimately appear in other apps' /proc/self/maps.
        // Google Play Services maps emoji fonts into app processes for shared rendering.
        // These are NOT virtual container artifacts.
        private val PROC_MAPS_WHITELISTED_PACKAGES = listOf(
            "com.google.android.gms",   // Google Play Services (fonts, shared libs)
            "com.google.android.trichromelibrary", // Chrome/WebView shared library
            "com.google.android.webview", // WebView shared library
        )

        // Path segments indicating a virtual container filesystem layout
        // Source: VirtualApp VEnvironment.java, ConbeerLib storage dir check
        private val VIRTUAL_PATH_SEGMENTS = listOf(
            "/virtual/data/",
            "/parallel_intl/",
            "/parallel_space/",
            "/dualspace/",
            "/clone/",
        )

        // Environment variables set by VirtualApp's IOUniformer.cpp
        // Source: VirtualApp/lib/src/main/jni/Foundation/IOUniformer.cpp
        private val VIRTUALAPP_ENV_VARS = listOf(
            "V_REPLACE_ITEM",
            "V_KEEP_ITEM",
            "V_SO_PATH",
            "REPLACE_ITEM_ORIG",
            "REPLACE_ITEM_DST",
            "V_API_LEVEL",
            "V_PREVIEW_API_LEVEL",
        )

        // Class name prefixes found in virtual container call stacks
        // Source: ConbeerLib Constants.java BLACKLISTED_STACKS
        private val CLONER_CLASS_PREFIXES = listOf(
            "com.lody.virtual",     // VirtualApp / Dual Space
            "com.doubleagent",      // Parallel Space
            "io.va.exposed",        // VirtualXposed
            "com.excelliance",      // 2Accounts
            "io.tt",                // Multi-Parallel
            "com.estrongs.vbox",    // Clone App (ES)
            "org.nl",               // Super Clone
            "com.polestar",         // Multi Account
        )

        // Known cloner package names (must match <queries> in AndroidManifest.xml)
        private val KNOWN_CLONER_PACKAGES = listOf(
            "com.lbe.parallel.intl",
            "com.lbe.parallel",
            "com.ludashi.dualspace",
            "com.excelliance.dualaid",
            "com.polestar.multiaccount",
            "com.polestar.super.clone",
            "com.nox.mopen.app",
            "com.applisto.appcloner",
            "com.virtualapp",
            "io.virtualapp",
            "io.twoface",
            "com.jumobile.multiapp",
            "com.dual.clone",
            "com.multi.parallel",
            "com.qihoo.magic",
            "com.game.cloner",
            "com.x8bit.biern",
        )
    }
}
