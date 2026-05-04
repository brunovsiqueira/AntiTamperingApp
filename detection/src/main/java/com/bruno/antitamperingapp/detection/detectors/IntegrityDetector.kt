package com.bruno.antitamperingapp.detection.detectors

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.bruno.antitamperingapp.detection.DetectionCategory
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.Evidence
import com.bruno.antitamperingapp.detection.TamperDetector
import com.bruno.antitamperingapp.detection.error.DetectionError
import com.bruno.antitamperingapp.detection.util.SafeExec
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Detects whether the app has been repackaged (decompiled, modified, re-signed).
 *
 * Uses 4 checks:
 * - **Signing certificate SHA-256**: cryptographically impossible to forge without the private key
 * - **Debug flag**: release builds never have FLAG_DEBUGGABLE
 * - **Installer source**: sideloaded apps weren't installed from a known store
 * - **DEX file CRC**: code modification changes the CRC of classes.dex
 *
 * See ADR-006 for research, trade-offs, and references.
 */
class IntegrityDetector(
    private val expectedSigningCertSha256: String,
    private val expectedDexCrcs: Map<String, Long> = emptyMap(),
) : TamperDetector {

    override val name: String = "IntegrityDetector"
    override val category: DetectionCategory = DetectionCategory.INTEGRITY
    override val weight: Float = 1.0f

    override suspend fun detect(context: Context): DetectionResult {
        val errors = mutableListOf<DetectionError>()
        val evidence = mutableListOf<Evidence>()

        checkSigningCertificate(context, evidence, errors)
        checkDebugFlag(context, evidence, errors)
        checkInstallerSource(context, evidence, errors)
        checkDexIntegrity(context, evidence, errors)

        return buildResult(evidence, errors)
    }

    // ──────────────────────────────────────────────
    // Check 1: Signing Certificate SHA-256
    // Hard signal — cryptographically impossible to forge
    //
    // Source: OWASP MASTG-TEST-0038, MASVS-RESILIENCE-2
    //
    // A repackaged app MUST be re-signed with the attacker's
    // key (they don't have ours). The SHA-256 will differ.
    // Only bypass: hook PackageManager (requires root/Frida).
    // ──────────────────────────────────────────────

    private fun checkSigningCertificate(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_SIGNATURE, name, errors) {
            val actualHash = getSigningCertSha256(context)

            if (actualHash == null) {
                evidence.add(
                    Evidence(
                        checkName = CHECK_SIGNATURE,
                        description = "Could not retrieve signing certificate",
                        rawValue = null,
                        suspicious = false,
                    )
                )
                return@runCatching
            }

            val matches = actualHash.equals(expectedSigningCertSha256, ignoreCase = true)

            evidence.add(
                Evidence(
                    checkName = CHECK_SIGNATURE,
                    description = if (!matches) {
                        "Signing certificate does NOT match expected value — app was re-signed"
                    } else {
                        "Signing certificate matches expected value"
                    },
                    rawValue = "actual=$actualHash expected=$expectedSigningCertSha256",
                    suspicious = !matches,
                )
            )
        }
    }

    // Source: OWASP MASTG-TEST-0038, Android developer docs
    private fun getSigningCertSha256(context: Context): String? {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES,
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES,
                )
            }

            val signature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures?.firstOrNull()
            } ?: return null

            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(signature.toByteArray())
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    // ──────────────────────────────────────────────
    // Check 2: Debug Flag
    // Hard signal — release builds NEVER have this flag
    //
    // Source: OWASP MASTG-TEST-0039, MASWE-0067
    //
    // Repackaged apps commonly enable debuggable=true
    // for analysis. Deterministic, zero false positives
    // on release builds.
    // ──────────────────────────────────────────────

    private fun checkDebugFlag(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_DEBUG_FLAG, name, errors) {
            val isDebuggable = (context.applicationInfo.flags and
                ApplicationInfo.FLAG_DEBUGGABLE) != 0

            evidence.add(
                Evidence(
                    checkName = CHECK_DEBUG_FLAG,
                    description = if (isDebuggable) {
                        "App has FLAG_DEBUGGABLE set — common in repackaged builds"
                    } else {
                        "App is not debuggable (release build)"
                    },
                    rawValue = "debuggable=$isDebuggable",
                    suspicious = isDebuggable,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 3: Installer Source
    // Soft signal — sideloaded != proof of tampering
    //
    // Source: OWASP MASTG-TEST-0047
    //
    // HIGH false positive risk for enterprise/MDM.
    // Easily spoofed on rooted devices.
    // ──────────────────────────────────────────────

    private fun checkInstallerSource(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_INSTALLER, name, errors) {
            val installer = getInstallerPackageName(context)
            val isFromTrustedStore = installer in TRUSTED_INSTALLERS

            evidence.add(
                Evidence(
                    checkName = CHECK_INSTALLER,
                    description = when {
                        isFromTrustedStore -> "Installed from trusted store: '$installer'"
                        installer == null -> "Installer unknown (sideloaded or ADB install)"
                        else -> "Installed by: '$installer' (not a known app store)"
                    },
                    rawValue = installer ?: "(null)",
                    suspicious = !isFromTrustedStore,
                )
            )
        }
    }

    private fun getInstallerPackageName(context: Context): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager
                    .getInstallSourceInfo(context.packageName)
                    .installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        } catch (_: Exception) {
            null
        }
    }

    // ──────────────────────────────────────────────
    // Check 4: DEX File CRC Integrity
    // Soft signal — catches code modification
    //
    // Source: OWASP MASTG-TEST-0047, Sindee.Dev blog
    //
    // Compares CRC32 of classes.dex files against expected
    // values. Expected CRCs must be stored in resources
    // (not code) to avoid circular dependency.
    //
    // Caveats: breaks with AAB/Play App Signing (Google
    // modifies DEX during processing). Fine for direct APK.
    // ──────────────────────────────────────────────

    private fun checkDexIntegrity(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        if (expectedDexCrcs.isEmpty()) {
            evidence.add(
                Evidence(
                    checkName = CHECK_DEX_CRC,
                    description = "DEX CRC check skipped (no expected values configured)",
                    rawValue = null,
                    suspicious = false,
                )
            )
            return
        }

        SafeExec.runCatching(CHECK_DEX_CRC, name, errors) {
            val apkPath = context.packageCodePath
            val mismatches = mutableListOf<String>()

            try {
                ZipFile(apkPath).use { zip ->
                    for ((dexName, expectedCrc) in expectedDexCrcs) {
                        val entry = zip.getEntry(dexName)
                        if (entry != null) {
                            val actualCrc = entry.crc
                            if (actualCrc != expectedCrc) {
                                mismatches.add("$dexName: expected=${expectedCrc.toString(16)} actual=${actualCrc.toString(16)}")
                            }
                        } else {
                            mismatches.add("$dexName: not found in APK")
                        }
                    }
                }
            } catch (e: Exception) {
                errors.add(
                    DetectionError.FileAccessFailed(
                        detectorName = name,
                        path = apkPath,
                        cause = e,
                    )
                )
            }

            val suspicious = mismatches.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_DEX_CRC,
                    description = if (suspicious) {
                        "DEX integrity mismatch: ${mismatches.size} file(s) modified"
                    } else {
                        "DEX integrity verified (${expectedDexCrcs.size} files match)"
                    },
                    rawValue = if (suspicious) mismatches.joinToString("; ") else "(all match)",
                    suspicious = suspicious,
                )
            )
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
        // Tier 1: Signature mismatch = definitive repackaging
        val signatureMismatch = evidence.any {
            it.suspicious && it.checkName == CHECK_SIGNATURE
        }
        if (signatureMismatch) return 1.0f

        // Tier 2: Soft signal scoring
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
        private const val CHECK_SIGNATURE = "integrity_signature"
        private const val CHECK_DEBUG_FLAG = "integrity_debug_flag"
        private const val CHECK_INSTALLER = "integrity_installer"
        private const val CHECK_DEX_CRC = "integrity_dex_crc"

        // Signature mismatch is the only hard signal.
        // Debug flag is suspicious but expected in debug builds.

        // Soft signal weights
        private val SOFT_CHECK_WEIGHTS = mapOf(
            CHECK_DEBUG_FLAG to 0.6f,
            CHECK_INSTALLER to 0.4f,
            CHECK_DEX_CRC to 0.8f,
        )

        // Source: Android docs, common installer package names
        private val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",          // Google Play Store
            "com.amazon.venezia",           // Amazon Appstore
            "com.huawei.appmarket",         // Huawei AppGallery
            "com.samsung.android.vending",  // Samsung Galaxy Store
            "com.xiaomi.market",            // Xiaomi GetApps
            "com.oppo.market",              // OPPO App Market
            "com.bbk.appstore",             // Vivo App Store
        )
    }
}
