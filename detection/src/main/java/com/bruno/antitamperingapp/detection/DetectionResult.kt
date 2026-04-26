package com.bruno.antitamperingapp.detection

import com.bruno.antitamperingapp.detection.error.DetectionError

/**
 * Result produced by a single [TamperDetector].
 *
 * @property detected Whether this detector found anomalies.
 * @property confidence How confident the detector is in its finding (0.0 = no signal, 1.0 = certain).
 * @property evidence The individual signals that contributed to this result.
 * @property errors Non-fatal errors encountered during detection (e.g., permission denied for one check).
 */
data class DetectionResult(
    val detected: Boolean,
    val confidence: Float,
    val evidence: List<Evidence>,
    val errors: List<DetectionError> = emptyList(),
) {
    init {
        require(confidence in 0f..1f) { "Confidence must be in [0.0, 1.0], got $confidence" }
    }

    companion object {
        /** Convenience for a clean result with no anomalies. */
        fun clean(): DetectionResult = DetectionResult(
            detected = false,
            confidence = 0f,
            evidence = emptyList(),
        )
    }
}

/**
 * A single piece of evidence collected during detection.
 *
 * @property checkName Short identifier for the check (e.g., "build_fingerprint", "data_dir_path").
 * @property description Human-readable explanation of what was found.
 * @property rawValue The actual value observed (e.g., the Build.FINGERPRINT string, a file path).
 * @property suspicious Whether this individual signal is considered anomalous.
 */
data class Evidence(
    val checkName: String,
    val description: String,
    val rawValue: String?,
    val suspicious: Boolean,
)
