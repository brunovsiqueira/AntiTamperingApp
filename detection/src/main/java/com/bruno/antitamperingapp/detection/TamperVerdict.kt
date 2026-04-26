package com.bruno.antitamperingapp.detection

import com.bruno.antitamperingapp.detection.error.DetectionError

/**
 * Overall verdict produced by [DetectionEngine] after running all detectors.
 *
 * @property status The aggregated trust level of the environment.
 * @property overallScore Aggregated score from all detectors (0.0 = fully trusted, 1.0 = definitely tampered).
 * @property results Per-category results mapped by [DetectionCategory].
 * @property errors Aggregated errors from all detectors.
 * @property durationMs Total wall-clock time for all detections in milliseconds.
 */
data class TamperVerdict(
    val status: TamperStatus,
    val overallScore: Float,
    val results: Map<DetectionCategory, DetectionResult>,
    val errors: List<DetectionError>,
    val durationMs: Long,
) {
    init {
        require(overallScore in 0f..1f) { "Overall score must be in [0.0, 1.0], got $overallScore" }
    }
}

/**
 * High-level trust classification derived from the aggregated score.
 */
enum class TamperStatus(val displayName: String) {
    /** No anomalies detected. Environment appears genuine. */
    SECURE("Secure"),

    /** Some weak signals detected. Environment may be modified. */
    WARNING("Warning"),

    /** Strong signals detected. Environment is likely tampered. */
    TAMPERED("Tampered"),
}
