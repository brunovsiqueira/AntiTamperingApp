package com.bruno.antitamperingapp.detection

import android.content.Context

/**
 * Contract for all environment anomaly detectors.
 *
 * Each implementation checks one category of threat (emulator, cloning, etc.)
 * and returns a [DetectionResult] with evidence and confidence score.
 *
 * Implementations must:
 * - Never throw uncaught exceptions (use [DetectionResult.errors] for non-fatal issues).
 * - Complete within a reasonable time (target < 500ms per detector).
 * - Be safe to call from any thread (detection runs on background dispatchers).
 */
interface TamperDetector {

    /** Human-readable name for logging and display. */
    val name: String

    /** Which threat category this detector addresses. */
    val category: DetectionCategory

    /**
     * Weight of this detector in the aggregated score.
     * Higher weight means this detector's result has more influence on the final verdict.
     * Range: 0.0 to 1.0.
     */
    val weight: Float

    /**
     * Run all checks for this detector's category.
     *
     * @param context Application context. Never hold a reference beyond this call.
     * @return A [DetectionResult] with findings, confidence, and any non-fatal errors.
     */
    suspend fun detect(context: Context): DetectionResult
}
