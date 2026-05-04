package com.bruno.antitamperingapp.detection.util

import android.util.Log
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.TamperVerdict

/**
 * Centralized logging for the detection module.
 *
 * Logging is **disabled by default** for security — detection details in logcat
 * are visible to any app on the device and expose which checks are active.
 * Enable only during development via [enabled] = true.
 *
 * Filter: `adb logcat -s TamperDetection`
 */
object DetectionLogger {

    /**
     * Set to true to enable detection logs. Default: false (silent in production).
     * Typically set from the app module: `DetectionLogger.enabled = BuildConfig.DEBUG`
     */
    var enabled: Boolean = false

    private const val TAG = "TamperDetection"

    fun detectorStarted(detectorName: String) {
        if (!enabled) return
        Log.d(TAG, "[$detectorName] Starting detection...")
    }

    fun detectorCompleted(detectorName: String, result: DetectionResult, durationMs: Long) {
        if (!enabled) return
        val status = if (result.detected) "DETECTED" else "CLEAN"
        Log.i(
            TAG,
            "[$detectorName] $status (confidence=${formatPercent(result.confidence)}, " +
                "evidence=${result.evidence.size}, errors=${result.errors.size}, " +
                "duration=${durationMs}ms)"
        )
        result.evidence.filter { it.suspicious }.forEach { ev ->
            Log.i(TAG, "  -> [${ev.checkName}] ${ev.description} (raw=${ev.rawValue})")
        }
        result.errors.forEach { err ->
            Log.w(TAG, "  !! $err")
        }
    }

    fun engineStarted(detectorCount: Int) {
        if (!enabled) return
        Log.i(TAG, "Detection engine started with $detectorCount detectors")
    }

    fun verdictProduced(verdict: TamperVerdict) {
        if (!enabled) return
        Log.i(
            TAG,
            "VERDICT: ${verdict.status.displayName} " +
                "(score=${formatPercent(verdict.overallScore)}, " +
                "duration=${verdict.durationMs}ms, errors=${verdict.errors.size})"
        )
    }

    private fun formatPercent(value: Float): String =
        "${(value * 100).toInt()}%"
}
