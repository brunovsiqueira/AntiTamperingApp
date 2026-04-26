package com.bruno.antitamperingapp.detection.util

import android.util.Log
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.TamperVerdict

/**
 * Centralized logging for the detection module.
 *
 * Uses Android's [Log] with a consistent tag prefix so all detection logs
 * can be filtered with: `adb logcat -s TamperDetection`
 */
object DetectionLogger {

    private const val TAG = "TamperDetection"

    fun detectorStarted(detectorName: String) {
        Log.d(TAG, "[$detectorName] Starting detection...")
    }

    fun detectorCompleted(detectorName: String, result: DetectionResult, durationMs: Long) {
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
        Log.i(TAG, "Detection engine started with $detectorCount detectors")
    }

    fun verdictProduced(verdict: TamperVerdict) {
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
