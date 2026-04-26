package com.bruno.antitamperingapp.detection.util

import android.util.Log
import com.bruno.antitamperingapp.detection.error.DetectionError
import kotlinx.coroutines.withTimeoutOrNull

@PublishedApi
internal const val TAG = "SafeExec"

/**
 * Defensive execution wrapper for detection checks.
 *
 * Ensures that no single check can crash the detection engine.
 * All exceptions are caught, logged, and converted to [DetectionError].
 */
object SafeExec {

    /**
     * Executes [block] with exception safety. Returns the result or null if it failed.
     * Any caught exception is logged and added to [errors].
     *
     * @param checkName Name of the check (for logging and error attribution).
     * @param detectorName Name of the detector running this check.
     * @param errors Mutable list where any error will be appended.
     * @param block The detection logic to execute.
     * @return The result of [block], or null if an exception occurred.
     */
    inline fun <T> runCatching(
        checkName: String,
        detectorName: String,
        errors: MutableList<DetectionError>,
        block: () -> T,
    ): T? {
        return try {
            block()
        } catch (e: SecurityException) {
            val error = DetectionError.PermissionDenied(
                detectorName = detectorName,
                permission = "$checkName (SecurityException: ${e.message})",
            )
            Log.w(TAG, error.toString(), e)
            errors.add(error)
            null
        } catch (e: Exception) {
            val error = DetectionError.Unexpected(
                detectorName = detectorName,
                cause = e,
            )
            Log.w(TAG, error.toString(), e)
            errors.add(error)
            null
        }
    }

    /**
     * Executes a suspending [block] with a timeout.
     * Returns the result or null if it timed out or threw.
     *
     * @param timeoutMs Maximum time in milliseconds.
     * @param checkName Name of the check (for error attribution).
     * @param detectorName Name of the detector.
     * @param errors Mutable list for error collection.
     * @param block The suspending detection logic.
     * @return The result, or null on timeout/error.
     */
    suspend inline fun <T> withTimeout(
        timeoutMs: Long,
        checkName: String,
        detectorName: String,
        errors: MutableList<DetectionError>,
        crossinline block: suspend () -> T,
    ): T? {
        return try {
            val result = withTimeoutOrNull(timeoutMs) { block() }
            if (result == null) {
                val error = DetectionError.Timeout(
                    detectorName = detectorName,
                    durationMs = timeoutMs,
                    limitMs = timeoutMs,
                )
                Log.w(TAG, error.toString())
                errors.add(error)
            }
            result
        } catch (e: Exception) {
            val error = DetectionError.Unexpected(
                detectorName = detectorName,
                cause = e,
            )
            Log.w(TAG, error.toString(), e)
            errors.add(error)
            null
        }
    }
}
