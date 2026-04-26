package com.bruno.antitamperingapp.detection.error

/**
 * Unified error model for all detection operations.
 *
 * Errors are non-fatal: a detector that encounters an error still produces a
 * [DetectionResult], but attaches the error for observability. The engine
 * never crashes due to a detector error.
 *
 * @property code Machine-readable error code for logging and analytics.
 * @property message Human-readable description of what went wrong.
 * @property detectorName Which detector produced this error.
 */
sealed class DetectionError(
    val code: String,
    val message: String,
    val detectorName: String,
) {
    /** A file or path could not be read (e.g., /proc/self/maps on a restricted device). */
    class FileAccessFailed(
        detectorName: String,
        val path: String,
        val cause: Throwable? = null,
    ) : DetectionError(
        code = "FILE_ACCESS_FAILED",
        message = "Failed to read '$path': ${cause?.message ?: "unknown"}",
        detectorName = detectorName,
    )

    /** A required permission was not granted. */
    class PermissionDenied(
        detectorName: String,
        val permission: String,
    ) : DetectionError(
        code = "PERMISSION_DENIED",
        message = "Permission '$permission' not granted",
        detectorName = detectorName,
    )

    /** An Android API is not available on this SDK version. */
    class ApiUnavailable(
        detectorName: String,
        val api: String,
        val requiredSdk: Int,
        val currentSdk: Int,
    ) : DetectionError(
        code = "API_UNAVAILABLE",
        message = "$api requires SDK $requiredSdk (current: $currentSdk)",
        detectorName = detectorName,
    )

    /** A detector check took longer than the allowed timeout. */
    class Timeout(
        detectorName: String,
        val durationMs: Long,
        val limitMs: Long,
    ) : DetectionError(
        code = "TIMEOUT",
        message = "Detector timed out after ${durationMs}ms (limit: ${limitMs}ms)",
        detectorName = detectorName,
    )

    /** An unexpected exception that was caught by the safety wrapper. */
    class Unexpected(
        detectorName: String,
        val cause: Throwable,
    ) : DetectionError(
        code = "UNEXPECTED",
        message = "Unexpected error: ${cause::class.simpleName} - ${cause.message}",
        detectorName = detectorName,
    )

    override fun toString(): String = "[$code] ($detectorName) $message"
}
