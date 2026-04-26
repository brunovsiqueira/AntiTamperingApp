package com.bruno.antitamperingapp.detection

import android.content.Context
import com.bruno.antitamperingapp.detection.error.DetectionError
import com.bruno.antitamperingapp.detection.util.DetectionLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext

/**
 * Orchestrates all [TamperDetector] instances and produces an aggregated [TamperVerdict].
 *
 * Detectors run concurrently on [Dispatchers.Default]. Each detector is independently
 * time-bounded and error-safe — a failing detector degrades the verdict rather than
 * crashing the engine.
 *
 * Thread safety: This class is stateless and safe to call from any thread.
 * The [evaluate] function is a suspend function designed to be called from a ViewModel scope.
 */
class DetectionEngine private constructor(
    private val detectors: List<TamperDetector>,
) {

    /**
     * Runs all registered detectors concurrently and produces an aggregated verdict.
     *
     * @param context Application context. Do not pass an Activity context.
     * @return A [TamperVerdict] with the overall status, per-category results, and timing.
     */
    suspend fun evaluate(context: Context): TamperVerdict = withContext(Dispatchers.Default) {
        val appContext = context.applicationContext
        DetectionLogger.engineStarted(detectors.size)
        val startTime = System.currentTimeMillis()

        val categoryResults = detectors
            .map { detector ->
                async { runDetector(detector, appContext) }
            }
            .awaitAll()

        val results = categoryResults.associate { it.first to it.second }
        val allErrors = results.values.flatMap { it.errors }
        val overallScore = computeOverallScore(results)
        val status = classifyStatus(overallScore)
        val durationMs = System.currentTimeMillis() - startTime

        val verdict = TamperVerdict(
            status = status,
            overallScore = overallScore,
            results = results,
            errors = allErrors,
            durationMs = durationMs,
        )
        DetectionLogger.verdictProduced(verdict)
        verdict
    }

    private suspend fun runDetector(
        detector: TamperDetector,
        context: Context,
    ): Pair<DetectionCategory, DetectionResult> {
        DetectionLogger.detectorStarted(detector.name)
        val startTime = System.currentTimeMillis()

        val result = try {
            detector.detect(context)
        } catch (e: Exception) {
            DetectionResult(
                detected = false,
                confidence = 0f,
                evidence = emptyList(),
                errors = listOf(
                    DetectionError.Unexpected(
                        detectorName = detector.name,
                        cause = e,
                    )
                ),
            )
        }

        val durationMs = System.currentTimeMillis() - startTime
        DetectionLogger.detectorCompleted(detector.name, result, durationMs)
        return detector.category to result
    }

    /**
     * Weighted average of all detector confidences.
     * Only detectors that flagged [DetectionResult.detected] = true contribute.
     */
    private fun computeOverallScore(
        results: Map<DetectionCategory, DetectionResult>,
    ): Float {
        val detectorsWithResults = detectors.mapNotNull { detector ->
            results[detector.category]?.let { result -> detector to result }
        }
        if (detectorsWithResults.isEmpty()) return 0f

        val totalWeight = detectorsWithResults.sumOf { it.first.weight.toDouble() }
        if (totalWeight == 0.0) return 0f

        val weightedSum = detectorsWithResults.sumOf { (detector, result) ->
            (detector.weight * result.confidence).toDouble()
        }
        return (weightedSum / totalWeight).toFloat().coerceIn(0f, 1f)
    }

    private fun classifyStatus(score: Float): TamperStatus = when {
        score >= TAMPERED_THRESHOLD -> TamperStatus.TAMPERED
        score >= WARNING_THRESHOLD -> TamperStatus.WARNING
        else -> TamperStatus.SECURE
    }

    /**
     * Builder for constructing a [DetectionEngine] with specific detectors.
     *
     * Usage:
     * ```
     * val engine = DetectionEngine.Builder()
     *     .addDetector(EmulatorDetector())
     *     .addDetector(CloningDetector())
     *     .build()
     * ```
     */
    class Builder {
        private val detectors = mutableListOf<TamperDetector>()

        fun addDetector(detector: TamperDetector): Builder = apply {
            detectors.add(detector)
        }

        fun build(): DetectionEngine {
            require(detectors.isNotEmpty()) { "At least one detector must be registered" }
            return DetectionEngine(detectors.toList())
        }
    }

    companion object {
        /** Score at or above this = TAMPERED. */
        private const val TAMPERED_THRESHOLD = 0.6f

        /** Score at or above this (but below TAMPERED) = WARNING. */
        private const val WARNING_THRESHOLD = 0.25f
    }
}
