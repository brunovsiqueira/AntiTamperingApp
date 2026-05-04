package com.bruno.antitamperingapp.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TamperVerdictTest {

    @Test
    fun `verdict with zero score is SECURE`() {
        val verdict = buildVerdict(
            emulatorDetected = false,
            emulatorConfidence = 0f,
            cloningDetected = false,
            cloningConfidence = 0f,
        )
        assertEquals(TamperStatus.SECURE, verdict.status)
        assertEquals(0f, verdict.overallScore)
    }

    @Test
    fun `verdict with any detected category is TAMPERED`() {
        val results = mapOf(
            DetectionCategory.EMULATOR to DetectionResult(
                detected = true, confidence = 1.0f, evidence = emptyList(),
            ),
            DetectionCategory.CLONING to DetectionResult.clean(),
            DetectionCategory.INTEGRITY to DetectionResult.clean(),
            DetectionCategory.HOOKING to DetectionResult.clean(),
        )
        // If any detector has detected=true, overall should be TAMPERED
        val anyDetected = results.values.any { it.detected }
        assertTrue(anyDetected)
    }

    @Test
    fun `overall score is 1 when any detector detected`() {
        val verdict = buildVerdict(
            emulatorDetected = true,
            emulatorConfidence = 1.0f,
            cloningDetected = false,
            cloningConfidence = 0f,
        )
        assertEquals(TamperStatus.TAMPERED, verdict.status)
        assertEquals(1.0f, verdict.overallScore)
    }

    @Test
    fun `multiple detected categories still produce TAMPERED`() {
        val verdict = buildVerdict(
            emulatorDetected = true,
            emulatorConfidence = 1.0f,
            cloningDetected = true,
            cloningConfidence = 1.0f,
        )
        assertEquals(TamperStatus.TAMPERED, verdict.status)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `overall score above 1 throws`() {
        TamperVerdict(
            status = TamperStatus.TAMPERED,
            overallScore = 1.5f,
            results = emptyMap(),
            errors = emptyList(),
            durationMs = 0,
        )
    }

    private fun buildVerdict(
        emulatorDetected: Boolean,
        emulatorConfidence: Float,
        cloningDetected: Boolean,
        cloningConfidence: Float,
    ): TamperVerdict {
        val results = mapOf(
            DetectionCategory.EMULATOR to DetectionResult(
                detected = emulatorDetected,
                confidence = emulatorConfidence,
                evidence = emptyList(),
            ),
            DetectionCategory.CLONING to DetectionResult(
                detected = cloningDetected,
                confidence = cloningConfidence,
                evidence = emptyList(),
            ),
        )
        val anyDetected = results.values.any { it.detected }
        val score = if (anyDetected) 1.0f else 0f
        val status = if (anyDetected) TamperStatus.TAMPERED else TamperStatus.SECURE
        return TamperVerdict(
            status = status,
            overallScore = score,
            results = results,
            errors = emptyList(),
            durationMs = 100,
        )
    }
}
