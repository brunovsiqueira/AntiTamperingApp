package com.bruno.antitamperingapp.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionResultTest {

    @Test
    fun `clean result has zero confidence and no detection`() {
        val result = DetectionResult.clean()
        assertFalse(result.detected)
        assertEquals(0f, result.confidence)
        assertTrue(result.evidence.isEmpty())
        assertTrue(result.errors.isEmpty())
    }

    @Test
    fun `confidence must be between 0 and 1`() {
        val result = DetectionResult(
            detected = true,
            confidence = 0.5f,
            evidence = emptyList(),
        )
        assertEquals(0.5f, result.confidence)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `confidence above 1 throws`() {
        DetectionResult(detected = true, confidence = 1.1f, evidence = emptyList())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `confidence below 0 throws`() {
        DetectionResult(detected = true, confidence = -0.1f, evidence = emptyList())
    }

    @Test
    fun `evidence items are preserved`() {
        val evidence = listOf(
            Evidence("check_a", "description A", "raw_a", suspicious = true),
            Evidence("check_b", "description B", "raw_b", suspicious = false),
        )
        val result = DetectionResult(
            detected = true,
            confidence = 0.8f,
            evidence = evidence,
        )
        assertEquals(2, result.evidence.size)
        assertTrue(result.evidence[0].suspicious)
        assertFalse(result.evidence[1].suspicious)
    }
}
