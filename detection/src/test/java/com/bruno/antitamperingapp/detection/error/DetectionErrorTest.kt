package com.bruno.antitamperingapp.detection.error

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionErrorTest {

    @Test
    fun `FileAccessFailed contains path and detector name`() {
        val error = DetectionError.FileAccessFailed(
            detectorName = "EmulatorDetector",
            path = "/proc/self/maps",
            cause = SecurityException("SELinux denied"),
        )
        assertEquals("FILE_ACCESS_FAILED", error.code)
        assertEquals("EmulatorDetector", error.detectorName)
        assertTrue(error.message.contains("/proc/self/maps"))
        assertTrue(error.toString().contains("FILE_ACCESS_FAILED"))
    }

    @Test
    fun `PermissionDenied includes permission name`() {
        val error = DetectionError.PermissionDenied(
            detectorName = "IntegrityDetector",
            permission = "READ_PHONE_STATE",
        )
        assertEquals("PERMISSION_DENIED", error.code)
        assertTrue(error.message.contains("READ_PHONE_STATE"))
    }

    @Test
    fun `ApiUnavailable includes SDK levels`() {
        val error = DetectionError.ApiUnavailable(
            detectorName = "ArtMethodChecker",
            api = "FromReflectedMethod",
            requiredSdk = 31,
            currentSdk = 28,
        )
        assertEquals("API_UNAVAILABLE", error.code)
        assertTrue(error.message.contains("31"))
        assertTrue(error.message.contains("28"))
    }

    @Test
    fun `Timeout includes duration and limit`() {
        val error = DetectionError.Timeout(
            detectorName = "EmulatorDetector",
            durationMs = 5000,
            limitMs = 4000,
        )
        assertEquals("TIMEOUT", error.code)
        assertTrue(error.message.contains("5000"))
    }

    @Test
    fun `Unexpected wraps cause exception`() {
        val cause = RuntimeException("something broke")
        val error = DetectionError.Unexpected(
            detectorName = "CloningDetector",
            cause = cause,
        )
        assertEquals("UNEXPECTED", error.code)
        assertTrue(error.message.contains("RuntimeException"))
        assertTrue(error.message.contains("something broke"))
    }
}
