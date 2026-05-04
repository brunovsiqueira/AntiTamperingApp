package com.bruno.antitamperingapp.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceTest {

    @Test
    fun `suspicious evidence preserves all fields`() {
        val evidence = Evidence(
            checkName = "build_hardware",
            description = "Build.HARDWARE indicates emulator: 'ranchu'",
            rawValue = "ranchu",
            suspicious = true,
        )
        assertEquals("build_hardware", evidence.checkName)
        assertEquals("ranchu", evidence.rawValue)
        assertTrue(evidence.suspicious)
    }

    @Test
    fun `clean evidence is not suspicious`() {
        val evidence = Evidence(
            checkName = "build_hardware",
            description = "Build.HARDWARE appears legitimate",
            rawValue = "qcom",
            suspicious = false,
        )
        assertFalse(evidence.suspicious)
    }

    @Test
    fun `null rawValue is allowed`() {
        val evidence = Evidence(
            checkName = "gl_renderer",
            description = "Could not query GL renderer",
            rawValue = null,
            suspicious = false,
        )
        assertNull(evidence.rawValue)
    }
}
