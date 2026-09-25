package com.messageguard

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class ExcelExporterTest {

    @Test
    fun testExcelExportStructure() {
        val sampleResults = listOf(
            AnalysisResult(
                id = 1L,
                timestamp = System.currentTimeMillis(),
                appSource = "Gmail",
                sender = "test@example.com",
                subject = "Security Update",
                verdict = Verdict.DANGER,
                riskScore = 85,
                category = "Phishing",
                senderTrust = "Unknown",
                summary = "Suspicious link detected",
                flags = listOf("malicious_url", "urgency_words"),
                action = "Block sender",
                mlScore = 80,
                aiScore = 90,
                messageSnippet = "Please update your password immediately",
                flaggedUrls = "http://malicious.link"
            ),
            AnalysisResult(
                id = 2L,
                timestamp = System.currentTimeMillis(),
                appSource = "WhatsApp",
                sender = "+1234567890",
                subject = "",
                verdict = Verdict.SAFE,
                riskScore = 5,
                category = "Clean",
                senderTrust = "Verified",
                summary = "Safe message",
                flags = emptyList(),
                action = "None",
                mlScore = 5,
                aiScore = -1,
                messageSnippet = "Hello, how are you?",
                flaggedUrls = ""
            )
        )

        val outputStream = ByteArrayOutputStream()
        try {
            ExcelExporter.exportToStream(sampleResults, outputStream)
            val bytes = outputStream.toByteArray()
            assertTrue("Exported stream should not be empty", bytes.isNotEmpty())
            // First few bytes of a zip/xlsx file is the PK header (zip format)
            assertEquals('P'.code.toByte(), bytes[0])
            assertEquals('K'.code.toByte(), bytes[1])
        } catch (e: Exception) {
            fail("ExcelExporter threw an exception during export: ${e.message}")
        }
    }
}
