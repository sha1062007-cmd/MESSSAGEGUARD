package com.messageguard.threatvision

import com.messageguard.threatvision.data.model.ExtractedContent
import com.messageguard.threatvision.data.model.ThreatCategory
import com.messageguard.threatvision.data.model.ThreatVerdict
import com.messageguard.threatvision.domain.engine.HybridDecisionEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HybridDecisionEngineTest {

    private val engine = HybridDecisionEngine()

    @Test
    fun testOtpSanitization() {
        val raw = "Your login OTP is 849204 for your bank account."
        val sanitized = engine.sanitizeForCloud(raw)
        assertTrue(sanitized.contains("[REDACTED_OTP]"))
        assertTrue(!sanitized.contains("849204"))
    }

    @Test
    fun testPhishingVerdictDanger() {
        val content = ExtractedContent(
            rawText = "Urgent: Verify your account immediately at http://secure-login.xyz",
            urls = listOf("http://secure-login.xyz")
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.90f,
            edgeNlpScore = 0.85f,
            edgeStructuralScore = 0.50f
        )

        assertEquals(ThreatVerdict.DANGER, result.verdict)
        assertEquals(ThreatCategory.PHISHING, result.category)
        assertTrue(result.riskScore >= 75)
    }

    @Test
    fun testHighNlpAndCloudScamEvidenceCannotProduceSafeVerdict() {
        val content = ExtractedContent(
            rawText = "An unverified email claims a large monetary prize in a special reward " +
                "program and urges the recipient to claim it immediately. This social engineering " +
                "message is designed to steal personal or financial information."
        )

        val result = engine.evaluate(
            content = content,
            edgeNlpScore = 0.99f,
            geminiCloudScore = 95,
            geminiReason = "Likely scam: prize lure seeking personal or financial information."
        )

        assertEquals(ThreatVerdict.DANGER, result.verdict)
        assertEquals(ThreatCategory.SCAM, result.category)
        assertTrue(result.riskScore >= 70)
        assertTrue(result.report?.components?.any {
            it.label == "Cloud AI (Gemini)" && it.score == 95
        } == true)
    }

    @Test
    fun testSafeContentVerdict() {
        val content = ExtractedContent(
            rawText = "Hey, let's meet up for coffee tomorrow at 10am."
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.0f,
            edgeNlpScore = 0.05f,
            edgeStructuralScore = 0.0f
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertEquals(ThreatCategory.SAFE, result.category)
        assertTrue(result.riskScore < 40)
    }

    @Test
    fun testBareIpv4UrlTriggersPhishingCategory() {
        val content = ExtractedContent(
            rawText = "Verify account at 185.34.22.10/login",
            urls = listOf("185.34.22.10/login")
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.50f,
            edgeNlpScore = 0.40f,
            edgeStructuralScore = 0.20f
        )

        assertEquals(ThreatCategory.PHISHING, result.category)
    }

    @Test
    fun testAcademicAnnouncementDoesNotBecomeDangerFromNlpOnly() {
        val content = ExtractedContent(
            rawText = "This email details a Department of CSE mini project presentation titled " +
                "Soil NPK Recommendation System from Kongu Engineering College students and faculty."
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.01f,
            edgeNlpScore = 0.95f,
            edgeStructuralScore = 0.0f,
            geminiCloudScore = 0,
            geminiReason = "The context is entirely academic and legitimate."
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertEquals(ThreatCategory.SAFE, result.category)
        assertTrue(result.riskScore < 30)
    }

    @Test
    fun testAcademicWordsDoNotMaskCredentialOrPaymentFraud() {
        val content = ExtractedContent(
            rawText = "University scholarship: claim now and enter your UPI PIN at " +
                "upi://pay?pa=fake@upi&mode=collect",
            urls = listOf("upi://pay?pa=fake@upi&mode=collect")
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.10f,
            edgeNlpScore = 0.95f,
            edgeStructuralScore = 0.10f,
            geminiCloudScore = 0
        )

        assertEquals(ThreatVerdict.DANGER, result.verdict)
    }

    @Test
    fun testAgriculturalSpreadsheetDoesNotBecomeDangerFromNlpOnly() {
        val content = ExtractedContent(
            rawText = "AgriData_Dist.xls Crop Soil N P K temperature humidity rainfall " +
                "rice loamy 90 42 43 20.8 82 202.9 maize sandy 78 43 37 21.7 80 226.1 " +
                "pulses black 20 68 19 20.9 82 202.9"
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.0f,
            edgeNlpScore = 0.95f,
            edgeStructuralScore = 0.0f,
            geminiCloudScore = 0,
            geminiReason = "This is an agricultural dataset containing crop and soil measurements."
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertEquals(ThreatCategory.SAFE, result.category)
        assertTrue(result.riskScore < 30)
    }

    @Test
    fun testSpreadsheetTermsDoNotMaskSuspiciousLinkFraud() {
        val content = ExtractedContent(
            rawText = "Crop dataset download: verify now at http://secure-bank-login.xyz to keep access",
            urls = listOf("http://secure-bank-login.xyz")
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.95f,
            edgeNlpScore = 0.95f,
            edgeStructuralScore = 0.30f
        )

        assertEquals(ThreatVerdict.DANGER, result.verdict)
    }

    @Test
    fun testIsolatedOtpReferenceCannotBecomeDangerFromNlpOnly() {
        val content = ExtractedContent(
            rawText = "Your Google verification code is 482910. Do not share this code with anyone."
        )

        val result = engine.evaluate(
            content = content,
            edgeNlpScore = 0.95f,
            geminiCloudScore = 0
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertEquals(ThreatCategory.SAFE, result.category)
        assertTrue(result.riskScore < 30)
    }

    @Test
    fun testSingleBlockedWordCannotBecomeWarningFromNlpOnly() {
        val content = ExtractedContent(
            rawText = "Your debit card is blocked for scheduled maintenance until 3 PM."
        )

        val result = engine.evaluate(
            content = content,
            edgeNlpScore = 0.95f,
            geminiCloudScore = 0
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertTrue(result.riskScore < 30)
    }

    @Test
    fun testTanglishScamWithShortLinkIsDangerAndUsesTamilPresentation() {
        val content = ExtractedContent(
            rawText = "Unga bank account block aagum. Udane verify pannunga at https://bit.ly/check-now",
            urls = listOf("https://bit.ly/check-now")
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.10f,
            edgeNlpScore = 0.85f,
            edgeStructuralScore = 0.50f,
            geminiCloudScore = 0
        )

        assertEquals(ThreatVerdict.DANGER, result.verdict)
        assertTrue(result.isTamilContent)
    }

    @Test
    fun testOneTanglishLikeWordDoesNotChangeEnglishSafeMessage() {
        val content = ExtractedContent(rawText = "The Panam bakery opens tomorrow morning.")

        val result = engine.evaluate(
            content = content,
            edgeNlpScore = 0.95f,
            geminiCloudScore = 0
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertFalse(result.isTamilContent)
    }

    @Test
    fun testGitHubUrlEvaluatesSafe() {
        val content = ExtractedContent(
            rawText = "Check out our project repository at https://github.com/sha1062007-cmd/STDAPP for the latest code changes.",
            urls = listOf("https://github.com/sha1062007-cmd/STDAPP")
        )

        val result = engine.evaluate(
            content = content,
            edgeUrlScore = 0.0f,
            edgeNlpScore = 0.05f,
            edgeStructuralScore = 0.0f,
            geminiCloudScore = 0
        )

        assertEquals(ThreatVerdict.SAFE, result.verdict)
        assertEquals(ThreatCategory.SAFE, result.category)
        assertTrue(result.riskScore < 30)
    }
}
