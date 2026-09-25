package com.messageguard

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests unrelated to PreExecutionScanner.
 * Scanner tests have been moved to PreExecutionScannerTest.kt.
 */
class SandboxAndAccuracyOverhaulTest {

    @Test
    fun testFuzzyAdversarialTanglishDetection() {
        val adversarialTanglish = "u n g a bank account bl0ck aagum. udane verify p@nnungaaa!"
        val detection = MessageLanguageDetector.detectTanglish(adversarialTanglish)
        assertTrue("Fuzzy matching and leetspeak de-obfuscation must identify adversarial Tanglish", detection.isDetected)
    }

    @Test
    fun testFuzzyAdversarialHinglishDetection() {
        val adversarialHinglish = "a a p k a bank khata b@nd ho jayega. turant verify karein."
        val isHinglish = MessageLanguageDetector.detectHinglish(adversarialHinglish)
        assertTrue("Fuzzy matching and leetspeak de-obfuscation must identify adversarial Hinglish", isHinglish)
    }

    @Test
    fun testScriptDetectionDevanagariAndTelugu() {
        val hindiMessage = "आपका बैंक खाता ब्लॉक कर दिया गया है। तुरंत सत्यापित करें।"
        val teluguMessage = "మీ బ్యాంక్ ఖాతా బ్లాక్ చేయబడింది. వెంటనే ధృవీకరించండి."

        assertTrue(MessageLanguageDetector.containsDevanagariScript(hindiMessage))
        assertTrue(MessageLanguageDetector.containsTeluguScript(teluguMessage))
        assertTrue(MessageLanguageDetector.isRegionalLanguage(hindiMessage))
        assertTrue(MessageLanguageDetector.isRegionalLanguage(teluguMessage))
    }

    @Test
    fun testCleanRegionalMessagesDoNotFalsePositive() {
        val cleanTanglish = "Innikki evening vangi pakkathula irukkura bakery la meet pannalam."
        val cleanHinglish = "Kal maine naya bank khata khulwaya savings ke liye."
        val cleanEnglishWithFuzzyToken = "Please pack all your belongings before leaving the room."

        val tanglishResult = MessageLanguageDetector.detectTanglish(cleanTanglish)
        assertFalse("Clean conversational sentence with isolated location reference should not trigger Tanglish scam detection", tanglishResult.isDetected)

        val hinglishResult = MessageLanguageDetector.detectHinglish(cleanHinglish)
        assertFalse("Clean informational sentence with single banking noun should not trigger Hinglish scam detection", hinglishResult)

        val englishResult = MessageLanguageDetector.detectTanglish(cleanEnglishWithFuzzyToken)
        assertFalse("Clean English text with coincidental words should not trigger Tanglish detection", englishResult.isDetected)
    }

    @Test
    fun testBankCertificatePinningFormat() {
        val sbiSha256 = "B883AC905D41F59D1D5A32BC562B28593F3804F5E68C697B76D743FE40306F85"
        assertEquals(64, sbiSha256.length)
        assertTrue(sbiSha256.all { it in '0'..'9' || it in 'A'..'F' })
    }
}
