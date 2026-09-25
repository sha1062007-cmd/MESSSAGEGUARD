package com.messageguard.threatvision

import com.messageguard.threatvision.domain.ocr.MlKitTextRecognizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MlKitTextRecognizerTest {

    @Test
    fun testRegexExtraction() {
        val sampleText = """
            Urgent: Update your account details at http://secure-bank.xyz or www.login-verify.top or bare-phish-domain.com!
            Contact support at +1-800-555-0199 or help@bank-security.com.
        """.trimIndent()

        val urls = MlKitTextRecognizer.extractUrls(sampleText)
        val phones = MlKitTextRecognizer.extractPhoneNumbers(sampleText)
        val emails = MlKitTextRecognizer.extractEmails(sampleText)

        assertEquals(3, urls.size)
        assertTrue(urls.contains("http://secure-bank.xyz"))
        assertTrue(urls.contains("www.login-verify.top"))
        assertTrue(urls.contains("bare-phish-domain.com"))

        assertEquals(1, phones.size)
        assertTrue(phones.contains("+1-800-555-0199"))

        assertEquals(1, emails.size)
        assertEquals("help@bank-security.com", emails[0])
    }

    @Test
    fun testNormalProseFalsePositives() {
        val proseText = """
            See you at 5 p.m. near St. Mary's, thanks.
            Please review report.pdf before 10 a.m., e.g., check version 2.0 at Dr. Smith's office.
        """.trimIndent()

        val extractedUrls = MlKitTextRecognizer.extractUrls(proseText)
        assertEquals("Prose containing abbreviations and file extensions should extract zero URLs", 0, extractedUrls.size)
    }

    @Test
    fun testBareIpv4UrlExtraction() {
        val ipv4Text = """
            Security Alert: Verify your account immediately at http://185.34.22.10/login or bare IP 192.168.1.50/admin!
        """.trimIndent()

        val extractedUrls = MlKitTextRecognizer.extractUrls(ipv4Text)
        assertEquals(2, extractedUrls.size)
        assertTrue(extractedUrls.contains("http://185.34.22.10/login"))
        assertTrue(extractedUrls.contains("192.168.1.50/admin"))
    }
}
