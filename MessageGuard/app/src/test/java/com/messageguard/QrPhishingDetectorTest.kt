package com.messageguard

import org.junit.Assert.*
import org.junit.Test

class QrPhishingDetectorTest {

    @Test
    fun `isKnownPhishingPayload identifies fake UPI collect requests`() {
        val payload = "upi://pay?pa=scammer@upi&pn=Prize&am=5000&tr=123&mode=collect"
        assertTrue("Fake UPI collect request in QR must be flagged", QrPhishingDetector.isKnownPhishingPayload(payload))
    }

    @Test
    fun `isKnownPhishingPayload allows standard payment link`() {
        val payload = "upi://pay?pa=store@okicici&pn=Merchant&am=100"
        assertFalse("Standard merchant UPI QR should not be flagged by simple payload check", QrPhishingDetector.isKnownPhishingPayload(payload))
    }

    @Test
    fun `typosquatted domain in QR is flagged via SpamAnalyzer analyzeDomain`() {
        val domainResult = SpamAnalyzer.analyzeDomain("https://paypa1.com/qr-verify")
        assertTrue("Typosquatted domain extracted from QR must be flagged", domainResult.isTyposquat)
    }

    @Test
    fun `homograph domain in QR is flagged via SpamAnalyzer analyzeDomain`() {
        val domainResult = SpamAnalyzer.analyzeDomain("https://xn--pple-43d.com/pay")
        assertTrue("Homograph domain extracted from QR must be flagged", domainResult.isHomograph)
    }
}
