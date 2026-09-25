package com.messageguard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatSignalPolicyTest {

    @Test
    fun `legitimate OTP safety advice is not a scam signal`() {
        val signals = ThreatSignalPolicy.analyze(
            "Your Google verification code is 482910. Do not share this code with anyone."
        )

        assertEquals(0, signals.count)
        assertFalse(signals.isCorroborated)
    }

    @Test
    fun `blocked maintenance notice is one signal not a threat verdict`() {
        val signals = ThreatSignalPolicy.analyze(
            "Your debit card is blocked for scheduled maintenance until 3 PM."
        )

        assertEquals(1, signals.count)
        assertFalse(signals.isCorroborated)
    }

    @Test
    fun `urgent request to share OTP is corroborated`() {
        val signals = ThreatSignalPolicy.analyze(
            "Urgent: share your OTP immediately to restore access."
        )

        assertTrue(signals.hasUrgency)
        assertTrue(signals.hasCredentialRequest)
        assertTrue(signals.isCorroborated)
        assertEquals(ThreatSignalPolicy.Confidence.MEDIUM, signals.confidence)
    }

    @Test
    fun `strong phishing email triggers HIGH confidence`() {
        val signals = ThreatSignalPolicy.analyze(
            "Urgent: Click here to verify your account immediately and share your OTP or claim your prize money."
        )

        assertTrue(signals.count >= 3)
        assertEquals(ThreatSignalPolicy.Confidence.HIGH, signals.confidence)
    }

    @Test
    fun `weak email triggers LOW confidence`() {
        val signals = ThreatSignalPolicy.analyze(
            "Hello, your statement is ready for review."
        )

        assertEquals(0, signals.count)
        assertEquals(ThreatSignalPolicy.Confidence.LOW, signals.confidence)
    }
}
