package com.messageguard

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageLanguageDetectorTest {

    @Test
    fun `native Tamil script selects Tamil presentation`() {
        assertTrue(MessageLanguageDetector.shouldUseTamil("உங்கள் வங்கி கணக்கு சரிபார்க்கப்பட வேண்டும்"))
    }

    @Test
    fun `Tanglish scam wording needs multiple indicators`() {
        val detection = MessageLanguageDetector.detectTanglish(
            "Unga bank account block aagum. Udane verify pannunga."
        )

        assertTrue(detection.isDetected)
        assertTrue(detection.matchedIndicators.size >= 2)
    }

    @Test
    fun `one coincidental Tanglish-like word does not change language`() {
        assertFalse(MessageLanguageDetector.shouldUseTamil("The Panam bakery opens tomorrow."))
    }
}
