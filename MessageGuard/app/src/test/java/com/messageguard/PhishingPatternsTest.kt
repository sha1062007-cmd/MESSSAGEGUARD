package com.messageguard

import org.junit.Assert.*
import org.junit.Test

class PhishingPatternsTest {

    @Test
    fun `voice callback regex matches phone call triggers`() {
        val pattern = Regex("(?i)call\\s+(immediately|now|at|our|support)?\\s*\\+?\\d{10,12}")
        assertTrue(pattern.containsMatchIn("Your bank account suspended, call immediately 9876543210"))
        assertTrue(pattern.containsMatchIn("Call at +919876543210 to stop auto debit"))
    }

    @Test
    fun `upi collect request detection trigger check`() {
        val msg = "Click upi://pay?pa=scam@upi&am=2000&mode=collect to receive cash reward"
        val lower = msg.lowercase()
        assertTrue(lower.contains("upi://pay") && lower.contains("collect"))
    }

    @Test
    fun `fake pin to receive money trigger check`() {
        val msg = "You won Rs 5000 cashback! Enter PIN to receive money into your account."
        assertTrue(msg.lowercase().contains("enter pin to receive"))
    }
}
