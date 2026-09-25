package com.messageguard

import org.junit.Assert.*
import org.junit.Test

/**
 * Regression test: verify callback-scam regex does NOT false-positive
 * on ordinary messages containing phone numbers.
 */
class CallbackScamRegressionTest {

    private val callbackScamPatterns = listOf(
        Regex("(?i)call\\s+(immediately|urgently|now\\s+to)\\s*\\+?\\d{10,12}"),
        Regex("(?i)call\\s+toll\\s*free\\s*\\d+\\s+to\\s+(verify|prevent|stop|unblock)"),
        Regex("(?i)contact\\s+(support|helpdesk|executive)\\s+(at|on)\\s+\\+?\\d+\\s+to\\s+(verify|unblock)"),
        Regex("(?i)dial\\s+\\+?\\d{10,12}\\s+to\\s+(stop|prevent|unblock)")
    )

    private fun matchesAny(message: String): Boolean {
        return callbackScamPatterns.any { it.containsMatchIn(message) }
    }

    // --- Should NOT fire (benign messages) ---

    @Test
    fun `benign office number is NOT flagged`() {
        assertFalse(
            "Legitimate office number should not trigger callback scam",
            matchesAny("For help, call our office at 9876543210")
        )
    }

    @Test
    fun `delivery tracking with phone number is NOT flagged`() {
        assertFalse(
            "Delivery tracking message should not trigger callback scam",
            matchesAny("Your order has shipped. For tracking, call 18001234567")
        )
    }

    @Test
    fun `friend sharing number is NOT flagged`() {
        assertFalse(
            "Casual message with phone number should not trigger",
            matchesAny("Hey, call me at 9998887770 when you're free")
        )
    }

    // --- Should fire (actual scam patterns) ---

    @Test
    fun `urgent call scam IS flagged`() {
        assertTrue(
            "Urgent call scam should trigger",
            matchesAny("Your bank account suspended, call immediately 9876543210")
        )
    }

    @Test
    fun `dial to prevent block IS flagged`() {
        assertTrue(
            "Dial-to-prevent scam should trigger",
            matchesAny("Dial +919876543210 to prevent account block")
        )
    }

    @Test
    fun `contact support scam IS flagged`() {
        assertTrue(
            "Contact support scam should trigger",
            matchesAny("Contact support at +919876543210 to verify your identity")
        )
    }
}
