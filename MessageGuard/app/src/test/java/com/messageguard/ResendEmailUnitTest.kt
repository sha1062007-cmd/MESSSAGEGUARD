package com.messageguard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ResendEmailUnitTest {

    @Test
    fun testResendApiPayloadAndKey() {
        val apiKey = BuildConfig.RESEND_API_KEY
        val alertFrom = BuildConfig.ALERT_FROM.ifBlank { "MessageGuard <onboarding@resend.dev>" }
        val alertTo = BuildConfig.ALERT_EMAIL

        println("\n=== RESEND API LIVE CONFIG CHECK ===")
        println("  RESEND_API_KEY Present : ${apiKey.isNotBlank()} (Length: ${apiKey.length})")
        println("  ALERT_FROM Address     : '$alertFrom'")
        println("  ALERT_TO Address       : '$alertTo'")

        assertTrue("ALERT_FROM must contain an email address", alertFrom.contains("@"))
        assertTrue("ALERT_EMAIL must contain an email address", alertTo.contains("@"))
        assertTrue("RESEND_API_KEY must not be blank in BuildConfig", apiKey.isNotBlank())
        println("=== RESEND API LIVE CONFIG CHECK PASSED ===\n")
    }
}
