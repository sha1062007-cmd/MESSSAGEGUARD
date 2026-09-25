package com.messageguard

import com.messageguard.sandbox.coordinator.DownloadIntentType
import com.messageguard.sandbox.coordinator.SandboxClaimCoordinator
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class SandboxAttributionTest {

    @Before
    fun clearState() {
        // Clear any primed intents from prior tests via reflection or by waiting for expiry
        // The coordinator's primedIntents is private, but we can use the public API to consume
        // Use a small window and let cleanup handle it; for test, just register and verify
    }

    @Test
    fun testWhatsAppAttributionViaPrimedIntent() {
        SandboxClaimCoordinator.registerExpectedDownload(
            sourcePackage = "com.whatsapp",
            intentType = DownloadIntentType.WHATSAPP_DOCUMENT,
            windowMs = 15_000L
        )
        // Peek should return WhatsApp
        val peeked = SandboxClaimCoordinator.peekPrimedIntent("com.whatsapp")
        assertNotNull("WhatsApp primed intent should be peekable", peeked)
        assertEquals("com.whatsapp", peeked!!.sourcePackage)
        assertEquals(DownloadIntentType.WHATSAPP_DOCUMENT, peeked.intentType)

        // Path-based peek for a WhatsApp doc saved to Download should still resolve via most-recent
        val recent = SandboxClaimCoordinator.getMostRecentPrimedIntent()
        assertNotNull("Most recent should be WhatsApp", recent)
        assertTrue(recent!!.sourcePackage.contains("whatsapp"))

        // Consume it to clean up
        val consumed = SandboxClaimCoordinator.matchAndConsumePrimedIntent("com.whatsapp")
        assertNotNull(consumed)
    }

    @Test
    fun testGmailAttributionViaPrimedIntent() {
        SandboxClaimCoordinator.registerExpectedDownload(
            sourcePackage = "com.google.android.gm",
            intentType = DownloadIntentType.GMAIL_ATTACHMENT,
            windowMs = 15_000L
        )
        val peeked = SandboxClaimCoordinator.peekPrimedIntent("com.google.android.gm")
        assertNotNull("Gmail primed intent should be peekable", peeked)
        assertEquals("com.google.android.gm", peeked!!.sourcePackage)

        // Path peek for a generic invoice in Download should resolve to Gmail when Gmail is most recent
        val pathPeek = SandboxClaimCoordinator.peekPrimedIntentForPath("Download/invoice.pdf")
        // For Download path, it peeks Gmail first, so should return Gmail
        assertNotNull(pathPeek)
        assertEquals("com.google.android.gm", pathPeek!!.sourcePackage)

        SandboxClaimCoordinator.matchAndConsumePrimedIntent("com.google.android.gm")
    }

    @Test
    fun testGenericDownloadAttributionFallback() {
        SandboxClaimCoordinator.registerExpectedDownload(
            sourcePackage = "com.android.chrome",
            intentType = DownloadIntentType.GENERIC_DOWNLOAD,
            windowMs = 15_000L
        )
        val recent = SandboxClaimCoordinator.getMostRecentPrimedIntent()
        assertNotNull(recent)
        assertEquals("com.android.chrome", recent!!.sourcePackage)
        SandboxClaimCoordinator.matchAndConsumePrimedIntent("com.android.chrome")
    }

    @Test
    fun testClaimDedupPreventsDuplicateScans() {
        val uri = "content://media/external/downloads/12345"
        val first = SandboxClaimCoordinator.tryClaim(uri, "ContentObserver")
        assertTrue("First claim should succeed", first)
        val second = SandboxClaimCoordinator.tryClaim(uri, "PeriodicSweepWorker")
        assertFalse("Second claim for same URI should be rejected (dedup)", second)
        // Clean up
        SandboxClaimCoordinator.markProcessed(uri)
        val third = SandboxClaimCoordinator.tryClaim(uri, "PeriodicSweepWorker")
        assertTrue("After markProcessed, claim should succeed again", third)
        SandboxClaimCoordinator.markProcessed(uri)
    }
}
