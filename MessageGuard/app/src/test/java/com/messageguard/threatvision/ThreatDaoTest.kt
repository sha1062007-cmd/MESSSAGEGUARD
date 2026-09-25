package com.messageguard.threatvision

import com.messageguard.threatvision.data.local.entity.ThreatScanEntity
import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatDaoTest {

    @Test
    fun testScanEntityConstruction() {
        val entity = ThreatScanEntity(
            id = 101L,
            extractedText = "Suspicious message body",
            extractedUrls = "http://phish.xyz,http://scam.top",
            riskScore = 88,
            verdict = "DANGER",
            threatCategory = "PHISHING",
            detectionReason = "High risk phishing link detected",
            recommendedActions = "Do not click link|Never share OTP",
            timestamp = 1600000000000L
        )

        assertEquals(101L, entity.id)
        assertEquals("DANGER", entity.verdict)
        assertEquals("PHISHING", entity.threatCategory)
        assertEquals(88, entity.riskScore)
        assertEquals(2, entity.extractedUrls.split(",").size)
        assertEquals(2, entity.recommendedActions.split("|").size)
    }
}
