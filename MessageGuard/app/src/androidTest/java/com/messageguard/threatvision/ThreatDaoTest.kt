package com.messageguard.threatvision

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.messageguard.AnalysisHistoryDatabase
import com.messageguard.threatvision.data.local.ThreatDao
import com.messageguard.threatvision.data.local.entity.ThreatScanEntity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ThreatDaoTest {

    private lateinit var database: AnalysisHistoryDatabase
    private lateinit var dao: ThreatDao

    @Before
    fun createDb() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            AnalysisHistoryDatabase::class.java
        ).allowMainThreadQueries().build()
        dao = database.threatDao()
    }

    @After
    fun closeDb() {
        database.close()
    }

    @Test
    fun testInsertAndGetScanById() = runBlocking {
        val scan = ThreatScanEntity(
            extractedText = "Phishing alert message text",
            extractedUrls = "http://phish-site.top",
            riskScore = 92,
            verdict = "DANGER",
            threatCategory = "PHISHING",
            detectionReason = "High risk phishing link detected",
            recommendedActions = "Do not click link|Block sender",
            timestamp = System.currentTimeMillis()
        )

        val insertedId = dao.insertScan(scan)
        val retrieved = dao.getScanById(insertedId)

        assertNotNull(retrieved)
        assertEquals("Phishing alert message text", retrieved?.extractedText)
        assertEquals("DANGER", retrieved?.verdict)
        assertEquals(92, retrieved?.riskScore)
    }

    @Test
    fun testGetAllScansAndClear() = runBlocking {
        val scan1 = ThreatScanEntity(
            extractedText = "Text 1",
            extractedUrls = "http://test1.com",
            riskScore = 30,
            verdict = "SAFE",
            threatCategory = "SAFE",
            detectionReason = "Normal message",
            recommendedActions = "None",
            timestamp = 1000L
        )

        val scan2 = ThreatScanEntity(
            extractedText = "Text 2",
            extractedUrls = "http://test2.xyz",
            riskScore = 85,
            verdict = "DANGER",
            threatCategory = "PHISHING",
            detectionReason = "Phishing domain",
            recommendedActions = "Do not click",
            timestamp = 2000L
        )

        dao.insertScan(scan1)
        dao.insertScan(scan2)

        val listBeforeClear = dao.getAllScans().first()
        assertEquals(2, listBeforeClear.size)
        assertEquals("Text 2", listBeforeClear[0].extractedText) // DESC timestamp order

        dao.clearAllScans()

        val listAfterClear = dao.getAllScans().first()
        assertEquals(0, listAfterClear.size)
    }
}
