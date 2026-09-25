package com.messageguard

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Migration6To7InstrumentedTest {

    @Test
    fun testMigration6To7PreservesData() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dbName = "migration_test_live.db"
        context.deleteDatabase(dbName)

        val config = SupportSQLiteOpenHelper.Configuration.builder(context)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(6) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    db.execSQL("""
                        CREATE TABLE IF NOT EXISTS analysis_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                            timestamp INTEGER NOT NULL,
                            appSource TEXT NOT NULL,
                            sender TEXT NOT NULL,
                            subject TEXT NOT NULL,
                            verdict TEXT NOT NULL,
                            riskScore INTEGER NOT NULL,
                            category TEXT NOT NULL,
                            senderTrust TEXT NOT NULL,
                            summary TEXT NOT NULL,
                            flags TEXT NOT NULL,
                            action TEXT NOT NULL,
                            mlScore INTEGER NOT NULL,
                            aiScore INTEGER NOT NULL,
                            messageSnippet TEXT NOT NULL,
                            reviewed INTEGER NOT NULL,
                            userFeedback TEXT,
                            flaggedUrls TEXT NOT NULL,
                            explainabilityJson TEXT NOT NULL,
                            typosquatFlag INTEGER NOT NULL,
                            senderReputationScore REAL NOT NULL
                        )
                    """.trimIndent())

                    db.execSQL("""
                        INSERT INTO analysis_history (
                            id, timestamp, appSource, sender, subject, verdict, riskScore, category,
                            senderTrust, summary, flags, action, mlScore, aiScore, messageSnippet,
                            reviewed, userFeedback, flaggedUrls, explainabilityJson, typosquatFlag, senderReputationScore
                        ) VALUES (
                            101, 1600000000000, 'WhatsApp', '+919999999999', 'OTP Alert', 'DANGER', 90,
                            'PHISHING', 'LOW', 'Phishing attempt', '[]', 'BLOCK', 90, -1, 'Verify OTP now',
                            0, NULL, '', '[]', 0, 0.0
                        )
                    """.trimIndent())
                }

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {}
            })
            .build()

        val helper = FrameworkSQLiteOpenHelperFactory().create(config)
        val db = helper.writableDatabase

        // Execute MIGRATION_6_7
        AnalysisHistoryDatabase.MIGRATION_6_7.migrate(db)

        // 1. Verify pre-existing v6 record is intact
        val cursorHistory = db.query("SELECT id, sender, verdict, riskScore FROM analysis_history WHERE id = 101")
        assertTrue("Analysis history data must be intact after migration to v7", cursorHistory.moveToFirst())
        assertEquals(101L, cursorHistory.getLong(0))
        assertEquals("+919999999999", cursorHistory.getString(1))
        assertEquals("DANGER", cursorHistory.getString(2))
        assertEquals(90, cursorHistory.getInt(3))
        cursorHistory.close()

        // 2. Verify new scan_reports table exists and is fully functional
        db.execSQL("""
            INSERT INTO scan_reports (
                id, fileName, sourceApp, sha256, timestamp, verdict, finalScore,
                structuralScore, ensembleScore, entropy, findingsJson, isFalsePositiveFlagged, userNote
            ) VALUES (
                'test_report_id', 'sample.pdf', 'Chrome', 'abcdef', 1700000000000,
                'SUSPICIOUS', 30, 30, 0, 7.6, '[]', 0, ''
            )
        """.trimIndent())

        val cursorReport = db.query("SELECT id, fileName, verdict FROM scan_reports WHERE id = 'test_report_id'")
        assertTrue("scan_reports table must be present and queryable post migration", cursorReport.moveToFirst())
        assertEquals("test_report_id", cursorReport.getString(0))
        assertEquals("sample.pdf", cursorReport.getString(1))
        assertEquals("SUSPICIOUS", cursorReport.getString(2))
        cursorReport.close()

        db.close()
        context.deleteDatabase(dbName)
    }
}
