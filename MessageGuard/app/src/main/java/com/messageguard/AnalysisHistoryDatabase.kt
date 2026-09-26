package com.messageguard

import android.content.Context
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.messageguard.sandbox.report.ScanReport
import com.messageguard.sandbox.report.ScanReportDao
import com.messageguard.threatvision.data.local.entity.ThreatScanEntity
import com.messageguard.threatvision.data.local.ThreatDao

@Database(entities = [AnalysisResult::class, ScanReport::class, ThreatScanEntity::class], version = 11, exportSchema = false)
@TypeConverters(StringListConverter::class, VerdictConverter::class)
abstract class AnalysisHistoryDatabase : RoomDatabase() {
    abstract fun dao(): AnalysisHistoryDao
    abstract fun scanReportDao(): ScanReportDao
    abstract fun threatDao(): ThreatDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Initial migration step for database version 1 to 2
            }
        }

        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN messageSnippet TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN reviewed INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN userFeedback TEXT DEFAULT NULL")
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN flaggedUrls TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN explainabilityJson TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN typosquatFlag INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN senderReputationScore REAL NOT NULL DEFAULT 0.0")
            }
        }

        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Create the new scan_reports table for file sandbox scan results.
                // Kept separate from analysis_history (message scans) — different data domain.
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS scan_reports (
                        id TEXT NOT NULL PRIMARY KEY,
                        fileName TEXT NOT NULL DEFAULT '',
                        sourceApp TEXT NOT NULL DEFAULT '',
                        sha256 TEXT NOT NULL DEFAULT '',
                        timestamp INTEGER NOT NULL DEFAULT 0,
                        verdict TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
                        finalScore INTEGER NOT NULL DEFAULT 0,
                        structuralScore INTEGER NOT NULL DEFAULT 0,
                        ensembleScore INTEGER NOT NULL DEFAULT 0,
                        entropy REAL NOT NULL DEFAULT 0.0,
                        findingsJson TEXT NOT NULL DEFAULT '[]',
                        isFalsePositiveFlagged INTEGER NOT NULL DEFAULT 0,
                        userNote TEXT NOT NULL DEFAULT ''
                    )
                """.trimIndent())
            }
        }

        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN uncertaintyReason TEXT DEFAULT NULL")
                db.execSQL("ALTER TABLE analysis_history ADD COLUMN modelDisagreementScore REAL NOT NULL DEFAULT 0.0")
            }
        }

        /**
         * MIGRATION_8_9 — Stale SIH label scrub (Sept 25 fix)
         *
         * Background: Early scan records stored "SIH Problem Statement: SIH25106" (and
         * similar variants) inside the `category` column at scan-time.  The label was
         * corrected to SIH26106 in source code, but persisted rows kept the old value.
         * This migration clears any category value that contains a stale SIH reference so
         * those rows display the current canonical label rather than a baked-in old value.
         *
         * The category field is for threat-class tags (e.g. "PHISHING") — not for
         * problem-statement numbers — so rows that carry stale SIH data are reset to '' .
         */
        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Clear any category values that embed a stale SIH label.
                // Rows with legitimate threat-class categories (PHISHING, SPAM, etc.)
                // do NOT contain "SIH" so are unaffected.
                db.execSQL(
                    "UPDATE analysis_history SET category = '' " +
                    "WHERE category LIKE '%SIH25106%' OR category LIKE '%SIH26106%' " +
                    "OR category LIKE '%Problem Statement%'"
                )
            }
        }

        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE analysis_history ADD COLUMN backendAnalysisJson TEXT NOT NULL DEFAULT ''"
                )
            }
        }

        class Migration10To11(private val context: Context) : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS `threat_scans` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `extractedText` TEXT NOT NULL,
                        `extractedUrls` TEXT NOT NULL,
                        `riskScore` INTEGER NOT NULL,
                        `verdict` TEXT NOT NULL,
                        `threatCategory` TEXT NOT NULL,
                        `detectionReason` TEXT NOT NULL,
                        `recommendedActions` TEXT NOT NULL,
                        `timestamp` INTEGER NOT NULL
                    )
                """.trimIndent())

                val oldDbFile = context.getDatabasePath("threat_vision_database")
                if (oldDbFile.exists() && oldDbFile.isFile) {
                    try {
                        android.database.sqlite.SQLiteDatabase.openDatabase(
                            oldDbFile.absolutePath,
                            null,
                            android.database.sqlite.SQLiteDatabase.OPEN_READONLY
                        ).use { oldDb ->
                            val cursor = oldDb.rawQuery(
                                "SELECT id, extractedText, extractedUrls, riskScore, verdict, threatCategory, detectionReason, recommendedActions, timestamp FROM threat_scans",
                                null
                            )
                            cursor.use { c ->
                                while (c.moveToNext()) {
                                    val id = c.getLong(0)
                                    val extractedText = c.getString(1)
                                    val extractedUrls = c.getString(2)
                                    val riskScore = c.getInt(3)
                                    val verdict = c.getString(4)
                                    val threatCategory = c.getString(5)
                                    val detectionReason = c.getString(6)
                                    val recommendedActions = c.getString(7)
                                    val timestamp = c.getLong(8)

                                    db.execSQL(
                                        """
                                        INSERT OR IGNORE INTO threat_scans (
                                            id, extractedText, extractedUrls, riskScore, verdict, 
                                            threatCategory, detectionReason, recommendedActions, timestamp
                                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                        """.trimIndent(),
                                        arrayOf<Any>(
                                            id, extractedText, extractedUrls, riskScore, verdict,
                                            threatCategory, detectionReason, recommendedActions, timestamp
                                        )
                                    )
                                }
                            }
                        }
                    } catch (e: Exception) {
                        android.util.Log.e("AnalysisHistoryDatabase", "CRITICAL: MIGRATION_10_11 data copy failed from ${oldDbFile.absolutePath}", e)
                        throw e
                    }
                }
            }
        }

        @Volatile private var INSTANCE: AnalysisHistoryDatabase? = null
        fun getInstance(context: Context): AnalysisHistoryDatabase =
            INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(
                    context.applicationContext,
                    AnalysisHistoryDatabase::class.java,
                    "messageguard_db"
                )
                .addMigrations(
                    MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5,
                    MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9,
                    MIGRATION_9_10, Migration10To11(context.applicationContext)
                )
                .build().also { INSTANCE = it }
            }
    }
}
