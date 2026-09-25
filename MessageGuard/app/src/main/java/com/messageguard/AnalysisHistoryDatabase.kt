package com.messageguard

import android.content.Context
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.messageguard.sandbox.report.ScanReport
import com.messageguard.sandbox.report.ScanReportDao

@Database(entities = [AnalysisResult::class, ScanReport::class], version = 8, exportSchema = false)
@TypeConverters(StringListConverter::class, VerdictConverter::class)
abstract class AnalysisHistoryDatabase : RoomDatabase() {
    abstract fun dao(): AnalysisHistoryDao
    abstract fun scanReportDao(): ScanReportDao

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

        @Volatile private var INSTANCE: AnalysisHistoryDatabase? = null
        fun getInstance(context: Context): AnalysisHistoryDatabase =
            INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(
                    context.applicationContext,
                    AnalysisHistoryDatabase::class.java,
                    "messageguard_db"
                )
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8)
                .fallbackToDestructiveMigration()
                .build().also { INSTANCE = it }
            }
    }
}

