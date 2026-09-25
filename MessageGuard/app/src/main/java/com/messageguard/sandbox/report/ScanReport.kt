package com.messageguard.sandbox.report

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Persists every sandbox scan result (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE).
 * Stored in the "scan_reports" table — separate from the message-scan "analysis_history"
 * table, since these are file scans with a different signal breakdown.
 */
@Entity(tableName = "scan_reports")
data class ScanReport(
    /** Matches SandboxItem.id — serves as the natural primary key. */
    @PrimaryKey val id: String,
    val fileName: String,
    val sourceApp: String,
    val sha256: String,
    val timestamp: Long,
    /** ScanVerdict.name — SAFE / SUSPICIOUS / MALICIOUS / INCONCLUSIVE */
    val verdict: String,
    val finalScore: Int,
    val structuralScore: Int,
    val ensembleScore: Int,
    val entropy: Double,
    /**
     * JSON array of finding objects: [{cat, desc, sev}, …]
     * Stored as text so no extra type-converter is needed.
     */
    val findingsJson: String,
    /** True when the user has tapped "This looks wrong" on this scan. */
    val isFalsePositiveFlagged: Boolean = false,
    /** Optional free-text note submitted with the false-positive flag. */
    val userNote: String = ""
)
