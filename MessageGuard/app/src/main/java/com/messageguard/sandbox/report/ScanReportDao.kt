package com.messageguard.sandbox.report

import androidx.lifecycle.LiveData
import androidx.room.*

@Dao
interface ScanReportDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(report: ScanReport)

    /** Live stream for the list screen — Room delivers on main thread. */
    @Query("SELECT * FROM scan_reports ORDER BY timestamp DESC")
    fun getAllLive(): LiveData<List<ScanReport>>

    @Query("SELECT * FROM scan_reports WHERE id = :id")
    suspend fun getById(id: String): ScanReport?

    /** Mark a report as user-flagged false positive with an optional note. */
    @Query("UPDATE scan_reports SET isFalsePositiveFlagged = 1, userNote = :note WHERE id = :id")
    suspend fun flagFalsePositive(id: String, note: String)

    @Query("SELECT COUNT(*) FROM scan_reports")
    suspend fun countAll(): Int
}
