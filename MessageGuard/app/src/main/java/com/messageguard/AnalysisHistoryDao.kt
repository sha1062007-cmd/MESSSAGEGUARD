package com.messageguard

import androidx.lifecycle.LiveData
import androidx.room.*

@Dao
interface AnalysisHistoryDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(result: AnalysisResult): Long

    @Delete
    suspend fun delete(result: AnalysisResult)

    @Query("DELETE FROM analysis_history WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT * FROM analysis_history ORDER BY timestamp DESC")
    fun getAllLive(): LiveData<List<AnalysisResult>>

    @Query("SELECT * FROM analysis_history ORDER BY timestamp DESC LIMIT 5")
    fun getRecentFiveLive(): LiveData<List<AnalysisResult>>

    @Query("SELECT * FROM analysis_history WHERE verdict = :verdict ORDER BY timestamp DESC")
    fun getByVerdictLive(verdict: Verdict): LiveData<List<AnalysisResult>>

    @Query("SELECT COUNT(*) FROM analysis_history WHERE timestamp >= :startOfDay")
    suspend fun countToday(startOfDay: Long): Int

    @Query("SELECT COUNT(*) FROM analysis_history WHERE verdict = :verdict AND timestamp >= :startOfDay")
    suspend fun countTodayByVerdict(verdict: Verdict, startOfDay: Long): Int

    @Query("SELECT * FROM analysis_history WHERE id = :id")
    suspend fun getById(id: Long): AnalysisResult?

    @Query("SELECT * FROM analysis_history WHERE sender = :sender ORDER BY timestamp DESC")
    suspend fun getBySender(sender: String): List<AnalysisResult>

    @Query("SELECT * FROM analysis_history ORDER BY timestamp DESC")
    suspend fun getAll(): List<AnalysisResult>

    @Query("SELECT COUNT(*) FROM analysis_history WHERE timestamp < :cutoffTimestamp")
    suspend fun countOlderThan(cutoffTimestamp: Long): Int

    @Query("DELETE FROM analysis_history WHERE timestamp < :cutoffTimestamp")
    suspend fun deleteScansOlderThan(cutoffTimestamp: Long): Int

    @Query("SELECT COUNT(*) FROM analysis_history")
    suspend fun countAll(): Int

    @Query("SELECT COUNT(*) FROM analysis_history WHERE verdict = :verdict")
    suspend fun countByVerdict(verdict: Verdict): Int

    @Query("UPDATE analysis_history SET reviewed = 1, userFeedback = :feedback WHERE id = :id")
    suspend fun submitFeedback(id: Long, feedback: String)

    @Query("DELETE FROM analysis_history")
    suspend fun clearAll()
}
