package com.messageguard

import android.content.Context
import androidx.lifecycle.LiveData
import java.util.Calendar

class AnalysisRepository(context: Context) {
    private val dao = AnalysisHistoryDatabase.getInstance(context).dao()

    suspend fun insert(result: AnalysisResult) = dao.insert(result)
    suspend fun deleteById(id: Long) = dao.deleteById(id)
    suspend fun clearAll() = dao.clearAll()
    suspend fun getById(id: Long) = dao.getById(id)
    suspend fun submitFeedback(id: Long, feedback: String) = dao.submitFeedback(id, feedback)
    
    fun getAllLive(): LiveData<List<AnalysisResult>> = dao.getAllLive()
    fun getRecentFiveLive(): LiveData<List<AnalysisResult>> = dao.getRecentFiveLive()
    fun getByVerdictLive(v: Verdict): LiveData<List<AnalysisResult>> = dao.getByVerdictLive(v)

    suspend fun getDashboardStats(): DashboardStats {
        val today = Calendar.getInstance().apply {
            set(Calendar.HOUR_OF_DAY, 0)
            set(Calendar.MINUTE, 0)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }.timeInMillis
        
        return DashboardStats(
            totalToday = dao.countToday(today),
            dangersFound = dao.countTodayByVerdict(Verdict.DANGER, today),
            safeCount = dao.countTodayByVerdict(Verdict.SAFE, today),
            warningCount = dao.countTodayByVerdict(Verdict.WARNING, today),
            totalOverall = dao.countAll(),
            safeOverall = dao.countByVerdict(Verdict.SAFE)
        )
    }
}
