package com.messageguard

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

class AutoExportWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            Log.d("AutoExportWorker", "Starting weekly auto-export background task...")
            val db = AnalysisHistoryDatabase.getInstance(applicationContext)
            val dao = db.dao()
            val results = dao.getAll()
            if (results.isNotEmpty()) {
                val path = StorageHelper.exportDatabaseToExcel(applicationContext, results)
                Log.d("AutoExportWorker", "Auto-export succeeded. File written to: $path")
            } else {
                Log.d("AutoExportWorker", "No logs found to export.")
            }
            Result.success()
        } catch (e: Exception) {
            Log.e("AutoExportWorker", "Auto-export task failed", e)
            Result.failure()
        }
    }

    companion object {
        private const val WORK_NAME = "WeeklyAutoExportWork"

        fun schedule(context: Context) {
            val workRequest = PeriodicWorkRequestBuilder<AutoExportWorker>(7, TimeUnit.DAYS)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                workRequest
            )
            Log.d("AutoExportWorker", "Weekly auto-export task scheduled.")
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            Log.d("AutoExportWorker", "Weekly auto-export task cancelled.")
        }
    }
}
