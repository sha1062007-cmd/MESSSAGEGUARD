package com.messageguard.sandbox.worker

import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.messageguard.sandbox.coordinator.SandboxClaimCoordinator
import com.messageguard.sandbox.trigger.DownloadFilterPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Fallback Trigger (1d): Periodic sweep for uncaptured downloads.
 * Sweeps MediaStore for recent files (last 2 minutes) enforcing the exact same
 * DownloadFilterPolicy as MediaStoreDownloadObserver.
 */
class PeriodicDownloadSweepWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    companion object {
        private const val TAG = "SandboxDetection"
        private const val WORK_NAME = "PeriodicDownloadSweepWork"
        private const val LOOKBACK_WINDOW_MS = 120_000L // 2 minutes

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(false)
                .build()

            val workRequest = PeriodicWorkRequestBuilder<PeriodicDownloadSweepWorker>(
                15, TimeUnit.MINUTES,
                5, TimeUnit.MINUTES // Flex interval
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                workRequest
            )
            Log.d(TAG, "PeriodicDownloadSweepWorker enqueued with unique policy KEEP (interval: 15m, flex: 5m).")
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            Log.d(TAG, "PeriodicDownloadSweepWorker cancelled.")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val resolver = applicationContext.contentResolver
            val cutoffSeconds = (System.currentTimeMillis() - LOOKBACK_WINDOW_MS) / 1000

            val queryUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                MediaStore.Downloads.EXTERNAL_CONTENT_URI
            } else {
                MediaStore.Files.getContentUri("external")
            }

            val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.RELATIVE_PATH,
                    MediaStore.MediaColumns.DATE_ADDED
                )
            } else {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.DATA,
                    MediaStore.MediaColumns.DATE_ADDED
                )
            }

            val selection = "${MediaStore.MediaColumns.DATE_ADDED} >= ?"
            val selectionArgs = arrayOf(cutoffSeconds.toString())

            Log.i(TAG, "[PeriodicSweep] Starting sweep with cutoffSeconds=$cutoffSeconds (lookback: ${LOOKBACK_WINDOW_MS / 1000}s) on URI=$queryUri")
            resolver.query(queryUri, projection, selection, selectionArgs, "${MediaStore.MediaColumns.DATE_ADDED} DESC")?.use { cursor ->
                Log.i(TAG, "[PeriodicSweep] Query returned ${cursor.count} rows.")
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID))
                    val displayName = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)) ?: "unnamed_file"
                    val size = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.SIZE))
                    val dateAdded = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATE_ADDED))

                    val relativePath = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.RELATIVE_PATH)) ?: ""
                    } else {
                        cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATA)) ?: ""
                    }

                    Log.d(TAG, "[PeriodicSweep] Inspecting: '$displayName' (id=$id, size=$size, path='$relativePath', dateAdded=$dateAdded)")

                    // Enforce the exact same DownloadFilterPolicy (no screenshot / DCIM leakage on pre-Q)
                    if (!DownloadFilterPolicy.isQualifyingDownload(displayName, size, relativePath)) {
                        Log.d(TAG, "[PeriodicSweep] Filter rejected: '$displayName'")
                        continue
                    }

                    val itemUri = Uri.withAppendedPath(queryUri, id.toString())
                    val uriKey = itemUri.toString()
                    val claimed = SandboxClaimCoordinator.tryClaim(uriKey, "PeriodicSweepWorker")
                    if (claimed) {
                        // Path-aware primed intent correlation
                        val primed = SandboxClaimCoordinator.matchPrimedIntentForPath(relativePath)
                        if (primed != null) {
                            Log.i(TAG, "[PeriodicSweep] Correlated missed file '$displayName' with primed intent from '${primed.sourcePackage}' (${primed.intentType}) based on path '$relativePath'!")
                        }
                        Log.i(TAG, "[PeriodicSweep] Claimed previously missed download '$displayName' (URI=$uriKey)")
                    } else {
                        Log.d(TAG, "[PeriodicSweep] Claim skipped for '$displayName' (already claimed or active)")
                    }
                }
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "PeriodicDownloadSweepWorker encountered an error", e)
            Result.failure()
        }
    }
}
