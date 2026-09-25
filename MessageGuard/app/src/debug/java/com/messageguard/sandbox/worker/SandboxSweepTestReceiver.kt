package com.messageguard.sandbox.worker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager

/**
 * DEBUG SOURCE-SET ONLY (src/debug/java):
 * Never compiled, packaged, or merged into release builds.
 */
class SandboxSweepTestReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SandboxDetection"
        const val ACTION = "com.messageguard.SANDBOX_SWEEP_NOW"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION) return
        Log.i(TAG, "[SandboxSweepTestReceiver] Debug test sweep triggered.")

        val oneTimeRequest = OneTimeWorkRequestBuilder<PeriodicDownloadSweepWorker>().build()
        WorkManager.getInstance(context).enqueue(oneTimeRequest)
    }
}
