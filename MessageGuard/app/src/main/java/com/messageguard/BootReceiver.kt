package com.messageguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = context.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
            if (prefs.getBoolean(Constants.KEY_SERVICE_ENABLED, true)) {
                com.messageguard.threatvision.service.FloatingBubbleService.startService(context)
                // Schedule Periodic Download Sweep Worker (persistent across reboots)
                com.messageguard.sandbox.worker.PeriodicDownloadSweepWorker.schedule(context)
            }
        }
    }
}

