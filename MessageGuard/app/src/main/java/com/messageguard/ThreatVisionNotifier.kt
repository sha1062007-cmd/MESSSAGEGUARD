package com.messageguard

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * Unified system notification builder for all three scan paths:
 *   1. AccessibilityEngineService (notification/SMS scans)
 *   2. AnalyzeSelectedRegionUseCase (Circle-to-Scan)
 *   3. Email sync path (future Phase 12)
 *
 * Bug Fix (Phase 3, Bug 2): Previously, accessibility and Circle-to-Scan paths
 * produced overlay/TTS/email alerts but zero system notifications, while the
 * sandbox path did post system notifications. This class unifies all three.
 *
 * Thread-safe: all methods can be called from any thread.
 */
object ThreatVisionNotifier {

    const val CHANNEL_SECURITY  = "tv_security_alerts"
    const val CHANNEL_SYNC      = "tv_sync_status"

    private const val NOTIFICATION_ID_THREAT = 9001
    private const val NOTIFICATION_ID_SYNC   = 9002

    // Keeps in-memory auto-increment so multiple alerts do not overwrite each other
    private var nextThreatId = NOTIFICATION_ID_THREAT

    /**
     * Call once in MainActivity.onCreate() to register channels before any
     * notification is posted (required for Android O+).
     */
    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (nm.getNotificationChannel(CHANNEL_SECURITY) == null) {
            val ch = NotificationChannel(
                CHANNEL_SECURITY,
                "Threat Vision Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when a suspicious or dangerous message is detected"
                enableVibration(true)
                enableLights(true)
            }
            nm.createNotificationChannel(ch)
        }

        if (nm.getNotificationChannel(CHANNEL_SYNC) == null) {
            val ch = NotificationChannel(
                CHANNEL_SYNC,
                "Email Security Sync",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Summary after offline email security synchronisation"
            }
            nm.createNotificationChannel(ch)
        }
    }

    /**
     * Post a system notification for a DANGER or WARNING scan result.
     * Safe to call for SAFE verdicts — returns immediately without posting.
     */
    fun notifyThreatResult(context: Context, result: AnalysisResult) {
        if (result.verdict == Verdict.SAFE || result.verdict == Verdict.UNCERTAIN) return

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val icon = android.R.drawable.ic_dialog_alert
        val title = when (result.verdict) {
            Verdict.DANGER  -> "Threat Detected — ${result.appSource}"
            Verdict.WARNING -> "Suspicious Content — ${result.appSource}"
            else -> return
        }
        val color = when (result.verdict) {
            Verdict.DANGER  -> 0xFFD32F2F.toInt()
            else            -> 0xFFF57C00.toInt()
        }

        val tapIntent = Intent(context, DetailActivity::class.java).apply {
            putExtra("result_id", result.id)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val pendingIntent = PendingIntent.getActivity(
            context, result.id.toInt(), tapIntent, pendingFlags
        )

        val body = result.summary.ifBlank {
            "From: ${result.sender}. Risk score: ${result.riskScore}%."
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_SECURITY)
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setColor(color)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .build()

        val id = synchronized(this) { nextThreatId++ }
        nm.notify(id, notification)
    }

    /**
     * Post a low-priority summary notification after an offline email sync batch.
     */
    fun notifySyncSummary(
        context: Context,
        total: Int,
        safe: Int,
        suspicious: Int,
        unsafe: Int
    ) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val pendingIntent = PendingIntent.getActivity(
            context, NOTIFICATION_ID_SYNC, tapIntent, pendingFlags
        )
        val body = "$total emails checked — Safe: $safe, Suspicious: $suspicious, Unsafe: $unsafe"
        val notification = NotificationCompat.Builder(context, CHANNEL_SYNC)
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setContentTitle("Email Security Synchronisation Complete")
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingIntent)
            .build()
        nm.notify(NOTIFICATION_ID_SYNC, notification)
    }

    fun notifyBatchSyncSummary(
        context: Context,
        totalScanned: Int,
        threatsFound: Int,
        dangerCount: Int,
        warningCount: Int
    ) {
        val safeCount = (totalScanned - threatsFound).coerceAtLeast(0)
        notifySyncSummary(
            context = context,
            total = totalScanned,
            safe = safeCount,
            suspicious = warningCount,
            unsafe = dangerCount
        )
    }
}
