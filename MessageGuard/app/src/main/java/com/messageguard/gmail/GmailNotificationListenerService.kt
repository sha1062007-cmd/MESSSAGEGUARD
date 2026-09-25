package com.messageguard.gmail

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import com.messageguard.DetailActivity
import com.messageguard.R
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * PS106 Threat Vision — Gmail Notification Listener Service
 * ===========================================================
 * Intercepts incoming email notifications from major email clients:
 *   - Gmail          (com.google.android.gm)
 *   - Outlook        (com.microsoft.office.outlook)
 *   - Yahoo Mail     (com.yahoo.mobile.client.android.mail)
 *   - Samsung Email  (com.samsung.android.email.provider)
 *   - ProtonMail     (ch.protonmail.android)
 *
 * Flow:
 *   1. Raw notification is instantly suppressed (cancelNotification)
 *   2. Shows transient ongoing notification: "🛡️ Threat Vision: Analyzing Incoming Email..."
 *   3. Forwards {sender, subject, snippet} to Python FastAPI backend POST /api/analyze-trigger
 *   4. Receives PS106 4-band verdict (SAFE/UNVERIFIED/SUSPICIOUS/MALICIOUS)
 *   5. Renders color-coded replacement notification with risk score
 *   6. Tapping notification opens DetailActivity with full forensic evidence
 */
class GmailNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "PS106EmailGuard"

        // Monitored email client packages
        private const val PKG_GMAIL        = "com.google.android.gm"
        private const val PKG_OUTLOOK      = "com.microsoft.office.outlook"
        private const val PKG_YAHOO        = "com.yahoo.mobile.client.android.mail"
        private const val PKG_SAMSUNG      = "com.samsung.android.email.provider"
        private const val PKG_PROTONMAIL   = "ch.protonmail.android"

        private val MONITORED_PACKAGES = setOf(
            PKG_GMAIL, PKG_OUTLOOK, PKG_YAHOO, PKG_SAMSUNG, PKG_PROTONMAIL
        )

        // Notification channels
        private const val CHANNEL_SCANNING = "tv_email_scanning"
        private const val CHANNEL_VERDICT  = "tv_email_verdict"

        // Backend API endpoint (configurable via SharedPreferences)
        private const val DEFAULT_BACKEND_URL = "http://10.0.2.2:8000"

        // PS106 4-Band Verdict Colors
        private const val COLOR_SAFE       = 0xFF4CAF50.toInt()  // Green
        private const val COLOR_UNVERIFIED = 0xFFFBC02D.toInt()  // Yellow
        private const val COLOR_SUSPICIOUS = 0xFFFF9800.toInt()  // Orange
        private const val COLOR_MALICIOUS  = 0xFFF44336.toInt()  // Red

        // Notification ID management
        private var nextVerdictId = 20000
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val httpClient = OkHttpClient.Builder()
        .callTimeout(30, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    override fun onListenerConnected() {
        super.onListenerConnected()
        createNotificationChannels()
        Log.i(TAG, "GmailNotificationListenerService connected — monitoring ${MONITORED_PACKAGES.size} email apps")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.w(TAG, "GmailNotificationListenerService disconnected")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val pkg = sbn.packageName ?: return
        if (pkg !in MONITORED_PACKAGES) return

        // Check if service is enabled in preferences
        val prefs = getSharedPreferences("messageguard_prefs", Context.MODE_PRIVATE)
        val isEnabled = prefs.getBoolean("email_guard_enabled", true)
        if (!isEnabled) return

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return

        // Extract email metadata from notification
        val sender = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val subject = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val snippet = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()
            ?: ""

        // Skip empty or system notifications
        if (sender.isBlank() && subject.isBlank()) return

        Log.d(TAG, "Email intercepted from $pkg | Sender: $sender | Subject: ${subject.take(50)}")

        // Step 1: Suppress the original unverified notification
        try {
            cancelNotification(sbn.key)
            Log.d(TAG, "Original notification suppressed: ${sbn.key}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cancel notification: ${e.message}")
        }

        // Step 2: Show transient "Scanning" notification
        val scanNotificationId = nextVerdictId++
        showScanningNotification(scanNotificationId, sender, pkg)

        // Step 3: Trigger backend analysis with on-device ML model fallback
        serviceScope.launch {
            try {
                val result = analyzeWithBackend(sender, subject, snippet)

                // Step 4: Replace scanning notification with verdict
                withContext(Dispatchers.Main) {
                    dismissNotification(scanNotificationId)
                    showVerdictNotification(scanNotificationId, result, sender, subject)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Backend analysis failed: ${e.message}. Falling back to on-device ML model analysis.", e)
                withContext(Dispatchers.Main) {
                    dismissNotification(scanNotificationId)
                    val localResult = analyzeWithOnDeviceML(sender, subject, snippet)
                    showVerdictNotification(scanNotificationId, localResult, sender, subject)
                }
            }
        }
    }

    /**
     * Fallback on-device ML analysis using PretrainedThreatEngine & SpamAnalyzer
     */
    private suspend fun analyzeWithOnDeviceML(sender: String, subject: String, snippet: String): JSONObject {
        val spamAnalyzer = com.messageguard.SpamAnalyzer(applicationContext)
        val outcome = spamAnalyzer.analyze(
            appSource = "Gmail Notification",
            sender = sender,
            subject = subject,
            messageBody = snippet
        )
        val result = outcome.result
        val verdictStr = when (result.verdict) {
            com.messageguard.Verdict.SAFE -> "SAFE"
            com.messageguard.Verdict.WARNING -> "SUSPICIOUS"
            com.messageguard.Verdict.DANGER -> "MALICIOUS"
            else -> "SAFE"
        }
        val riskScore = when (result.verdict) {
            com.messageguard.Verdict.SAFE -> 10
            com.messageguard.Verdict.WARNING -> 55
            com.messageguard.Verdict.DANGER -> 85
            else -> 10
        }
        val json = JSONObject().apply {
            put("verdict", verdictStr)
            put("risk_score", riskScore)
            put("summary", result.summary)
            put("case_id", "LOCAL-${System.currentTimeMillis()}")
            put("risk_color", if (verdictStr == "SAFE") "#4CAF50" else if (verdictStr == "SUSPICIOUS") "#FF9800" else "#F44336")
        }
        spamAnalyzer.close()
        return json
    }

    /**
     * POST {sender, subject, snippet} to FastAPI backend /api/analyze-trigger
     */
    private fun analyzeWithBackend(sender: String, subject: String, snippet: String): JSONObject {
        val prefs = getSharedPreferences("messageguard_prefs", Context.MODE_PRIVATE)
        val backendUrl = prefs.getString("backend_url", DEFAULT_BACKEND_URL) ?: DEFAULT_BACKEND_URL

        val payload = JSONObject().apply {
            put("sender", sender)
            put("subject", subject)
            put("snippet", snippet)
        }

        val request = Request.Builder()
            .url("$backendUrl/api/analyze-trigger")
            .post(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()

        Log.d(TAG, "Sending analysis request to $backendUrl/api/analyze-trigger")

        val response = httpClient.newCall(request).execute()
        val responseBody = response.body?.string() ?: "{}"

        if (!response.isSuccessful) {
            throw RuntimeException("Backend returned ${response.code}: $responseBody")
        }

        Log.d(TAG, "Backend response: ${responseBody.take(200)}")
        return JSONObject(responseBody)
    }

    /**
     * Show transient "🛡️ Analyzing Incoming Email..." notification
     */
    private fun showScanningNotification(notificationId: Int, sender: String, sourceApp: String) {
        val appName = when (sourceApp) {
            PKG_GMAIL -> "Gmail"
            PKG_OUTLOOK -> "Outlook"
            PKG_YAHOO -> "Yahoo Mail"
            PKG_SAMSUNG -> "Samsung Email"
            PKG_PROTONMAIL -> "ProtonMail"
            else -> "Email"
        }

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notification = NotificationCompat.Builder(this, CHANNEL_SCANNING)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("🛡️ Threat Vision: Analyzing $appName")
            .setContentText("Scanning email from $sender...")
            .setSubText("PS106 Email Security")
            .setOngoing(true)
            .setProgress(0, 0, true)  // Indeterminate progress bar
            .setColor(Color.parseColor("#1a237e"))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .build()

        nm.notify(notificationId, notification)
    }

    /**
     * Show PS106 4-band color-coded verdict notification
     */
    private fun showVerdictNotification(
        notificationId: Int,
        result: JSONObject,
        sender: String,
        subject: String
    ) {
        val verdict = result.optString("verdict", "UNVERIFIED")
        val riskScore = result.optInt("risk_score", 0)
        val summary = result.optString("summary", "Analysis complete")
        val caseId = result.optString("case_id", "")
        val riskColor = result.optString("risk_color", "#FBC02D")

        // Determine notification color and emoji from verdict
        val (color, emoji, bandLabel) = when (verdict) {
            "SAFE", "VERIFIED" -> Triple(COLOR_SAFE, "✅", "SAFE")
            "UNVERIFIED"       -> Triple(COLOR_UNVERIFIED, "⚠️", "UNVERIFIED")
            "SUSPICIOUS"       -> Triple(COLOR_SUSPICIOUS, "🔶", "SUSPICIOUS")
            "MALICIOUS"        -> Triple(COLOR_MALICIOUS, "🚨", "MALICIOUS")
            else               -> Triple(COLOR_UNVERIFIED, "⚠️", "UNVERIFIED")
        }

        // Build intent to open DetailActivity with forensic evidence
        val detailIntent = Intent(this, DetailActivity::class.java).apply {
            putExtra("email_sender", sender)
            putExtra("email_subject", subject)
            putExtra("email_verdict", verdict)
            putExtra("email_risk_score", riskScore)
            putExtra("email_summary", summary)
            putExtra("email_case_id", caseId)
            putExtra("analysis_json", result.toString())
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this, notificationId, detailIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val notification = NotificationCompat.Builder(this, CHANNEL_VERDICT)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("$emoji $bandLabel — Risk: $riskScore/100")
            .setContentText("From: $sender")
            .setSubText("PS106 Threat Vision")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("$summary\n\nFrom: $sender\nSubject: $subject\nCase: $caseId")
                    .setBigContentTitle("$emoji $bandLabel — Risk Score: $riskScore/100")
            )
            .setColor(color)
            .setColorized(true)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setPriority(
                if (verdict == "MALICIOUS" || verdict == "SUSPICIOUS")
                    NotificationCompat.PRIORITY_HIGH
                else NotificationCompat.PRIORITY_DEFAULT
            )
            .setCategory(NotificationCompat.CATEGORY_EMAIL)
            .setGroup("ps106_email_verdicts")
            .build()

        nm.notify(notificationId, notification)
        Log.i(TAG, "Verdict notification posted: $verdict ($riskScore/100) for $sender | Case: $caseId")
    }

    /**
     * Fallback notification when backend is unreachable
     */
    private fun showFallbackNotification(
        notificationId: Int,
        sender: String,
        subject: String,
        error: String?
    ) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val notification = NotificationCompat.Builder(this, CHANNEL_VERDICT)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("⚠️ UNVERIFIED — Email Not Analyzed")
            .setContentText("From: $sender — $subject")
            .setSubText("Backend unavailable")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("Could not verify email security.\nFrom: $sender\nSubject: $subject\n\nReason: ${error ?: "Backend unreachable"}\n\nExercise caution with this email.")
            )
            .setColor(COLOR_UNVERIFIED)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_EMAIL)
            .build()

        nm.notify(notificationId, notification)
        Log.w(TAG, "Fallback UNVERIFIED notification for $sender: $error")
    }

    /**
     * Dismiss a notification by ID
     */
    private fun dismissNotification(notificationId: Int) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.cancel(notificationId)
    }

    /**
     * Create required notification channels (Android O+)
     */
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Scanning channel (low priority, ongoing)
        if (nm.getNotificationChannel(CHANNEL_SCANNING) == null) {
            val scanChannel = NotificationChannel(
                CHANNEL_SCANNING,
                "Email Security Scanning",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows while Threat Vision is analyzing an incoming email"
                setShowBadge(false)
            }
            nm.createNotificationChannel(scanChannel)
        }

        // Verdict channel (high priority for dangerous emails)
        if (nm.getNotificationChannel(CHANNEL_VERDICT) == null) {
            val verdictChannel = NotificationChannel(
                CHANNEL_VERDICT,
                "Email Security Verdicts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Color-coded security verdicts for analyzed emails"
                enableVibration(true)
                enableLights(true)
                lightColor = Color.RED
            }
            nm.createNotificationChannel(verdictChannel)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        Log.i(TAG, "GmailNotificationListenerService destroyed")
    }
}
