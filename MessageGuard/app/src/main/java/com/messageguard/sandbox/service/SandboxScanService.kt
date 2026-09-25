package com.messageguard.sandbox.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.IBinder
import android.util.Log
import com.messageguard.AnalysisHistoryDatabase
import com.messageguard.sandbox.capture.SandboxCaptureEngine
import com.messageguard.sandbox.model.CaptureSource
import com.messageguard.sandbox.report.ScanReport
import com.messageguard.sandbox.scan.PreExecutionScanner
import com.messageguard.sandbox.scan.ScanVerdict
import com.messageguard.sandbox.ui.ScanReportDetailActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/**
 * Foreground service that receives a URI from SandboxScanActivity,
 * performs quarantine capture + pre-execution scan off the activity lifecycle,
 * persists the scan report to Room (all verdicts — SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE),
 * and posts the verdict as a system notification that deep-links into the detail screen.
 */
class SandboxScanService : Service() {

    companion object {
        private const val TAG = "SandboxScanService"
        private const val CHANNEL_ID = "messageguard_sandbox"
        private const val CHANNEL_NAME = "MessageGuard Sandbox"
        private const val NOTIF_PROGRESS_ID = 1001
        private const val NOTIF_RESULT_ID = 1002

        const val EXTRA_URI = "extra_uri"
        const val EXTRA_FILENAME = "extra_filename"
        const val EXTRA_MIME = "extra_mime"
        const val EXTRA_PACKAGE = "extra_package"
        const val EXTRA_CAPTURE_SOURCE = "extra_capture_source"

        fun buildIntent(context: Context, uri: Uri, fileName: String, mime: String, pkg: String, captureSource: CaptureSource = CaptureSource.USER_OPEN): Intent {
            return Intent(context, SandboxScanService::class.java).apply {
                putExtra(EXTRA_URI, uri.toString())
                putExtra(EXTRA_FILENAME, fileName)
                putExtra(EXTRA_MIME, mime)
                putExtra(EXTRA_PACKAGE, pkg)
                putExtra(EXTRA_CAPTURE_SOURCE, captureSource.name)
            }
        }
    }

    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIF_PROGRESS_ID, buildProgressNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        val uriString = intent.getStringExtra(EXTRA_URI)
        val fileName = intent.getStringExtra(EXTRA_FILENAME) ?: "intercepted_document"
        val mime = intent.getStringExtra(EXTRA_MIME) ?: "application/pdf"
        val pkg = intent.getStringExtra(EXTRA_PACKAGE) ?: "unknown"
        val captureSource = try {
            CaptureSource.valueOf(intent.getStringExtra(EXTRA_CAPTURE_SOURCE) ?: CaptureSource.USER_OPEN.name)
        } catch (_: IllegalArgumentException) {
            CaptureSource.USER_OPEN
        }

        if (uriString == null) {
            Log.e(TAG, "[ScanService] No URI provided, stopping.")
            stopSelf()
            return START_NOT_STICKY
        }

        val uri = Uri.parse(uriString)
        Log.i(TAG, "[ScanService] Received scan request: uri=$uri, file=$fileName, pkg=$pkg")

        scope.launch {
            try {
                // Step 1: Quarantine capture
                val item = SandboxCaptureEngine.captureFile(
                    context = applicationContext,
                    sourceUri = uri,
                    originalFileName = fileName,
                    originalMimeType = mime,
                    sourcePackage = pkg,
                    captureSource = captureSource
                )

                if (item == null) {
                    Log.e(TAG, "[ScanService] Capture failed for $uri")
                    postVerdictNotification("Scan Failed", "Could not read file stream from $pkg", false, null)
                    stopSelf(startId)
                    return@launch
                }

                Log.i(TAG, "[ScanService] Captured ${item.fileSize} bytes. SHA-256=${item.sha256}. Starting scan...")

                // Step 2: Pre-execution scan (structural heuristics + ensemble analysis)
                val result = PreExecutionScanner.scanItem(item, applicationContext)

                Log.i(TAG, "[ScanService] VERDICT=${result.verdict}, Score=${result.threatScore}/100, Struct=${result.structuralScore}, Ens=${result.ensembleScore}, Entropy=${result.entropy}, Findings=${result.findings.size}")

                // Step 3: Persist report to Room — ALL verdicts, not just MALICIOUS
                val findingsJson = buildFindingsJson(result.findings.map { Triple(it.category.name, it.description, it.severity) })
                val report = ScanReport(
                    id = item.id,
                    fileName = item.originalFileName,
                    sourceApp = pkg,
                    sha256 = item.sha256,
                    timestamp = System.currentTimeMillis(),
                    verdict = result.verdict.name,
                    finalScore = result.threatScore,
                    structuralScore = result.structuralScore,
                    ensembleScore = result.ensembleScore,
                    entropy = result.entropy,
                    findingsJson = findingsJson
                )
                val db = AnalysisHistoryDatabase.getInstance(applicationContext)
                db.scanReportDao().insert(report)
                Log.i(TAG, "[ScanService] Report persisted: id=${item.id}, verdict=${result.verdict}")

                // Step 4: Post result notification with deep-link to detail screen
                val (title, message) = when (result.verdict) {
                    ScanVerdict.SAFE ->
                        "✅ MessageGuard: File Safe" to "'${item.originalFileName}' — no threats detected. Tap for details."
                    ScanVerdict.SUSPICIOUS ->
                        "⚠️ MessageGuard: Suspicious File" to "'${item.originalFileName}' scored ${result.threatScore}/100. Tap for details."
                    ScanVerdict.MALICIOUS ->
                        "🚨 THREAT BLOCKED" to "'${item.originalFileName}' blocked! ${result.findings.firstOrNull()?.description ?: ""}. Tap for details."
                    ScanVerdict.INCONCLUSIVE ->
                        "ℹ️ MessageGuard: Scan Inconclusive" to "'${item.originalFileName}' could not be fully analysed. Tap for details."
                }

                postVerdictNotification(title, message, result.verdict == ScanVerdict.MALICIOUS, item.id)

            } catch (e: Exception) {
                Log.e(TAG, "[ScanService] Unexpected error", e)
                postVerdictNotification("Scan Error", e.message ?: "Unknown error", false, null)
            } finally {
                stopSelf(startId)
            }
        }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        job.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH).apply {
            description = "MessageGuard sandbox scan results"
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildProgressNotification(): Notification {
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("MessageGuard Sandbox")
            .setContentText("Scanning file for threats…")
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setOngoing(true)
            .build()
    }

    private fun postVerdictNotification(title: String, message: String, isAlert: Boolean, reportId: String?) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.cancel(NOTIF_PROGRESS_ID)

        val builder = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(Notification.BigTextStyle().bigText(message))
            .setSmallIcon(if (isAlert) android.R.drawable.ic_dialog_alert else android.R.drawable.ic_dialog_info)
            .setAutoCancel(true)

        // Deep-link: tapping the notification opens the specific scan's detail screen
        if (reportId != null) {
            val deepLinkIntent = Intent(this, ScanReportDetailActivity::class.java).apply {
                putExtra(ScanReportDetailActivity.EXTRA_REPORT_ID, reportId)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pendingIntent = PendingIntent.getActivity(
                this, reportId.hashCode(), deepLinkIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.setContentIntent(pendingIntent)
        }

        nm.notify(NOTIF_RESULT_ID, builder.build())
    }

    /** Serialises findings to [{cat, desc, sev}, …] JSON without Gson dependency. */
    private fun buildFindingsJson(findings: List<Triple<String, String, Int>>): String {
        val arr = JSONArray()
        findings.forEach { (cat, desc, sev) ->
            arr.put(JSONObject().apply {
                put("cat", cat)
                put("desc", desc)
                put("sev", sev)
            })
        }
        return arr.toString()
    }
}
