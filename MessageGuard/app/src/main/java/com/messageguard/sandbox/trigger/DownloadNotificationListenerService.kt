package com.messageguard.sandbox.trigger

import android.app.Notification
import android.content.Intent
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.messageguard.sandbox.capture.SandboxCaptureEngine
import com.messageguard.sandbox.coordinator.DownloadIntentType
import com.messageguard.sandbox.coordinator.SandboxClaimCoordinator
import com.messageguard.sandbox.model.CaptureSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Secondary trigger: NotificationListenerService.
 * Listens for download completion notifications from Gmail, WhatsApp, and Chrome.
 * Non-blocking: If disabled, ContentObserver and Periodic Sweep operate independently.
 */
class DownloadNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "SandboxDetection"

        // Monitored downloader packages
        private const val PKG_GMAIL = "com.google.android.gm"
        private const val PKG_WHATSAPP = "com.whatsapp"
        private const val PKG_WHATSAPP_W4B = "com.whatsapp.w4b"
        private const val PKG_CHROME = "com.android.chrome"
        private const val PKG_DOWNLOAD_PROVIDER = "com.android.providers.downloads"

        // Keywords identifying completed downloads across English & generic Android notifications
        private val COMPLETION_KEYWORDS = listOf(
            "download complete",
            "download completed",
            "downloaded",
            "saved to",
            "file received",
            "attachment saved"
        )
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "DownloadNotificationListenerService connected and active.")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val pkg = sbn.packageName ?: return
        if (pkg != PKG_GMAIL && pkg != PKG_WHATSAPP && pkg != PKG_WHATSAPP_W4B && pkg != PKG_CHROME && pkg != PKG_DOWNLOAD_PROVIDER) {
            return
        }

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return

        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

        val combinedContent = "$title $text $bigText".lowercase()

        val isDownloadCompletion = COMPLETION_KEYWORDS.any { combinedContent.contains(it) }

        if (isDownloadCompletion) {
            val intentType = when (pkg) {
                PKG_WHATSAPP, PKG_WHATSAPP_W4B -> DownloadIntentType.WHATSAPP_DOCUMENT
                PKG_GMAIL -> DownloadIntentType.GMAIL_ATTACHMENT
                else -> DownloadIntentType.GENERIC_DOWNLOAD
            }

            // Extract any underlying URI or intent data
            val contentIntent = notification.contentIntent
            val keys = extras.keySet().joinToString(", ")
            val extrasMap = extras.keySet().associateWith { key ->
                val v = extras.get(key)
                if (v is Array<*>) v.contentToString() else v?.toString() ?: "null"
            }

            Log.i(TAG, "[NotificationListener] Download completion intercepted from '$pkg'. Title='$title', Text='$text', contentIntent=$contentIntent, extrasKeys=[$keys]")
            extrasMap.forEach { (k, v) ->
                Log.d(TAG, "[NotificationListener] Extra: '$k' = '$v'")
            }

            // Telemetry-only: register/corroborate primed intent for atomic correlation with MediaStore
            SandboxClaimCoordinator.registerExpectedDownload(
                sourcePackage = pkg,
                intentType = intentType,
                windowMs = 15_000L
            )
            Log.i(TAG, "[NotificationListener] Download intent registered for '$pkg'. Waiting for MediaStore or Sweep capture.")
        }
    }
}
