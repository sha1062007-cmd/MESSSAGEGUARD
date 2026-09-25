package com.messageguard.sandbox.trigger

import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.messageguard.sandbox.coordinator.DownloadIntentType
import com.messageguard.sandbox.coordinator.SandboxClaimCoordinator

/**
 * Tertiary trigger: Isolated WhatsApp document download click detector.
 * Strictly decoupled from existing message OCR and text extraction logic.
 * Acts solely as a 15-second anticipatory priming signal.
 */
object WhatsAppDownloadActionDetector {

    private const val TAG = "SandboxDetection"
    private const val PKG_WHATSAPP = "com.whatsapp"
    private const val PKG_WHATSAPP_W4B = "com.whatsapp.w4b"

    private val ACTION_KEYWORDS = listOf(
        "download", "save", "save to download", "save to downloads", "download document"
    )

    /**
     * Inspects an AccessibilityEvent for explicit user clicks on WhatsApp download actions.
     * Guaranteed side-effect free on the main message analysis flow.
     */
    fun onAccessibilityEvent(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg != PKG_WHATSAPP && pkg != PKG_WHATSAPP_W4B) return

        // Only listen for click / tap interactions
        if (event.eventType != AccessibilityEvent.TYPE_VIEW_CLICKED) return

        val source = event.source ?: return
        try {
            val text = source.text?.toString() ?: ""
            val desc = source.contentDescription?.toString() ?: ""
            val combined = "$text $desc".lowercase()

            val isDownloadClick = ACTION_KEYWORDS.any { combined.contains(it) }

            if (isDownloadClick) {
                Log.i(TAG, "[AccessibilityAction] User tapped download action in WhatsApp ('$combined'). Priming expected download.")
                SandboxClaimCoordinator.registerExpectedDownload(
                    sourcePackage = pkg,
                    intentType = DownloadIntentType.WHATSAPP_DOCUMENT,
                    windowMs = 15_000L
                )
            }
        } finally {
            source.recycle()
        }
    }
}
