package com.messageguard.sandbox.ui

import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.messageguard.sandbox.coordinator.SandboxClaimCoordinator
import com.messageguard.sandbox.service.SandboxScanService

/**
 * Transparent trampoline activity that intercepts user taps on downloaded documents.
 * Receives the URI + transient FLAG_GRANT_READ_URI_PERMISSION grant from Chrome,
 * immediately delegates to SandboxScanService (survives activity lifecycle),
 * and finishes — keeping the UX frictionless.
 */
class SandboxScanActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "SandboxScanActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val targetUri: Uri? = intent.data ?: @Suppress("DEPRECATION") intent.getParcelableExtra("extra_target_uri")
        val fileName = intent.getStringExtra("extra_file_name") ?: "intercepted_document"
        val mime = contentResolver.getType(targetUri ?: Uri.EMPTY) ?: "application/pdf"
        val hasReadGrant = (intent.flags and android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0

        Log.i(TAG, "[ScanActivity] Started: targetUri=$targetUri")
        Log.i(TAG, "[ScanActivity] Origin: callingPackage='$callingPackage', referrer='${referrer?.toString()}'")
        Log.i(TAG, "[ScanActivity] URI: authority='${targetUri?.authority}', scheme='${targetUri?.scheme}'")
        Log.i(TAG, "[ScanActivity] Flags: FLAG_GRANT_READ_URI_PERMISSION=$hasReadGrant (raw=0x${Integer.toHexString(intent.flags)})")

        if (targetUri == null) {
            Log.e(TAG, "[ScanActivity] No URI — finishing.")
            finish()
            return
        }

        // Resolve source app via primed-intent correlation (NotificationListener / Accessibility)
        // before falling back to callingPackage. This correctly attributes WhatsApp/Gmail downloads
        // even when the VIEW intent's callingPackage is the file manager.
        val resolvedPkg = resolveSourcePackage(targetUri, fileName, callingPackage)
        val pkg = resolvedPkg ?: callingPackage ?: "unknown"
        Log.i(TAG, "[ScanActivity] Attribution: fileName='$fileName' callingPackage='$callingPackage' resolvedPkg='$resolvedPkg' finalPkg='$pkg'")
        val serviceIntent = SandboxScanService.buildIntent(this, targetUri, fileName, mime, pkg)
        startForegroundService(serviceIntent)

        Log.i(TAG, "[ScanActivity] Dispatched to SandboxScanService. Finishing activity.")
        finish()
    }

    private fun resolveSourcePackage(targetUri: Uri, fileName: String, callingPackage: String?): String? {
        val uriString = targetUri.toString().lowercase()
        val nameLower = fileName.lowercase()
        // 1. WhatsApp document: check fileName/path for whatsapp markers or recent WhatsApp primed intent (peek, don't consume)
        if (nameLower.contains("whatsapp") || uriString.contains("whatsapp") || nameLower.contains("wa-")) {
            val primed = SandboxClaimCoordinator.peekPrimedIntent("com.whatsapp")
                ?: SandboxClaimCoordinator.peekPrimedIntent("com.whatsapp.w4b")
            if (primed != null) {
                Log.i(TAG, "[Attribution] Resolved WhatsApp via peek: ${primed.sourcePackage}")
                return primed.sourcePackage
            }
        }
        // Also check WhatsApp primed via isWhatsAppPrimed (covers Download-saved WhatsApp docs)
        if (isWhatsAppPrimed()) {
            val primed = SandboxClaimCoordinator.peekPrimedIntent("com.whatsapp")
                ?: SandboxClaimCoordinator.peekPrimedIntent("com.whatsapp.w4b")
            if (primed != null) {
                Log.i(TAG, "[Attribution] Resolved WhatsApp via recent primed peek: ${primed.sourcePackage}")
                return primed.sourcePackage
            }
        }
        // 2. Gmail attachment: peek without consuming
        val gmailPrimed = SandboxClaimCoordinator.peekPrimedIntent("com.google.android.gm")
        if (gmailPrimed != null) {
            Log.i(TAG, "[Attribution] Resolved Gmail via peek: ${gmailPrimed.sourcePackage}")
            return gmailPrimed.sourcePackage
        }
        // 3. Generic: try path-based peek (covers Download directory → Chrome/DownloadProvider)
        val pathPrimed = SandboxClaimCoordinator.peekPrimedIntentForPath(fileName)
        if (pathPrimed != null) {
            Log.i(TAG, "[Attribution] Resolved via path peek: ${pathPrimed.sourcePackage}")
            return pathPrimed.sourcePackage
        }
        // 4. Fallback: most recent primed intent regardless of package
        val recent = SandboxClaimCoordinator.getMostRecentPrimedIntent()
        if (recent != null) {
            Log.i(TAG, "[Attribution] Resolved via most-recent primed peek: ${recent.sourcePackage} (${recent.intentType})")
            return recent.sourcePackage
        }
        return null
    }

    private fun isWhatsAppPrimed(): Boolean {
        // Check if any WhatsApp primed intent is still active (15s window)
        val recent = SandboxClaimCoordinator.getMostRecentPrimedIntent()
        return recent?.sourcePackage?.contains("whatsapp") == true
    }
}
