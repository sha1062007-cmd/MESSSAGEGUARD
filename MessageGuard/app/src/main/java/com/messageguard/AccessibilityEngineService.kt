package com.messageguard

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.messageguard.security.BankingOverlayDetector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

data class ContentFingerprint(
    val packageName: String,
    val contentHash: Int,
    val timestamp: Long
)

class AccessibilityEngineService : AccessibilityService() {

    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private val handler = Handler(Looper.getMainLooper())
    private var debounceRunnable: Runnable? = null
    private var lastFingerprint: ContentFingerprint? = null
    private lateinit var prefs: SharedPreferences
    private lateinit var overlayManager: OverlayManager
    private lateinit var repository: AnalysisRepository
    private lateinit var spamAnalyzer: SpamAnalyzer

    private val isAnalyzing = AtomicBoolean(false)
    private lateinit var bankingOverlayDetector: BankingOverlayDetector

    override fun onServiceConnected() {
        super.onServiceConnected()
        prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        overlayManager = OverlayManager(this).also { mgr ->
            // BUG FIX: Stop TTS immediately when the result popup is dismissed.
            // Without this, the TTS engine keeps speaking even after the overlay view
            // is removed from screen, because removing a view does NOT stop TextToSpeech.
            mgr.onDismiss = {
                com.messageguard.threatvision.domain.voice.VoiceCommandManager
                    .getInstance(this)
                    .stopSpeaking()
            }
        }
        repository = AnalysisRepository(this)
        spamAnalyzer = SpamAnalyzer(this)
        bankingOverlayDetector = BankingOverlayDetector(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg == "com.messageguard") return

        // Sub-step 3: Overlay-During-Banking-App Detection.
        // Fires on every window change; cheap path that bails immediately if not a banking app.
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            ::bankingOverlayDetector.isInitialized &&
            prefs.getBoolean(Constants.KEY_SERVICE_ENABLED, true)
        ) {
            bankingOverlayDetector.onForegroundPackageChanged(pkg)
        }

        // Auto-launch compact Threat Vision floating bubble when Gmail is opened
        if (pkg == "com.google.android.gm") {
            try {
                com.messageguard.threatvision.service.FloatingBubbleService.startService(this)
            } catch (_: Exception) {}
        }

        // Additive Hook: WhatsApp Document Download Click Tracker (15s priming signal for File Sandbox)
        // Strictly isolated and non-intrusive on message extraction logic.
        if (pkg == "com.whatsapp" || pkg == "com.whatsapp.w4b") {
            com.messageguard.sandbox.trigger.WhatsAppDownloadActionDetector.onAccessibilityEvent(event)
        }

        val app = SupportedApp.fromPackage(pkg) ?: return
        if (!isAppEnabled(app)) return
        if (!prefs.getBoolean(Constants.KEY_SERVICE_ENABLED, true)) return

        if (overlayManager.isOverlayShowing) return

        debounceRunnable?.let { handler.removeCallbacks(it) }
        debounceRunnable = Runnable {
            if (isAnalyzing.get() || overlayManager.isOverlayShowing) return@Runnable

            val rootNode = rootInActiveWindow ?: return@Runnable
            val extracted = extractContent(rootNode, app)
            rootNode.recycle()

            if (extracted.isNullOrBlank()) return@Runnable
            if (!shouldAnalyze(pkg, extracted)) return@Runnable

            isAnalyzing.set(true)

            // 1. INSTANT FEEDBACK: Show the "Detecting" overlay state immediately
            overlayManager.showDetectingState()

            scope.launch {
                try {
                    // 2. BACKGROUND PROCESSING: Run the heavy ML/AI pipeline
                    val outcome = spamAnalyzer.analyze(
                        appSource = app.displayName,
                        sender = parseSender(extracted),
                        subject = parseSubject(extracted),
                        messageBody = parseBody(extracted)
                    )
                    
                    val logAll = prefs.getBoolean(Constants.KEY_LOG_ALL_SCANS, false)
                    var finalResult = outcome.result
                    if (logAll || outcome.result.verdict != Verdict.SAFE) {
                        val insertedId = repository.insert(outcome.result)
                        finalResult = outcome.result.copy(id = insertedId)
                    }
                    
                    // 3. UI SYNC: Transition the existing overlay to the final result
                    withContext(Dispatchers.Main) {
                        if (outcome.analysisTriggered) {
                            overlayManager.transitionToResult(finalResult)

                            if (finalResult.verdict == Verdict.WARNING || finalResult.verdict == Verdict.DANGER) {
                                // Bug Fix (Phase 3 Bug 2): Post system notification so the alert
                                // persists in the notification tray even after the overlay is dismissed.
                                ThreatVisionNotifier.notifyThreatResult(
                                    this@AccessibilityEngineService, finalResult
                                )

                                val voiceManager = com.messageguard.threatvision.domain.voice.VoiceCommandManager.getInstance(this@AccessibilityEngineService)
                                val threatVerdict = when (finalResult.verdict) {
                                    Verdict.DANGER -> com.messageguard.threatvision.data.model.ThreatVerdict.DANGER
                                    Verdict.WARNING -> com.messageguard.threatvision.data.model.ThreatVerdict.WARNING
                                    else -> com.messageguard.threatvision.data.model.ThreatVerdict.SAFE
                                }
                                voiceManager.speakVerdict(threatVerdict, finalResult.summary)
                            }
                        } else {
                            // If analysis was filtered out (too short/system noise), dismiss the overlay
                            overlayManager.dismissOverlay()
                        }
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    withContext(Dispatchers.Main) {
                        // Fallback: cleanup overlay on error to prevent being stuck on detecting
                        overlayManager.dismissOverlay()
                    }
                } finally {
                    // Analysis lock held for 7s to prevent repetitive scanning
                    handler.postDelayed({ isAnalyzing.set(false) }, 7000)
                }
            }
        }
        handler.postDelayed(debounceRunnable!!, 1000)
    }

    private fun shouldAnalyze(packageName: String, content: String): Boolean {
        val newHash = content.trim().hashCode()
        val last = lastFingerprint
        val now = System.currentTimeMillis()
        val isDuplicate = last?.contentHash == newHash && (now - last.timestamp) < 300_000
        if (isDuplicate) return false

        lastFingerprint = ContentFingerprint(packageName, newHash, now)
        return true
    }

    private fun extractContent(node: AccessibilityNodeInfo, app: SupportedApp): String? {
        val sb = StringBuilder()
        extractTextRecursive(node, sb, 0)
        return sb.toString().trim().takeIf { it.length > 25 }
    }

    private fun extractTextRecursive(node: AccessibilityNodeInfo, sb: StringBuilder, depth: Int) {
        if (depth > 20) return
        val nodePkg = node.packageName?.toString()
        if (nodePkg == "com.messageguard") return

        val text = node.text?.toString()
        if (!text.isNullOrBlank()) {
            val lowerText = text.lowercase()
            if (!lowerText.contains("see full report") && !lowerText.contains("security origin")) {
                sb.append(text).append("\n")
            }
        }
        
        val desc = node.contentDescription?.toString()
        if (!desc.isNullOrBlank() && desc != text) sb.append(desc).append("\n")
        
        for (i in 0 until node.childCount) {
            node.getChild(i)?.let { child ->
                extractTextRecursive(child, sb, depth + 1)
                child.recycle()
            }
        }
    }

    private fun parseSender(text: String) = text.lines().filter { it.isNotBlank() }.firstOrNull() ?: "Unknown"
    private fun parseSubject(text: String) = text.lines().filter { it.isNotBlank() }.getOrNull(1) ?: ""
    private fun parseBody(text: String): String {
        return text.lines()
            .filter { line ->
                val l = line.lowercase()
                !l.contains("reply") && !l.contains("forward") && 
                !l.contains("save to") && !l.contains("add star") &&
                !l.contains("inbox") && !l.contains("emoji") &&
                !l.contains("show contact")
            }
            .joinToString(" ")
            .ifBlank { text }
            .take(1000)
    }

    private fun isAppEnabled(app: SupportedApp) = prefs.getBoolean(when (app) {
        SupportedApp.GMAIL -> Constants.KEY_MONITOR_GMAIL
        SupportedApp.WHATSAPP -> Constants.KEY_MONITOR_WHATSAPP
        SupportedApp.TELEGRAM -> Constants.KEY_MONITOR_TELEGRAM
        SupportedApp.SMS -> Constants.KEY_MONITOR_SMS
        SupportedApp.INSTAGRAM -> Constants.KEY_MONITOR_INSTAGRAM
        SupportedApp.LINKEDIN -> Constants.KEY_MONITOR_LINKEDIN
    }, true)

    override fun onInterrupt() {}
    override fun onDestroy() {
        super.onDestroy()
        debounceRunnable?.let { handler.removeCallbacks(it) }
        if (::spamAnalyzer.isInitialized) spamAnalyzer.close()
    }
}
