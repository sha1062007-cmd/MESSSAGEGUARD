package com.messageguard.threatvision.ui.components

import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import com.messageguard.R
import com.messageguard.threatvision.data.model.RiskAssessment
import com.messageguard.threatvision.data.model.ThreatVerdict

/**
 * Singleton overlay card manager for showing Threat Vision results on screen.
 * Uses WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY to display on top of WhatsApp/SMS.
 * Positioned at the top-middle to completely avoid collision with the soft keyboard.
 * Automatically dismisses SAFE verdicts after 5s; WARNING/DANGER require manual tap to close.
 */
object FloatingResultCard {

    private const val TAG = "ThreatVisionLog"
    private var activeCardView: View? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var autoDismissRunnable: Runnable? = null
    var lastRiskAssessment: RiskAssessment? = null
        private set

    /**
     * Shows an immediate "Analyzing Message..." animated loading card on screen as soon as circle selection finishes.
     */
    fun showAnalyzingLoading(context: Context) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { showAnalyzingLoading(context) }
            return
        }

        dismiss(context)

        val windowManager = context.applicationContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val inflater = LayoutInflater.from(context)

        val cardView = inflater.inflate(R.layout.overlay_threat_result, null)
        activeCardView = cardView

        val tvVerdict = cardView.findViewById<TextView>(R.id.tv_verdict)
        val tvScore = cardView.findViewById<TextView>(R.id.tv_score)
        val tvCategory = cardView.findViewById<TextView>(R.id.tv_category)
        val tvReason = cardView.findViewById<TextView>(R.id.tv_reason)
        val tvRecommendations = cardView.findViewById<TextView>(R.id.tv_recommendations)
        val tvRecommendationsHeader = cardView.findViewById<TextView>(R.id.tv_rec_header)
        val btnDismiss = cardView.findViewById<TextView>(R.id.btn_dismiss)
        val btnToggleReport = cardView.findViewById<TextView>(R.id.btn_toggle_report)
        val container = cardView.findViewById<View>(R.id.result_card_container)
        val presentation = ScanResultLocalizer.loading(context)

        container.setBackgroundResource(R.drawable.bg_overlay_warning)
        tvVerdict.text = "⚡ ANALYZING MESSAGE..."
        tvVerdict.setTextColor(android.graphics.Color.parseColor("#00E5FF"))

        tvScore.text = "Running OCR & Edge ML..."
        tvCategory.text = "Status: Scanning"
        tvReason.text = "Analyzing selected screen crop with 5 Edge ML models + Gemini Cloud AI..."
        tvRecommendations.text = "• Extracting text & links...\n• Evaluating UPI & Phishing signals..."
        btnToggleReport.visibility = View.GONE
        tvVerdict.text = presentation.title
        tvScore.text = presentation.score
        tvCategory.text = presentation.status
        tvReason.text = presentation.summary
        tvRecommendationsHeader.visibility = View.GONE
        tvRecommendations.text = presentation.recommendations
        btnDismiss.setOnClickListener { dismiss(context) }

        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        val widthPx = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 320f, context.resources.displayMetrics).toInt()
        val topMarginPx = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 80f, context.resources.displayMetrics).toInt()

        val params = WindowManager.LayoutParams(
            widthPx,
            WindowManager.LayoutParams.WRAP_CONTENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = topMarginPx
        }

        try {
            windowManager.addView(cardView, params)
        } catch (e: Exception) {
            activeCardView = null
        }
    }

    /**
     * Shows a premium floating threat assessment result card on screen.
     * Safely dismisses any existing card first to prevent memory leaks or view overlaps.
     */
    fun show(context: Context, assessment: RiskAssessment) {
        // Ensure execution happens on Main thread (WindowManager calls require main looper)
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { show(context, assessment) }
            return
        }

        android.util.Log.d(TAG, "FloatingResultCard: showing result overlay card. Verdict=${assessment.verdict}")

        // Dismiss touch lockout barrier as analysis is complete
        ScanLockoutOverlay.dismiss(context)
        lastRiskAssessment = assessment

        // 1. Clean up previous instances first to avoid screen clutter and leaks
        dismiss(context)

        val windowManager = context.applicationContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val inflater = LayoutInflater.from(context)

        val cardView = inflater.inflate(R.layout.overlay_threat_result, null)
        activeCardView = cardView

        // 2. Populate UI Content
        val tvVerdict = cardView.findViewById<TextView>(R.id.tv_verdict)
        val tvScore = cardView.findViewById<TextView>(R.id.tv_score)
        val tvCategory = cardView.findViewById<TextView>(R.id.tv_category)
        val tvReason = cardView.findViewById<TextView>(R.id.tv_reason)
        val tvRecommendations = cardView.findViewById<TextView>(R.id.tv_recommendations)
        val tvRecommendationsHeader = cardView.findViewById<TextView>(R.id.tv_rec_header)
        val btnDismiss = cardView.findViewById<TextView>(R.id.btn_dismiss)
        val btnToggleReport = cardView.findViewById<TextView>(R.id.btn_toggle_report)
        val layoutReportContainer = cardView.findViewById<View>(R.id.layout_report_container)
        val containerComponents = cardView.findViewById<android.widget.LinearLayout>(R.id.container_components)
        val tvReportHeader = cardView.findViewById<TextView>(R.id.tv_report_header)
        val presentation = ScanResultLocalizer.result(context, assessment)

        tvVerdict.text = presentation.verdict
        tvScore.text = ScanResultLocalizer.riskScore(
            context,
            assessment.riskScore,
            presentation.useTamil
        )
        tvReason.text = presentation.summary
        tvRecommendationsHeader.text = presentation.recommendationsHeader
        tvRecommendationsHeader.visibility =
            if (presentation.recommendations.isEmpty()) View.GONE else View.VISIBLE
        tvRecommendations.text = presentation.recommendations.joinToString("\n") { "• $it" }

        // Bind Category with Secondary Categories if present
        val catText = if (assessment.secondaryCategories.isNotEmpty()) {
            "${presentation.category} (+${assessment.secondaryCategories.joinToString { it.name }})"
        } else {
            presentation.category
        }
        tvCategory.text = catText

        // Populate Forensic Forwarding Provenance (Section 2 & 5)
        val tvFwd = cardView.findViewById<TextView>(R.id.tv_forwarding_provenance)
        if (!assessment.forwardingEvidenceLevel.isNullOrBlank() && assessment.forwardingEvidenceLevel != "ORIGINAL SOURCE UNDETERMINABLE") {
            tvFwd.visibility = View.VISIBLE
            val orig = assessment.originalSender ?: "UNKNOWN"
            val fwdBy = assessment.forwardedBy ?: "Contact"
            tvFwd.text = "🔄 Forwarded Message (${assessment.forwardingEvidenceLevel})\nOriginal Sender: $orig\nForwarded By: $fwdBy"
        } else {
            tvFwd.visibility = View.GONE
        }

        // Populate Observed Infrastructure, Auth, and Domain Intel if available
        val tvMeta = cardView.findViewById<TextView>(R.id.tv_forensic_meta)
        val metaParts = mutableListOf<String>()
        assessment.authStatusSummary?.let { metaParts.add("Auth: $it") }
        assessment.domainIntelligenceSummary?.let { metaParts.add("Domain: $it") }
        assessment.observedInfrastructure?.let { metaParts.add("Infrastructure: $it") }
        if (metaParts.isNotEmpty()) {
            tvMeta.visibility = View.VISIBLE
            tvMeta.text = metaParts.joinToString(" • ")
        } else {
            tvMeta.visibility = View.GONE
        }

        // Populate Additive Investigation & Attribution Section (SIH26106)
        val tvTrace = cardView.findViewById<TextView>(R.id.tv_investigation_trace)
        val traceParts = mutableListOf<String>()
        assessment.correlationSummary?.let { traceParts.add("🔗 Correlation: $it") }
        assessment.campaignSummary?.let { traceParts.add("🎯 Threat Campaign: $it") }
        assessment.investigationGraphSummary?.let { traceParts.add("🕸️ Graph Provenance: $it") }

        if (traceParts.isNotEmpty()) {
            tvTrace.visibility = View.VISIBLE
            tvTrace.text = traceParts.joinToString("\n\n")
        } else {
            tvTrace.visibility = View.GONE
        }

        val btnViewFullCase = cardView.findViewById<TextView>(R.id.btn_view_full_case)
        btnViewFullCase?.setOnClickListener {
            dismiss(context)
            val intent = Intent(context, com.messageguard.DetailActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                if (!assessment.backendCaseId.isNullOrBlank()) {
                    if (!assessment.backendAnalysisJson.isNullOrBlank()) {
                        putExtra("analysis_json", assessment.backendAnalysisJson)
                        putExtra("email_sender", assessment.senderEmail ?: "")
                    }
                    putExtra("backend_case_id", assessment.backendCaseId)
                } else {
                    // Circle-to-Scan local result: convert RiskAssessment into AnalysisResult
                    // so DetailActivity opens the EXACT scan rather than a generic screen
                    val appVerdict = when (assessment.verdict) {
                        ThreatVerdict.SAFE -> com.messageguard.Verdict.SAFE
                        ThreatVerdict.WARNING -> com.messageguard.Verdict.WARNING
                        ThreatVerdict.DANGER -> com.messageguard.Verdict.DANGER
                        else -> com.messageguard.Verdict.UNCERTAIN
                    }
                    val flagsList = mutableListOf<String>()
                    if (assessment.reason.isNotBlank()) flagsList.add(assessment.reason)
                    flagsList.addAll(assessment.recommendations)
                    if (assessment.correlationSummary != null) flagsList.add("Correlation: ${assessment.correlationSummary}")
                    if (assessment.campaignSummary != null) flagsList.add("Campaign: ${assessment.campaignSummary}")

                    val scanResult = com.messageguard.AnalysisResult(
                        id = 0L,
                        appSource = "Circle-to-Scan",
                        sender = assessment.senderEmail ?: "Visual Screen Capture",
                        subject = assessment.category.name,
                        messageSnippet = assessment.reason,
                        mlScore = assessment.riskScore,
                        aiScore = if (assessment.riskScore > 50) assessment.riskScore else -1,
                        riskScore = assessment.riskScore,
                        verdict = appVerdict,
                        summary = assessment.reason,
                        action = if (appVerdict == com.messageguard.Verdict.DANGER) "Quarantine / Delete" else if (appVerdict == com.messageguard.Verdict.WARNING) "Flagged / Warn User" else "Allowed",
                        senderTrust = if (appVerdict == com.messageguard.Verdict.SAFE) "High Trust" else "Untrusted",
                        timestamp = System.currentTimeMillis(),
                        flags = flagsList
                    )
                    putExtra("analysis_result", scanResult)
                    putExtra("backend_case_id", "SCAN-${System.currentTimeMillis().toString().takeLast(6)}")
                }
            }
            context.startActivity(intent)
        }

        // "Open in Gmail" — visible only when a sender email is available (backend Gmail path)
        val btnOpenInGmail = cardView.findViewById<TextView>(R.id.btn_open_in_gmail)
        if (!assessment.senderEmail.isNullOrBlank()) {
            btnOpenInGmail?.visibility = View.VISIBLE
            btnOpenInGmail?.setOnClickListener {
                dismiss(context)
                // Direct launch of Gmail inbox/conversation list (never Compose)
                val launchIntent = context.packageManager.getLaunchIntentForPackage("com.google.android.gm")?.apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
                if (launchIntent != null) {
                    try {
                        context.startActivity(launchIntent)
                        return@setOnClickListener
                    } catch (_: Exception) {}
                }
                // Generic email inbox fallback
                try {
                    val mailIntent = Intent(Intent.ACTION_MAIN).apply {
                        addCategory(Intent.CATEGORY_APP_EMAIL)
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                    context.startActivity(mailIntent)
                } catch (_: Exception) {}
            }
        } else {
            btnOpenInGmail?.visibility = View.GONE
        }

        // Populate Bixby-Style Expandable Report Components with Staggered Entrance
        val report = assessment.report
        if (report != null && report.components.isNotEmpty()) {
            containerComponents.removeAllViews()
            report.components.forEachIndexed { index, comp ->
                val rowView = TextView(context).apply {
                    val statusColor = when (comp.status) {
                        com.messageguard.threatvision.data.model.ComponentStatus.DANGER -> "#FF5252"
                        com.messageguard.threatvision.data.model.ComponentStatus.WARNING -> "#FFD700"
                        com.messageguard.threatvision.data.model.ComponentStatus.SAFE -> "#69F0AE"
                    }
                    val icon = when {
                        comp.label.contains("UPI") -> "💳"
                        comp.label.contains("URL") -> "🔗"
                        comp.label.contains("NLP") -> "🧠"
                        comp.label.contains("BODMAS") -> "⚙️"
                        comp.label.contains("Typosquat") -> "🏦"
                        else -> "☁️"
                    }
                    val detailText = if (!comp.detail.isNullOrBlank()) "\n   └ ${comp.detail}" else ""
                    val scoreDisplay = if (comp.weight == 0.0) "N/A" else "${comp.score}% risk"
                    text = "$icon ${comp.label}: $scoreDisplay$detailText"
                    setTextColor(android.graphics.Color.parseColor(statusColor))
                    textSize = 11f
                    setPadding(0, 4, 0, 4)

                    val localizedDetail = ScanResultLocalizer.componentDetail(
                        context,
                        comp.status,
                        comp.detail,
                        presentation.useTamil
                    )
                    val localizedDetailText = if (!localizedDetail.isNullOrBlank()) "\n   └ $localizedDetail" else ""
                    val localizedScore = ScanResultLocalizer.componentScore(
                        context,
                        comp.score,
                        comp.weight != 0.0,
                        presentation.useTamil
                    )
                    val localizedLabel = ScanResultLocalizer.componentLabel(context, comp.label, presentation.useTamil)
                    text = "$icon $localizedLabel: $localizedScore$localizedDetailText"
                    
                    // Reduced opacity (~50%) for N/A components so eyes prioritize active scores
                    if (comp.weight == 0.0) {
                        alpha = 0.5f
                    }
                }
                containerComponents.addView(rowView)
            }

            btnToggleReport.setOnClickListener {
                if (layoutReportContainer.visibility == View.VISIBLE) {
                    layoutReportContainer.visibility = View.GONE
                    btnToggleReport.text = presentation.expandReport
                } else {
                    // Cancel auto-dismiss timer so user has unlimited time to review the expanded report & investigation
                    autoDismissRunnable?.let {
                        mainHandler.removeCallbacks(it)
                        autoDismissRunnable = null
                    }
                    layoutReportContainer.visibility = View.VISIBLE
                    btnToggleReport.text = presentation.collapseReport

                    // Staggered Entrance Animation for component rows (60ms delay per row)
                    for (i in 0 until containerComponents.childCount) {
                        val child = containerComponents.getChildAt(i)
                        child.alpha = if ((report.components.getOrNull(i)?.weight ?: 1.0) == 0.0) 0f else 0f
                        child.translationY = 12f
                        child.animate()
                            .alpha(if ((report.components.getOrNull(i)?.weight ?: 1.0) == 0.0) 0.5f else 1.0f)
                            .translationY(0f)
                            .setDuration(200)
                            .setStartDelay(i * 60L)
                            .start()
                    }
                }
            }
            btnToggleReport.text = presentation.expandReport
        } else {
            btnToggleReport.visibility = View.GONE
        }

        // 3. Apply custom neon styles dynamically based on Threat Level
        val container = cardView.findViewById<View>(R.id.result_card_container)
        when {
            !assessment.isComplete -> {
                container.setBackgroundResource(R.drawable.bg_overlay_warning)
                tvVerdict.setTextColor(context.getColor(R.color.warning_yellow))
            }
            assessment.verdict == ThreatVerdict.SAFE -> {
                container.setBackgroundResource(R.drawable.bg_overlay_safe)
                tvVerdict.setTextColor(context.getColor(R.color.safe_green))
                tvCategory.setTextColor(context.getColor(R.color.safe_green))
            }
            assessment.verdict == ThreatVerdict.WARNING -> {
                container.setBackgroundResource(R.drawable.bg_overlay_warning)
                tvVerdict.setTextColor(context.getColor(R.color.warning_yellow))
            }
            else -> {
                container.setBackgroundResource(R.drawable.bg_overlay_danger)
                tvVerdict.setTextColor(context.getColor(R.color.danger_red))
            }
        }

        // Spring Reveal Animation for card view entrance (Scale 0.85 -> 1.0, Overshoot 1.2f)
        cardView.scaleX = 0.85f
        cardView.scaleY = 0.85f
        cardView.alpha = 0f
        cardView.animate()
            .scaleX(1.0f)
            .scaleY(1.0f)
            .alpha(1.0f)
            .setDuration(350)
            .setInterpolator(android.view.animation.OvershootInterpolator(1.2f))
            .start()

        // 4. Set up Click Listener for manual close button (✕)
        btnDismiss.setOnClickListener {
            android.util.Log.d(TAG, "FloatingResultCard: user tapped dismiss button (✕).")
            dismiss(context)
        }

        // 5. Configure Layout Params (Positioned at top-middle, non-focusable so keyboard stays open)
        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        val widthPx = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            320f,
            context.resources.displayMetrics
        ).toInt()

        val topMarginPx = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            80f,
            context.resources.displayMetrics
        ).toInt()

        val params = WindowManager.LayoutParams(
            widthPx,
            WindowManager.LayoutParams.WRAP_CONTENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = topMarginPx
        }

        // 6. Draw to window
        try {
            windowManager.addView(cardView, params)
            android.util.Log.d(TAG, "FloatingResultCard: view added to WindowManager successfully.")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "FloatingResultCard: failed to add view to WindowManager", e)
            activeCardView = null
            return
        }

        // 7. Configure Auto-Dismiss logic
        if (assessment.verdict == ThreatVerdict.SAFE && assessment.isComplete) {
            android.util.Log.d(TAG, "FloatingResultCard: SAFE verdict. Scheduling auto-dismiss in 5 seconds.")
            val runnable = Runnable {
                android.util.Log.d(TAG, "FloatingResultCard: auto-dismiss timer expired. Dismissing card.")
                dismiss(context)
            }
            autoDismissRunnable = runnable
            mainHandler.postDelayed(runnable, 5000)
        }
    }

    /**
     * Safely removes the overlay card view from WindowManager and clears auto-dismiss runnables.
     */
    fun dismiss(context: Context) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { dismiss(context) }
            return
        }

        // BUG FIX: Stop any in-progress TTS utterance immediately.
        // Removing the view from WindowManager does NOT stop TextToSpeech —
        // the engine keeps speaking unless we explicitly call stop().
        ScanLockoutOverlay.dismiss(context)
        com.messageguard.threatvision.domain.voice.VoiceCommandManager
            .getInstance(context.applicationContext)
            .stopSpeaking()

        // Cancel pending timers
        autoDismissRunnable?.let {
            mainHandler.removeCallbacks(it)
            autoDismissRunnable = null
        }

        activeCardView?.let { card ->
            try {
                val windowManager = context.applicationContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                windowManager.removeView(card)
                android.util.Log.d(TAG, "FloatingResultCard: overlay card removed from WindowManager.")
            } catch (e: Exception) {
                android.util.Log.e(TAG, "FloatingResultCard: failed to remove overlay card from WindowManager", e)
            } finally {
                activeCardView = null
            }
        }
    }
}
