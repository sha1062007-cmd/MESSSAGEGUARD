package com.messageguard

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.view.ContextThemeWrapper
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.animation.AccelerateInterpolator
import android.view.animation.Animation
import android.view.animation.AnimationUtils
import android.view.animation.DecelerateInterpolator
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import kotlin.math.abs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OverlayManager(private val context: Context) {

    private val scope = CoroutineScope(Dispatchers.Main + Job())
    private val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())

    private var overlayView: View? = null
    private var dismissRunnable: Runnable? = null
    @Volatile var isOverlayShowing = false
        private set
    private var isExpanded = false
    private var currentResult: AnalysisResult? = null
    private var lastDismissedAt = 0L

    /**
     * Optional callback invoked immediately when the overlay is dismissed by the user
     * (close button, see-report tap, or auto-timeout).
     * Hook this up to stop any active TTS utterance so the voice doesn't
     * keep speaking after the result popup disappears.
     */
    var onDismiss: (() -> Unit)? = null

    private val enterAnimation: Animation by lazy {
        AnimationUtils.loadAnimation(context, R.anim.anim_overlay_enter)
    }
    private val exitAnimation: Animation by lazy {
        AnimationUtils.loadAnimation(context, R.anim.anim_overlay_exit)
    }

    fun showDetectingState() {
        if (!android.provider.Settings.canDrawOverlays(context)) return
        if (isOverlaySuppressed() || isOverlayShowing) return
        handler.post {
            if (!android.provider.Settings.canDrawOverlays(context)) return@post
            isOverlayShowing = true
            removeOverlaySynchronous()
            isExpanded = false

            val themedContext = ContextThemeWrapper(context, R.style.Theme_MessageGuard)
            val view = LayoutInflater.from(themedContext).inflate(R.layout.overlay_bubble, null)
            
            view.findViewById<View>(R.id.loading_group).visibility = View.VISIBLE
            view.findViewById<View>(R.id.result_group).visibility = View.GONE
            
            setupDragAndExpand(view)

            val params = createLayoutParams()
            try {
                windowManager.addView(view, params)
                overlayView = view
                view.startAnimation(enterAnimation)
            } catch (e: Exception) {
                android.util.Log.w("OverlayManager", "Failed to add overlay window (permission or token invalid): ${e.message}")
                isOverlayShowing = false
                overlayView = null
            }
        }
    }

    fun transitionToResult(result: AnalysisResult) {
        handler.post {
            val view = overlayView ?: return@post
            currentResult = result
            isOverlayShowing = true

            val loadingGroup = view.findViewById<View>(R.id.loading_group)
            val resultGroup = view.findViewById<View>(R.id.result_group)
            val bubble = view.findViewById<LinearLayout>(R.id.bubble_container)

            setupResultViews(view, result)

            loadingGroup.animate().alpha(0f).setDuration(250).withEndAction {
                loadingGroup.visibility = View.GONE

                // Apply verdict-keyed obsidian border drawable
                bubble.setBackgroundResource(backgroundDrawableFor(result.verdict))
                resultGroup.alpha = 0f
                resultGroup.visibility = View.VISIBLE
                resultGroup.animate().alpha(1f).setDuration(300).start()

                animateBars(view, result)
            }.start()
        }
    }

    private fun setupResultViews(view: View, result: AnalysisResult) {
        val tvVerdict = view.findViewById<TextView>(R.id.tv_verdict)
        val tvSummary = view.findViewById<TextView>(R.id.tv_summary)
        val tvWhyFlagged = view.findViewById<TextView>(R.id.tv_why_flagged)
        val btnExpand = view.findViewById<Button>(R.id.btn_see_report)
        val btnClose = view.findViewById<Button>(R.id.btn_close_bubble)
        val btnSettings = view.findViewById<View>(R.id.btn_settings)
        
        tvVerdict.text = overlayTitleFor(result.verdict)
        tvVerdict.setTextColor(verdictTextColor(result.verdict))
        
        tvSummary.text = result.summary
        
        val whyFlagged = result.flags.find { it.startsWith("__why_flagged:") }?.removePrefix("__why_flagged:")
        if (result.verdict != Verdict.SAFE && !whyFlagged.isNullOrBlank()) {
            tvWhyFlagged.text = whyFlagged
            tvWhyFlagged.visibility = View.VISIBLE
        } else {
            tvWhyFlagged.visibility = View.GONE
        }
        
        btnSettings?.setOnClickListener {
            val intent = android.content.Intent(context, AlertSettingsActivity::class.java).apply {
                flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
            }
            context.startActivity(intent)
            removeOverlay()
        }

        btnClose.setOnClickListener {
            applyButtonPressAnim(btnClose) { onUserDismissed() }
        }
        btnExpand.setOnClickListener {
            applyButtonPressAnim(btnExpand) {
                val intent = android.content.Intent(context, DetailActivity::class.java).apply {
                    if (result.id == 0L) {
                        putExtra("analysis_result", result)
                    } else {
                        putExtra("result_id", result.id)
                    }
                    flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(intent)
                onUserDismissed()
            }
        }
    }

    /**
     * Scales button down then back up (tactile press feel) before firing [action].
     */
    private fun applyButtonPressAnim(view: View, action: () -> Unit) {
        view.animate()
            .scaleX(0.92f).scaleY(0.92f)
            .setDuration(80)
            .setInterpolator(AccelerateInterpolator())
            .withEndAction {
                view.animate()
                    .scaleX(1f).scaleY(1f)
                    .setDuration(120)
                    .setInterpolator(DecelerateInterpolator())
                    .withEndAction { action() }
                    .start()
            }.start()
    }

    private fun animateBars(view: View, result: AnalysisResult) {
        val progressMl = view.findViewById<ProgressBar>(R.id.progress_ml)
        val progressAi = view.findViewById<ProgressBar>(R.id.progress_ai)
        val progressOverall = view.findViewById<ProgressBar>(R.id.progress_overall)
        
        val tvMlScore = view.findViewById<TextView>(R.id.tv_ml_score)
        val tvAiScore = view.findViewById<TextView>(R.id.tv_ai_score)
        val tvOverallScore = view.findViewById<TextView>(R.id.tv_overall_score)

        // 1. ML Score Animation
        animateProgressBar(progressMl, result.mlScore, scoreColor(result.mlScore))
        tvMlScore.text = "${result.mlScore}%"
        tvMlScore.setTextColor(scoreColor(result.mlScore))

        // 2. AI Score Logic (Fixing the numeric leak bug)
        if (result.aiScore == -1) {
            // AI OFFLINE STATE: Gray label, hidden progress
            progressAi.visibility = View.INVISIBLE
            tvAiScore.text = "Offline"
            tvAiScore.setTextColor(Color.GRAY)
            tvAiScore.textSize = 11f
        } else {
            // AI ONLINE STATE: Normal color, animated fill
            progressAi.visibility = View.VISIBLE
            animateProgressBar(progressAi, result.aiScore, scoreColor(result.aiScore))
            tvAiScore.text = "${result.aiScore}%"
            tvAiScore.setTextColor(scoreColor(result.aiScore))
            tvAiScore.textSize = 12f
        }

        // 3. Overall Risk Animation
        animateProgressBar(progressOverall, result.riskScore, scoreColor(result.riskScore))
        tvOverallScore.text = "${result.riskScore}%"
        tvOverallScore.setTextColor(scoreColor(result.riskScore))
    }

    private fun animateProgressBar(bar: ProgressBar, target: Int, color: Int) {
        bar.progressTintList = android.content.res.ColorStateList.valueOf(color)
        val animator = ValueAnimator.ofInt(0, target)
        animator.duration = 600
        animator.interpolator = DecelerateInterpolator()
        animator.addUpdateListener { bar.progress = it.animatedValue as Int }
        animator.start()
    }

    private fun createLayoutParams() = WindowManager.LayoutParams(
        WindowManager.LayoutParams.WRAP_CONTENT,
        WindowManager.LayoutParams.WRAP_CONTENT,
        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
        PixelFormat.TRANSLUCENT
    ).apply {
        gravity = Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL
        y = 120
    }

    fun showResult(result: AnalysisResult) {
        if (!android.provider.Settings.canDrawOverlays(context)) return
        if (isOverlaySuppressed() || isOverlayShowing) return
        if (overlayView == null) {
            showDetectingState()
            handler.postDelayed({ transitionToResult(result) }, 100)
        } else {
            transitionToResult(result)
        }
    }

    fun dismissOverlay() {
        onUserDismissed()
    }

    private fun expandOverlay(view: View, result: AnalysisResult) {
        isExpanded = true
        dismissRunnable?.let { handler.removeCallbacks(it) }

        val expandedSection = view.findViewById<LinearLayout>(R.id.expanded_section)
        val tvFlags = view.findViewById<TextView>(R.id.tv_flags)
        val tvSenderTrust = view.findViewById<TextView>(R.id.tv_sender_trust)
        val tvAction = view.findViewById<TextView>(R.id.tv_action)

        val visibleFlags = result.flags.filterNot { it.startsWith("__") }
        tvFlags.text = visibleFlags.joinToString("\n") { "• $it" }
            .ifEmpty { "High-fidelity forensic verification completed." }

        tvSenderTrust.text = "Security Origin: ${result.senderTrust}"
        tvAction.text = result.action
        tvAction.setTypeface(null, Typeface.BOLD)

        expandedSection.visibility = View.VISIBLE
        expandedSection.alpha = 0f
        expandedSection.animate().alpha(1f).setDuration(250).start()

        updateLayoutParams(view, WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL)
    }

    private fun collapseOverlay(view: View) {
        isExpanded = false
        val expandedSection = view.findViewById<LinearLayout>(R.id.expanded_section)
        expandedSection.animate().alpha(0f).setDuration(150).withEndAction {
            expandedSection.visibility = View.GONE
        }.start()

        if (currentResult?.verdict == Verdict.SAFE) {
            scheduleDismiss(SAFE_AUTO_DISMISS_MS)
        }
        updateLayoutParams(view, WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE)
    }

    private fun updateLayoutParams(view: View, flags: Int) {
        val params = view.layoutParams as? WindowManager.LayoutParams ?: return
        params.flags = flags
        windowManager.updateViewLayout(view, params)
    }

    private fun setupDragAndExpand(view: View) {
        var initialX = 0; var initialY = 0; var initialTouchX = 0f; var initialTouchY = 0f
        var isDragging = false

        view.setOnTouchListener { v, event ->
            val params = v.layoutParams as? WindowManager.LayoutParams ?: return@setOnTouchListener false
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    initialX = params.x
                    initialY = params.y
                    initialTouchX = event.rawX
                    initialTouchY = event.rawY
                    isDragging = false
                    false
                }
                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - initialTouchX
                    val deltaY = event.rawY - initialTouchY
                    if (!isDragging && (abs(deltaX) > 12 || abs(deltaY) > 12)) {
                        isDragging = true
                    }
                    if (isDragging) {
                        params.x = initialX + deltaX.toInt()
                        params.y = initialY - deltaY.toInt()
                        windowManager.updateViewLayout(v, params)
                        true
                    } else {
                        false
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    isDragging = false
                    false
                }
                else -> false
            }
        }
    }

    private fun scoreColor(score: Int): Int = when {
        score >= 70 -> Color.parseColor("#FF5252")   // ruby neon
        score >= 35 -> Color.parseColor("#FFC400")   // amber neon
        else        -> Color.parseColor("#00E676")   // emerald neon
    }

    // Obsidian palette: bright neon tints on dark background
    private fun verdictTextColor(verdict: Verdict): Int = when (verdict) {
        Verdict.DANGER  -> Color.parseColor("#FF5252")
        Verdict.WARNING -> Color.parseColor("#FFC400")
        Verdict.SAFE    -> Color.parseColor("#00E676")
        Verdict.UNCERTAIN -> Color.parseColor("#9E9E9E")
    }

    private fun overlayTitleFor(verdict: Verdict) = when (verdict) {
        Verdict.DANGER  -> "⚠  HIGH RISK DETECTED"
        Verdict.WARNING -> "⚡  SUSPICIOUS ACTIVITY"
        Verdict.SAFE    -> "✓  MESSAGE VERIFIED SAFE"
        Verdict.UNCERTAIN -> "?  UNABLE TO CONFIRM"
    }

    // Returns a drawable res ID so the obsidian border glow is preserved
    private fun backgroundDrawableFor(verdict: Verdict) = when (verdict) {
        Verdict.DANGER  -> R.drawable.bg_overlay_danger
        Verdict.WARNING -> R.drawable.bg_overlay_warning
        Verdict.SAFE    -> R.drawable.bg_overlay_safe
        Verdict.UNCERTAIN -> R.drawable.bg_overlay_warning
    }

    private fun scheduleDismiss(delayMs: Long) {
        dismissRunnable?.let { handler.removeCallbacks(it) }
        dismissRunnable = Runnable { if (!isExpanded) removeOverlay() }
        handler.postDelayed(dismissRunnable!!, delayMs)
    }

    private fun onUserDismissed() {
        // Stop any active TTS utterance immediately — the popup is gone,
        // we must not let the voice keep speaking in the background.
        onDismiss?.invoke()
        isOverlayShowing = false
        lastDismissedAt = System.currentTimeMillis()
        removeOverlay()
    }

    private fun isOverlaySuppressed(): Boolean {
        // Enforce 8-second cooldown after dismiss so switching activities doesn't immediately retrigger!
        return System.currentTimeMillis() - lastDismissedAt < OVERLAY_DISMISS_SUPPRESSION_MS
    }

    private fun removeOverlaySynchronous() {
        val view = overlayView ?: return
        overlayView = null
        dismissRunnable?.let { handler.removeCallbacks(it) }
        dismissRunnable = null
        try {
            windowManager.removeViewImmediate(view)
        } catch (_: Exception) {
            runCatching { windowManager.removeView(view) }
        }
    }

    private fun removeOverlay() {
        val view = overlayView ?: return
        overlayView = null
        isOverlayShowing = false
        dismissRunnable?.let { handler.removeCallbacks(it) }
        dismissRunnable = null

        // Use ViewPropertyAnimator instead of Animation class. Animation class callbacks
        // are notoriously unreliable for views added directly to WindowManager, causing zombie views.
        view.animate()
            .alpha(0f)
            .translationY(150f)
            .setDuration(200)
            .withEndAction {
                runCatching { windowManager.removeView(view) }
            }
            .start()
    }

    companion object {
        private const val SAFE_AUTO_DISMISS_MS = 6_000L
        private const val OVERLAY_DISMISS_SUPPRESSION_MS = 8_000L
    }
}
