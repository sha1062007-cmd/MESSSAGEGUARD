package com.messageguard.threatvision.ui.components

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView

/**
 * Full-screen touch lockout overlay for Threat Vision scanning.
 * When a scan is initiated (e.g. single tap on floating bubble), this overlay
 * consumes ALL touch events on screen to prevent user typing, tab switching,
 * or background navigation while ML models & Gemini analyze the message.
 *
 * Displays:
 * "🛡️ THREAT VISION: ANALYZING..."
 * "Touch locked to ensure security · Please wait..."
 */
object ScanLockoutOverlay {

    private const val TAG = "ThreatVisionLog"
    private var lockoutView: View? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var autoUnlockRunnable: Runnable? = null

    /**
     * Activates full-screen touch lock.
     * Consumes touches and displays the scanning state.
     * Auto-times out after 12 seconds as a safeguard.
     */
    fun show(context: Context, statusMessage: String = "Analyzing Email for Threats...") {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { show(context, statusMessage) }
            return
        }

        dismiss(context)

        val windowManager = context.applicationContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager

        // Create root full-screen container that intercepts all touches
        val rootLayout = FrameLayout(context).apply {
            setBackgroundColor(Color.parseColor("#80000000")) // 50% dark dimming overlay
            isClickable = true
            isFocusable = true

            // Consume all touch events completely to lock the screen
            setOnTouchListener { _, _ ->
                // Return true so no touches leak to the underlying app (e.g. Gmail)
                true
            }
        }

        // Create stylish centered card
        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            val padding = dpToPx(context, 24f)
            setPadding(padding, padding, padding, padding)
            background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE
                cornerRadius = dpToPx(context, 16f).toFloat()
                setColor(Color.parseColor("#1C2438"))
                setStroke(dpToPx(context, 2f), Color.parseColor("#00E5FF")) // neon cyan border
            }
        }

        val cardParams = FrameLayout.LayoutParams(
            dpToPx(context, 320f),
            FrameLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            gravity = Gravity.CENTER
        }

        // Header Title
        val tvTitle = TextView(context).apply {
            text = "🛡️ THREAT VISION ACTIVE"
            textSize = 15f
            setTextColor(Color.parseColor("#00E5FF"))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            letterSpacing = 0.05f
        }
        card.addView(tvTitle)

        // Progress bar
        val progressBar = ProgressBar(context).apply {
            val size = dpToPx(context, 36f)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                topMargin = dpToPx(context, 16f)
                bottomMargin = dpToPx(context, 12f)
            }
        }
        card.addView(progressBar)

        // Status text
        val tvStatus = TextView(context).apply {
            text = statusMessage
            textSize = 14f
            setTextColor(Color.WHITE)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }
        card.addView(tvStatus)

        // Lockout note
        val tvLockNote = TextView(context).apply {
            text = "Screen touch locked during analysis\nPreventing fraudulent actions..."
            textSize = 12f
            setTextColor(Color.parseColor("#B0BEC5"))
            gravity = Gravity.CENTER
            setPadding(0, dpToPx(context, 6f), 0, 0)
        }
        card.addView(tvLockNote)

        // Emergency unlock button (small text at bottom)
        val btnUnlock = TextView(context).apply {
            text = "Cancel Scan"
            textSize = 11f
            setTextColor(Color.parseColor("#FF5252"))
            setPadding(
                dpToPx(context, 12f),
                dpToPx(context, 8f),
                dpToPx(context, 12f),
                dpToPx(context, 8f)
            )
            gravity = Gravity.CENTER
            setOnClickListener {
                android.util.Log.d(TAG, "ScanLockoutOverlay: emergency unlock tapped by user.")
                dismiss(context)
            }
        }
        val unlockParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = dpToPx(context, 14f)
        }
        card.addView(btnUnlock, unlockParams)

        rootLayout.addView(card, cardParams)

        // Layout params for full-screen modal touch blocker
        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        // Crucial: Omit FLAG_NOT_TOUCH_MODAL and FLAG_NOT_FOCUSABLE to capture all touches!
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.CENTER
        }

        try {
            windowManager.addView(rootLayout, params)
            lockoutView = rootLayout
            android.util.Log.d(TAG, "ScanLockoutOverlay: full-screen touch lock activated.")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "ScanLockoutOverlay: failed to add lockout view", e)
            lockoutView = null
            return
        }

        // Safety timeout: auto-unlock after 12 seconds in case scan hangs
        autoUnlockRunnable = Runnable {
            android.util.Log.w(TAG, "ScanLockoutOverlay: 12-second safety timeout expired. Unlocking screen.")
            dismiss(context)
        }
        mainHandler.postDelayed(autoUnlockRunnable!!, 12000)
    }

    /**
     * Unlocks the screen and removes the overlay.
     */
    fun dismiss(context: Context) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { dismiss(context) }
            return
        }

        autoUnlockRunnable?.let {
            mainHandler.removeCallbacks(it)
            autoUnlockRunnable = null
        }

        lockoutView?.let { view ->
            try {
                val windowManager = context.applicationContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                windowManager.removeView(view)
                android.util.Log.d(TAG, "ScanLockoutOverlay: screen touch lock released.")
            } catch (e: Exception) {
                android.util.Log.e(TAG, "ScanLockoutOverlay: failed to remove lockout view", e)
            } finally {
                lockoutView = null
            }
        }
    }

    val isLockActive: Boolean
        get() = lockoutView != null

    private fun dpToPx(context: Context, dp: Float): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp,
            context.resources.displayMetrics
        ).toInt()
    }
}
