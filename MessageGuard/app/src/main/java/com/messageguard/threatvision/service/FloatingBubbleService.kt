package com.messageguard.threatvision.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.TypedValue
import android.content.ActivityNotFoundException
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.Animation
import android.view.animation.RotateAnimation
import android.view.animation.ScaleAnimation
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.core.app.NotificationCompat
import com.messageguard.R
import com.messageguard.threatvision.domain.voice.VoiceCommandManager
import com.messageguard.threatvision.ui.main.CapturePermissionActivity

class FloatingBubbleService : Service() {

    /** Pending full-screen capture runnable — stored so a bubble tap during the
     *  1.5-second confirmation window can cancel it before capture fires. */
    private var pendingFullScreenCapture: Runnable? = null

    private lateinit var windowManager: WindowManager
    private var bubbleView: View? = null
    private var layoutParams: WindowManager.LayoutParams? = null

    // ── 3-State UI overlay elements ─────────────────────────────────────
    private var micBadge: View? = null           // State 1: green mic badge
    private var statusLabel: TextView? = null     // State 2/3: "Listening..." / "Analyzing..."
    private var pulseAnimation: ScaleAnimation? = null
    private var spinAnimation: RotateAnimation? = null

    companion object {
        private const val NOTIFICATION_ID = 9001
        private const val CHANNEL_ID = "threat_vision_bubble_channel"
        const val ACTION_START_SCAN = "com.messageguard.ACTION_START_SCAN"
        const val ACTION_HANDLE_VOICE_COMMAND = "com.messageguard.ACTION_HANDLE_VOICE_COMMAND"
        const val EXTRA_SPOKEN_TEXT = "extra_spoken_text"
        
        fun startService(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(context)) {
                android.util.Log.w("ThreatVisionLog", "FloatingBubbleService: cannot start, overlay permission not granted.")
                return
            }
            val intent = Intent(context, FloatingBubbleService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopService(context: Context) {
            val intent = Intent(context, FloatingBubbleService::class.java)
            context.stopService(intent)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundServiceNotification()
        if (intent?.action == ACTION_START_SCAN) {
            android.util.Log.d("ThreatVisionLog", "FloatingBubbleService received ACTION_START_SCAN. Initiating canonical Circle-to-Scan flow.")
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                onBubbleTapped()
            }
            return START_STICKY
        }
        if (intent?.action == ACTION_HANDLE_VOICE_COMMAND) {
            val spokenText = intent.getStringExtra(EXTRA_SPOKEN_TEXT)
            if (!spokenText.isNullOrBlank()) {
                val voiceManager = VoiceCommandManager.getInstance(this)
                val command = voiceManager.interpretText(spokenText)
                android.util.Log.d("ThreatVisionLog", "FloatingBubbleService received voice command from Intent: '$spokenText' -> $command")
                handleVoiceCommand(command, voiceManager)
            }
            return START_STICKY
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startForegroundServiceNotification()
        setupFloatingBubble()
        setupVoiceCallbacks()

        // Long-lived Registration: MediaStoreDownloadObserver & Fallback Sweep Worker tied to Service lifecycle
        com.messageguard.sandbox.trigger.MediaStoreDownloadObserver.register(this)
        com.messageguard.sandbox.worker.PeriodicDownloadSweepWorker.schedule(this)

        // Always-on wake-word listening is DISABLED (architecturally broken on Android).
        // Voice entry point is Push-to-Talk only (bubble tap → startListeningForCommand).
    }

    private fun startForegroundServiceNotification() {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Threat Vision Active",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "MessageGuard's protection bubble is active"
            }
            notificationManager.createNotificationChannel(channel)
        }

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Threat Vision Active")
            .setContentText("Tap to scan; hold for a voice command")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun dpToPx(dp: Float): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp,
            resources.displayMetrics
        ).toInt()
    }

    // ═══════════════════════════════════════════════════════════════════
    //  FLOATING BUBBLE SETUP & 3-STATE VISUAL OVERLAY
    // ═══════════════════════════════════════════════════════════════════

    private fun setupFloatingBubble() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            val permissionIntent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName")
            ).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(permissionIntent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
            return
        }

        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager

        // Build compact composite bubble: 40dp icon + mic badge + status label
        val container = FrameLayout(this)

        // Main compact bubble icon (40dp)
        val bubbleImageView = ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            contentDescription = "Threat Vision Bubble"
        }
        container.addView(bubbleImageView, FrameLayout.LayoutParams(
            dpToPx(40f), dpToPx(40f)
        ))

        // State 1: Green mic badge (bottom-right corner of bubble)
        val badge = View(this).apply {
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(Color.parseColor("#4CAF50"))  // green
                setStroke(dpToPx(1f), Color.WHITE)
            }
            visibility = View.GONE
        }
        val badgeSize = dpToPx(10f)
        val badgeParams = FrameLayout.LayoutParams(badgeSize, badgeSize).apply {
            gravity = Gravity.BOTTOM or Gravity.END
            marginEnd = dpToPx(1f)
            bottomMargin = dpToPx(1f)
        }
        container.addView(badge, badgeParams)
        micBadge = badge

        // State 2/3: Status text label (below bubble)
        val label = TextView(this).apply {
            textSize = 9f
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.parseColor("#CC000000"))
            setPadding(dpToPx(3f), dpToPx(1f), dpToPx(3f), dpToPx(1f))
            gravity = Gravity.CENTER
            visibility = View.GONE
        }
        val labelParams = FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.WRAP_CONTENT,
            FrameLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            gravity = Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL
            topMargin = dpToPx(42f)
        }
        container.addView(label, labelParams)
        statusLabel = label

        bubbleView = container

        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        val bubbleWidth = dpToPx(48f)   // compact width
        val bubbleHeight = dpToPx(58f)  // compact height
        val initialX = dpToPx(16f)
        val initialY = dpToPx(120f)

        layoutParams = WindowManager.LayoutParams(
            bubbleWidth,
            bubbleHeight,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = initialX
            y = initialY
        }

        try {
            windowManager.addView(bubbleView, layoutParams)
            com.messageguard.threatvision.state.ThreatVisionStateHolder.onBubbleStarted()
            android.util.Log.d("ThreatVisionLog", "Floating bubble view added successfully to WindowManager.")
        } catch (e: Exception) {
            android.util.Log.e("ThreatVisionLog", "Failed to add floating bubble view to WindowManager", e)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
            return
        }

        setupTouchAndDragListener()
    }

    // ═══════════════════════════════════════════════════════════════════
    //  3-STATE VISUAL TRANSITIONS
    // ═══════════════════════════════════════════════════════════════════

    private fun updateVisualState(state: VoiceCommandManager.ListeningState) {
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            // Clear previous animations
            bubbleView?.clearAnimation()
            pulseAnimation?.cancel()
            spinAnimation?.cancel()

            when (state) {
                VoiceCommandManager.ListeningState.ACTIVE_COMMAND -> {
                    // State 2: pulsing neon ring + "Listening..." label
                    micBadge?.visibility = View.VISIBLE
                    (micBadge?.background as? GradientDrawable)?.setColor(Color.parseColor("#00E5FF"))  // neon cyan
                    statusLabel?.text = "🎙️ Listening..."
                    statusLabel?.visibility = View.VISIBLE

                    // Pulse animation on the bubble
                    pulseAnimation = ScaleAnimation(
                        1.0f, 1.15f, 1.0f, 1.15f,
                        Animation.RELATIVE_TO_SELF, 0.5f,
                        Animation.RELATIVE_TO_SELF, 0.5f
                    ).apply {
                        duration = 600
                        repeatCount = Animation.INFINITE
                        repeatMode = Animation.REVERSE
                        interpolator = AccelerateDecelerateInterpolator()
                    }
                    bubbleView?.startAnimation(pulseAnimation)
                }
                VoiceCommandManager.ListeningState.ANALYZING -> {
                    // State 3: distinct orange badge + "Analyzing..." label + rotation
                    micBadge?.visibility = View.VISIBLE
                    (micBadge?.background as? GradientDrawable)?.setColor(Color.parseColor("#FF9800"))  // orange
                    statusLabel?.text = "⏳ Analyzing..."
                    statusLabel?.visibility = View.VISIBLE

                    // Rotate animation for analyzing indicator
                    spinAnimation = RotateAnimation(
                        0f, 360f,
                        Animation.RELATIVE_TO_SELF, 0.5f,
                        Animation.RELATIVE_TO_SELF, 0.5f
                    ).apply {
                        duration = 1200
                        repeatCount = Animation.INFINITE
                        interpolator = AccelerateDecelerateInterpolator()
                    }
                    micBadge?.startAnimation(spinAnimation)
                }
                VoiceCommandManager.ListeningState.STOPPED -> {
                    // No visual indicators
                    micBadge?.visibility = View.GONE
                    statusLabel?.visibility = View.GONE
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  VOICE CALLBACK WIRING & ALWAYS-ON STARTUP
    // ═══════════════════════════════════════════════════════════════════

    private fun setupVoiceCallbacks() {
        val voiceManager = VoiceCommandManager.getInstance(this)

        // Wire up state change → visual transition
        voiceManager.onStateChanged = { state ->
            android.util.Log.d("ThreatVisionLog", "FloatingBubbleService: Voice state → $state")
            updateVisualState(state)
        }

        // Wire up command recognized
        voiceManager.onCommandRecognized = { command ->
            handleVoiceCommand(command, voiceManager)
        }

        // Wire up errors — simple message + audio already handled in VoiceCommandManager
        voiceManager.onError = { errorMsg ->
            android.util.Log.e("ThreatVisionLog", "VoiceCommandManager error: $errorMsg")
            android.widget.Toast.makeText(this, errorMsg, android.widget.Toast.LENGTH_LONG).show()
        }
    }


    private fun handleVoiceCommand(command: VoiceCommandManager.VoiceCommand, voiceManager: VoiceCommandManager) {
        when (command) {
            is VoiceCommandManager.VoiceCommand.ScanThis -> {
                android.util.Log.d("ThreatVisionLog", "Voice command: 'scan this'. Launching circle selection overlay.")
                voiceManager.playPreScanChime()
                android.widget.Toast.makeText(this, "Opening selection canvas...", android.widget.Toast.LENGTH_SHORT).show()
                voiceManager.signalAnalyzing()
                onBubbleTapped()
            }
            is VoiceCommandManager.VoiceCommand.ScanPage -> {
                android.util.Log.d("ThreatVisionLog", "Voice command: 'scan the page'. Triggering pre-scan chime and full screen capture.")

                if (!MediaProjectionService.isSessionActive) {
                    android.util.Log.w("ThreatVisionLog", "Full-screen scan requested but no active projection session.")
                    android.widget.Toast.makeText(this, "Please enable Protection first, then try again.", android.widget.Toast.LENGTH_LONG).show()
                    voiceManager.speakError("Protection is not active. Please enable it first.")
                    // Return to wake-word listening
                    voiceManager.signalAnalysisComplete()
                } else {
                    voiceManager.signalAnalyzing()

                    // Pre-capture confirmation: chime + visual toast + 1.5s cancellable delay.
                    voiceManager.playPreScanChime()
                    android.widget.Toast.makeText(this, "📷 Scanning full screen in 1.5s... Tap bubble to cancel.", android.widget.Toast.LENGTH_SHORT).show()
                    
                    val captureRunnable = Runnable {
                        pendingFullScreenCapture = null
                        android.util.Log.d("ThreatVisionLog", "Full-screen capture delay elapsed. Firing capture now.")
                        val fullScreenIntent = Intent(this, MediaProjectionService::class.java).apply {
                            action = MediaProjectionService.ACTION_CAPTURE_FULL_SCREEN
                        }
                        androidx.core.content.ContextCompat.startForegroundService(this, fullScreenIntent)
                    }
                    pendingFullScreenCapture = captureRunnable
                    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(captureRunnable, 1500)
                }
            }
            is VoiceCommandManager.VoiceCommand.ToggleOn -> {
                android.util.Log.d("ThreatVisionLog", "Voice command: 'turn on'. Enabling Threat Vision protection.")
                com.messageguard.threatvision.state.ThreatVisionStateHolder.enableProtection(this)
                android.widget.Toast.makeText(this, "Threat Vision Protection ON", android.widget.Toast.LENGTH_SHORT).show()
                voiceManager.signalAnalysisComplete()
            }
            is VoiceCommandManager.VoiceCommand.ToggleOff -> {
                android.util.Log.d("ThreatVisionLog", "Voice command: 'turn off'. Disabling Threat Vision protection.")
                com.messageguard.threatvision.state.ThreatVisionStateHolder.disableProtection(this)
                android.widget.Toast.makeText(this, "Threat Vision Protection OFF", android.widget.Toast.LENGTH_SHORT).show()
                voiceManager.signalAnalysisComplete()
            }
            is VoiceCommandManager.VoiceCommand.Unknown -> {
                android.util.Log.w("ThreatVisionLog", "Voice command unrecognized: '${command.spokenText}'")
                android.widget.Toast.makeText(this, "Unrecognized: '${command.spokenText}'. Try 'scan this' or 'scan the page'.", android.widget.Toast.LENGTH_LONG).show()
                // Return to wake-word listening
                voiceManager.signalAnalysisComplete()
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  TOUCH, DRAG, AND LONG-PRESS (PUSH-TO-TALK FALLBACK)
    // ═══════════════════════════════════════════════════════════════════

    private fun setupTouchAndDragListener() {
        val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
        var longPressRunnable: Runnable? = null

        bubbleView?.setOnTouchListener(object : View.OnTouchListener {
            private var initialX = 0
            private var initialY = 0
            private var initialTouchX = 0f
            private var initialTouchY = 0f
            private var isClick = false
            private var isLongPress = false

            override fun onTouch(v: View?, event: MotionEvent): Boolean {
                val params = layoutParams ?: return false

                when (event.action) {
                    MotionEvent.ACTION_DOWN -> {
                        initialX = params.x
                        initialY = params.y
                        initialTouchX = event.rawX
                        initialTouchY = event.rawY
                        isClick = true
                        isLongPress = false

                        longPressRunnable = Runnable {
                            if (isClick) {
                                isLongPress = true
                                isClick = false
                                onBubbleLongPressed()
                            }
                        }
                        mainHandler.postDelayed(longPressRunnable!!, 600)
                        return true
                    }
                    MotionEvent.ACTION_MOVE -> {
                        val dx = (event.rawX - initialTouchX).toInt()
                        val dy = (event.rawY - initialTouchY).toInt()

                        if (Math.abs(dx) > 10 || Math.abs(dy) > 10) {
                            isClick = false
                            longPressRunnable?.let { mainHandler.removeCallbacks(it) }
                        }

                        params.x = initialX + dx
                        params.y = initialY + dy
                        try {
                            windowManager.updateViewLayout(bubbleView, params)
                        } catch (_: Exception) {}
                        return true
                    }
                    MotionEvent.ACTION_UP -> {
                        longPressRunnable?.let { mainHandler.removeCallbacks(it) }
                        if (isClick && !isLongPress) {
                            onBubbleTapped()
                        }
                        return true
                    }
                    MotionEvent.ACTION_CANCEL -> {
                        longPressRunnable?.let { mainHandler.removeCallbacks(it) }
                        return true
                    }
                }
                return false
            }
        })
    }

    /**
     * Long-press: User Voice Command (Push-to-Talk).
     * Always listens for user voice commands ("scan this", "scan the page", "turn on", "turn off").
     * Does NOT automatically scan or read old cards on long-press — waits for your spoken command.
     */
    private fun onBubbleLongPressed() {
        android.util.Log.d("ThreatVisionLog", "FloatingBubbleService: Long-press detected. Starting in-app speech recognition.")

        cancelPendingFullScreenCapture()

        val voiceManager = com.messageguard.threatvision.domain.voice.VoiceCommandManager.getInstance(this)

        // Check RECORD_AUDIO permission before starting speech recognizer
        if (androidx.core.content.ContextCompat.checkSelfPermission(
                this,
                android.Manifest.permission.RECORD_AUDIO
            ) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            android.util.Log.w("ThreatVisionLog", "FloatingBubbleService: RECORD_AUDIO permission missing. Requesting in MainActivity.")
            android.widget.Toast.makeText(
                this,
                "Microphone permission required for voice commands.",
                android.widget.Toast.LENGTH_LONG
            ).show()

            val mainActivityIntent = Intent(this, com.messageguard.MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                putExtra(com.messageguard.MainActivity.EXTRA_REQUEST_RECORD_AUDIO, true)
            }
            startActivity(mainActivityIntent)
            return
        }

        try {
            voiceManager.startListeningForCommand()
        } catch (e: Exception) {
            android.util.Log.w("ThreatVisionLog", "Failed to start voice listener: $e")
            voiceManager.playTryAgainChime()
            android.widget.Toast.makeText(this, "Didn't catch that, try again", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    /**
     * On bubble single tap:
     * Restores the original Circle-to-Scan gesture selection overlay (DrawingCanvasView).
     * The user draws a circle/rectangle box around any message, and ONLY that region is captured & analyzed.
     */
    private fun onBubbleTapped() {
        if (cancelPendingFullScreenCapture()) {
            android.util.Log.d("ThreatVisionLog", "Bubble tapped during full-screen capture countdown. Capture cancelled.")
            android.widget.Toast.makeText(this, "Scan cancelled.", android.widget.Toast.LENGTH_SHORT).show()
            com.messageguard.threatvision.ui.components.ScanLockoutOverlay.dismiss(this)
            VoiceCommandManager.getInstance(this).signalAnalysisComplete()
            return
        }

        val projectionAlreadyActive = MediaProjectionService.isSessionActive

        if (projectionAlreadyActive) {
            android.util.Log.d("ThreatVisionLog", "Bubble tapped: projection active. Launching OverlaySelectionService for user Circle-to-Scan region selection.")
            val overlayIntent = Intent(this, OverlaySelectionService::class.java)
            startService(overlayIntent)
        } else {
            android.util.Log.d("ThreatVisionLog", "Bubble tapped: no active projection. Launching CapturePermissionActivity for consent.")
            val consentIntent = Intent(this, CapturePermissionActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(consentIntent)
        }
    }

    /**
     * Cancels a pending full-screen capture if one is queued.
     * Returns true if a capture was actually cancelled, false if nothing was pending.
     */
    private fun cancelPendingFullScreenCapture(): Boolean {
        val pending = pendingFullScreenCapture ?: return false
        android.os.Handler(android.os.Looper.getMainLooper()).removeCallbacks(pending)
        pendingFullScreenCapture = null
        android.util.Log.d("ThreatVisionLog", "Pending full-screen capture cancelled.")
        return true
    }

    override fun onDestroy() {
        super.onDestroy()
        com.messageguard.threatvision.state.ThreatVisionStateHolder.onBubbleStopped(this)
        VoiceCommandManager.getInstance(this).shutdown()
        com.messageguard.sandbox.trigger.MediaStoreDownloadObserver.unregister(this)
        if (bubbleView != null) {
            try {
                windowManager.removeView(bubbleView)
            } catch (_: IllegalArgumentException) {}
            bubbleView = null
        }
    }
}
