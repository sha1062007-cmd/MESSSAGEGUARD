package com.messageguard.threatvision.service

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.PixelFormat
import android.graphics.RectF
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.view.WindowManager
import com.messageguard.threatvision.ui.components.DrawingCanvasView

class OverlaySelectionService : Service() {

    private lateinit var windowManager: WindowManager
    private var canvasView: DrawingCanvasView? = null

    private var projectionService: MediaProjectionService? = null
    private var isBound = false
    private var pendingBounds: RectF? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? MediaProjectionService.MediaProjectionBinder
            projectionService = binder?.getService()
            isBound = true

            // Register onReadyListener to drain pendingBounds as soon as isProjectionReady flips to true
            projectionService?.onReadyListener = {
                drainPendingBoundsIfReady()
            }

            // Attempt to drain immediately if projection was already ready at bind time
            drainPendingBoundsIfReady()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            projectionService = null
            isBound = false
        }
    }

    private fun drainPendingBoundsIfReady() {
        pendingBounds?.let { bounds ->
            if (isBound && projectionService?.isProjectionReady == true) {
                projectionService?.captureAndCropRegion(bounds)
                pendingBounds = null
                stopSelf()
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        android.util.Log.d("ThreatVisionLog", "OverlaySelectionService: onCreate called.")
        if (!MediaProjectionService.isSessionActive) {
            android.util.Log.w("ThreatVisionLog", "OverlaySelectionService: MediaProjectionService session is not active. Stopping service immediately.")
            stopSelf()
            return
        }
        bindProjectionService()
        setupOverlayCanvas()
    }

    private fun bindProjectionService() {
        android.util.Log.d("ThreatVisionLog", "OverlaySelectionService: binding to MediaProjectionService.")
        val intent = Intent(this, MediaProjectionService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE or Context.BIND_IMPORTANT)
    }

    private fun setupOverlayCanvas() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            android.util.Log.e("ThreatVisionLog", "OverlaySelectionService: cannot draw overlays permission missing. Stopping.")
            stopSelf()
            return
        }

        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        android.util.Log.d("ThreatVisionLog", "OverlaySelectionService: initializing DrawingCanvasView.")

        val drawingView = DrawingCanvasView(this).apply {
            onSelectionComplete = { bounds, _ ->
                android.util.Log.d("ThreatVisionLog", "Circle selection complete with bounds: $bounds. isBound=$isBound, isProjectionReady=${projectionService?.isProjectionReady}")
                if (isBound && projectionService?.isProjectionReady == true) {
                    android.util.Log.d("ThreatVisionLog", "Projection service ready. Triggering captureAndCropRegion.")
                    projectionService?.captureAndCropRegion(bounds)
                    stopSelf()
                } else {
                    android.util.Log.d("ThreatVisionLog", "Projection service not ready yet. Queuing pendingBounds.")
                    pendingBounds = bounds
                }
            }
            onCancelRequested = {
                android.util.Log.d("ThreatVisionLog", "OverlaySelectionService: Cancel requested by user. Tearing down selection canvas.")
                android.widget.Toast.makeText(this@OverlaySelectionService, "Scan cancelled", android.widget.Toast.LENGTH_SHORT).show()
                stopSelf()
            }
        }
        canvasView = drawingView

        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

        val layoutParams = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        )

        try {
            windowManager.addView(canvasView, layoutParams)
            android.util.Log.d("ThreatVisionLog", "OverlaySelectionService: drawing canvas view successfully added to WindowManager.")
        } catch (e: Exception) {
            android.util.Log.e("ThreatVisionLog", "OverlaySelectionService: failed to add canvas view", e)
            stopSelf()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        android.util.Log.d("ThreatVisionLog", "OverlaySelectionService: onDestroy called, tearing down canvas.")
        projectionService?.onReadyListener = null
        if (isBound) {
            try {
                unbindService(serviceConnection)
            } catch (_: Exception) {}
            isBound = false
        }
        if (canvasView != null) {
            try {
                windowManager.removeView(canvasView)
            } catch (_: IllegalArgumentException) {}
            canvasView = null
        }
    }
}
