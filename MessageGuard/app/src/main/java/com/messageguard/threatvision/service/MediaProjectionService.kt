package com.messageguard.threatvision.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.graphics.RectF
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.DisplayMetrics
import android.util.Log
import android.view.WindowManager
import androidx.core.app.NotificationCompat
import com.messageguard.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Foreground service that holds a single [MediaProjection] for the entire
 * Protection session.  The projection is obtained once (via user consent in
 * [CapturePermissionActivity]) and reused across multiple circle-and-scan
 * gestures without re-prompting.
 *
 * Per-scan ephemeral resources ([VirtualDisplay], [ImageReader]) are created
 * and released inside [captureAndCropRegion], but the [MediaProjection] itself
 * stays alive until the service is explicitly stopped (Protection OFF) or the
 * system revokes it via [MediaProjection.Callback.onStop].
 */
class MediaProjectionService : Service() {

    inner class MediaProjectionBinder : Binder() {
        fun getService(): MediaProjectionService = this@MediaProjectionService
    }

    private val binder = MediaProjectionBinder()
    private var mediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var projectionCallback: MediaProjection.Callback? = null

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.Main + serviceJob)

    var isProjectionReady: Boolean = false
        private set

    var onReadyListener: (() -> Unit)? = null

    companion object {
        private const val TAG = "ThreatVisionLog"
        private const val NOTIFICATION_ID = 9002
        private const val CHANNEL_ID = "media_projection_channel"

        const val EXTRA_RESULT_CODE = "extra_result_code"
        const val EXTRA_DATA_INTENT = "extra_data_intent"
        const val ACTION_CAPTURE_FULL_SCREEN = "com.messageguard.ACTION_CAPTURE_FULL_SCREEN"

        var onCroppedBitmapCaptured: ((Bitmap) -> Unit)? = null

        /**
         * Static flag indicating whether a MediaProjection session is currently
         * active.  Checked by [FloatingBubbleService] on bubble tap to decide
         * whether to skip consent and launch the drawing canvas directly.
         */
        @Volatile
        var isSessionActive: Boolean = false
            private set

        internal fun markSessionActive() { isSessionActive = true }
        internal fun markSessionInactive() { isSessionActive = false }

        fun stopService(context: Context) {
            val intent = Intent(context, MediaProjectionService::class.java)
            context.stopService(intent)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        startForegroundNotification()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotification()

        if (intent?.action == ACTION_CAPTURE_FULL_SCREEN) {
            Log.d(TAG, "MediaProjectionService onStartCommand: ACTION_CAPTURE_FULL_SCREEN received.")
            captureFullScreen()
            return START_NOT_STICKY
        }

        val resultCode = intent?.getIntExtra(EXTRA_RESULT_CODE, 0) ?: 0
        val dataIntent = intent?.getParcelableExtra<Intent>(EXTRA_DATA_INTENT)

        if (resultCode != 0 && dataIntent != null) {
            // Only initialize if we don't already have an active projection
            if (mediaProjection == null) {
                val projectionManager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
                mediaProjection = projectionManager.getMediaProjection(resultCode, dataIntent)

                val cb = object : MediaProjection.Callback() {
                    override fun onStop() {
                        Log.d(TAG, "MediaProjection.Callback.onStop: system revoked projection.")
                        releaseAllResources()
                    }
                }
                projectionCallback = cb
                mediaProjection?.registerCallback(cb, Handler(Looper.getMainLooper()))
                isProjectionReady = true
                markSessionActive()
                com.messageguard.threatvision.state.ThreatVisionStateHolder.onProjectionStarted(this)
                Log.d(TAG, "MediaProjectionService initialized: isProjectionReady=true. Projection held for session.")
                ensureVirtualDisplayCreated()
                onReadyListener?.invoke()

                // Explicitly DO NOT auto-launch selection overlay when a projection
                // session becomes active. Screen sharing is a persistent capability only;
                // the user must tap the floating bubble to start a Circle-to-Scan.
                Log.d(TAG, "Projection session is ready. Waiting for explicit user gesture before starting selection overlay.")
            } else {
                Log.d(TAG, "MediaProjectionService.onStartCommand: projection already active, ignoring duplicate init.")
            }
        }

        return START_NOT_STICKY
    }

    private fun startForegroundNotification() {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Screen Capture Active",
                NotificationManager.IMPORTANCE_LOW
            )
            notificationManager.createNotificationChannel(channel)
        }

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Screen Capture Active")
            .setContentText("Capturing user-selected region for threat analysis")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun ensureVirtualDisplayCreated() {
        if (virtualDisplay == null && mediaProjection != null) {
            try {
                val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
                val metrics = DisplayMetrics()
                @Suppress("DEPRECATION")
                wm.defaultDisplay.getMetrics(metrics)
                val width = metrics.widthPixels
                val height = metrics.heightPixels
                val density = metrics.densityDpi

                imageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
                virtualDisplay = mediaProjection?.createVirtualDisplay(
                    "ThreatVisionScreenCapture",
                    width,
                    height,
                    density,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    imageReader?.surface,
                    null,
                    null
                )
                Log.d(TAG, "ensureVirtualDisplayCreated: Persistent VirtualDisplay and ImageReader created successfully.")
            } catch (e: Exception) {
                Log.e(TAG, "ensureVirtualDisplayCreated: Failed to initialize persistent VirtualDisplay", e)
            }
        }
    }

    /**
     * Captures the screen and crops to [cropRect]. Uses the persistent
     * [VirtualDisplay] + [ImageReader] held alive for the session.
     */
    fun captureAndCropRegion(cropRect: RectF) {
        Log.d(TAG, "captureAndCropRegion called with cropRect: $cropRect. isProjectionReady=$isProjectionReady")
        if (!isProjectionReady || mediaProjection == null) {
            Log.e(TAG, "captureAndCropRegion: projection not ready or null. Aborting.")
            return
        }

        // Initialize VirtualDisplay and ImageReader if not already done
        ensureVirtualDisplayCreated()

        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getMetrics(metrics)
        val width = metrics.widthPixels
        val height = metrics.heightPixels

        // 1. Try to acquire the latest image immediately from the buffer
        val immediateImage: Image? = try {
            imageReader?.acquireLatestImage()
        } catch (e: Exception) {
            Log.w(TAG, "captureAndCropRegion: Failed to acquire image immediately from buffer", e)
            null
        }

        if (immediateImage != null) {
            Log.d(TAG, "captureAndCropRegion: acquired image immediately from buffer.")
            processAndCropImage(immediateImage, cropRect, width, height)
        } else {
            Log.d(TAG, "captureAndCropRegion: no image in buffer, registering listener.")
            imageReader?.setOnImageAvailableListener({ reader ->
                // Unregister listener immediately to process exactly one frame
                reader.setOnImageAvailableListener(null, null)

                val image: Image? = try {
                    reader.acquireLatestImage() ?: reader.acquireNextImage()
                } catch (e: Exception) {
                    Log.e(TAG, "captureAndCropRegion listener: Failed to acquire image inside listener", e)
                    null
                }

                if (image != null) {
                    processAndCropImage(image, cropRect, width, height)
                } else {
                    Log.e(TAG, "captureAndCropRegion listener: Acquired image is null.")
                }
            }, Handler(Looper.getMainLooper()))
        }
    }

    private fun processAndCropImage(image: Image, cropRect: RectF, width: Int, height: Int) {
        try {
            val planes = image.planes
            val buffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * width

            val bitmap = Bitmap.createBitmap(
                width + rowPadding / pixelStride,
                height,
                Bitmap.Config.ARGB_8888
            )
            bitmap.copyPixelsFromBuffer(buffer)
            image.close()

            val cropLeft = cropRect.left.toInt().coerceIn(0, width - 1)
            val cropTop = cropRect.top.toInt().coerceIn(0, height - 1)
            val cropWidth = cropRect.width().toInt().coerceAtMost(width - cropLeft)
            val cropHeight = cropRect.height().toInt().coerceAtMost(height - cropTop)

            if (cropWidth > 0 && cropHeight > 0) {
                val croppedBitmap = Bitmap.createBitmap(bitmap, cropLeft, cropTop, cropWidth, cropHeight)
                bitmap.recycle()
                Log.d(TAG, "Cropped bitmap captured (${croppedBitmap.width}x${croppedBitmap.height}). Invoking onCroppedBitmapCaptured listener.")
                onCroppedBitmapCaptured?.invoke(croppedBitmap)
                analyzeAndShowResult(croppedBitmap)
            } else {
                bitmap.recycle()
                Log.e(TAG, "Invalid crop dimensions: width=$cropWidth, height=$cropHeight. Skipping.")
            }
        } catch (e: Exception) {
            Log.e(TAG, "processAndCropImage: error during crop processing", e)
            try { image.close() } catch (ignored: Exception) {}
        }
    }

    /**
     * Captures the full visible screen without cropping.
     * Downscales the bitmap to an OCR-optimal width limit (max 1280px) to conserve memory.
     * Enforces strict bitmap.recycle() and image.close() discipline.
     */
    fun captureFullScreen() {
        Log.d(TAG, "captureFullScreen called. isProjectionReady=$isProjectionReady")
        if (!isProjectionReady || mediaProjection == null) {
            Log.e(TAG, "captureFullScreen: projection not ready or null. Aborting with user feedback.")
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                android.widget.Toast.makeText(
                    applicationContext,
                    "Screen capture session not active. Please enable Protection first.",
                    android.widget.Toast.LENGTH_LONG
                ).show()
            }
            return
        }

        ensureVirtualDisplayCreated()

        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getMetrics(metrics)
        val width = metrics.widthPixels
        val height = metrics.heightPixels

        val immediateImage: Image? = try {
            imageReader?.acquireLatestImage()
        } catch (e: Exception) {
            Log.w(TAG, "captureFullScreen: Failed to acquire image immediately from buffer", e)
            null
        }

        if (immediateImage != null) {
            Log.d(TAG, "captureFullScreen: acquired image immediately from buffer.")
            processFullScreenImage(immediateImage, width, height)
        } else {
            Log.d(TAG, "captureFullScreen: no image in buffer, registering listener.")
            imageReader?.setOnImageAvailableListener({ reader ->
                reader.setOnImageAvailableListener(null, null)
                val image: Image? = try {
                    reader.acquireLatestImage() ?: reader.acquireNextImage()
                } catch (e: Exception) {
                    Log.e(TAG, "captureFullScreen listener: Failed to acquire image", e)
                    null
                }
                if (image != null) {
                    processFullScreenImage(image, width, height)
                }
            }, Handler(Looper.getMainLooper()))
        }
    }

    private fun processFullScreenImage(image: Image, width: Int, height: Int) {
        try {
            val planes = image.planes
            val buffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * width

            val rawBitmap = Bitmap.createBitmap(
                width + rowPadding / pixelStride,
                height,
                Bitmap.Config.ARGB_8888
            )
            rawBitmap.copyPixelsFromBuffer(buffer)
            image.close()

            // Downscale high-resolution screen captures to OCR-optimal max width (1280px)
            val maxOcrWidth = 1280
            val finalBitmap = if (width > maxOcrWidth) {
                val scaleFactor = maxOcrWidth.toFloat() / width
                val targetHeight = (height * scaleFactor).toInt()
                val scaled = Bitmap.createScaledBitmap(rawBitmap, maxOcrWidth, targetHeight, true)
                rawBitmap.recycle()
                Log.d(TAG, "Full-screen capture downscaled from ${width}x${height} to ${scaled.width}x${scaled.height}.")
                scaled
            } else {
                rawBitmap
            }

            analyzeAndShowResult(finalBitmap)
        } catch (e: Exception) {
            Log.e(TAG, "processFullScreenImage: error processing full screen capture", e)
            try { image.close() } catch (ignored: Exception) {}
        }
    }

    /**
     * Releases per-scan ephemeral resources (no-op since they are persistent).
     */
    private fun releaseEphemeralResources() {
        // Noop - VirtualDisplay and ImageReader are persistent for the session
    }

    /**
     * Full teardown: releases everything including the MediaProjection itself.
     * Called when Protection is turned OFF or the system revokes the projection.
     */
    private fun releaseAllResources() {
        isProjectionReady = false
        markSessionInactive()
        com.messageguard.threatvision.state.ThreatVisionStateHolder.onProjectionStopped(this)
        
        virtualDisplay?.release()
        virtualDisplay = null
        imageReader?.close()
        imageReader = null
        
        projectionCallback?.let { cb ->
            try {
                mediaProjection?.unregisterCallback(cb)
            } catch (e: Exception) {
                Log.e(TAG, "Error unregistering callback", e)
            }
        }
        projectionCallback = null

        try {
            mediaProjection?.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping MediaProjection session", e)
        }
        mediaProjection = null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        com.messageguard.threatvision.ui.components.FloatingResultCard.dismiss(this)
        Log.d(TAG, "All MediaProjection resources released, foreground notification removed.")
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.d(TAG, "MediaProjectionService onTaskRemoved: clearing projection session on app swipe away.")
        releaseAllResources()
        stopSelf()
    }

    private fun analyzeAndShowResult(bitmap: Bitmap) {
        // Show immediate "ANALYZING MESSAGE..." feedback card on screen
        com.messageguard.threatvision.ui.components.FloatingResultCard.showAnalyzingLoading(this@MediaProjectionService)

        serviceScope.launch {
            Log.d(TAG, "MediaProjectionService: running analysis use case on background thread...")
            val result = withContext(Dispatchers.IO) {
                val textRecognizer = com.messageguard.threatvision.domain.ocr.MlKitTextRecognizer()
                try {
                    val db = com.messageguard.threatvision.data.local.ThreatDatabase.getDatabase(applicationContext)
                    val useCase = com.messageguard.threatvision.domain.usecase.AnalyzeSelectedRegionUseCase(
                        textRecognizer,
                        com.messageguard.threatvision.domain.engine.HybridDecisionEngine(),
                        db.threatDao(),
                        applicationContext
                    )
                    useCase.execute(bitmap)
                } catch (e: Exception) {
                    Log.e(TAG, "Analysis failed", e)
                    com.messageguard.threatvision.domain.usecase.AnalyzeSelectedRegionUseCase.unavailableAssessment()
                } finally {
                    textRecognizer.close()
                    if (!bitmap.isRecycled) bitmap.recycle()
                }
            }

            val voiceManager = com.messageguard.threatvision.domain.voice.VoiceCommandManager.getInstance(applicationContext)
            val isVoiceScan = voiceManager.currentState == com.messageguard.threatvision.domain.voice.VoiceCommandManager.ListeningState.ANALYZING

            if (result != null) {
                Log.d(TAG, "Analysis completed: verdict=${result.verdict}. Showing result card overlay.")
                com.messageguard.threatvision.ui.components.FloatingResultCard.show(this@MediaProjectionService, result)

                // Dispatch Email Alert notification for WARNING and DANGER threats
                if (result.isComplete && (result.verdict == com.messageguard.threatvision.data.model.ThreatVerdict.DANGER ||
                    result.verdict == com.messageguard.threatvision.data.model.ThreatVerdict.WARNING)) {
                    try {
                        val emailManager = com.messageguard.EmailAlertManager(applicationContext)
                        emailManager.sendAlertFromRiskAssessment(result, "Circle-to-Scan")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to send threat email alert", e)
                    }
                }

                if (result.isComplete && (result.verdict == com.messageguard.threatvision.data.model.ThreatVerdict.DANGER ||
                    result.verdict == com.messageguard.threatvision.data.model.ThreatVerdict.WARNING || isVoiceScan)) {
                    voiceManager.speakVerdict(result.verdict, result.reason, result.isTamilContent)
                }
            } else {
                Log.e(TAG, "Analysis result is null. Skipping card display.")
                com.messageguard.threatvision.ui.components.ScanLockoutOverlay.dismiss(this@MediaProjectionService)
                if (isVoiceScan) {
                    voiceManager.speakError("Scan failed. Please try again.")
                }
            }

            if (isVoiceScan) {
                voiceManager.signalAnalysisComplete()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceJob.cancel()
        releaseAllResources()
        Log.d(TAG, "MediaProjectionService destroyed.")
    }
}
