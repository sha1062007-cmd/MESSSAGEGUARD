package com.messageguard.threatvision.ui.main

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.drawable.ColorDrawable
import android.media.projection.MediaProjectionManager
import android.os.Bundle
import com.messageguard.threatvision.service.MediaProjectionService

/**
 * Transparent, zero-UI Activity whose sole purpose is to host the system
 * MediaProjection consent dialog ("Share your screen with …?").
 *
 * Extends plain [Activity] (not AppCompatActivity) because:
 *   1. It renders no views of its own — only the system consent prompt.
 *   2. Its manifest theme is @android:style/Theme.Translucent.NoTitleBar,
 *      which is a platform theme incompatible with AppCompat's requirement
 *      for a Theme.AppCompat descendant.
 *   3. Using plain Activity with startActivityForResult/onActivityResult
 *      avoids the AppCompat theme crash entirely.
 */
class CapturePermissionActivity : Activity() {

    companion object {
        private const val REQUEST_CODE_SCREEN_CAPTURE = 1001
        const val EXTRA_USE_ACTIVE_PROJECTION = "com.messageguard.extra.USE_ACTIVE_PROJECTION"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setBackgroundDrawable(ColorDrawable(android.graphics.Color.TRANSPARENT))

        if (intent.getBooleanExtra(EXTRA_USE_ACTIVE_PROJECTION, false) && MediaProjectionService.isSessionActive) {
            android.util.Log.d("ThreatVisionLog", "Active projection session detected; no automatic scan is started. User must tap the floating bubble for Circle-to-Scan.")
            finish()
            return
        }

        val projectionManager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        @Suppress("DEPRECATION")
        startActivityForResult(projectionManager.createScreenCaptureIntent(), REQUEST_CODE_SCREEN_CAPTURE)
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_CODE_SCREEN_CAPTURE) {
            if (resultCode == RESULT_OK && data != null) {
                android.util.Log.d("ThreatVisionLog", "MediaProjection consent GRANTED. Starting MediaProjectionService (it will launch OverlaySelectionService once projection is ready).")
                val serviceIntent = Intent(this, MediaProjectionService::class.java).apply {
                    putExtra(MediaProjectionService.EXTRA_RESULT_CODE, resultCode)
                    putExtra(MediaProjectionService.EXTRA_DATA_INTENT, data)
                }
                androidx.core.content.ContextCompat.startForegroundService(this, serviceIntent)
            } else {
                android.util.Log.d("ThreatVisionLog", "MediaProjection consent DENIED or cancelled by user.")
            }
            finish()
        }
    }
}
