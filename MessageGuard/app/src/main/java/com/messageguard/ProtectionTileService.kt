package com.messageguard

import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import com.messageguard.threatvision.service.MediaProjectionService
import com.messageguard.threatvision.ui.main.CapturePermissionActivity

/** Quick Settings safety-net trigger for Circle-to-Scan. */
@RequiresApi(Build.VERSION_CODES.N)
class ProtectionTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onTileAdded() {
        super.onTileAdded()
        android.util.Log.d("ThreatVisionLog", "Quick Settings scan tile added.")
    }

    override fun onClick() {
        super.onClick()
        if (!Settings.canDrawOverlays(this)) {
            android.util.Log.w("ThreatVisionLog", "Quick Settings scan blocked: overlay permission missing.")
            android.widget.Toast.makeText(this, "Allow display over other apps to scan.", android.widget.Toast.LENGTH_LONG).show()
            val settingsIntent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                data = android.net.Uri.parse("package:$packageName")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            safeStartActivityAndCollapse(settingsIntent)
            return
        }

        val currentlyEnabled = com.messageguard.threatvision.state.ThreatVisionStateHolder.isProtectionActive
        val nextEnabled = !currentlyEnabled

        android.util.Log.d(
            "ThreatVisionLog",
            "Quick Settings Threat Vision tile toggled. nextEnabled=$nextEnabled"
        )

        if (nextEnabled) {
            com.messageguard.threatvision.state.ThreatVisionStateHolder.enableProtection(this)
            android.widget.Toast.makeText(this, "Threat Vision ON", android.widget.Toast.LENGTH_SHORT).show()

            if (!com.messageguard.threatvision.service.MediaProjectionService.isSessionActive) {
                val scanIntent = Intent(this, CapturePermissionActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                safeStartActivityAndCollapse(scanIntent)
            }
        } else {
            com.messageguard.threatvision.state.ThreatVisionStateHolder.disableProtection(this)
            android.widget.Toast.makeText(this, "Threat Vision OFF", android.widget.Toast.LENGTH_SHORT).show()
        }

        updateTileState()
    }

    private fun safeStartActivityAndCollapse(intent: Intent) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pendingIntent = android.app.PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
                )
                startActivityAndCollapse(pendingIntent)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (e: Exception) {
            android.util.Log.e("ThreatVisionLog", "TileService failed to start activity", e)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        }
    }

    private fun updateTileState() {
        val qsTile = qsTile ?: return
        com.messageguard.threatvision.state.ThreatVisionStateHolder.initialize(this)
        val isActive = com.messageguard.threatvision.state.ThreatVisionStateHolder.isProtectionActive ||
                com.messageguard.threatvision.service.MediaProjectionService.isSessionActive

        qsTile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        qsTile.label = "Threat Vision"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            qsTile.subtitle = if (isActive) "Protection ON" else "Protection OFF"
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            qsTile.icon = android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_shield)
        }
        qsTile.updateTile()
    }
}
