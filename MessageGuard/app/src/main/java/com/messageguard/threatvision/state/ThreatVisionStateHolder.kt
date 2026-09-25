package com.messageguard.threatvision.state

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.service.quicksettings.TileService
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.messageguard.Constants
import com.messageguard.ProtectionTileService
import com.messageguard.threatvision.domain.voice.VoiceCommandManager
import com.messageguard.threatvision.service.FloatingBubbleService
import com.messageguard.threatvision.service.MediaProjectionService
import com.messageguard.threatvision.service.OverlaySelectionService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Single source of truth for Threat Vision protection state, floating bubble visibility,
 * and MediaProjection (screen capture) session lifecycle.
 *
 * Coordinates:
 * - MainActivity & MainViewModel (in-app switch & pulse glow)
 * - Quick Settings Tile (ProtectionTileService)
 * - FloatingBubbleService
 * - MediaProjectionService
 */
object ThreatVisionStateHolder {

    private const val TAG = "ThreatVisionLog"

    data class ProtectionState(
        val isProtectionEnabled: Boolean = false,
        val isBubbleActive: Boolean = false,
        val isProjectionActive: Boolean = false
    )

    private val _stateFlow = MutableStateFlow(ProtectionState())
    val stateFlow: StateFlow<ProtectionState> = _stateFlow.asStateFlow()

    private val _liveData = MutableLiveData(ProtectionState())
    val liveData: LiveData<ProtectionState> = _liveData

    private var initialized = false

    @Synchronized
    fun initialize(context: Context) {
        if (initialized) return
        val appContext = context.applicationContext
        val prefs = appContext.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        val savedEnabled = prefs.getBoolean(Constants.KEY_SERVICE_ENABLED, false)

        val initial = ProtectionState(
            isProtectionEnabled = savedEnabled,
            isBubbleActive = false,
            isProjectionActive = false
        )
        _stateFlow.value = initial
        _liveData.postValue(initial)
        initialized = true
        Log.d(TAG, "ThreatVisionStateHolder initialized. isProtectionEnabled=$savedEnabled")

        if (savedEnabled && (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(appContext))) {
            Log.d(TAG, "Restoring FloatingBubbleService on app startup.")
            FloatingBubbleService.startService(appContext)
        }
    }

    val isProtectionActive: Boolean
        get() = _stateFlow.value.isProtectionEnabled

    val isProjectionActive: Boolean
        get() = _stateFlow.value.isProjectionActive

    val isBubbleActive: Boolean
        get() = _stateFlow.value.isBubbleActive

    /**
     * Centralized activation entry point. Starts FloatingBubbleService and updates all observers.
     */
    fun enableProtection(context: Context) {
        val appContext = context.applicationContext
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(appContext)) {
            Log.w(TAG, "Cannot enable protection: Overlay permission missing.")
            return
        }

        savePreference(appContext, true)
        updateState { it.copy(isProtectionEnabled = true) }

        // Start Floating Bubble Service
        FloatingBubbleService.startService(appContext)

        // Request tile state refresh AFTER state has updated
        requestTileUpdate(appContext)
        Log.d(TAG, "ThreatVisionStateHolder: Protection ENABLED.")
    }

    /**
     * Centralized deactivation entry point. Stops all services and clears projection resources.
     */
    fun disableProtection(context: Context) {
        val appContext = context.applicationContext
        savePreference(appContext, false)
        updateState {
            it.copy(
                isProtectionEnabled = false,
                isBubbleActive = false,
                isProjectionActive = false
            )
        }

        // Stop services cleanly
        FloatingBubbleService.stopService(appContext)
        MediaProjectionService.stopService(appContext)
        appContext.stopService(Intent(appContext, OverlaySelectionService::class.java))
        VoiceCommandManager.getInstance(appContext).cancelListening()

        // Request tile state refresh AFTER state has updated
        requestTileUpdate(appContext)
        Log.d(TAG, "ThreatVisionStateHolder: Protection DISABLED. All services stopped.")
    }

    fun toggle(context: Context) {
        if (isProtectionActive) {
            disableProtection(context)
        } else {
            enableProtection(context)
        }
    }

    /**
     * Lifecycle hooks called from services.
     */
    fun onBubbleStarted() {
        updateState { it.copy(isBubbleActive = true) }
        Log.d(TAG, "ThreatVisionStateHolder: Bubble marked active.")
    }

    fun onBubbleStopped(context: Context? = null) {
        updateState { it.copy(isBubbleActive = false) }
        context?.let { requestTileUpdate(it.applicationContext) }
        Log.d(TAG, "ThreatVisionStateHolder: Bubble marked inactive.")
    }

    fun onProjectionStarted(context: Context? = null) {
        updateState { it.copy(isProjectionActive = true) }
        context?.let { requestTileUpdate(it.applicationContext) }
        Log.d(TAG, "ThreatVisionStateHolder: Projection session marked active.")
    }

    /**
     * Triggered both on explicit stop and when system revokes projection via MediaProjection.Callback.onStop()
     */
    fun onProjectionStopped(context: Context? = null) {
        updateState { it.copy(isProjectionActive = false) }
        context?.let { requestTileUpdate(it.applicationContext) }
        Log.d(TAG, "ThreatVisionStateHolder: Projection session marked inactive.")
    }

    private fun updateState(reducer: (ProtectionState) -> ProtectionState) {
        val next = reducer(_stateFlow.value)
        _stateFlow.value = next
        _liveData.postValue(next)
    }

    private fun savePreference(context: Context, enabled: Boolean) {
        context.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(Constants.KEY_SERVICE_ENABLED, enabled)
            .apply()
    }

    fun requestTileUpdate(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                TileService.requestListeningState(
                    context,
                    ComponentName(context, ProtectionTileService::class.java)
                )
            } catch (e: Exception) {
                Log.w(TAG, "Failed to request tile update: ${e.message}")
            }
        }
    }
}
