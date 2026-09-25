package com.messageguard.config

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.io.InputStreamReader

/**
 * Feature flags for Threat Vision.
 * Dynamically toggles features based on active credentials and user preferences.
 */
object FeatureFlags {

    private const val TAG = "ThreatVisionLog"
    private const val CONFIG_PATH = "config/api_keys.template.json"

    /**
     * Reserved Gmail API Sync Flag.
     * Evaluates to true ONLY when a non-empty client_id is supplied in the config
     * or preferences; otherwise remains safely inactive.
     */
    fun isGmailApiSyncEnabled(context: Context): Boolean {
        // First check user custom override in SharedPreferences
        val prefs = context.getSharedPreferences(com.messageguard.Constants.PREFS_NAME, Context.MODE_PRIVATE)
        val customClientId = prefs.getString("gmail_api_client_id", "") ?: ""
        if (customClientId.isNotBlank()) return true

        // Otherwise check bundled configuration template
        return try {
            context.assets.open(CONFIG_PATH).use { stream ->
                InputStreamReader(stream).use { reader ->
                    val root = Gson().fromJson(reader, JsonObject::class.java)
                    val clientId = root.getAsJsonObject("gmail_api")?.get("client_id")?.asString ?: ""
                    clientId.isNotBlank()
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * On-device BEC & lexical XGBoost scoring enabled
     */
    const val ON_DEVICE_BEC_DETECTION_ENABLED = true

    /**
     * Offline backlog synchronization enabled
     */
    const val OFFLINE_RECOVERY_SYNC_ENABLED = true
}
