package com.messageguard

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.CheckBox
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.lifecycle.lifecycleScope
import androidx.core.app.NotificationManagerCompat
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsActivity : AppCompatActivity() {

    private lateinit var prefs: android.content.SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Settings"

        prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)

        // ── Notification Listener Permission Banner ───────────────────────────
        // Bug Fix: NLS was declared in manifest but users had no UI path to grant it.
        // Show a persistent banner in Settings if not yet granted.
        val btnGrantNls = findViewById<Button?>(R.id.btn_grant_notification_listener)
        val enabledListeners = NotificationManagerCompat.getEnabledListenerPackages(this)
        val nlsGranted = enabledListeners.contains(packageName)
        if (btnGrantNls != null) {
            btnGrantNls.visibility = if (nlsGranted) android.view.View.GONE else android.view.View.VISIBLE
            btnGrantNls.setOnClickListener {
                try {
                    startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                } catch (e: Exception) {
                    Toast.makeText(this, "Cannot open notification settings", Toast.LENGTH_SHORT).show()
                }
            }
        }

        val etApiKey = findViewById<TextInputEditText>(R.id.et_api_key)
        val btnTest = findViewById<Button>(R.id.btn_test_key)
        val tvResult = findViewById<TextView>(R.id.tv_test_result)
        val progressTest = findViewById<ProgressBar>(R.id.progress_test)
        val layoutApiKeyGroup = findViewById<android.view.View>(R.id.layout_api_key_group)

        val cbGmail = findViewById<CheckBox>(R.id.cb_gmail)
        val cbWhatsapp = findViewById<CheckBox>(R.id.cb_whatsapp)
        val cbTelegram = findViewById<CheckBox>(R.id.cb_telegram)
        val cbSms = findViewById<CheckBox>(R.id.cb_sms)
        val cbInstagram = findViewById<CheckBox>(R.id.cb_instagram)
        val cbLinkedin = findViewById<CheckBox>(R.id.cb_linkedin)
        val btnClearHistory = findViewById<Button>(R.id.btn_clear_history)
        val switchLogAll = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_log_all)

        val switchDarkTheme = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_dark_theme)
        switchDarkTheme.isChecked = prefs.getBoolean(Constants.KEY_THEME_DARK, true)
        switchDarkTheme.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(Constants.KEY_THEME_DARK, checked).apply()
            AppCompatDelegate.setDefaultNightMode(
                if (checked) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
            )
        }

        val switchFloatingBubble = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_floating_bubble)
        switchFloatingBubble?.isChecked = prefs.getBoolean(Constants.KEY_SHOW_FLOATING_BUBBLE, true)
        switchFloatingBubble?.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(Constants.KEY_SHOW_FLOATING_BUBBLE, checked).apply()
            if (checked && prefs.getBoolean(Constants.KEY_SERVICE_ENABLED, true)) {
                com.messageguard.threatvision.service.FloatingBubbleService.startService(this)
            } else {
                com.messageguard.threatvision.service.FloatingBubbleService.stopService(this)
            }
        }

        switchLogAll.isChecked = prefs.getBoolean(Constants.KEY_LOG_ALL_SCANS, false)
        switchLogAll.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(Constants.KEY_LOG_ALL_SCANS, checked).apply()
        }

        val btnExportExcel = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_export_excel)
        btnExportExcel.setOnClickListener {
            lifecycleScope.launch {
                val db = AnalysisHistoryDatabase.getInstance(this@SettingsActivity)
                val results = withContext(Dispatchers.IO) { db.dao().getAll() }
                if (results.isEmpty()) {
                    Toast.makeText(this@SettingsActivity, "No logs to export", Toast.LENGTH_SHORT).show()
                } else {
                    val path = withContext(Dispatchers.IO) { StorageHelper.exportDatabaseToExcel(this@SettingsActivity, results) }
                    if (path != null) {
                        Toast.makeText(this@SettingsActivity, "Excel exported to: $path", Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this@SettingsActivity, "Export failed", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        val switchWeeklyExport = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_weekly_export)
        switchWeeklyExport.isChecked = prefs.getBoolean(Constants.KEY_WEEKLY_EXPORT, false)
        switchWeeklyExport.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(Constants.KEY_WEEKLY_EXPORT, checked).apply()
            if (checked) {
                AutoExportWorker.schedule(this@SettingsActivity)
            } else {
                AutoExportWorker.cancel(this@SettingsActivity)
            }
        }

        val switchLanguageTamil = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_language_tamil)
        switchLanguageTamil.isChecked = prefs.getBoolean(Constants.KEY_LANGUAGE_TAMIL, false)
        switchLanguageTamil.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(Constants.KEY_LANGUAGE_TAMIL, checked).apply()
        }

        val chipGroupRetention = findViewById<com.google.android.material.chip.ChipGroup>(R.id.chip_group_retention)
        val retentionDays = prefs.getInt(Constants.KEY_RETENTION_DAYS, -1) // Default is -1 (Never)

        var isProgrammaticChange = false
        fun selectChipForRetention(days: Int) {
            isProgrammaticChange = true
            when (days) {
                7 -> chipGroupRetention.check(R.id.chip_retention_7)
                30 -> chipGroupRetention.check(R.id.chip_retention_30)
                90 -> chipGroupRetention.check(R.id.chip_retention_90)
                else -> chipGroupRetention.check(R.id.chip_retention_never)
            }
            isProgrammaticChange = false
        }

        selectChipForRetention(retentionDays)

        chipGroupRetention.setOnCheckedStateChangeListener { _, checkedIds ->
            if (isProgrammaticChange) return@setOnCheckedStateChangeListener

            val newDays = when (checkedIds.firstOrNull()) {
                R.id.chip_retention_7 -> 7
                R.id.chip_retention_30 -> 30
                R.id.chip_retention_90 -> 90
                else -> -1
            }

            val currentSavedDays = prefs.getInt(Constants.KEY_RETENTION_DAYS, -1)
            if (newDays == currentSavedDays) return@setOnCheckedStateChangeListener

            if (newDays > 0) {
                lifecycleScope.launch {
                    val db = AnalysisHistoryDatabase.getInstance(this@SettingsActivity)
                    val cutoff = System.currentTimeMillis() - (newDays * 24L * 3600L * 1000L)
                    val count = withContext(Dispatchers.IO) { db.dao().countOlderThan(cutoff) }

                    if (count > 0) {
                        AlertDialog.Builder(this@SettingsActivity)
                            .setTitle("Delete Old Scans?")
                            .setMessage("Applying this setting will immediately delete $count scans older than $newDays days. This cannot be undone. Do you want to proceed?")
                            .setPositiveButton("Proceed") { _, _ ->
                                lifecycleScope.launch {
                                    val deleted = withContext(Dispatchers.IO) { db.dao().deleteScansOlderThan(cutoff) }
                                    prefs.edit().putInt(Constants.KEY_RETENTION_DAYS, newDays).apply()
                                    Toast.makeText(this@SettingsActivity, "Cleared $deleted old scans", Toast.LENGTH_SHORT).show()
                                }
                            }
                            .setNegativeButton("Cancel") { dialog, _ ->
                                selectChipForRetention(currentSavedDays)
                                dialog.dismiss()
                            }
                            .setOnCancelListener {
                                selectChipForRetention(currentSavedDays)
                            }
                            .show()
                    } else {
                        prefs.edit().putInt(Constants.KEY_RETENTION_DAYS, newDays).apply()
                        Toast.makeText(this@SettingsActivity, "Retention setting saved. No old scans found to delete.", Toast.LENGTH_SHORT).show()
                    }
                }
            } else {
                // If set to "Never", save immediately
                prefs.edit().putInt(Constants.KEY_RETENTION_DAYS, newDays).apply()
                Toast.makeText(this@SettingsActivity, "Retention setting updated to Never.", Toast.LENGTH_SHORT).show()
            }
        }

        etApiKey.setText(prefs.getString(Constants.KEY_API_KEY, ""))
        tvResult.text = "Models active: URL CNN + NLP TFLite + XGBoost/BODMAS Ensemble"
        tvResult.setTextColor(Color.DKGRAY)
        cbGmail.isChecked = prefs.getBoolean(Constants.KEY_MONITOR_GMAIL, true)
        cbWhatsapp.isChecked = prefs.getBoolean(Constants.KEY_MONITOR_WHATSAPP, true)
        cbTelegram.isChecked = prefs.getBoolean(Constants.KEY_MONITOR_TELEGRAM, true)
        cbSms.isChecked = prefs.getBoolean(Constants.KEY_MONITOR_SMS, true)
        cbInstagram.isChecked = prefs.getBoolean(Constants.KEY_MONITOR_INSTAGRAM, true)
        cbLinkedin.isChecked = prefs.getBoolean(Constants.KEY_MONITOR_LINKEDIN, true)

        listOf(cbGmail to Constants.KEY_MONITOR_GMAIL,
            cbWhatsapp to Constants.KEY_MONITOR_WHATSAPP,
            cbTelegram to Constants.KEY_MONITOR_TELEGRAM,
            cbSms to Constants.KEY_MONITOR_SMS,
            cbInstagram to Constants.KEY_MONITOR_INSTAGRAM,
            cbLinkedin to Constants.KEY_MONITOR_LINKEDIN
        ).forEach { (cb, key) ->
            cb.setOnCheckedChangeListener { _, checked ->
                prefs.edit().putBoolean(key, checked).apply()
            }
        }

        btnTest.setOnClickListener {
            val key = etApiKey.text?.toString()?.trim() ?: ""
            if (key.isEmpty()) {
                tvResult.text = "Please enter an API key"
                tvResult.setTextColor(Color.parseColor("#EA4335"))
                return@setOnClickListener
            }
            testApiKey(key, btnTest, tvResult, progressTest)
        }

        // If a compile-time API key is provided via BuildConfig, hide the API key input group
        try {
            val bundledKeyPresent = BuildConfig.GEMINI_API_KEY.isNotBlank() || BuildConfig.RESEND_API_KEY.isNotBlank()
            if (bundledKeyPresent) {
                layoutApiKeyGroup?.visibility = android.view.View.GONE
                tvResult.text = "Using bundled API configuration"
                tvResult.setTextColor(Color.parseColor("#34a853"))
            }
        } catch (_: Exception) {}

        val btnResetWeights = findViewById<Button>(R.id.btn_reset_weights)
        btnResetWeights?.setOnClickListener {
            val resetWeights = floatArrayOf(
                Constants.DEFAULT_WEIGHT_URL,
                Constants.DEFAULT_WEIGHT_NLP,
                Constants.DEFAULT_WEIGHT_BODMAS,
                Constants.DEFAULT_WEIGHT_TYPOSQUAT,
                Constants.DEFAULT_WEIGHT_REPUTATION
            )
            AdaptiveTrustEngine.boundAndNormalizeWeights(resetWeights)
            prefs.edit().apply {
                putFloat(Constants.KEY_WEIGHT_URL, resetWeights[0])
                putFloat(Constants.KEY_WEIGHT_NLP, resetWeights[1])
                putFloat(Constants.KEY_WEIGHT_BODMAS, resetWeights[2])
                putFloat(Constants.KEY_WEIGHT_TYPOSQUAT, resetWeights[3])
                putFloat(Constants.KEY_WEIGHT_REPUTATION, resetWeights[4])
            }.apply()
            updateModelConfidenceUi()
            Toast.makeText(this, "Ensemble weights reset to defaults (Sum = 1.0)", Toast.LENGTH_SHORT).show()
        }

        btnClearHistory.setOnClickListener {
            lifecycleScope.launch {
                val db = AnalysisHistoryDatabase.getInstance(this@SettingsActivity)
                db.dao().clearAll()
                tvResult.text = "History cleared"
                tvResult.setTextColor(Color.parseColor("#34a853"))
            }
        }

        updateModelConfidenceUi()
    }

    override fun onResume() {
        super.onResume()
        updateModelConfidenceUi()
    }

    private fun updateModelConfidenceUi() {
        val wUrl = prefs.getFloat(Constants.KEY_WEIGHT_URL, Constants.DEFAULT_WEIGHT_URL)
        val wNlp = prefs.getFloat(Constants.KEY_WEIGHT_NLP, Constants.DEFAULT_WEIGHT_NLP)
        val wBodmas = prefs.getFloat(Constants.KEY_WEIGHT_BODMAS, Constants.DEFAULT_WEIGHT_BODMAS)
        val wTypo = prefs.getFloat(Constants.KEY_WEIGHT_TYPOSQUAT, Constants.DEFAULT_WEIGHT_TYPOSQUAT)
        val wRep = prefs.getFloat(Constants.KEY_WEIGHT_REPUTATION, Constants.DEFAULT_WEIGHT_REPUTATION)

        val pctUrl = (wUrl * 100).toInt()
        val pctNlp = (wNlp * 100).toInt()
        val pctBodmas = (wBodmas * 100).toInt()
        val pctTypo = (wTypo * 100).toInt()
        val pctRep = (wRep * 100).toInt()

        findViewById<TextView>(R.id.tv_weight_url)?.text = "$pctUrl%"
        findViewById<ProgressBar>(R.id.progress_weight_url)?.progress = pctUrl

        findViewById<TextView>(R.id.tv_weight_nlp)?.text = "$pctNlp%"
        findViewById<ProgressBar>(R.id.progress_weight_nlp)?.progress = pctNlp

        findViewById<TextView>(R.id.tv_weight_bodmas)?.text = "$pctBodmas%"
        findViewById<ProgressBar>(R.id.progress_weight_bodmas)?.progress = pctBodmas

        findViewById<TextView>(R.id.tv_weight_typosquat)?.text = "$pctTypo%"
        findViewById<ProgressBar>(R.id.progress_weight_typosquat)?.progress = pctTypo

        findViewById<TextView>(R.id.tv_weight_reputation)?.text = "$pctRep%"
        findViewById<ProgressBar>(R.id.progress_weight_reputation)?.progress = pctRep
    }

    private fun testApiKey(
        apiKey: String,
        btnTest: Button,
        tvResult: TextView,
        progress: ProgressBar
    ) {
        btnTest.isEnabled = false
        tvResult.text = "Testing..."
        tvResult.setTextColor(Color.GRAY)
        progress.visibility = android.view.View.VISIBLE

        lifecycleScope.launch {
            try {
                val engine = AIAnalysisEngine(apiKey)
                engine.analyze(
                    appSource = "test",
                    sender = "MessageGuard Test",
                    subject = "API Key Validation",
                    messageBody = "This is a test message to verify the API key."
                )
                tvResult.text = "✓ API key valid — Connected to Claude"
                tvResult.setTextColor(Color.parseColor("#34a853"))
                prefs.edit().putString(Constants.KEY_API_KEY, apiKey).apply()
            } catch (e: InvalidApiKeyException) {
                tvResult.text = "✗ Invalid API key (401 Unauthorized)"
                tvResult.setTextColor(Color.parseColor("#EA4335"))
            } catch (e: Exception) {
                tvResult.text = "✗ Error: ${e.message}"
                tvResult.setTextColor(Color.parseColor("#EA4335"))
            } finally {
                btnTest.isEnabled = true
                progress.visibility = android.view.View.GONE
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
