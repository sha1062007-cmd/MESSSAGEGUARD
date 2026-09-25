package com.messageguard

import android.Manifest
import android.animation.ValueAnimator
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.animation.Animation
import android.view.animation.AnimationUtils
import android.widget.Button
import android.widget.TextView
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import android.content.Context
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.switchmaterial.SwitchMaterial
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REQUEST_RECORD_AUDIO = "extra_request_record_audio"
        const val REQUEST_CODE_RECORD_AUDIO = 201
    }

    private val viewModel: MainViewModel by viewModels()
    private var pulseAnimation: Animation? = null
    private lateinit var tvProtectionStatus: TextView
    private lateinit var viewPulseDot: View
    private lateinit var viewPulseGlow: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        val isDark = prefs.getBoolean(Constants.KEY_THEME_DARK, true)
        AppCompatDelegate.setDefaultNightMode(
            if (isDark) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
        )

        if (!prefs.getBoolean(Constants.KEY_ONBOARDING_COMPLETED, false)) {
            startActivity(Intent(this, OnboardingActivity::class.java))
            finish()
            return
        }

        setContentView(R.layout.activity_main)

        // Register notification channels (Android O+ requirement; no-op on earlier versions)
        ThreatVisionNotifier.createChannels(this)

        // Handle runtime RECORD_AUDIO permission request triggered from FloatingBubbleService
        if (intent?.getBooleanExtra(EXTRA_REQUEST_RECORD_AUDIO, false) == true) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), REQUEST_CODE_RECORD_AUDIO)
            }
        }

        try {
            val switchEnable = findViewById<SwitchMaterial>(R.id.switch_enable)
            val tvTotal = findViewById<TextView>(R.id.tv_total_today)
            val tvDanger = findViewById<TextView>(R.id.tv_dangers)
            val tvSafe = findViewById<TextView>(R.id.tv_safe)
            val rvRecent = findViewById<RecyclerView>(R.id.rv_recent_scans)
            val btnHistory = findViewById<Button>(R.id.btn_view_history)
            val btnSettings = findViewById<Button>(R.id.btn_settings)
            val tvPermissionWarning = findViewById<TextView>(R.id.tv_permission_warning)

            // New dashboard components
            val progressSecurityIndex = findViewById<CircularProgressIndicator>(R.id.progress_security_index)
            val tvSecurityIndexValue = findViewById<TextView>(R.id.tv_security_index_value)
            val tvSecurityIndexLabel = findViewById<TextView>(R.id.tv_security_index_label)
            tvProtectionStatus = findViewById(R.id.tv_protection_status)
            viewPulseGlow = findViewById(R.id.view_pulse_glow)
            viewPulseDot = findViewById(R.id.view_pulse_dot)

            // Initialize pulse animation resource
            pulseAnimation = AnimationUtils.loadAnimation(this, R.anim.pulse)

            rvRecent.layoutManager = LinearLayoutManager(this)
            val adapter = HistoryAdapter { result ->
                val intent = Intent(this, DetailActivity::class.java)
                intent.putExtra("result_id", result.id)
                startActivity(intent)
            }
            rvRecent.adapter = adapter

            viewModel.recentScans.observe(this) { adapter.submitList(it) }

            viewModel.stats.observe(this) { stats ->
                tvTotal.text = stats.totalToday.toString()
                tvDanger.text = (stats.dangersFound + stats.warningCount).toString()
                tvSafe.text = stats.safeCount.toString()

                // Calculate overall security index (ratio of safe scans to overall scans)
                val totalOverall = stats.totalOverall
                val safeOverall = stats.safeOverall
                val index = if (totalOverall == 0) 100 else ((safeOverall * 100) / totalOverall).coerceIn(0, 100)

                // Animate progress and value text
                animateSecurityIndex(progressSecurityIndex, tvSecurityIndexValue, tvSecurityIndexLabel, index)
            }

            viewModel.isEnabled.observe(this) { checked ->
                switchEnable.isChecked = checked
                updateProtectionUi(checked, tvProtectionStatus, viewPulseDot, viewPulseGlow)
            }

            switchEnable.setOnCheckedChangeListener { _, checked ->
                if (checked != com.messageguard.threatvision.state.ThreatVisionStateHolder.isProtectionActive) {
                    viewModel.toggleService(checked)
                }
                if (checked) {
                    // Sandbox Download Observer & Sweep Worker Activation
                    com.messageguard.sandbox.trigger.MediaStoreDownloadObserver.register(this)
                    com.messageguard.sandbox.worker.PeriodicDownloadSweepWorker.schedule(this)

                    // Handle Voice Trigger Consent and Activation
                    val prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
                    val voiceDisclosed = prefs.getBoolean(Constants.KEY_VOICE_PRIVACY_DISCLOSED, false)

                    if (!voiceDisclosed) {
                        // Show one-time Bilingual Voice Privacy Disclosure Dialog
                        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                            .setTitle("Bilingual Voice Privacy / குரல் தனியுரிமை")
                            .setMessage(
                                "English:\nMessageGuard processes voice commands using Android Speech Services " +
                                "(on-device when available, or via Google's secure speech API). Audio is processed " +
                                "only after you hold the scan bubble to speak; it is never recorded, saved, or stored by MessageGuard.\n\n" +
                                "தமிழ்:\nமெசேஜ்கார்ட் குரல் கட்டளைகளை ஆண்ட்ராய்டு ஸ்பீச் சேவை மூலம் பரிசோதிக்கிறது " +
                                "(கிடைக்கும் போது சாதனத்திலும் அல்லது கூகுளின் பாதுகாப்பான குரல் API மூலமாகவும்). " +
                                "குரல் சொற்கள் எங்கும் சேமிக்கப்படாது அல்லது பதிவு செய்யப்படாது."
                            )
                            .setPositiveButton("Accept / ஏற்றுக்கொள்") { _, _ ->
                                prefs.edit()
                                    .putBoolean(Constants.KEY_VOICE_PRIVACY_DISCLOSED, true)
                                    .putBoolean(Constants.KEY_VOICE_TRIGGER_ENABLED, true)
                                    .apply()

                                // Request microphone permission for voice trigger
                                if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                                    ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), REQUEST_CODE_RECORD_AUDIO)
                                } else {
                                    // Voice trigger (always-on) is DISABLED. PTT via bubble tap is the only voice entry point.
                                    android.util.Log.d("ThreatVisionLog", "MainActivity: RECORD_AUDIO granted. PTT mode active — no continuous listening started.")
                                }
                            }
                            .setNegativeButton("Decline / நிராகரி") { dialog, _ ->
                                prefs.edit()
                                    .putBoolean(Constants.KEY_VOICE_PRIVACY_DISCLOSED, true)
                                    .putBoolean(Constants.KEY_VOICE_TRIGGER_ENABLED, false)
                                    .apply()
                                dialog.dismiss()
                                android.widget.Toast.makeText(
                                    this,
                                    "Circle scan active. Hands-free voice trigger disabled.",
                                    android.widget.Toast.LENGTH_LONG
                                ).show()
                            }
                            .setOnCancelListener {
                                prefs.edit()
                                    .putBoolean(Constants.KEY_VOICE_PRIVACY_DISCLOSED, true)
                                    .putBoolean(Constants.KEY_VOICE_TRIGGER_ENABLED, false)
                                    .apply()
                                android.widget.Toast.makeText(
                                    this,
                                    "Circle scan active. Hands-free voice trigger disabled.",
                                    android.widget.Toast.LENGTH_LONG
                                ).show()
                            }
                            .show()
                    } else {
                        // Already disclosed - activate voice trigger if enabled
                        val voiceEnabled = prefs.getBoolean(Constants.KEY_VOICE_TRIGGER_ENABLED, false)
                        if (voiceEnabled) {
                            if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), REQUEST_CODE_RECORD_AUDIO)
                            } else {
                                // Voice trigger (always-on) is DISABLED. PTT via bubble tap is the only voice entry point.
                                android.util.Log.d("ThreatVisionLog", "MainActivity: Voice-enabled pref set but continuous listening is disabled. PTT active.")
                            }
                        }
                    }
                }
            }

            btnHistory.setOnClickListener {
                startActivity(Intent(this, HistoryActivity::class.java))
            }
            findViewById<Button>(R.id.btn_view_scan_reports)?.setOnClickListener {
                startActivity(Intent(this, com.messageguard.sandbox.ui.ScanReportListActivity::class.java))
            }
            btnSettings.setOnClickListener {
                startActivity(Intent(this, SettingsActivity::class.java))
            }


            val qrPickerLauncher = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.GetContent()) { uri ->
                uri?.let { imageUri ->
                    lifecycleScope.launch {
                        try {
                            val bitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                android.graphics.ImageDecoder.decodeBitmap(android.graphics.ImageDecoder.createSource(contentResolver, imageUri))
                            } else {
                                android.provider.MediaStore.Images.Media.getBitmap(contentResolver, imageUri)
                            }
                            val result = QrPhishingDetector.scanBitmap(bitmap)
                            val message = if (!result.qrFound) {
                                "No valid QR code payload found in image."
                            } else {
                                "Payload: ${result.rawPayload}\n\nThreat Assessment: ${result.threatSummary}"
                            }
                            com.google.android.material.dialog.MaterialAlertDialogBuilder(this@MainActivity)
                                .setTitle("QR Code Phishing Forensic Result")
                                .setMessage(message)
                                .setPositiveButton("OK", null)
                                .show()
                        } catch (e: Exception) {
                            android.widget.Toast.makeText(this@MainActivity, "Failed to decode image: ${e.message}", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }

            findViewById<Button>(R.id.btn_scan_qr)?.setOnClickListener {
                qrPickerLauncher.launch("image/*")
            }



            val btnRunTestId = resources.getIdentifier("btn_run_detection_test", "id", packageName)
            if (btnRunTestId != 0) {
                findViewById<Button>(btnRunTestId)?.setOnClickListener {
                    lifecycleScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                        val spamAnalyzer = SpamAnalyzer(applicationContext)
                        DetectionTestHarness.run(applicationContext, spamAnalyzer, "AFTER_CORROBORATION_FIXES")
                        withContext(kotlinx.coroutines.Dispatchers.Main) {
                            android.widget.Toast.makeText(
                                this@MainActivity,
                                "Benchmark finished! Check Logcat tag: DETECTION_TEST",
                                android.widget.Toast.LENGTH_LONG
                            ).show()
                        }
                    }
                }
            }

            requestNotificationPermission()
            checkPermissions(tvPermissionWarning)
            setupThreatVisionPipeline()
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "onCreate initialization failed", e)
            android.widget.Toast.makeText(this, "UI initialization error — please restart", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    private fun setupThreatVisionPipeline() {
        com.messageguard.threatvision.service.MediaProjectionService.onCroppedBitmapCaptured = { croppedBitmap ->
            android.util.Log.d("ThreatVisionLog", "MainActivity: onCroppedBitmapCaptured triggered (${croppedBitmap.width}x${croppedBitmap.height}). Handled directly by system overlay result card.")
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 101)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.loadStats()
        // Re-evaluate pulse based on REAL accessibility service state, not just the UI toggle.
        // A user could flip the switch without actually granting the accessibility permission.
        val prefEnabled = viewModel.isEnabled.value ?: false
        val serviceActuallyRunning = isAccessibilityEnabled() && prefEnabled
        updateProtectionUi(serviceActuallyRunning, tvProtectionStatus, viewPulseDot, viewPulseGlow)
        if (serviceActuallyRunning) {
            checkAndRequestBatteryExemption()
        }
    }

    private fun updateProtectionUi(
        enabled: Boolean,
        statusText: TextView,
        dotView: View,
        glowView: View
    ) {
        if (enabled) {
            statusText.text = "System Shield Active"
            statusText.setTextColor(ContextCompat.getColor(this, android.R.color.white))
            dotView.setBackgroundResource(R.drawable.dot_green)
            glowView.setBackgroundResource(R.drawable.dot_green)
            glowView.visibility = View.VISIBLE
            pulseAnimation?.let { glowView.startAnimation(it) }
        } else {
            statusText.text = "Protection Paused"
            statusText.setTextColor(ContextCompat.getColor(this, android.R.color.darker_gray))
            dotView.setBackgroundResource(R.drawable.dot_yellow)
            glowView.clearAnimation()
            glowView.visibility = View.GONE
        }
    }

    private fun animateSecurityIndex(
        gauge: CircularProgressIndicator,
        valueLabel: TextView,
        statusLabel: TextView,
        targetIndex: Int
    ) {
        // Animate circular indicator progress
        val animator = ValueAnimator.ofInt(gauge.progress, targetIndex)
        animator.duration = 1200
        animator.addUpdateListener { anim ->
            val progress = anim.animatedValue as Int
            gauge.progress = progress
            valueLabel.text = "$progress%"
        }
        animator.start()

        // Update indicator safety status text & colors based on threshold values
        when {
            targetIndex >= 90 -> {
                statusLabel.text = "SECURE"
                statusLabel.setTextColor(ContextCompat.getColor(this, R.color.safe_green))
                gauge.setIndicatorColor(ContextCompat.getColor(this, R.color.safe_green))
            }
            targetIndex >= 70 -> {
                statusLabel.text = "VULNERABLE"
                statusLabel.setTextColor(ContextCompat.getColor(this, R.color.warning_yellow))
                gauge.setIndicatorColor(ContextCompat.getColor(this, R.color.warning_yellow))
            }
            else -> {
                statusLabel.text = "HIGH RISK"
                statusLabel.setTextColor(ContextCompat.getColor(this, R.color.danger_red))
                gauge.setIndicatorColor(ContextCompat.getColor(this, R.color.danger_red))
            }
        }
    }

    private fun checkPermissions(tvWarning: TextView) {
        val hasOverlay = Settings.canDrawOverlays(this)
        val hasAccessibility = isAccessibilityEnabled()
        if (!hasOverlay || !hasAccessibility) {
            tvWarning.visibility = View.VISIBLE
            tvWarning.text = buildString {
                if (!hasOverlay) append("⚠ Overlay permission needed. ")
                if (!hasAccessibility) append("⚠ Accessibility permission needed.")
            }
            tvWarning.setOnClickListener {
                if (!hasOverlay) {
                    startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:$packageName")))
                } else {
                    startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                }
            }
        } else {
            tvWarning.visibility = View.GONE
        }
    }

    private fun isAccessibilityEnabled(): Boolean {
        return try {
            val enabled = Settings.Secure.getInt(contentResolver,
                Settings.Secure.ACCESSIBILITY_ENABLED)
            if (enabled == 1) {
                val services = Settings.Secure.getString(contentResolver,
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
                services.contains(packageName)
            } else false
        } catch (e: Exception) { false }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CODE_RECORD_AUDIO) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                android.util.Log.d("ThreatVisionLog", "MainActivity: RECORD_AUDIO granted. PTT mode active — no continuous listening started.")
            } else {
                android.util.Log.w("ThreatVisionLog", "MainActivity: RECORD_AUDIO denied.")
            }
        }
    }

    private fun checkAndRequestBatteryExemption() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                    .setTitle("Battery Exemption Required / பேட்டரி அனுமதி")
                    .setMessage(
                        "English:\nTo allow continuous voice commands in the background without Android terminating " +
                        "the scanner service, please disable battery optimization for MessageGuard.\n\n" +
                        "தமிழ்:\nபின்புலத்தில் மெசேஜ்கார்ட் தொடர்ந்து செயல்பட, பேட்டரி மேம்படுத்தல் (Battery Optimization) " +
                        "அமைப்பிலிருந்து விலக்களிக்க அனுமதிக்கவும்."
                    )
                    .setPositiveButton("Configure / அமை") { _, _ ->
                        try {
                            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                data = Uri.parse("package:$packageName")
                            }
                            startActivity(intent)
                        } catch (e: Exception) {
                            android.util.Log.e("ThreatVisionLog", "Failed to request ignore battery optimizations", e)
                        }
                    }
                    .setNegativeButton("Cancel / ரத்து செய்", null)
                    .show()
            }
        }
    }
}
