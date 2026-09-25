package com.messageguard

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AlertDialog
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.messageguard.databinding.AlertSettingsBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class AlertSettingsActivity : AppCompatActivity() {

    private lateinit var binding: AlertSettingsBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = AlertSettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        
        // Load initial state
        val hasBundledAlertConfiguration = BuildConfig.RESEND_API_KEY.isNotBlank() &&
            BuildConfig.ALERT_EMAIL.isNotBlank()
        binding.switchEnableAlerts.isChecked = prefs.getBoolean(
            Constants.KEY_EMAIL_ALERTS_ENABLED,
            hasBundledAlertConfiguration
        )
        binding.etResendApiKey.setText(
            prefs.getString(Constants.KEY_RESEND_API_KEY, "")
                .orEmpty()
                .ifBlank { BuildConfig.RESEND_API_KEY }
        )
        binding.etAlertEmail.setText(
            prefs.getString(Constants.KEY_ALERT_EMAIL_ADDRESS, "")
                .orEmpty()
                .ifBlank { BuildConfig.ALERT_EMAIL }
        )
        binding.etAlertFrom.setText(
            prefs.getString(Constants.KEY_ALERT_FROM_EMAIL, "")
                .orEmpty()
                .ifBlank { BuildConfig.ALERT_FROM.ifBlank { "MessageGuard <onboarding@resend.dev>" } }
        )
        binding.cbAlertDangerous.isChecked = prefs.getBoolean(Constants.KEY_EMAIL_ALERT_DANGEROUS, true)
        binding.cbAlertSuspicious.isChecked = prefs.getBoolean(Constants.KEY_EMAIL_ALERT_SUSPICIOUS, true)

        binding.btnSave.setOnClickListener {
            prefs.edit().apply {
                putBoolean(Constants.KEY_EMAIL_ALERTS_ENABLED, binding.switchEnableAlerts.isChecked)
                putString(Constants.KEY_RESEND_API_KEY, binding.etResendApiKey.text.toString())
                putString(Constants.KEY_ALERT_EMAIL_ADDRESS, binding.etAlertEmail.text.toString())
                putString(Constants.KEY_ALERT_FROM_EMAIL, binding.etAlertFrom.text.toString())
                putBoolean(Constants.KEY_EMAIL_ALERT_DANGEROUS, binding.cbAlertDangerous.isChecked)
                putBoolean(Constants.KEY_EMAIL_ALERT_SUSPICIOUS, binding.cbAlertSuspicious.isChecked)
                apply()
            }
            Toast.makeText(this, "Resend Settings Saved", Toast.LENGTH_SHORT).show()
            finish()
        }

        binding.btnTestEmail.setOnClickListener {
            val email = binding.etAlertEmail.text.toString().trim().ifBlank { BuildConfig.ALERT_EMAIL }
            // Keep a build-time key hidden from the UI, while allowing a local.properties setup
            // to power a real test email. A user-entered key always takes precedence.
            val apiKey = binding.etResendApiKey.text.toString().trim().ifBlank { BuildConfig.RESEND_API_KEY }
            val from = binding.etAlertFrom.text.toString().trim()
            
            if (email.isBlank() || apiKey.isBlank()) {
                Toast.makeText(this, "Enter API Key and Recipient Email", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (from.isBlank()) {
                Toast.makeText(this, "Enter a verified From Email", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            Toast.makeText(this, "Sending Resend test alert...", Toast.LENGTH_SHORT).show()
            binding.btnTestEmail.isEnabled = false
            
            val mockResult = AnalysisResult(
                verdict = Verdict.DANGER,
                summary = "Resend API connection test successful. Threat monitoring is live.",
                riskScore = 99,
                flags = listOf("http://resend-test.com", "Entropy: 4.8", "Brand: ResendTest", "TLD: .api"),
                timestamp = System.currentTimeMillis(),
                senderTrust = "API-Test"
            )

            EmailAlertManager(this).sendTestAlert(
                result = mockResult,
                recipient = email,
                from = from,
                apiKey = apiKey
            ) { success, message ->
                if (!isFinishing && !isDestroyed) {
                    binding.btnTestEmail.isEnabled = true
                    Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                    // If Resend indicates the account is limited to testing to owner's email,
                    // offer a direct link to the domain verification page with guidance.
                    if (!success && message.contains("testing emails to your own email address", ignoreCase = true)) {
                        AlertDialog.Builder(this)
                            .setTitle("Resend Domain Verification Required")
                            .setMessage("Resend is currently restricting test sends to the account owner. To send alerts to other recipients, verify your sending domain at resend.com/domains.")
                            .setPositiveButton("Open Resend Domains") { _, _ ->
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://resend.com/domains"))
                                startActivity(intent)
                            }
                            .setNegativeButton("OK", null)
                            .show()
                    }
                }
            }
        }
    }
}
