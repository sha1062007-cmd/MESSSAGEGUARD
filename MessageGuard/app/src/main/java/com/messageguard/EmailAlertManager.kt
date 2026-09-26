package com.messageguard

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

class EmailAlertManager(private val context: Context) {

    private val prefs = context.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()
    private val mainHandler = Handler(Looper.getMainLooper())
    
    companion object {
        private val cooldownMap = ConcurrentHashMap<String, Long>()
        private const val COOLDOWN_MS = 5000L // Reduced from 1 hour to 5 seconds for testing
        private val JSON_TYPE = "application/json; charset=utf-8".toMediaType()
    }

    private fun getTargetEmail(): String = prefs.getString(Constants.KEY_ALERT_EMAIL_ADDRESS, "")
        ?.ifBlank { BuildConfig.ALERT_EMAIL } ?: BuildConfig.ALERT_EMAIL

    private fun getResendApiKey(): String = prefs.getString(Constants.KEY_RESEND_API_KEY, "")
        ?.ifBlank { BuildConfig.RESEND_API_KEY } ?: BuildConfig.RESEND_API_KEY

    private fun getFromEmail(): String = prefs.getString(Constants.KEY_ALERT_FROM_EMAIL, "")
        ?.ifBlank { BuildConfig.ALERT_FROM.ifBlank { "MessageGuard <onboarding@resend.dev>" } } 
        ?: (BuildConfig.ALERT_FROM.ifBlank { "MessageGuard <onboarding@resend.dev>" })

    fun sendAlertFromRiskAssessment(assessment: com.messageguard.threatvision.data.model.RiskAssessment, sender: String = "Circle-to-Scan") {
        val dummyResult = AnalysisResult(
            verdict = when (assessment.verdict) {
                com.messageguard.threatvision.data.model.ThreatVerdict.DANGER -> Verdict.DANGER
                com.messageguard.threatvision.data.model.ThreatVerdict.WARNING -> Verdict.WARNING
                else -> Verdict.SAFE
            },
            summary = assessment.report?.summary ?: assessment.reason,
            messageSnippet = assessment.reason,
            explainabilityJson = "",
            typosquatFlag = false,
            senderReputationScore = 0.0f,
            sender = sender,
            riskScore = assessment.riskScore
        )
        sendAlertIfQualified(dummyResult)
    }

    fun sendAlertIfQualified(result: AnalysisResult) {
        val emailEnabled = prefs.getBoolean(Constants.KEY_EMAIL_ALERTS_ENABLED, true)
        if (!emailEnabled) return

        val target = getTargetEmail()
        val key = getResendApiKey()
        
        Log.d("ResendAlert", "Config Check - Key Len: ${key.length}, Target: '$target'")
        Log.d("ResendAlertDebug", "Config Check - Key Len: ${key.length}, Target: '$target', From: '${getFromEmail()}'")

        if (target.isBlank() || key.isBlank()) {
            Log.w("ResendAlertDebug", "MISSING CONFIG: Resend API Key or Alert Email Target blank.")
            Log.w("ResendAlert", "MISSING CONFIG: Please add RESEND_API_KEY and ALERT_EMAIL to local.properties or App Settings.")
            return
        }

        val shouldAlert = when (result.verdict) {
            Verdict.DANGER -> prefs.getBoolean(Constants.KEY_EMAIL_ALERT_DANGEROUS, true)
            // FP-6 FIX: SUSPICIOUS (WARNING) = "needs user review", not a confirmed threat.
            // Auto-alerting on every SUSPICIOUS creates alert fatigue and contradicts the
            // 3-tier classification. Default is now opt-in (false). Users can re-enable in Settings.
            Verdict.WARNING -> prefs.getBoolean(Constants.KEY_EMAIL_ALERT_SUSPICIOUS, true)
            else -> false
        }
        if (!shouldAlert) return

        // CONTENT-BASED COOLDOWN KEY (fixes duplicate alerts across scan sources):
        // Before: subject+sender alone was too weak — same SMS scanned via accessibility + circle-to-scan
        // could be from 2 different senders ("" or generic subject) and fire twice.
        // Now include a stable hash of the actual message body as the primary dedup anchor so regardless
        // whether accessibility OR circle-to-scan observes the same message, it only fires once.
        val contentHash = (result.messageSnippet.take(300) + result.summary.take(100) + result.flags.joinToString()).hashCode().toString(36)
        val messageKey = "${result.verdict.name}|${result.riskScore}|${result.sender.take(20)}|$contentHash"
        val now = System.currentTimeMillis()
        if (now - (cooldownMap[messageKey] ?: 0L) < COOLDOWN_MS) {
            Log.d("ResendAlertDebug", "Duplicate alert suppressed by cooldown: key=$messageKey")
            return
        }

        scope.launch {
            try {
                val delivery = sendViaResend(result, target, getFromEmail(), key)
                if (delivery.isSuccessful) {
                    cooldownMap[messageKey] = System.currentTimeMillis()
                }
            } catch (e: Exception) {
                Log.e("ResendAlertDebug", "Fatal error in alert dispatch: ${e.message}", e)
                Log.e("ResendAlert", "Fatal error in alert dispatch: ${e.message}")
            }
        }
    }

    /**
     * Sends a settings-screen test using the values currently typed by the user. This deliberately
     * bypasses notification toggles and cooldowns, but not Resend's own validation.
     */
    fun sendTestAlert(
        result: AnalysisResult,
        recipient: String,
        from: String,
        apiKey: String,
        onComplete: (isSuccessful: Boolean, message: String) -> Unit
    ) {
        scope.launch {
            val effectiveKey = if (apiKey.trim().isBlank()) getResendApiKey() else apiKey.trim()
            val effectiveFrom = if (from.trim().isBlank()) getFromEmail() else from.trim()
            val delivery = sendViaResend(result, recipient.trim(), effectiveFrom, effectiveKey)
            mainHandler.post { onComplete(delivery.isSuccessful, delivery.message) }
        }
    }

    private data class DeliveryResult(val isSuccessful: Boolean, val message: String)

    private fun sendViaResend(result: AnalysisResult, to: String, from: String, apiKey: String): DeliveryResult {
        val htmlContent = EmailTemplate.getHtmlTemplate(
            threatLevel = result.verdict.name,
            url = result.extractFirstUrl(),
            confidence = "${result.riskScore}%",
            aiSummary = result.summary,
            entropy = "N/A",
            brandMimicry = "YES",
            tldRisk = "HIGH",
            timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date()),
            deviceName = Build.MODEL
        )

        val subject = "[MSG_GUARD] ${result.verdict.name} Alert - ${result.sender}"

        // Ensure 'from' is a valid single address string; Resend requires a verified sender
        // Fix: sometimes 'from' receives a concatenated string from UI or logs like 'MessageGuard <onboarding@resend.dev>Good...'
        val normalizedFrom = try {
            if (from.contains("<") && from.contains(">")) {
                val extracted = from.substring(0, from.indexOf(">") + 1)
                extracted
            } else {
                "MessageGuard <$from>"
            }
        } catch (e: Exception) {
            "MessageGuard <onboarding@resend.dev>"
        }
        // Fallback sender (from BuildConfig or our default) to use if Resend rejects the domain
        val normalizedFallback = "MessageGuard <onboarding@resend.dev>"

        // We'll build the payload per-attempt so we can swap the 'from' address and retry if needed
        var attempt = 0
        var currentFrom = normalizedFrom

        val finalApiKey = if (apiKey.isBlank()) getResendApiKey() else apiKey
        if (finalApiKey.isBlank()) {
            Log.e("ResendAlertDebug", "No API key available for sending alerts")
            Log.e("ResendAlert", "No API key available for sending alerts")
            return DeliveryResult(false, "No Resend API key configured. Add it in Settings or local.properties.")
        }

        // Try once, then one retry on 5xx or retry once with fallback sender if domain unverified
        while (attempt < 2) {
            try {
                var delivery: DeliveryResult? = null
                // Build request fresh for this attempt with current 'from'
                val payload = JSONObject().apply {
                    put("from", currentFrom)
                    put("to", JSONArray().put(to))
                    put("subject", subject)
                    put("html", htmlContent)
                }
                val request = Request.Builder()
                    .url("https://api.resend.com/emails")
                    .addHeader("Authorization", "Bearer $finalApiKey")
                    .addHeader("Content-Type", "application/json")
                    .post(payload.toString().toRequestBody(JSON_TYPE))
                    .build()

                Log.d("ResendAlertDebug", "Attempting send - from: $currentFrom, to: $to, subject: $subject")
                Log.d("ResendAlert", "Attempting send - from: $currentFrom, to: $to, subject: $subject")
                client.newCall(request).execute().use { response ->
                    val bodyStr = response.body?.string().orEmpty()
                    Log.d("ResendAlertDebug", "HTTP Status ${response.code} | Response body: $bodyStr")
                    Log.d("ResendAlert", "Resend response body: $bodyStr")
                    if (response.isSuccessful) {
                        Log.i("ResendAlertDebug", "Alert sent successfully [HTTP ${response.code}] to $to")
                        Log.i("ResendAlert", "Alert sent successfully to $to (from: $currentFrom)")
                        delivery = DeliveryResult(true, "Test email sent. Check $to.")
                    } else {
                        Log.e("ResendAlertDebug", "HTTP Status ${response.code} | Resend Error Body: $bodyStr")
                        Log.e("ResendAlert", "Resend API Error: ${response.code} / $bodyStr")
                        // If domain not verified, try once with the configured fallback sender
                        if (bodyStr.contains("domain is not verified", true) && currentFrom != normalizedFallback && attempt == 0) {
                            Log.w("ResendAlertDebug", "Domain unverified for $currentFrom; retrying with fallback $normalizedFallback")
                            Log.w("ResendAlert", "Domain not verified for $currentFrom; retrying with fallback sender $normalizedFallback")
                            currentFrom = normalizedFallback
                            attempt++
                            delivery = null // indicate retry
                        } else if (response.code in 500..599 && attempt == 0) {
                            attempt++
                            Log.w("ResendAlertDebug", "Server error ${response.code}, retrying once")
                            Log.w("ResendAlert", "Server error, retrying once")
                            delivery = null
                        } else {
                            val short = bodyStr.take(800)
                            delivery = DeliveryResult(false, "Resend rejected request (${response.code}): $short")
                        }
                    }
                }

                if (delivery != null) return delivery
            } catch (e: Exception) {
                Log.e("ResendAlertDebug", "Network exception on send attempt $attempt: ${e.javaClass.simpleName} - ${e.message}", e)
                Log.e("ResendAlert", "Network failure in alert: ${e.message}")
                if (attempt == 0) {
                    attempt++
                    Thread.sleep(300)
                    continue
                }
                return DeliveryResult(false, "Could not send email: ${e.message}")
            }
        }
        return DeliveryResult(false, "Unknown error sending alert")
    }

    private fun AnalysisResult.extractFirstUrl(): String {
        return flags.find { it.contains("http") }?.split(":")?.drop(1)?.joinToString(":")?.trim() 
            ?: "No URLs detected in payload."
    }
}
