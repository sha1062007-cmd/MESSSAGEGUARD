package com.messageguard.threatvision.domain.gemini

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.messageguard.threatvision.domain.model.InputSpec
import com.messageguard.threatvision.domain.model.InputType
import com.messageguard.threatvision.domain.model.ModelStatus
import com.messageguard.threatvision.domain.model.SignalFeatures
import com.messageguard.threatvision.domain.model.SignalScore
import com.messageguard.threatvision.domain.model.ThreatSignalModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Standing ensemble member connecting directly to Gemini Cloud LLM.
 * Features:
 * - Direct API connection with user/default API key
 * - PII Redaction for email/phone numbers before cloud dispatch
 * - In-memory SHA-256 caching & rate-limit throttling
 * - Maps response into normalized [SignalScore]
 */
class GeminiEmailAnalysisModel(private val context: Context) : ThreatSignalModel {

    override val modelId: String = "gemini_ensemble"
    override val version: String = "1.5.0"
    override val inputSpec: InputSpec = InputSpec(
        type = InputType.TEXT,
        description = "Redacted email text, sender, and detected URLs"
    )

    private val gson = Gson()
    private val httpClient = OkHttpClient.Builder()
        .callTimeout(15, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val cache = ConcurrentHashMap<String, SignalScore>()
    private var backoffUntil = 0L

    companion object {
        private const val TAG = "ThreatVisionLog"
        private const val DEFAULT_MODEL = "models/gemini-2.5-flash"
    }

    override suspend fun score(features: SignalFeatures): SignalScore = withContext(Dispatchers.IO) {
        val apiKey = getApiKey()
        if (apiKey.isBlank()) {
            return@withContext SignalScore(
                modelId = modelId,
                riskScore = 0.0f,
                confidence = 0.0f,
                category = "SAFE",
                explanation = "Gemini API key not configured.",
                status = ModelStatus.DISABLED_AWAITING_SPEC
            )
        }

        if (System.currentTimeMillis() < backoffUntil) {
            return@withContext SignalScore(
                modelId = modelId,
                riskScore = 0.0f,
                confidence = 0.0f,
                category = "SUSPICIOUS",
                explanation = "Gemini rate-limited (cooling down).",
                status = ModelStatus.ACTIVE
            )
        }

        val textToAnalyze = features.rawText.ifBlank { "${features.subject}\n${features.rawText}" }
        if (textToAnalyze.isBlank()) {
            return@withContext SignalScore(
                modelId = modelId,
                riskScore = 0.0f,
                confidence = 0.0f,
                category = "SAFE",
                explanation = "Empty content to analyze.",
                status = ModelStatus.ACTIVE
            )
        }

        // 1. Redact PII (emails, phone numbers, UPI handles)
        val redacted = redactPii(textToAnalyze)
        val hash = sha256(redacted)

        // 2. Check Cache
        cache[hash]?.let { cached ->
            Log.d(TAG, "GeminiEmailAnalysisModel: Cache hit for hash ${hash.take(8)}")
            return@withContext cached
        }

        // 3. Prepare Prompt
        val prompt = """
            You are an advanced Cybersecurity & Anti-Phishing AI forensic engine.
            Analyze the following email/message snippet for fraud, BEC (Business Email Compromise), spoofing, credential harvesting, or urgency scams.
            
            SENDER: ${features.sender}
            DETECTED URLS: ${features.urls.joinToString(", ")}
            EMAIL BODY:
            ${redacted.take(1000)}
            
            Return JSON ONLY with no formatting ticks:
            {
              "verdict": "SAFE" | "WARNING" | "DANGER",
              "risk_score": <integer 0-100>,
              "confidence": <float 0.0-1.0>,
              "category": "PHISHING" | "SPAM" | "BEC_FRAUD" | "SPOOFING" | "OTP_FRAUD" | "SAFE",
              "reason": "<one sentence explanation>"
            }
        """.trimIndent()

        val requestBody = JsonObject().apply {
            add("contents", gson.toJsonTree(listOf(mapOf("parts" to listOf(mapOf("text" to prompt))))))
        }.toString().toRequestBody("application/json".toMediaType())

        val url = "https://generativelanguage.googleapis.com/v1beta/$DEFAULT_MODEL:generateContent?key=$apiKey"
        val request = Request.Builder().url(url).post(requestBody).build()

        try {
            val response = httpClient.newCall(request).execute()
            val code = response.code
            val bodyString = response.body?.string() ?: ""
            response.close()

            if (code == 429 || code == 503) {
                backoffUntil = System.currentTimeMillis() + 45_000L
                Log.w(TAG, "Gemini API rate limited ($code). Cooling down 45s.")
                return@withContext SignalScore(
                    modelId = modelId,
                    riskScore = 0.0f,
                    confidence = 0.0f,
                    explanation = "Gemini rate-limited ($code).",
                    status = ModelStatus.ACTIVE
                )
            }

            if (code == 200) {
                val json = gson.fromJson(bodyString, JsonObject::class.java)
                val responseText = json.getAsJsonArray("candidates")
                    ?.get(0)?.asJsonObject
                    ?.getAsJsonObject("content")
                    ?.getAsJsonArray("parts")
                    ?.get(0)?.asJsonObject
                    ?.get("text")?.asString ?: ""

                val start = responseText.indexOf('{')
                val end = responseText.lastIndexOf('}')
                if (start != -1 && end != -1) {
                    val parsed = gson.fromJson(responseText.substring(start, end + 1), JsonObject::class.java)
                    val rawScore = parsed.get("risk_score")?.asInt ?: 0
                    val confidence = parsed.get("confidence")?.asFloat ?: 0.85f
                    val category = parsed.get("category")?.asString?.uppercase() ?: "SUSPICIOUS"
                    val reason = parsed.get("reason")?.asString ?: "Evaluated by Gemini Forensic LLM."

                    val signalScore = SignalScore(
                        modelId = modelId,
                        riskScore = (rawScore / 100f).coerceIn(0.0f, 1.0f),
                        confidence = confidence.coerceIn(0.0f, 1.0f),
                        category = category,
                        explanation = reason,
                        status = ModelStatus.ACTIVE
                    )
                    cache[hash] = signalScore
                    return@withContext signalScore
                }
            }
            Log.w(TAG, "Gemini response error ($code): $bodyString")
        } catch (e: Exception) {
            Log.w(TAG, "Gemini call exception: ${e.message}")
        }

        SignalScore(
            modelId = modelId,
            riskScore = 0.0f,
            confidence = 0.0f,
            explanation = "Gemini offline or unreachable.",
            status = ModelStatus.ACTIVE
        )
    }

    private fun getApiKey(): String {
        val prefs = context.getSharedPreferences(com.messageguard.Constants.PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(com.messageguard.Constants.KEY_API_KEY, "") ?: ""
    }

    private fun redactPii(input: String): String {
        // Redact phone numbers, email addresses, and UPI IDs
        return input
            .replace(Regex("""[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"""), "[REDACTED_EMAIL]")
            .replace(Regex("""(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"""), "[REDACTED_PHONE]")
            .replace(Regex("""(?i)\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b"""), "[REDACTED_UPI]")
    }

    private fun sha256(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
