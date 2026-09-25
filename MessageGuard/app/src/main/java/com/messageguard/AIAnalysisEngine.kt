package com.messageguard

import android.util.Log
import com.google.gson.*
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class InvalidApiKeyException : Exception("Invalid API key — check Settings")

/**
 * Dedicated standalone verification engine used specifically by [SettingsActivity]
 * to test and validate custom Gemini API keys entered by the user.
 *
 * Production real-time inference and hybrid edge-cloud scoring pipelines
 * route through [SpamAnalyzer.requestGeminiDirect].
 */
class AIAnalysisEngine(private val apiKey: String) {
    private val gson = Gson()
    private val client = OkHttpClient.Builder().callTimeout(60, TimeUnit.SECONDS).build()

    suspend fun analyze(appSource: String, sender: String, subject: String, messageBody: String): AnalysisResult = withContext(Dispatchers.IO) {
        if (apiKey.isBlank() || messageBody.isBlank()) throw Exception("Invalid input")
        
        val discoveryUrl = "https://generativelanguage.googleapis.com/v1beta/models?key=$apiKey"
        val models = try {
            client.newCall(Request.Builder().url(discoveryUrl).build()).execute().use { res ->
                val root = gson.fromJson(res.body?.string(), JsonObject::class.java)
                root.getAsJsonArray("models")?.map { it.asJsonObject.get("name").asString } ?: emptyList()
            }
        } catch (e: Exception) { emptyList() }

        // Model selection priority: verified against live API 2026-08-20.
        // gemini-1.5-flash and gemini-2.0-flash are no longer available on this key.
        val bestModel = models.find { it.contains("gemini-2.5-flash-lite") }
            ?: models.find { it.contains("gemini-2.5-flash") }
            ?: models.find { it.contains("gemini-flash-latest") }
            ?: models.find { it.contains("gemini-pro") }
            ?: "models/gemini-2.5-flash"
            
        val url = "https://generativelanguage.googleapis.com/v1beta/$bestModel:generateContent?key=$apiKey"
        val prompt = """
            You are a Cybersecurity forensic engine. Analyze the following MESSAGE content.
            
            DIRECTIVE: Default to SAFE unless there is clear evidence of: credential harvesting, financial fraud requests, impersonation of a real institution/bank, or malicious links. Ordinary personal, academic, or business messages — even ones mentioning money, urgency, deadlines, or links to well-known verified services — should be SAFE unless a specific fraud pattern is present.
            
            SENDER: $sender
            SUBJECT: $subject
            CONTENT TO ANALYZE: ${messageBody.take(800)}
            
            Return JSON ONLY:
            {
              "verdict": "SAFE" | "WARNING" | "DANGER",
              "score": <0-100>,
              "summary": "<1-2 sentences explanation>"
            }
        """.trimIndent()

        val body = JsonObject().apply {
            add("contents", gson.toJsonTree(listOf(mapOf("parts" to listOf(mapOf("text" to prompt))))))
        }.toString().toRequestBody("application/json".toMediaType())

        for (retry in 0..1) {
            try {
                val res = client.newCall(Request.Builder().url(url).post(body).build()).execute()
                val code = res.code; val rawBody = res.body?.string()
                res.close()

                if (code == 401 || code == 403) throw InvalidApiKeyException()
                if (code == 200) {
                    val json = gson.fromJson(rawBody, JsonObject::class.java)
                    val text = json.getAsJsonArray("candidates")?.get(0)?.asJsonObject?.getAsJsonObject("content")
                        ?.getAsJsonArray("parts")?.get(0)?.asJsonObject?.get("text")?.asString ?: ""
                    val f = text.indexOf('{'); val l = text.lastIndexOf('}')
                    val j = gson.fromJson(text.substring(f, l+1), JsonObject::class.java)
                    val vStr = j.get("verdict")?.asString?.uppercase()
                    val v = when (vStr) {
                        "DANGER" -> Verdict.DANGER
                        "WARNING" -> Verdict.WARNING
                        else -> Verdict.SAFE
                    }
                    val score = j.get("score")?.asInt ?: if (v == Verdict.DANGER) 85 else if (v == Verdict.WARNING) 45 else 0
                    return@withContext AnalysisResult(
                        appSource = appSource, sender = sender, subject = subject,
                        verdict = v,
                        riskScore = score,
                        aiScore = score,
                        summary = j.get("summary")?.asString ?: "Scan successful"
                    )
                } else if (code == 429) delay(15_000)
                else throw Exception("Model failed: $code")
            } catch (e: InvalidApiKeyException) { throw e }
            catch (e: Exception) { if (retry == 0) continue else throw e }
        }
        throw Exception("Quota hit. Please retry.")
    }
}
