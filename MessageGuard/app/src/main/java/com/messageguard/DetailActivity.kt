package com.messageguard

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import android.text.SpannableString
import android.text.Spanned
import android.text.style.BackgroundColorSpan
import com.google.gson.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit

class DetailActivity : AppCompatActivity() {

    private val gson = Gson()
    
    private val geminiClient = OkHttpClient.Builder()
        .addInterceptor(HttpLoggingInterceptor { Log.d("GeminiHTTP", it) }.apply {
            level = HttpLoggingInterceptor.Level.BODY
        })
        .callTimeout(45, TimeUnit.SECONDS)
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(25, TimeUnit.SECONDS)
        .build()

    data class LocalExplainabilityItem(val span: String, val reason: String)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_detail)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val resultId = intent.getLongExtra("result_id", -1L)
        val passedResult = intent.getSerializableExtra("analysis_result") as? AnalysisResult
        val analysisJsonStr = intent.getStringExtra("analysis_json")

        if (resultId == -1L && passedResult == null && analysisJsonStr.isNullOrBlank()) {
            finish()
            return
        }

        lifecycleScope.launch {
            val result: AnalysisResult? = if (passedResult != null) {
                passedResult
            } else if (!analysisJsonStr.isNullOrBlank()) {
                try {
                    val jsonObj = JSONObject(analysisJsonStr)
                    val verdictStr = jsonObj.optString("verdict", "UNVERIFIED")
                    val verdictObj = when (verdictStr) {
                        "SAFE", "VERIFIED" -> Verdict.SAFE
                        "SUSPICIOUS" -> Verdict.WARNING
                        "MALICIOUS" -> Verdict.DANGER
                        else -> Verdict.UNCERTAIN
                    }
                    val riskScore = jsonObj.optInt("risk_score", 0)
                    val summary = jsonObj.optString("summary", "Email Security Analysis Complete")
                    val sender = intent.getStringExtra("email_sender") ?: jsonObj.optJSONObject("email_metadata")?.optString("sender") ?: "Unknown Sender"
                    val subject = intent.getStringExtra("email_subject") ?: jsonObj.optJSONObject("email_metadata")?.optString("subject") ?: "(No Subject)"

                    val extractedFlags = mutableListOf<String>()
                    val contentAnalysis = jsonObj.optJSONObject("content_analysis")
                    if (contentAnalysis != null) {
                        val riskFactorsArr = contentAnalysis.optJSONArray("risk_factors")
                        if (riskFactorsArr != null) {
                            for (i in 0 until riskFactorsArr.length()) {
                                extractedFlags.add(riskFactorsArr.getString(i))
                            }
                        }
                    }
                    val spoofingObj = contentAnalysis?.optJSONObject("spoofing_indicators")
                    if (spoofingObj != null) {
                        val factorsArr = spoofingObj.optJSONArray("factors")
                        if (factorsArr != null) {
                            for (i in 0 until factorsArr.length()) {
                                val factor = factorsArr.getString(i)
                                if (!extractedFlags.contains(factor)) {
                                    extractedFlags.add(factor)
                                }
                            }
                        }
                    }
                    if (extractedFlags.isEmpty()) {
                        extractedFlags.add("No specific content risk factors detected")
                    }

                    val res = AnalysisResult(
                        id = 0L,
                        appSource = "Gmail Notification",
                        sender = sender,
                        subject = subject,
                        messageSnippet = subject,
                        mlScore = riskScore,
                        aiScore = if (jsonObj.has("ai_score")) jsonObj.optInt("ai_score") else -1,
                        riskScore = riskScore,
                        verdict = verdictObj,
                        summary = summary,
                        action = if (verdictObj == Verdict.DANGER) "Quarantine / Delete" else if (verdictObj == Verdict.WARNING) "Flagged / Warn User" else "Allowed",
                        senderTrust = if (verdictObj == Verdict.SAFE) "High Trust" else "Low / Untrusted",
                        timestamp = System.currentTimeMillis(),
                        explainabilityJson = "",
                        flags = extractedFlags
                    )
                    // Persist to Room DB so history & dashboard are populated!
                    val repo = AnalysisRepository(this@DetailActivity)
                    val newId = repo.insert(res)
                    res.copy(id = newId)
                } catch (e: Exception) {
                    Log.e("DetailActivity", "Failed to parse analysis_json: ${e.message}", e)
                    null
                }
            } else {
                val db = AnalysisHistoryDatabase.getInstance(this@DetailActivity)
                db.dao().getById(resultId)
            }

            if (result == null) { finish(); return@launch }
            
            title = "Forensic Analysis Report"
            
            val tvVerdict = findViewById<TextView>(R.id.tv_detail_verdict)
            tvVerdict.text = "${result.verdict.name} Verdict"
            tvVerdict.setTextColor(when(result.verdict) {
                Verdict.SAFE -> Color.parseColor("#2E7D32")
                Verdict.WARNING -> Color.parseColor("#E65100")
                else -> Color.parseColor("#C62828")
            })

            // Risk index colors
            findViewById<ProgressBar>(R.id.progress_detail_risk).apply {
                progress = result.riskScore
                progressTintList = android.content.res.ColorStateList.valueOf(
                    when (result.verdict) {
                        Verdict.SAFE -> Color.parseColor("#2E7D32")
                        Verdict.WARNING -> Color.parseColor("#E65100")
                        Verdict.DANGER -> Color.parseColor("#C62828")
                        Verdict.UNCERTAIN -> Color.parseColor("#9E9E9E")
                    }
                )
            }

            // Bind Breakdown
            val progressMl = findViewById<ProgressBar>(R.id.progress_detail_ml)
            val tvMlScore = findViewById<TextView>(R.id.tv_detail_ml_score)
            progressMl.progress = result.mlScore
            progressMl.progressTintList = android.content.res.ColorStateList.valueOf(scoreColor(result.mlScore))
            tvMlScore.text = "${result.mlScore}%"
            tvMlScore.setTextColor(scoreColor(result.mlScore))

            val progressAi = findViewById<ProgressBar>(R.id.progress_detail_ai)
            val tvAiScore = findViewById<TextView>(R.id.tv_detail_ai_score)
            if (result.aiScore == -1) {
                progressAi.visibility = View.INVISIBLE
                tvAiScore.text = "Offline"
                tvAiScore.setTextColor(Color.GRAY)
            } else {
                progressAi.visibility = View.VISIBLE
                progressAi.progress = result.aiScore
                progressAi.progressTintList = android.content.res.ColorStateList.valueOf(scoreColor(result.aiScore))
                tvAiScore.text = "${result.aiScore}%"
                tvAiScore.setTextColor(scoreColor(result.aiScore))
            }

            // Message Snippet Highlight rendering
            val tvMessageBody = findViewById<TextView>(R.id.tv_detail_message_body)
            val rawMsg = result.flags.find { it.startsWith("__RAW_MESSAGE=") }?.removePrefix("__RAW_MESSAGE=")
            val bodyText = result.messageSnippet.ifBlank { rawMsg ?: result.subject }
            tvMessageBody.text = highlightSpans(bodyText, result.explainabilityJson)

            // Other fields
            findViewById<TextView>(R.id.tv_detail_sender).text = "Sender: ${result.sender}"
            findViewById<TextView>(R.id.tv_detail_subject).text = "Subject: ${result.subject.ifBlank { "(No Subject)" }}"
            findViewById<TextView>(R.id.tv_detail_summary).text = result.summary
            
            // Format Risk Factors & Specific Reasoning Signals clearly
            val visibleFlags = result.flags.filterNot { it.startsWith("__") }
            val formattedFlags = if (visibleFlags.isNotEmpty()) {
                visibleFlags.joinToString("\n\n") { "• $it" }
            } else {
                "• No specific content risk factors detected"
            }
            val tvFlags = findViewById<TextView>(R.id.tv_detail_flags)
            tvFlags.visibility = View.VISIBLE
            tvFlags.text = formattedFlags

            findViewById<TextView>(R.id.tv_detail_trust).text = "Trust Profile: ${result.senderTrust.uppercase()}"
            findViewById<TextView>(R.id.tv_detail_action).text = "Enforced Action: ${result.action.ifBlank { "Monitored" }}"
            findViewById<TextView>(R.id.tv_detail_app).text = "Source Application: ${result.appSource}"
            findViewById<TextView>(R.id.tv_detail_time).text = "Scan Timestamp: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(result.timestamp)}"

            var activeResultId = result.id
            bindFeedbackCard(result) { newId -> activeResultId = newId }

            val btnDelete = findViewById<Button>(R.id.btn_delete_detail)
            
            fun updateDeleteButton() {
                if (activeResultId == 0L) {
                    btnDelete.text = "Dismiss Report"
                    btnDelete.setOnClickListener { finish() }
                } else {
                    btnDelete.text = "Delete This Record"
                    btnDelete.setOnClickListener {
                        lifecycleScope.launch {
                            AnalysisHistoryDatabase.getInstance(this@DetailActivity).dao().deleteById(activeResultId)
                            finish()
                        }
                    }
                }
            }
            updateDeleteButton()
        }
    }

    private fun bindFeedbackCard(result: AnalysisResult, onPersisted: (Long) -> Unit) {
        val repo = AnalysisRepository(this)

        val layoutActive   = findViewById<LinearLayout>(R.id.layout_feedback_active)
        val layoutReadonly = findViewById<LinearLayout>(R.id.layout_feedback_readonly)
        val tvChip         = findViewById<TextView>(R.id.tv_feedback_confirmed)
        val btnCorrect     = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_feedback_correct)
        val btnWrong       = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_feedback_wrong)
        val layoutSubForm  = findViewById<LinearLayout>(R.id.layout_false_report)
        val tvLabel        = findViewById<TextView>(R.id.tv_false_report_label)
        val etNote         = findViewById<EditText>(R.id.et_feedback_note)
        val btnSubmit      = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_submit_feedback)
        val tvReadonlyType = findViewById<TextView>(R.id.tv_readonly_type)
        val tvReadonlyNote = findViewById<TextView>(R.id.tv_readonly_note)

        fun showSubmittedState(feedbackString: String) {
            layoutActive.visibility   = View.GONE
            layoutReadonly.visibility = View.GONE
            tvChip.visibility         = View.VISIBLE

            val parts = feedbackString.split(":", limit = 2)
            val typeKey = parts[0].trim()
            val noteText = if (parts.size > 1) parts[1].trim() else ""

            val typeLabel = when (typeKey) {
                "confirmed_correct" -> "You marked this verdict as correct."
                "false_positive"    -> "Reported as False Positive (verdict was too harsh)."
                "false_negative"    -> "Reported as False Negative (verdict missed a threat)."
                else                -> feedbackString
            }
            tvReadonlyType.text = typeLabel
            if (noteText.isNotBlank()) {
                tvReadonlyNote.text = "Your note: \"$noteText\""
                tvReadonlyNote.visibility = View.VISIBLE
            } else {
                tvReadonlyNote.visibility = View.GONE
            }
        }

        if (result.reviewed) {
            showSubmittedState(result.userFeedback ?: "confirmed_correct")
        }

        tvChip.setOnClickListener {
            tvChip.visibility         = View.GONE
            layoutReadonly.visibility = View.VISIBLE
        }
        val collapseHint = findViewById<TextView>(R.id.tv_collapse_hint)
        collapseHint.setOnClickListener {
            layoutReadonly.visibility = View.GONE
            tvChip.visibility         = View.VISIBLE
        }

        fun lockButtons() {
            btnCorrect.isEnabled = false
            btnWrong.isEnabled   = false
            btnSubmit.isEnabled  = false
        }

        fun persistAndConfirm(feedbackString: String) {
            lockButtons()
            lifecycleScope.launch {
                var currentId = result.id
                if (currentId == 0L) {
                    currentId = repo.insert(result)
                    onPersisted(currentId)
                }
                repo.submitFeedback(currentId, feedbackString)

                val isCorrect = feedbackString.startsWith("confirmed_correct")
                withContext(Dispatchers.IO) {
                    AdaptiveTrustEngine.adjustWeightsOnFeedback(this@DetailActivity, result, isCorrect, feedbackString)
                }

                showSubmittedState(feedbackString)
            }
        }

        btnCorrect.setOnClickListener {
            persistAndConfirm("confirmed_correct")
        }

        btnWrong.setOnClickListener {
            val isFalsePositive = result.verdict == Verdict.DANGER || result.verdict == Verdict.WARNING
            tvLabel.text = if (isFalsePositive)
                "Report as False Positive — this message is actually safe."
            else
                "Report as False Negative — this message is actually dangerous."
            layoutSubForm.visibility = View.VISIBLE
        }

        btnSubmit.setOnClickListener {
            val isFalsePositive = result.verdict == Verdict.DANGER || result.verdict == Verdict.WARNING
            val typeKey  = if (isFalsePositive) "false_positive" else "false_negative"
            val noteText = etNote.text?.toString()?.trim() ?: ""
            val feedbackString = if (noteText.isNotBlank()) "$typeKey: $noteText" else typeKey
            persistAndConfirm(feedbackString)
        }
    }

    private fun highlightSpans(text: String, explainabilityJson: String): SpannableString {
        val spannable = SpannableString(text)
        if (explainabilityJson.isBlank()) return spannable

        try {
            val listType = object : com.google.gson.reflect.TypeToken<List<LocalExplainabilityItem>>() {}.type
            val items: List<LocalExplainabilityItem> = gson.fromJson(explainabilityJson, listType)

            for (item in items) {
                val spanText = item.span
                val reasonText = item.reason
                if (spanText.isBlank()) continue

                val color = when {
                    reasonText.contains("Heuristic", ignoreCase = true) || 
                    reasonText.contains("Impersonation", ignoreCase = true) ||
                    reasonText.contains("Homograph", ignoreCase = true) ||
                    reasonText.contains("Homoglyph", ignoreCase = true) -> Color.parseColor("#FFCDD2") // Red
                    reasonText.contains("CNN", ignoreCase = true) -> Color.parseColor("#FFF9C4")       // Yellow
                    reasonText.contains("NLP", ignoreCase = true) -> Color.parseColor("#B2EBF2")       // Cyan
                    else -> Color.parseColor("#E0E0E0")
                }

                var index = text.indexOf(spanText, ignoreCase = true)
                while (index >= 0) {
                    spannable.setSpan(
                        BackgroundColorSpan(color),
                        index,
                        index + spanText.length,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                    index = text.indexOf(spanText, index + 1, ignoreCase = true)
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return spannable
    }

    private fun scoreColor(score: Int): Int = when {
        score >= 70 -> Color.parseColor("#C62828")
        score >= 35 -> Color.parseColor("#E65100")
        else -> Color.parseColor("#2E7D32")
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
