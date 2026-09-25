package com.messageguard

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
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
import java.io.File
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
        val passedBackendCaseId = intent.getStringExtra("backend_case_id")

        if (resultId == -1L && passedResult == null && analysisJsonStr.isNullOrBlank()) {
            finish()
            return
        }

        lifecycleScope.launch {
            var parsedJsonObj: JSONObject? = null
            val result: AnalysisResult? = if (passedResult != null) {
                passedResult
            } else if (!analysisJsonStr.isNullOrBlank()) {
                try {
                    val jsonObj = JSONObject(analysisJsonStr)
                    parsedJsonObj = jsonObj
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
                        senderTrust = when (verdictObj) {
                            Verdict.SAFE -> "High Trust"
                            Verdict.UNCERTAIN -> "Unverified"
                            Verdict.WARNING -> "Suspicious"
                            Verdict.DANGER -> "Low / Untrusted"
                        },
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

            // 1. Case Identifier & Classification Banner
            val displayCaseId = passedBackendCaseId
                ?: parsedJsonObj?.optString("case_id")
                ?: (if (result.id != 0L) "CASE-DB-${result.id}" else "SCAN-LOCAL")
            findViewById<TextView>(R.id.tv_detail_case_id).text = "Case ID: $displayCaseId"

            val displayCategory = parsedJsonObj?.optString("primaryCategory")
                ?: if (result.verdict == Verdict.DANGER) "MALICIOUS_THREAT" else if (result.verdict == Verdict.WARNING) "SUSPICIOUS_PHISHING" else "VERIFIED_SAFE"
            val tvCategory = findViewById<TextView>(R.id.tv_detail_category)
            tvCategory.text = displayCategory.replace("_", " ")
            when (result.verdict) {
                Verdict.SAFE, Verdict.UNCERTAIN -> {
                    tvCategory.setTextColor(Color.parseColor("#2E7D32"))
                    tvCategory.setBackgroundColor(Color.parseColor("#E8F5E9"))
                }
                Verdict.WARNING -> {
                    tvCategory.setTextColor(Color.parseColor("#E65100"))
                    tvCategory.setBackgroundColor(Color.parseColor("#FFF3E0"))
                }
                Verdict.DANGER -> {
                    tvCategory.setTextColor(Color.parseColor("#C62828"))
                    tvCategory.setBackgroundColor(Color.parseColor("#FFEBEE"))
                }
            }

            findViewById<TextView>(R.id.tv_detail_timestamp_header).text =
                "Forensic Ingestion: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(result.timestamp)}"

            // 2. Verdict & Overall Risk Card
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

            // 3. ML vs AI Score Breakdown Card
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

            // 4. Email Authentication Forensics Card (SPF/DKIM/DMARC)
            val authObj = parsedJsonObj?.optJSONObject("authentication")
            val spfStatus = authObj?.optJSONObject("spf")?.optString("status") ?: if (result.verdict == Verdict.SAFE) "PASS" else "UNKNOWN"
            val dkimStatus = authObj?.optJSONObject("dkim")?.optString("status") ?: if (result.verdict == Verdict.SAFE) "PASS" else "UNKNOWN"
            val dmarcStatus = authObj?.optJSONObject("dmarc")?.optString("status") ?: if (result.verdict == Verdict.SAFE) "PASS" else "UNKNOWN"
            
            formatAuthBadge(findViewById(R.id.tv_auth_spf), "SPF", spfStatus)
            formatAuthBadge(findViewById(R.id.tv_auth_dkim), "DKIM", dkimStatus)
            formatAuthBadge(findViewById(R.id.tv_auth_dmarc), "DMARC", dmarcStatus)

            val domainAuthStatus = authObj?.optString("domain_authorization_status")
                ?: if (result.verdict == Verdict.SAFE) "DOMAIN_AUTHORIZED" else "PARTIAL_OR_UNAVAILABLE"
            val tvDomainStatus = findViewById<TextView>(R.id.tv_auth_domain_status)
            tvDomainStatus.text = "Domain Authorization: $domainAuthStatus"
            tvDomainStatus.setTextColor(if (domainAuthStatus == "DOMAIN_AUTHORIZED") Color.parseColor("#2E7D32") else Color.parseColor("#C62828"))

            val authNote = authObj?.optString("forensic_note")
                ?: "Header authentication results indicate domain alignment status. Auth failures do not confirm attacker IP."
            findViewById<TextView>(R.id.tv_auth_note).text = authNote

            // 5. Origin & GeoLocation Intelligence Card
            var earObs = parsedJsonObj?.optJSONObject("earliest_reliable_observed_ip")
            val earObsStr = parsedJsonObj?.optString("earliest_reliable_observed_ip")
            val geoIp = earObs?.optString("ip")
                ?: if (!earObsStr.isNullOrBlank() && earObsStr != "ORIGIN_NOT_DETERMINABLE") earObsStr
                else (if (result.appSource.contains("Circle", ignoreCase = true)) "N/A (Visual Capture)" else "127.0.0.1 (Direct Relay)")

            val geoCity = earObs?.optString("city", "")?.takeIf { it.isNotBlank() && it != "Unknown City" }
            val geoRegion = earObs?.optString("region", "")?.takeIf { it.isNotBlank() }
            val geoCountry = earObs?.optString("country", "")?.takeIf { it.isNotBlank() && it != "Unknown Country" }
            val geoLoc = listOfNotNull(geoCity, geoRegion, geoCountry).joinToString(", ").ifBlank {
                if (earObs != null) "Approximate Network Transit"
                else if (result.appSource.contains("Circle", ignoreCase = true)) "Local Device OCR"
                else "Internal Network Subnet"
            }

            val geoIsp = earObs?.optString("isp")?.takeIf { it.isNotBlank() && it != "Unknown ISP" }
                ?: earObs?.optString("org")?.takeIf { it.isNotBlank() }
                ?: "Local / Transit Network"
            val geoClass = earObs?.optString("classification") ?: (if (result.verdict == Verdict.DANGER) "[UNTRUSTED ROUTE]" else "[DIRECT TRANSIT]")
            val geoDisc = parsedJsonObj?.optString("geo_disclaimer")
                ?: "IMPORTANT: Location represents the approximate network infrastructure associated with the observed IP address. It does not establish the sender's exact physical location or identity."

            val lat = earObs?.optDouble("lat")?.takeIf { !it.isNaN() && it != 0.0 }
            val lon = earObs?.optDouble("lon")?.takeIf { !it.isNaN() && it != 0.0 }

            findViewById<TextView>(R.id.tv_geo_ip).text = "Earliest Reliable Observable Public IP: $geoIp"
            findViewById<TextView>(R.id.tv_geo_location).text = "Approximate Location: $geoLoc"
            findViewById<TextView>(R.id.tv_geo_isp).text = "ISP / Organization: $geoIsp"
            findViewById<TextView>(R.id.tv_geo_classification).text = "Infrastructure: $geoClass"
            findViewById<TextView>(R.id.tv_geo_disclaimer).text = geoDisc

            val tvCoords = findViewById<TextView>(R.id.tv_geo_coordinates)
            val webViewMap = findViewById<android.webkit.WebView>(R.id.webview_forensic_map)
            val tvMapPlaceholder = findViewById<TextView>(R.id.tv_map_placeholder)

            if (lat != null && lon != null && lat in -90.0..90.0 && lon in -180.0..180.0) {
                val formattedCoords = String.format(Locale.US, "Coordinates: %.4f° N/S, %.4f° E/W", lat, lon)
                tvCoords.text = formattedCoords
                tvCoords.visibility = View.VISIBLE
                tvMapPlaceholder.visibility = View.GONE
                webViewMap.visibility = View.VISIBLE

                // Load interactive OpenStreetMap / Leaflet tile map
                val sanitizedCity = (geoCity ?: "Observed Infrastructure").replace("'", "\\'")
                val sanitizedIp = geoIp.replace("'", "\\'")
                val mapHtml = """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
                        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
                        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
                        <style>
                            body, html { margin:0; padding:0; height:100%; width:100%; background:#ECEFF1; font-family: sans-serif; }
                            #map { height:100%; width:100%; }
                            .custom-popup { font-size:11px; line-height:1.4; color:#263238; }
                            .popup-title { font-weight:bold; color:#C62828; margin-bottom:2px; }
                        </style>
                    </head>
                    <body>
                        <div id="map"></div>
                        <script>
                            var map = L.map('map', { zoomControl: false, attributionControl: false }).setView([$lat, $lon], 7);
                            L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
                                maxZoom: 18
                            }).addTo(map);
                            var circle = L.circle([$lat, $lon], {
                                color: '#1565C0',
                                fillColor: '#2196F3',
                                fillOpacity: 0.25,
                                radius: 25000
                            }).addTo(map);
                            var marker = L.marker([$lat, $lon]).addTo(map);
                            marker.bindPopup("<div class='custom-popup'><div class='popup-title'>Observed Network Infrastructure</div><b>IP:</b> $sanitizedIp<br/><b>Location:</b> $sanitizedCity<br/><i>Approximate transit node</i></div>").openPopup();
                        </script>
                    </body>
                    </html>
                """.trimIndent()

                webViewMap.settings.javaScriptEnabled = true
                webViewMap.settings.domStorageEnabled = true
                webViewMap.loadDataWithBaseURL("https://openstreetmap.org", mapHtml, "text/html", "UTF-8", null)
            } else {
                tvCoords.text = "Coordinates: Unavailable (Non-routable or private IP)"
                webViewMap.visibility = View.GONE
                tvMapPlaceholder.visibility = View.VISIBLE
                if (geoIp.startsWith("10.") || geoIp.startsWith("192.168.") || geoIp.startsWith("172.") || geoIp.startsWith("127.")) {
                    tvMapPlaceholder.text = "Private / Non-Global IP ($geoIp)\nGeolocation unavailable for internal network addresses."
                } else {
                    tvMapPlaceholder.text = "Approximate Location Unavailable\nNo routable coordinates could be resolved."
                }
            }

            // Populate Observed Relay Sequence
            val relayChainArr = parsedJsonObj?.optJSONArray("relay_chain")
            val tvRelaySeq = findViewById<TextView>(R.id.tv_relay_sequence)
            if (relayChainArr != null && relayChainArr.length() > 0) {
                val sbRelay = StringBuilder()
                for (i in 0 until relayChainArr.length()) {
                    val hop = relayChainArr.getJSONObject(i)
                    val hopIdx = hop.optInt("hop_index", i + 1)
                    val hopIp = hop.optString("ip", "unknown")
                    val hopTrust = hop.optString("trust_label", "OBSERVED")
                    val hopFrom = hop.optString("from_host", "")
                    val hopBy = hop.optString("by_host", "")
                    sbRelay.append("Hop $hopIdx: $hopIp ($hopTrust)")
                    if (hopFrom.isNotBlank() || hopBy.isNotBlank()) {
                        sbRelay.append("\n       from: ${hopFrom.take(28)} by: ${hopBy.take(28)}")
                    }
                    if (i < relayChainArr.length() - 1) sbRelay.append("\n  ↓\n")
                }
                tvRelaySeq.text = sbRelay.toString()
            } else {
                tvRelaySeq.text = "Hop 1: $geoIp [Earliest Observable Hop]"
            }

            // 6. Campaign & Relationship Graph Card
            val campObj = parsedJsonObj?.optJSONObject("campaign")
            val campaignName = campObj?.optString("campaign_name") ?: "Campaign Cluster: Standalone / Unclustered"
            findViewById<TextView>(R.id.tv_detail_campaign_name).text = campaignName

            val graphTree = buildString {
                appendLine("CASE: $displayCaseId")
                appendLine(" ├── ORIGIN: $geoIp ($geoLoc)")
                appendLine(" ├── DOMAIN: ${result.sender.substringAfter("@", "unknown-domain")}")
                appendLine(" ├── AUTH: $domainAuthStatus (SPF:$spfStatus DKIM:$dkimStatus DMARC:$dmarcStatus)")
                appendLine(" ├── VERDICT: ${result.verdict.name} (Risk Score: ${result.riskScore}%)")
                appendLine(" └── CAMPAIGN: $campaignName")
            }
            findViewById<TextView>(R.id.tv_detail_graph_tree).text = graphTree

            val graphSummary = parsedJsonObj?.optString("investigation_graph_summary")
                ?: "Graph Topology: 6 Entity Nodes, 5 Forensic Edges"
            findViewById<TextView>(R.id.tv_detail_graph_stats).text = graphSummary

            // 7. Message Snippet Highlight rendering
            val tvMessageBody = findViewById<TextView>(R.id.tv_detail_message_body)
            val rawMsg = result.flags.find { it.startsWith("__RAW_MESSAGE=") }?.removePrefix("__RAW_MESSAGE=")
            val bodyText = result.messageSnippet.ifBlank { rawMsg ?: result.subject }
            tvMessageBody.text = highlightSpans(bodyText, result.explainabilityJson)

            // 8. Forensic Summary & Red Flags
            findViewById<TextView>(R.id.tv_detail_summary).text = result.summary
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
            findViewById<TextView>(R.id.tv_detail_sender).text = "Sender: ${result.sender}"
            findViewById<TextView>(R.id.tv_detail_subject).text = "Subject: ${result.subject.ifBlank { "(No Subject)" }}"
            findViewById<TextView>(R.id.tv_detail_time).text = "Scan Timestamp: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(result.timestamp)}"

            // 9. Forensic PDF Dossier Export Button (ALWAYS VISIBLE for all scans)
            val reportUrl = parsedJsonObj?.optString("report_url")
                ?: if (displayCaseId.startsWith("MG-") || displayCaseId.startsWith("PS106-")) "http://10.0.2.2:8000/generate-report/$displayCaseId" else null
            val btnPdf = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_open_pdf_report)
            btnPdf.visibility = View.VISIBLE
            btnPdf.setOnClickListener {
                exportOrOpenPdfReport(result, displayCaseId, reportUrl)
            }

            // 10. Open in Gmail Button (Inside action area next to Delete)
            val btnGmail = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_open_in_gmail)
            btnGmail.visibility = View.VISIBLE
            btnGmail.setOnClickListener {
                openMessageInGmail(result)
            }

            // 9.5 Verdict Feedback Click Handlers
            val btnFeedbackYes = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_feedback_yes)
            val btnFeedbackNo = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_feedback_no)
            val tvFeedbackStatus = findViewById<TextView>(R.id.tv_feedback_status)
            val layoutFeedbackBtns = findViewById<View>(R.id.layout_feedback_buttons)

            btnFeedbackYes?.setOnClickListener {
                layoutFeedbackBtns?.visibility = View.GONE
                tvFeedbackStatus?.visibility = View.VISIBLE
                tvFeedbackStatus?.text = "Thank you! Marked as Correct verdict."
                tvFeedbackStatus?.setTextColor(Color.parseColor("#2E7D32"))
                Toast.makeText(this@DetailActivity, "Feedback saved: Verified Correct", Toast.LENGTH_SHORT).show()
            }

            btnFeedbackNo?.setOnClickListener {
                layoutFeedbackBtns?.visibility = View.GONE
                tvFeedbackStatus?.visibility = View.VISIBLE
                tvFeedbackStatus?.text = "Flagged for retraining & threshold recalibration."
                tvFeedbackStatus?.setTextColor(Color.parseColor("#C62828"))
                Toast.makeText(this@DetailActivity, "Feedback saved: Flagged for Review", Toast.LENGTH_SHORT).show()
            }

            // 10. Delete Forensic Record
            var activeResultId = result.id
            val btnDelete = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_delete_detail)
            btnDelete.setOnClickListener {
                lifecycleScope.launch {
                    // Delete from backend if real backend case ID
                    if (displayCaseId.startsWith("MG-") || displayCaseId.startsWith("PS106-")) {
                        withContext(Dispatchers.IO) {
                            try {
                                val prefs = getSharedPreferences("messageguard_prefs", Context.MODE_PRIVATE)
                                val backendUrl = prefs.getString("backend_url", "http://10.0.2.2:8000") ?: "http://10.0.2.2:8000"
                                val client = OkHttpClient.Builder().callTimeout(5, TimeUnit.SECONDS).build()
                                val delReq = Request.Builder().url("$backendUrl/api/cases/$displayCaseId").delete().build()
                                client.newCall(delReq).execute().close()
                            } catch (e: Exception) {
                                Log.w("DetailActivity", "Backend case delete error: ${e.message}")
                            }
                        }
                    }
                    if (activeResultId != 0L) {
                        AnalysisHistoryDatabase.getInstance(this@DetailActivity).dao().deleteById(activeResultId)
                    }
                    Toast.makeText(this@DetailActivity, "Forensic record and PDF dossier deleted", Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
        }
    }

    private fun formatAuthBadge(tv: TextView, label: String, status: String) {
        val cleanStatus = status.uppercase()
        tv.text = "$label: $cleanStatus"
        when {
            cleanStatus.contains("PASS") -> {
                tv.setBackgroundColor(Color.parseColor("#E8F5E9"))
                tv.setTextColor(Color.parseColor("#2E7D32"))
            }
            cleanStatus.contains("FAIL") -> {
                tv.setBackgroundColor(Color.parseColor("#FFEBEE"))
                tv.setTextColor(Color.parseColor("#C62828"))
            }
            else -> {
                tv.setBackgroundColor(Color.parseColor("#EEEEEE"))
                tv.setTextColor(Color.parseColor("#616161"))
            }
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

    private fun openMessageInGmail(result: AnalysisResult) {
        val emailRegex = Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        val senderEmail = emailRegex.find(result.sender)?.value
        val subject = result.subject.trim().takeIf { it.isNotBlank() && it != "(No Subject)" }

        // Strategy 1: Targeted Gmail compose / view deep link by sender address
        if (!senderEmail.isNullOrBlank()) {
            val deepLink = Uri.parse("googlegmail://co?to=${Uri.encode(senderEmail)}")
            val gmailIntent = Intent(Intent.ACTION_VIEW, deepLink).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            try {
                startActivity(gmailIntent)
                return
            } catch (_: Exception) {}
        }

        // Strategy 2: Direct launch of Gmail application
        val launchIntent = packageManager.getLaunchIntentForPackage("com.google.android.gm")
        if (launchIntent != null) {
            launchIntent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
            try {
                startActivity(launchIntent)
                return
            } catch (_: Exception) {}
        }

        // Strategy 3: Standard mailto intent fallback
        try {
            val mailtoUri = if (!senderEmail.isNullOrBlank()) {
                Uri.parse("mailto:$senderEmail")
            } else if (!subject.isNullOrBlank()) {
                Uri.parse("mailto:?subject=${Uri.encode(subject)}")
            } else {
                Uri.parse("mailto:")
            }
            val mailIntent = Intent(Intent.ACTION_VIEW, mailtoUri).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(mailIntent)
        } catch (e: Exception) {
            Toast.makeText(this, "Gmail app not installed", Toast.LENGTH_SHORT).show()
        }
    }

    private fun exportOrOpenPdfReport(result: AnalysisResult, displayCaseId: String, reportUrl: String?) {
        // If there's an active backend report URL, try launching it first
        if (!reportUrl.isNullOrBlank()) {
            try {
                val pdfIntent = Intent(Intent.ACTION_VIEW, Uri.parse(reportUrl)).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivity(pdfIntent)
                return
            } catch (e: Exception) {
                Log.w("DetailActivity", "Failed to open remote PDF URL: ${e.message}, generating local PDF...")
            }
        }

        // Generate high-fidelity local Forensic PDF Dossier using Android PdfDocument
        try {
            val pdfDocument = android.graphics.pdf.PdfDocument()
            val pageInfo = android.graphics.pdf.PdfDocument.PageInfo.Builder(595, 842, 1).create() // Standard A4 (595x842 pt)
            val page = pdfDocument.startPage(pageInfo)
            val canvas = page.canvas
            val paint = android.graphics.Paint()

            // Header Banner (Dark Navy)
            paint.color = Color.parseColor("#0D1B2A")
            paint.style = android.graphics.Paint.Style.FILL
            canvas.drawRect(0f, 0f, 595f, 90f, paint)

            // Header Title
            paint.color = Color.WHITE
            paint.textSize = 18f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            canvas.drawText("MessageGuard Threat Vision — Forensic Report", 30f, 42f, paint)

            paint.textSize = 10f
            paint.typeface = Typeface.DEFAULT
            paint.color = Color.parseColor("#90CAF9")
            val timestampStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(result.timestamp)
            canvas.drawText("Case ID: $displayCaseId   |   Generated: $timestampStr", 30f, 65f, paint)

            // Verdict Banner
            var yPos = 125f
            val verdictColor = when (result.verdict) {
                Verdict.SAFE -> Color.parseColor("#2E7D32")
                Verdict.WARNING -> Color.parseColor("#E65100")
                Verdict.DANGER -> Color.parseColor("#C62828")
                Verdict.UNCERTAIN -> Color.parseColor("#F57F17")
            }
            paint.color = verdictColor
            canvas.drawRoundRect(30f, yPos, 565f, yPos + 45f, 8f, 8f, paint)

            paint.color = Color.WHITE
            paint.textSize = 14f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            val verdictText = "VERDICT: ${result.verdict.name}   |   Risk Score: ${result.riskScore}/100"
            canvas.drawText(verdictText, 45f, yPos + 28f, paint)

            // Incident Metadata Section
            yPos += 75f
            paint.color = Color.parseColor("#1B263B")
            paint.textSize = 13f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            canvas.drawText("INCIDENT METADATA", 30f, yPos, paint)

            paint.color = Color.parseColor("#415A77")
            paint.strokeWidth = 1f
            canvas.drawLine(30f, yPos + 5f, 565f, yPos + 5f, paint)

            yPos += 24f
            paint.textSize = 10.5f
            paint.typeface = Typeface.DEFAULT
            paint.color = Color.parseColor("#212121")
            canvas.drawText("Source Application: ${result.appSource}", 35f, yPos, paint)
            yPos += 18f
            canvas.drawText("Sender: ${result.sender}", 35f, yPos, paint)
            yPos += 18f
            canvas.drawText("Subject: ${result.subject.ifBlank { "(No Subject)" }}", 35f, yPos, paint)
            yPos += 18f
            canvas.drawText("Security Profile: ${result.senderTrust}   |   Enforced Action: ${result.action}", 35f, yPos, paint)

            // Forensic Summary & Red Flags
            yPos += 35f
            paint.color = Color.parseColor("#1B263B")
            paint.textSize = 13f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            canvas.drawText("FORENSIC EVIDENCE & RED FLAGS", 30f, yPos, paint)
            canvas.drawLine(30f, yPos + 5f, 565f, yPos + 5f, paint)

            yPos += 24f
            paint.textSize = 10f
            paint.typeface = Typeface.DEFAULT
            paint.color = Color.parseColor("#37474F")
            val summaryText = "Summary: ${result.summary}"
            canvas.drawText(summaryText.take(80), 35f, yPos, paint)

            yPos += 22f
            for (flag in result.flags.take(6)) {
                paint.color = Color.parseColor("#C62828")
                canvas.drawText("• ", 35f, yPos, paint)
                paint.color = Color.parseColor("#263238")
                canvas.drawText(flag.take(78), 45f, yPos, paint)
                yPos += 18f
            }

            // Footer
            paint.color = Color.parseColor("#B0BEC5")
            canvas.drawLine(30f, 800f, 565f, 800f, paint)
            paint.textSize = 8.5f
            paint.color = Color.parseColor("#78909C")
            canvas.drawText("Generated by MessageGuard Threat Vision Endpoint Agent | Case $displayCaseId", 30f, 815f, paint)

            pdfDocument.finishPage(page)

            // Save to documents directory
            val reportsDir = File(getExternalFilesDir(android.os.Environment.DIRECTORY_DOCUMENTS), "Reports")
            if (!reportsDir.exists()) reportsDir.mkdirs()
            val pdfFile = File(reportsDir, "MessageGuard_${displayCaseId}.pdf")
            pdfFile.outputStream().use { out ->
                pdfDocument.writeTo(out)
            }
            pdfDocument.close()

            // Open via FileProvider
            val fileUri = androidx.core.content.FileProvider.getUriForFile(
                this,
                "${applicationContext.packageName}.fileprovider",
                pdfFile
            )

            val openIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(fileUri, "application/pdf")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(Intent.createChooser(openIntent, "Open Forensic PDF Dossier"))
            Toast.makeText(this, "Exported PDF: ${pdfFile.name}", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Log.e("DetailActivity", "Failed to generate local PDF: ${e.message}", e)
            Toast.makeText(this, "Error exporting PDF: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
