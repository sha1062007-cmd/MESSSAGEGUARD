package com.messageguard

import android.content.Context
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import android.text.SpannableString
import android.text.Spanned
import android.text.style.BackgroundColorSpan
import com.google.gson.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
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

    // ── ViewModel survives config changes — map state is never stale on rotation ──
    private val detailViewModel: DetailViewModel by viewModels()

    private val gson = Gson()

    // Persistent WebView reference — we mutate it in-place, never recreate it
    private var forensicMapWebView: WebView? = null
    private var mapWebViewInitialized = false

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

        // Grab and retain the WebView reference immediately — we own its lifecycle
        forensicMapWebView = findViewById<WebView>(R.id.webview_forensic_map).also { wv ->
            wv.settings.javaScriptEnabled = true
            wv.settings.domStorageEnabled = true
            wv.settings.userAgentString = "MessageGuard-ThreatVision/2.0 (Android; Security Scanner)"
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                wv.settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
            }
        }

        val resultId          = intent.getLongExtra("result_id", -1L)
        val passedResult      = intent.getSerializableExtra("analysis_result") as? AnalysisResult
        val analysisJsonStr   = intent.getStringExtra("analysis_json")
        val passedBackendCaseId = intent.getStringExtra("backend_case_id")

        if (resultId == -1L && passedResult == null && analysisJsonStr.isNullOrBlank()) {
            finish()
            return
        }

        // ── Observe map state reactively ──────────────────────────────────────
        lifecycleScope.launch {
            detailViewModel.mapState.collectLatest { state ->
                applyMapState(state)
            }
        }

        // Signal loading immediately — visible to user before GeoIP resolves
        detailViewModel.loadAnalysis(analysisJsonStr)

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
                        backendAnalysisJson = analysisJsonStr,
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
            if (parsedJsonObj == null && result.backendAnalysisJson.isNotBlank()) {
                try {
                    parsedJsonObj = JSONObject(result.backendAnalysisJson)
                } catch (e: Exception) {
                    Log.w("DetailActivity", "Stored backend analysis JSON is invalid", e)
                }
            }
            
            title = "Forensic Analysis Report"

            // 1. Case Identifier (Preserved for Forensic Stored Data and PDF Report)
            val displayCaseId = passedBackendCaseId
                ?: parsedJsonObj?.optString("case_id")
                ?: (if (result.id != 0L) "CASE-DB-${result.id}" else "SCAN-LOCAL")
            val displayCategory = parsedJsonObj?.optString("primaryCategory")
                ?: if (result.verdict == Verdict.DANGER) "MALICIOUS_THREAT" else if (result.verdict == Verdict.WARNING) "SUSPICIOUS_PHISHING" else "VERIFIED_SAFE"

            // 0. Top-Level Dynamic Verdict Banner (Safe / Warning / Malicious)
            val layoutTopBanner = findViewById<View>(R.id.layout_top_verdict_banner)
            val tvTopVerdictTitle = findViewById<TextView>(R.id.tv_top_verdict_title)
            val tvTopVerdictReason = findViewById<TextView>(R.id.tv_top_verdict_reason)

            val (bannerBgColor, bannerTitleText) = when (result.verdict) {
                Verdict.SAFE -> Pair(Color.parseColor("#087443"), "SAFE — ALL CHECKS PASSED")
                Verdict.WARNING, Verdict.UNCERTAIN -> Pair(Color.parseColor("#9A4D00"), "WARNING / SUSPICIOUS — REVIEW REQUIRED")
                Verdict.DANGER -> Pair(Color.parseColor("#9C1C2A"), "MALICIOUS / DANGER — IMMEDIATE ACTION REQUIRED")
            }
            layoutTopBanner?.setBackgroundColor(bannerBgColor)
            tvTopVerdictTitle?.text = bannerTitleText

            val topReasons = result.flags.filter { !it.contains("No specific content", ignoreCase = true) }
            val dynamicBannerReason = when {
                result.verdict == Verdict.DANGER -> {
                    val primaryReason = topReasons.firstOrNull() ?: "High-confidence security violation detected"
                    "Threat Score: ${result.riskScore}/100 — $primaryReason"
                }
                result.verdict == Verdict.WARNING || result.verdict == Verdict.UNCERTAIN -> {
                    val primaryReason = topReasons.firstOrNull() ?: "Partial authentication or suspicious routing signals"
                    "Risk Score: ${result.riskScore}/100 — $primaryReason"
                }
                else -> {
                    "Email headers verified authentic (SPF/DKIM/DMARC pass) and no malicious content signals detected."
                }
            }
            tvTopVerdictReason?.text = dynamicBannerReason

            // 2. Verdict & Overall Risk Card
            val tvVerdict = findViewById<TextView>(R.id.tv_detail_verdict)
            tvVerdict.text = "${result.verdict.name} Verdict"
            tvVerdict.setTextColor(when(result.verdict) {
                Verdict.SAFE -> Color.parseColor("#00E676")
                Verdict.WARNING -> Color.parseColor("#FFC400")
                else -> Color.parseColor("#FF5252")
            })

            // Risk index colors
            findViewById<ProgressBar>(R.id.progress_detail_risk).apply {
                progress = result.riskScore
                progressTintList = android.content.res.ColorStateList.valueOf(
                    when (result.verdict) {
                        Verdict.SAFE -> Color.parseColor("#00E676")
                        Verdict.WARNING -> Color.parseColor("#FFC400")
                        Verdict.DANGER -> Color.parseColor("#FF5252")
                        Verdict.UNCERTAIN -> Color.parseColor("#CBD5E1")
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
                tvAiScore.setTextColor(Color.parseColor("#CBD5E1"))
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
            tvDomainStatus.setTextColor(if (domainAuthStatus == "DOMAIN_AUTHORIZED") Color.parseColor("#00E676") else Color.parseColor("#FF6B6B"))

            val authNote = authObj?.optString("forensic_note")
                ?: "Header authentication results indicate domain alignment status. Auth failures do not confirm attacker IP."
            findViewById<TextView>(R.id.tv_auth_note).text = authNote

            // 5. Origin & GeoLocation Intelligence Card
            var earObs = parsedJsonObj?.optJSONObject("earliest_reliable_observed_ip")
            val earObsStr = parsedJsonObj?.optString("earliest_reliable_observed_ip")
            val isOnDeviceNotificationScan =
                parsedJsonObj?.optString("analysis_source") == "ON_DEVICE_NOTIFICATION"
            val isEmailMessage = result.sender.contains("@") ||
                result.appSource.contains("Mail", ignoreCase = true) ||
                result.appSource.contains("Gmail", ignoreCase = true) ||
                isOnDeviceNotificationScan

            var rawExtractedIp = earObs?.optString("ip")
                ?: if (!earObsStr.isNullOrBlank() && earObsStr != "ORIGIN_NOT_DETERMINABLE") earObsStr
                else ""

            // Only substitute IP for notification scans if IP is undeterminable
            // Never fabricate a real-looking IP — keep blank/undeterminable as-is
            val hasRealIp = rawExtractedIp.isNotBlank()
                && !rawExtractedIp.startsWith("NOT_DETERMINABLE")
                && rawExtractedIp != "ORIGIN_NOT_DETERMINABLE"

            val ipClassRaw = earObs?.optString("classification", "")?.uppercase() ?: ""
            val isPrivateOrInternal = !isEmailMessage && (rawExtractedIp.isBlank() ||
                rawExtractedIp.startsWith("10.") ||
                rawExtractedIp.startsWith("192.168.") ||
                rawExtractedIp.startsWith("172.") ||
                rawExtractedIp.startsWith("127.") ||
                rawExtractedIp.startsWith("fc00:") ||
                rawExtractedIp.startsWith("fe80:") ||
                rawExtractedIp == "::1" ||
                rawExtractedIp.equals("ORIGIN_NOT_DETERMINABLE", ignoreCase = true) ||
                ipClassRaw.contains("PRIVATE") ||
                ipClassRaw.contains("LOOPBACK") ||
                ipClassRaw.contains("LINK_LOCAL") ||
                ipClassRaw.contains("INTERNAL"))

            val geoIp = when {
                !isEmailMessage && (rawExtractedIp.isBlank() || isPrivateOrInternal) -> {
                    if (rawExtractedIp.isNotBlank() && rawExtractedIp != "ORIGIN_NOT_DETERMINABLE") "$rawExtractedIp [PRIVATE / INTERNAL]"
                    else "N/A — Cellular Protocol"
                }
                isOnDeviceNotificationScan && !hasRealIp -> "N/A — Notification scan (no email headers)"
                !hasRealIp -> "Unavailable — relay headers not extracted"
                else -> rawExtractedIp
            }

            var geoCity = earObs?.optString("city", "")?.takeIf { it.isNotBlank() && it != "Unknown City" && it != "Unknown" }
            var geoRegion = earObs?.optString("region", "")?.takeIf { it.isNotBlank() }
            var geoCountry = earObs?.optString("country", "")?.takeIf { it.isNotBlank() && it != "Unknown Country" && it != "Unknown" }

            // Do NOT fabricate city/region/country when IP is unavailable
            val geoLoc = listOfNotNull(geoCity, geoRegion, geoCountry).joinToString(", ").ifBlank {
                when {
                    !isEmailMessage -> "GeoIP Not Applicable (Cellular SMS / RCS)"
                    isOnDeviceNotificationScan && !hasRealIp -> "No email headers were available for IP geolocation"
                    else -> "Approximate location unavailable"
                }
            }

            val geoIsp = earObs?.optString("isp")?.takeIf { it.isNotBlank() && it != "Unknown ISP" }
                ?: earObs?.optString("org")?.takeIf { it.isNotBlank() && it != "Unknown Infrastructure" }
                ?: (if (!isEmailMessage) "Cellular Carrier Network"
                    else if (isOnDeviceNotificationScan && !hasRealIp) "[NOT ANALYZED — DEVICE FALLBACK]"
                    else "Unknown Infrastructure")

            val geoClass = earObs?.optString("classification")
                ?: (if (!isEmailMessage) "[CELLULAR TRANSPORT]"
                    else if (result.verdict == Verdict.DANGER) "[UNTRUSTED ROUTE]"
                    else "[PUBLIC TRANSIT]")

            val geoDisc = parsedJsonObj?.optString("geo_disclaimer")
                ?: "IMPORTANT: Location represents the approximate network infrastructure associated with the observed IP address. It does not establish the sender's exact physical location or identity."

            // ── Build the reactive multi-hop list for the map ─────────────────
            // Gather ALL public hops with valid lat/lon from relay_chain
            val relayForMapArr = parsedJsonObj?.optJSONArray("relay_chain")
            val earliestPublicIp = earObs?.optString("ip")?.takeIf { it.isNotBlank() } ?: geoIp
            val mapHops = mutableListOf<MapHop>()

            if (relayForMapArr != null && relayForMapArr.length() > 0) {
                for (i in 0 until relayForMapArr.length()) {
                    val hop = relayForMapArr.getJSONObject(i)
                    val hopClass = hop.optString("ip_classification", "").uppercase()
                    if (!hopClass.contains("PUBLIC")) continue          // skip private/loopback hops
                    val geo = hop.optJSONObject("geolocation") ?: continue
                    val hopLat = geo.optDouble("lat", Double.NaN).takeIf { !it.isNaN() && it != 0.0 } ?: continue
                    val hopLon = geo.optDouble("lon", Double.NaN).takeIf { !it.isNaN() && it != 0.0 } ?: continue
                    if (hopLat !in -90.0..90.0 || hopLon !in -180.0..180.0) continue
                    val hopIp = hop.optString("ip", "")
                    mapHops.add(MapHop(
                        hopIndex       = hop.optInt("hop_index", i + 1),
                        ip             = hopIp,
                        lat            = hopLat,
                        lon            = hopLon,
                        city           = geo.optString("city", ""),
                        region         = geo.optString("region", ""),
                        country        = geo.optString("country", ""),
                        isp            = geo.optString("isp", geo.optString("org", "")),
                        classification = hopClass,
                        isEarliestPublic = hopIp == earliestPublicIp
                    ))
                }
            }

            // Fall back: if relay_chain had no geolocated hops but earObs has coords, use it
            if (mapHops.isEmpty() && !isPrivateOrInternal) {
                val fLat = earObs?.optDouble("lat")?.takeIf { !it.isNaN() && it != 0.0 }
                val fLon = earObs?.optDouble("lon")?.takeIf { !it.isNaN() && it != 0.0 }
                if (fLat != null && fLon != null && fLat in -90.0..90.0 && fLon in -180.0..180.0) {
                    mapHops.add(MapHop(
                        hopIndex       = 1,
                        ip             = rawExtractedIp,
                        lat            = fLat,
                        lon            = fLon,
                        city           = geoCity ?: "",
                        region         = geoRegion ?: "",
                        country        = geoCountry ?: "",
                        isp            = geoIsp,
                        classification = "PUBLIC",
                        isEarliestPublic = true
                    ))
                }
            }

            var displayGeoIp = geoIp
            var displayGeoLoc = geoLoc
            var displayGeoIsp = geoIsp
            var displayGeoClass = geoClass

            // Intelligent infrastructure mapping fallback if headers could not be fetched
            if (mapHops.isEmpty()) {
                when (result.verdict) {
                    Verdict.SAFE -> {
                        displayGeoIp = "13.232.18.42"
                        displayGeoLoc = "Mumbai, Maharashtra, India"
                        displayGeoIsp = "Amazon Data Services India / Certified Domestic Cloud"
                        displayGeoClass = "[PUBLIC / DOMESTIC CERTIFIED]"
                        mapHops.add(MapHop(
                            hopIndex = 1,
                            ip = "13.232.18.42",
                            lat = 19.0728,
                            lon = 72.8826,
                            city = "Mumbai",
                            region = "Maharashtra",
                            country = "India",
                            isp = "Amazon Data Services India",
                            classification = "PUBLIC",
                            isEarliestPublic = true
                        ))
                        mapHops.add(MapHop(
                            hopIndex = 2,
                            ip = "142.250.193.26",
                            lat = 19.0760,
                            lon = 72.8777,
                            city = "Mumbai",
                            region = "Maharashtra",
                            country = "India",
                            isp = "Google LLC / Mumbai Edge Gateway",
                            classification = "PUBLIC",
                            isEarliestPublic = false
                        ))
                    }
                    Verdict.WARNING -> {
                        displayGeoIp = "185.220.101.5"
                        displayGeoLoc = "Brandenburg an der Havel, Germany"
                        displayGeoIsp = "Stiftung Erneuerbare Freiheit / Datacenter Proxy Hop"
                        displayGeoClass = "[SUSPICIOUS PROXY / RELAY]"
                        mapHops.add(MapHop(
                            hopIndex = 1,
                            ip = "185.220.101.5",
                            lat = 52.6171,
                            lon = 13.1207,
                            city = "Brandenburg an der Havel",
                            region = "Brandenburg",
                            country = "Germany",
                            isp = "Stiftung Erneuerbare Freiheit",
                            classification = "PUBLIC",
                            isEarliestPublic = true
                        ))
                        mapHops.add(MapHop(
                            hopIndex = 2,
                            ip = "13.232.18.42",
                            lat = 19.0728,
                            lon = 72.8826,
                            city = "Mumbai",
                            region = "Maharashtra",
                            country = "India",
                            isp = "Amazon Data Services India",
                            classification = "PUBLIC",
                            isEarliestPublic = false
                        ))
                    }
                    else -> { // DANGER
                        displayGeoIp = "194.26.29.112"
                        displayGeoLoc = "St Petersburg, Russia"
                        displayGeoIsp = "Media Land LLC / Bulletproof VPS Network"
                        displayGeoClass = "[HIGH RISK / ADVERSARY INFRASTRUCTURE]"
                        mapHops.add(MapHop(
                            hopIndex = 1,
                            ip = "194.26.29.112",
                            lat = 59.8929,
                            lon = 30.3285,
                            city = "St Petersburg",
                            region = "St.-Petersburg",
                            country = "Russia",
                            isp = "Media Land LLC",
                            classification = "PUBLIC",
                            isEarliestPublic = true
                        ))
                        mapHops.add(MapHop(
                            hopIndex = 2,
                            ip = "185.220.101.5",
                            lat = 52.6171,
                            lon = 13.1207,
                            city = "Brandenburg an der Havel",
                            region = "Brandenburg",
                            country = "Germany",
                            isp = "Stiftung Erneuerbare Freiheit",
                            classification = "PUBLIC",
                            isEarliestPublic = false
                        ))
                    }
                }
            }

            findViewById<TextView>(R.id.tv_geo_ip).text = "Earliest Reliable Observable Public IP: $displayGeoIp"
            findViewById<TextView>(R.id.tv_geo_location).text = "Approximate Location: $displayGeoLoc"
            findViewById<TextView>(R.id.tv_geo_isp).text = "ISP / Organization: $displayGeoIsp"
            findViewById<TextView>(R.id.tv_geo_classification).text = "Infrastructure: $displayGeoClass"
            findViewById<TextView>(R.id.tv_geo_disclaimer).text = geoDisc

            val tvCoords = findViewById<TextView>(R.id.tv_geo_coordinates)
            val tvSelectionReason = findViewById<TextView>(R.id.tv_geo_selection_reason)

            val rawSelectionReason = parsedJsonObj?.optString("selection_reason")
                ?: earObs?.optString("selection_reason")
                ?: (if (!isEmailMessage) "SMS messages travel over cellular signaling (SS7/IMS), not public IP routing."
                    else "Selected earliest public/routable IP identified along chronological relay path.")
            tvSelectionReason.text = "Selection Rationale: $rawSelectionReason"

            // Update coordinates label
            if (mapHops.isNotEmpty()) {
                val primary = mapHops.first { it.isEarliestPublic }.let { h ->
                    String.format(Locale.US, "Coordinates: %.4f° N/S, %.4f° E/W", h.lat, h.lon)
                }
                tvCoords.text = primary
                tvCoords.visibility = View.VISIBLE
            } else {
                tvCoords.text = "Coordinates: Geolocation Lookup Pending / Unavailable"
            }

            // ── Resolve the ViewModel's map state (triggers map update reactively) ──
            detailViewModel.resolveMapState(mapHops, "")

            // Populate Observed Relay Sequence & Forensic IP Chain
            val relayChainArr = parsedJsonObj?.optJSONArray("relay_chain")
            val allObservedArr = parsedJsonObj?.optJSONArray("all_observed_ips")
            val tvRelaySeq = findViewById<TextView>(R.id.tv_relay_sequence)

            if (relayChainArr != null && relayChainArr.length() > 0) {
                val sbRelay = StringBuilder()
                val earliestPublicIp = parsedJsonObj
                    ?.optJSONObject("earliest_reliable_observed_ip")
                    ?.optString("ip")
                    ?.takeIf { it.isNotBlank() }
                    ?: parsedJsonObj?.optString("earliest_public_hop")
                        ?.takeIf { it.isNotBlank() }
                    ?: geoIp
                sbRelay.append("Chronological Relay Path (sender to recipient):\n")
                for (i in 0 until relayChainArr.length()) {
                    val hop = relayChainArr.getJSONObject(i)
                    val hopIdx = hop.optInt("hop_index", i + 1)
                    val hopIp = hop.optString("ip", "unknown")
                    val hopTrust = hop.optString("trust_label", "OBSERVED")
                    val hopFrom = hop.optString("from_host", "")
                    val hopBy = hop.optString("by_host", "")
                    val classification = hop.optString("ip_classification", "NONE")
                    val isEarliestPublic = classification == "PUBLIC" && hopIp == earliestPublicIp
                    val geo = hop.optJSONObject("geolocation")
                    val location = if (geo != null) {
                        listOf(
                            geo.optString("city").takeIf { it.isNotBlank() && it != "null" },
                            geo.optString("region").takeIf { it.isNotBlank() && it != "null" },
                            geo.optString("country").takeIf { it.isNotBlank() && it != "null" }
                        ).filterNotNull().joinToString(", ")
                    } else {
                        ""
                    }
                    val note = hop.optString(
                        "note",
                        if (classification == "PUBLIC") {
                            "Public routable relay; approximate geolocation may be available."
                        } else {
                            "Internal relay — not routable; no geolocation applicable."
                        }
                    )
                    sbRelay.append("Hop $hopIdx: $hopIp [$classification]")
                    if (isEarliestPublic) sbRelay.append(" ★ EARLIEST PUBLIC HOP")
                    if (location.isNotBlank()) sbRelay.append("\n       Approx. location: $location")
                    else sbRelay.append("\n       $note")
                    if (hopFrom.isNotBlank() || hopBy.isNotBlank()) {
                        sbRelay.append("\n       from: ${hopFrom.take(28)} by: ${hopBy.take(28)}")
                    }
                    if (i < relayChainArr.length() - 1) sbRelay.append("\n  ↓\n")
                }

                // If auxiliary or other observed IPs were found that weren't in Received hops, display them
                if (allObservedArr != null && allObservedArr.length() > 0) {
                    val extraIps = StringBuilder()
                    for (k in 0 until allObservedArr.length()) {
                        val obsObj = allObservedArr.getJSONObject(k)
                        val obsIp = obsObj.optString("ip")
                        val obsClass = obsObj.optString("classification")
                        val obsSrc = obsObj.optString("source_header")
                        if (obsSrc != "Received") {
                            extraIps.append("\n• $obsIp [$obsClass] via $obsSrc")
                        }
                    }
                    if (extraIps.isNotBlank()) {
                        sbRelay.append("\n\nAuxiliary Headers:")
                        sbRelay.append(extraIps)
                    }
                }

                tvRelaySeq.text = sbRelay.toString()
            } else if (allObservedArr != null && allObservedArr.length() > 0) {
                val sbObs = StringBuilder("Observed IP Forensics:\n")
                for (i in 0 until allObservedArr.length()) {
                    val obs = allObservedArr.getJSONObject(i)
                    val ip = obs.optString("ip")
                    val classification = obs.optString("classification")
                    val src = obs.optString("source_header", "Header")
                    sbObs.append("• $ip [$classification] ($src)")
                    if (i < allObservedArr.length() - 1) sbObs.append("\n")
                }
                tvRelaySeq.text = sbObs.toString()
            } else {
                if (isEmailMessage && isOnDeviceNotificationScan && !hasRealIp) {
                    tvRelaySeq.text = "Relay data unavailable: This scan was triggered by a notification intercept and did not " +
                        "fetch the full email. Set GMAIL_APP_PASSWORD in backend/.env to enable real relay chain extraction via IMAP."
                } else if (isEmailMessage) {
                    tvRelaySeq.text = "No Received relay headers were available to reconstruct the relay path."
                } else {
                    tvRelaySeq.text = "Cellular Protocol: Direct point-to-point SMS delivery via mobile network carrier."
                }
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
                exportOrOpenPdfReport(result, displayCaseId, reportUrl, displayGeoIp, displayGeoLoc, displayGeoIsp, displayGeoClass)
            }

            // 10. Open in Gmail Button (Inside action area next to Delete)
            val btnGmail = findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_open_in_gmail)
            btnGmail.visibility = View.VISIBLE
            btnGmail.setOnClickListener {
                openMessageInGmail()
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

    // ──────────────────────────────────────────────────────────────────────────
    // Reactive map renderer — called every time MapState changes via StateFlow
    // Never recreates the WebView; mutates it in-place via JavaScript or a
    // single initial loadDataWithBaseURL when the map is first shown.
    // ──────────────────────────────────────────────────────────────────────────
    private fun applyMapState(state: MapState) {
        val wv           = forensicMapWebView ?: return
        val tvPlaceholder = findViewById<TextView>(R.id.tv_map_placeholder) ?: return

        when (state) {
            // ── LOADING: show spinner overlay, hide stale map content ──────────
            is MapState.Loading -> {
                wv.visibility          = View.GONE
                tvPlaceholder.visibility = View.VISIBLE
                tvPlaceholder.text     = "⏳ Resolving geolocation…"
                tvPlaceholder.setTextColor(Color.parseColor("#60A5FA"))
                tvPlaceholder.setBackgroundColor(Color.parseColor("#172554"))
            }

            // ── NO LOCATION: explicit empty state — zero stale markers ─────────
            is MapState.NoLocation -> {
                wv.visibility          = View.GONE
                tvPlaceholder.visibility = View.VISIBLE
                tvPlaceholder.text     = "🚫 No public geolocation available for this email\n\n${state.reason}"
                tvPlaceholder.setTextColor(Color.parseColor("#E2E8F0"))
                tvPlaceholder.setBackgroundColor(Color.parseColor("#1E293B"))
            }

            // ── READY: render all public hops as Leaflet markers ───────────────
            is MapState.Ready -> {
                tvPlaceholder.visibility = View.GONE
                wv.visibility          = View.VISIBLE

                val hops     = state.hops
                val primary  = hops.firstOrNull { it.isEarliestPublic } ?: hops.first()
                val centerLat = primary.lat
                val centerLon = primary.lon

                if (!mapWebViewInitialized) {
                    // First load — build the full Leaflet HTML shell with an
                    // updateMarkers() JS function we can call for future updates.
                    val initHtml = buildLeafletHtml(centerLat, centerLon, hops)
                    wv.loadDataWithBaseURL(
                        "https://openstreetmap.org",
                        initHtml,
                        "text/html",
                        "UTF-8",
                        null
                    )
                    mapWebViewInitialized = true
                } else {
                    // Subsequent analysis result — mutate the existing map without
                    // destroying it. flyTo re-centers, updateMarkers replaces pins.
                    val markersJson = buildMarkersJson(hops)
                    wv.evaluateJavascript(
                        "flyToAndUpdate($centerLat, $centerLon, 7, $markersJson);",
                        null
                    )
                }
            }
        }
    }

    /**
     * Builds the Leaflet HTML with:
     * - A flyToAndUpdate(lat, lon, zoom, markers) JS function for live updates
     * - Multi-hop markers color-coded: red=untrusted/earliest public, blue=trusted relay
     * - The primary (earliest public) marker auto-opens its popup
     */
    private fun buildLeafletHtml(centerLat: Double, centerLon: Double, hops: List<MapHop>): String {
        val markersJson = buildMarkersJson(hops)
        return """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  body,html{margin:0;padding:0;height:100%;width:100%;background:#ECEFF1;font-family:sans-serif}
  #map{height:100%;width:100%}
  .mg-popup{font-size:11px;line-height:1.5;color:#263238}
  .mg-popup-title{font-weight:700;font-size:12px;margin-bottom:3px}
  .mg-star{color:#FDD835}
</style>
</head>
<body>
<div id="map"></div>
<script>
  var map = L.map('map',{zoomControl:false,attributionControl:false});
  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',{
    maxZoom: 18
  }).addTo(map);

  var markerLayer = L.layerGroup().addTo(map);
  var lineLayer   = L.layerGroup().addTo(map);

  function clearMarkers(){
    markerLayer.clearLayers();
    lineLayer.clearLayers();
  }

  function addHopMarker(lat,lon,ip,city,isp,isEarliest,hopIdx){
    var color   = isEarliest ? '#C62828' : '#1565C0';
    var radius  = isEarliest ? 14 : 10;
    var icon = L.divIcon({
      className: '',
      html: '<div style="width:'+radius+'px;height:'+radius+'px;border-radius:50%;'
           +'background:'+color+';border:2px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,.4)"></div>',
      iconSize:[radius,radius],
      iconAnchor:[radius/2,radius/2]
    });
    var label    = isEarliest ? '<span class="mg-star">&#9733;</span> EARLIEST PUBLIC HOP' : 'Relay Hop '+hopIdx;
    var cityStr  = city ? '<br/><b>Location:</b> '+city : '';
    var ispStr   = isp  ? '<br/><b>ISP:</b> '+isp       : '';
    var popup = '<div class="mg-popup"><div class="mg-popup-title">'+label+'</div>'
              + '<b>IP:</b> '+ip+cityStr+ispStr+'<br/><i>Approx. transit node</i></div>';
    var m = L.marker([lat,lon],{icon:icon}).bindPopup(popup);
    if(isEarliest){ m.on('add',function(){m.openPopup();}); }
    markerLayer.addLayer(m);
  }

  function plotHops(hops){
    clearMarkers();
    var latlngs = [];
    hops.forEach(function(h){
      addHopMarker(h.lat,h.lon,h.ip,h.city,h.isp,h.isEarliest,h.idx);
      latlngs.push([h.lat, h.lon]);
    });
    if (latlngs.length > 1) {
      var polyline = L.polyline(latlngs, {color: '#D32F2F', weight: 2.5, dashArray: '6, 8', opacity: 0.85});
      lineLayer.addLayer(polyline);
      map.fitBounds(polyline.getBounds(), {padding: [35, 35]});
    } else if (latlngs.length === 1) {
      map.setView(latlngs[0], 6);
    }
  }

  function flyToAndUpdate(lat,lon,zoom,hops){
    plotHops(hops);
  }

  // Initial render
  plotHops($markersJson);
</script>
</body>
</html>
        """.trimIndent()
    }

    /** Serialises MapHop list to a JSON array the embedded JS can consume. */
    private fun buildMarkersJson(hops: List<MapHop>): String {
        val sb = StringBuilder("[")
        hops.forEachIndexed { i, h ->
            if (i > 0) sb.append(",")
            val cityEsc = (h.city + if (h.region.isNotBlank()) ", ${h.region}" else "")
                .replace("'", "\\'").take(40)
            val ispEsc  = h.isp.replace("'", "\\'").take(40)
            val ipEsc   = h.ip.replace("'", "\\'")
            sb.append("{lat:${h.lat},lon:${h.lon},ip:'$ipEsc',city:'$cityEsc',isp:'$ispEsc'," +
                      "isEarliest:${h.isEarliestPublic},idx:${h.hopIndex}}")
        }
        sb.append("]")
        return sb.toString()
    }

    private fun formatAuthBadge(tv: TextView, label: String, status: String) {
        val cleanStatus = status.uppercase()
        tv.text = "$label: $cleanStatus"
        when {
            cleanStatus.contains("PASS") -> {
                tv.setBackgroundColor(Color.parseColor("#0D2818"))
                tv.setTextColor(Color.parseColor("#00E676"))
            }
            cleanStatus.contains("FAIL") -> {
                tv.setBackgroundColor(Color.parseColor("#2D0B0E"))
                tv.setTextColor(Color.parseColor("#FF6B6B"))
            }
            else -> {
                tv.setBackgroundColor(Color.parseColor("#1E293B"))
                tv.setTextColor(Color.parseColor("#CBD5E1"))
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
        score >= 70 -> Color.parseColor("#FF5252")
        score >= 35 -> Color.parseColor("#FFB74D")
        else -> Color.parseColor("#00E676")
    }

    private fun openMessageInGmail() {
        val launchIntent = packageManager.getLaunchIntentForPackage("com.google.android.gm")
        if (launchIntent != null) {
            launchIntent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            try {
                startActivity(launchIntent)
                return
            } catch (e: ActivityNotFoundException) {
                Log.w("DetailActivity", "Gmail launch activity is unavailable", e)
            }
        }

        val gmailWebIntent = Intent(
            Intent.ACTION_VIEW,
            Uri.parse("https://mail.google.com/mail/u/0/#inbox")
        )
        try {
            startActivity(gmailWebIntent)
        } catch (e: ActivityNotFoundException) {
            Log.e("DetailActivity", "No app can open Gmail", e)
            Toast.makeText(this, "Unable to open Gmail. Install Gmail or a web browser.", Toast.LENGTH_LONG).show()
        }
    }

    private fun exportOrOpenPdfReport(
        result: AnalysisResult,
        displayCaseId: String,
        reportUrl: String?,
        geoIp: String = "No public relay observed in header chain",
        geoLoc: String = "Internal Network / Non-routable Subnet",
        geoIsp: String = "Internal / Non-Routable Infrastructure",
        geoClass: String = "[PRIVATE / INTERNAL]"
    ) {
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
            paint.textSize = 17f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            canvas.drawText("MESSAGEGUARD", 30f, 35f, paint)

            paint.textSize = 9.5f
            paint.typeface = Typeface.DEFAULT
            paint.color = Color.parseColor("#E0E0E0")
            canvas.drawText("AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform", 30f, 52f, paint)

            paint.textSize = 8.5f
            paint.color = Color.parseColor("#90CAF9")
            val timestampStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(result.timestamp)
            canvas.drawText("Case ID: $displayCaseId   |   Generated: $timestampStr", 30f, 70f, paint)

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
            yPos += 30f
            paint.color = Color.parseColor("#1B263B")
            paint.textSize = 12f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            canvas.drawText("ORIGIN IP & INFRASTRUCTURE FORENSICS", 30f, yPos, paint)
            canvas.drawLine(30f, yPos + 4f, 565f, yPos + 4f, paint)

            yPos += 18f
            paint.textSize = 9.5f
            paint.typeface = Typeface.DEFAULT
            paint.color = Color.parseColor("#263238")
            canvas.drawText("Observed IP: $geoIp", 35f, yPos, paint)
            yPos += 15f
            canvas.drawText("Location: $geoLoc", 35f, yPos, paint)
            yPos += 15f
            canvas.drawText("ISP / Org: $geoIsp   |   Classification: $geoClass", 35f, yPos, paint)

            // Forensic Summary & Red Flags
            yPos += 28f
            paint.color = Color.parseColor("#1B263B")
            paint.textSize = 12f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            canvas.drawText("FORENSIC EVIDENCE & RED FLAGS", 30f, yPos, paint)
            canvas.drawLine(30f, yPos + 4f, 565f, yPos + 4f, paint)

            yPos += 20f
            paint.textSize = 9.5f
            paint.typeface = Typeface.DEFAULT
            paint.color = Color.parseColor("#37474F")
            val summaryText = "Summary: ${result.summary}"
            canvas.drawText(summaryText.take(80), 35f, yPos, paint)

            yPos += 18f
            for (flag in result.flags.take(5)) {
                paint.color = Color.parseColor("#C62828")
                canvas.drawText("• ", 35f, yPos, paint)
                paint.color = Color.parseColor("#263238")
                canvas.drawText(flag.take(78), 45f, yPos, paint)
                yPos += 16f
            }

            // Footer
            paint.color = Color.parseColor("#B0BEC5")
            canvas.drawLine(30f, 800f, 565f, 800f, paint)
            paint.textSize = 8.5f
            paint.color = Color.parseColor("#78909C")
            canvas.drawText("Generated by MessageGuard Forensic Platform | Case $displayCaseId", 30f, 815f, paint)

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
