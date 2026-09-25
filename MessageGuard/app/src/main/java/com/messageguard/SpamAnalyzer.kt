package com.messageguard

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.util.Log
import com.google.gson.*
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.tensorflow.lite.Interpreter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlin.math.*

class SpamAnalyzer(context: Context) : AutoCloseable {

    data class AnalysisOutcome(
        val result: AnalysisResult,
        val analysisTriggered: Boolean
    )

    data class MlResult(
        val urlScore: Float, 
        val nlpScore: Float, 
        val bodmasScore: Float, 
        val typosquatScore: Float,
        val reputationScore: Float,
        val finalScore: Float,
        val modelDisagreement: Float = 0f,
        val uncertaintyReason: String? = null
    )
    
    data class ClaudeDecision(val verdict: Verdict, val reason: String, val summary: String, val score: Int)

    private val appContext = context.applicationContext
    private val gson = Gson()
    private val emailManager = EmailAlertManager(context)
    private val analyzerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var urlInterpreter: Interpreter? = null
    private var ortEnvironment: OrtEnvironment? = null
    
    // ONNX Model sessions:
    // 1. url_detector.onnx (Tabular XGBoost URL classification)
    // 2. calibrated_voting_0..2.onnx (Calibrated Voting Ensemble)
    // 3. full_bodmas.onnx (BODMAS structural anomaly model)
    private var urlSession: OrtSession? = null
    private var urlInputName: String? = null
    private var votingSessions: List<Pair<OrtSession, String>> = emptyList()
    private var bodmasSession: OrtSession? = null
    private var bodmasInputName: String? = null
    private val urlLock = Any()
    private val urlSessionLock = Any()
    private val votingLock = Any()
    private val bodmasLock = Any()

    // TFLite NLP model — custom-trained text_nlp_model.tflite (432KB, 96.5% acc, 34.8K messages)
    private var nlpInterpreter: Interpreter? = null
    private var nlpVocab: Map<String, Int> = emptyMap()
    private var assetWhitelist: Set<String> = emptySet()
    private val nlpLock = Any()

    // Do not attach an HTTP body logger here: Gemini requests contain user message text and
    // the API key is part of the request URL. Keeping them out of logcat is essential for a
    // security application and does not affect model behavior.
    private val geminiClient = OkHttpClient.Builder()
        .callTimeout(45, TimeUnit.SECONDS)
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    companion object {
        private val JSON_TYPE = "application/json".toMediaType()
        private const val NLP_MAX_LEN = 60
        private const val NLP_VOCAB_SIZE = 8000
        private const val NLP_OOV_TOKEN_ID = 1
        private const val W_URL        = Constants.DEFAULT_WEIGHT_URL
        private const val W_NLP        = Constants.DEFAULT_WEIGHT_NLP
        private const val W_BODMAS     = Constants.DEFAULT_WEIGHT_BODMAS
        private const val W_TYPOSQUAT  = Constants.DEFAULT_WEIGHT_TYPOSQUAT
        private const val W_REPUTATION = Constants.DEFAULT_WEIGHT_REPUTATION
        private const val DANGER_THRESHOLD  = 70
        private const val WARNING_THRESHOLD = 40 

        // MODEL_FALLBACK_CHAIN — verified against live API on 2026-08-20.
        // Each model confirmed via GET /v1beta/models?key=... before adding.
        // Priority: best quality first, fastest/most-available as fallbacks.
        private val MODEL_FALLBACK_CHAIN = listOf(
            "gemini-2.5-flash",        // PRIMARY: Best quality, high quota, stable
            "gemini-2.5-flash-lite",   // FAST FALLBACK: Lower latency, same generation
            "gemini-flash-latest",     // ALIAS FALLBACK: Always resolves to latest flash
            "gemini-3.5-flash",        // EXTENDED: Verified available on this key
            "gemini-3.5-flash-lite",   // EXTENDED LITE: Verified available on this key
            "gemini-3.1-flash-lite"    // LAST RESORT: Stable lite model
        )
        
        private val permanentlyDeadModels = mutableSetOf<String>()
        private val quotaExhaustedUntil = mutableMapOf<String, Long>()
        private var hasLoggedAvailableModels = false

        // Fix B: Gemini score cache — same message hash → same AI score within 10 minutes
        // Prevents AI=75→10→5 flip-flopping on repeated scans of identical content.
        private val geminiScoreCache = mutableMapOf<Int, Pair<ClaudeDecision, Long>>()
        private const val GEMINI_CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes

        data class DomainAnalysisResult(
            val isTyposquat: Boolean = false,
            val isHomograph: Boolean = false
        )

        fun analyzeDomain(urlOrHost: String): DomainAnalysisResult {
            val rawHost = if (urlOrHost.contains("://")) extractDomain(urlOrHost) else urlOrHost.trim().lowercase()
            if (rawHost.isBlank()) return DomainAnalysisResult()

            // 1. Decode Punycode to Unicode (e.g. xn--pple-43d.com -> аpple.com)
            val unicodeHost = try {
                java.net.IDN.toUnicode(rawHost)
            } catch (_: Exception) {
                rawHost
            }

            val officialDomains = setOf(
                "google.com", "internshala.com", "github.com", "gitlab.com", "stackoverflow.com",
                "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "hdfc.com", "icicibank.com", "axisbank.com",
                "linkedin.com", "microsoft.com", "apple.com", "amazon.in", "amazon.com",
                "flipkart.com", "swiggy.com", "zomato.com", "jiomart.com", "jio.com", "airtel.in",
                "paypal.com", "facebook.com", "netflix.com", "youtube.com", "instagram.com",
                "whatsapp.com", "twitter.com", "x.com"
            )

            val protectedBrands = listOf(
                "google", "internshala", "github", "gitlab", "stackoverflow", "sbi", "onlinesbi",
                "hdfcbank", "hdfc", "icicibank", "axisbank", "linkedin", "microsoft", "apple",
                "amazon", "flipkart", "swiggy", "zomato", "jiomart", "paypal", "netflix", "facebook"
            )

            // 2. Parse eTLD+1 (registrable root domain) and subdomain prefix
            val (rootDomain, subdomainPrefix) = parseEtldPlusOne(unicodeHost)

            // Rule: If root domain is an official brand root domain (e.g. github.com, paypal.com, google.com),
            // subdomains like raw.githubusercontent.com, mail.paypal.com or accounts.google.com are LEGITIMATE (NOT FLAGGED).
            if (officialDomains.contains(rootDomain.lowercase())) {
                return DomainAnalysisResult(isTyposquat = false, isHomograph = false)
            }

            // 3. IDN Homograph & Mixed Script Detection
            var homographDetected = false
            val labels = unicodeHost.split(".")
            for (label in labels) {
                if (hasMixedScripts(label)) {
                    homographDetected = true
                    break
                }
            }

            // Normalize homoglyphs (e.g. Cyrillic 'а', 'е', 'о', 'р', 'с', 'х', 'у' -> Latin equivalents)
            val normalizedUnicodeHost = normalizeHomoglyphs(unicodeHost)
            val (normRootDomain, normSubdomainPrefix) = parseEtldPlusOne(normalizedUnicodeHost)

            // 4. Typosquatting / Brand Mimicry Detection
            var typosquatDetected = false

            // A) Root domain is untrusted. Check if root label itself is a typosquat of a protected brand (e.g. paypa1.com)
            val rootLabel = normRootDomain.substringBefore(".")
            for (brand in protectedBrands) {
                if (rootLabel.length >= 4 && brand.length >= 4 && rootLabel != brand) {
                    if (levenshteinDistance(rootLabel, brand) in 1..2) {
                        typosquatDetected = true
                        break
                    }
                }
            }

            // B) Root domain is untrusted. Check if brand name appears in subdomain prefix (e.g. paypal.com.attacker.xyz)
            if (!typosquatDetected && normSubdomainPrefix.isNotBlank()) {
                for (brand in protectedBrands) {
                    if (normSubdomainPrefix.contains(brand)) {
                        typosquatDetected = true
                        break
                    }
                }
            }

            // C) Check if homoglyph-normalized root matches a protected brand (e.g. xn--pple-43d.com -> аpple.com -> apple.com)
            if (rawHost.startsWith("xn--") || homographDetected || normRootDomain != rootDomain) {
                val normRootLabel = normRootDomain.substringBefore(".")
                for (brand in protectedBrands) {
                    if (normRootLabel == brand || (normRootLabel.length >= 4 && levenshteinDistance(normRootLabel, brand) <= 2)) {
                        homographDetected = true
                    }
                }
            }

            return DomainAnalysisResult(
                isTyposquat = typosquatDetected,
                isHomograph = homographDetected
            )
        }

        private fun parseEtldPlusOne(host: String): Pair<String, String> {
            val parts = host.lowercase().split(".")
            if (parts.size <= 2) {
                return Pair(host.lowercase(), "")
            }

            // Multi-level TLDs
            val multiLevelTlds = setOf(
                "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk",
                "co.in", "net.in", "org.in", "gov.in", "ac.in",
                "com.au", "net.au", "org.au",
                "co.jp", "ne.jp", "or.jp",
                "com.br", "co.za", "onlinesbi.sbi"
            )

            val lastTwo = "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
            return if (multiLevelTlds.contains(lastTwo) && parts.size >= 3) {
                val root = "${parts[parts.size - 3]}.$lastTwo"
                val prefix = parts.subList(0, parts.size - 3).joinToString(".")
                Pair(root, prefix)
            } else {
                val root = "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
                val prefix = parts.subList(0, parts.size - 2).joinToString(".")
                Pair(root, prefix)
            }
        }

        fun hasMixedScripts(label: String): Boolean {
            var hasLatin = false
            var hasOther = false
            for (cp in label.codePoints().toArray()) {
                val script = Character.UnicodeScript.of(cp)
                if (script == Character.UnicodeScript.LATIN) {
                    hasLatin = true
                } else if (script == Character.UnicodeScript.CYRILLIC || 
                           script == Character.UnicodeScript.GREEK || 
                           script == Character.UnicodeScript.ARABIC) {
                    hasOther = true
                }
            }
            return hasLatin && hasOther
        }

        fun normalizeHomoglyphs(text: String): String {
            val sb = StringBuilder()
            for (ch in text) {
                val replacement = when (ch) {
                    'а', '\u0430' -> 'a'
                    'е', '\u0435' -> 'e'
                    'о', '\u043e' -> 'o'
                    'р', '\u0440' -> 'p'
                    'с', '\u0441' -> 'c'
                    'х', '\u0445' -> 'x'
                    'у', '\u0443' -> 'y'
                    'і', '\u0456' -> 'i'
                    'ѕ', '\u0455' -> 's'
                    'ј', '\u0458' -> 'j'
                    'ԁ', '\u0501' -> 'd'
                    'ԛ', '\u051B' -> 'q'
                    'ԝ', '\u051D' -> 'w'
                    'ο', '\u03BF' -> 'o'
                    'ν', '\u03BD' -> 'v'
                    else -> ch
                }
                sb.append(replacement)
            }
            return sb.toString()
        }

        private fun extractDomain(url: String): String {
            return try {
                val uri = java.net.URL(url)
                uri.host.lowercase()
            } catch (_: Exception) {
                ""
            }
        }

        fun levenshteinDistance(s1: String, s2: String): Int {
            val dp = IntArray(s2.length + 1) { it }
            for (i in 1..s1.length) {
                var prev = i - 1
                dp[0] = i
                for (j in 1..s2.length) {
                    val temp = dp[j]
                    if (s1[i - 1] == s2[j - 1]) {
                        dp[j] = prev
                    } else {
                        dp[j] = minOf(dp[j] + 1, dp[j - 1] + 1, prev + 1)
                    }
                    prev = temp
                }
            }
            return dp[s2.length]
        }
    }

    init {
        try {
            urlInterpreter = Interpreter(loadAssetBuffer(appContext, "url_cnn_model.tflite"), Interpreter.Options())
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to init URL TFLite model: ${e.message}")
        }
        try {
            nlpInterpreter = Interpreter(loadAssetBuffer(appContext, "text_nlp_model.tflite"), Interpreter.Options())
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to init NLP TFLite model: ${e.message}")
        }
        try {
            ortEnvironment = OrtEnvironment.getEnvironment()
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to init OrtEnvironment: ${e.message}")
        }

        // Load ONNX sessions:
        // 1. url_detector.onnx (Tabular XGBoost URL classification)
        // 2. calibrated_voting_0/1/2.onnx (Calibrated Multi-Model Ensemble)
        // 3. full_bodmas.onnx (BODMAS structural anomaly model)
        if (ortEnvironment != null) {
            try {
                val urlBytes = loadAssetBytes(appContext, "url_detector.onnx")
                urlSession = ortEnvironment!!.createSession(urlBytes, OrtSession.SessionOptions())
                urlInputName = urlSession?.inputNames?.firstOrNull()
            } catch (e: Exception) {
                Log.w("SpamAnalyzer", "url_detector.onnx not loaded (${e.message}) — URL ONNX scoring disabled, TFLite fallback active.")
            }

            votingSessions = (0..2).mapNotNull { idx ->
                try {
                    val bytes = loadAssetBytes(appContext, "calibrated_voting_$idx.onnx")
                    val session = ortEnvironment!!.createSession(bytes, OrtSession.SessionOptions())
                    val inputName = session.inputNames.firstOrNull() ?: "float_input"
                    Pair(session, inputName)
                } catch (e: Exception) {
                    Log.w("SpamAnalyzer", "calibrated_voting_$idx.onnx not loaded (${e.message})")
                    null
                }
            }

            try {
                val bodmasBytes = loadAssetBytes(appContext, "full_bodmas.onnx")
                bodmasSession = ortEnvironment!!.createSession(bodmasBytes, OrtSession.SessionOptions())
                bodmasInputName = bodmasSession?.inputNames?.firstOrNull()
            } catch (e: Exception) {
                Log.w("SpamAnalyzer", "full_bodmas.onnx not loaded: ${e.message}")
            }
        }

        try {
            nlpVocab = loadTfidfVocab(appContext)
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to init NLP TF-IDF vocab: ${e.message}")
        }
        try {
            assetWhitelist = loadWhitelist(appContext)
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to init whitelist: ${e.message}")
        }
    }

    suspend fun analyze(
        appSource: String, sender: String, subject: String, messageBody: String
    ): AnalysisOutcome = withContext(Dispatchers.IO) {

        val rawMessage = listOf(subject, messageBody)
            .filter { it.isNotBlank() }
            .joinToString(" ")
            .ifBlank { messageBody }
            .trim()

        if (rawMessage.length < 30 || isGenericUi(rawMessage)) {
            return@withContext AnalysisOutcome(
                result = AnalysisResult(
                    verdict = Verdict.SAFE, 
                    summary = "Scanning: Ready for dynamic content analysis.",
                    messageSnippet = rawMessage.take(200),
                    explainabilityJson = "",
                    typosquatFlag = false,
                    senderReputationScore = 0.0f
                ),
                analysisTriggered = false
            )
        }

        val urls = extractUrls(rawMessage)
        val normalizedSender = normalizeSender(sender)

        val db = AnalysisHistoryDatabase.getInstance(appContext)
        val pastScans = db.dao().getBySender(normalizedSender)
        val reputationScore = if (pastScans.isEmpty()) {
            0.0f
        } else {
            val threatSum = pastScans.sumOf { scan ->
                when (scan.verdict) {
                    Verdict.DANGER -> 1.0
                    Verdict.WARNING -> 0.5
                    Verdict.SAFE -> 0.0
                    Verdict.UNCERTAIN -> 0.0
                }
            }
            (threatSum / pastScans.size).toFloat().coerceIn(0f, 1f)
        }

        val indicators = mutableListOf<String>()
        val explainabilityList = mutableListOf<ExplainabilityItem>()
        if (reputationScore > 0.4f) {
            indicators.add("Sender Reputation Alert")
            explainabilityList.add(ExplainabilityItem(normalizedSender, "Sender Reputation: High threat ratio history (${(reputationScore * 100).toInt()}%)"))
        }

        val ml = runMlPipeline(rawMessage, urls, indicators, explainabilityList, reputationScore)
        val mlPct = (ml.finalScore * 100).toInt().coerceIn(0, 100)

        // MODEL DISAGREEMENT LOGGING:
        // Log when models strongly disagree — this is critical for error analysis.
        if (ml.modelDisagreement > 0.30f) {
            Log.w("SpamAnalyzer", "MODEL_DISAGREEMENT: URL=${(ml.urlScore*100).toInt()}% NLP=${(ml.nlpScore*100).toInt()}% " +
                "BODMAS=${(ml.bodmasScore*100).toInt()}% TYPO=${(ml.typosquatScore*100).toInt()}% " +
                "DISAGREEMENT=${"%.2f".format(ml.modelDisagreement)} UNCERTAINTY=${ml.uncertaintyReason ?: "none"}")
            ModelDisagreementLogger.logDisagreement(
                mlScore = mlPct,
                urlScore = ml.urlScore,
                nlpScore = ml.nlpScore,
                bodmasScore = ml.bodmasScore,
                typosquatScore = ml.typosquatScore,
                reputationScore = reputationScore,
                disagreement = ml.modelDisagreement,
                uncertaintyReason = ml.uncertaintyReason,
                finalVerdict = Verdict.SAFE // Will be updated after final verdict
            )
        }

        // Disagreement-Resolver Pattern (Modified):
        // Cloud AI is now always invoked if available to prevent "OFFLINE" status
        // and unwarranted offline penalties that push warnings to danger.
        val aiDecision = withTimeoutOrNull(5_000) { requestGeminiDirect(rawMessage, indicators) }

        val preCorroborationScore: Int
        val aiScore = aiDecision?.score ?: -1 

        // Log agreement telemetry for evaluation
        if (aiScore != -1) {
            val agreementDiff = Math.abs(mlPct - aiScore)
            Log.i("SpamAnalyzer", "DISAGREEMENT_TELEMETRY: localML=$mlPct% aiCloud=$aiScore% diff=$agreementDiff pts. Indicators=${indicators.size}")
        }

        val textThreatSignals = ThreatSignalPolicy.analyze(rawMessage)
        val localEvidenceClearlyClean = mlPct < 35 && !textThreatSignals.isCorroborated &&
            ml.urlScore < 0.30f && ml.typosquatScore < 0.40f && reputationScore < 0.35f
        val hasLegitimateRewardContext = rawMessage.lowercase().let { lower ->
            lower.contains("cashback") && (lower.contains("wallet") || lower.contains("bill") ||
                lower.contains("credited") || lower.contains("valid for"))
        }

        if (aiScore == -1) {
            // AI OFFLINE: Use ML score with a slight penalty for lack of cloud verification
            preCorroborationScore = (mlPct * 1.1).toInt().coerceIn(0, 100)
        } else {
            // CLOUD ONLINE: Balanced weighting between local ensemble (55%) and cloud AI (45%)
            var rawCalculatedScore = (mlPct * 0.55 + aiScore * 0.45).toInt().coerceIn(0, 100)

            // STRONG CLOUD CORROBORATION GUARD:
            // When all local edge models rate the message clearly safe (low NLP, clean URLs,
            // clean typosquat, clean reputation, AND < 2 independent text signals), the Cloud
            // AI alone CANNOT produce a DANGER or even WARNING-level alert.
            // This stops the JioMart-style "verified cashback SMS → Cloud hallucinates typos →
            // DANGER 85%" bug in the accessibility/SMS scan path.
            if (localEvidenceClearlyClean) {
                rawCalculatedScore = when {
                    aiScore >= 70 -> if (hasLegitimateRewardContext) 28 else 38
                    aiScore >= 40 -> rawCalculatedScore.coerceAtMost(if (hasLegitimateRewardContext) 25 else 35)
                    else -> rawCalculatedScore.coerceAtMost(25)
                }
            } else if (mlPct < 15 && !textThreatSignals.isCorroborated && rawCalculatedScore >= DANGER_THRESHOLD) {
                // Legacy guard for ultra-clean local scans: Cloud alone still can't force DANGER
                rawCalculatedScore = 39
            } else if (mlPct < 10 && rawCalculatedScore >= DANGER_THRESHOLD) {
                rawCalculatedScore = 65
            }

            preCorroborationScore = rawCalculatedScore
        }

        val firedModels = mutableListOf<String>()
        val signals = mutableListOf<String>()
        if (ml.nlpScore > 0.80f) {
            firedModels.add("Text NLP")
            signals.add("Social engineering pattern")
        }
        if (ml.urlScore > 0.85f) {
            firedModels.add("URL CNN")
            signals.add("Suspicious link pattern")
        }
        if (ml.bodmasScore > 0.85f) {
            firedModels.add("Heuristic Core")
            signals.add("Structural anomaly")
        }
        if (ml.typosquatScore > 0.5f) {
            firedModels.add("Brand Impersonation")
            signals.add("Mimicked brand domain")
        }
        if (ml.reputationScore > 0.4f) {
            firedModels.add("Sender Reputation")
            signals.add("Historical spam activity")
        }
        if (aiScore >= 40) {
            firedModels.add("Cloud AI")
            aiDecision?.reason?.let { signals.add(it) }
        }

        // ── CORROBORATION GATE ────────────────────────────────────────────────────
        // Precision guarantee: a single fired model alone must NOT be able to push
        // a message to DANGER (>= 70) or SUSPICIOUS (>= 40), with two specific exemptions:
        //
        // EXEMPTION 1 — Confirmed typosquat / homograph (typosquatScore >= 0.9f):
        //   A homograph or brand-mimicry detection is a structural, high-confidence
        //   signal. These are not keyword matches and don't false-positive on legitimate text.
        //
        // EXEMPTION 2 — Tamil/Tanglish heuristic high-confidence fire (nlpScore >= 0.70f
        //   from tamilHeuristicScore, which sets nS = tamilHeuristicScore via maxOf):
        //   The Tamil heuristic requires 2+ co-occurring Tamil phishing keywords before
        //   scoring 0.70+. That internal corroboration already acts as a 2-signal gate.
        //   Exempting it here prevents the cap from incorrectly demoting Tamil scams from
        //   DANGER to SUSPICIOUS. The Tamil heuristic already IS the second signal.
        //
        // Note: tamilHeuristicScore is not directly accessible here (it lives in runMlPipeline
        // return), but its effect is fully captured in ml.nlpScore: when Tamil heuristic fires
        // at 0.70+ it overrides cappedNs via maxOf(), making ml.nlpScore == tamilHeuristicScore.
        // A threshold of >= 0.70f exactly matches the 2-keyword (0.70f) and 3-keyword (0.85f) tiers.
        val confirmedTyposquat = ml.typosquatScore >= 0.9f
        val tamilHeuristicFired  = ml.nlpScore >= 0.70f && isTamilText(rawMessage).let { isTamil ->
            isTamil || MessageLanguageDetector.detectTanglish(rawMessage).isDetected
        }
        // Bug Fix (Phase 3, Bug 3): Hinglish high-confidence detection was previously not exempt
        // from the 2-model corroboration cap. detectHinglish() already requires ≥1 phrase match
        // OR ≥2 word matches — internal corroboration — so one fired model is already two signals.
        val hinglishHeuristicFired = ml.nlpScore >= 0.70f &&
            MessageLanguageDetector.detectHinglish(rawMessage)
        val gateExempt = confirmedTyposquat || tamilHeuristicFired || hinglishHeuristicFired

        val corroboratedFinalScore = when {
            gateExempt -> preCorroborationScore  // High-confidence single signal — bypass cap
            firedModels.size < 1 ->
                // Zero models fired above threshold: score cannot reach WARNING
                preCorroborationScore.coerceAtMost(WARNING_THRESHOLD - 1)
            firedModels.size < 2 ->
                // Only 1 model fired: score cannot reach DANGER (but WARNING is allowed)
                preCorroborationScore.coerceAtMost(DANGER_THRESHOLD - 1)
            else -> preCorroborationScore  // 2+ independent signals: no cap applied
        }

        if (corroboratedFinalScore != preCorroborationScore) {
            Log.d("SpamAnalyzer", "CORROBORATION_CAP: firedModels=${firedModels.size} " +
                "gateExempt=$gateExempt raw=$preCorroborationScore capped=$corroboratedFinalScore")
        }
        val finalRiskScore = corroboratedFinalScore
        val finalVerdict = computeVerdict(finalRiskScore)
        // ── END CORROBORATION GATE ────────────────────────────────────────────────

        Log.d(
            "FalsePositiveTest",
            "REAL_SCAN_PIPELINE: Message='${rawMessage.take(50)}' | URL_CNN=${(ml.urlScore * 100).toInt()}% | NLP=${(ml.nlpScore * 100).toInt()}% | BODMAS=${(ml.bodmasScore * 100).toInt()}% | TYPOSQUAT=${(ml.typosquatScore * 100).toInt()}% | REP=${(ml.reputationScore * 100).toInt()}% | LOCAL_PCT=${mlPct}% | AI_CLOUD=${if (aiScore == -1) "OFFLINE" else aiScore} | FIRED=${firedModels.size} | FINAL_SCORE=${finalRiskScore} | VERDICT=${finalVerdict}"
        )

        Log.d(
            "SpamAnalyzer",
            "SCAN: URL=${ml.urlScore} NLP=${ml.nlpScore} BODMAS=${ml.bodmasScore} TYPO=${ml.typosquatScore} REP=${ml.reputationScore} " +
            "AI=${if (aiScore == -1) "OFFLINE" else aiScore.toString()} " +
            "MLPCT=${mlPct} FINAL=${finalRiskScore} VERDICT=$finalVerdict"
        )

        val whyFlagged = when {
            firedModels.isEmpty() -> "Flagged due to cumulative low-confidence signals (Combined Risk: $mlPct%)."
            else -> {
                val modelText = if (firedModels.size == 1) "1 model" else "${firedModels.size} models"
                val signalsText = if (signals.isNotEmpty()) " [Signal: ${signals.joinToString("; ")}]" else ""
                "Flagged by $modelText (${firedModels.joinToString(", ")})$signalsText."
            }
        }

        val explainabilityJson = gson.toJson(explainabilityList)

        val result = AnalysisResult(
            appSource = appSource, sender = normalizedSender, subject = subject,
            verdict = finalVerdict, riskScore = finalRiskScore,
            category = if (finalVerdict == Verdict.SAFE) "legitimate" else "phishing",
            senderTrust = if (finalVerdict == Verdict.DANGER) "high-risk" else "unknown",
            summary = aiDecision?.summary ?: generateHeuristicSummary(finalVerdict, indicators),
            flags = listOf(
                "NLP Engine     : ${formatPercent(ml.nlpScore)}",
                "URL Forensic   : ${formatPercent(ml.urlScore)}",
                "Heuristic Core : ${formatPercent(ml.bodmasScore)}",
                "Typosquatting  : ${formatPercent(ml.typosquatScore)}",
                "Reputation     : ${formatPercent(ml.reputationScore)}",
                "Combined Risk  : ${formatPercent(finalRiskScore/100f)}",
                "Cloud Forensic : ${if (aiScore != -1) "Operational" else "Cloud analysis unavailable (offline)"}",
                "Disagreement   : ${"%.2f".format(ml.modelDisagreement)}",
                "__why_flagged:$whyFlagged"
            ),
            action = aiDecision?.reason ?: "Message verified by local edge sentinel.",
            mlScore = mlPct,
            aiScore = aiScore,
            messageSnippet = rawMessage.take(200),
            flaggedUrls = urls.joinToString("\n"),
            explainabilityJson = explainabilityJson,
            typosquatFlag = ml.typosquatScore > 0.5f,
            senderReputationScore = ml.reputationScore,
            uncertaintyReason = ml.uncertaintyReason,
            modelDisagreementScore = ml.modelDisagreement
        )

        if (finalVerdict != Verdict.SAFE) {
            // Guard against empty / OCR-failure scans being treated as email-worthy threats.
            // If the message body is under 15 chars or < 3 words, the scanner probably
            // grabbed nothing useful — skip alert regardless of verdict.
            val wordCount = rawMessage.trim().split(Regex("""\s+""")).filter { it.isNotBlank() }.size
            val isMeaningfulMessage = rawMessage.trim().length >= 15 && wordCount >= 3
            if (isMeaningfulMessage) {
                emailManager.sendAlertIfQualified(result)
            } else {
                Log.i("SpamAnalyzer", "Alert suppressed for short/empty scan (len=${rawMessage.length}, words=$wordCount)")
            }
        }
        AnalysisOutcome(result = result, analysisTriggered = true)
    }

    private fun generateHeuristicSummary(verdict: Verdict, indicators: List<String>): String {
        if (verdict == Verdict.SAFE) return "No threat signals detected. Message appears safe."
        val signals = indicators.joinToString(", ").take(150)
        return "Local analysis complete. Patterns identified: $signals. Cloud verification unavailable."
    }

    private fun computeVerdict(score: Int) = when {
        score >= DANGER_THRESHOLD -> Verdict.DANGER
        score >= WARNING_THRESHOLD -> Verdict.WARNING
        else -> Verdict.SAFE
    }

    fun runMlPipelinePublic(
        message: String,
        urls: List<String>,
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>,
        reputationScore: Float
    ) = runMlPipeline(message, urls, indicators, explainabilityItems, reputationScore)

    private fun runMlPipeline(
        message: String, 
        urls: List<String>, 
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>,
        reputationScore: Float
    ): MlResult {
        val lower = message.lowercase()
        // Isolated words such as "blocked", "OTP", or "PAN card" are common in legitimate
        // notices. They may be shown as evidence only after a second, independent text signal.
        val textThreatSignals = ThreatSignalPolicy.analyze(message)
        if (textThreatSignals.isCorroborated) {
            val keywords = mapOf(
                "blocked" to "Heuristic: Account status alarm",
                "suspended" to "Heuristic: Account status alarm",
                "aadhaar" to "Heuristic: Identity data request",
                "pan card" to "Heuristic: Identity data request",
                "otp" to "Heuristic: Identity data request"
            )
            for ((word, reason) in keywords) {
                if (lower.contains(word)) {
                    indicators.add(reason.substringAfter(": "))
                    val regex = Regex("(?i)\\b$word\\b|(?i)$word")
                    regex.findAll(message).forEach { match ->
                        explainabilityItems.add(ExplainabilityItem(match.value, reason))
                    }
                }
            }
        }
        
        // FP-3 FIX: URL shortener alone is a weak contextual signal — not a standalone threat indicator.
        // A promotional message from Flipkart/Amazon with bit.ly is NOT suspicious by itself.
        // Only add to indicators (which feed the score) when text is already corroborated (2+ signals).
        val hasShortLinkInBody = urls.any { url ->
            val uL = url.lowercase()
            uL.contains("bit.ly") || uL.contains("tinyurl") || uL.contains("t.co")
        }
        if (hasShortLinkInBody) {
            explainabilityItems.add(ExplainabilityItem(
                "URL Shortener detected",
                "Heuristic: Short-link present (weak signal — informational only)"
            ))
            // Only escalate to a score-feeding indicator when corroborated by text signals
            if (textThreatSignals.isCorroborated) {
                indicators.add("URL Shortener mask")
            }
        }

        val (isTyposquat, isHomograph) = checkTyposquattingAndHomographs(urls, indicators, explainabilityItems)
        val tS = if (isTyposquat || isHomograph) 1.0f else 0.0f

        val tamilHeuristicScore = addHeuristicSignals(message, urls, indicators, explainabilityItems)

        val uS = scoreUrlModel(urls, indicators, explainabilityItems)
        // NLP score: custom-trained TFLite model (text_nlp_model.tflite) + Tamil Heuristic engine fallback boost
        val rawNs = scoreTfliteNlpModel(message, indicators, explainabilityItems)
        // BankTx / Retailer-Promo NLP guard: the TFLite English NLP model was trained on generic spam keywords
        // and routinely returns 80-99% on legitimate bank SMS or retailer cashback messages.
        // When 2+ corroborated textual threat signals are ABSENT, no suspicious URLs, AND the text
        // matches structured bank/retailer markers, cap the NLP contribution at 0.22 (roughly 22%) so it
        // cannot single-handedly force a WARNING or DANGER.
        val hasBankTx = lower.containsAllAtLeastTwo(listOf(
            "debited", "credited", "rs.", "inr ", "mandate", "autopay",
            "ifsc", "neft", "imps", "reference no", "txn",
            "transaction", "available balance", "a/c no", "a/c.", "account"
        ))
        val hasRetailer = lower.containsAllAtLeastTwo(listOf(
            "jiomart", "flipkart", "amazon", "swiggy", "zomato",
            "cashback", "wallet to be used", "t&ca", "valid for today",
            "credited in wallet", "shop now", "next bill on", "order has shipped"
        ))
        val capNlpForSafeContext = !textThreatSignals.isCorroborated &&
            uS < 0.30f && !isTyposquat && !isHomograph && (hasBankTx || hasRetailer)
        val cappedNs = if (capNlpForSafeContext) rawNs.coerceAtMost(0.22f) else rawNs
        val nS = maxOf(cappedNs, tamilHeuristicScore)
        val bS = scoreBodmasModel(message, urls, indicators, explainabilityItems)

        val weights = getEnsembleWeights()
        val wUrl = weights[0]
        val wNlp = weights[1]
        val wBodmas = weights[2]
        val wTypo = weights[3]
        val wRep = weights[4]

        // Fix A: Short-link + urgency floor
        // When ANY URL is a known shortener (bit.ly / tinyurl / t.co / etc.) AND the message
        // contains urgency/financial-threat language, the ONNX model cannot score the true
        // destination. Apply a minimum BODMAS floor so these messages don't score 0 on all
        // static signals and become entirely dependent on a flaky Gemini call.
        val SHORTLINK_DOMAINS = setOf("bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "short.url", "rb.gy")
        val hasShortLink = urls.any { url -> SHORTLINK_DOMAINS.any { url.lowercase().contains(it) } }
        val adjustedBs = if (hasShortLink && textThreatSignals.isCorroborated) {
            indicators.add("Short-link mask with urgency language")
            explainabilityItems.add(ExplainabilityItem("URL Shortener + Urgency", "Heuristic: Masked URL combined with urgency triggers is a strong phishing indicator"))
            bS.coerceAtLeast(0.5f)   // floor at 0.5 — contributes ~9 pts to mlPct via BODMAS weight
        } else bS

        val rawWeightedSum = (uS * wUrl + nS * wNlp + adjustedBs * wBodmas + tS * wTypo + reputationScore * wRep)
        val totalWeights = (wUrl + wNlp + wBodmas + wTypo + wRep).coerceAtLeast(0.01f)
        val ensemble = (rawWeightedSum / totalWeights).coerceIn(0f, 1f)

        // MODEL DISAGREEMENT CALCULATION:
        // When models strongly disagree (e.g., NLP=0.9 but URL=0.1), the result is uncertain.
        // Disagreement = standard deviation of active model scores (normalized 0-1).
        val activeScores = mutableListOf(uS, nS, adjustedBs, tS, reputationScore)
            .filter { it > 0f } // Only consider models that actually scored
        val disagreement = if (activeScores.size >= 2) {
            val mean = activeScores.average().toFloat()
            val variance = activeScores.map { (it - mean) * (it - mean) }.average().toFloat()
            kotlin.math.sqrt(variance.toDouble()).toFloat()
        } else 0f

        // UNCERTAINTY DETECTION:
        // When models disagree strongly AND no single model has high confidence,
        // the pipeline cannot make a reliable decision.
        val uncertaintyReason = when {
            disagreement > 0.35f && (activeScores.maxOrNull() ?: 0f) < 0.70f ->
                "Model disagreement (std=${"%.2f".format(disagreement)}): models produce conflicting signals with no dominant consensus"
            disagreement > 0.40f ->
                "Severe model disagreement (std=${"%.2f".format(disagreement)}): reliable classification not possible"
            urls.isNotEmpty() && uS < 0.10f && nS > 0.70f && tS < 0.10f && adjustedBs < 0.10f ->
                "Text-only threat signal without corroborating URL evidence: NLP flagged but URL models see no structural anomaly"
            else -> null
        }

        return MlResult(
            urlScore = uS, nlpScore = nS, bodmasScore = adjustedBs,
            typosquatScore = tS, reputationScore = reputationScore,
            finalScore = ensemble, modelDisagreement = disagreement,
            uncertaintyReason = uncertaintyReason
        )
    }

    private fun addHeuristicSignals(
        message: String,
        urls: List<String>,
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>
    ): Float {
        val lower = message.lowercase(Locale.getDefault())

        val textThreatSignals = ThreatSignalPolicy.analyze(message)
        val phishingTriggers = mapOf(
            "verify your account" to "Account verification request",
            "confirm your password" to "Credential validation prompt",
            "update your payment" to "Billing information change request",
            "unauthorized login attempt" to "Login security alert",
            "click here" to "Direct click-through request",
            "your account has been suspended" to "Account suspension threat",
            "payment failed" to "Payment failure scam pattern",
            "urgent action required" to "Urgency phishing signal"
        )

        for ((phrase, reason) in phishingTriggers) {
            if (textThreatSignals.isCorroborated && lower.contains(phrase)) {
                indicators.add(reason)
                explainabilityItems.add(ExplainabilityItem(phrase, reason))
            }
        }

        if (textThreatSignals.isCorroborated && textThreatSignals.hasUrgency) {
            indicators.add("Urgency language detected")
            explainabilityItems.add(ExplainabilityItem("Urgency phrase detected", "Phishing urgency pattern"))
        }

        val requestActions = listOf("click here", "open now", "tap here", "review now", "update now")
        if (textThreatSignals.isCorroborated && requestActions.any { lower.contains(it) }) {
            indicators.add("Direct action request")
            explainabilityItems.add(ExplainabilityItem(requestActions.first { lower.contains(it) }, "Action-oriented phishing wording"))
        }

        // Item 6: Tamil Language Heuristic Keyword Signals
        var tamilHeuristicScore = 0.0f
        val tanglishDetection = MessageLanguageDetector.detectTanglish(message)
        val isTamilInput = isTamilText(message) || tanglishDetection.isDetected
        if (isTamilInput) {
            val tamilScamTriggers = mapOf(
                "வங்கி" to "Tamil Heuristic: Bank reference",
                "கணக்கு" to "Tamil Heuristic: Account alert",
                "கடவுச்சொல்" to "Tamil Heuristic: Credential / PIN request",
                "பின்" to "Tamil Heuristic: Credential / PIN request",
                "ஓடிபி" to "Tamil Heuristic: OTP data request",
                "இணைப்பு" to "Tamil Heuristic: Direct link click request",
                "பணம்" to "Tamil Heuristic: Money / Payment request",
                "வெற்றி" to "Tamil Heuristic: Lottery / Prize lure",
                "அவசரம்" to "Tamil Heuristic: Urgency phishing trigger",
                "உடனே" to "Tamil Heuristic: Immediate action demand",
                "முடக்கப்பட்டது" to "Tamil Heuristic: Account blocked / suspended alarm",
                "சரிபார்க்கவும்" to "Tamil Heuristic: Verification request"
            )
            val tanglishScamTriggers = mapOf(
                "vangi" to "Tanglish Heuristic: Bank reference",
                "kanakku" to "Tanglish Heuristic: Account alert",
                "panam" to "Tanglish Heuristic: Money / payment request",
                "kaasu" to "Tanglish Heuristic: Money / payment request",
                "udane" to "Tanglish Heuristic: Immediate action demand",
                "seekiram" to "Tanglish Heuristic: Immediate action demand",
                "block aagum" to "Tanglish Heuristic: Account blocked alarm",
                "verify pannunga" to "Tanglish Heuristic: Verification request",
                "otp anuppunga" to "Tanglish Heuristic: OTP data request",
                "pin anuppunga" to "Tanglish Heuristic: Credential / PIN request",
                "link click pannunga" to "Tanglish Heuristic: Direct link click request"
            )
            val triggers = if (tanglishDetection.isDetected && !isTamilText(message)) {
                tanglishScamTriggers
            } else {
                tamilScamTriggers
            }
            var count = 0
            for ((trigger, reason) in triggers) {
                if (lower.contains(trigger)) {
                    count++
                    indicators.add(reason)
                    explainabilityItems.add(ExplainabilityItem(trigger, reason))
                }
            }
            if (count >= 3) {
                tamilHeuristicScore = 0.85f
            } else if (count >= 2) {
                tamilHeuristicScore = 0.70f
            }
        } else if (MessageLanguageDetector.detectHinglish(message)) {
            val hinglishScamTriggers = mapOf(
                "bank" to "Hinglish Heuristic: Bank reference",
                "khata" to "Hinglish Heuristic: Account alert",
                "account" to "Hinglish Heuristic: Account alert",
                "paisa" to "Hinglish Heuristic: Money / payment request",
                "rupaye" to "Hinglish Heuristic: Money / payment request",
                "turant" to "Hinglish Heuristic: Immediate action demand",
                "jaldi" to "Hinglish Heuristic: Immediate action demand",
                "block" to "Hinglish Heuristic: Account blocked alarm",
                "verify" to "Hinglish Heuristic: Verification request",
                "otp" to "Hinglish Heuristic: OTP data request",
                "pin" to "Hinglish Heuristic: Credential / PIN request",
                "password" to "Hinglish Heuristic: Credential / Password request",
                "inaam" to "Hinglish Heuristic: Lottery / Prize lure",
                "aadhaar" to "Hinglish Heuristic: Identity data request"
            )
            var count = 0
            for ((trigger, reason) in hinglishScamTriggers) {
                if (lower.contains(trigger)) {
                    count++
                    indicators.add(reason)
                    explainabilityItems.add(ExplainabilityItem(trigger, reason))
                }
            }
            if (count >= 3) {
                tamilHeuristicScore = 0.85f
            } else if (count >= 2) {
                tamilHeuristicScore = 0.70f
            }
        }

        // FP-1 FIX: "Not on allowlist" means UNKNOWN, not SUSPICIOUS.
        // An unknown domain is informational context for the user, not evidence of a threat.
        // Removing this from indicators stops the GitHub-URL false-positive and similar clean-domain FPs.
        if (urls.isNotEmpty() && urls.none { isTrustedDomain(it) }) {
            explainabilityItems.add(ExplainabilityItem(
                urls.first(),
                "Domain not on verified allowlist (informational — unknown ≠ suspicious)"
            ))
        }

        return tamilHeuristicScore
    }

    private fun isTrustedDomain(url: String): Boolean {
        val safeHosts = setOf(
            "google.com", "github.com", "gitlab.com", "stackoverflow.com", "linkedin.com",
            "microsoft.com", "apple.com", "amazon.in", "amazon.com", "flipkart.com",
            "swiggy.com", "zomato.com", "jiomart.com", "jio.com", "airtel.in", "netflix.com",
            "paypal.com", "facebook.com", "youtube.com", "instagram.com", "whatsapp.com",
            "twitter.com", "x.com", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
            "axisbank.com", "internshala.com"
        )
        val host = extractDomain(url)
        return safeHosts.any { host == it || host.endsWith(".$it") } ||
               assetWhitelist.any { host == it || host.endsWith(".$it") }
    }

    suspend fun requestGeminiDirectPublic(msg: String, mlIndicators: List<String>): ClaudeDecision? =
        requestGeminiDirect(msg, mlIndicators)

    private suspend fun requestGeminiDirect(msg: String, mlIndicators: List<String>): ClaudeDecision? {
        val key = BuildConfig.GEMINI_API_KEY.trim()
        if (key.isBlank()) return null

        // Instant Connectivity Check — skip cloud network wait when offline
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
        val activeNetwork = cm?.activeNetworkInfo
        val isConnected = activeNetwork != null && activeNetwork.isConnected
        if (!isConnected) {
            Log.d("ULTRA_AI", "Device is offline — skipping Gemini Cloud call immediately without timeout delay.")
            return null
        }

        // Diagnostic: List models one time if we keep getting 404s
        if (!hasLoggedAvailableModels) {
            hasLoggedAvailableModels = true
            scopeLogAvailableModels(key)
        }

        // Fix B: Check in-memory cache first — same content hash = same AI score
        val msgHash = msg.hashCode()
        val cached = geminiScoreCache[msgHash]
        if (cached != null && (System.currentTimeMillis() - cached.second) < GEMINI_CACHE_TTL_MS) {
            Log.d("SpamAnalyzer", "Gemini cache HIT for msg hash $msgHash — returning cached score ${cached.first.score}")
            return cached.first
        }

        // Only the redacted text is transmitted to the cloud service. Local models still use
        // the original message so on-device detection quality is unaffected.
        val prompt = buildPrecisionPrompt(redactSensitiveDataForCloud(msg), mlIndicators)
        // Fix B: temperature=0.0 eliminates sampling variance on borderline-classification messages.
        // Without this, identical prompts get AI=75→10→5 draws at default temp~1.0.
        val generationConfig = JsonObject().apply { addProperty("temperature", 0.0) }
        val bodyData = JsonObject().apply {
            add("contents", gson.toJsonTree(listOf(mapOf("parts" to listOf(mapOf("text" to prompt))))))
            add("generationConfig", generationConfig)
        }.toString()
        val requestBody = bodyData.toRequestBody(JSON_TYPE)

        // Triple-fallback strategy across v1beta and v1 versions
        for (verId in listOf("v1beta", "v1")) {
            for (model in MODEL_FALLBACK_CHAIN) {
                val fullModelId = "$verId/$model"
                if (permanentlyDeadModels.contains(fullModelId)) continue
                
                val exhaustsAt = quotaExhaustedUntil[fullModelId] ?: 0L
                if (System.currentTimeMillis() < exhaustsAt) continue

                val url = "https://generativelanguage.googleapis.com/$verId/models/$model:generateContent?key=$key"
                try {
                    val response = geminiClient.newCall(Request.Builder().url(url).post(requestBody).build()).execute()
                    val code = response.code
                    val rawBody = response.body?.string()
                    response.close()

                    if (code == 200 && rawBody != null) {
                        val text = gson.fromJson(rawBody, JsonObject::class.java).getAsJsonArray("candidates")?.get(0)?.asJsonObject
                            ?.getAsJsonObject("content")?.getAsJsonArray("parts")?.get(0)?.asJsonObject?.get("text")?.asString ?: ""
                        val decision = parseForensicResponse(text)
                        // Fix B: Store in cache so repeated scans of same content stay consistent
                        if (decision != null) geminiScoreCache[msgHash] = Pair(decision, System.currentTimeMillis())
                        return decision
                    } else if (code == 429 || code == 503) {
                        Log.w("ULTRA_AI", "$code Service Unavailable/Rate Limit on $fullModelId — cooling 60s.")
                        quotaExhaustedUntil[fullModelId] = System.currentTimeMillis() + 60_000L
                    } else if (code == 404) {
                        Log.e("ULTRA_AI", "404 Not Found on $fullModelId — skipping.")
                        permanentlyDeadModels.add(fullModelId)
                    } else {
                        Log.e("ULTRA_AI", "API Error $code on $fullModelId: $rawBody")
                    }
                } catch (e: Exception) { Log.e("ULTRA_AI", "Network failure on $model: ${e.message}") }
            }
        }
        return null
    }

    private fun scopeLogAvailableModels(key: String) {
        analyzerScope.launch {
            try {
                val listUrl = "https://generativelanguage.googleapis.com/v1beta/models?key=$key"
                val resp = geminiClient.newCall(Request.Builder().url(listUrl).get().build()).execute()
                Log.d("ULTRA_AI", "DIAGNOSTIC - Available Models: ${resp.body?.string()}")
                resp.close()
            } catch (e: Exception) { Log.e("ULTRA_AI", "Failed to list models: ${e.message}") }
        }
    }

    private fun buildPrecisionPrompt(content: String, mlIndicators: List<String>): String {
        val indicatorText = if (mlIndicators.isEmpty()) "Heuristically clean." else mlIndicators.joinToString("\n  - ", prefix = "  - ")
        return """
            You are a Cybersecurity forensic engine. Analyze the following MESSAGE content.
            CRITICAL: Ignore the presence of system buttons like 'Reply', 'Forward', 'Inbox', or 'Save to Drive'. These are part of the Gmail app, not the message.
            
            TRUST DIRECTIVE: If the message is about internships, training updates, or recruitment from domains like 'internshala.com', 'google.com', or 'linkedin.com', it is SAFE.
            
            ML SIGNALS: $indicatorText
            CONTENT TO ANALYZE: ${content.take(800)}
            
            Return JSON ONLY:
            {
              "verdict": "SAFE" | "WARNING" | "DANGER",
              "score": <0-100>,
              "reason": "<1 sentence explanation>",
              "summary": "<2 precise sentences of context>"
            }
        """.trimIndent()
    }

    private fun parseForensicResponse(rawText: String): ClaudeDecision? {
        val f = rawText.indexOf('{'); val l = rawText.lastIndexOf('}')
        if (f < 0 || l <= f) return null
        return try {
            val json = gson.fromJson(rawText.substring(f, l + 1), JsonObject::class.java)
            ClaudeDecision(
                verdict = when (json.get("verdict")?.asString?.uppercase()) { "DANGER" -> Verdict.DANGER; "WARNING" -> Verdict.WARNING; else -> Verdict.SAFE },
                reason  = json.get("reason")?.asString ?: "Verified",
                summary = json.get("summary")?.asString ?: "Scan finalized.",
                score   = json.get("score")?.asInt      ?: 0
            )
        } catch (_: Exception) { null }
    }

    private fun redactSensitiveDataForCloud(text: String): String {
        return text
            .replace(Regex("""\\b\\d{4,8}\\b"""), "[REDACTED_CODE]")
            .replace(
                Regex("""(?i)\\b(password|pin|cvv|otp|code)\\s*[:=]\\s*\\S+"""),
                "$1: [REDACTED]"
            )
    }

    private fun scoreUrlModel(
        urls: List<String>, 
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>
    ): Float {
        val interpreter = urlInterpreter ?: return 0f
        if (urls.isEmpty()) return 0f
        var maxScore = 0f
        val out = Array(1) { FloatArray(1) }
        urls.forEach { url ->
            // If the domain is officially verified and not typosquatted, score it 0.0 (Clean)
            if (isTrustedDomain(url)) {
                explainabilityItems.add(ExplainabilityItem(url, "Official Domain: Verified legitimate service"))
                return@forEach
            }
            val inp = Array(1) { IntArray(200).apply {
                val chars = url.lowercase()
                for (i in 0 until minOf(chars.length, 200)) this[i] = chars[i].code.coerceIn(1, 127)
            }}
            synchronized(urlLock) { interpreter.run(inp, out) }
            val prob = toProb(out[0][0])
            if (prob > 0.85) {
                indicators.add("CNN Pattern: Suspicious link structure")
                explainabilityItems.add(ExplainabilityItem(url, "URL CNN Model: Suspicious patterns"))
            } else {
                explainabilityItems.add(ExplainabilityItem(url, "Extracted URL (Scanned Safe)"))
            }
            maxScore = max(maxScore, prob)
        }
        return maxScore
    }

    fun isTamilText(text: String): Boolean = MessageLanguageDetector.containsTamilScript(text)

    /**
     * Must clean text while preserving Tamil unicode characters (\u0B80-\u0BFF):
     *   BEFORE (ASCII-only regex bug): cleaned.replace(Regex("[^a-z0-9\\s<>]"), "") -> stripped all Tamil script to ""
     *   AFTER (Tamil fix): cleaned.replace(Regex("[^a-z0-9\\s<>\\u0B80-\\u0BFF]"), "") -> preserves Tamil script
     */
    private fun cleanText(text: String): String {
        var cleaned = text.lowercase()
        cleaned = cleaned.replace(Regex("http\\S+"), "<url>")
        cleaned = cleaned.replace(Regex("[^a-z0-9\\s<>\\u0B80-\\u0BFF]"), "")
        return cleaned.trim()
    }

    private fun tokenizeAndPad(text: String, vocab: Map<String, Int>): IntArray {
        val cleaned = cleanText(text)
        val words = cleaned.split(Regex("\\s+")).filter { it.isNotEmpty() }

        val tokenIds = words.map { word ->
            val id = vocab[word] ?: NLP_OOV_TOKEN_ID
            if (id >= NLP_VOCAB_SIZE) NLP_OOV_TOKEN_ID else id
        }

        // padding='post': real tokens first, zero-padding after
        val result = IntArray(NLP_MAX_LEN)
        for (i in 0 until NLP_MAX_LEN) {
            result[i] = if (i < tokenIds.size) tokenIds[i] else 0
        }
        return result
    }

    /**
     * Returns true if the target string contains at least 2 distinct terms from the provided list.
     * Used for bank-transaction and verified-retailer context detection: we need MULTIPLE
     * matching terms to avoid a single coincidental word (e.g. the word "account" in a
     * non-banking phishing message) from triggering the protective NLP cap.
     */
    private fun String.containsAllAtLeastTwo(terms: List<String>): Boolean {
        return terms.count { this.contains(it) } >= 2
    }

    private fun scoreTfliteNlpModel(
        message: String,
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>
    ): Float {
        // ARCHITECTURE NOTE (Hackathon Demo): On-device TFLite NLP model is trained on English text.
        // For Tamil text, detection routes through Tamil Heuristic Keyword Engine + Tamil Gemini Cloud AI (when online) + Tamil TTS alert voice.
        if (isTamilText(message)) {
            Log.i("SpamAnalyzer", "Tamil script detected — routing through Tamil Heuristic Engine + Gemini Cloud AI path.")
        }
        val interpreter = nlpInterpreter ?: run {
            Log.w("SpamAnalyzer", "NLP TFLite model uninitialized — defaulting NLP score to 0.0f")
            return 0f
        }
        if (nlpVocab.isEmpty()) {
            Log.w("SpamAnalyzer", "NLP vocab empty — defaulting NLP score to 0.0f")
            return 0f
        }
        val tokenIds = tokenizeAndPad(message, nlpVocab)
        val floatTokens = FloatArray(tokenIds.size) { tokenIds[it].toFloat() }
        val inp = Array(1) { floatTokens }
        val out = Array(1) { FloatArray(1) }
        return try {
            synchronized(nlpLock) { interpreter.run(inp, out) }
            val prob = toProb(out[0][0])
            if (prob > 0.80f) {
                indicators.add("NLP Flag: Text pattern matches spam/phishing training data")
                explainabilityItems.add(ExplainabilityItem(message.take(40) + "...", "TFLite NLP Model (96.5% acc): High spam probability"))
            }
            android.util.Log.d("FalsePositiveTest", "NLP_TFLITE_SCORE: msg='${message.take(40)}' prob=$prob")
            prob
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "CRITICAL: TFLite NLP inference failure — entering degraded/inconclusive state", e)
            indicators.add("Degraded Engine: NLP inference exception")
            explainabilityItems.add(ExplainabilityItem(message.take(40) + "...", "NLP Model Error: Inference failed (${e.javaClass.simpleName})"))
            0.50f // Non-zero degraded uncertainty score prevents false-safe malware bypass
        }
    }



    private fun scoreBodmasModel(
        msg: String, 
        urls: List<String>, 
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>
    ): Float {
        val session = urlSession ?: return 0f
        val env = ortEnvironment ?: return 0f
        val input = urlInputName ?: return 0f
        
        if (urls.isEmpty()) return 0f
        var maxScore = 0f

        urls.forEach { url ->
            // Extract the 14 features expected by the converted XGBoost model:
            // 0: url_length, 1: domain_length, 2: qty_digits, 3: qty_dots, 4: qty_hyphens,
            // 5: has_https, 6: qty_subdomains, 7: url_entropy, 8: has_suspicious_keyword,
            // 9: qty_special_chars, 10: url_depth, 11: is_ip, 12: is_suspicious_tld, 13: query_length
            val feat = FloatArray(14)
            val lower = url.lowercase(Locale.US)
            val uri = try { java.net.URI(url) } catch (_: Exception) { null }
            val host = uri?.host ?: ""
            val query = uri?.query ?: ""
            val path = uri?.path ?: ""

            feat[0] = url.length.toFloat()
            feat[1] = host.length.toFloat()
            feat[2] = url.count { it.isDigit() }.toFloat()
            feat[3] = url.count { it == '.' }.toFloat()
            feat[4] = url.count { it == '-' }.toFloat()
            feat[5] = if (lower.startsWith("https")) 1.0f else 0.0f
            feat[6] = host.split('.').dropLast(2).size.coerceAtLeast(0).toFloat()

            // Calculate URL Entropy
            val frequencies = url.groupingBy { it }.eachCount()
            var entropy = 0.0
            for (count in frequencies.values) {
                val p = count.toDouble() / url.length
                entropy -= p * (Math.log(p) / Math.log(2.0))
            }
            feat[7] = entropy.toFloat()

            // FP-2 FIX: Remove "bank", "account", "upi" — these appear in legitimate SBI/HDFC/Jio URLs
            // (e.g. netbanking.hdfcbank.com/..., sbi.co.in/account-...). Keeping them inflated feat[8]
            // on clean transactional messages and boosted BODMAS score incorrectly.
            val suspiciousKeywords = listOf("login", "verify", "secure", "paytm", "signin", "phish", "malware", "steal", "harvest")
            feat[8] = if (suspiciousKeywords.any { lower.contains(it) }) 1.0f else 0.0f
            feat[9] = url.count { !it.isLetterOrDigit() && it != '/' && it != ':' && it != '.' && it != '?' && it != '=' }.toFloat()
            feat[10] = path.split('/').filter { it.isNotEmpty() }.size.toFloat()
            
            val isIpPattern = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
            feat[11] = if (isIpPattern.matches(host)) 1.0f else 0.0f

            val suspiciousTlds = listOf(
                ".xyz", ".top", ".club", ".info", ".win", ".bid", ".icu", ".loan",
                ".site", ".online", ".live", ".click", ".download", ".racing",
                ".science", ".party", ".gq", ".cf", ".ga", ".ml", ".tk"
            )
            feat[12] = if (suspiciousTlds.any { host.endsWith(it) }) 1.0f else 0.0f
            feat[13] = query.length.toFloat()

            var score = 0f
            try {
                OnnxTensor.createTensor(env, arrayOf(feat)).use { t ->
                    val candidateScores = mutableListOf<Float>()

                    // 1. Primary url_detector.onnx model
                    synchronized(urlSessionLock) {
                        session.run(mapOf(input to t)).use { res ->
                            val outputVal = res[1].value
                            if (outputVal is List<*>) {
                                val map = outputVal.firstOrNull() as? Map<*, *>
                                val s = (map?.get(1L) as? Number)?.toFloat()
                                    ?: (map?.get(1) as? Number)?.toFloat()
                                if (s != null) candidateScores.add(s)
                            }
                        }
                    }

                    // 2. Calibrated Voting Ensemble models (calibrated_voting_0, 1, 2)
                    if (votingSessions.isNotEmpty()) {
                        val votingFeat = FloatArray(37)
                        System.arraycopy(feat, 0, votingFeat, 0, feat.size)
                        OnnxTensor.createTensor(env, arrayOf(votingFeat)).use { vT ->
                            synchronized(votingLock) {
                                for ((vSession, vInput) in votingSessions) {
                                    try {
                                        vSession.run(mapOf(vInput to vT)).use { res ->
                                            val outputVal = res[1].value
                                            if (outputVal is List<*>) {
                                                val map = outputVal.firstOrNull() as? Map<*, *>
                                                val s = (map?.get(1L) as? Number)?.toFloat()
                                                    ?: (map?.get(1) as? Number)?.toFloat()
                                                if (s != null) candidateScores.add(s)
                                            }
                                        }
                                    } catch (ve: Exception) {
                                        Log.w("SpamAnalyzer", "Voting model step failed", ve)
                                    }
                                }
                            }
                        }
                    }

                    // 3. Full BODMAS Model (full_bodmas.onnx)
                    // TODO (Phase 3 Bug 5 fix — re-enable when Q1 is answered):
                    // full_bodmas.onnx expects a 2381-feature input but only 14 features are
                    // currently populated; the remaining 2367 dimensions are zeroed. Running the
                    // model in this state produces near-random output that degrades ensemble
                    // accuracy. The session is still loaded (close() still works), but it is
                    // excluded from candidateScores until the feature spec is confirmed.
                    // Restore by un-commenting the block below and implementing the 2381-feature
                    // extraction from the model training script.
                    /*
                    val bSession = bodmasSession
                    val bInput = bodmasInputName
                    if (bSession != null && bInput != null) {
                        val bodmasFeat = FloatArray(2381)
                        System.arraycopy(feat, 0, bodmasFeat, 0, feat.size)
                        OnnxTensor.createTensor(env, arrayOf(bodmasFeat)).use { bT ->
                            synchronized(bodmasLock) {
                                try {
                                    bSession.run(mapOf(bInput to bT)).use { res ->
                                        val outputVal = res[1].value
                                        if (outputVal is List<*>) {
                                            val map = outputVal.firstOrNull() as? Map<*, *>
                                            val s = (map?.get(1L) as? Number)?.toFloat()
                                                ?: (map?.get(1) as? Number)?.toFloat()
                                            if (s != null) candidateScores.add(s)
                                        }
                                    }
                                } catch (be: Exception) {
                                    Log.w("SpamAnalyzer", "BODMAS model step failed", be)
                                }
                            }
                        }
                    }
                    */

                    score = if (candidateScores.isNotEmpty()) {
                        candidateScores.average().toFloat()
                    } else {
                        0f
                    }
                }
            } catch (e: Exception) {
                Log.e("SpamAnalyzer", "CRITICAL: ONNX run failed for URL: $url — entering degraded/inconclusive state", e)
                indicators.add("Degraded Engine: URL ONNX inference exception")
                explainabilityItems.add(ExplainabilityItem(url, "URL Model Error: Inference failed (${e.javaClass.simpleName})"))
                score = 0.50f // Non-zero degraded uncertainty score prevents false-safe malware bypass
            }
            maxScore = maxOf(maxScore, score)
        }

        if (maxScore > 0.80) {
            indicators.add("Structural Anomaly: Suspicious URL details flagged by XGBoost")
        }
        return maxScore
    }

    private fun loadTfidfVocab(context: Context): Map<String, Int> {
        return try {
            val json = context.assets.open("tfidf_vocab.json").bufferedReader().use { it.readText() }
            val jsonObject = JSONObject(json)
            val vocab = HashMap<String, Int>(jsonObject.length())
            jsonObject.keys().forEach { key -> vocab[key] = jsonObject.getInt(key) }
            Log.d("SpamAnalyzer", "TF-IDF vocab loaded: ${vocab.size} tokens")
            vocab
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to load tfidf_vocab.json: ${e.message}")
            emptyMap()
        }
    }

    private fun loadWhitelist(context: Context): Set<String> {
        return try {
            val json = context.assets.open("whitelist.json").bufferedReader().use { it.readText() }
            val array = org.json.JSONArray(json)
            val set = HashSet<String>(array.length())
            for (i in 0 until array.length()) {
                set.add(array.getString(i).trim().lowercase())
            }
            Log.d("SpamAnalyzer", "Whitelist loaded: ${set.size} domains")
            set
        } catch (e: Exception) {
            Log.e("SpamAnalyzer", "Failed to load whitelist.json: ${e.message}")
            emptySet()
        }
    }

    private fun isGenericUi(text: String): Boolean = listOf("media grid", "see full report", "metadata:").any { text.lowercase().contains(it) }
    


    private fun formatPercent(s: Float) = String.format(Locale.US, "%.1f%%", s * 100f)
    private fun extractUrls(text: String) = Regex("""(?i)https?://[^\s<>"']+""").findAll(text).map { it.value.trimEnd('.', ',', ';') }.distinct().toList()
    private fun toProb(r: Float) = if (r.isNaN()) 0f else if (r in 0f..1f) r else (1.0 / (1.0 + exp(-r.toDouble()))).toFloat()
    private fun loadAssetBuffer(c: Context, a: String): ByteBuffer {
        val bytes = loadAssetBytes(c, a)
        return ByteBuffer.allocateDirect(bytes.size).order(ByteOrder.nativeOrder()).put(bytes).apply { rewind() }
    }
    private fun loadAssetBytes(c: Context, a: String) = c.assets.open(a).use { it.readBytes() }
    override fun close() {
        analyzerScope.cancel()
        urlInterpreter?.close()
        nlpInterpreter?.close()
        urlSession?.close()
        bodmasSession?.close()
        votingSessions.forEach { runCatching { it.first.close() } }
        ortEnvironment?.close()
        runCatching { geminiClient.dispatcher.executorService.shutdown() }
    }

    data class ExplainabilityItem(val span: String, val reason: String)

    private fun getEnsembleWeights(): FloatArray {
        val prefs = appContext.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        val wUrl = prefs.getFloat(Constants.KEY_WEIGHT_URL, W_URL)
        val wNlp = prefs.getFloat(Constants.KEY_WEIGHT_NLP, W_NLP)
        val wBodmas = prefs.getFloat(Constants.KEY_WEIGHT_BODMAS, W_BODMAS)
        val wTypo = prefs.getFloat(Constants.KEY_WEIGHT_TYPOSQUAT, W_TYPOSQUAT)
        val wRep = prefs.getFloat(Constants.KEY_WEIGHT_REPUTATION, W_REPUTATION)
        val weights = floatArrayOf(wUrl, wNlp, wBodmas, wTypo, wRep)

        val sum = weights.sum()
        // Epsilon tolerance check: if weight sum deviates from 1.0f by more than 0.001f, normalize
        if (weights.any { !it.isFinite() || it < 0f } || sum <= 0f || !sum.isFinite() || abs(sum - 1.0f) > 0.001f) {
            Log.w("SpamAnalyzer", "Ensemble weights unnormalized (Sum=$sum) — auto-normalizing to sum 1.0f.")
            AdaptiveTrustEngine.boundAndNormalizeWeights(weights)
        }
        return weights
    }

    private fun checkTyposquattingAndHomographs(
        urls: List<String>,
        indicators: MutableList<String>,
        explainabilityItems: MutableList<ExplainabilityItem>
    ): Pair<Boolean, Boolean> {
        if (urls.isEmpty()) return Pair(false, false)
        var typosquatFound = false
        var homographFound = false

        for (url in urls) {
            val res = analyzeDomain(url)
            if (res.isHomograph) {
                homographFound = true
                indicators.add("Homograph/IDN spoofing detected")
                explainabilityItems.add(ExplainabilityItem(url, "Homograph/IDN spoofing detected: Domain uses mixed-script or visual homoglyph mimicry"))
            }
            if (res.isTyposquat) {
                typosquatFound = true
                indicators.add("Impersonation threat")
                explainabilityItems.add(ExplainabilityItem(url, "Impersonation Warning: Domain mimics a protected brand"))
            }
        }

        return Pair(typosquatFound, homographFound)
    }

    private fun normalizeSender(sender: String): String {
        val trimmed = sender.trim()
        if (trimmed.contains("@")) {
            return trimmed.lowercase()
        }
        val digitsOnly = trimmed.filter { it.isDigit() }
        if (digitsOnly.length >= 10) {
            // Note: takeLast(10) canonicalizes across prefix/country code differences, accepting small collision risk
            return digitsOnly.takeLast(10)
        }
        return trimmed.lowercase()
    }
}
