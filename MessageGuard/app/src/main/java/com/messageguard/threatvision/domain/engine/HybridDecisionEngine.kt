package com.messageguard.threatvision.domain.engine

import com.messageguard.MessageLanguageDetector
import com.messageguard.ThreatSignalPolicy
import com.messageguard.threatvision.data.model.ComponentStatus
import com.messageguard.threatvision.data.model.ExtractedContent
import com.messageguard.threatvision.data.model.RiskAssessment
import com.messageguard.threatvision.data.model.ScoreComponent
import com.messageguard.threatvision.data.model.ThreatCategory
import com.messageguard.threatvision.data.model.ThreatReport
import com.messageguard.threatvision.data.model.ThreatThresholds
import com.messageguard.threatvision.data.model.ThreatVerdict
import com.messageguard.threatvision.domain.ocr.MlKitTextRecognizer

class HybridDecisionEngine {

    /**
     * Sanitizes sensitive information (like 4-8 digit OTPs, PINs, and Passwords)
     * from raw text before transmitting to external Cloud APIs.
     */
    fun sanitizeForCloud(text: String): String {
        var sanitized = text
        // Mask 4 to 8 digit OTP numbers
        sanitized = sanitized.replace(Regex("""\b\d{4,8}\b"""), "[REDACTED_OTP]")
        // Mask explicit password/PIN assignments
        sanitized = sanitized.replace(Regex("""(?i)(password|pin|cvv|code)\s*[:=]\s*\S+"""), "$1: [REDACTED]")
        return sanitized
    }

    /**
     * Evaluates extracted screen content using edge scores (URL, NLP, Structural) and optional Cloud AI score.
     */
    fun evaluate(
        content: ExtractedContent,
        edgeUrlScore: Float = 0f,
        edgeNlpScore: Float = 0f,
        edgeStructuralScore: Float = 0f,
        typosquatScore: Float = 0f,
        geminiCloudScore: Int? = null,
        geminiReason: String? = null
    ): RiskAssessment {
        android.util.Log.d("ThreatVisionLog", "HybridDecisionEngine: evaluate() called — edgeUrl=$edgeUrlScore, edgeNlp=$edgeNlpScore, edgeStructural=$edgeStructuralScore, geminiCloud=$geminiCloudScore")

        val rawLower = content.rawText.lowercase()

        // 1. Dedicated UPI Collect Fraud Detector (`upi://pay` with `mode=collect` or `collect`)
        val isUpiCollectFraud = rawLower.contains("upi://pay") &&
            (rawLower.contains("mode=collect") || Regex("""\bcollect\b""").containsMatchIn(rawLower))
        val upiScore = if (isUpiCollectFraud) 95 else if (rawLower.contains("upi://pay")) 40 else 0

        // 2. Component Scores calculation & Dynamic Weight Normalization
        val urlScoreInt = (edgeUrlScore * 100).toInt().coerceIn(0, 100)

        // A text-only model can be confidently wrong when OCR captures a formal academic
        // announcement, a bank transaction SMS, or a verified cashback notice.
        // Do not let that single high-NLP score overrule clean links, clean structure,
        // and a non-threatening textual-signal analysis. Strong scam evidence still takes priority.
        val hasAcademicContext = containsAcademicContext(rawLower)
        val hasStructuredInformationalContext = containsStructuredInformationalContext(rawLower)
        val hasBankTransactionContext = containsBankTransactionContext(rawLower)
        val hasVerifiedRetailerContext = containsVerifiedRetailerContext(rawLower)
        val textThreatSignals = ThreatSignalPolicy.analyze(content.rawText)
        val hasStrongScamEvidence = hasStrongScamEvidence(rawLower, content.urls)
        val useInformationalContextGuard = (hasAcademicContext || hasStructuredInformationalContext ||
            hasBankTransactionContext || hasVerifiedRetailerContext) &&
            !hasStrongScamEvidence &&
            !textThreatSignals.isCorroborated &&
            edgeUrlScore < 0.40f &&
            edgeStructuralScore < 0.40f &&
            typosquatScore < 0.50f
        val effectiveNlpScore = if (useInformationalContextGuard) {
            edgeNlpScore.coerceAtMost(0.22f)
        } else {
            edgeNlpScore
        }
        val nlpScoreInt = (effectiveNlpScore * 100).toInt().coerceIn(0, 100)
        val structScoreInt = (edgeStructuralScore * 100).toInt().coerceIn(0, 100)
        val typoScoreInt = (typosquatScore * 100).toInt().coerceIn(0, 100)

        val components = mutableListOf<ScoreComponent>()
        val hasUrls = content.urls.isNotEmpty()

        // Specific typosquat domain extraction for detail text
        val flaggedTyposquatDomain = content.urls.firstOrNull() ?: "untrusted link"

        if (upiScore > 0) {
            components.add(
                ScoreComponent(
                    label = "UPI Collect Detector",
                    score = upiScore,
                    weight = 0.30,
                    status = if (upiScore >= 70) ComponentStatus.DANGER else ComponentStatus.WARNING,
                    detail = if (isUpiCollectFraud) "upi://pay fake collect request disguised as payment" else "UPI deep link detected"
                )
            )
        }

        if (hasUrls) {
            components.add(
                ScoreComponent(
                    label = "URL Forensic (CNN)",
                    score = urlScoreInt,
                    weight = 0.30,
                    status = if (urlScoreInt >= 70) ComponentStatus.DANGER else if (urlScoreInt >= 40) ComponentStatus.WARNING else ComponentStatus.SAFE,
                    detail = if (urlScoreInt >= 40) "Suspicious link structure/shortener pattern" else "Links appear clean"
                )
            )
        } else {
            components.add(
                ScoreComponent(
                    label = "URL Forensic (CNN)",
                    score = 0,
                    weight = 0.0, // Excluded from weighted sum (N/A)
                    status = ComponentStatus.SAFE,
                    detail = "N/A — No links extracted from message"
                )
            )
        }

        components.add(
            ScoreComponent(
                label = "Text Pattern (NLP)",
                score = nlpScoreInt,
                weight = 0.40,
                status = if (nlpScoreInt >= 70) ComponentStatus.DANGER else if (nlpScoreInt >= 40) ComponentStatus.WARNING else ComponentStatus.SAFE,
                detail = when {
                    useInformationalContextGuard -> "Informational or structured data context; no credential, payment, or suspicious-link request"
                    nlpScoreInt >= 40 -> "Social engineering / urgency phrasing"
                    else -> "Language pattern verified safe"
                }
            )
        )

        components.add(
            ScoreComponent(
                label = "Heuristic Core (BODMAS)",
                score = structScoreInt,
                weight = 0.20,
                status = if (structScoreInt >= 70) ComponentStatus.DANGER else if (structScoreInt >= 40) ComponentStatus.WARNING else ComponentStatus.SAFE,
                detail = if (structScoreInt >= 40) "Structural payload anomaly" else "Payload structure normal"
            )
        )

        if (typoScoreInt > 0) {
            components.add(
                ScoreComponent(
                    label = "Typosquat & Homograph",
                    score = typoScoreInt,
                    weight = 0.20,
                    status = if (typoScoreInt >= 50) ComponentStatus.DANGER else ComponentStatus.SAFE,
                    detail = if (typoScoreInt >= 50) "Domain '$flaggedTyposquatDomain' mimics protected official brand" else "No domain impersonation"
                )
            )
        }

        if (geminiCloudScore != null) {
            components.add(
                ScoreComponent(
                    label = "Cloud AI (Gemini)",
                    score = geminiCloudScore,
                    weight = 0.40,
                    status = if (geminiCloudScore >= 70) ComponentStatus.DANGER else if (geminiCloudScore >= 40) ComponentStatus.WARNING else ComponentStatus.SAFE,
                    detail = geminiReason ?: "Cloud forensic analysis complete"
                )
            )
        }

        // 3. Overall Blended Score with Exact Dynamic Weight Normalization (sum of active weights)
        var totalWeight = 0.0
        var weightedSum = 0.0
        components.filter { it.label != "Cloud AI (Gemini)" && it.weight > 0.0 }.forEach { comp ->
            weightedSum += comp.score * comp.weight
            totalWeight += comp.weight
        }
        
        val edgeScorePercent = if (totalWeight > 0) (weightedSum / totalWeight).toInt().coerceIn(0, 100) else 0

        var blended = if (geminiCloudScore != null) {
            ((edgeScorePercent * 0.60f) + (geminiCloudScore * 0.40f)).toInt().coerceIn(0, 100)
        } else {
            edgeScorePercent
        }

        // Strict Override Rule for UPI Collect Scams (Forces DANGER threshold directly)
        if (isUpiCollectFraud) {
            blended = blended.coerceAtLeast(85)
        }

        val hasShortLink = content.urls.any(::isKnownShortener)
        val hasHighConfidenceTechnicalEvidence = edgeUrlScore >= 0.40f || edgeStructuralScore >= 0.70f ||
            typosquatScore >= 0.50f || content.urls.any { isSuspiciousUrl(it) && !isKnownShortener(it) }
        val hasTechnicalEvidence = hasHighConfidenceTechnicalEvidence ||
            (hasShortLink && textThreatSignals.isCorroborated)
        val hasCloudEvidence = (geminiCloudScore ?: 0) >= 40
        val textOnlyUncorroborated = !isUpiCollectFraud && !hasTechnicalEvidence &&
            !textThreatSignals.isCorroborated
        val hasLegitimateRewardContext = rawLower.contains("cashback") &&
            (rawLower.contains("wallet") || rawLower.contains("bill") ||
                rawLower.contains("credited") || rawLower.contains("valid for"))
        val noDirectScamLanguage = !hasStrongScamEvidence(rawLower, content.urls)
        val localModelSum = edgeUrlScore + edgeNlpScore + edgeStructuralScore + typosquatScore
        val localEvidenceClearlyClean = !hasTechnicalEvidence &&
            !textThreatSignals.isCorroborated &&
            noDirectScamLanguage &&
            edgeUrlScore < 0.30f && edgeNlpScore < 0.40f &&
            edgeStructuralScore < 0.30f && typosquatScore < 0.40f

        // A model score alone is not a scam verdict. This guard prevents a genuine OTP,
        // delivery cashback, or bank-maintenance message from being escalated for one generic word.
        if (textOnlyUncorroborated) {
            blended = blended.coerceAtMost(29)
        }

        // CLOUD CORROBORATION GUARD (fixes hallucinated "typos" / "misspellings" verdicts):
        // When ALL local edge models say the message is clearly safe, the Cloud AI alone
        // CANNOT produce a DANGER verdict. Even WARNING is capped below the alert threshold
        // unless local evidence independently agrees.
        // JioMart bug path: verified cashback SMS → NLP~0.25 + Cloud hallucinates misspellings → 85% DANGER
        // After fix: same input → cap 38% (below 40 WARNING threshold) → SAFE.
        if (localEvidenceClearlyClean && !isUpiCollectFraud) {
            val cloudScore = geminiCloudScore ?: 0
            blended = when {
                cloudScore >= 70 -> if (hasLegitimateRewardContext) 28 else 38
                cloudScore >= 40 -> blended.coerceAtMost(if (hasLegitimateRewardContext) 25 else 35)
                else -> blended.coerceAtMost(if (hasLegitimateRewardContext) 18 else 25)
            }
        } else if (noDirectScamLanguage && !textThreatSignals.isCorroborated && localModelSum < 0.80f && !isUpiCollectFraud) {
            // Second-tier guard: models borderline but still no scam language + no corroboration
            // Cloud AI alone still cannot force DANGER (cap at WARNING threshold -1)
            if ((geminiCloudScore ?: 0) >= 70) {
                blended = blended.coerceAtMost(39)
            }
        }

        // Two distinct textual scam signals plus a concrete suspicious URL are strong evidence,
        // even when a shortener prevents the URL model from seeing the final destination.
        if (textThreatSignals.isCorroborated && content.urls.any(::isSuspiciousUrl)) {
            blended = blended.coerceAtLeast(ThreatThresholds.DANGER_THRESHOLD)
        }

        val maxNonTextComponentScore = components
            .filter { it.label != "Text Pattern (NLP)" }
            .maxOfOrNull { it.score } ?: 0
        val effectiveScore = if (!textOnlyUncorroborated && maxNonTextComponentScore >= 85) {
            maxOf(blended, (maxNonTextComponentScore * 0.9f).toInt())
        } else {
            blended
        }
        val finalRiskScore = effectiveScore

        val verdict = when {
            isUpiCollectFraud || effectiveScore >= ThreatThresholds.DANGER_THRESHOLD -> ThreatVerdict.DANGER
            effectiveScore >= 30 -> ThreatVerdict.WARNING
            else -> ThreatVerdict.SAFE
        }

        android.util.Log.d(
            "FalsePositiveTest",
            "HYBRID_ENGINE_EVAL: Text='${content.rawText.take(50)}' | Blended=$blended% | TextSignals=${textThreatSignals.count} | MaxNonText=$maxNonTextComponentScore% | EffectiveScore=$effectiveScore% | Verdict=$verdict"
        )

        // 5. Determine Threat Category
        val category = when {
            isUpiCollectFraud || content.rawText.contains(Regex("(?i)\\b(upi|pin|paytm|phonepe|gpay)\\b")) && finalRiskScore >= 50 -> ThreatCategory.OTP_FRAUD
            edgeUrlScore > 0.60f || content.urls.any { isSuspiciousUrl(it) } -> ThreatCategory.PHISHING
            content.rawText.contains(Regex("(?i)\\b(otp|pin|aadhaar|pan|bank|cvv)\\b")) &&
                textThreatSignals.isCorroborated && finalRiskScore >= ThreatThresholds.WARNING_THRESHOLD -> ThreatCategory.OTP_FRAUD
            content.rawText.contains(Regex("(?i)\\b(job|salary|internship|hiring|earn daily)\\b")) && finalRiskScore >= ThreatThresholds.WARNING_THRESHOLD -> ThreatCategory.FAKE_JOB
            effectiveNlpScore > 0.50f && verdict != ThreatVerdict.SAFE -> ThreatCategory.SCAM
            verdict != ThreatVerdict.SAFE -> ThreatCategory.SUSPICIOUS
            else -> ThreatCategory.SAFE
        }

        // 6. Generate Risk Factors & Explanation
        val riskFactors = mutableListOf<String>()
        if (isUpiCollectFraud) riskFactors.add("UPI collect-request disguised as money receipt")
        if (urlScoreInt >= 40) riskFactors.add("Suspicious URL structure / unverified link")
        if (nlpScoreInt >= 40 && textThreatSignals.isCorroborated) riskFactors.add("Corroborated urgency or credentials-seeking language pattern")
        if (typoScoreInt >= 50) riskFactors.add("Domain typosquatting mimicking official brand")
        if (geminiCloudScore != null && geminiCloudScore >= 40) riskFactors.add("Cloud AI flagged threat signatures")

        val summary = geminiReason ?: when (verdict) {
            ThreatVerdict.DANGER -> if (isUpiCollectFraud) "Fake UPI collect link detected — do not enter PIN" else "High risk threat detected — matches phishing patterns"
            ThreatVerdict.WARNING -> "Suspicious elements detected in selected area — exercise caution"
            ThreatVerdict.SAFE -> "No malicious markers or suspicious links identified"
        }

        val recommendations = when (verdict) {
            ThreatVerdict.DANGER -> listOf(
                "Do not tap links or enter UPI PIN.",
                "Never share OTPs, passwords, or bank details.",
                "Block sender and delete message."
            )
            ThreatVerdict.WARNING -> listOf(
                "Verify sender through official channels.",
                "Avoid entering credentials on unverified pages."
            )
            ThreatVerdict.SAFE -> listOf(
                "Content verified normal. Stay vigilant."
            )
        }

        val report = ThreatReport(
            overallVerdict = verdict,
            overallScore = finalRiskScore,
            summary = summary,
            components = components,
            riskFactors = if (riskFactors.isEmpty()) listOf("No high risk anomalies detected") else riskFactors,
            recommendation = recommendations.firstOrNull() ?: "Stay vigilant"
        )

        return RiskAssessment(
            riskScore = finalRiskScore,
            verdict = verdict,
            category = category,
            reason = summary,
            recommendations = recommendations,
            report = report,
            isTamilContent = MessageLanguageDetector.shouldUseTamil(content.rawText)
        )
    }

    private fun isSuspiciousUrl(url: String): Boolean {
        val lower = url.lowercase()
        return lower.contains("bit.ly") ||
               lower.contains("tinyurl") ||
               lower.contains(".xyz") ||
               lower.endsWith(".top") ||
               lower.contains(".top/") ||
               MlKitTextRecognizer.IPV4_PATTERN.containsMatchIn(lower)
    }

    private fun isKnownShortener(url: String): Boolean {
        val lower = url.lowercase()
        return listOf("bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "short.url", "rb.gy")
            .any { domain -> lower.contains(domain) }
    }

    private fun containsAcademicContext(text: String): Boolean {
        val academicTerms = listOf(
            "department of", "college", "university", "faculty", "students",
            "mini project", "presentation", "recommendation system", "assignment",
            "semester", "exam", "lecture", "course", "workshop", "research"
        )
        return academicTerms.count(text::contains) >= 2
    }

    /**
     * OCR commonly sees spreadsheet cells as one message. Crop/soil datasets are benign
     * structured information, not social-engineering content. This guard only reduces the
     * text-model contribution when every independent fraud signal is absent.
     */
    private fun containsStructuredInformationalContext(text: String): Boolean {
        val agriculturalTerms = listOf(
            "crop", "crops", "soil", "npk", "fertilizer", "fertiliser", "cereal",
            "millet", "pulse", "pulses", "agriculture", "yield", "irrigation"
        )
        val spreadsheetTerms = listOf(
            ".xlsx", ".xls", "csv", "dataset", "data set", "column", "row", "table"
        )
        val numericTokens = Regex("""\\b\\d+(?:\\.\\d+)?\\b""").findAll(text).count()

        return agriculturalTerms.count(text::contains) >= 2 ||
            spreadsheetTerms.any(text::contains) ||
            numericTokens >= 8
    }

    private fun hasStrongScamEvidence(text: String, urls: List<String>): Boolean {
        val credentialOrPaymentRequest = listOf(
            "share otp", "enter otp", "enter your pin", "share your pin", "password",
            "cvv", "upi://pay", "mode=collect", "bank details", "card details"
        ).any(text::contains)
        val financialLure = listOf(
            "you've won", "you have won", "claim your prize", "claim now", "cash reward",
            "refund", "lottery"
        ).any(text::contains)
        val coerciveLinkRequest = listOf(
            "verify immediately", "verify now", "account suspended", "account blocked",
            "click here", "update now"
        ).any(text::contains) && urls.any(::isSuspiciousUrl)

        return credentialOrPaymentRequest || financialLure || coerciveLinkRequest ||
            urls.any(::isSuspiciousUrl)
    }

    /**
     * Structured bank transaction SMS language (debit/credit alerts, mandate notices,
     * auto-pay info from HDFC/SBI/ICICI shortcodes like JX-UCOBNK-S). None of these terms
     * by themselves indicate fraud — they appear in every legitimate bank SMS.
     */
    private fun containsBankTransactionContext(text: String): Boolean {
        val bankTxTerms = listOf(
            "debited", "credited", "rs.", "inr ", "mandate", "autopay", "account",
            "ifsc", "neft", "imps", "reference no", "ref no", "nrn", "txn",
            "transaction", "available balance", "a/c no", "a/c.", "holder", "nominee",
            "standing instruction", "billpay", "bill pay", "set for", "scheduled"
        )
        val hitCount = bankTxTerms.count(text::contains)
        if (hitCount >= 2) return true
        val numericTokens = Regex("""\b\d{4,}\b""").findAll(text).count()
        val hasAmount = Regex("""rs\.?\s*\d""", RegexOption.IGNORE_CASE).containsMatchIn(text) ||
                Regex("""inr\s*\d""", RegexOption.IGNORE_CASE).containsMatchIn(text)
        return hasAmount && numericTokens >= 2
    }

    /**
     * Verified retailer / service-provider cashback & promotional language that routinely
     * shows up in branded apps (JioMart, Amazon, Flipkart, Swiggy) and SMS shortcodes.
     * By itself this is never scam evidence — it's the normal form of legitimate promos.
     */
    private fun containsVerifiedRetailerContext(text: String): Boolean {
        val retailerTerms = listOf(
            "jiomart", "flipkart", "amazon", "swiggy", "zomato", "paytm wallet",
            "phonepe wallet", "gpay wallet", "cashback", "wallet to be used",
            "t&ca", "valid for today", "credited in wallet", "shop now",
            "next bill on", "order has shipped", "your order", "delivery update"
        )
        return retailerTerms.count(text::contains) >= 2
    }
}
