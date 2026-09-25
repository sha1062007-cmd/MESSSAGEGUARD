package com.messageguard.threatvision.domain.usecase

import android.graphics.Bitmap
import com.messageguard.threatvision.data.local.ThreatDao
import com.messageguard.threatvision.data.local.entity.ThreatScanEntity
import com.messageguard.threatvision.data.model.ExtractedContent
import com.messageguard.threatvision.data.model.RiskAssessment
import com.messageguard.threatvision.data.model.ThreatCategory
import com.messageguard.threatvision.data.model.ThreatVerdict
import com.messageguard.threatvision.domain.engine.HybridDecisionEngine
import com.messageguard.threatvision.domain.ocr.MlKitTextRecognizer

class AnalyzeSelectedRegionUseCase(
    private val textRecognizer: MlKitTextRecognizer,
    private val hybridDecisionEngine: HybridDecisionEngine,
    private val threatDao: ThreatDao,
    private val context: android.content.Context
) {

    suspend fun execute(croppedBitmap: Bitmap, geminiCloudScore: Int? = null, geminiReason: String? = null): RiskAssessment {
        // 1. Run QR Detector & ML Kit OCR to extract text, QR codes & entities
        val qrResult = try {
            com.messageguard.QrPhishingDetector.scanBitmap(croppedBitmap)
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            android.util.Log.w("ThreatVisionLog", "QR Scan exception", e)
            com.messageguard.QrAnalysisResult()
        }

        val content: ExtractedContent = try {
            val ocrExtracted = textRecognizer.extractTextFromBitmap(croppedBitmap)
            if (qrResult.qrFound && qrResult.rawPayload.isNotBlank()) {
                val combinedText = if (ocrExtracted.rawText.isBlank()) qrResult.rawPayload else "${ocrExtracted.rawText}\n[QR Payload: ${qrResult.rawPayload}]"
                val combinedUrls = (ocrExtracted.urls + qrResult.rawPayload).distinct().filter { it.startsWith("http://", ignoreCase = true) || it.startsWith("https://", ignoreCase = true) || it.startsWith("upi://", ignoreCase = true) }
                ocrExtracted.copy(rawText = combinedText, urls = combinedUrls)
            } else {
                ocrExtracted
            }
        } catch (error: Exception) {
            if (error is kotlinx.coroutines.CancellationException) throw error
            android.util.Log.w("ThreatVisionLog", "OCR did not complete; returning an incomplete scan result.", error)
            return unavailableAssessment()
        }

        if (content.rawText.isBlank() && !qrResult.qrFound) {
            return unavailableAssessment()
        }

        // 2. Sanitize content before any optional cloud API transmission
        val sanitizedTextForCloud = hybridDecisionEngine.sanitizeForCloud(content.rawText)

        // 3. Evaluate Edge ML & Hybrid decision using SpamAnalyzer models
        val spamAnalyzer = com.messageguard.SpamAnalyzer(context)
        try {
        val indicators = mutableListOf<String>()
        val explainability = mutableListOf<com.messageguard.SpamAnalyzer.ExplainabilityItem>()

        if (qrResult.qrFound) {
            indicators.add("QR Code Intercept: ${qrResult.threatSummary}")
            explainability.add(com.messageguard.SpamAnalyzer.ExplainabilityItem(qrResult.rawPayload.take(50), "QR Analysis: ${qrResult.threatSummary}"))
        }

        val normalizedUrls = content.urls.map { com.messageguard.threatvision.domain.ocr.MlKitTextRecognizer.normalizeDomainOcr(it) }
        val domainRes = normalizedUrls.firstOrNull()?.let { com.messageguard.SpamAnalyzer.analyzeDomain(it) }
        val typosquatScore = if (domainRes?.isTyposquat == true || domainRes?.isHomograph == true || qrResult.isTyposquat || qrResult.isHomograph) 0.95f else 0.0f

        val mlResult = spamAnalyzer.runMlPipelinePublic(
            message = content.rawText,
            urls = normalizedUrls,
            indicators = indicators,
            explainabilityItems = explainability,
            reputationScore = 0.0f
        )

        // Try Cloud AI (Gemini) forensic analysis for non-empty text
        var finalGeminiScore = geminiCloudScore
        var finalGeminiReason = geminiReason

        if (finalGeminiScore == null) {
            val aiDecision = kotlinx.coroutines.withTimeoutOrNull(8000) {
                spamAnalyzer.requestGeminiDirectPublic(sanitizedTextForCloud, indicators)
            }
            if (aiDecision != null && aiDecision.score != -1) {
                finalGeminiScore = aiDecision.score
                finalGeminiReason = aiDecision.summary.ifBlank { aiDecision.reason }
            }
        }

        val assessment = hybridDecisionEngine.evaluate(
            content = content,
            edgeUrlScore = mlResult.urlScore,
            edgeNlpScore = mlResult.nlpScore,
            edgeStructuralScore = mlResult.bodmasScore,
            typosquatScore = typosquatScore,
            geminiCloudScore = finalGeminiScore,
            geminiReason = finalGeminiReason
        )

        // 4. Persist scan result to local Room DB (ONLY user-selected text)
        val entity = ThreatScanEntity(
            extractedText = content.rawText,
            extractedUrls = content.urls.joinToString(","),
            riskScore = assessment.riskScore,
            verdict = assessment.verdict.name,
            threatCategory = assessment.category.name,
            detectionReason = assessment.reason,
            recommendedActions = assessment.recommendations.joinToString("|"),
            timestamp = System.currentTimeMillis()
        )
        threatDao.insertScan(entity)

        // MediaProjectionService is the single Circle-to-Scan alert owner. Keeping this use
        // case side-effect free prevents duplicate Resend alerts for one scan.
        return assessment
        } finally {
            spamAnalyzer.close()
        }
    }

    companion object {
        fun unavailableAssessment() = RiskAssessment(
            riskScore = 0,
            verdict = ThreatVerdict.SAFE,
            category = ThreatCategory.SAFE,
            reason = "Unable to read text clearly via OCR. For Tamil and regional languages, please use Accessibility Scan.",
            recommendations = listOf(
                "Use Accessibility Scan for 100% accurate reading of Tamil / regional text without OCR.",
                "Or re-circle only Latin / English text with high contrast."
            ),
            isComplete = false
        )
    }
}

