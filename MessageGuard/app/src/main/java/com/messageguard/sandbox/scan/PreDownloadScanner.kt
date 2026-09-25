package com.messageguard.sandbox.scan

import android.content.Context
import com.messageguard.SpamAnalyzer
import com.messageguard.threatvision.data.model.ThreatThresholds
import java.util.Locale

data class PreDownloadScanResult(
    val fileName: String,
    val sourcePackage: String,
    val preDownloadScore: Int,
    val metadataHeuristicScore: Int,
    val fastMlScore: Int,
    val verdict: ScanVerdict,
    val findings: List<String>,
    val scanDurationMs: Long
)

/**
 * Pre-Download Preliminary Scanner Engine:
 * Performs metadata heuristic checks + fast-path ML evaluation on download notifications / URLs / metadata
 * BEFORE the full file payload lands on disk.
 *
 * Formula: preDownloadScore = (0.50 * metadataHeuristicScore) + (0.50 * fastMlScore)
 */
object PreDownloadScanner {

    private const val TAG = "PreDownloadScanner"

    private val EXECUTABLE_EXTENSIONS = listOf(
        ".apk", ".exe", ".vbs", ".scr", ".bat", ".cmd", ".js", ".ps1", ".jar", ".dex", ".dll", ".hta"
    )

    fun evaluatePreDownload(
        context: Context,
        fileName: String,
        sourcePackage: String,
        sourceUrl: String? = null,
        expectedMimeType: String? = null,
        declaredSizeBytes: Long = 0L
    ): PreDownloadScanResult {
        val startTime = System.currentTimeMillis()
        val findings = mutableListOf<String>()

        val lowerName = fileName.lowercase(Locale.ROOT)
        var metadataScore = 0

        // 1. Double extension / Mismatched Extension Heuristics (e.g. photo.jpg.apk or photo.jpg that is 40MB)
        val hasDoubleExtension = Regex("""\.[a-z0-9]{2,4}\.(apk|exe|vbs|bat|cmd|js|ps1|scr|jar)$""").containsMatchIn(lowerName)
        if (hasDoubleExtension) {
            metadataScore += 50
            findings.add("Double-extension detected (e.g. deceptive filename ending in executable extension)")
        }

        val ext = lowerName.substringAfterLast('.', "")
        if (ext.isNotEmpty() && EXECUTABLE_EXTENSIONS.contains(".$ext")) {
            metadataScore += 30
            findings.add("Executable/package installer extension detected (.$ext)")
        }

        // File-size vs Type Anomaly Check (e.g. image claiming to be 50MB+)
        if ((lowerName.endsWith(".jpg") || lowerName.endsWith(".png") || lowerName.endsWith(".jpeg")) && declaredSizeBytes > 25 * 1024 * 1024) {
            metadataScore += 35
            findings.add("File-size anomaly: Image file claims unusually large size (${declaredSizeBytes / (1024 * 1024)}MB)")
        }

        // 2. Fast-Path ML Model Evaluation (URL CNN / Typosquatting / Reputation)
        var fastMlScore = 0
        if (!sourceUrl.isNullOrBlank()) {
            val spamAnalyzer = SpamAnalyzer(context)
            try {
                val indicators = mutableListOf<String>()
                val explainability = mutableListOf<SpamAnalyzer.ExplainabilityItem>()
                val mlResult = spamAnalyzer.runMlPipelinePublic(
                    message = "",
                    urls = listOf(sourceUrl),
                    indicators = indicators,
                    explainabilityItems = explainability,
                    reputationScore = 0.0f
                )
                fastMlScore = (mlResult.finalScore * 100).toInt().coerceIn(0, 100)
                if (fastMlScore >= 50) {
                    findings.add("Fast-path URL ML engine flagged suspicious link pattern ($fastMlScore%)")
                }
            } catch (_: Exception) {
                fastMlScore = 0
            } finally {
                spamAnalyzer.close()
            }
        }

        metadataScore = metadataScore.coerceIn(0, 100)

        // 3. Weighted Blend & Corroboration Guard
        val blended = (0.50f * metadataScore + 0.50f * fastMlScore).toInt().coerceIn(0, 100)
        
        // Uncorroborated capping: pre-download preliminary scores cap below MALICIOUS_MIN (60)
        // unless both metadata and fast-ML agree or executable extension + double extension match
        val isCorroborated = (metadataScore >= 40 && fastMlScore >= 40) || (hasDoubleExtension && ext == "apk")
        val finalPreScore = if (isCorroborated) blended else blended.coerceAtMost(ThreatThresholds.SANDBOX_MALICIOUS_MIN - 1)

        val verdict = when {
            finalPreScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN -> ScanVerdict.MALICIOUS
            finalPreScore >= ThreatThresholds.SANDBOX_SUSPICIOUS_MIN -> ScanVerdict.SUSPICIOUS
            else -> ScanVerdict.SAFE
        }

        return PreDownloadScanResult(
            fileName = fileName,
            sourcePackage = sourcePackage,
            preDownloadScore = finalPreScore,
            metadataHeuristicScore = metadataScore,
            fastMlScore = fastMlScore,
            verdict = verdict,
            findings = findings,
            scanDurationMs = System.currentTimeMillis() - startTime
        )
    }
}
