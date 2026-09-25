package com.messageguard.threatvision.data.model

enum class ComponentStatus {
    SAFE, WARNING, DANGER
}

data class ScoreComponent(
    val label: String,
    val score: Int,
    val weight: Double,
    val status: ComponentStatus,
    val detail: String? = null
)

data class ThreatReport(
    val overallVerdict: ThreatVerdict,
    val overallScore: Int,
    val summary: String,
    val components: List<ScoreComponent>,
    val riskFactors: List<String>,
    val recommendation: String
)

data class RiskAssessment(
    val riskScore: Int, // 0 to 100
    val verdict: ThreatVerdict,
    val category: ThreatCategory,
    val reason: String,
    val recommendations: List<String>,
    val report: ThreatReport? = null,
    /** False when OCR did not produce readable text; this is not a SAFE verdict. */
    val isComplete: Boolean = true,
    /** Used only to choose the result language. It does not change the verdict. */
    val isTamilContent: Boolean = false,
    // Additive Forensic Fields (Section 1 & Section 5)
    val secondaryCategories: List<ThreatCategory> = emptyList(),
    val forwardingEvidenceLevel: String? = null,
    val forwardedBy: String? = null,
    val originalSender: String? = null,
    val observedInfrastructure: String? = null,
    val authStatusSummary: String? = null,
    val domainIntelligenceSummary: String? = null,
    val correlationSummary: String? = null,
    val campaignSummary: String? = null,
    val investigationGraphSummary: String? = null,
    /** Backend PS106 case_id (e.g. "PS106-ABCD1234") set when the assessment was produced by the backend pipeline. Null for local Circle-to-Scan results. */
    val backendCaseId: String? = null,
    /** Sender email address, used to deep-link "Open in Gmail" to filter the inbox for this sender. */
    val senderEmail: String? = null,
    /** Raw JSON string from the backend /api/analyze-trigger response, used to restore DetailActivity state. */
    val backendAnalysisJson: String? = null
)
