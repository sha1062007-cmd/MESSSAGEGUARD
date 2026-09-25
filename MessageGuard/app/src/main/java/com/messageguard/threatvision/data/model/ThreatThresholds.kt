package com.messageguard.threatvision.data.model

object ThreatThresholds {
    // Message-Scanning Thresholds (SMS / Accessibility / Screen OCR)
    // Messages require higher corroboration (Score >= 70) to alert as DANGER because informational,
    // conversational, or retail promo texts frequently use urgency words without containing malware.
    const val SCORE_SAFE_MAX = 39
    const val SCORE_WARNING_MIN = 40
    const val SCORE_DANGER_MIN = 70
    const val SCORE_MAX = 100

    const val WARNING_THRESHOLD = 40
    const val DANGER_THRESHOLD = 70

    // THREE-LEVEL DECISION SYSTEM:
    // LOW RISK:     0-39  (SAFE)
    // MEDIUM RISK:  40-69 (SUSPICIOUS / WARNING)
    // HIGH RISK:    70-100 (DANGER)
    // UNCERTAIN:    When model disagreement > 0.35 and no dominant model,
    //               the system returns UNCERTAIN instead of forcing a binary decision.
    const val UNCERTAINTY_DISAGREEMENT_THRESHOLD = 0.35f

    // Disagreement-Resolver Boundary Range:
    // Only scores in the 35..65 range call Cloud Gemini for disambiguation.
    const val DISAGREEMENT_BOUNDARY_MIN = 35
    const val DISAGREEMENT_BOUNDARY_MAX = 65

    // Pre-Download File Sandbox Thresholds:
    // DELIBERATE ASYMMETRY: SANDBOX_MALICIOUS_MIN is set to 60 (rather than 70) because
    // downloaded documents (PDF/APK/binary payloads) carry significantly higher risk of persistent
    // device compromise upon opening than ephemeral text messages. A file scoring >= 60 in structural
    // anomalies or embedded phishing URLs warrants blocking before user execution.
    const val SANDBOX_SAFE_MAX = 19
    const val SANDBOX_SUSPICIOUS_MIN = 20
    const val SANDBOX_MALICIOUS_MIN = 60
}


