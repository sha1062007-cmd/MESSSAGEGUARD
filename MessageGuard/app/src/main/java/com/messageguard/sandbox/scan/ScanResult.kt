package com.messageguard.sandbox.scan

enum class ScanVerdict {
    SAFE,
    SUSPICIOUS,
    MALICIOUS,
    INCONCLUSIVE
}

enum class ThreatCategory {
    EMBEDDED_JAVASCRIPT,
    AUTO_EXECUTE_ACTION,
    EMBEDDED_EXECUTABLE,
    HIGH_ENTROPY_PACKED,
    DANGEROUS_PERMISSIONS,
    SUSPICIOUS_MIME_MISMATCH,
    INCONCLUSIVE_INACCESSIBLE,
    INCONCLUSIVE_ERROR,
    NONE
}

data class ThreatFinding(
    val category: ThreatCategory,
    val description: String,
    val severity: Int // 1 (low) to 10 (critical)
)

data class ScanResult(
    val itemId: String,
    val fileName: String,
    val fileSize: Long,
    val sha256: String,
    val verdict: ScanVerdict,
    val threatScore: Int,       // 0 to 100 — final combined score
    val structuralScore: Int,   // 0 to 100 — structural heuristics sub-score
    val ensembleScore: Int,     // 0 to 100 — ML ensemble sub-score (0 if skipped)
    val findings: List<ThreatFinding>,
    val scanDurationMs: Long,
    val entropy: Double
)
