package com.messageguard.sandbox.report

import com.messageguard.sandbox.scan.ScanVerdict
import com.messageguard.sandbox.scan.ThreatCategory
import org.json.JSONArray

/**
 * Rule-based plain-language summary generator.
 *
 * Translates a [ScanReport]'s signal breakdown into 1–3 plain sentences that a non-technical
 * user can read and act on. Deliberately rule-based (no LLM call) to avoid latency, network
 * dependency, and cost in the scan hot path.
 *
 * Output contract:
 *  - [plainSummary]: 1–3 sentences, human-readable, no internal signal names.
 *  - [technicalDetail]: raw scores and finding list for the expandable "Technical Details" section.
 */
object ScanSummaryGenerator {

    data class Summary(val plainSummary: String, val technicalDetail: String)

    /**
     * Holds a parsed view of the findings JSON for rule matching.
     * Each entry is a (category-name, description, severity) triple.
     */
    private data class FindingInfo(val cat: String, val desc: String, val sev: Int)

    fun generate(report: ScanReport): Summary {
        val verdict = runCatching { ScanVerdict.valueOf(report.verdict) }.getOrDefault(ScanVerdict.INCONCLUSIVE)
        val findings = parseFindings(report.findingsJson)

        val plain = buildPlainSummary(verdict, findings, report)
        val technical = buildTechnicalDetail(report, findings)
        return Summary(plain, technical)
    }

    // -------------------------------------------------------------------------
    // Plain-language summary — ordered by priority (most severe pattern first)
    // -------------------------------------------------------------------------

    private fun buildPlainSummary(
        verdict: ScanVerdict,
        findings: List<FindingInfo>,
        report: ScanReport
    ): String {
        val cats = findings.map { ThreatCategory.entries.find { e -> e.name == it.cat } }.toSet()

        val hasExecutable = ThreatCategory.EMBEDDED_EXECUTABLE in cats
        val hasJs = ThreatCategory.EMBEDDED_JAVASCRIPT in cats
        val hasAutoExec = ThreatCategory.AUTO_EXECUTE_ACTION in cats
        val hasHighEntropyCorroborated = findings.any {
            it.cat == ThreatCategory.HIGH_ENTROPY_PACKED.name && it.sev >= 5
        }
        val hasHighEntropyAlone = findings.any {
            it.cat == ThreatCategory.HIGH_ENTROPY_PACKED.name && it.sev < 5
        }
        val hasMalformedStructure = ThreatCategory.SUSPICIOUS_MIME_MISMATCH in cats
        val hasDangerousPerms = ThreatCategory.DANGEROUS_PERMISSIONS in cats
        val isInconclusive = verdict == ScanVerdict.INCONCLUSIVE

        return when {
            // Highest-risk: launch action = direct exploit
            hasExecutable ->
                "This file contains a hidden command that can launch external programs automatically when opened — a hallmark of exploit documents used to install malware. " +
                "Do not open this file and delete it immediately."

            // JS + auto-exec = drive-by exploit
            hasJs && hasAutoExec ->
                "This file embeds executable JavaScript code that runs automatically when opened, without any user interaction. " +
                "This is consistent with a drive-by exploit designed to silently compromise your device."

            // JS alone (no trigger)
            hasJs ->
                "This file contains embedded JavaScript code, which is highly unusual for a standard document. " +
                "Legitimate PDFs almost never include active scripts — this is a strong indicator of a malicious or tampered file."

            // Phishing URL detected by ML ensemble
            verdict == ScanVerdict.MALICIOUS && hasMalformedStructure && hasHighEntropyCorroborated ->
                "This file has a tampered or malformed structure combined with unusually randomised data — " +
                "consistent with an encrypted or packed payload designed to evade detection. It was blocked as a precaution."

            // High entropy + corroborating structural anomaly
            hasHighEntropyCorroborated ->
                "The file's data appears strongly randomised, which — combined with other suspicious structural elements — " +
                "is consistent with an obfuscated or encrypted payload. It may contain hidden malware."

            // Dangerous APK permissions
            hasDangerousPerms ->
                "This app file requests a dangerous combination of system-level permissions commonly used by banking trojans: " +
                "accessibility access, automatic startup on boot, and access to SMS messages or screen overlays."

            // Malformed PDF (no other signals)
            hasMalformedStructure ->
                "This file has a malformed structure (missing standard end markers), which can indicate tampering or an intentionally corrupted document. " +
                "It was flagged as suspicious but no active exploit was found."

            // Uncorroborated high entropy (false-positive territory)
            hasHighEntropyAlone ->
                "The file's data randomness is elevated (entropy ${String.format("%.2f", report.entropy)}), but this alone is not conclusive — " +
                "compressed images, fonts, and standard PDF streams commonly produce similar readings in completely benign files. " +
                "No active scripts or executable content were found."

            // Phishing link (ensemble only, no structural)
            verdict == ScanVerdict.MALICIOUS || verdict == ScanVerdict.SUSPICIOUS ->
                "The file was flagged for containing patterns associated with phishing or social engineering — " +
                "such as suspicious links or deceptive text. Treat with caution."

            // Safe
            verdict == ScanVerdict.SAFE ->
                "No suspicious structures, scripts, embedded executables, or anomalous data patterns were found in this file. " +
                "It appears safe based on static analysis."

            // Inconclusive
            isInconclusive ->
                "This file could not be fully analysed — it may have been empty, inaccessible, or in a format that could not be scanned. " +
                "Treat it with caution if you received it from an unknown source."

            else ->
                "The file was scanned and received a verdict of ${verdict.name.lowercase()}. Review the technical details below for specifics."
        }
    }

    // -------------------------------------------------------------------------
    // Technical detail — raw scores for the expandable section
    // -------------------------------------------------------------------------

    private fun buildTechnicalDetail(report: ScanReport, findings: List<FindingInfo>): String {
        val sb = StringBuilder()
        sb.appendLine("Verdict: ${report.verdict}")
        sb.appendLine("Final Score: ${report.finalScore}/100")
        sb.appendLine("Structural Score: ${report.structuralScore}/100")
        sb.appendLine("Ensemble (ML) Score: ${report.ensembleScore}/100")
        sb.appendLine("Shannon Entropy: ${String.format("%.2f", report.entropy)} bits/byte")
        sb.appendLine("SHA-256: ${report.sha256}")
        sb.appendLine("Source App: ${report.sourceApp.ifBlank { "unknown" }}")
        sb.appendLine()
        if (findings.isEmpty()) {
            sb.appendLine("Findings: none")
        } else {
            sb.appendLine("Findings (${findings.size}):")
            findings.forEachIndexed { i, f ->
                sb.appendLine("  ${i + 1}. [${f.cat}] sev=${f.sev} — ${f.desc}")
            }
        }
        if (report.isFalsePositiveFlagged) {
            sb.appendLine()
            sb.appendLine("⚑ Flagged by user as possible false positive.")
            if (report.userNote.isNotBlank()) sb.appendLine("  Note: \"${report.userNote}\"")
        }
        return sb.toString().trimEnd()
    }

    // -------------------------------------------------------------------------
    // JSON parsing — uses Gson to be robust in JVM unit tests and Android runtime
    // -------------------------------------------------------------------------

    private fun parseFindings(json: String): List<FindingInfo> {
        if (json.isBlank()) return emptyList()
        return runCatching {
            val listType = object : com.google.gson.reflect.TypeToken<List<Map<String, Any>>>() {}.type
            val rawList: List<Map<String, Any>> = com.google.gson.Gson().fromJson(json, listType) ?: emptyList()
            rawList.map { map ->
                FindingInfo(
                    cat = map["cat"]?.toString() ?: "NONE",
                    desc = map["desc"]?.toString() ?: "",
                    sev = (map["sev"] as? Number)?.toInt() ?: 0
                )
            }
        }.getOrDefault(emptyList())
    }
}
