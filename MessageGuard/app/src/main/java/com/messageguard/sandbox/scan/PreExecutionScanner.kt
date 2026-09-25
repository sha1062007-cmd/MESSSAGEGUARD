package com.messageguard.sandbox.scan

import android.util.Log
import com.messageguard.sandbox.model.SandboxItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.DataFormatException
import java.util.zip.Inflater
import kotlin.math.ln

/**
 * Phase 3 Pre-Execution Scanning Engine:
 * Performs static structural heuristics on quarantined files before any execution or user opening.
 * Analyzes PDFs, APKs, and generic binaries for hidden macros, launch actions, script injection, and entropy.
 */
object PreExecutionScanner {

    private const val TAG = "PreExecutionScanner"

    // Safety cap for FlateDecode decompression to prevent zip-bomb DoS.
    // A 20MB cap prevents a small compressed file from inflating to gigabytes.
    private const val MAX_DECOMPRESSED_BYTES = 20 * 1024 * 1024
    private const val MAX_COMPRESSED_BYTES = 5 * 1024 * 1024

    // PDF Suspicious structural tags
    private val PDF_DANGEROUS_TAGS = mapOf(
        "/JS" to ThreatFinding(ThreatCategory.EMBEDDED_JAVASCRIPT, "Embedded JavaScript tag detected (/JS)", 8),
        "/JavaScript" to ThreatFinding(ThreatCategory.EMBEDDED_JAVASCRIPT, "Embedded JavaScript dictionary detected (/JavaScript)", 8),
        "/OpenAction" to ThreatFinding(ThreatCategory.AUTO_EXECUTE_ACTION, "Auto-executing OpenAction trigger detected", 7),
        "/AA" to ThreatFinding(ThreatCategory.AUTO_EXECUTE_ACTION, "Automatic Annotation action trigger detected (/AA)", 7),
        "/Launch" to ThreatFinding(ThreatCategory.EMBEDDED_EXECUTABLE, "External application launch action detected (/Launch)", 10),
        "/EmbeddedFiles" to ThreatFinding(ThreatCategory.EMBEDDED_EXECUTABLE, "Hidden embedded payload files detected (/EmbeddedFiles)", 6)
    )

    suspend fun scanItem(item: SandboxItem, context: android.content.Context? = null): ScanResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val file = File(item.quarantinedFilePath)

        if (!file.exists() || file.length() == 0L) {
            Log.w(TAG, "[Scanner] File missing or empty: ${item.quarantinedFilePath}")
            return@withContext ScanResult(
                itemId = item.id,
                fileName = item.originalFileName,
                fileSize = 0L,
                sha256 = item.sha256,
                verdict = ScanVerdict.INCONCLUSIVE,
                threatScore = 0,
                structuralScore = 0,
                ensembleScore = 0,
                findings = listOf(ThreatFinding(ThreatCategory.INCONCLUSIVE_INACCESSIBLE, "File was empty (0 bytes) or inaccessible during capture", 0)),
                scanDurationMs = System.currentTimeMillis() - startTime,
                entropy = 0.0
            )
        }

        val bytes = file.readBytes()
        val entropy = calculateShannonEntropy(bytes)
        val findings = mutableListOf<ThreatFinding>()

        // 1. Check Magic Bytes and Structure
        val isPdf = isPdfFile(bytes)
        val isZipOrApk = isZipOrApk(bytes)

        if (isPdf) {
            scanPdf(bytes, findings)
        } else if (isZipOrApk) {
            scanZipOrApk(bytes, findings)
        }

        // Real PDFs compress content with FlateDecode, which routinely produces whole-file
        // entropy of 7.5–7.85. That is expected content encoding, not packing. Detect it once
        // so the entropy gate can calibrate (Phase 2 real-world false-positive fix).
        val pdfUsesFlateDecode = isPdf &&
            indexOf(bytes, "/FlateDecode".toByteArray(Charsets.US_ASCII), 0) != -1

        // 2. High Entropy Check — corroboration required to reach MALICIOUS.
        //
        // Shannon entropy alone is a weak signal: compressed streams, embedded images, and
        // font subsets in ordinary PDFs routinely produce values in the 7.0–7.9 range.
        // Corroboration rule: entropy is a meaningful escalator ONLY when accompanied by at
        // least one other structural finding of severity >= 5 (not itself).
        //
        // Qualifying corroborators: EMBEDDED_EXECUTABLE, EMBEDDED_JAVASCRIPT,
        // DANGEROUS_PERMISSIONS>=5, SUSPICIOUS_MIME_MISMATCH>=5 (now severity 5), or any
        // other non-entropy finding of severity >= 5.
        if (entropy > 7.5 && bytes.size > 2048) {
            // Phase 2 real-world FP fix: a FlateDecode-compressed PDF in the 7.5–7.9 band is
            // ordinary document compression (observed: 100KB WhatsApp PDF at entropy 7.67
            // falsely flagged SUSPICIOUS). Informational only — sev 1 → score 10 → SAFE.
            // Entropy >= 7.9 on a compressed PDF still escalates (possible packed payload).
            if (isPdf && pdfUsesFlateDecode && entropy < 7.9) {
                findings.add(
                    ThreatFinding(
                        ThreatCategory.HIGH_ENTROPY_PACKED,
                        "Elevated data randomness (entropy $entropy) — expected for FlateDecode-compressed PDF streams; consistent with ordinary document compression",
                        1
                    )
                )
                Log.i(TAG, "[Scanner] Entropy $entropy expected for compressed PDF (FlateDecode present) — severity 1, informational")
            } else {
                val hasCorroboratingFinding = findings.any {
                    it.category != ThreatCategory.HIGH_ENTROPY_PACKED && it.severity >= 5
                }
                if (hasCorroboratingFinding) {
                    // Corroborated: add with full weight — contributes meaningfully alongside the
                    // structural signal that justifies suspicion.
                    findings.add(
                        ThreatFinding(
                            ThreatCategory.HIGH_ENTROPY_PACKED,
                            "High data randomness (entropy $entropy) combined with structural anomalies — consistent with an obfuscated or packed payload",
                            6
                        )
                    )
                    Log.w(TAG, "[Scanner] Entropy $entropy CORROBORATED by structural finding — severity 6")
                } else {
                    // Uncorroborated: entropy alone cannot reach MALICIOUS_MIN=60.
                    // Severity 3 → score 30 → SUSPICIOUS at most. Keeps the signal visible
                    // without triggering a false block.
                    findings.add(
                        ThreatFinding(
                            ThreatCategory.HIGH_ENTROPY_PACKED,
                            "Elevated data randomness (entropy $entropy) — common in compressed or image-heavy files; no structural exploit confirmed",
                            3
                        )
                    )
                    Log.i(TAG, "[Scanner] Entropy $entropy uncorroborated — severity 3, capped at SUSPICIOUS")
                }
            }


        }

        // 2b. /OpenAction and /AA corroboration rule.
        //
        // Relationship-aware structural parsing (in scanPdf) already resolves
        // /OpenAction -> /GoTo (benign) vs /JS /Launch /URI (dangerous) where
        // object structure is parseable. This fallback covers unparsable cases
        // (no indirect objects, raw string match only) via co-occurrence.
        //
        // If structural parser already made a decision (description contains
        // "structural:"), do not override it here.
        val hasExecutionVector = findings.any {
            it.category == ThreatCategory.EMBEDDED_JAVASCRIPT ||
            it.category == ThreatCategory.EMBEDDED_EXECUTABLE
        }
        val hasStructuralDecision = findings.any { it.description.contains("structural:") }
        if (!hasExecutionVector && !hasStructuralDecision) {
            val demotedFindings = findings.map { f ->
                if (f.category == ThreatCategory.AUTO_EXECUTE_ACTION) {
                    Log.i(TAG, "[Scanner] Demoting uncorroborated AUTO_EXECUTE_ACTION '${f.description}' sev ${f.severity} → 3")
                    f.copy(
                        description = "${f.description} (uncorroborated — action type unverified; may be benign GoTo)",
                        severity = 3
                    )
                } else f
            }
            findings.clear()
            findings.addAll(demotedFindings)
        } else if (hasStructuralDecision) {
            Log.i(TAG, "[Scanner] Structural decision present — skipping co-occurrence demotion")
        }

        // 3. Structural Threat Scoring & Hard Exploit Trigger Check
        val hasHardExploitTrigger = findings.any {
            (it.category == ThreatCategory.EMBEDDED_EXECUTABLE && it.severity >= 8) ||
            (it.category == ThreatCategory.EMBEDDED_JAVASCRIPT && findings.any { f -> f.category == ThreatCategory.AUTO_EXECUTE_ACTION }) ||
            (it.category == ThreatCategory.DANGEROUS_PERMISSIONS && it.severity >= 8)
        }

        val rawStructuralScore = (findings.sumOf { it.severity * 10 }).coerceIn(0, 100)
        val structuralScore = if (hasHardExploitTrigger) maxOf(rawStructuralScore, 85) else rawStructuralScore

        // 4. Secondary Multi-Signal Ensemble & Pre-Trained APK Engine Scanning
        var ensembleScore = 0
        if (context != null && !hasHardExploitTrigger) {
            try {
                // If the file is an APK, run the Pre-trained TFLite Neural Threat Engine
                val isApk = item.originalFileName.lowercase().endsWith(".apk") || item.quarantinedFilePath.lowercase().endsWith(".apk")
                if (isApk) {
                    ApkStaticExtractor.extractFeatures(context, file.absolutePath)?.let { vector ->
                        PretrainedApkThreatEngine(context).use { engine ->
                            val apkResult = engine.scanApk(vector)
                            if (apkResult.isMalicious) {
                                ensembleScore = (apkResult.maliciousProbability * 100).toInt().coerceIn(0, 100)
                                findings.add(
                                    ThreatFinding(
                                        ThreatCategory.EMBEDDED_EXECUTABLE,
                                        "Pre-trained APK Neural Engine flagged high threat probability (${(apkResult.maliciousProbability * 100).toInt()}%). Risk factors: ${apkResult.riskFactors.joinToString("; ")}",
                                        9
                                    )
                                )
                            }
                        }
                    }
                }

                // If the file is a PDF, run the Pre-trained PDF ONNX Soft-Voting Ensemble Engine
                if (isPdf) {
                    val pdfFeatures = extractPdfFeatureVector(bytes, findings)
                    if (pdfFeatures.size == 21) {
                        val pretrainedEngine = com.messageguard.ml.PretrainedThreatEngine(context)
                        try {
                            val pdfScore = pretrainedEngine.predictPdfEnsembleScore(pdfFeatures)
                            val pdfEnsembleInt = (pdfScore * 100).toInt().coerceIn(0, 100)
                            ensembleScore = maxOf(ensembleScore, pdfEnsembleInt)
                            if (pdfEnsembleInt >= 72) {
                                findings.add(
                                    ThreatFinding(
                                        ThreatCategory.EMBEDDED_EXECUTABLE,
                                        "Pre-trained PDF ONNX Soft-Voting Ensemble flagged suspicious structure ($pdfEnsembleInt%)",
                                        8
                                    )
                                )
                            }
                        } finally {
                            pretrainedEngine.close()
                        }
                    }
                }

                // Phase 2 FP fix: feed the NLP classifier printable text only for PDFs or text binaries
                val rawText = String(bytes, Charsets.ISO_8859_1)
                val extractedText = Regex("""[\u0020-\u007E\r\n\t]{6,}""").findAll(rawText).joinToString(" ") { it.value }
                val extractedUrls = Regex("""(?i)https?://[^\s<>"'()\\]+""").findAll(extractedText).map { it.value.trimEnd('.', ',', ';') }.distinct().take(10).toList()

                if (extractedUrls.isNotEmpty() || isPdf) {
                    val spamAnalyzer = com.messageguard.SpamAnalyzer(context)
                    try {
                        val indicators = mutableListOf<String>()
                        val explainability = mutableListOf<com.messageguard.SpamAnalyzer.ExplainabilityItem>()
                        val mlResult = spamAnalyzer.runMlPipelinePublic(
                            message = "", // Do not feed raw PDF binary headers (%PDF-1.4) into the text NLP model
                            urls = extractedUrls,
                            indicators = indicators,
                            explainabilityItems = explainability,
                            reputationScore = 0.0f
                        )
                        val textEnsemble = (mlResult.finalScore * 100).toInt().coerceIn(0, 100)
                        ensembleScore = maxOf(ensembleScore, textEnsemble)
                        if (textEnsemble >= 70) {
                            findings.add(ThreatFinding(ThreatCategory.EMBEDDED_JAVASCRIPT, "Embedded phishing link or social engineering pattern detected", 7))
                        }
                    } finally {
                        spamAnalyzer.close()
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "[Scanner] Ensemble secondary scan failed gracefully", e)
            }
        }


        // 5. Symmetric Combination Rule (Offline & Exploit Resilient):
        // a) Hard structural exploits (e.g. /Launch) -> score >= 85 (MALICIOUS).
        // b) High-confidence ensemble (e.g. phishing PDF with clean structure) -> maxOf(structural, ensemble).
        // c) Otherwise, weighted synthesis: max(StructuralScore, (0.40 * Ensemble + 0.60 * Structural))
        val finalThreatScore = when {
            hasHardExploitTrigger -> structuralScore
            ensembleScore >= com.messageguard.threatvision.data.model.ThreatThresholds.SANDBOX_MALICIOUS_MIN -> maxOf(structuralScore, ensembleScore)
            else -> maxOf(structuralScore, (0.40 * ensembleScore + 0.60 * structuralScore).toInt()).coerceIn(0, 100)
        }.coerceAtMost(100)



        val verdict = when {
            finalThreatScore >= com.messageguard.threatvision.data.model.ThreatThresholds.SANDBOX_MALICIOUS_MIN -> ScanVerdict.MALICIOUS
            finalThreatScore >= com.messageguard.threatvision.data.model.ThreatThresholds.SANDBOX_SUSPICIOUS_MIN -> ScanVerdict.SUSPICIOUS
            else -> ScanVerdict.SAFE
        }

        val duration = System.currentTimeMillis() - startTime
        Log.i(TAG, "[Scanner] Completed scan of '${item.originalFileName}' in ${duration}ms. Verdict=$verdict, Score=$finalThreatScore (Struct=$structuralScore, Ens=$ensembleScore), Entropy=$entropy, Findings=${findings.size}")

        ScanResult(
            itemId = item.id,
            fileName = item.originalFileName,
            fileSize = bytes.size.toLong(),
            sha256 = item.sha256,
            verdict = verdict,
            threatScore = finalThreatScore,
            structuralScore = structuralScore,
            ensembleScore = ensembleScore,
            findings = findings,
            scanDurationMs = duration,
            entropy = entropy
        )
    }

    private fun extractPdfFeatureVector(bytes: ByteArray, findings: List<ThreatFinding>): FloatArray {
        val vector = FloatArray(21) { 0.0f }
        val rawText = String(bytes, Charsets.ISO_8859_1)
        
        vector[0] = (bytes.size.toFloat() / (1024f * 1024f)).coerceIn(0f, 10f) // File size MB
        vector[1] = calculateShannonEntropy(bytes).toFloat() // Entropy
        vector[2] = if (findings.any { it.category == ThreatCategory.EMBEDDED_JAVASCRIPT }) 1.0f else 0.0f // JS tag
        vector[3] = if (findings.any { it.category == ThreatCategory.AUTO_EXECUTE_ACTION }) 1.0f else 0.0f // OpenAction/AA
        vector[4] = if (findings.any { it.category == ThreatCategory.EMBEDDED_EXECUTABLE }) 1.0f else 0.0f // Launch/EmbeddedFiles
        vector[5] = if (rawText.contains("/Page")) 1.0f else 0.0f
        vector[6] = if (rawText.contains("/Encrypt")) 1.0f else 0.0f
        vector[7] = if (rawText.contains("/ObjStm")) 1.0f else 0.0f
        vector[8] = if (rawText.contains("/URI")) 1.0f else 0.0f
        vector[9] = if (rawText.contains("/SubmitForm")) 1.0f else 0.0f
        vector[10] = if (rawText.contains("/XFA")) 1.0f else 0.0f
        vector[11] = if (rawText.contains("/RichMedia")) 1.0f else 0.0f
        vector[12] = if (rawText.contains("/Launch")) 1.0f else 0.0f
        vector[13] = if (rawText.contains("/EmbeddedFile")) 1.0f else 0.0f
        vector[14] = if (rawText.contains("/Colors")) 1.0f else 0.0f
        vector[15] = if (rawText.contains("/Font")) 1.0f else 0.0f
        vector[16] = if (rawText.contains("/ProcSet")) 1.0f else 0.0f
        vector[17] = if (rawText.contains("/MediaBox")) 1.0f else 0.0f
        vector[18] = if (rawText.contains("endobj")) 1.0f else 0.0f
        vector[19] = if (rawText.contains("stream")) 1.0f else 0.0f
        vector[20] = if (rawText.contains("xref")) 1.0f else 0.0f
        return vector
    }

    private fun isPdfFile(bytes: ByteArray): Boolean {
        if (bytes.size < 4) return false
        // %PDF
        return bytes[0] == 0x25.toByte() && bytes[1] == 0x50.toByte() &&
               bytes[2] == 0x44.toByte() && bytes[3] == 0x46.toByte()
    }


    private fun isZipOrApk(bytes: ByteArray): Boolean {
        if (bytes.size < 4) return false
        // PK..
        return bytes[0] == 0x50.toByte() && bytes[1] == 0x4B.toByte() &&
               bytes[2] == 0x03.toByte() && bytes[3] == 0x04.toByte()
    }

    private val SUSPICIOUS_PAYLOAD_EXTENSIONS = listOf(
        ".exe", ".apk", ".vbs", ".scr", ".bat", ".cmd", ".js", ".ps1", ".jar", ".dex", ".dll", ".hta"
    )

    // ──────────────────────────────────────────────────────────────────────
    // Structural PDF parser: relationship-aware, replaces bare string matching
    // where possible. Deterministic, no ML, <5ms for typical PDFs.
    // ──────────────────────────────────────────────────────────────────────
    private enum class ResolvedActionType {
        BENIGN_GOTO,        // /S /GoTo — navigates within document
        DANGEROUS_JS,       // /S /JavaScript or /JS
        DANGEROUS_LAUNCH,   // /S /Launch
        DANGEROUS_URI,      // /S /URI
        DANGEROUS_GOTOR,    // /S /GoToR — external file
        DANGEROUS_OTHER,    // /S /SubmitForm, /ImportData, etc.
        UNKNOWN             // could not resolve
    }

    private object PdfStructuralParser {
        private val objPattern = Regex("""(\d+)\s+(\d+)\s+obj(.*?)endobj""", RegexOption.DOT_MATCHES_ALL)
        private val refPattern = Regex("""(\d+)\s+(\d+)\s+R""")
        private val openActionPattern = Regex("""/OpenAction\s+(\d+\s+\d+\s+R|<<.*?>>|/\w+)""", RegexOption.DOT_MATCHES_ALL)
        private val aaPattern = Regex("""/AA\s*<<(.*?)>>""", RegexOption.DOT_MATCHES_ALL)
        private val sTypePattern = Regex("""/S\s*/(\w+)""")
        private val jsInDictPattern = Regex("""/JS\b|/JavaScript\b""")

        fun parseObjects(content: String): Map<String, String> {
            val map = mutableMapOf<String, String>()
            for (m in objPattern.findAll(content)) {
                val key = "${m.groupValues[1]} ${m.groupValues[2]}"
                map[key] = m.groupValues[3]
            }
            return map
        }

        /**
         * Extended parse that also decompresses PDF 1.5+ object streams (/Type /ObjStm).
         * Finds ObjStm objects, decompresses their FlateDecode streams, parses the
         * embedded object index (N / First), and merges embedded objects into the map.
         * Also skips /Type /XRef streams (not parsed as content).
         * Returns merged map and count of ObjStm objects found.
         */
        fun parseObjectsWithObjStm(bytes: ByteArray, content: String): Map<String, String> {
            val classic = parseObjects(content).toMutableMap()
            // Find ObjStm streams in raw bytes
            val objStmEmbedded = extractObjStmObjects(bytes)
            for ((k, v) in objStmEmbedded) {
                if (k !in classic) classic[k] = v
            }
            return classic
        }

        private fun extractObjStmObjects(bytes: ByteArray): Map<String, String> {
            val result = mutableMapOf<String, String>()
            val streamPat = "stream".toByteArray(Charsets.US_ASCII)
            val endStreamPat = "endstream".toByteArray(Charsets.US_ASCII)
            var offset = 0
            while (offset < bytes.size) {
                val sPos = indexOf(bytes, streamPat, offset)
                if (sPos == -1) break
                val dataStart = sPos + streamPat.size
                if (dataStart >= bytes.size) break
                val firstByte = bytes[dataStart].toInt().toChar()
                if (firstByte != '\r' && firstByte != '\n') { offset = sPos + streamPat.size; continue }
                val actualStart = when {
                    dataStart + 1 < bytes.size && bytes[dataStart].toInt().toChar() == '\r' && bytes[dataStart + 1].toInt().toChar() == '\n' -> dataStart + 2
                    else -> dataStart + 1
                }
                val ePos = indexOf(bytes, endStreamPat, actualStart)
                if (ePos == -1) break
                // Check dictionary preceding stream for /Type /ObjStm and /XRef
                val dictStart = maxOf(0, sPos - 2048)
                val dictRegion = String(bytes, dictStart, sPos - dictStart, Charsets.US_ASCII)
                val isObjStm = dictRegion.contains("/Type") && dictRegion.contains("/ObjStm")
                val isXRef = dictRegion.contains("/Type") && dictRegion.contains("/XRef")
                if (isXRef) {
                    // Skip XRef streams — not content, just cross-reference
                    offset = ePos + endStreamPat.size
                    continue
                }
                if (isObjStm) {
                    // Parse N and First from dict
                    val nMatch = Regex("""/N\s+(\d+)""").find(dictRegion)
                    val firstMatch = Regex("""/First\s+(\d+)""").find(dictRegion)
                    val n = nMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0
                    val first = firstMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0
                    if (n > 0 && n < 1000) {
                        val compressed = bytes.copyOfRange(actualStart, ePos)
                        val decompressed = tryDecompressForObjStm(compressed)
                        if (decompressed != null) {
                            val decompressedStr = String(decompressed, Charsets.ISO_8859_1)
                            val embedded = parseObjStmStream(decompressedStr, n, first)
                            for ((k, v) in embedded) result[k] = v
                        }
                    }
                }
                offset = ePos + endStreamPat.size
            }
            return result
        }

        private fun tryDecompressForObjStm(compressed: ByteArray): ByteArray? {
            return try {
                val inflater = Inflater()
                inflater.setInput(compressed)
                val buf = ByteArray(8192)
                val out = mutableListOf<Byte>()
                while (!inflater.finished()) {
                    val len = inflater.inflate(buf)
                    if (len == 0) {
                        if (inflater.needsDictionary()) { inflater.end(); return null }
                        break
                    }
                    for (i in 0 until len) out.add(buf[i])
                    if (out.size > 5 * 1024 * 1024) { inflater.end(); return null }
                }
                inflater.end()
                out.toByteArray()
            } catch (_: Exception) { null }
        }

        private fun parseObjStmStream(decompressed: String, n: Int, first: Int): Map<String, String> {
            val map = mutableMapOf<String, String>()
            // Decompressed stream: "objNum offset objNum offset ... <objects>"
            // Example: "5 0 6 15 << /S /GoTo >> << /S /JavaScript >>"
            // The index occupies First bytes; after that are concatenated objects.
            // We parse by reading 2*N integers, then slicing objects by offsets.
            val tokens = decompressed.trim().split(Regex("\\s+"))
            if (tokens.size < 2 * n) return map
            // Extract index pairs
            val indexPairs = mutableListOf<Pair<Int, Int>>() // objNum, offset
            for (i in 0 until n) {
                val num = tokens[2 * i].toIntOrNull() ?: continue
                val off = tokens[2 * i + 1].toIntOrNull() ?: continue
                indexPairs.add(Pair(num, off))
            }
            if (indexPairs.size != n) return map
            // The objects start at byte offset First in decompressed string
            if (first < 0 || first > decompressed.length) return map
            val objectsSection = decompressed.substring(minOf(first, decompressed.length))
            // Offsets are relative to start of objectsSection (i.e., First)
            // Sort by offset to slice
            val sorted = indexPairs.sortedBy { it.second }
            for (idx in sorted.indices) {
                val (objNum, off) = sorted[idx]
                val nextOff = if (idx + 1 < sorted.size) sorted[idx + 1].second else objectsSection.length
                if (off < 0 || off >= objectsSection.length || nextOff <= off) continue
                val objContent = objectsSection.substring(off, minOf(nextOff, objectsSection.length)).trim()
                // ObjStm objects are bare dictionaries/streams without obj headers; store as "N 0" -> content
                if (objContent.isNotEmpty()) {
                    map["$objNum 0"] = objContent
                }
            }
            return map
        }

        // Byte search helper (duplicated for encapsulation; same as outer indexOf but private here)
        private fun indexOf(haystack: ByteArray, needle: ByteArray, fromIndex: Int): Int {
            if (needle.isEmpty()) return fromIndex
            val first = needle[0]
            val end = haystack.size - needle.size
            var i = fromIndex
            while (i <= end) {
                if (haystack[i] == first) {
                    var match = true
                    for (j in 1 until needle.size) if (haystack[i + j] != needle[j]) { match = false; break }
                    if (match) return i
                }
                i++
            }
            return -1
        }

        fun findCatalogKeys(objects: Map<String, String>): List<String> {
            return objects.filter { (_, body) ->
                body.contains("/Type") && body.contains("/Catalog")
            }.keys.toList()
        }

        fun resolveReference(ref: String, objects: Map<String, String>): String? {
            // ref like "5 0 R" -> key "5 0"
            val parts = ref.trim().split(Regex("\\s+"))
            if (parts.size < 3) return null
            val key = "${parts[0]} ${parts[1]}"
            return objects[key]
        }

        fun extractActionType(dictContent: String): ResolvedActionType {
            val sMatch = sTypePattern.find(dictContent)
            if (sMatch != null) {
                return when (sMatch.groupValues[1]) {
                    "GoTo" -> ResolvedActionType.BENIGN_GOTO
                    "JavaScript", "JS" -> ResolvedActionType.DANGEROUS_JS
                    "Launch" -> ResolvedActionType.DANGEROUS_LAUNCH
                    "URI" -> ResolvedActionType.DANGEROUS_URI
                    "GoToR" -> ResolvedActionType.DANGEROUS_GOTOR
                    "SubmitForm", "ImportData", "Movie", "Sound", "Hide",
                    "SetOCGState", "Rendition", "Trans", "GoTo3DView" -> ResolvedActionType.DANGEROUS_OTHER
                    else -> ResolvedActionType.DANGEROUS_OTHER
                }
            }
            // No /S but contains /JS tag -> dangerous JS
            if (jsInDictPattern.containsMatchIn(dictContent)) {
                return ResolvedActionType.DANGEROUS_JS
            }
            return ResolvedActionType.UNKNOWN
        }

        /**
         * Resolve every /OpenAction in the document to its action type.
         * Returns list of resolved types (one per OpenAction occurrence).
         * Empty list means no OpenAction found.
         */
        fun resolveOpenActions(content: String, objects: Map<String, String>): List<ResolvedActionType> {
            val results = mutableListOf<ResolvedActionType>()
            for (m in openActionPattern.findAll(content)) {
                val raw = m.groupValues[1].trim()
                val dictBody: String? = when {
                    raw.matches(Regex("""\d+\s+\d+\s+R""")) -> resolveReference(raw, objects)
                    raw.startsWith("<<") -> raw
                    raw.startsWith("/") -> {
                        // Direct name like /GoTo — treat as benign only if GoTo
                        if (raw == "/GoTo") {
                            results.add(ResolvedActionType.BENIGN_GOTO)
                            continue
                        } else {
                            null
                        }
                    }
                    else -> null
                }
                if (dictBody != null) {
                    results.add(extractActionType(dictBody))
                } else if (raw.matches(Regex("""\d+\s+\d+\s+R"""))) {
                    // Unresolvable reference -> unknown (orphaned)
                    results.add(ResolvedActionType.UNKNOWN)
                } else {
                    results.add(ResolvedActionType.UNKNOWN)
                }
            }
            return results
        }

        fun resolveAATypes(content: String, objects: Map<String, String>): List<ResolvedActionType> {
            val results = mutableListOf<ResolvedActionType>()
            for (m in aaPattern.findAll(content)) {
                val aaBody = m.groupValues[1]
                // AA dict may contain indirect refs or nested dicts; look for /S inside
                // Also check for refs inside AA
                val refs = refPattern.findAll(aaBody).toList()
                if (refs.isNotEmpty()) {
                    for (r in refs) {
                        val resolved = resolveReference(r.value, objects)
                        if (resolved != null) results.add(extractActionType(resolved))
                        else results.add(ResolvedActionType.UNKNOWN)
                    }
                }
                // Also check direct /S in AA body itself
                val direct = extractActionType(aaBody)
                if (direct != ResolvedActionType.UNKNOWN) {
                    // Avoid duplicate if already added via ref
                    if (results.isEmpty() || results.last() == ResolvedActionType.UNKNOWN) {
                        if (results.isNotEmpty()) results.removeAt(results.lastIndex)
                        results.add(direct)
                    }
                } else if (refs.isEmpty()) {
                    // No ref and no direct S -> check for JS
                    if (jsInDictPattern.containsMatchIn(aaBody)) {
                        results.add(ResolvedActionType.DANGEROUS_JS)
                    } else {
                        results.add(ResolvedActionType.UNKNOWN)
                    }
                }
            }
            return results
        }

        /**
         * Determine if /EmbeddedFiles is reachable from the catalog.
         * Orphaned unreferenced EmbeddedFiles objects should not escalate.
         */
        fun isEmbeddedFilesReachable(content: String, objects: Map<String, String>): Boolean {
            if (objects.isEmpty()) {
                // No parseable objects -> fallback: if /EmbeddedFiles present at all, treat as reachable
                return content.contains("/EmbeddedFiles")
            }
            val catalogKeys = findCatalogKeys(objects)
            if (catalogKeys.isEmpty()) {
                // No catalog found -> cannot determine reachability, treat as reachable (conservative)
                return content.contains("/EmbeddedFiles")
            }
            // BFS from catalog through indirect references
            val reachable = mutableSetOf<String>()
            val queue = ArrayDeque<String>()
            catalogKeys.forEach { queue.add(it); reachable.add(it) }
            while (queue.isNotEmpty()) {
                val cur = queue.removeFirst()
                val body = objects[cur] ?: continue
                for (rm in refPattern.findAll(body)) {
                    val refKey = "${rm.groupValues[1]} ${rm.groupValues[2]}"
                    if (refKey !in reachable && refKey in objects) {
                        reachable.add(refKey)
                        queue.add(refKey)
                    }
                }
            }
            // Check if any reachable object contains /EmbeddedFiles
            for (k in reachable) {
                if (objects[k]?.contains("/EmbeddedFiles") == true) return true
            }
            // Also check catalog body itself (if /EmbeddedFiles is inline, not in separate object)
            // The catalog raw text in content may have it before obj parsing; check via reachable bodies already covers it.
            // As fallback, if no reachable object has it but raw content does, it might be orphaned -> not reachable
            return false
        }

        /** Feature vector for potential classifier: deterministic, cheap. */
        data class StructuralFeatures(
            val entropy: Double,
            val fileSize: Int,
            val objectCount: Int,
            val streamCount: Int,
            val hasFlateDecode: Boolean,
            val jsResolvedDangerous: Boolean,
            val embeddedFilesReachable: Boolean,
            val openActionBenignCount: Int,
            val openActionDangerousCount: Int,
            val maxNestingDepth: Int,
            val filterTypes: Set<String>,
            val compressedToRawRatio: Double
        )

        fun extractFeatures(bytes: ByteArray, content: String, objects: Map<String, String>): StructuralFeatures {
            val streamCount = Regex("""\bstream\b""").findAll(content).count()
            val filterTypes = Regex("""/Filter\s*(?:\[([^\]]+)\]|/(\w+))""").findAll(content).mapNotNull {
                it.groupValues[1].ifEmpty { it.groupValues[2] }
            }.flatMap { it.split(Regex("""\s+""")).map { s -> s.trim().removePrefix("/").removeSuffix("]") } }
                .filter { it.isNotEmpty() }.toSet()
            val openActions = resolveOpenActions(content, objects)
            val benign = openActions.count { it == ResolvedActionType.BENIGN_GOTO }
            val dangerous = openActions.count { it != ResolvedActionType.BENIGN_GOTO && it != ResolvedActionType.UNKNOWN }
            val reachable = isEmbeddedFilesReachable(content, objects)
            // Max nesting: count "<< >>" depth naively
            var depth = 0; var maxDepth = 0
            var i = 0
            while (i < content.length - 1) {
                if (content[i] == '<' && content[i + 1] == '<') { depth++; maxDepth = maxOf(maxDepth, depth); i += 2 } else if (content[i] == '>' && content[i + 1] == '>') { depth = maxOf(0, depth - 1); i += 2 } else i++
            }
            val ratio = if (bytes.isNotEmpty()) streamCount.toDouble() / bytes.size else 0.0
            return StructuralFeatures(
                entropy = 0.0, fileSize = bytes.size, objectCount = objects.size, streamCount = streamCount,
                hasFlateDecode = content.contains("/FlateDecode"),
                jsResolvedDangerous = dangerous > 0,
                embeddedFilesReachable = reachable,
                openActionBenignCount = benign, openActionDangerousCount = dangerous,
                maxNestingDepth = maxDepth, filterTypes = filterTypes, compressedToRawRatio = ratio
            )
        }
    }

    private fun scanPdf(bytes: ByteArray, findings: MutableList<ThreatFinding>) {
        val content = String(bytes, Charsets.ISO_8859_1)

        // Phase 1: Scan raw (uncompressed) content for dangerous tags.
        scanPdfTags(content, findings, "raw")

        // Phase 2: Decompress FlateDecode streams and scan their contents.
        // Malicious payloads hidden inside compressed streams are invisible to raw string matching.
        // Decompression is capped to MAX_DECOMPRESSED_BYTES to prevent zip-bomb DoS.
        val decompResult = decompressFlateDecodeStreams(bytes)
        if (decompResult.exceededCap) {
            // Zip-bomb or adversarial payload: compressed data inflates beyond the safe limit.
            findings.add(
                ThreatFinding(
                    ThreatCategory.SUSPICIOUS_MIME_MISMATCH,
                    "FlateDecode payload exceeds safe decompression limit (possible zip-bomb)",
                    5
                )
            )
            Log.w(TAG, "[Scanner] FlateDecode decompression exceeded safe limit — flagged as SUSPICIOUS")
        }
        if (decompResult.content.isNotEmpty()) {
            Log.i(TAG, "[Scanner] FlateDecode decompression yielded ${decompResult.content.length} chars of additional content")
            scanPdfTags(decompResult.content, findings, "decompressed")
        }

        // Phase 2b: Relationship-aware structural refinement (replaces pure co-occurrence demotion where possible).
        // Parses indirect objects (including PDF 1.5+ object streams /ObjStm) and resolves
        // /OpenAction -> /S /GoTo vs /S /JavaScript etc., and checks /EmbeddedFiles reachability.
        // Handles /XRef streams gracefully (skipped). Deterministic, <10ms.
        val structuralStart = System.currentTimeMillis()
        val classicCount = PdfStructuralParser.parseObjects(content).size
        val objects = PdfStructuralParser.parseObjectsWithObjStm(bytes, content)
        val objStmAdded = objects.size - classicCount
        if (objects.isNotEmpty()) {
            refineAutoExecuteFindings(content, objects, findings)
            refineEmbeddedFilesReachability(content, objects, findings, decompResult.content)
            val parsedMs = System.currentTimeMillis() - structuralStart
            Log.i(TAG, "[Scanner] Structural parse: ${objects.size} objects (classic=$classicCount + ObjStm=$objStmAdded), ${parsedMs}ms, reachable check done")
        }

        // Check for missing EOF marker.
        // Severity 5 (was 4): a PDF lacking %%EOF is structurally malformed — commonly seen in
        // truncated exploit documents — and must be eligible as a corroborating signal alongside
        // high entropy. Severity 4 was unreachable by the corroboration threshold (>=5).
        if (!content.contains("%%EOF")) {
            findings.add(
                ThreatFinding(
                    ThreatCategory.SUSPICIOUS_MIME_MISMATCH,
                    "Malformed PDF: Missing %%EOF trailer marker (truncated or tampered structure)",
                    5
                )
            )
        }
    }

    private fun refineAutoExecuteFindings(content: String, objects: Map<String, String>, findings: MutableList<ThreatFinding>) {
        val autoIndices = findings.indices.filter { findings[it].category == ThreatCategory.AUTO_EXECUTE_ACTION }
        if (autoIndices.isEmpty()) return

        val openTypes = PdfStructuralParser.resolveOpenActions(content, objects)
        val aaTypes = PdfStructuralParser.resolveAATypes(content, objects)
        val allTypes = openTypes + aaTypes

        if (allTypes.isEmpty()) {
            // No parseable structure -> fallback handled by scanItem's hasExecutionVector rule; do nothing here
            Log.i(TAG, "[Scanner] Structural: no resolvable /OpenAction or /AA found — deferring to co-occurrence rule")
            return
        }

        val hasDangerous = allTypes.any {
            it == ResolvedActionType.DANGEROUS_JS || it == ResolvedActionType.DANGEROUS_LAUNCH ||
            it == ResolvedActionType.DANGEROUS_URI || it == ResolvedActionType.DANGEROUS_GOTOR ||
            it == ResolvedActionType.DANGEROUS_OTHER
        }
        val allBenign = allTypes.isNotEmpty() && allTypes.all { it == ResolvedActionType.BENIGN_GOTO }
        val allUnknown = allTypes.all { it == ResolvedActionType.UNKNOWN }

        if (allUnknown) {
            Log.i(TAG, "[Scanner] Structural: all /OpenAction/AA unresolvable (orphaned) — deferring to co-occurrence rule")
            return
        }

        if (hasDangerous) {
            Log.w(TAG, "[Scanner] Structural: /OpenAction/AA resolves to dangerous action $allTypes — keeping severity 7")
            // Dangerous: ensure severity stays 7 and mark as structural decision so co-occurrence fallback doesn't demote it
            for (idx in autoIndices) {
                val f = findings[idx]
                val newDesc = if (f.description.contains("structural:")) f.description
                    else if (f.description.contains("uncorroborated")) f.description.replace(" (uncorroborated — action type unverified; may be benign GoTo)", " (structural: dangerous action ${allTypes.first()})")
                    else "${f.description} (structural: dangerous action ${allTypes.first()})"
                findings[idx] = if (f.severity < 7) {
                    f.copy(description = newDesc, severity = 7)
                } else if (!f.description.contains("structural:")) {
                    f.copy(description = newDesc)
                } else f
            }
        } else if (allBenign) {
            Log.i(TAG, "[Scanner] Structural: /OpenAction/AA resolves to benign /GoTo $allTypes — demoting to severity 3")
            for (idx in autoIndices) {
                val f = findings[idx]
                findings[idx] = f.copy(
                    description = "${f.description} (structural: GoTo — navigates within document, not an exploit)",
                    severity = 3
                )
            }
        }
    }

    private fun refineEmbeddedFilesReachability(content: String, objects: Map<String, String>, findings: MutableList<ThreatFinding>, decompressedContent: String = "") {
        val efIndices = findings.indices.filter {
            findings[it].category == ThreatCategory.EMBEDDED_EXECUTABLE && findings[it].description.contains("/EmbeddedFiles")
        }
        if (efIndices.isEmpty()) return
        // If raw content has no /EmbeddedFiles but decompressed does, the finding came from decompressed stream
        // — don't demote based on raw catalog reachability (stream content is not an object reference).
        if (!content.contains("/EmbeddedFiles") && decompressedContent.contains("/EmbeddedFiles")) {
            Log.i(TAG, "[Scanner] Structural: /EmbeddedFiles found in decompressed stream — skipping orphaned check")
            return
        }
        val reachable = PdfStructuralParser.isEmbeddedFilesReachable(content, objects)
        if (!reachable) {
            Log.i(TAG, "[Scanner] Structural: /EmbeddedFiles is orphaned (not reachable from catalog) — demoting to severity 3")
            for (idx in efIndices) {
                val f = findings[idx]
                if (f.severity >= 6) {
                    findings[idx] = f.copy(
                        description = "Embedded document reference detected but not reachable from catalog (/EmbeddedFiles — orphaned, not an active attachment)",
                        severity = 3
                    )
                }
            }
        } else {
            Log.i(TAG, "[Scanner] Structural: /EmbeddedFiles is reachable from catalog — keeping severity ${findings[efIndices.first()].severity}")
        }
    }

    /**
     * Scan a content string (raw or decompressed) for PDF dangerous tags.
     * Deduplicates: if a tag was already found in a prior scan phase, it is not added again.
     */
    private fun scanPdfTags(content: String, findings: MutableList<ThreatFinding>, source: String) {
        for ((tag, finding) in PDF_DANGEROUS_TAGS) {
            if (content.contains(tag, ignoreCase = false)) {
                if (tag == "/EmbeddedFiles") {
                    val lowerContent = content.lowercase()
                    val hasDangerousPayloadExt = SUSPICIOUS_PAYLOAD_EXTENSIONS.any { ext -> lowerContent.contains(ext) }

                    if (hasDangerousPayloadExt) {
                        val alreadyFound = findings.any {
                            it.category == ThreatCategory.EMBEDDED_EXECUTABLE && it.severity >= 8
                        }
                        if (!alreadyFound) {
                            findings.add(
                                ThreatFinding(
                                    ThreatCategory.EMBEDDED_EXECUTABLE,
                                    "Embedded payload file with executable/script extension detected (/EmbeddedFiles)",
                                    8
                                )
                            )
                            Log.w(TAG, "[Scanner] PDF /EmbeddedFiles with dangerous extension detected ($source) — severity 8")
                        }
                    } else {
                        val alreadyFound = findings.any {
                            it.category == ThreatCategory.EMBEDDED_EXECUTABLE
                        }
                        if (!alreadyFound) {
                            findings.add(
                                ThreatFinding(
                                    ThreatCategory.EMBEDDED_EXECUTABLE,
                                    "Embedded document or data attachment detected (/EmbeddedFiles — no executable extension confirmed)",
                                    3
                                )
                            )
                            Log.i(TAG, "[Scanner] PDF /EmbeddedFiles uncorroborated ($source) — severity 3, capped at SUSPICIOUS")
                        }
                    }
                } else {
                    val alreadyFound = findings.any {
                        it.category == finding.category && it.description == finding.description
                    }
                    if (!alreadyFound) {
                        findings.add(finding)
                        Log.w(TAG, "[Scanner] PDF threat matched ($source): ${finding.description}")
                    }
                }
            }
        }
    }

    private data class DecompressionResult(val content: String, val exceededCap: Boolean)

    /**
     * Find FlateDecode-compressed streams in the PDF and decompress them.
     * Returns the concatenated decompressed content and whether the safety cap was exceeded.
     *
     * Safety:
     * - Total decompressed bytes capped at MAX_DECOMPRESSED_BYTES (20MB) to prevent zip-bomb DoS.
     * - Individual stream compressed size capped at MAX_COMPRESSED_BYTES (5MB).
     * - Corrupt/truncated streams are logged and skipped, not crashed.
     */
    private fun decompressFlateDecodeStreams(bytes: ByteArray): DecompressionResult {
        val streamPattern = "stream".toByteArray(Charsets.US_ASCII)
        val endstreamPattern = "endstream".toByteArray(Charsets.US_ASCII)
        val decompressedParts = mutableListOf<String>()
        var totalDecompressed = 0

        var searchOffset = 0
        while (searchOffset < bytes.size) {
            val streamPos = indexOf(bytes, streamPattern, searchOffset)
            if (streamPos == -1) break

            // The stream keyword must be followed by CR, LF, or CRLF per PDF spec.
            val dataStart = streamPos + streamPattern.size
            if (dataStart >= bytes.size) break
            when (bytes[dataStart].toInt().toChar()) {
                '\r' -> {
                    // Could be \r\n — skip both
                    if (dataStart + 1 < bytes.size && bytes[dataStart + 1].toInt().toChar() == '\n') {
                        // dataStart + 2 is actual start
                    }
                    // else dataStart + 1
                }
                '\n' -> { /* LF only — dataStart + 1 is actual start */ }
                else -> {
                    // Not a valid PDF stream delimiter — skip this occurrence
                    searchOffset = streamPos + streamPattern.size
                    continue
                }
            }
            // Calculate actual data start (after CR/LF/CRLF)
            val actualDataStart = when {
                dataStart < bytes.size && bytes[dataStart].toInt().toChar() == '\r' &&
                    dataStart + 1 < bytes.size && bytes[dataStart + 1].toInt().toChar() == '\n' -> dataStart + 2
                dataStart < bytes.size && (bytes[dataStart].toInt().toChar() == '\r' || bytes[dataStart].toInt().toChar() == '\n') -> dataStart + 1
                else -> dataStart
            }

            // Find endstream
            val endstreamPos = indexOf(bytes, endstreamPattern, actualDataStart)
            if (endstreamPos == -1) {
                Log.w(TAG, "[Scanner] FlateDecode: stream at $streamPos has no matching endstream — truncated PDF")
                break
            }

            // Look backwards from stream position for the dictionary context (up to 2048 bytes).
            val dictSearchStart = maxOf(0, streamPos - 2048)
            val dictRegion = String(bytes, dictSearchStart, streamPos - dictSearchStart, Charsets.US_ASCII)

            val isFlateDecode = dictRegion.contains("/FlateDecode") ||
                dictRegion.contains("[/FlateDecode") ||
                dictRegion.contains("/FlateDecode]")

            if (isFlateDecode) {
                val compressedSize = endstreamPos - actualDataStart
                if (compressedSize <= 0 || compressedSize > MAX_COMPRESSED_BYTES) {
                    Log.w(TAG, "[Scanner] FlateDecode stream at $streamPos: compressed size $compressedSize out of range — skipping")
                    searchOffset = endstreamPos + endstreamPattern.size
                    continue
                }

                val compressedData = bytes.copyOfRange(actualDataStart, endstreamPos)
                val capExceeded = booleanArrayOf(false)
                val decompressedBytes = inflateBytes(compressedData, capExceeded)

                if (capExceeded[0]) {
                    Log.w(TAG, "[Scanner] FlateDecode stream at $streamPos: decompression exceeded cap — zip-bomb detected")
                    return DecompressionResult("", true)
                }

                if (decompressedBytes != null) {
                    totalDecompressed += decompressedBytes.size
                    if (totalDecompressed > MAX_DECOMPRESSED_BYTES) {
                        Log.w(TAG, "[Scanner] FlateDecode: total decompressed bytes ($totalDecompressed) exceeded cap ($MAX_DECOMPRESSED_BYTES) — flagging and stopping")
                        return DecompressionResult("", true)
                    }
                    val part = String(decompressedBytes, Charsets.ISO_8859_1)
                    decompressedParts.add(part)
                    Log.i(TAG, "[Scanner] FlateDecode stream at $streamPos: ${compressedSize}B compressed → ${decompressedBytes.size}B decompressed")
                } else {
                    Log.w(TAG, "[Scanner] FlateDecode stream at $streamPos: decompression failed (corrupt/truncated) — skipping")
                }
            }

            searchOffset = endstreamPos + endstreamPattern.size
        }

        return DecompressionResult(decompressedParts.joinToString("\n"), false)
    }

    /**
     * Decompress a zlib/DEFLATE byte array using java.util.zip.Inflater.
     * Returns the decompressed bytes, or null on error.
     * Sets [capExceeded] to true if decompression exceeded MAX_DECOMPRESSED_BYTES.
     */
    private fun inflateBytes(compressed: ByteArray, capExceeded: BooleanArray = booleanArrayOf(false)): ByteArray? {
        return try {
            val inflater = Inflater()
            inflater.setInput(compressed)
            val buffer = ByteArray(8192)
            val output = mutableListOf<Byte>()
            while (!inflater.finished()) {
                val len = inflater.inflate(buffer)
                if (len == 0) {
                    if (inflater.needsDictionary()) {
                        Log.w(TAG, "[Scanner] Inflater needs dictionary — not standard zlib")
                        inflater.end()
                        return null
                    }
                    break
                }
                for (i in 0 until len) output.add(buffer[i])
                if (output.size > MAX_DECOMPRESSED_BYTES) {
                    capExceeded[0] = true
                    inflater.end()
                    return null
                }
            }
            inflater.end()
            output.toByteArray()
        } catch (e: DataFormatException) {
            Log.w(TAG, "[Scanner] Inflater DataFormatException: ${e.message}")
            null
        } catch (e: Exception) {
            Log.w(TAG, "[Scanner] Inflater unexpected error: ${e.message}")
            null
        }
    }

    /**
     * Find the first occurrence of [target] in [bytes] starting at [fromIndex].
     * Returns -1 if not found.
     */
    private fun indexOf(bytes: ByteArray, target: ByteArray, fromIndex: Int): Int {
        if (target.isEmpty()) return fromIndex
        val firstByte = target[0]
        val end = bytes.size - target.size
        var i = fromIndex
        while (i <= end) {
            if (bytes[i] == firstByte) {
                var match = true
                for (j in 1 until target.size) {
                    if (bytes[i + j] != target[j]) {
                        match = false
                        break
                    }
                }
                if (match) return i
            }
            i++
        }
        return -1
    }

    private fun scanZipOrApk(bytes: ByteArray, findings: MutableList<ThreatFinding>) {
        val content = String(bytes, Charsets.ISO_8859_1)
        if (content.contains("classes.dex")) {
            Log.i(TAG, "[Scanner] APK signature detected: classes.dex present")
        }
        if (content.contains("AndroidManifest.xml")) {
            // Check for high-privilege persistence/accessibility combos:
            // Legitimate screen readers/accessibility tools request BIND_ACCESSIBILITY_SERVICE.
            // Requiring 3 co-occurring signals (Accessibility + Boot Persistence + SMS/Alert/Overlay)
            // avoids false-flagging legitimate assistive tools.
            val hasAccessibility = content.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
            val hasBoot = content.contains("android.permission.RECEIVE_BOOT_COMPLETED")
            val hasSmsOrOverlay = content.contains("android.permission.RECEIVE_SMS") ||
                                  content.contains("android.permission.SYSTEM_ALERT_WINDOW") ||
                                  content.contains("android.permission.READ_SMS")

            if (hasAccessibility && hasBoot && hasSmsOrOverlay) {
                findings.add(
                    ThreatFinding(
                        ThreatCategory.DANGEROUS_PERMISSIONS,
                        "APK requests trojan permission combo (Accessibility + Boot + SMS/Overlay)",
                        8
                    )
                )
            } else if (hasAccessibility && hasBoot) {
                findings.add(
                    ThreatFinding(
                        ThreatCategory.DANGEROUS_PERMISSIONS,
                        "APK requests Accessibility + Boot persistence (review app origin)",
                        5
                    )
                )
            }
        }
    }

    private fun calculateShannonEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val frequency = IntArray(256)
        for (b in bytes) {
            frequency[b.toInt() and 0xFF]++
        }
        var entropy = 0.0
        val total = bytes.size.toDouble()
        for (count in frequency) {
            if (count > 0) {
                val p = count / total
                entropy -= p * (ln(p) / ln(2.0))
            }
        }
        return Math.round(entropy * 100.0) / 100.0
    }
}
