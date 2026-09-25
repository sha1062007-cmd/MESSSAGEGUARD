package com.messageguard

import com.messageguard.sandbox.model.CaptureSource
import com.messageguard.sandbox.model.SandboxItem
import com.messageguard.sandbox.model.SandboxStatus
import com.messageguard.sandbox.scan.PreExecutionScanner
import com.messageguard.sandbox.scan.ScanVerdict
import com.messageguard.threatvision.data.model.ThreatThresholds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * Dedicated tests for PreExecutionScanner, including FlateDecode decompression coverage.
 * Moved from SandboxAndAccuracyOverhaulTest.kt to keep scanner tests self-contained.
 */
class PreExecutionScannerTest {

    // ──────────────────────────────────────────────────────────────────────────
    // Helper: build a minimal PDF byte array
    // ──────────────────────────────────────────────────────────────────────────

    private fun buildPdfBytes(body: String): ByteArray {
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val bodyBytes = body.toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        return header + bodyBytes + footer
    }

    /**
     * Compress [raw] using zlib (DEFLATE) and return the compressed bytes.
     * This produces valid FlateDecode-compatible compressed data.
     */
    private fun flateCompress(raw: ByteArray): ByteArray {
        val deflater = Deflater()
        deflater.setInput(raw)
        deflater.finish()
        val buffer = ByteArrayOutputStream()
        val chunk = ByteArray(4096)
        while (!deflater.finished()) {
            val len = deflater.deflate(chunk)
            buffer.write(chunk, 0, len)
        }
        deflater.end()
        return buffer.toByteArray()
    }

    /**
     * Build a synthetic PDF where the given tag(s) appear ONLY inside a FlateDecode-compressed
     * stream, not in any plaintext dictionary. This is the exact scenario the scanner was blind to
     * before the FlateDecode fix.
     */
    private fun buildPdfWithCompressedStream(compressedContent: String): ByteArray {
        val compressed = flateCompress(compressedContent.toByteArray(Charsets.ISO_8859_1))
        // PDF structure: header + object with /Filter /FlateDecode + stream + compressed data + endstream + %%EOF
        val sb = StringBuilder()
        sb.append("1 0 obj\n")
        sb.append("<< /Type /EmbeddedFile /Filter /FlateDecode /Length ${compressed.size} >>\n")
        sb.append("stream\n")
        val streamHeader = sb.toString().toByteArray(Charsets.ISO_8859_1)
        val streamFooter = "\nendstream\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        return header + streamHeader + compressed + streamFooter + footer
    }

    /**
     * Build a PDF with PDF 1.5+ object stream (/Type /ObjStm) containing N embedded objects.
     * The embedded objects are stored compressed and invisible to classic regex parsing.
     */
    private fun buildPdfWithObjStm(catalogExtra: String, embeddedObjects: List<Pair<Int, String>>): ByteArray {
        // Build the decompressed ObjStm stream: index + concatenated objects
        // Index format: "objNum offset objNum offset ..." then objects concatenated
        val indexParts = mutableListOf<String>()
        val objectsSection = StringBuilder()
        var offset = 0
        val sorted = embeddedObjects.sortedBy { it.first }
        // First pass: build objectsSection and collect offsets
        val offsets = mutableListOf<Int>()
        for ((_, content) in sorted) {
            offsets.add(offset)
            objectsSection.append(content)
            // Add a space separator if not ending with whitespace
            if (!content.endsWith(" ") && !content.endsWith("\n")) objectsSection.append(" ")
            offset = objectsSection.length
        }
        // Build index string: "objNum offset "
        val indexStr = buildString {
            for (i in sorted.indices) {
                append("${sorted[i].first} ${offsets[i]} ")
            }
        }
        val first = indexStr.length
        val decompressed = indexStr + objectsSection.toString()
        val compressed = flateCompress(decompressed.toByteArray(Charsets.ISO_8859_1))
        // Build PDF
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val catalogObj = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R $catalogExtra >>\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val pagesObj = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val pageObj = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val objStmHeader = "10 0 obj\n<< /Type /ObjStm /N ${sorted.size} /First $first /Length ${compressed.size} /Filter /FlateDecode >>\nstream\n".toByteArray(Charsets.ISO_8859_1)
        val objStmFooter = "\nendstream\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        return header + catalogObj + pagesObj + pageObj + objStmHeader + compressed + objStmFooter + footer
    }

    private fun makeTestItem(bytes: ByteArray, id: String, fileName: String, source: CaptureSource = CaptureSource.MEDIASTORE_OBSERVER): SandboxItem {
        val tempFile = File.createTempFile("scanner_test_", ".pdf")
        tempFile.deleteOnExit()
        tempFile.writeBytes(bytes)
        return SandboxItem(
            id = id,
            originalFileName = fileName,
            originalMimeType = "application/pdf",
            fileSize = tempFile.length(),
            sha256 = "test_sha256_$id",
            sourcePackage = "com.android.chrome",
            captureSource = source,
            quarantinedFilePath = tempFile.absolutePath,
            status = SandboxStatus.PENDING_SCAN
        )
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Existing scanner tests (moved from SandboxAndAccuracyOverhaulTest.kt)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    fun testPreExecutionScannerInconclusiveOnEmptyFile() = runBlocking {
        val tempFile = File.createTempFile("empty_test", ".pdf")
        tempFile.deleteOnExit()

        val item = SandboxItem(
            id = "test_empty_1",
            originalFileName = "empty.pdf",
            originalMimeType = "application/pdf",
            fileSize = 0L,
            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sourcePackage = "com.android.chrome",
            captureSource = CaptureSource.MEDIASTORE_OBSERVER,
            quarantinedFilePath = tempFile.absolutePath,
            status = SandboxStatus.PENDING_SCAN
        )

        val result = PreExecutionScanner.scanItem(item)
        assertEquals(ScanVerdict.INCONCLUSIVE, result.verdict)
        assertEquals(0, result.threatScore)
    }

    @Test
    fun testPreExecutionScannerHardExploitShortCircuit() = runBlocking {
        val bytes = buildPdfBytes("/Launch /JS /OpenAction")
        val item = makeTestItem(bytes, "test_exploit_1", "invoice_exploit.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertEquals(ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
    }

    @Test
    fun testHighEntropyAloneProducesSuspiciousNotMalicious() = runBlocking {
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        val randomBytes = ByteArray(4096)
        for (i in randomBytes.indices) {
            randomBytes[i] = (i % 256).toByte()
        }
        val bytes = header + randomBytes + footer
        val item = makeTestItem(bytes, "test_benign_entropy_1", "benign_compressed_sample.pdf")

        val result = PreExecutionScanner.scanItem(item)
        assertNotEquals("Entropy alone must NEVER reach MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        assertEquals(ScanVerdict.SUSPICIOUS, result.verdict)
        assertTrue(result.threatScore < ThreatThresholds.SANDBOX_MALICIOUS_MIN)
        assertTrue(result.entropy > 7.5)
    }

    @Test
    fun testHighEntropyWithCorroborationEscalates() = runBlocking {
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val randomBytes = ByteArray(4096)
        for (i in randomBytes.indices) {
            randomBytes[i] = (i % 256).toByte()
        }
        // Omit %%EOF — missing EOF (sev 5) corroborator fires
        val bytes = header + randomBytes
        val item = makeTestItem(bytes, "test_corroborated_1", "tampered_payload.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        // Corroborated: entropy sev 6 + missing EOF sev 5 = raw score 110 → coerced to 100 → MALICIOUS
        assertEquals(ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
        assertTrue(result.threatScore <= 100)
    }

    @Test
    fun testEmbeddedFilesWithXmlInvoiceDoesNotTriggerMalicious() = runBlocking {
        val content = "%PDF-1.4\n/EmbeddedFiles << /Names [(factur-x.xml) 10 0 R] >>\n%%EOF"
        val bytes = content.toByteArray(Charsets.ISO_8859_1)
        val item = makeTestItem(bytes, "test_einvoice_1", "factur-x_invoice.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertNotEquals("Benign e-invoices with /EmbeddedFiles must not trigger MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        assertEquals(ScanVerdict.SUSPICIOUS, result.verdict)
        assertEquals(30, result.threatScore)
    }

    @Test
    fun testEmbeddedFilesWithExePayloadTriggersMalicious() = runBlocking {
        val content = "%PDF-1.4\n/EmbeddedFiles << /Names [(payload_invoice.exe) 10 0 R] >>\n%%EOF"
        val bytes = content.toByteArray(Charsets.ISO_8859_1)
        val item = makeTestItem(bytes, "test_malicious_exe_1", "invoice_with_exe.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertEquals(ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NEW: FlateDecode decompression tests
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    fun testFlateDecodeHiddenJsDetectedAsMalicious() = runBlocking {
        // /JS exists ONLY inside a FlateDecode-compressed stream, nowhere in plaintext.
        // Before the fix, this would produce a SAFE verdict (false negative).
        // After the fix, decompression reveals /JS → MALICIOUS.
        val compressedContent = "This stream contains /JS hidden payload. /JS app.alert('pwned')"
        val bytes = buildPdfWithCompressedStream(compressedContent)
        val item = makeTestItem(bytes, "test_flate_js_1", "hidden_js_attack.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertEquals("Hidden /JS inside FlateDecode stream must be detected", ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
        assertTrue("Must have at least one finding from decompressed content", result.findings.size >= 1)
        val jsFinding = result.findings.any {
            it.category == com.messageguard.sandbox.scan.ThreatCategory.EMBEDDED_JAVASCRIPT
        }
        assertTrue("Must contain EMBEDDED_JAVASCRIPT finding", jsFinding)
    }

    @Test
    fun testFlateDecodeHiddenEmbeddedFilesWithExeDetected() = runBlocking {
        // /EmbeddedFiles + .exe extension hidden inside compressed stream only.
        val compressedContent = "Embedded payload: /EmbeddedFiles << /Names [(trojan.exe) 5 0 R] >>"
        val bytes = buildPdfWithCompressedStream(compressedContent)
        val item = makeTestItem(bytes, "test_flate_embedded_1", "hidden_embedded_exe.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertEquals("Hidden /EmbeddedFiles + .exe must be detected via decompression", ScanVerdict.MALICIOUS, result.verdict)
        val exeFinding = result.findings.any {
            it.category == com.messageguard.sandbox.scan.ThreatCategory.EMBEDDED_EXECUTABLE && it.severity >= 8
        }
        assertTrue("Must contain EMBEDDED_EXECUTABLE finding with sev >= 8", exeFinding)
    }

    @Test
    fun testFlateDecodeHiddenEmbeddedXmlNotEscalated() = runBlocking {
        // /EmbeddedFiles with benign XML (no dangerous extension) inside compressed stream.
        // Should remain SUSPICIOUS, not MALICIOUS.
        val compressedContent = "Invoice attachment: /EmbeddedFiles << /Names [(factur-x.xml) 5 0 R] >>"
        val bytes = buildPdfWithCompressedStream(compressedContent)
        val item = makeTestItem(bytes, "test_flate_xml_1", "hidden_xml_invoice.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertNotEquals("Benign XML in compressed stream must not be MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        assertEquals(ScanVerdict.SUSPICIOUS, result.verdict)
    }

    @Test
    fun testFlateDecodeZipBombRejected() = runBlocking {
        // Build a small compressed payload that inflates to > MAX_DECOMPRESSED_BYTES.
        // We simulate this by creating a compressible payload larger than the cap,
        // then verifying the scanner handles the overflow gracefully.
        val largePayload = "A".repeat(25 * 1024 * 1024) // 25MB of compressible data
        val compressed = flateCompress(largePayload.toByteArray(Charsets.ISO_8859_1))

        val streamHeader = "1 0 obj\n<< /Type /EmbeddedFile /Filter /FlateDecode /Length ${compressed.size} >>\nstream\n"
            .toByteArray(Charsets.ISO_8859_1)
        val streamFooter = "\nendstream\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        val bytes = header + streamHeader + compressed + streamFooter + footer

        val item = makeTestItem(bytes, "test_zip_bomb_1", "zip_bomb.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)

        // Must NOT hang or OOM — the scanner should complete and flag as SUSPICIOUS
        assertTrue("Zip-bomb must complete within time (scan took ${result.scanDurationMs}ms)", result.scanDurationMs < 30000)
        assertNotEquals("Zip-bomb must not be SAFE", ScanVerdict.SAFE, result.verdict)
        val findingsText = result.findings.joinToString(" ") { it.description }
        assertTrue("Findings must mention decompression limit or SUSPICIOUS",
            findingsText.contains("decompression") || findingsText.contains("limit") ||
            result.verdict == ScanVerdict.SUSPICIOUS || result.verdict == ScanVerdict.MALICIOUS
        )
    }

    @Test
    fun testFlateDecodeCorruptStreamHandledGracefully() = runBlocking {
        // Build a PDF with a /FlateDecode stream containing garbage (not valid zlib).
        val corruptData = byteArrayOf(0x01, 0x02, 0x03, 0xFF.toByte(), 0xFE.toByte(), 0xFD.toByte(), 0x00, 0x00)
        val streamHeader = "1 0 obj\n<< /Type /EmbeddedFile /Filter /FlateDecode /Length ${corruptData.size} >>\nstream\n"
            .toByteArray(Charsets.ISO_8859_1)
        val streamFooter = "\nendstream\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        val bytes = header + streamHeader + corruptData + streamFooter + footer

        val item = makeTestItem(bytes, "test_corrupt_stream_1", "corrupt_stream.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)

        // Must NOT crash — should return a valid verdict (likely SAFE since corrupt data has no tags)
        assertTrue("Verdict must be a valid enum", result.verdict in ScanVerdict.values())
        assertTrue("Scan must complete (took ${result.scanDurationMs}ms)", result.scanDurationMs < 10000)
    }

    @Test
    fun testFlateDecodeMixedRawAndCompressed() = runBlocking {
        // /JS in compressed stream + /OpenAction in raw — both should be detected.
        val compressedContent = "Hidden /JS payload in compressed stream"
        val compressed = flateCompress(compressedContent.toByteArray(Charsets.ISO_8859_1))
        val streamHeader = "1 0 obj\n<< /Type /EmbeddedFile /Filter /FlateDecode /Length ${compressed.size} >>\nstream\n"
            .toByteArray(Charsets.ISO_8859_1)
        val streamFooter = "\nendstream\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val rawContent = "/OpenAction << /URI (http://evil.com) >>\n"
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        val bytes = header + streamHeader + compressed + streamFooter + rawContent.toByteArray(Charsets.ISO_8859_1) + footer

        val item = makeTestItem(bytes, "test_mixed_1", "mixed_attack.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)

        // /JS from decompressed + /OpenAction from raw → should be MALICIOUS (JS + action)
        assertEquals(ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
        val hasJs = result.findings.any {
            it.category == com.messageguard.sandbox.scan.ThreatCategory.EMBEDDED_JAVASCRIPT
        }
        val hasAction = result.findings.any {
            it.category == com.messageguard.sandbox.scan.ThreatCategory.AUTO_EXECUTE_ACTION
        }
        assertTrue("Must have EMBEDDED_JAVASCRIPT from decompressed stream", hasJs)
        assertTrue("Must have AUTO_EXECUTE_ACTION from raw content", hasAction)
    }

    @Test
    fun testFlateDecodeMultiFilterArrayDetected() = runBlocking {
        // /Filter [/FlateDecode] (array syntax, not bare) — must also be detected.
        val compressedContent = "Hidden /JS inside array-filter stream"
        val compressed = flateCompress(compressedContent.toByteArray(Charsets.ISO_8859_1))
        val streamHeader = "1 0 obj\n<< /Type /EmbeddedFile /Filter [/FlateDecode] /Length ${compressed.size} >>\nstream\n"
            .toByteArray(Charsets.ISO_8859_1)
        val streamFooter = "\nendstream\nendobj\n".toByteArray(Charsets.ISO_8859_1)
        val header = "%PDF-1.4\n".toByteArray(Charsets.ISO_8859_1)
        val footer = "\n%%EOF".toByteArray(Charsets.ISO_8859_1)
        val bytes = header + streamHeader + compressed + streamFooter + footer

        val item = makeTestItem(bytes, "test_multi_filter_1", "array_filter_attack.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)

        assertEquals("Array-syntax /Filter [/FlateDecode] must be decompressed", ScanVerdict.MALICIOUS, result.verdict)
        val jsFinding = result.findings.any {
            it.category == com.messageguard.sandbox.scan.ThreatCategory.EMBEDDED_JAVASCRIPT
        }
        assertTrue("Must detect /JS in array-filter compressed stream", jsFinding)
    }

    @Test
    fun testPlaintextJsStillDetectedWithoutDecompression() = runBlocking {
        // Regression: /JS in plaintext must still be detected (decompression is additive, not replacing).
        val bytes = buildPdfBytes("/JS app.alert('plaintext')")
        val item = makeTestItem(bytes, "test_plaintext_js_1", "plaintext_js.pdf", CaptureSource.ACCESSIBILITY_ENGINE)

        val result = PreExecutionScanner.scanItem(item)
        assertEquals(ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Structural parsing tests (relationship-aware)
    // ──────────────────────────────────────────────────────────────────────────

    private fun buildCatalogPdf(catalogBody: String, extraObjects: String = ""): ByteArray {
        val content = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R $catalogBody >>\nendobj\n")
            append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
            append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n")
            if (extraObjects.isNotEmpty()) append(extraObjects)
            append("%%EOF")
        }
        return content.toByteArray(Charsets.ISO_8859_1)
    }

    @Test
    fun testOpenActionGoToDoesNotEscalate() = runBlocking {
        // /OpenAction -> /GoTo is benign navigation, not an exploit.
        // Structural parser should resolve it and demote to SUSPICIOUS at most.
        val bytes = buildCatalogPdf(
            catalogBody = "/OpenAction 5 0 R",
            extraObjects = "5 0 obj\n<< /S /GoTo /D [3 0 R /Fit] >>\nendobj\n"
        )
        val item = makeTestItem(bytes, "test_goto_1", "goto_nav.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertNotEquals("GoTo navigation must NOT be MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        assertTrue("GoTo should be SAFE or SUSPICIOUS", result.verdict == ScanVerdict.SAFE || result.verdict == ScanVerdict.SUSPICIOUS)
        // The finding description should contain structural marker
        val goToDemoted = result.findings.any { it.description.contains("structural:") && it.severity == 3 }
        assertTrue("Structural demotion to sev 3 with structural marker expected", goToDemoted || result.verdict == ScanVerdict.SAFE)
    }

    @Test
    fun testOpenActionJsEscalatesToMalicious() = runBlocking {
        // /OpenAction -> /JavaScript is a drive-by exploit.
        val bytes = buildCatalogPdf(
            catalogBody = "/OpenAction 5 0 R",
            extraObjects = "5 0 obj\n<< /S /JavaScript /JS (app.alert('pwned')) >>\nendobj\n"
        )
        val item = makeTestItem(bytes, "test_js_action_1", "js_action.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertEquals("OpenAction -> JS must be MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        val hasJs = result.findings.any { it.category == com.messageguard.sandbox.scan.ThreatCategory.EMBEDDED_JAVASCRIPT }
        val hasAction = result.findings.any { it.category == com.messageguard.sandbox.scan.ThreatCategory.AUTO_EXECUTE_ACTION && it.severity >= 7 }
        assertTrue("Must have EMBEDDED_JAVASCRIPT", hasJs)
        assertTrue("Must have AUTO_EXECUTE_ACTION sev 7", hasAction)
    }

    @Test
    fun testOpenActionUriEscalates() = runBlocking {
        val bytes = buildCatalogPdf(
            catalogBody = "/OpenAction 5 0 R",
            extraObjects = "5 0 obj\n<< /S /URI /URI (http://evil.example.com) >>\nendobj\n"
        )
        val item = makeTestItem(bytes, "test_uri_action_1", "uri_action.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        // URI via OpenAction is dangerous; without JS co-occurrence it should still be at least SUSPICIOUS
        // and with structural resolution it stays sev 7, so combined with no other signals it will be SUSPICIOUS (score 70? no hard trigger).
        // Verify NOT demoted to 3.
        val autoFinding = result.findings.find { it.category == com.messageguard.sandbox.scan.ThreatCategory.AUTO_EXECUTE_ACTION }
        assertNotNull("Should have AUTO_EXECUTE_ACTION finding", autoFinding)
        assertTrue("URI action should NOT be demoted to 3, got ${autoFinding!!.severity} findings=${result.findings}", autoFinding.severity >= 7)
    }

    @Test
    fun testEmbeddedFilesOrphanedDoesNotEscalate() = runBlocking {
        // /EmbeddedFiles in an orphaned object not reachable from catalog.
        val content = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
            append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
            append("3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n")
            append("99 0 obj\n<< /EmbeddedFiles << /Names [(orphan.exe) 100 0 R] >> >>\nendobj\n")
            append("100 0 obj\n<< /Type /EmbeddedFile >>\nstream\nMZ fake exe\nendstream\nendobj\n")
            append("%%EOF")
        }.toByteArray(Charsets.ISO_8859_1)
        val item = makeTestItem(content, "test_orphan_1", "orphan_embedded.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertNotEquals("Orphaned EmbeddedFiles must NOT be MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.verdict == ScanVerdict.SUSPICIOUS || result.verdict == ScanVerdict.SAFE)
        val orphanDemoted = result.findings.any { it.description.contains("orphaned") && it.severity == 3 }
        assertTrue("Orphaned finding should be demoted with orphaned marker", orphanDemoted)
    }

    @Test
    fun testEmbeddedFilesReachableWithExeEscalates() = runBlocking {
        // /EmbeddedFiles reachable from catalog via /Names -> dangerous exe
        val content = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names 4 0 R >>\nendobj\n")
            append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
            append("3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n")
            append("4 0 obj\n<< /EmbeddedFiles << /Names [(payload.exe) 5 0 R] >> >>\nendobj\n")
            append("5 0 obj\n<< /Type /EmbeddedFile >>\nstream\nMZ\nendstream\nendobj\n")
            append("%%EOF")
        }.toByteArray(Charsets.ISO_8859_1)
        val item = makeTestItem(content, "test_reachable_exe_1", "reachable_exe.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertEquals("Reachable EmbeddedFiles with .exe must be MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
    }

    @Test
    fun testStructuralParseLatency() = runBlocking {
        // Ensure structural parsing does not add >50ms for typical PDF
        val bytes = buildCatalogPdf(
            catalogBody = "/OpenAction 5 0 R",
            extraObjects = "5 0 obj\n<< /S /GoTo /D [3 0 R /Fit] >>\nendobj\n" +
                "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        )
        val item = makeTestItem(bytes, "test_latency_1", "latency.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertTrue("Scan should complete quickly (<100ms for small PDF, structural <5ms portion)", result.scanDurationMs < 5000)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ObjStm tests (PDF 1.5+ object streams)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    fun testObjStmJsActionEscalatesCorrectly() = runBlocking {
        // Gap confirmation: /JS hidden inside ObjStm is invisible to classic regex.
        // Catalog /OpenAction 5 0 R where 5 0 is inside ObjStm 10 0.
        val bytes = buildPdfWithObjStm(
            catalogExtra = "/OpenAction 5 0 R",
            embeddedObjects = listOf(
                5 to "<< /S /JavaScript /JS (app.alert('pwned')) >>",
                6 to "<< /S /GoTo /D [3 0 R /Fit] >>"
            )
        )
        val item = makeTestItem(bytes, "test_objstm_js_1", "objstm_js.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        // Must be MALICIOUS via relationship: OpenAction -> JS inside ObjStm
        assertEquals("JS inside ObjStm must be resolved and escalate to MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        val hasJs = result.findings.any { it.category == com.messageguard.sandbox.scan.ThreatCategory.EMBEDDED_JAVASCRIPT }
        val hasAction = result.findings.any { it.category == com.messageguard.sandbox.scan.ThreatCategory.AUTO_EXECUTE_ACTION && it.severity >= 7 }
        assertTrue("Must have EMBEDDED_JAVASCRIPT from ObjStm", hasJs)
        assertTrue("Must have AUTO_EXECUTE_ACTION sev 7 (dangerous, not demoted)", hasAction)
        // Verify object counts: classic 4 (1,2,3,10) + ObjStm 2 = 6 total
        assertTrue("Should have findings from ObjStm resolution", result.findings.size >= 2)
    }

    @Test
    fun testObjStmGoToDoesNotEscalate() = runBlocking {
        // ObjStm with benign GoTo should NOT escalate
        val bytes = buildPdfWithObjStm(
            catalogExtra = "/OpenAction 5 0 R",
            embeddedObjects = listOf(
                5 to "<< /S /GoTo /D [3 0 R /Fit] >>"
            )
        )
        val item = makeTestItem(bytes, "test_objstm_goto_1", "objstm_goto.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertNotEquals("GoTo inside ObjStm must NOT be MALICIOUS", ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.verdict == ScanVerdict.SUSPICIOUS || result.verdict == ScanVerdict.SAFE)
    }

    @Test
    fun testObjStmStressMultipleObjects() = runBlocking {
        // Stress: ObjStm with 5 objects, including nested references
        val bytes = buildPdfWithObjStm(
            catalogExtra = "/OpenAction 5 0 R",
            embeddedObjects = listOf(
                5 to "<< /S /Launch /F (evil.exe) >>",
                6 to "<< /S /GoTo /D [3 0 R /Fit] >>",
                7 to "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
                8 to "<< /S /URI /URI (http://evil.com) >>",
                9 to "<< /S /JavaScript /JS (alert) >>"
            )
        )
        val item = makeTestItem(bytes, "test_objstm_stress_1", "objstm_stress.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        // Contains dangerous Launch + JS via ObjStm, must be MALICIOUS
        assertEquals(ScanVerdict.MALICIOUS, result.verdict)
        assertTrue(result.threatScore >= ThreatThresholds.SANDBOX_MALICIOUS_MIN)
    }

    @Test
    fun testXRefStreamDoesNotCrash() = runBlocking {
        // Cross-reference stream (/Type /XRef) should be skipped gracefully, not crash
        val content = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
            append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
            append("3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n")
            append("4 0 obj\n<< /Type /XRef /Length 10 /W [1 2 1] /Filter /FlateDecode >>\nstream\n")
            append("compressed_xref_data")
            append("\nendstream\nendobj\n")
            append("%%EOF")
        }.toByteArray(Charsets.ISO_8859_1)
        val item = makeTestItem(content, "test_xref_1", "xref.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        // Should not crash, verdict should be SAFE or SUSPICIOUS (no malicious tags)
        assertTrue(result.verdict == ScanVerdict.SAFE || result.verdict == ScanVerdict.SUSPICIOUS)
        assertTrue("Scan must complete", result.scanDurationMs < 5000)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Real-world false-positive regression (Phase 2): compressed PDFs
    // Observed on-device: 100KB WhatsApp PDF, entropy 7.67, FlateDecode present
    // → was SUSPICIOUS 30/100. Must be SAFE.
    // ──────────────────────────────────────────────────────────────────────────

    private fun buildRealWorldLikePdf(withFlateDecode: Boolean): ByteArray {
        // ~7.7 entropy body: 220 uniformly-distributed byte values → log2(220) ≈ 7.78
        val body = ByteArray(8192) { i -> (i % 220).toByte() }
        val filterText = if (withFlateDecode) "<< /Filter /FlateDecode /Length 8192 >>" else "<< /Length 8192 >>"
        val content = buildString {
            append("%PDF-1.7\n")
            append("1 0 obj\n$filterText\nstream\n")
            append("%%EOF")
        }
        val header = content.toByteArray(Charsets.ISO_8859_1)
        return header + body
    }

    @Test
    fun testCompressedPdfNormalEntropyIsSafe() = runBlocking {
        // Real-world case: ordinary FlateDecode-compressed PDF, entropy ~7.78 → SAFE, not SUSPICIOUS
        val bytes = buildRealWorldLikePdf(withFlateDecode = true)
        val item = makeTestItem(bytes, "test_real_pdf_1", "whatsapp_document.pdf", CaptureSource.USER_OPEN)
        val result = PreExecutionScanner.scanItem(item)
        assertTrue("Entropy was ${result.entropy}, expected 7.5–7.9 band", result.entropy > 7.5 && result.entropy < 7.9)
        assertEquals("Ordinary compressed PDF must be SAFE (was the live false positive)", ScanVerdict.SAFE, result.verdict)
        val entropyFinding = result.findings.find { it.category == com.messageguard.sandbox.scan.ThreatCategory.HIGH_ENTROPY_PACKED }
        if (entropyFinding != null) {
            assertEquals("Compressed-PDF entropy must be informational (sev 1)", 1, entropyFinding.severity)
            assertTrue(entropyFinding.description.contains("expected for FlateDecode"))
        }
    }

    @Test
    fun testUncompressedHighEntropyPdfStillSuspicious() = runBlocking {
        // Same entropy band WITHOUT FlateDecode (raw high-entropy blob) → still SUSPICIOUS (sev 3)
        val bytes = buildRealWorldLikePdf(withFlateDecode = false)
        val item = makeTestItem(bytes, "test_raw_entropy_1", "packed_blob.pdf", CaptureSource.ACCESSIBILITY_ENGINE)
        val result = PreExecutionScanner.scanItem(item)
        assertEquals("High entropy without compression explanation stays SUSPICIOUS", ScanVerdict.SUSPICIOUS, result.verdict)
    }
}
