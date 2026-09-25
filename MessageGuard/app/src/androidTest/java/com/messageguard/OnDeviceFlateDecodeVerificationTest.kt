package com.messageguard

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.messageguard.sandbox.model.CaptureSource
import com.messageguard.sandbox.model.SandboxItem
import com.messageguard.sandbox.model.SandboxStatus
import com.messageguard.sandbox.scan.PreExecutionScanner
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * On-device verification of PreExecutionScanner against real PDF files
 * pushed to the emulator via adb push.
 */
@RunWith(AndroidJUnit4::class)
class OnDeviceFlateDecodeVerificationTest {

    private val TAG = "OnDeviceVerify"

    private fun scanFile(fileName: String) = runBlocking {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        // Try app-private external files dir first (scoped storage friendly), then /sdcard/Download
        val candidates = listOf(
            File(ctx.getExternalFilesDir(null), fileName),
            File("/sdcard/Download/$fileName"),
            File("/sdcard/Download/demo_test_pdfs/$fileName"),
            File("/data/local/tmp/$fileName")
        )
        var file: File? = null
        var filePath = ""
        for (c in candidates) {
            try {
                if (c.exists() && c.canRead()) { file = c; filePath = c.absolutePath; break }
            } catch (_: Exception) {}
            // Also try via content resolver copy to cache if direct File fails
        }
        if (file == null) {
            // Fallback: try to copy from MediaStore via ContentResolver
            try {
                val cacheFile = File(ctx.cacheDir, fileName)
                // Try to find file via MediaStore query and copy
                val projection = arrayOf(android.provider.MediaStore.MediaColumns._ID, android.provider.MediaStore.MediaColumns.DISPLAY_NAME)
                val cursor = ctx.contentResolver.query(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    projection, "${android.provider.MediaStore.MediaColumns.DISPLAY_NAME}=?", arrayOf(fileName), null
                )
                cursor?.use {
                    if (it.moveToFirst()) {
                        val id = it.getLong(0)
                        val uri = android.content.ContentUris.withAppendedId(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, id)
                        ctx.contentResolver.openInputStream(uri)?.use { input ->
                            cacheFile.outputStream().use { out -> input.copyTo(out) }
                        }
                        if (cacheFile.exists()) { file = cacheFile; filePath = cacheFile.absolutePath }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "MediaStore fallback failed for $fileName: ${e.message}")
            }
        }
        val resolvedFile = file
        if (resolvedFile == null || !resolvedFile.exists()) {
            Log.e(TAG, "FILE NOT FOUND: $fileName (tried ${candidates.map { it.absolutePath }})")
            return@runBlocking null
        }
        filePath = resolvedFile.absolutePath
        Log.i(TAG, "Scanning $fileName from $filePath (${resolvedFile.length()} bytes)")

        val item = SandboxItem(
            id = "ondevice_$fileName",
            originalFileName = fileName,
            originalMimeType = "application/pdf",
            fileSize = resolvedFile.length(),
            sha256 = "ondevice_test_${fileName.hashCode()}",
            sourcePackage = "com.android.chrome",
            captureSource = CaptureSource.MEDIASTORE_OBSERVER,
            quarantinedFilePath = filePath,
            status = SandboxStatus.PENDING_SCAN
        )

        val result = PreExecutionScanner.scanItem(item, InstrumentationRegistry.getInstrumentation().targetContext)

        Log.i(TAG, "=== $fileName ===")
        Log.i(TAG, "  Verdict: ${result.verdict}")
        Log.i(TAG, "  Score: ${result.threatScore}/100 (Struct=${result.structuralScore}, Ens=${result.ensembleScore})")
        Log.i(TAG, "  Entropy: ${result.entropy}")
        Log.i(TAG, "  Findings (${result.findings.size}):")
        result.findings.forEach { f ->
            Log.i(TAG, "    [sev=${f.severity}] ${f.category}: ${f.description}")
        }
        Log.i(TAG, "  Duration: ${result.scanDurationMs}ms")

        result
    }

    @Test
    fun verifyAllTestPDFs() = runBlocking {
        val testFiles = listOf(
            // MALICIOUS expected
            "demo_hidden_js_flatedecode.pdf" to "MALICIOUS",
            "demo_plaintext_js.pdf" to "MALICIOUS",
            "demo_embedded_exe.pdf" to "MALICIOUS",
            // SAFE/SUSPICIOUS expected (benign stress test)
            "demo_clean_simple.pdf" to "SAFE",
            "demo_openaction_goto.pdf" to "SAFE",
            "demo_embedded_xml_invoice.pdf" to "SUSPICIOUS",
            "demo_high_entropy_image.pdf" to "SAFE|SUSPICIOUS",
            "demo_acroform_fields.pdf" to "SAFE",
            "demo_embedded_fonts.pdf" to "SAFE",
            "demo_missing_eof.pdf" to "SUSPICIOUS"
        )

        val results = mutableListOf<Pair<String, String>>()

        for ((fileName, expected) in testFiles) {
            val result = scanFile(fileName)
            val actual = result?.verdict?.name ?: "ERROR"
            val pass = when {
                expected.contains("|") -> expected.split("|").any { it == actual }
                else -> expected == actual
            }
            val status = if (pass) "PASS" else "FAIL"
            results.add("$status: $fileName — expected=$expected actual=$actual" to status)
            Log.i(TAG, "[$status] $fileName: expected=$expected actual=$actual")
        }

        Log.i(TAG, "")
        Log.i(TAG, "========== SUMMARY ==========")
        results.forEach { (line, _) -> Log.i(TAG, line) }
        val passed = results.count { it.second == "PASS" }
        val failed = results.count { it.second == "FAIL" }
        Log.i(TAG, "Total: ${results.size} | Passed: $passed | Failed: $failed")

        // Assert all pass
        val failedTests = results.filter { it.second == "FAIL" }
        if (failedTests.isNotEmpty()) {
            val msg = failedTests.joinToString("\n") { it.first }
            throw AssertionError("Some tests failed:\n$msg")
        }
    }
}
