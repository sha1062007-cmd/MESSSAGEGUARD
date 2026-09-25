package com.messageguard.sandbox.capture

import android.content.Context
import android.net.Uri
import android.util.Log
import com.messageguard.sandbox.model.CaptureSource
import com.messageguard.sandbox.model.SandboxItem
import com.messageguard.sandbox.model.SandboxStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * Phase 2 Capture Engine: Safely copies incoming downloads into private quarantine storage,
 * computes SHA-256 hash on-the-fly, enforces non-trusted naming, and cleans up on failure.
 */
object SandboxCaptureEngine {

    private const val TAG = "SandboxCaptureEngine"
    private val capturedItems = ConcurrentHashMap<String, SandboxItem>()

    fun getAllCapturedItems(): List<SandboxItem> = capturedItems.values.toList()

    fun getItem(id: String): SandboxItem? = capturedItems[id]

    /**
     * Captures a file from a content Uri or stream source.
     * Logs the EXACT capture source and reports any stream-open failures with full fidelity.
     */
    suspend fun captureFile(
        context: Context,
        sourceUri: Uri?,
        directStream: InputStream? = null,
        originalFileName: String,
        originalMimeType: String = "application/octet-stream",
        sourcePackage: String,
        captureSource: CaptureSource
    ): SandboxItem? = withContext(Dispatchers.IO) {
        val fileStore = SandboxFileStore(context)
        val destinationFile = fileStore.createQuarantineFile()

        Log.i(
            TAG,
            "[CaptureEngine] >>> Starting capture attempt. Source=$captureSource, File='$originalFileName', URI=$sourceUri, Destination='${destinationFile.name}'"
        )

        var bytesCopied = 0L
        val digest = MessageDigest.getInstance("SHA-256")

        try {
            val inputStream: InputStream? = directStream ?: if (sourceUri != null) {
                Log.d(TAG, "[CaptureEngine] Opening ContentResolver stream on: $sourceUri (Source: $captureSource)")
                context.contentResolver.openInputStream(sourceUri)
            } else {
                null
            }

            if (inputStream == null) {
                Log.e(
                    TAG,
                    "[CaptureEngine] FAILED: Stream could not be opened for '$originalFileName' via $captureSource (Uri=$sourceUri). Scoped Storage or invalid reference."
                )
                destinationFile.delete()
                return@withContext null
            }

            inputStream.use { input ->
                FileOutputStream(destinationFile).use { output ->
                    val buffer = ByteArray(8192)
                    var read: Int
                    while (input.read(buffer).also { read = it } != -1) {
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        bytesCopied += read
                    }
                    output.flush()
                }
            }

            val sha256Hex = digest.digest().joinToString("") { "%02x".format(it) }

            Log.i(
                TAG,
                "[CaptureEngine] SUCCESS: Captured '$originalFileName' ($bytesCopied bytes) via $captureSource into '${destinationFile.absolutePath}'. SHA-256=$sha256Hex"
            )

            val item = SandboxItem(
                id = destinationFile.nameWithoutExtension,
                originalFileName = originalFileName,
                originalMimeType = originalMimeType,
                fileSize = bytesCopied,
                sha256 = sha256Hex,
                sourcePackage = sourcePackage,
                captureSource = captureSource,
                quarantinedFilePath = destinationFile.absolutePath,
                status = SandboxStatus.PENDING_SCAN
            )

            capturedItems[item.id] = item
            return@withContext item

        } catch (e: SecurityException) {
            Log.e(TAG, "[CaptureEngine] SECURITY EXCEPTION: Access denied reading $sourceUri via $captureSource", e)
            destinationFile.delete()
            return@withContext null
        } catch (e: Exception) {
            Log.e(TAG, "[CaptureEngine] ERROR: Failed while capturing '$originalFileName' via $captureSource", e)
            destinationFile.delete()
            return@withContext null
        }
    }
}
