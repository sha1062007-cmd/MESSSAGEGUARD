package com.messageguard.sandbox.capture

import android.content.Context
import java.io.File
import java.util.UUID

/**
 * Handles creation and path resolution for the app-private sandbox storage.
 * All files are isolated in context.filesDir/file_sandbox/pending/.
 * Filenames are strictly sanitized to random non-executable identifiers.
 */
class SandboxFileStore(private val context: Context) {

    private val sandboxDir: File
        get() = File(context.filesDir, "file_sandbox/pending").also {
            if (!it.exists()) {
                it.mkdirs()
            }
        }

    /**
     * Generates a collision-resistant, non-executable filename:
     * sandbox_<timestamp>_<uuid>.bin
     */
    fun createQuarantineFile(): File {
        val uniqueId = UUID.randomUUID().toString().replace("-", "").take(8)
        val fileName = "sandbox_${System.currentTimeMillis()}_$uniqueId.bin"
        return File(sandboxDir, fileName)
    }

    /**
     * Cleans up all pending files in the sandbox directory.
     */
    fun clearPending(): Boolean {
        return try {
            sandboxDir.listFiles()?.forEach { it.delete() }
            true
        } catch (e: Exception) {
            false
        }
    }
}
