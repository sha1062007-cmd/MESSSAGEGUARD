package com.messageguard.sandbox.trigger

import android.os.Build

/**
 * Shared filter policy used by both MediaStoreDownloadObserver and PeriodicDownloadSweepWorker.
 * Guarantees zero divergence in path, size, and extension filtering.
 */
object DownloadFilterPolicy {

    // Disallowed partial / temporary / system noise extensions
    val EXCLUDED_EXTENSIONS = setOf(
        "tmp", "crdownload", "part", "download", "nomedia", "cache"
    )

    // Allowed / Targeted directory path prefixes
    val TARGET_PATH_PATTERNS = listOf(
        "Download",
        "Downloads",
        "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents",
        "Android/media/com.whatsapp.w4b/WhatsApp Business/Media/WhatsApp Business Documents"
    )

    // Monitored packages that can prime download intents
    val MONITORED_PACKAGES = listOf(
        "com.whatsapp",
        "com.whatsapp.w4b",
        "com.google.android.gm",
        "com.android.chrome",
        "com.android.providers.downloads"
    )

    fun isQualifyingDownload(
        displayName: String,
        size: Long,
        relativePathOrData: String
    ): Boolean {
        // 1. Filter zero-byte or negative size files
        if (size <= 0) return false

        // 2. Filter partial / temp download extensions
        val ext = displayName.substringAfterLast('.', "").lowercase()
        if (ext.isBlank() || EXCLUDED_EXTENSIONS.contains(ext)) return false

        // 3. Filter strictly to target download directories
        val isTargetDir = TARGET_PATH_PATTERNS.any { target ->
            relativePathOrData.contains(target, ignoreCase = true)
        }
        return isTargetDir
    }
}
