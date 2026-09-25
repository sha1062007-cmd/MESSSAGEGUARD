package com.messageguard.sandbox.coordinator

import android.net.Uri
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

enum class DownloadIntentType {
    WHATSAPP_DOCUMENT,
    GMAIL_ATTACHMENT,
    GENERIC_DOWNLOAD
}

enum class ClaimState {
    PENDING_CAPTURE,
    CAPTURED,
    PROCESSED
}

data class PrimedIntent(
    val sourcePackage: String,
    val intentType: DownloadIntentType,
    val timestamp: Long,
    val windowMs: Long = 15_000L
) {
    val isExpired: Boolean get() = System.currentTimeMillis() - timestamp > windowMs
}

data class ClaimLock(
    val uriString: String,
    val claimedByLayer: String,
    val claimedAt: Long = System.currentTimeMillis(),
    val ttlMs: Long = 10_000L,
    var state: ClaimState = ClaimState.PENDING_CAPTURE
) {
    val isExpired: Boolean get() = state == ClaimState.PENDING_CAPTURE && (System.currentTimeMillis() - claimedAt > ttlMs)
}

object SandboxClaimCoordinator {

    private const val TAG = "SandboxCoordinator"
    private const val SHA256_DEDUP_WINDOW_MS = 60_000L

    // In-memory active URI/path claim locks with 10s TTL auto-release
    private val activeClaims = ConcurrentHashMap<String, ClaimLock>()

    // Primed intent registry for anticipatory user actions (e.g. Accessibility tap in WhatsApp)
    private val primedIntents = ConcurrentHashMap<String, PrimedIntent>()

    // Recently processed SHA-256 hashes to prevent redundant double-scans
    private val recentProcessedHashes = ConcurrentHashMap<String, Long>()

    /**
     * Attempts to atomically claim a file URI/Path for quarantine.
     * Returns true if claim was acquired by this layer.
     * If an existing claim is older than 10s and never moved to CAPTURED, it auto-releases and grants the claim.
     */
    @Synchronized
    fun tryClaim(uriOrPath: String, layerName: String): Boolean {
        cleanupExpired()

        val existing = activeClaims[uriOrPath]
        if (existing != null) {
            if (!existing.isExpired && existing.state != ClaimState.PENDING_CAPTURE) {
                Log.d(TAG, "[$layerName] File '$uriOrPath' already active in state ${existing.state} by '${existing.claimedByLayer}' — skipping duplicate.")
                return false
            } else if (existing.isExpired) {
                Log.w(TAG, "[$layerName] Previous claim on '$uriOrPath' by '${existing.claimedByLayer}' expired after 10s TTL without completion. Re-claiming for $layerName.")
            } else {
                Log.d(TAG, "[$layerName] File '$uriOrPath' currently locked by '${existing.claimedByLayer}' — waiting or skipping.")
                return false
            }
        }

        activeClaims[uriOrPath] = ClaimLock(
            uriString = uriOrPath,
            claimedByLayer = layerName,
            claimedAt = System.currentTimeMillis(),
            state = ClaimState.PENDING_CAPTURE
        )
        Log.i(TAG, "[$layerName] Claim ACQUIRED for '$uriOrPath'")
        return true
    }

    /**
     * Marks a claimed URI as successfully moved into sandbox pending folder.
     */
    fun markCaptured(uriOrPath: String) {
        activeClaims[uriOrPath]?.let {
            it.state = ClaimState.CAPTURED
            Log.d(TAG, "Claim '$uriOrPath' transitioned to CAPTURED.")
        }
    }

    /**
     * Retrieves the most recently claimed URI key.
     */
    fun getLatestActiveClaimUri(): String? {
        cleanupExpired()
        return activeClaims.values.maxByOrNull { it.claimedAt }?.uriString
    }

    /**
     * Marks processing complete (file released or deleted).
     */
    fun markProcessed(uriOrPath: String, sha256: String? = null) {
        activeClaims.remove(uriOrPath)
        if (!sha256.isNullOrBlank()) {
            recentProcessedHashes[sha256] = System.currentTimeMillis()
        }
        Log.d(TAG, "Claim '$uriOrPath' released and marked PROCESSED.")
    }

    /**
     * Registers an expected/anticipated download action (e.g. Accessibility tap on "Save").
     */
    fun registerExpectedDownload(
        sourcePackage: String,
        intentType: DownloadIntentType,
        windowMs: Long = 15_000L
    ) {
        primedIntents[sourcePackage] = PrimedIntent(
            sourcePackage = sourcePackage,
            intentType = intentType,
            timestamp = System.currentTimeMillis(),
            windowMs = windowMs
        )
        Log.i(TAG, "Primed expected download intent registered for '$sourcePackage' (window: ${windowMs}ms)")
    }

    /**
     * Checks if there is an active primed intent for a package and consumes it if found.
     */
    fun matchAndConsumePrimedIntent(sourcePackage: String): PrimedIntent? {
        val primed = primedIntents[sourcePackage] ?: return null
        return if (primed.isExpired) {
            primedIntents.remove(sourcePackage)
            null
        } else {
            primedIntents.remove(sourcePackage)
            Log.i(TAG, "Matched active primed intent for '$sourcePackage'!")
            primed
        }
    }

    /**
     * Path-aware correlation: matches and consumes primed intents based on the actual
     * landing directory path of the file (e.g. WhatsApp vs Gmail/Downloads).
     */
    fun matchPrimedIntentForPath(relativePathOrData: String): PrimedIntent? {
        val pathLower = relativePathOrData.lowercase()

        // 1. WhatsApp document directory -> strictly match WhatsApp packages
        if (pathLower.contains("com.whatsapp.w4b") || pathLower.contains("whatsapp business")) {
            return matchAndConsumePrimedIntent("com.whatsapp.w4b")
        }
        if (pathLower.contains("com.whatsapp") || pathLower.contains("whatsapp")) {
            return matchAndConsumePrimedIntent("com.whatsapp")
        }

        // 2. Standard Download directory -> match Gmail, Chrome, or Android Download Provider
        if (pathLower.contains("download")) {
            // Check specific app intents first before generic download provider
            return matchAndConsumePrimedIntent("com.google.android.gm")
                ?: matchAndConsumePrimedIntent("com.android.chrome")
                ?: matchAndConsumePrimedIntent("com.android.providers.downloads")
        }

        return null
    }

    /**
     * Returns the most recent active primed intent regardless of package, for attribution fallback.
     * Used by SandboxScanActivity to resolve source when callingPackage is generic.
     */
    fun getMostRecentPrimedIntent(): PrimedIntent? {
        cleanupExpired()
        return primedIntents.values.maxByOrNull { it.timestamp }?.takeIf { !it.isExpired }
    }

    /** Peek without consuming — for attribution in SandboxScanActivity. */
    fun peekPrimedIntent(sourcePackage: String): PrimedIntent? {
        cleanupExpired()
        return primedIntents[sourcePackage]?.takeIf { !it.isExpired }
    }

    /** Peek path-based correlation without consuming. */
    fun peekPrimedIntentForPath(relativePathOrData: String): PrimedIntent? {
        val pathLower = relativePathOrData.lowercase()
        if (pathLower.contains("com.whatsapp.w4b") || pathLower.contains("whatsapp business")) {
            return peekPrimedIntent("com.whatsapp.w4b")
        }
        if (pathLower.contains("com.whatsapp") || pathLower.contains("whatsapp")) {
            return peekPrimedIntent("com.whatsapp")
        }
        if (pathLower.contains("download")) {
            return peekPrimedIntent("com.google.android.gm")
                ?: peekPrimedIntent("com.android.chrome")
                ?: peekPrimedIntent("com.android.providers.downloads")
        }
        return null
    }

    /**
     * Checks if a file's SHA-256 hash was already scanned/processed within the 60s deduplication window.
     */
    fun isDuplicateHash(sha256: String): Boolean {
        val lastSeen = recentProcessedHashes[sha256] ?: return false
        val isFresh = (System.currentTimeMillis() - lastSeen) < SHA256_DEDUP_WINDOW_MS
        if (!isFresh) {
            recentProcessedHashes.remove(sha256)
        }
        return isFresh
    }

    private fun cleanupExpired() {
        val now = System.currentTimeMillis()
        activeClaims.entries.removeIf { (_, lock) -> lock.isExpired }
        primedIntents.entries.removeIf { (_, intent) -> intent.isExpired }
        recentProcessedHashes.entries.removeIf { (_, timestamp) -> (now - timestamp) > SHA256_DEDUP_WINDOW_MS }
    }
}
