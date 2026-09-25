package com.messageguard.sandbox.model

/**
 * Capture source indicating which trigger layer provided the file reference.
 */
enum class CaptureSource {
    NOTIFICATION_LISTENER,
    MEDIASTORE_OBSERVER,
    ACCESSIBILITY_ENGINE,
    SWEEP_WORKER,
    USER_OPEN
}

/**
 * Lifecycle status of a quarantined file inside the sandbox.
 */
enum class SandboxStatus {
    PENDING_SCAN,
    SCANNING,
    SAFE,
    SUSPICIOUS,
    INFECTED,
    FAILED_CAPTURE
}

/**
 * Core data model representing a captured/quarantined download in the sandbox.
 */
data class SandboxItem(
    val id: String,                         // sandbox_<timestamp>_<uuid>
    val originalFileName: String,          // Preserved for display only, never used on disk
    val originalMimeType: String,
    val fileSize: Long,
    val sha256: String,
    val sourcePackage: String,
    val captureSource: CaptureSource,
    val quarantinedFilePath: String,       // Absolute path inside context.filesDir/file_sandbox/pending/
    val status: SandboxStatus = SandboxStatus.PENDING_SCAN,
    val timestamp: Long = System.currentTimeMillis()
)
