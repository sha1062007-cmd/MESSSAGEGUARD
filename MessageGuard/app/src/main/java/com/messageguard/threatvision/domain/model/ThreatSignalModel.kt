package com.messageguard.threatvision.domain.model

/**
 * Pluggable Threat Signal Model Contract.
 * Allows on-device models (ONNX, TFLite), cloud models (Gemini), and future
 * heuristics to slot into the Threat Vision decision engine seamlessly.
 */
interface ThreatSignalModel {
    /** Unique identifier matching entries in manifest.json (e.g. "bec_classifier", "gemini_ensemble") */
    val modelId: String

    /** Human-readable model version or signature */
    val version: String

    /** Input specifications expected by this model */
    val inputSpec: InputSpec

    /**
     * Executes inference on the extracted email features.
     * Returns a [SignalScore] with risk rating (0.0 to 1.0) and confidence.
     */
    suspend fun score(features: SignalFeatures): SignalScore

    /** Releases internal resources, sessions, or buffers. */
    fun close() {}
}

enum class InputType {
    TEXT,
    URL_LIST,
    FEATURE_VECTOR,
    RAW_HEADERS
}

data class InputSpec(
    val type: InputType,
    val vectorDimension: Int? = null,
    val description: String = ""
)

data class SignalFeatures(
    val rawText: String = "",
    val subject: String = "",
    val sender: String = "",
    val urls: List<String> = emptyList(),
    val numericVector: FloatArray? = null,
    val headers: Map<String, String> = emptyMap()
)

data class SignalScore(
    val modelId: String,
    /** Normalized risk rating from 0.0 (safe) to 1.0 (imminent danger) */
    val riskScore: Float,
    /** Confidence in the prediction from 0.0 to 1.0 */
    val confidence: Float,
    val category: String = "SUSPICIOUS",
    val explanation: String = "",
    val status: ModelStatus = ModelStatus.ACTIVE
)

enum class ModelStatus {
    ACTIVE,
    DISABLED_AWAITING_SPEC,
    STUB,
    FAILED
}
