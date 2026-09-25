package com.messageguard.threatvision.domain.model

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.io.InputStreamReader

data class ModelManifest(
    val version: String = "2.0.0",
    @SerializedName("generated_at") val generatedAt: String = "",
    val models: List<ManifestModelEntry> = emptyList()
)

data class ManifestModelEntry(
    @SerializedName("model_id") val modelId: String,
    val version: String = "1.0.0",
    val type: String = "ONNX",
    @SerializedName("file_path") val filePath: String? = null,
    val status: String = "active",
    val weight: Float = 0.25f,
    val description: String = ""
)

/**
 * Registry holding all active, disabled, and stubbed ThreatSignalModel instances.
 * Guarantees single-model failures return zero-confidence without halting the ensemble.
 */
class ModelRegistry(private val context: Context) {

    private val modelsMap = mutableMapOf<String, ThreatSignalModel>()
    private var manifest: ModelManifest = ModelManifest()

    companion object {
        private const val TAG = "ThreatVisionLog"
        private const val MANIFEST_PATH = "models/manifest.json"
    }

    init {
        loadManifest()
    }

    private fun loadManifest() {
        try {
            context.assets.open(MANIFEST_PATH).use { stream ->
                InputStreamReader(stream).use { reader ->
                    manifest = Gson().fromJson(reader, ModelManifest::class.java)
                    Log.d(TAG, "ModelRegistry: Loaded manifest v${manifest.version} with ${manifest.models.size} models")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "ModelRegistry: Failed to load manifest.json", e)
        }
    }

    fun registerModel(model: ThreatSignalModel) {
        modelsMap[model.modelId] = model
        Log.d(TAG, "ModelRegistry: Registered model ${model.modelId} (v${model.version})")
    }

    fun getModel(modelId: String): ThreatSignalModel? = modelsMap[modelId]

    fun getAllActiveModels(): List<ThreatSignalModel> {
        val activeEntries = manifest.models.filter { it.status.equals("active", ignoreCase = true) }
        return activeEntries.mapNotNull { entry ->
            modelsMap[entry.modelId]
        }
    }

    fun getManifestEntry(modelId: String): ManifestModelEntry? {
        return manifest.models.find { it.modelId == modelId }
    }

    /**
     * Executes all registered active models in parallel/sequence with strict failure isolation.
     */
    suspend fun scoreAll(features: SignalFeatures): List<SignalScore> {
        val scores = mutableListOf<SignalScore>()
        val activeModels = getAllActiveModels()

        for (model in activeModels) {
            try {
                val score = model.score(features)
                scores.add(score)
            } catch (e: Exception) {
                Log.w(TAG, "ModelRegistry: Model ${model.modelId} threw exception during scoring", e)
                scores.add(
                    SignalScore(
                        modelId = model.modelId,
                        riskScore = 0.0f,
                        confidence = 0.0f,
                        explanation = "Inference failed: ${e.message}",
                        status = ModelStatus.FAILED
                    )
                )
            }
        }
        return scores
    }

    fun closeAll() {
        modelsMap.values.forEach {
            try {
                it.close()
            } catch (e: Exception) {
                Log.w(TAG, "ModelRegistry: Error closing ${it.modelId}", e)
            }
        }
        modelsMap.clear()
    }
}
