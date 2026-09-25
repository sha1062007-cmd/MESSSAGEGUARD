package com.messageguard.sandbox.scan

import android.content.Context
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

data class ApkScanResult(
    val maliciousProbability: Float,
    val isMalicious: Boolean,
    val riskFactors: List<String>,
    val inferenceTimeMs: Long
)

class PretrainedApkThreatEngine(private val context: Context) : AutoCloseable {

    private var tfliteInterpreter: Interpreter? = null
    private val lock = Any()

    init {
        initializeEngine()
    }

    private fun initializeEngine() {
        synchronized(lock) {
            try {
                val modelBuffer = loadModelFile("models/threat_engine_quant.tflite")
                if (modelBuffer != null) {
                    val options = Interpreter.Options().apply {
                        setNumThreads(2)
                    }
                    tfliteInterpreter = Interpreter(modelBuffer, options)
                }
            } catch (e: Exception) {
                tfliteInterpreter = null
            }
        }
    }

    private fun loadModelFile(assetPath: String): ByteBuffer? {
        return try {
            val fileDescriptor = context.assets.openFd(assetPath)
            val inputStream = FileInputStream(fileDescriptor.fileDescriptor)
            val fileChannel = inputStream.channel
            val startOffset = fileDescriptor.startOffset
            val declaredLength = fileDescriptor.declaredLength
            fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
        } catch (e: Exception) {
            null
        }
    }

    fun scanApk(featureVector: ApkFeatureVector): ApkScanResult {
        val startTime = System.currentTimeMillis()
        val interpreter = tfliteInterpreter

        // Fallback weighted scoring if model file is missing or failed initialization
        if (interpreter == null) {
            val fallbackScore = calculateFallbackScore(featureVector)
            return ApkScanResult(
                maliciousProbability = fallbackScore,
                isMalicious = fallbackScore >= 0.70f,
                riskFactors = extractRiskFactors(featureVector),
                inferenceTimeMs = System.currentTimeMillis() - startTime
            )
        }

        return synchronized(lock) {
            try {
                // Input shape: [1, 64] float tensor
                val inputBuffer = ByteBuffer.allocateDirect(ApkStaticExtractor.FEATURE_VECTOR_SIZE * 4)
                    .order(ByteOrder.nativeOrder())
                
                featureVector.features.forEach { inputBuffer.putFloat(it) }
                inputBuffer.flip()

                // Output shape: [1, 1] probability tensor
                val outputArray = Array(1) { FloatArray(1) }
                interpreter.run(inputBuffer, outputArray)

                val probability = outputArray[0][0].coerceIn(0.0f, 1.0f)
                val elapsed = System.currentTimeMillis() - startTime

                ApkScanResult(
                    maliciousProbability = probability,
                    isMalicious = probability >= 0.70f,
                    riskFactors = extractRiskFactors(featureVector),
                    inferenceTimeMs = elapsed
                )
            } catch (e: Exception) {
                val fallbackScore = calculateFallbackScore(featureVector)
                ApkScanResult(
                    maliciousProbability = fallbackScore,
                    isMalicious = fallbackScore >= 0.70f,
                    riskFactors = extractRiskFactors(featureVector),
                    inferenceTimeMs = System.currentTimeMillis() - startTime
                )
            }
        }
    }

    private fun calculateFallbackScore(featureVector: ApkFeatureVector): Float {
        var score = 0.0f
        if (featureVector.hasInstallPackagesFlag) score += 0.35f
        if (featureVector.hasSystemAlertWindowFlag) score += 0.25f
        if (featureVector.dangerousPermissionCount >= 10) score += 0.30f
        return score.coerceIn(0.0f, 1.0f)
    }

    private fun extractRiskFactors(vector: ApkFeatureVector): List<String> {
        val risks = mutableListOf<String>()
        if (vector.hasInstallPackagesFlag) risks.add("Requests permission to install external packages (REQUEST_INSTALL_PACKAGES)")
        if (vector.hasSystemAlertWindowFlag) risks.add("Requests permission to draw over other apps (SYSTEM_ALERT_WINDOW)")
        if (vector.dangerousPermissionCount >= 8) risks.add("Requests high volume of dangerous permissions (${vector.dangerousPermissionCount})")
        return risks
    }

    override fun close() {
        synchronized(lock) {
            tfliteInterpreter?.close()
            tfliteInterpreter = null
        }
    }
}
