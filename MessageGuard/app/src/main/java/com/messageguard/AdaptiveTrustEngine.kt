package com.messageguard

import android.content.Context
import android.util.Log

object AdaptiveTrustEngine {

    const val MIN_WEIGHT = 0.05f
    const val MAX_WEIGHT = 0.60f
    const val STEP_WRONG = 0.02f
    const val STEP_CORRECT = 0.01f

    // Weight Order: 0: URL CNN, 1: Text NLP, 2: BODMAS Core, 3: Typosquatting, 4: Reputation
    fun adjustWeightsOnFeedback(
        context: Context,
        result: AnalysisResult,
        isCorrect: Boolean,
        feedbackNote: String? = null
    ): FloatArray {
        val prefs = context.getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        val currentWeights = floatArrayOf(
            prefs.getFloat(Constants.KEY_WEIGHT_URL, Constants.DEFAULT_WEIGHT_URL),
            prefs.getFloat(Constants.KEY_WEIGHT_NLP, Constants.DEFAULT_WEIGHT_NLP),
            prefs.getFloat(Constants.KEY_WEIGHT_BODMAS, Constants.DEFAULT_WEIGHT_BODMAS),
            prefs.getFloat(Constants.KEY_WEIGHT_TYPOSQUAT, Constants.DEFAULT_WEIGHT_TYPOSQUAT),
            prefs.getFloat(Constants.KEY_WEIGHT_REPUTATION, Constants.DEFAULT_WEIGHT_REPUTATION)
        )

        Log.d("AdaptiveTrustEngine", "Starting weights adjustment. Current: ${currentWeights.joinToString()}")

        val subScores = parseSubScores(result.flags)
        val updatedWeights = currentWeights.copyOf()

        if (!isCorrect) {
            val isFalsePositive = result.verdict == Verdict.DANGER || result.verdict == Verdict.WARNING
            if (isFalsePositive) {
                // False Positive: Nudge DOWN the highest scoring model(s) that caused false alarm
                val maxScore = subScores.maxOrNull() ?: 0f
                val targetIndices = subScores.indices.filter { subScores[it] >= (maxScore - 0.05f) }
                nudgeWeightsDown(updatedWeights, targetIndices, STEP_WRONG)
            } else {
                // False Negative: Nudge UP the lowest scoring model(s) that missed the threat
                val minScore = subScores.minOrNull() ?: 1f
                val targetIndices = subScores.indices.filter { subScores[it] <= (minScore + 0.05f) }
                nudgeWeightsUp(updatedWeights, targetIndices, STEP_WRONG)
            }
        } else {
            // Correct feedback on DANGER/WARNING: Nudge UP agreeing model(s)
            if (result.verdict == Verdict.DANGER || result.verdict == Verdict.WARNING) {
                val maxScore = subScores.maxOrNull() ?: 0f
                val targetIndices = subScores.indices.filter { subScores[it] >= (maxScore - 0.05f) }
                nudgeWeightsUp(updatedWeights, targetIndices, STEP_CORRECT)
            }
        }

        // Clamp to [0.05, 0.60] and normalize sum to 1.0
        boundAndNormalizeWeights(updatedWeights)

        val weightSum = updatedWeights.sum()
        Log.d("AdaptiveTrustEngine", "Updated weights after adjustment (Sum=${"%.4f".format(weightSum)}): ${updatedWeights.joinToString()}")

        // Save back to SharedPreferences
        prefs.edit().apply {
            putFloat(Constants.KEY_WEIGHT_URL, updatedWeights[0])
            putFloat(Constants.KEY_WEIGHT_NLP, updatedWeights[1])
            putFloat(Constants.KEY_WEIGHT_BODMAS, updatedWeights[2])
            putFloat(Constants.KEY_WEIGHT_TYPOSQUAT, updatedWeights[3])
            putFloat(Constants.KEY_WEIGHT_REPUTATION, updatedWeights[4])
        }.apply()

        return updatedWeights
    }

    private fun nudgeWeightsDown(weights: FloatArray, targetIndices: List<Int>, step: Float) {
        val totalDelta = step * targetIndices.size
        val otherIndices = weights.indices.filter { it !in targetIndices }

        for (idx in targetIndices) {
            weights[idx] -= step
        }
        if (otherIndices.isNotEmpty()) {
            val share = totalDelta / otherIndices.size
            for (idx in otherIndices) {
                weights[idx] += share
            }
        }
    }

    private fun nudgeWeightsUp(weights: FloatArray, targetIndices: List<Int>, step: Float) {
        val totalDelta = step * targetIndices.size
        val otherIndices = weights.indices.filter { it !in targetIndices }

        for (idx in targetIndices) {
            weights[idx] += step
        }
        if (otherIndices.isNotEmpty()) {
            val share = totalDelta / otherIndices.size
            for (idx in otherIndices) {
                weights[idx] -= share
            }
        }
    }

    fun boundAndNormalizeWeights(weights: FloatArray) {
        if (weights.isEmpty()) return
        val n = weights.size
        for (iter in 0 until 5) {
            for (i in 0 until n) {
                weights[i] = if (weights[i].isFinite() && weights[i] >= 0f) {
                    weights[i].coerceIn(MIN_WEIGHT, MAX_WEIGHT)
                } else {
                    MIN_WEIGHT
                }
            }
            val sum = weights.sum()
            if (sum > 0f) {
                for (i in 0 until n) {
                    weights[i] = weights[i] / sum
                }
            }
        }
    }

    fun parseSubScores(flags: List<String>): FloatArray {
        var urlScore = 0f
        var nlpScore = 0f
        var bodmasScore = 0f
        var typoScore = 0f
        var repScore = 0f

        for (flag in flags) {
            val lower = flag.lowercase()
            val valStr = flag.substringAfter(":").trim().removeSuffix("%")
            val valFloat = (valStr.toFloatOrNull() ?: 0f) / 100f

            when {
                lower.contains("url forensic") -> urlScore = valFloat
                lower.contains("nlp engine") -> nlpScore = valFloat
                lower.contains("heuristic core") -> bodmasScore = valFloat
                lower.contains("typosquatting") -> typoScore = valFloat
                lower.contains("reputation") -> repScore = valFloat
            }
        }

        return floatArrayOf(urlScore, nlpScore, bodmasScore, typoScore, repScore)
    }
}
