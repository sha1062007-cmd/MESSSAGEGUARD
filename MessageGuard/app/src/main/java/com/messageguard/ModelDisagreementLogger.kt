package com.messageguard

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * ModelDisagreementLogger — Tracks and logs model disagreements for error analysis.
 *
 * When multiple models in the ensemble disagree strongly, this logger captures
 * the diagnostic information needed to understand WHY the prediction was wrong.
 *
 * Privacy: Only model scores and decision outcomes are logged.
 * Message content is NEVER logged (redacted).
 */
object ModelDisagreementLogger {

    private const val TAG = "ModelDisagreement"

    data class DisagreementEvent(
        val timestamp: Long,
        val mlScore: Int,
        val urlScore: Float,
        val nlpScore: Float,
        val bodmasScore: Float,
        val typosquatScore: Float,
        val reputationScore: Float,
        val disagreement: Float,
        val uncertaintyReason: String?,
        val finalVerdict: Verdict,
        val aiScore: Int = -1
    )

    // Store recent disagreements for analysis (max 500 entries)
    private val recentDisagreements = object : LinkedHashMap<Long, DisagreementEvent>(100, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, DisagreementEvent>): Boolean {
            return size > 500
        }
    }

    /**
     * Log a disagreement event if the models disagree significantly.
     */
    fun logDisagreement(
        mlScore: Int,
        urlScore: Float,
        nlpScore: Float,
        bodmasScore: Float,
        typosquatScore: Float,
        reputationScore: Float,
        disagreement: Float,
        uncertaintyReason: String?,
        finalVerdict: Verdict,
        aiScore: Int = -1
    ) {
        if (disagreement < 0.25f) return // Only log meaningful disagreements

        val event = DisagreementEvent(
            timestamp = System.currentTimeMillis(),
            mlScore = mlScore,
            urlScore = urlScore,
            nlpScore = nlpScore,
            bodmasScore = bodmasScore,
            typosquatScore = typosquatScore,
            reputationScore = reputationScore,
            disagreement = disagreement,
            uncertaintyReason = uncertaintyReason,
            finalVerdict = finalVerdict,
            aiScore = aiScore
        )

        synchronized(recentDisagreements) {
            recentDisagreements[event.timestamp] = event
        }

        // Determine which models disagree
        val highModels = mutableListOf<String>()
        val lowModels = mutableListOf<String>()
        if (urlScore > 0.60f) highModels.add("URL") else lowModels.add("URL")
        if (nlpScore > 0.60f) highModels.add("NLP") else lowModels.add("NLP")
        if (bodmasScore > 0.60f) highModels.add("BODMAS") else lowModels.add("BODMAS")
        if (typosquatScore > 0.50f) highModels.add("TYPO") else lowModels.add("TYPO")

        Log.w(TAG, "DISAGREEMENT_EVENT: mlPct=$mlScore% verdict=$finalVerdict " +
            "std=${"%.3f".format(disagreement)} " +
            "HIGH=[${highModels.joinToString(",")}] LOW=[${lowModels.joinToString(",")}] " +
            "uncertainty=${uncertaintyReason ?: "none"}")
    }

    /**
     * Get summary statistics of recent disagreements.
     */
    fun getDisagreementSummary(): String {
        synchronized(recentDisagreements) {
            if (recentDisagreements.isEmpty()) return "No disagreement events recorded"
            val events = recentDisagreements.values.toList()
            val avgDisagreement = events.map { it.disagreement }.average()
            val avgMlScore = events.map { it.mlScore }.average()
            val verdictCounts = events.groupBy { it.finalVerdict }
                .mapValues { it.value.size }
            return "Events=${events.size} AvgStd=${"%.3f".format(avgDisagreement)} " +
                "AvgMlPct=${"%.1f".format(avgMlScore)} " +
                "Verdicts=$verdictCounts"
        }
    }

    /**
     * Get the most recent N disagreement events for diagnostic output.
     */
    fun getRecentDisagreements(n: Int = 20): List<DisagreementEvent> {
        synchronized(recentDisagreements) {
            val values = recentDisagreements.values.toList()
            return if (values.size <= n) values else values.subList(values.size - n, values.size)
        }
    }

    /**
     * Clear all recorded disagreements.
     */
    fun clear() {
        synchronized(recentDisagreements) {
            recentDisagreements.clear()
        }
    }
}
