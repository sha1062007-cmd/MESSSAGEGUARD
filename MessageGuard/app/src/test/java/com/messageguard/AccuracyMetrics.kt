package com.messageguard

/**
 * AccuracyMetrics — Computes precision, recall, F1, specificity, confusion matrix,
 * and per-class metrics for the Threat Vision detection pipeline.
 *
 * Ground truth mapping:
 * - SAFE → expected SAFE verdict
 * - SUSPICIOUS → expected WARNING or DANGER
 * - PHISHING → expected WARNING or DANGER
 * - MALICIOUS → expected DANGER
 * - BORDERLINE → any verdict accepted
 */
object AccuracyMetrics {

    data class MetricResult(
        val accuracy: Double,
        val precision: Double,
        val recall: Double,
        val f1Score: Double,
        val specificity: Double,
        val falsePositiveRate: Double,
        val falseNegativeRate: Double,
        val confusionMatrix: ConfusionMatrix,
        val perClassMetrics: Map<String, ClassMetrics>
    )

    data class ConfusionMatrix(
        val truePositives: Int,
        val falsePositives: Int,
        val trueNegatives: Int,
        val falseNegatives: Int
    ) {
        val total: Int get() = truePositives + falsePositives + trueNegatives + falseNegatives
    }

    data class ClassMetrics(
        val className: String,
        val precision: Double,
        val recall: Double,
        val f1Score: Double,
        val support: Int
    )

    data class Prediction(
        val sampleId: String,
        val expectedCategory: ThreatVisionTestDataset.Category,
        val predictedVerdict: Verdict,
        val mlScore: Int,
        val urlScore: Float,
        val nlpScore: Float,
        val bodmasScore: Float,
        val typosquatScore: Float,
        val reputationScore: Float,
        val modelFiredCount: Int
    )

    /**
     * Evaluate a list of predictions against ground truth.
     * For binary classification: threat vs safe.
     */
    fun evaluate(predictions: List<Prediction>): MetricResult {
        // Binary classification: threat vs safe
        val tp = predictions.count { isThreat(it.expectedCategory) && isThreatVerdict(it.predictedVerdict) }
        val fp = predictions.count { !isThreat(it.expectedCategory) && isThreatVerdict(it.predictedVerdict) }
        val tn = predictions.count { !isThreat(it.expectedCategory) && !isThreatVerdict(it.predictedVerdict) }
        val fn = predictions.count { isThreat(it.expectedCategory) && !isThreatVerdict(it.predictedVerdict) }

        val cm = ConfusionMatrix(tp, fp, tn, fn)
        val accuracy = if (cm.total > 0) (tp + tn).toDouble() / cm.total else 0.0
        val precision = if (tp + fp > 0) tp.toDouble() / (tp + fp) else 0.0
        val recall = if (tp + fn > 0) tp.toDouble() / (tp + fn) else 0.0
        val f1 = if (precision + recall > 0) 2.0 * precision * recall / (precision + recall) else 0.0
        val specificity = if (tn + fp > 0) tn.toDouble() / (tn + fp) else 0.0
        val fpr = if (fp + tn > 0) fp.toDouble() / (fp + tn) else 0.0
        val fnr = if (fn + tp > 0) fn.toDouble() / (fn + tp) else 0.0

        // Per-class metrics (SAFE, SUSPICIOUS, PHISHING, MALICIOUS)
        val perClass = mutableMapOf<String, ClassMetrics>()
        for (cat in listOf("SAFE", "SUSPICIOUS", "PHISHING", "MALICIOUS")) {
            val catPredictions = predictions.filter { it.expectedCategory.name == cat }
            if (catPredictions.isEmpty()) continue

            val catTp = catPredictions.count { matchesCategory(it.predictedVerdict, cat) }
            val catFn = catPredictions.size - catTp

            // For this class, everything else is "negative"
            val otherPredictions = predictions.filter { it.expectedCategory.name != cat }
            val catFp = otherPredictions.count { matchesCategory(it.predictedVerdict, cat) }

            val catPrecision = if (catTp + catFp > 0) catTp.toDouble() / (catTp + catFp) else 0.0
            val catRecall = if (catTp + catFn > 0) catTp.toDouble() / (catTp + catFn) else 0.0
            val catF1 = if (catPrecision + catRecall > 0) 2.0 * catPrecision * catRecall / (catPrecision + catRecall) else 0.0

            perClass[cat] = ClassMetrics(cat, catPrecision, catRecall, catF1, catPredictions.size)
        }

        return MetricResult(
            accuracy = accuracy,
            precision = precision,
            recall = recall,
            f1Score = f1,
            specificity = specificity,
            falsePositiveRate = fpr,
            falseNegativeRate = fnr,
            confusionMatrix = cm,
            perClassMetrics = perClass
        )
    }

    /**
     * Evaluate per-component accuracy (URL detection, NLP, etc.)
     */
    fun evaluateComponent(
        predictions: List<Prediction>,
        component: String,
        threshold: Float
    ): MetricResult {
        val componentPredictions = predictions.map { pred ->
            val score = when (component) {
                "URL" -> pred.urlScore
                "NLP" -> pred.nlpScore
                "BODMAS" -> pred.bodmasScore
                "TYPOSQUAT" -> pred.typosquatScore
                else -> 0f
            }
            val predictedThreat = score > threshold
            val expectedThreat = isThreat(pred.expectedCategory)
            Prediction(
                sampleId = pred.sampleId,
                expectedCategory = pred.expectedCategory,
                predictedVerdict = if (predictedThreat) Verdict.DANGER else Verdict.SAFE,
                mlScore = pred.mlScore,
                urlScore = pred.urlScore,
                nlpScore = pred.nlpScore,
                bodmasScore = pred.bodmasScore,
                typosquatScore = pred.typosquatScore,
                reputationScore = pred.reputationScore,
                modelFiredCount = pred.modelFiredCount
            )
        }
        return evaluate(componentPredictions)
    }

    /**
     * Generate error analysis report.
     */
    fun generateErrorAnalysis(predictions: List<Prediction>): Map<String, List<Prediction>> {
        val falsePositives = predictions.filter { !isThreat(it.expectedCategory) && isThreatVerdict(it.predictedVerdict) }
        val falseNegatives = predictions.filter { isThreat(it.expectedCategory) && !isThreatVerdict(it.predictedVerdict) }
        val truePositives = predictions.filter { isThreat(it.expectedCategory) && isThreatVerdict(it.predictedVerdict) }
        val trueNegatives = predictions.filter { !isThreat(it.expectedCategory) && !isThreatVerdict(it.predictedVerdict) }

        return mapOf(
            "FALSE_POSITIVES" to falsePositives,
            "FALSE_NEGATIVES" to falseNegatives,
            "TRUE_POSITIVES" to truePositives,
            "TRUE_NEGATIVES" to trueNegatives
        )
    }

    /**
     * Print a formatted accuracy report.
     */
    fun printReport(result: MetricResult, label: String = "") {
        val header = if (label.isNotEmpty()) "=== $label ACCURACY REPORT ===" else "=== ACCURACY REPORT ==="
        println(header)
        println("Accuracy:        ${"%.2f%%".format(result.accuracy * 100)}")
        println("Precision:       ${"%.2f%%".format(result.precision * 100)}")
        println("Recall:          ${"%.2f%%".format(result.recall * 100)}")
        println("F1 Score:        ${"%.2f%%".format(result.f1Score * 100)}")
        println("Specificity:     ${"%.2f%%".format(result.specificity * 100)}")
        println("False Pos. Rate: ${"%.2f%%".format(result.falsePositiveRate * 100)}")
        println("False Neg. Rate: ${"%.2f%%".format(result.falseNegativeRate * 100)}")
        println()
        println("Confusion Matrix:")
        println("  TP=${result.confusionMatrix.truePositives}  FP=${result.confusionMatrix.falsePositives}")
        println("  FN=${result.confusionMatrix.falseNegatives}  TN=${result.confusionMatrix.trueNegatives}")
        println("  Total=${result.confusionMatrix.total}")
        println()
        println("Per-Class Metrics:")
        for ((name, metrics) in result.perClassMetrics) {
            println("  $name: P=${"%.2f%%".format(metrics.precision * 100)} R=${"%.2f%%".format(metrics.recall * 100)} F1=${"%.2f%%".format(metrics.f1Score * 100)} Support=${metrics.support}")
        }
        println("=".repeat(header.length))
    }

    private fun isThreat(category: ThreatVisionTestDataset.Category): Boolean =
        category in listOf(ThreatVisionTestDataset.Category.SUSPICIOUS, ThreatVisionTestDataset.Category.PHISHING, ThreatVisionTestDataset.Category.MALICIOUS)

    private fun isThreatVerdict(verdict: Verdict): Boolean =
        verdict in listOf(Verdict.WARNING, Verdict.DANGER)

    private fun matchesCategory(verdict: Verdict, expectedCat: String): Boolean =
        when (expectedCat) {
            "SAFE" -> verdict == Verdict.SAFE
            "SUSPICIOUS" -> verdict == Verdict.WARNING
            "PHISHING" -> verdict == Verdict.WARNING || verdict == Verdict.DANGER
            "MALICIOUS" -> verdict == Verdict.DANGER
            else -> false
        }
}
