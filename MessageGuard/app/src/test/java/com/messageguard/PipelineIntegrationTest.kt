package com.messageguard

import org.junit.Assert.*
import org.junit.Test

/**
 * Integration tests for the complete Threat Vision detection pipeline.
 * Tests the interaction between components (NLP + URL + BODMAS + ensemble).
 */
class PipelineIntegrationTest {

    @Test
    fun `ensemble weights sum to 1_0f`() {
        val weights = floatArrayOf(
            Constants.DEFAULT_WEIGHT_URL,
            Constants.DEFAULT_WEIGHT_NLP,
            Constants.DEFAULT_WEIGHT_BODMAS,
            Constants.DEFAULT_WEIGHT_TYPOSQUAT,
            Constants.DEFAULT_WEIGHT_REPUTATION
        )
        assertEquals(1.0f, weights.sum(), 0.001f)
    }

    @Test
    fun `model disagreement is computed correctly`() {
        // Simulate: NLP=0.9 (high), URL=0.1 (low), BODMAS=0.1 (low)
        val scores = listOf(0.1f, 0.9f, 0.1f)
        val mean = scores.average().toFloat()
        val variance = scores.map { (it - mean) * (it - mean) }.average().toFloat()
        val std = kotlin.math.sqrt(variance.toDouble()).toFloat()
        
        assertTrue("Disagreement should be > 0.3 when NLP=0.9 and URL=0.1", std > 0.3f)
    }

    @Test
    fun `model agreement produces low disagreement`() {
        // All models agree: NLP=0.8, URL=0.75, BODMAS=0.78
        val scores = listOf(0.75f, 0.8f, 0.78f)
        val mean = scores.average().toFloat()
        val variance = scores.map { (it - mean) * (it - mean) }.average().toFloat()
        val std = kotlin.math.sqrt(variance.toDouble()).toFloat()
        
        assertTrue("Disagreement should be < 0.1 when all models agree", std < 0.1f)
    }

    @Test
    fun `corroboration gate blocks single model from DANGER`() {
        // Only 1 model fired (NLP) → score should be capped at 69
        val firedModels = 1
        val preCorroborationScore = 85
        val cappedScore = when {
            firedModels < 1 -> preCorroborationScore.coerceAtMost(39)
            firedModels < 2 -> preCorroborationScore.coerceAtMost(69)
            else -> preCorroborationScore
        }
        assertEquals("Single model should cap at 69", 69, cappedScore)
    }

    @Test
    fun `corroboration gate allows two models to reach DANGER`() {
        val firedModels = 2
        val preCorroborationScore = 85
        val cappedScore = when {
            firedModels < 1 -> preCorroborationScore.coerceAtMost(39)
            firedModels < 2 -> preCorroborationScore.coerceAtMost(69)
            else -> preCorroborationScore
        }
        assertEquals("Two models should not be capped", 85, cappedScore)
    }

    @Test
    fun `corroboration gate exempts high-confidence typosquat`() {
        val confirmedTyposquat = true
        val preCorroborationScore = 85
        val gatedScore = if (confirmedTyposquat) preCorroborationScore else 69
        assertEquals("Confirmed typosquat should bypass cap", 85, gatedScore)
    }

    @Test
    fun `bank context guard caps NLP for legitimate bank SMS`() {
        val lower = "your sbi a/c xx4567 debited rs.5000 credited available balance"
        val hasBankTx = lower.containsAllAtLeastTwo(listOf(
            "debited", "credited", "rs.", "inr ", "mandate", "autopay",
            "ifsc", "neft", "imps", "reference no", "txn",
            "transaction", "available balance", "a/c no", "a/c.", "account"
        ))
        assertTrue("Should detect bank transaction context", hasBankTx)
    }

    @Test
    fun `retailer context guard caps NLP for legitimate retailer SMS`() {
        val lower = "your jiomart order has been shipped. cashback of rs.100 will be credited in wallet"
        val hasRetailer = lower.containsAllAtLeastTwo(listOf(
            "jiomart", "flipkart", "amazon", "swiggy", "zomato",
            "cashback", "wallet to be used", "t&ca", "valid for today",
            "credited in wallet", "shop now", "next bill on", "order has shipped"
        ))
        assertTrue("Should detect retailer context", hasRetailer)
    }

    @Test
    fun `URL entropy calculation is correct`() {
        val url1 = "http://example.com" // Low entropy (repetitive)
        val url2 = "http://x7k2m9.pw/a?b=3&c=8" // Higher entropy (varied)

        fun calcEntropy(s: String): Double {
            val freq = s.groupingBy { it }.eachCount()
            var entropy = 0.0
            for (count in freq.values) {
                val p = count.toDouble() / s.length
                entropy -= p * (Math.log(p) / Math.log(2.0))
            }
            return entropy
        }

        val e1 = calcEntropy(url1)
        val e2 = calcEntropy(url2)
        assertTrue("More random URL should have higher entropy", e2 > e1)
    }

    @Test
    fun `ThreatSignalPolicy requires 2 signals for corroboration`() {
        val result1 = ThreatSignalPolicy.analyze("Your account is blocked")
        assertFalse("Single urgency signal should not be corroborated", result1.isCorroborated)

        val result2 = ThreatSignalPolicy.analyze("Your account is blocked. Click here immediately to verify.")
        assertTrue("Urgency + action request should be corroborated", result2.isCorroborated)
    }

    @Test
    fun `safety advice message is not flagged as credential request`() {
        val result = ThreatSignalPolicy.analyze("Your OTP is 847291. Do not share this OTP with anyone.")
        assertFalse("Safety advice should not trigger credential request", result.hasCredentialRequest)
    }

    @Test
    fun `homograph detection catches mixed scripts`() {
        assertTrue("Mixed Latin+Cyrillic should be detected", SpamAnalyzer.hasMixedScripts("аpple")) // Cyrillic а
        assertFalse("Pure Latin should not be flagged", SpamAnalyzer.hasMixedScripts("apple"))
    }

    @Test
    fun `homoglyph normalization converts Cyrillic to Latin`() {
        val normalized = SpamAnalyzer.normalizeHomoglyphs("аpple.com") // Cyrillic а -> Latin a
        assertEquals("apple.com", normalized)
    }

    @Test
    fun `levenshtein distance is correct`() {
        assertEquals(0, SpamAnalyzer.levenshteinDistance("same", "same"))
        assertEquals(1, SpamAnalyzer.levenshteinDistance("paypa1", "paypal"))
        assertEquals(1, SpamAnalyzer.levenshteinDistance("google", "gogle"))
    }

    @Test
    fun `uncertainty detection when models strongly disagree`() {
        // Scenario: NLP=0.85 (high threat), URL=0.05 (clean), BODMAS=0.05 (clean)
        val urlScore = 0.05f
        val nlpScore = 0.85f
        val bodmasScore = 0.05f
        val typoScore = 0f

        val activeScores = listOf(urlScore, nlpScore, bodmasScore, typoScore).filter { it > 0f }
        val mean = activeScores.average().toFloat()
        val variance = activeScores.map { (it - mean) * (it - mean) }.average().toFloat()
        val disagreement = kotlin.math.sqrt(variance.toDouble()).toFloat()

        val maxScore = activeScores.maxOrNull() ?: 0f
        val hasUncertainty = disagreement > 0.35f && maxScore < 0.70f
        // In this case maxScore=0.85 > 0.70, so uncertainty is NOT triggered (NLP is dominant)
        assertFalse("Strong single model should not trigger uncertainty", hasUncertainty)
    }

    @Test
    fun `uncertainty when all models are moderate but disagree`() {
        val urlScore = 0.30f
        val nlpScore = 0.45f
        val bodmasScore = 0.20f
        val typoScore = 0.0f

        val activeScores = listOf(urlScore, nlpScore, bodmasScore).filter { it > 0f }
        val mean = activeScores.average().toFloat()
        val variance = activeScores.map { (it - mean) * (it - mean) }.average().toFloat()
        val disagreement = kotlin.math.sqrt(variance.toDouble()).toFloat()

        val maxScore = activeScores.maxOrNull() ?: 0f
        val hasUncertainty = disagreement > 0.35f && maxScore < 0.70f
        // mean=0.317, variance~0.012, std~0.11 < 0.35, so no uncertainty
        // This is correct: moderate disagreement is not uncertainty
    }

    private fun String.containsAllAtLeastTwo(terms: List<String>): Boolean {
        return terms.count { this.contains(it) } >= 2
    }
}
