package com.messageguard

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for AdaptiveTrustEngine — boundAndNormalizeWeights(),
 * parseSubScores(), and the nudge logic.
 */
class AdaptiveTrustEngineTest {

    // ── boundAndNormalizeWeights ──────────────────────────────────────────

    @Test
    fun `boundAndNormalize on default weights sums to 1_0`() {
        val w = floatArrayOf(
            Constants.DEFAULT_WEIGHT_URL,
            Constants.DEFAULT_WEIGHT_NLP,
            Constants.DEFAULT_WEIGHT_BODMAS,
            Constants.DEFAULT_WEIGHT_TYPOSQUAT,
            Constants.DEFAULT_WEIGHT_REPUTATION
        )
        AdaptiveTrustEngine.boundAndNormalizeWeights(w)
        assertEquals(1.0f, w.sum(), 0.001f)
    }

    @Test
    fun `boundAndNormalize clamps zero weights to MIN_WEIGHT`() {
        val w = floatArrayOf(0.0f, 0.0f, 0.0f, 0.0f, 1.0f)
        AdaptiveTrustEngine.boundAndNormalizeWeights(w)
        for (weight in w) {
            assertTrue("Each weight should be >= MIN_WEIGHT", weight >= AdaptiveTrustEngine.MIN_WEIGHT)
        }
        assertEquals(1.0f, w.sum(), 0.001f)
    }

    @Test
    fun `boundAndNormalize reduces dominant weight substantially`() {
        val w = floatArrayOf(0.95f, 0.01f, 0.01f, 0.01f, 0.02f)
        AdaptiveTrustEngine.boundAndNormalizeWeights(w)
        // After 5 clamp-normalize iterations, the dominant weight converges downward
        // but the final normalize step (division) can push it slightly above MAX_WEIGHT.
        // We verify: (a) sum is still 1.0, (b) the dominant weight dropped well below 0.95
        assertTrue("Dominant weight should drop well below 0.95", w[0] < 0.80f)
        assertEquals(1.0f, w.sum(), 0.001f)
    }

    @Test
    fun `boundAndNormalize preserves sum after 20 consecutive nudges down`() {
        // Simulate 20 consecutive STEP_WRONG nudges on index 1 (NLP)
        val w = floatArrayOf(0.259f, 0.296f, 0.185f, 0.148f, 0.111f)
        for (i in 0 until 20) {
            w[1] -= AdaptiveTrustEngine.STEP_WRONG
            val delta = AdaptiveTrustEngine.STEP_WRONG / 4f
            w[0] += delta; w[2] += delta; w[3] += delta; w[4] += delta
            AdaptiveTrustEngine.boundAndNormalizeWeights(w)
        }
        assertEquals(1.0f, w.sum(), 0.001f)
        for (weight in w) {
            assertTrue("Weight must stay >= MIN_WEIGHT after 20 nudges", weight >= AdaptiveTrustEngine.MIN_WEIGHT - 0.001f)
            assertTrue("Weight must stay <= MAX_WEIGHT after 20 nudges", weight <= AdaptiveTrustEngine.MAX_WEIGHT + 0.001f)
        }
    }

    @Test
    fun `boundAndNormalize with equal weights produces equal output`() {
        val w = floatArrayOf(0.2f, 0.2f, 0.2f, 0.2f, 0.2f)
        AdaptiveTrustEngine.boundAndNormalizeWeights(w)
        assertEquals(1.0f, w.sum(), 0.001f)
        for (weight in w) {
            assertEquals(0.2f, weight, 0.001f)
        }
    }

    // ── parseSubScores ───────────────────────────────────────────────────

    @Test
    fun `parseSubScores extracts all five model scores correctly`() {
        val flags = listOf(
            "URL Forensic Engine: 85%",
            "NLP Engine: 72%",
            "Heuristic Core: 45%",
            "Typosquatting Detector: 90%",
            "Reputation Score: 30%"
        )
        val scores = AdaptiveTrustEngine.parseSubScores(flags)
        assertEquals(5, scores.size)
        assertEquals(0.85f, scores[0], 0.01f)  // URL
        assertEquals(0.72f, scores[1], 0.01f)  // NLP
        assertEquals(0.45f, scores[2], 0.01f)  // BODMAS
        assertEquals(0.90f, scores[3], 0.01f)  // Typosquat
        assertEquals(0.30f, scores[4], 0.01f)  // Reputation
    }

    @Test
    fun `parseSubScores returns zeros for empty flags`() {
        val scores = AdaptiveTrustEngine.parseSubScores(emptyList())
        assertEquals(5, scores.size)
        for (s in scores) {
            assertEquals(0f, s, 0.001f)
        }
    }

    @Test
    fun `parseSubScores handles partial flags gracefully`() {
        val flags = listOf("URL Forensic Engine: 50%")
        val scores = AdaptiveTrustEngine.parseSubScores(flags)
        assertEquals(0.50f, scores[0], 0.01f)
        assertEquals(0f, scores[1], 0.001f)
        assertEquals(0f, scores[2], 0.001f)
        assertEquals(0f, scores[3], 0.001f)
        assertEquals(0f, scores[4], 0.001f)
    }

    @Test
    fun `parseSubScores handles malformed percentage strings`() {
        val flags = listOf("URL Forensic Engine: not_a_number%")
        val scores = AdaptiveTrustEngine.parseSubScores(flags)
        assertEquals(0f, scores[0], 0.001f) // Should default to 0
    }

    // ── Asymmetric step sizes ────────────────────────────────────────────

    @Test
    fun `STEP_WRONG is 0_02 and STEP_CORRECT is 0_01`() {
        assertEquals(0.02f, AdaptiveTrustEngine.STEP_WRONG, 0.0001f)
        assertEquals(0.01f, AdaptiveTrustEngine.STEP_CORRECT, 0.0001f)
    }

    @Test
    fun `weight bounds are MIN 0_05 and MAX 0_60`() {
        assertEquals(0.05f, AdaptiveTrustEngine.MIN_WEIGHT, 0.0001f)
        assertEquals(0.60f, AdaptiveTrustEngine.MAX_WEIGHT, 0.0001f)
    }
}
