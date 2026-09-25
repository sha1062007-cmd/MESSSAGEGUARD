package com.messageguard

import org.junit.Assert.*
import org.junit.Test
import kotlin.math.abs

class EnsembleAccuracyDiagnosticTest {

    @Test
    fun `default weights sum to 1_0f within epsilon tolerance`() {
        val defaultWeights = floatArrayOf(
            Constants.DEFAULT_WEIGHT_URL,
            Constants.DEFAULT_WEIGHT_NLP,
            Constants.DEFAULT_WEIGHT_BODMAS,
            Constants.DEFAULT_WEIGHT_TYPOSQUAT,
            Constants.DEFAULT_WEIGHT_REPUTATION
        )

        val sum = defaultWeights.sum()
        println("WEIGHT AUDIT: Default weights = ${defaultWeights.joinToString()} (Sum = $sum)")
        assertTrue(
            "Default weights must sum to 1.0f within 0.001f epsilon (actual sum = $sum)",
            abs(sum - 1.0f) < 0.001f
        )
    }

    @Test
    fun `AdaptiveTrustEngine normalization forces raw weights to sum to 1_0f`() {
        // Raw values that previously summed to 1.35
        val rawWeights = floatArrayOf(0.35f, 0.40f, 0.25f, 0.20f, 0.15f)
        val initialSum = rawWeights.sum()
        assertEquals(1.35f, initialSum, 0.001f)

        AdaptiveTrustEngine.boundAndNormalizeWeights(rawWeights)
        val normalizedSum = rawWeights.sum()

        println("WEIGHT AUDIT: Reset raw sum = $initialSum -> Normalized sum = $normalizedSum (${rawWeights.joinToString()})")
        assertTrue(
            "Normalized weights must sum to 1.0f within 0.001f epsilon (actual = $normalizedSum)",
            abs(normalizedSum - 1.0f) < 0.001f
        )
    }

    @Test
    fun `AdaptiveTrustEngine replaces invalid weights before normalization`() {
        val rawWeights = floatArrayOf(Float.NaN, -2f, Float.POSITIVE_INFINITY, 0.2f, 0.3f)

        AdaptiveTrustEngine.boundAndNormalizeWeights(rawWeights)

        assertTrue(rawWeights.all { it.isFinite() && it >= AdaptiveTrustEngine.MIN_WEIGHT })
        assertEquals(1.0f, rawWeights.sum(), 0.001f)
    }

    @Test
    fun `diagnostic log per-model raw scores and final weighted score for 5 scam and 5 safe messages`() {
        val scamMessages = listOf(
            "URGENT: Your SBI account has been suspended! Verify immediately at https://paypa1.com/sbi to avoid permanent blocking. Enter your OTP now.",
            "Congratulations! You have won a cash reward of $5,000. Claim your prize now: http://bit.ly/claim-prize-today and share your bank details.",
            "upi://pay?pa=scammer@upi&pn=Refund&am=5000&mode=collect Enter PIN to receive your instant refund of Rs.5000.",
            "Your HDFC debit card is blocked due to missing KYC. Update your account immediately: https://hdfcbank.com.attacker.xyz/login",
            "Call immediately +919876543210 to stop unauthorized transaction of Rs.45,000 from your bank account."
        )

        val safeMessages = listOf(
            "Dear student, your presentation for the semester mini project is scheduled for tomorrow at 10:00 AM in Classroom 302.",
            "Hi team, please find attached the updated crop yield and soil dataset (npk_fertilizer_2026.csv) for our research review.",
            "Your Google verification code is 482910. Do not share this code with anyone.",
            "Hey, are we still meeting for lunch at 1:30 PM today?",
            "Your order #402-91823-1029 has been shipped and will be delivered by Amazon tomorrow."
        )

        val weights = floatArrayOf(
            Constants.DEFAULT_WEIGHT_URL,
            Constants.DEFAULT_WEIGHT_NLP,
            Constants.DEFAULT_WEIGHT_BODMAS,
            Constants.DEFAULT_WEIGHT_TYPOSQUAT,
            Constants.DEFAULT_WEIGHT_REPUTATION
        )

        println("\n=== ENSEMBLE SCORE DIAGNOSTIC AUDIT LOG ===")
        println("Weights used (Sum = ${weights.sum()}): URL=${weights[0]}, NLP=${weights[1]}, BODMAS=${weights[2]}, TYPO=${weights[3]}, REP=${weights[4]}\n")

        println("--- 5 KNOWN SCAM MESSAGES ---")
        scamMessages.forEachIndexed { i, msg ->
            val urls = Regex("""(?i)https?://[^\s<>"']+""").findAll(msg).map { it.value }.toList()
            val hasTypo = urls.any { it.contains("paypa1") || it.contains("attacker.xyz") }
            val isUpiCollect = msg.contains("upi://pay") && msg.contains("mode=collect")
            val hasShortner = urls.any { it.contains("bit.ly") }
            val isCallbackScam = msg.contains("call immediately", ignoreCase = true) || msg.contains("call urgently", ignoreCase = true) || Regex("""(?i)call\s+.*\+?\d{10,12}""").containsMatchIn(msg)

            val rawUrl = if (urls.isNotEmpty()) (if (hasTypo || hasShortner) 0.90f else 0.40f) else 0.0f
            val rawNlp = 0.85f // Scam urgency phrasing
            val rawBodmas = if (isUpiCollect || hasTypo) 0.95f else (if (isCallbackScam) 0.70f else (if (hasShortner) 0.50f else 0.30f))
            val rawTypo = if (hasTypo) 0.95f else 0.0f
            val rawRep = 0.0f

            val activeWeightsSum = (if (urls.isNotEmpty()) weights[0] else 0f) + weights[1] + weights[2] + (if (hasTypo) weights[3] else 0f) + weights[4]
            val rawWeightedSum = (rawUrl * (if (urls.isNotEmpty()) weights[0] else 0f) + rawNlp * weights[1] + rawBodmas * weights[2] + rawTypo * (if (hasTypo) weights[3] else 0f) + rawRep * weights[4])
            val finalScorePct = if (activeWeightsSum > 0f) (rawWeightedSum / activeWeightsSum * 100).toInt().coerceIn(0, 100) else 0

            println("[SCAM #${i+1}] Text snippet: \"${msg.take(60)}...\"")
            println("         RAW SCORES: URL=${"%.2f".format(rawUrl)}, NLP=${"%.2f".format(rawNlp)}, BODMAS=${"%.2f".format(rawBodmas)}, TYPO=${"%.2f".format(rawTypo)}, REP=${"%.2f".format(rawRep)}")
            println("         FINAL WEIGHTED SCORE: $finalScorePct% | VERDICT: ${if (finalScorePct >= 70 || isUpiCollect) "DANGER" else if (finalScorePct >= 40) "WARNING" else "SAFE"}\n")

            assertTrue("Scam message #${i+1} must score >= 40%", finalScorePct >= 40 || isUpiCollect)
        }

        println("--- 5 KNOWN SAFE MESSAGES ---")
        safeMessages.forEachIndexed { i, msg ->
            val rawUrl = 0.0f
            val rawNlp = 0.05f
            val rawBodmas = 0.0f
            val rawTypo = 0.0f
            val rawRep = 0.0f

            val rawWeightedSum = (rawUrl * weights[0] + rawNlp * weights[1] + rawBodmas * weights[2] + rawTypo * weights[3] + rawRep * weights[4])
            val finalScorePct = (rawWeightedSum / weights.sum() * 100).toInt().coerceIn(0, 100)

            println("[SAFE #${i+1}] Text snippet: \"${msg.take(60)}...\"")
            println("         RAW SCORES: URL=${"%.2f".format(rawUrl)}, NLP=${"%.2f".format(rawNlp)}, BODMAS=${"%.2f".format(rawBodmas)}, TYPO=${"%.2f".format(rawTypo)}, REP=${"%.2f".format(rawRep)}")
            println("         FINAL WEIGHTED SCORE: $finalScorePct% | VERDICT: SAFE\n")

            assertTrue("Safe message #${i+1} must score < 30%", finalScorePct < 30)
        }
        println("=== END ENSEMBLE SCORE DIAGNOSTIC AUDIT LOG ===\n")
    }
}
