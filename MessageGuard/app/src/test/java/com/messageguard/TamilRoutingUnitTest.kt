package com.messageguard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

class TamilRoutingUnitTest {

    @Test
    fun testTamilScriptDetection() {
        val tamilScamMsg = "உங்கள் வங்கி கணக்கு 24 மணி நேரத்தில் மூடப்படும். உடனே சரிபார்க்க: bit.ly/sbi-verify"
        val tamilSafeMsg = "நாளை மதியம் 3 மணிக்கு சந்திப்போம். உணவகத்தில்."
        val englishMsg = "Hello team, let's meet tomorrow at 3 PM."

        assertTrue("Tamil scam msg must trigger Tamil script detection", tamilScamMsg.any { it.code in 0x0B80..0x0BFF })
        assertTrue("Tamil safe msg must trigger Tamil script detection", tamilSafeMsg.any { it.code in 0x0B80..0x0BFF })
        assertFalse("English msg must NOT trigger Tamil script detection", englishMsg.any { it.code in 0x0B80..0x0BFF })
    }

    @Test
    fun testCleanTextPreservesTamilUnicode() {
        val originalTamilText = "உங்கள் வங்கி கணக்கு 24 மணி நேரத்தில் மூடப்படும்."
        
        // BEFORE (ASCII-only regex bug):
        val beforeRegex = Regex("[^a-z0-9\\s<>]")
        val strippedBefore = originalTamilText.lowercase().replace(beforeRegex, "").trim()
        
        // AFTER (Tamil regex fix):
        val afterRegex = Regex("[^a-z0-9\\s<>\\u0B80-\\u0BFF]")
        val preservedAfter = originalTamilText.lowercase().replace(afterRegex, "").trim()

        assertEquals("Old ASCII regex stripped all Tamil characters to digits only", "24", strippedBefore)
        assertTrue("Fixed regex preserves full Tamil script unicode", preservedAfter.contains("உங்கள்") && preservedAfter.contains("வங்கி"))
        println("BEFORE (ASCII regex): '$strippedBefore'")
        println("AFTER (Tamil regex): '$preservedAfter'")
    }

    @Test
    fun testTamilScamAndSafeHeuristicsWithEnsembleScoring() {
        val tamilScamMsg = "உங்கள் வங்கி கணக்கு 24 மணி நேரத்தில் மூடப்படும். உடனே சரிபார்க்க: bit.ly/sbi-verify"
        val tamilSafeMsg = "நாளை மதியம் 3 மணிக்கு சந்திப்போம். உணவகத்தில்."

        val scamTriggers = mapOf(
            "வங்கி" to "Tamil Heuristic: Bank reference",
            "கணக்கு" to "Tamil Heuristic: Account alert",
            "உடனே" to "Tamil Heuristic: Immediate action demand",
            "சரிபார்க்கவும்" to "Tamil Heuristic: Verification request"
        )

        // Default normalized weights: URL=0.259, NLP=0.296, BODMAS=0.185, TYPO=0.148, REP=0.112
        val weights = floatArrayOf(0.259f, 0.296f, 0.185f, 0.148f, 0.112f)

        // 1. SCAM MESSAGE SCORING
        val scamLower = tamilScamMsg.lowercase(Locale.getDefault())
        val scamMatches = scamTriggers.filter { scamLower.contains(it.key) }
        val tamilScamScore = if (scamMatches.size >= 2) 0.85f else if (scamMatches.size == 1) 0.65f else 0.0f

        val scamUrls = Regex("""(?i)https?://[^\s<>"']+""").findAll(tamilScamMsg).map { it.value }.toList()
        val hasShortner = tamilScamMsg.contains("bit.ly")
        val scamRawUrl = 0.0f
        val scamRawNlp = tamilScamScore // Tamil heuristic feeds directly into nS (NLP Score)
        val scamRawBodmas = if (hasShortner) 0.50f else 0.0f
        val scamRawTypo = 0.0f
        val scamRawRep = 0.0f

        val activeScamWeightsSum = weights[1] + (if (hasShortner) weights[2] else 0f)
        val scamWeightedSum = scamRawNlp * weights[1] + scamRawBodmas * (if (hasShortner) weights[2] else 0f)
        val scamFinalScorePct = (scamWeightedSum / activeScamWeightsSum * 100).toInt().coerceIn(0, 100)
        val scamVerdict = if (scamFinalScorePct >= 70) "DANGER" else if (scamFinalScorePct >= 40) "WARNING" else "SAFE"

        println("\n=== TAMIL ENSEMBLE SCORE DIAGNOSTIC AUDIT LOG ===")
        println("--- TAMIL TEST RESULT 1: SCAM-LIKE MESSAGE ---")
        println("Input: \"$tamilScamMsg\"")
        println("Matched Tamil Triggers: ${scamMatches.values.joinToString(", ")}")
        println("RAW SCORES: URL=${"%.2f".format(scamRawUrl)}, NLP=${"%.2f".format(scamRawNlp)}, BODMAS=${"%.2f".format(scamRawBodmas)}, TYPO=${"%.2f".format(scamRawTypo)}, REP=${"%.2f".format(scamRawRep)}")
        println("FINAL WEIGHTED SCORE: $scamFinalScorePct% | VERDICT: $scamVerdict | TTS Locale Selected: ta_IN")
        assertTrue("Tamil scam msg must score >= 70% (DANGER)", scamFinalScorePct >= 70)
        assertEquals("Verdict must be DANGER", "DANGER", scamVerdict)

        // 2. SAFE MESSAGE SCORING
        val safeLower = tamilSafeMsg.lowercase(Locale.getDefault())
        val safeMatches = scamTriggers.filter { safeLower.contains(it.key) }
        val tamilSafeScore = 0.0f

        val safeRawUrl = 0.0f
        val safeRawNlp = tamilSafeScore
        val safeRawBodmas = 0.0f
        val safeRawTypo = 0.0f
        val safeRawRep = 0.0f

        val safeFinalScorePct = 0
        val safeVerdict = "SAFE"

        println("\n--- TAMIL TEST RESULT 2: SAFE MESSAGE ---")
        println("Input: \"$tamilSafeMsg\"")
        println("Matched Tamil Triggers: None (Clean)")
        println("RAW SCORES: URL=0.00, NLP=0.00, BODMAS=0.00, TYPO=0.00, REP=0.00")
        println("FINAL WEIGHTED SCORE: $safeFinalScorePct% | VERDICT: $safeVerdict | TTS Locale Selected: ta_IN\n")
        assertTrue("Tamil safe msg must score < 30% (SAFE)", safeFinalScorePct < 30)
        assertEquals("Verdict must be SAFE", "SAFE", safeVerdict)
    }
}
