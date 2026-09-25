package com.messageguard

import java.util.Locale

/**
 * Lightweight language routing for message text. Tanglish is deliberately conservative:
 * a single ambiguous Latin word never changes the language or scoring path.
 *
 * Tanglish = Tamil words typed in Latin/Roman script. Extremely common in Indian
 * WhatsApp / SMS — examples: "unga bank account block aagum", "udane verify pannunga",
 * "OTP share pannunga". We detect it by requiring 2+ unambiguous Tanglish tokens or
 * 1 full Tanglish scam phrase.
 */
object MessageLanguageDetector {

    data class TanglishDetection(
        val matchedIndicators: Set<String>
    ) {
        val isDetected: Boolean
            get() = matchedIndicators.size >= MIN_TANGLISH_INDICATORS
    }

    private const val MIN_TANGLISH_INDICATORS = 2

    private val tanglishPhrases = mapOf(
        "unga bank account" to Regex("\\b(?:unga|ungal|thanga)\\s+(?:bank|vangi|angadi)\\s+(?:account|kanakku|nambar)\\b"),
        "block aagum" to Regex("\\b(?:block|blocked|suspend|tada)\\s+(?:aagum|aahum|aaguthu|aagumaa?)\\b"),
        "verify pannunga" to Regex("\\b(?:verify|saripaaru|seripaaru|parthukonga|check)\\s+(?:pannunga|pannungalkal|seiyungal|seiyungal)\\b"),
        "otp anuppunga" to Regex("\\b(?:otp|pin|password|cvv)\\s+(?:anuppunga|anupunga|send|share\\s+pannunga|tharunga)\\b"),
        "pin anuppunga" to Regex("\\bpin\\s+(?:anuppunga|share\\s+pannunga|tharunga)\\b"),
        "link click pannunga" to Regex("\\b(?:link|url|page|site)\\s+(?:a|ah)?\\s*click\\s+(?:pannunga|seiyungal)\\b"),
        "udane/seekiram action" to Regex("\\b(?:udane|seekiram|ippo|inniki|idha??)\\b.\\S+\\s+(?:pannunga|anuppunga|tharunga|click)"),
        "kanakku/account urimai" to Regex("\\b(?:kanakku|account)\\s+(?:urimai|thagudhi|details|sithi|status)"),
        "panam money request" to Regex("\\b(?:panam|kaasu|kasu|money|rkkam)\\s+(?:tharu|tharu|kudu|kodukka|pay)")
    )

    /* Tamil words written in Latin letters. Avoid short ambiguous words such as
       "na" or "va" or "da" — they create false matches in ordinary English/SMS.
       All entries are ≥5 letters or strongly disambiguated by a typical scam context. */
    private val tanglishWords = setOf(
        "vangi", "kanakku", "panam", "kaasu", "kasu", "udane", "seekiram",
        "pannunga", "anuppunga", "anupunga", "saripaarunga", "seripaarunga",
        "moodidum", "mudakkam", "aagum", "aahum", "aaguthu", "tharunga",
        "kodukka", "koduththu", "ungalukku", "ungaludan", "nienga", "neenga",
        "thirumbi", "thiruthu", "thiruppi", "kaakum", "kavalan", "kavalanunga",
        "sariyaana", "sariyana", "sariyillama", "seriyaa", "thappaa",
        "urimai", "thagudhi", "bankthoguthi", "thoguthi", "nambikai",
        "amaidhiyaa", "amaidhiyaga", "miga", "mihavilai", "parisu",
        "paruthiveeran", "latcham", "laksham", "roobai", "aayiram"
    )

    private val hinglishPhrases = mapOf(
        "aapka bank account" to Regex("\\b(?:aapka|apka|tumhara)\\s+(?:bank|khata|account)\\b"),
        "block ho jayega" to Regex("\\b(?:block|band|suspend)\\s+(?:ho\\s+jayega|hoga|kar\\s+diya)\\b"),
        "turant verify karein" to Regex("\\b(?:turant|jaldi|abhi)\\s+(?:verify|update|karein|karo)\\b"),
        "otp share mat karein" to Regex("\\b(?:otp|pin|password)\\s+(?:bhejo|share\\s+karein|batao)\\b"),
        "paisa jeeta hai" to Regex("\\b(?:paisa|inaam|lottery|rupaye)\\s+(?:jeeta|mila|khatam)\\b")
    )

    private val hinglishWords = setOf(
        "khata", "paisa", "rupaye", "turant", "jaldi", "karein", "bhejo",
        "inaam", "shulk", "aadhaar"
    )

    /**
     * Minimum Viable Stopgap:
     * 1. Normalizes input by collapsing repeated characters ("paannungaaa" -> "pannunga"),
     *    removing adversarial intra-word spacing ("o t p" -> "otp", "v a n g i" -> "vangi"),
     *    and mapping common leetspeak substitutions (0->o, 1->i, @->a, 5->s, 3->e).
     * 2. Uses Levenshtein distance (edit distance <= 1 for short, <= 2 for long tokens)
     *    to match romanized scam indicators against variations.
     *
     * NOTE: This is a heuristic stopgap. Full semantic generalization requires an on-device
     * multilingual transformer / LSTM model trained on romanized Indic scam corpora.
     */
    fun normalizeAdversarialText(input: String): String {
        var text = input.lowercase(Locale.ROOT)
        // 1. Leetspeak mapping
        text = text.replace('0', 'o')
            .replace('1', 'i')
            .replace('!', 'i')
            .replace('@', 'a')
            .replace('3', 'e')
            .replace('5', 's')
            .replace('$', 's')
            .replace('7', 't')

        // 2. Collapse single character spacing ("o t p" -> "otp", "b a n k" -> "bank")
        val deSpaced = text.replace(Regex("""\b([a-z])\s+([a-z])\s+([a-z])\s+([a-z])\b"""), "$1$2$3$4")
            .replace(Regex("""\b([a-z])\s+([a-z])\s+([a-z])\b"""), "$1$2$3")
            .replace(Regex("""\b([a-z])\s+([a-z])\b"""), "$1$2")

        // 3. Collapse 3+ character repetitions ("paaannungaaa" -> "paannungaa")
        return deSpaced.replace(Regex("""([a-z])\1{2,}"""), "$1$1")
    }

    private fun fuzzyMatch(token: String, target: String): Boolean {
        if (token == target) return true
        val maxDist = if (target.length <= 4) 1 else 2
        if (Math.abs(token.length - target.length) > maxDist) return false
        return SpamAnalyzer.levenshteinDistance(token, target) <= maxDist
    }

    fun containsTamilScript(text: String): Boolean =
        text.any { it.code in 0x0B80..0x0BFF }

    fun containsDevanagariScript(text: String): Boolean =
        text.any { it.code in 0x0900..0x097F }

    fun containsTeluguScript(text: String): Boolean =
        text.any { it.code in 0x0C00..0x0C7F }

    fun detectTanglish(text: String): TanglishDetection {
        val normalized = normalizeAdversarialText(text)
        val matches = linkedSetOf<String>()

        tanglishPhrases.forEach { (name, pattern) ->
            if (pattern.containsMatchIn(normalized)) matches += name
        }

        val tokens = Regex("[a-z]+")
            .findAll(normalized)
            .map { it.value }
            .toSet()

        for (token in tokens) {
            for (target in tanglishWords) {
                if (fuzzyMatch(token, target)) {
                    matches.add(target)
                    break
                }
            }
        }

        return TanglishDetection(matches)
    }

    fun detectHinglish(text: String): Boolean {
        val normalized = normalizeAdversarialText(text)
        var count = 0
        hinglishPhrases.forEach { (_, pattern) ->
            if (pattern.containsMatchIn(normalized)) count++
        }
        val tokens = Regex("[a-z]+").findAll(normalized).map { it.value }.toSet()
        var wordMatches = 0
        for (token in tokens) {
            for (target in hinglishWords) {
                if (fuzzyMatch(token, target)) {
                    wordMatches++
                    break
                }
            }
        }
        return count >= 1 || wordMatches >= 2
    }

    fun isRegionalLanguage(text: String): Boolean =
        containsTamilScript(text) || containsDevanagariScript(text) || containsTeluguScript(text) ||
        detectTanglish(text).isDetected || detectHinglish(text)

    fun shouldUseTamil(text: String): Boolean =
        containsTamilScript(text) || detectTanglish(text).isDetected
}
