package com.messageguard

/**
 * Groups textual scam evidence by meaning instead of treating a lone word such as "OTP",
 * "blocked", or "verify" as a threat. A group only contributes once.
 */
object ThreatSignalPolicy {

    enum class Confidence {
        HIGH,
        MEDIUM,
        LOW
    }

    data class TextThreatSignals(
        val hasUrgency: Boolean,
        val hasActionRequest: Boolean,
        val hasCredentialRequest: Boolean,
        val hasMoneyLure: Boolean,
        val hasCallbackScam: Boolean
    ) {
        val count: Int
            get() = listOf(
                hasUrgency,
                hasActionRequest,
                hasCredentialRequest,
                hasMoneyLure,
                hasCallbackScam
            ).count { it }

        val isCorroborated: Boolean
            get() = count >= 2

        val confidence: Confidence
            get() = when {
                count >= 3 -> Confidence.HIGH
                count == 2 -> Confidence.MEDIUM
                else -> Confidence.LOW
            }
    }

    private val urgencyPattern = Regex(
        "\\b(?:urgent(?:ly)?|immediately|without delay|as soon as possible|expire[ds]?|" +
            "suspend(?:ed)?|block(?:ed)?|deactivate(?:d)?)\\b",
        RegexOption.IGNORE_CASE
    )
    // FP-4 FIX: Removed "contact", "visit", "call", "open" — these appear constantly in legitimate
    // messages (e.g. "call 1800-11-2211", "contact our branch", "visit incometax.gov.in").
    // The full 10-word set made the corroboration threshold of 2 too easy to reach with a single
    // additional signal like urgency. Retained words are genuinely directive phishing actions.
    private val actionPattern = Regex(
        "\\b(?:click|tap|verify|update|confirm|dial)\\b",
        RegexOption.IGNORE_CASE
    )
    private val credentialRequestPattern = Regex(
        "\\b(?:share|enter|provide|submit|send|reply(?:\\s+with)?)\\s+" +
            "(?:your\\s+)?(?:otp|one[- ]time password|pin|password|cvv|bank details|card details)\\b",
        RegexOption.IGNORE_CASE
    )
    /**
     * Safety advice patterns that EXCLUDE a message from being flagged as credential request.
     * These are legitimate messages that tell users NOT to share their OTP/PIN.
     */
    private val credentialSafetyAdvicePattern = Regex(
        "\\b(?:do not|don't|never|neverse|should not|shouldn't)\\s+(?:share|enter|provide|submit|send|reply(?:\\s+with)?)\\s+" +
            "(?:your\\s+)?(?:otp|one[- ]time password|pin|password|cvv|bank details|card details)\\b",
        RegexOption.IGNORE_CASE
    )

    /**
     * Additional safety patterns: messages that are clearly informational, not phishing.
     * These patterns indicate the message is providing information or asking the user
     * to protect themselves, not requesting credentials.
     */
    private val informationalPatterns = Regex(
        "\\b(?:if not initiated by you|call \\d+|visit (?:our |the )?(?:branch|office|website)|" +
            "for (?:help|assistance|support) (?:call|visit|contact)|" +
            "do not share (?:this|your) (?:otp|code|pin|password)|" +
            "valid for \\d+ (?:minutes?|mins?)|expires? (?:in|on|at))\\b",
        RegexOption.IGNORE_CASE
    )
    private val moneyLurePattern = Regex(
        "\\b(?:you(?:'|’)ve won|you have won|claim (?:your )?(?:prize|reward)|lottery|cash reward|" +
            "instant refund|cashback)\\b",
        RegexOption.IGNORE_CASE
    )
    private val callbackScamPattern = Regex(
        "\\b(?:call\\s+(?:immediately|urgently|now)|dial\\s+\\+?\\d{10,12}|" +
            "contact\\s+(?:support|helpdesk|executive)\\s+(?:at|on)\\s+\\+?\\d+)\\b",
        RegexOption.IGNORE_CASE
    )

    fun analyze(text: String): TextThreatSignals {
        val hasCredentialRequest = credentialRequestPattern.containsMatchIn(text) &&
            !credentialSafetyAdvicePattern.containsMatchIn(text) &&
            !informationalPatterns.containsMatchIn(text)

        return TextThreatSignals(
            hasUrgency = urgencyPattern.containsMatchIn(text),
            hasActionRequest = actionPattern.containsMatchIn(text),
            hasCredentialRequest = hasCredentialRequest,
            hasMoneyLure = moneyLurePattern.containsMatchIn(text),
            hasCallbackScam = callbackScamPattern.containsMatchIn(text)
        )
    }
}
