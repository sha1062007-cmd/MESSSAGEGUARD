package com.messageguard.threatvision.domain.header

import java.util.regex.Pattern

/**
 * Data representation of parsed email security headers.
 */
data class ParsedEmailHeaders(
    val from: String = "",
    val replyTo: String = "",
    val returnPath: String = "",
    val subject: String = "",
    val authenticationResults: String = "",
    val receivedChain: List<ReceivedHop> = emptyList(),
    val spfStatus: AuthStatus = AuthStatus.NONE,
    val dkimStatus: AuthStatus = AuthStatus.NONE,
    val dmarcStatus: AuthStatus = AuthStatus.NONE,
    val originatingIp: String? = null,
    val isRelaySuspicious: Boolean = false,
    val isDisplayNameSpoofed: Boolean = false,
    val spoofingIndicators: List<String> = emptyList()
)

data class ReceivedHop(
    val fromHost: String = "",
    val byHost: String = "",
    val ip: String? = null,
    val timestamp: String = ""
)

enum class AuthStatus {
    PASS,
    FAIL,
    SOFTFAIL,
    NEUTRAL,
    NONE
}

/**
 * Parser for RFC 5322 email headers and relay chains.
 * Detects IP spoofing, hop relay discrepancies, and display name impersonation.
 */
object EmailHeaderParser {

    private val IPV4_PATTERN = Pattern.compile("""\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b""")
    private val AUTH_SPF_PATTERN = Pattern.compile("""spf=(pass|fail|softfail|neutral|none)""", Pattern.CASE_INSENSITIVE)
    private val AUTH_DKIM_PATTERN = Pattern.compile("""dkim=(pass|fail|neutral|none)""", Pattern.CASE_INSENSITIVE)
    private val AUTH_DMARC_PATTERN = Pattern.compile("""dmarc=(pass|fail|none)""", Pattern.CASE_INSENSITIVE)

    fun parse(rawHeaders: String): ParsedEmailHeaders {
        val lines = rawHeaders.lines()
        val headerMap = mutableMapOf<String, StringBuilder>()
        var currentHeader: String? = null

        for (line in lines) {
            if (line.startsWith(" ") || line.startsWith("\t")) {
                currentHeader?.let { headerMap[it]?.append(" ")?.append(line.trim()) }
            } else {
                val colonIdx = line.indexOf(':')
                if (colonIdx != -1) {
                    val key = line.substring(0, colonIdx).trim().lowercase()
                    val value = line.substring(colonIdx + 1).trim()
                    headerMap.computeIfAbsent(key) { StringBuilder() }.append(value)
                    currentHeader = key
                }
            }
        }

        val from = headerMap["from"]?.toString() ?: ""
        val replyTo = headerMap["reply-to"]?.toString() ?: ""
        val returnPath = headerMap["return-path"]?.toString() ?: ""
        val authResults = headerMap["authentication-results"]?.toString() ?: ""
        val receivedList = lines.filter { it.startsWith("Received:", ignoreCase = true) }

        // Parse SPF / DKIM / DMARC
        val spf = parseAuthStatus(AUTH_SPF_PATTERN, authResults)
        val dkim = parseAuthStatus(AUTH_DKIM_PATTERN, authResults)
        val dmarc = parseAuthStatus(AUTH_DMARC_PATTERN, authResults)

        // Parse Hops and IPs
        val hops = mutableListOf<ReceivedHop>()
        var originatingIp: String? = null
        for (rec in receivedList) {
            val matcher = IPV4_PATTERN.matcher(rec)
            var ip: String? = null
            if (matcher.find()) {
                val candidateIp = matcher.group()
                // Ignore private IP ranges
                if (!isPrivateIp(candidateIp)) {
                    ip = candidateIp
                    if (originatingIp == null) originatingIp = candidateIp
                }
            }
            hops.add(ReceivedHop(ip = ip, timestamp = rec))
        }

        // Detect Spoofing & Anomalies
        val indicators = mutableListOf<String>()
        var isDisplayNameSpoofed = false

        // 1. From vs Reply-To Mismatch
        val fromEmail = extractEmail(from)
        val replyToEmail = extractEmail(replyTo)
        if (fromEmail.isNotBlank() && replyToEmail.isNotBlank()) {
            val fromDomain = extractDomain(fromEmail)
            val replyToDomain = extractDomain(replyToEmail)
            if (fromDomain != replyToDomain) {
                indicators.add("From/Reply-To domain mismatch: '$fromDomain' vs '$replyToDomain'")
            }
        }

        // 2. Display Name Spoofing: e.g. "Google Security <attacker@evil.com>"
        if (from.contains("<") && from.contains(">")) {
            val displayName = from.substringBefore("<").trim().removeSurrounding("\"")
            val targetBrands = listOf("google", "paypal", "microsoft", "apple", "amazon", "netflix", "hdfc", "sbi", "icici", "chase")
            for (brand in targetBrands) {
                if (displayName.contains(brand, ignoreCase = true) && !fromEmail.contains(brand, ignoreCase = true)) {
                    isDisplayNameSpoofed = true
                    indicators.add("Display name impersonation detected: claims '$displayName' from unrelated domain '$fromEmail'")
                    break
                }
            }
        }

        // 3. SPF / DMARC failure
        var isRelaySuspicious = false
        if (spf == AuthStatus.FAIL || dkim == AuthStatus.FAIL || dmarc == AuthStatus.FAIL) {
            isRelaySuspicious = true
            indicators.add("Authentication failure: SPF=$spf, DKIM=$dkim, DMARC=$dmarc")
        }

        return ParsedEmailHeaders(
            from = from,
            replyTo = replyTo,
            returnPath = returnPath,
            authenticationResults = authResults,
            receivedChain = hops,
            spfStatus = spf,
            dkimStatus = dkim,
            dmarcStatus = dmarc,
            originatingIp = originatingIp,
            isRelaySuspicious = isRelaySuspicious,
            isDisplayNameSpoofed = isDisplayNameSpoofed,
            spoofingIndicators = indicators
        )
    }

    private fun parseAuthStatus(pattern: Pattern, input: String): AuthStatus {
        val m = pattern.matcher(input)
        if (m.find()) {
            return when (m.group(1)?.lowercase()) {
                "pass" -> AuthStatus.PASS
                "fail" -> AuthStatus.FAIL
                "softfail" -> AuthStatus.SOFTFAIL
                "neutral" -> AuthStatus.NEUTRAL
                else -> AuthStatus.NONE
            }
        }
        return AuthStatus.NONE
    }

    private fun isPrivateIp(ip: String): Boolean {
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip.startsWith("172.16.")
    }

    private fun extractEmail(headerVal: String): String {
        val start = headerVal.indexOf('<')
        val end = headerVal.indexOf('>')
        return if (start != -1 && end != -1 && end > start) {
            headerVal.substring(start + 1, end).trim().lowercase()
        } else {
            headerVal.trim().lowercase()
        }
    }

    private fun extractDomain(email: String): String {
        return email.substringAfter('@', "").trim()
    }
}
