package com.messageguard

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for the homograph/typosquat detection logic in SpamAnalyzer.
 * Tests analyzeDomain(), hasMixedScripts(), normalizeHomoglyphs() — all companion object functions.
 */
class HomographDetectionTest {

    // ── analyzeDomain: legitimate domains ────────────────────────────────

    @Test
    fun `official domain google_com is not flagged`() {
        val result = SpamAnalyzer.analyzeDomain("google.com")
        assertFalse(result.isTyposquat)
        assertFalse(result.isHomograph)
    }

    @Test
    fun `subdomain of official domain mail_google_com is not flagged`() {
        val result = SpamAnalyzer.analyzeDomain("mail.google.com")
        assertFalse(result.isTyposquat)
        assertFalse(result.isHomograph)
    }

    @Test
    fun `official multi-level TLD sbi_co_in is not flagged`() {
        val result = SpamAnalyzer.analyzeDomain("sbi.co.in")
        assertFalse(result.isTyposquat)
        assertFalse(result.isHomograph)
    }

    // ── analyzeDomain: typosquat domains ─────────────────────────────────

    @Test
    fun `gooogle_com is detected as typosquat of google`() {
        val result = SpamAnalyzer.analyzeDomain("gooogle.com")
        assertTrue("gooogle.com should be flagged as typosquat", result.isTyposquat)
    }

    @Test
    fun `paypa1_com is detected as typosquat of paypal`() {
        val result = SpamAnalyzer.analyzeDomain("paypa1.com")
        assertTrue("paypa1.com should be flagged as typosquat", result.isTyposquat)
    }

    @Test
    fun `brand in subdomain paypal_com_attacker_xyz is detected`() {
        val result = SpamAnalyzer.analyzeDomain("paypal.com.attacker.xyz")
        assertTrue("paypal.com.attacker.xyz should be flagged as typosquat", result.isTyposquat)
    }

    // ── analyzeDomain: IDN homograph domains ─────────────────────────────

    @Test
    fun `punycode apple homograph xn--pple-43d_com is detected`() {
        // xn--pple-43d.com decodes to аpple.com (Cyrillic а + Latin pple)
        val result = SpamAnalyzer.analyzeDomain("xn--pple-43d.com")
        assertTrue("Punycode homograph of apple.com should be flagged", result.isHomograph)
    }

    // ── analyzeDomain: unrelated domains ─────────────────────────────────

    @Test
    fun `completely unrelated domain randomsite_org is not flagged`() {
        val result = SpamAnalyzer.analyzeDomain("randomsite.org")
        assertFalse(result.isTyposquat)
        assertFalse(result.isHomograph)
    }

    @Test
    fun `empty string returns safe result`() {
        val result = SpamAnalyzer.analyzeDomain("")
        assertFalse(result.isTyposquat)
        assertFalse(result.isHomograph)
    }

    @Test
    fun `full URL with protocol is parsed correctly`() {
        val result = SpamAnalyzer.analyzeDomain("https://gooogle.com/login")
        assertTrue("gooogle.com from full URL should be flagged as typosquat", result.isTyposquat)
    }

    // ── hasMixedScripts direct tests ─────────────────────────────────────

    @Test
    fun `pure latin label is not mixed script`() {
        assertFalse(SpamAnalyzer.hasMixedScripts("google"))
    }

    @Test
    fun `mixed cyrillic and latin is detected`() {
        // "аpple" = Cyrillic а + Latin pple
        assertTrue(SpamAnalyzer.hasMixedScripts("\u0430pple"))
    }

    // ── normalizeHomoglyphs direct tests ─────────────────────────────────

    @Test
    fun `cyrillic a normalizes to latin a`() {
        assertEquals("a", SpamAnalyzer.normalizeHomoglyphs("\u0430"))
    }

    @Test
    fun `pure latin string is unchanged`() {
        assertEquals("hello", SpamAnalyzer.normalizeHomoglyphs("hello"))
    }

    // ── levenshteinDistance direct tests ──────────────────────────────────

    @Test
    fun `identical strings have distance 0`() {
        assertEquals(0, SpamAnalyzer.levenshteinDistance("paypal", "paypal"))
    }

    @Test
    fun `single substitution has distance 1`() {
        assertEquals(1, SpamAnalyzer.levenshteinDistance("paypal", "paypa1"))
    }

    @Test
    fun `single insertion has distance 1`() {
        assertEquals(1, SpamAnalyzer.levenshteinDistance("google", "gooogle"))
    }
}
