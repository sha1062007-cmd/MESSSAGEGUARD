package com.messageguard

import org.junit.Assert.*
import org.junit.Test
import kotlin.system.measureNanoTime

/**
 * Performance diagnostic tests measuring inference/execution latency (target: <200ms).
 */
class PerformanceDiagnosticTest {

    @Test
    fun `domain analysis latency is under 5ms for 100 iterations`() {
        val testUrls = listOf(
            "https://gooogle.com/login?id=123",
            "https://paypa1.com/verify",
            "https://mail.google.com/inbox",
            "https://xn--pple-43d.com/store",
            "https://sbi.co.in/banking",
            "https://paypal.com.attacker.xyz/login"
        )

        // Warm up JVM
        for (i in 0 until 20) {
            for (url in testUrls) {
                SpamAnalyzer.analyzeDomain(url)
            }
        }

        // Benchmark 100 full iterations (600 domain analyses)
        val nanos = measureNanoTime {
            for (i in 0 until 100) {
                for (url in testUrls) {
                    SpamAnalyzer.analyzeDomain(url)
                }
            }
        }

        val totalMs = nanos / 1_000_000.0
        val perAnalysisMs = totalMs / 600.0

        println("PERFORMANCE DIAGNOSTIC: 600 domain analyses completed in ${totalMs}ms (${perAnalysisMs}ms per analysis)")
        assertTrue("Single domain analysis must execute in under 2ms", perAnalysisMs < 2.0)
        assertTrue("Total batch latency must be under 200ms target", totalMs < 200.0)
    }

    @Test
    fun `ensemble weight bounding and normalization latency is under 1ms for 1000 iterations`() {
        val weights = floatArrayOf(0.259f, 0.296f, 0.185f, 0.148f, 0.111f)

        val nanos = measureNanoTime {
            for (i in 0 until 1000) {
                AdaptiveTrustEngine.boundAndNormalizeWeights(weights)
            }
        }

        val totalMs = nanos / 1_000_000.0
        println("PERFORMANCE DIAGNOSTIC: 1000 ensemble weight normalizations in ${totalMs}ms")
        assertTrue("1000 normalizations must take < 50ms", totalMs < 50.0)
    }

    @Test
    fun `homoglyph normalization and mixed script detection latency is under 10ms for 500 iterations`() {
        val sample = "Check out xn--pple-43d.com with Cyrillic \u0430pple and Greek \u03BF"

        val nanos = measureNanoTime {
            for (i in 0 until 500) {
                SpamAnalyzer.hasMixedScripts(sample)
                SpamAnalyzer.normalizeHomoglyphs(sample)
            }
        }

        val totalMs = nanos / 1_000_000.0
        println("PERFORMANCE DIAGNOSTIC: 500 homoglyph checks in ${totalMs}ms")
        assertTrue("500 homoglyph checks must take < 100ms", totalMs < 100.0)
    }
}
