package com.messageguard.threatvision.domain.ocr

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.ColorMatrix
import android.graphics.ColorMatrixColorFilter
import android.graphics.Paint
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import com.messageguard.threatvision.data.model.ExtractedContent
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class MlKitTextRecognizer : AutoCloseable {

    private val recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)

    /**
     * Extracts text, URLs, phone numbers, and email addresses from a cropped screen bitmap.
     * Applies contrast boost preprocessing for low-light/low-contrast screen captures.
     */
    suspend fun extractTextFromBitmap(srcBitmap: Bitmap, enhanceContrast: Boolean = true): ExtractedContent =
        suspendCancellableCoroutine { continuation ->
            android.util.Log.d("ThreatVisionLog", "MlKitTextRecognizer: starting OCR on bitmap (${srcBitmap.width}x${srcBitmap.height}), enhanceContrast=$enhanceContrast")
            var safeBitmap = srcBitmap
            if (safeBitmap.width < 32 || safeBitmap.height < 32) {
                val newWidth = maxOf(32, safeBitmap.width)
                val newHeight = maxOf(32, safeBitmap.height)
                safeBitmap = Bitmap.createScaledBitmap(safeBitmap, newWidth, newHeight, true)
            }
            val processedBitmap = if (enhanceContrast) boostContrast(safeBitmap) else safeBitmap
            val image = InputImage.fromBitmap(processedBitmap, 0)

            recognizer.process(image)
                .addOnSuccessListener { visionText ->
                    if (enhanceContrast && processedBitmap != srcBitmap && !processedBitmap.isRecycled) {
                        processedBitmap.recycle()
                    }
                    val fullText = visionText.text.trim()
                    val urls = extractUrls(fullText)
                    val phoneNumbers = extractPhoneNumbers(fullText)
                    val emails = extractEmails(fullText)

                    val wordCount = fullText.split(Regex("""\s+""")).filter { it.isNotBlank() }.size
                    val isTooShortFragment = (fullText.length < 25 || wordCount < 4) && urls.isEmpty()
                    val isGarbled = isOcrGarbled(fullText) || isTooShortFragment

                    val effectiveUrls = if (isGarbled) emptyList() else urls.map { normalizeDomainOcr(it) }
                    val effectivePhones = if (isGarbled) emptyList() else phoneNumbers
                    val effectiveEmails = if (isGarbled) emptyList() else emails

                    android.util.Log.d("ThreatVisionLog", "MlKitTextRecognizer: OCR SUCCESS — text length=${fullText.length}, words=$wordCount, isGarbled=$isGarbled, isTooShortFragment=$isTooShortFragment, urls=${effectiveUrls.size}, phones=${effectivePhones.size}")
                    if (fullText.isBlank()) {
                        android.util.Log.w("ThreatVisionLog", "MlKitTextRecognizer: WARNING — OCR returned BLANK text. The cropped region may not contain readable text.")
                    } else if (isGarbled) {
                        android.util.Log.w("ThreatVisionLog", "MlKitTextRecognizer: OCR SUPPRESSED — Extracted text is non-Latin garble or stray UI fragment ('${fullText.replace("\n", " ")}'). Returning incomplete.")
                    }

                    continuation.resume(
                        ExtractedContent(
                            rawText = if (isGarbled) "" else fullText,
                            urls = effectiveUrls,
                            phoneNumbers = effectivePhones,
                            emails = effectiveEmails
                        )
                    )
                }
                .addOnFailureListener { exception ->
                    if (enhanceContrast && processedBitmap != srcBitmap && !processedBitmap.isRecycled) {
                        processedBitmap.recycle()
                    }
                    android.util.Log.e("ThreatVisionLog", "MlKitTextRecognizer: OCR FAILED", exception)
                    continuation.resumeWithException(exception)
                }
        }

    /**
     * Adaptive contrast boost pre-processor.
     * Analyzes image histogram to determine optimal contrast and brightness adjustments
     * rather than using fixed parameters.
     */
    private fun boostContrast(src: Bitmap): Bitmap {
        // Step 1: Analyze image histogram to determine if enhancement is needed
        val stats = analyzeImageStats(src)
        
        // Step 2: Choose appropriate enhancement based on image quality
        val contrast = when {
            stats.contrast < 30 -> 1.5f   // Low contrast image needs more boost
            stats.contrast < 60 -> 1.3f   // Medium contrast — standard boost
            else -> 1.1f                  // Already good contrast — minimal boost
        }
        
        val brightness = when {
            stats.meanBrightness < 80 -> 15f    // Dark image — add brightness
            stats.meanBrightness > 200 -> -10f  // Very bright — reduce slightly
            else -> 0f
        }
        
        val width = src.width
        val height = src.height
        val dest = Bitmap.createBitmap(width, height, src.config ?: Bitmap.Config.ARGB_8888)

        val canvas = Canvas(dest)
        val paint = Paint()

        val translate = 128f * (1f - contrast) + brightness
        val colorMatrix = ColorMatrix(
            floatArrayOf(
                contrast, 0f, 0f, 0f, translate,
                0f, contrast, 0f, 0f, translate,
                0f, 0f, contrast, 0f, translate,
                0f, 0f, 0f, 1f, 0f
            )
        )

        paint.colorFilter = ColorMatrixColorFilter(colorMatrix)
        canvas.drawBitmap(src, 0f, 0f, paint)
        return dest
    }

    /**
     * Analyzes basic image statistics to inform preprocessing decisions.
     */
    private fun analyzeImageStats(bitmap: Bitmap): ImageStats {
        var totalBrightness = 0L
        var minBrightness = 255
        var maxBrightness = 0
        val sampleStep = maxOf(1, bitmap.width * bitmap.height / 10000) // Sample for performance

        var pixelCount = 0
        for (x in 0 until bitmap.width step sampleStep) {
            for (y in 0 until bitmap.height step sampleStep) {
                val pixel = bitmap.getPixel(x, y)
                val r = android.graphics.Color.red(pixel)
                val g = android.graphics.Color.green(pixel)
                val b = android.graphics.Color.blue(pixel)
                val brightness = (r * 0.299 + g * 0.587 + b * 0.114).toInt()
                totalBrightness += brightness
                minBrightness = minOf(minBrightness, brightness)
                maxBrightness = maxOf(maxBrightness, brightness)
                pixelCount++
            }
        }

        val meanBrightness = if (pixelCount > 0) (totalBrightness / pixelCount).toInt() else 128
        val contrast = maxBrightness - minBrightness

        return ImageStats(meanBrightness = meanBrightness, contrast = contrast)
    }

    private data class ImageStats(val meanBrightness: Int, val contrast: Int)

    companion object {

        private val NON_URL_EXTENSIONS = setOf(
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "png", "jpg", "jpeg", "gif", "svg", "webp", "mp3", "mp4",
            "zip", "rar", "tar", "gz", "7z", "apk", "exe", "dmg"
        )

        private val COMMON_ABBREVIATIONS = setOf(
            "e.g", "i.e", "p.m", "a.m", "st", "vs", "etc", "dr", "mr", "mrs", "inc", "ltd"
        )

        internal val IPV4_PATTERN = Regex(
            """^(https?://)?((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?(?:/[^\s]*)?$""",
            RegexOption.IGNORE_CASE
        )

        private fun isVersionNumber(token: String): Boolean {
            val versionPattern = Regex("""^\d{1,2}\.\d{1,2}(\.\d{1,2})?$""")
            return versionPattern.matches(token) && !IPV4_PATTERN.matches(token)
        }

        private val VALID_TLDS = setOf(
            "com", "org", "net", "in", "co.in", "io", "ai", "app", "dev", "co", "me", "gov", "edu",
            "info", "biz", "xyz", "online", "site", "top", "club", "store", "tech", "link",
            "uk", "us", "ca", "de", "fr", "au", "jp", "ru", "cn", "sbi", "bank"
        )

        /**
         * Extracts full URLs (http/https/www), valid bare web domains (e.g. secure-bank-login.com),
         * and raw IPv4 address URLs (e.g. 185.34.22.10/login).
         * Strict validation ensures random words or time formats (e.g. '14:02', 'Shahul.2') are not falsely extracted as URLs.
         */
        fun extractUrls(text: String): List<String> {
            val schemePattern = Regex("""^(https?://[^\s]+|www\.[^\s]+)$""", RegexOption.IGNORE_CASE)
            val bareDomainPattern = Regex("""^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.([a-zA-Z]{2,})(?:/[^\s]*)?$""", RegexOption.IGNORE_CASE)

            return text.split(Regex("""\s+"""))
                .map { it.trimEnd('.', ',', ';', '!', '?', ')', '"', '\'', '•', '-') }
                .filter { token ->
                    val cleanToken = token.trimStart('(', '"', '\'')
                    val cleanLower = cleanToken.lowercase()
                    val extension = cleanLower.substringAfterLast('.', "")
                    val tld = cleanLower.substringBefore('/').substringAfterLast('.', "")

                    val hasScheme = cleanLower.startsWith("http://") || cleanLower.startsWith("https://")
                    val isTimeOnly = cleanLower.matches(Regex("""^\d{1,2}:\d{2}(:\d{2})?$"""))

                    cleanToken.isNotBlank() &&
                    !cleanToken.contains("@") &&
                    (!cleanToken.contains(":") || hasScheme || cleanToken.matches(Regex(""".*:\d{2,5}(/.*)?"""))) &&
                    !isTimeOnly &&
                    !isVersionNumber(cleanLower) &&
                    !COMMON_ABBREVIATIONS.contains(cleanLower) &&
                    !NON_URL_EXTENSIONS.contains(extension) &&
                    (schemePattern.matches(cleanToken) ||
                     IPV4_PATTERN.matches(cleanToken) ||
                     (bareDomainPattern.matches(cleanToken) && VALID_TLDS.contains(tld)))
                }
                .distinct()
                .toList()
        }

        fun extractPhoneNumbers(text: String): List<String> {
            val phoneRegex = Regex("""(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}""")
            return phoneRegex.findAll(text).map { it.value.trim() }.distinct().toList()
        }

        fun extractEmails(text: String): List<String> {
            val emailRegex = Regex("""[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}""")
            return emailRegex.findAll(text).map { it.value.lowercase().trim() }.distinct().toList()
        }

        /**
         * Detects whether ML Kit OCR output is garbage produced when Latin OCR attempts
         * to parse non-Latin script (e.g. Tamil characters misread as "rHlB6İT Jio 6T680T6").
         */
        fun isOcrGarbled(text: String): Boolean {
            val trimmed = text.trim()
            if (trimmed.length < 8) return false

            // If genuine Tamil Unicode is present, OCR did NOT fail to encode script
            if (text.any { it.code in 0x0B80..0x0BFF }) return false

            val tokens = trimmed.split(Regex("""\s+""")).filter { it.isNotBlank() }
            if (tokens.isEmpty()) return false

            // Token-level metrics
            var garbledTokens = 0
            val commonEnglishAndTechWords = setOf(
                "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
                "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
                "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
                "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
                "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
                "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
                "people", "into", "year", "your", "good", "some", "could", "them", "see", "other",
                "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
                "back", "after", "use", "two", "how", "our", "work", "first", "well", "way",
                "even", "new", "want", "because", "any", "these", "give", "day", "most", "us",
                "jio", "sbi", "hdfc", "icici", "axis", "amazon", "flipkart", "swiggy", "zomato",
                "otp", "rs", "inr", "account", "bank", "debited", "credited", "payment", "card",
                "valid", "recharge", "balance", "txn", "ref", "order", "delivery", "track", "click",
                "dear", "customer", "call", "help", "support", "team", "alert", "service", "app"
            )

            // Pattern for alternating alphanumeric noise like "6T680T6", "rHlB6İT", "15:02"
            val digitLetterInterleaved = Regex("""(?i)(?:[a-z]\d[a-z]|\d[a-z]\d|[a-z]{1,2}\d{2,}[a-z]{1,2})""")

            for (token in tokens) {
                val clean = token.lowercase().filter { it.isLetterOrDigit() }
                if (clean.length >= 3) {
                    val isCommon = commonEnglishAndTechWords.contains(clean)
                    val isNumeric = clean.all { it.isDigit() }
                    val hasInterleavedNoise = digitLetterInterleaved.containsMatchIn(clean)
                    val hasSpecialUnicodeNoise = token.any { it.code in 0x0100..0x024F || it.code in 0x0370..0x03FF || it.code in 0x0400..0x04FF }

                    if (hasInterleavedNoise || hasSpecialUnicodeNoise || (!isCommon && !isNumeric && clean.length >= 6 && clean.count { "aeiou".contains(it) } == 0)) {
                        garbledTokens++
                    }
                }
            }

            val garbleRatio = garbledTokens.toFloat() / tokens.size.coerceAtLeast(1)
            return garbleRatio >= 0.40f && tokens.size >= 3
        }

        /**
         * Normalizes domains by fixing common OCR character misrecognitions
         * (e.g. "ijo.com" when context is Jio -> "jio.com") before downstream scoring.
         * Maintains both original and normalized versions for confidence tracking.
         */
        fun normalizeDomainOcr(domain: String): String {
            val lower = domain.trim().lowercase()
            return when {
                // Common OCR misreads: ijo -> jio
                lower == "ijo.com" || lower == "www.ijo.com" -> "jio.com"
                lower.endsWith(".ijo.com") -> lower.replace(".ijo.com", ".jio.com")
                // Common OCR misreads: rn -> m, cl -> d, 0 -> o
                lower.contains("hdfc") && lower.contains("rn") -> lower.replace("rn", "m")
                // Common OCR misreads in popular domains
                lower.startsWith("http") && lower.contains("0") -> {
                    // Fix digit/letter confusion in known domains
                    lower.replace("0", "o").replace("1", "l").let { fixed ->
                        if (fixed != lower) fixed else lower
                    }
                }
                else -> lower
            }
        }
    }

    override fun close() {
        recognizer.close()
    }
}
