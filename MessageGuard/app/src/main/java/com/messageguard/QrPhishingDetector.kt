package com.messageguard

import android.graphics.Bitmap
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

data class QrAnalysisResult(
    val qrFound: Boolean = false,
    val rawPayload: String = "",
    val isPhishingUrl: Boolean = false,
    val isTyposquat: Boolean = false,
    val isHomograph: Boolean = false,
    val threatSummary: String = ""
)

object QrPhishingDetector {

    suspend fun scanBitmap(bitmap: Bitmap): QrAnalysisResult = suspendCancellableCoroutine { continuation ->
        val image = InputImage.fromBitmap(bitmap, 0)
        val scanner = BarcodeScanning.getClient()

        scanner.process(image)
            .addOnSuccessListener { barcodes ->
                if (barcodes.isNullOrEmpty()) {
                    continuation.resume(QrAnalysisResult(qrFound = false))
                    return@addOnSuccessListener
                }

                val barcode = barcodes.firstOrNull { 
                    it.valueType == Barcode.TYPE_URL || it.valueType == Barcode.TYPE_TEXT
                } ?: barcodes.firstOrNull()

                if (barcode == null) {
                    continuation.resume(QrAnalysisResult(qrFound = false))
                    return@addOnSuccessListener
                }

                val rawValue = barcode.rawValue ?: ""
                val url = barcode.url?.url ?: rawValue

                val domainResult = SpamAnalyzer.analyzeDomain(url)
                val isPhishing = domainResult.isTyposquat || domainResult.isHomograph || isKnownPhishingPayload(rawValue)

                val summary = when {
                    domainResult.isHomograph -> "QR Code contains IDN Homograph spoofing domain"
                    domainResult.isTyposquat -> "QR Code contains typosquatted brand domain"
                    isPhishing -> "QR Code contains suspicious payload link"
                    else -> "QR Code scanned clean"
                }

                continuation.resume(
                    QrAnalysisResult(
                        qrFound = true,
                        rawPayload = rawValue,
                        isPhishingUrl = isPhishing,
                        isTyposquat = domainResult.isTyposquat,
                        isHomograph = domainResult.isHomograph,
                        threatSummary = summary
                    )
                )
            }
            .addOnFailureListener {
                continuation.resume(QrAnalysisResult(qrFound = false, threatSummary = "Scan failure: ${it.message}"))
            }
    }

    fun isKnownPhishingPayload(payload: String): Boolean {
        val lower = payload.lowercase()
        return lower.contains("upi://pay") &&
            (lower.contains("mode=collect") || Regex("""\bcollect\b""").containsMatchIn(lower))
    }
}
