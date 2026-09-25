package com.messageguard

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import android.util.Log

@RunWith(AndroidJUnit4::class)
class SpamAnalyzerTest {
    @Test
    fun runPhishingPipelineTests() = runBlocking {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val spamAnalyzer = SpamAnalyzer(appContext)
        
        val messages = listOf(
            // Safe messages
            "Hi, are we still meeting for lunch at 1pm tomorrow?",
            "Your Amazon order #114-2938471 has shipped. Track here: amazon.in/track/114293",
            "Your OTP for login is 483920. Do not share this with anyone.",
            "Reminder: Your electricity bill of Rs 450 is due on 15th. Pay via official portal.",
            // Known scams (English)
            "URGENT: Your bank account will be BLOCKED in 24 hours. Verify immediately: bit.ly/sbi-verify-acc",
            "Congratulations! You've won Rs 50,000. Claim now by entering your UPI PIN: upi://pay?pa=claim@fake&mode=collect",
            "Dear user, your KYC has expired. Update immediately or lose access: tinyurl.com/kyc-update-urgent",
            "SBI ALERT: Suspicious activity detected. Click http://sb1-secure.xyz/verify to unblock account.",
            "Your PAN card is blocked. Update Aadhaar link now: bit.ly/pan-aadhaar-update",
            // Tamil examples
            "உங்கள் வங்கி கணக்கு 24 மணி நேரத்தில் மூடப்படும். உடனே சரிபார்க்க: bit.ly/sbi-verify",
            "வாழ்த்துக்கள்! நீங்கள் Rs 50,000 வென்றுள்ளீர்கள். UPI PIN உள்ளிட்டு பெறுங்கள்.",
            "நாளை மதியம் 3 மணிக்கு சந்திப்போம். உணவகத்தில்.",
            // Hindi examples
            "आपका बैंक खाता 24 घंटे में ब्लॉक हो जाएगा। तुरंत सत्यापित करें: bit.ly/hdfc-verify",
            "बधाई हो! आप Rs 50000 जीत गए हैं। अपना UPI PIN दर्ज करें।",
            "कल दोपहर 1 बजे लंच पर मिलते हैं।"
        )
        
        Log.d("FalsePositiveTest", "=== STARTING PIPELINE DIAGNOSTIC ===")
        for (msg in messages) {
            val outcome = spamAnalyzer.analyze(
                appSource = "SMS",
                sender = "DiagnosticTest",
                subject = "",
                messageBody = msg
            )
            val res = outcome.result
            Log.d("FalsePositiveTest", "DIAG: msg='${msg.take(45)}' | VERDICT=${res.verdict} | RISK=${res.riskScore} | ML=${res.mlScore} | AI=${res.aiScore} | FLAGS=${res.flags.take(5)}")
        }
        Log.d("FalsePositiveTest", "=== PIPELINE DIAGNOSTIC COMPLETE ===")
    }
}
