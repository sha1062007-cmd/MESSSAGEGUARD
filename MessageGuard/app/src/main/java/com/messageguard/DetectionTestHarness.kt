package com.messageguard

import android.content.Context
import android.util.Log

/**
 * DetectionTestHarness — Runs the local ML pipeline on a fixed set of 24 test messages
 * and logs results to logcat tag DETECTION_TEST for before/after comparison.
 *
 * Usage: In DEBUG builds only, call DetectionTestHarness.run(context, analyzer) to
 * produce a pipe-delimited log of every message verdict.
 *
 * IMPORTANT: This harness calls runMlPipelinePublic() only — no Gemini network calls —
 * so results are fully reproducible without connectivity.
 */
object DetectionTestHarness {

    private const val TAG = "DETECTION_TEST"

    data class TestMessage(
        val id: String,
        val category: Category,
        val description: String,
        val sender: String,
        val body: String,
        val containsUrl: Boolean = false
    )

    enum class Category {
        LEGIT,      // Must score SAFE
        SCAM,       // Must score WARNING or DANGER
        BORDERLINE  // SAFE or WARNING both acceptable; DANGER requires manual review
    }

    private val testSet = listOf(

        // ══════════════════════════════════════════════════════════════════════════
        // ── 25 LEGITIMATE MESSAGES (Expected: SAFE) ──────────────────────────────
        // ══════════════════════════════════════════════════════════════════════════

        // 1. Bank & Financial Transactional
        TestMessage(
            id = "LEGIT_01",
            category = Category.LEGIT,
            description = "SBI Net Banking OTP",
            sender = "SBIINB",
            body = "Your OTP for SBI Net Banking is 847291. Valid for 10 minutes. Do not share this OTP with anyone. Ref No: TXN20240818. If not initiated by you, call 1800-11-2211. -SBI"
        ),
        TestMessage(
            id = "LEGIT_02",
            category = Category.LEGIT,
            description = "HDFC Debit Card Transaction Alert",
            sender = "HDFCBK",
            body = "Alert: Rs. 3,450.00 spent on your HDFC Bank Card ending 8124 at RELIANCE DIGITAL on 20-AUG-24. Avl Bal: Rs. 48,210.50. Call 18002664332 if not you."
        ),
        TestMessage(
            id = "LEGIT_03",
            category = Category.LEGIT,
            description = "ICICI Bank Monthly e-Statement Alert",
            sender = "ICICIB",
            body = "Dear Customer, e-Statement for your ICICI Bank A/C XX9012 for the month of July 2024 has been sent to your registered email. Check at icicibank.com"
        ),
        TestMessage(
            id = "LEGIT_04",
            category = Category.LEGIT,
            description = "Axis Bank Monthly Home Loan EMI Reminder",
            sender = "AXISBK",
            body = "Dear Customer, EMI of Rs. 24,500 for Loan A/C 98124891 is due on 05-SEP-2024. Kindly maintain sufficient balance in your linked account."
        ),
        TestMessage(
            id = "LEGIT_05",
            category = Category.LEGIT,
            description = "Bajaj Finserv No-Cost EMI Auto-Debit Schedule",
            sender = "BAJAJF",
            body = "Reminder: Your EMI of Rs. 1,999 for order #BF8912 is scheduled for auto-debit on 2nd Sep. Total tenure: 6 months."
        ),

        // 2. Telecom & Utility Bills
        TestMessage(
            id = "LEGIT_06",
            category = Category.LEGIT,
            description = "Jio Prepaid Plan Recharge Confirmation",
            sender = "JIO",
            body = "Dear customer, your Jio recharge of Rs.239 is successful. Plan validity: 28 days. Data: 1.5GB/day. Calls: Unlimited. Enjoy your Jio services!"
        ),
        TestMessage(
            id = "LEGIT_07",
            category = Category.LEGIT,
            description = "Airtel Postpaid Bill Generation Notice",
            sender = "AIRTEL",
            body = "Your Airtel Postpaid bill for #9840123456 is Rs. 588.82. Due date: 28-Aug-2024. Pay conveniently via Airtel Thanks app or airtel.in/billpay",
            containsUrl = true
        ),
        TestMessage(
            id = "LEGIT_08",
            category = Category.LEGIT,
            description = "TNEB Electricity Bill Monthly Notice",
            sender = "TNEBLT",
            body = "TNEB: Electricity consumption bill for consumer #04098124 for July is Rs. 1,420. Due date without penalty: 30-Aug-2024. Pay via tnebnet.org"
        ),
        TestMessage(
            id = "LEGIT_09",
            category = Category.LEGIT,
            description = "Indane LPG Gas Cylinder Booking Confirmation",
            sender = "INDANE",
            body = "Dear Customer, Refill booking #891249 for consumer 781290 is confirmed. Cash memo amount: Rs. 810.50. Cylinder delivery expected in 2 days."
        ),

        // 3. E-Commerce & Deliveries
        TestMessage(
            id = "LEGIT_10",
            category = Category.LEGIT,
            description = "Amazon Package Shipped with Official Link",
            sender = "AMAZON",
            body = "Your Amazon order #402-9812345-6543210 has been shipped. Expected delivery: Aug 22. Track at https://amazon.in/orders",
            containsUrl = true
        ),
        TestMessage(
            id = "LEGIT_11",
            category = Category.LEGIT,
            description = "Flipkart Out for Delivery with PIN",
            sender = "FLIPKT",
            body = "Your Flipkart order for boAt Rockerz is out for delivery today. Delivery agent: Rajesh (8912409124). Share delivery PIN 4920 only upon receipt."
        ),
        TestMessage(
            id = "LEGIT_12",
            category = Category.LEGIT,
            description = "Myntra Return Pickup Confirmation",
            sender = "MYNTRA",
            body = "Return pickup for order #MY89124 has been completed. Refund of Rs. 1,299 will be credited to source account in 3-5 business days."
        ),
        TestMessage(
            id = "LEGIT_13",
            category = Category.LEGIT,
            description = "Swiggy Food Delivery Live Tracking",
            sender = "SWIGGY",
            body = "Your Swiggy order from Biryani Blues is arriving in 15 mins. Track your delivery partner at https://swiggy.com/track/4812",
            containsUrl = true
        ),
        TestMessage(
            id = "LEGIT_14",
            category = Category.LEGIT,
            description = "Zomato Table Booking Confirmation",
            sender = "ZOMATO",
            body = "Table reserved for 4 at Mainland China for tonight 8:30 PM. Booking ID #ZOM-4891. Manage reservation in Zomato app."
        ),

        // 4. Transportation, Travel & Subscriptions
        TestMessage(
            id = "LEGIT_15",
            category = Category.LEGIT,
            description = "Uber Ride OTP Verification",
            sender = "UBERIN",
            body = "Your Uber ride PIN is 8124. Driver Ramesh (Swift Dzire TN-09-AB-1234) is arriving in 3 mins. Do not start ride without sharing PIN."
        ),
        TestMessage(
            id = "LEGIT_16",
            category = Category.LEGIT,
            description = "IRCTC Train Ticket Booking Confirmed",
            sender = "IRCTCi",
            body = "PNR: 4218901245, Train: 12624 MAS MAIL, 21-Aug, 2A - B1 24 (CNF). Total Fare: Rs. 1450. Happy Journey! - IRCTC"
        ),
        TestMessage(
            id = "LEGIT_17",
            category = Category.LEGIT,
            description = "Netflix Subscription Renewal Invoice",
            sender = "NETFLX",
            body = "Netflix: Payment of Rs. 649 for Premium plan succeeded on 19-Aug. Next billing: 19-Sep. Manage account at netflix.com/youraccount",
            containsUrl = true
        ),

        // 5. Government, Health & Personal
        TestMessage(
            id = "LEGIT_18",
            category = Category.LEGIT,
            description = "UIDAI Official Aadhaar Auth OTP",
            sender = "UIDAIG",
            body = "581290 is the OTP to download e-Aadhaar. Valid for 10 mins. UIDAI never calls or sends SMS asking for Aadhaar number or OTP."
        ),
        TestMessage(
            id = "LEGIT_19",
            category = Category.LEGIT,
            description = "Apollo Hospitals Doctor Appointment Reminder",
            sender = "APOLLO",
            body = "Reminder: Your appointment with Dr. Sundaram is scheduled for tomorrow 11:30 AM at Apollo Greams Road. Reach 15 mins prior."
        ),
        TestMessage(
            id = "LEGIT_20",
            category = Category.LEGIT,
            description = "GitHub Pull Request Notification with Clean URL",
            sender = "GITHUB",
            body = "A new pull request #104 was opened by contributor in repository. Review code changes at https://github.com/project/pull/104",
            containsUrl = true
        ),
        TestMessage(
            id = "LEGIT_21",
            category = Category.LEGIT,
            description = "Tamil Legitimate: Jio Cashback Promo SMS",
            sender = "JIO",
            body = "உங்கள் ஜியோ எண் 9876543210-க்கு ரூ.50 கேஷ்பேக் கிடைத்துள்ளது. ரீசார்ஜ் செய்ய MyJio செயலியைப் பார்க்கவும்."
        ),
        TestMessage(
            id = "LEGIT_22",
            category = Category.LEGIT,
            description = "Tamil Legitimate: Bank Deposit Notification",
            sender = "SBIINB",
            body = "உங்கள் கணக்கில் ரூ.12,500 வரவு வைக்கப்பட்டுள்ளது. உங்கள் இருப்பை அறிய SBI கிளையை அணுகவும்."
        ),
        TestMessage(
            id = "LEGIT_23",
            category = Category.LEGIT,
            description = "Tamil Legitimate: Family Festival Greeting",
            sender = "+919876543210",
            body = "இனிய பொங்கல் நல்வாழ்த்துகள்! உங்கள் குடும்பத்தினருடன் மகிழ்ச்சியாக கொண்டாட வாழ்த்துகிறேன்."
        ),
        TestMessage(
            id = "LEGIT_24",
            category = Category.LEGIT,
            description = "Tanglish Legitimate: Informal Movie Meetup",
            sender = "+919840123456",
            body = "Nalaiku evening meet pannalaama? Movie ticket book panniten. Neenga vandhudunga."
        ),
        TestMessage(
            id = "LEGIT_25",
            category = Category.LEGIT,
            description = "Tanglish Legitimate: Dinner GPay Settlement",
            sender = "+919710987654",
            body = "Machan lunch bill share pannunga. Enakku gpay pannidu Rs.200."
        ),


        // ══════════════════════════════════════════════════════════════════════════
        // ── 25 SCAM / PHISHING MESSAGES (Expected: DANGER) ───────────────────────
        // ══════════════════════════════════════════════════════════════════════════

        // 1. Banking & KYC Phishing
        TestMessage(
            id = "SCAM_01",
            category = Category.SCAM,
            description = "Fake SBI Account Block with Phishing URL",
            sender = "+918765432100",
            body = "URGENT: Your SBI account has been blocked due to suspicious activity. Click immediately to unblock: http://sbi-secure-update.xyz/unblock Failure to act will result in permanent closure.",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_02",
            category = Category.SCAM,
            description = "HDFC Credit Card Permanent Block Threat",
            sender = "+918877665544",
            body = "Your HDFC Bank Credit Card ending 4521 has been temporarily blocked. Please click to restore access: http://hdfcbank-secure.top/restore-card If not completed in 60 mins, card will be permanently blocked.",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_03",
            category = Category.SCAM,
            description = "Urgent KYC Suspension with Bitly Shortlink",
            sender = "+913210987654",
            body = "FINAL WARNING: Your HDFC account will be suspended in 2 hours due to incomplete KYC. Update immediately: https://bit.ly/hdfc-kyc-urgent Ignore at your own risk.",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_04",
            category = Category.SCAM,
            description = "Fake ICICI PAN Linking Expiry Scam",
            sender = "+919012489124",
            body = "Dear ICICI user, your netbanking will be terminated today because PAN is not linked. Update PAN details here immediately: http://icici-pan-link.live/kyc",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_05",
            category = Category.SCAM,
            description = "Fake PhonePe KYC Account Expiry Notice",
            sender = "+917812901245",
            body = "PhonePe KYC Alert: Your wallet will be blocked within 24 hours. Call PhonePe manager 09876543210 or install KYC APK from http://phonepe-support.site",
            containsUrl = true
        ),

        // 2. Prize, Lottery & Cashback Traps
        TestMessage(
            id = "SCAM_06",
            category = Category.SCAM,
            description = "KBC Lottery 25 Lakh Prize Scam",
            sender = "+917654321098",
            body = "CONGRATULATIONS! You have won Rs.25,00,000 in the KBC Lucky Draw! Claim your reward within 24 hours. Call our KBC executive: 09876543210. Lottery ID: KBC-2024."
        ),
        TestMessage(
            id = "SCAM_07",
            category = Category.SCAM,
            description = "Fake Cash Prize Demanding OTP Handover",
            sender = "+917766554433",
            body = "Your reward of Rs.8500 is ready to be credited to your account. To receive, share the OTP sent to your registered number with our agent at 09988112233. This offer expires in 1 hour."
        ),
        TestMessage(
            id = "SCAM_08",
            category = Category.SCAM,
            description = "Government Subsidized Car Lottery Winner Scam",
            sender = "+918124901245",
            body = "You are selected for Prime Minister Free Vehicle Yojana 2024! Pay registration fee of Rs. 1,500 to dispatch your car. Contact 09812401245 immediately."
        ),

        // 3. Payment Fraud, Typosquatting & App Sideloading
        TestMessage(
            id = "SCAM_09",
            category = Category.SCAM,
            description = "UPI Collect Request Trapping User for Refund",
            sender = "+914321098765",
            body = "You have received a UPI collect request of Rs.1 from CASHBACK-REFUND. Accept this request to receive your pending refund of Rs.5000. Tap: upi://pay?pa=scam@upi&pn=REFUND&am=1"
        ),
        TestMessage(
            id = "SCAM_10",
            category = Category.SCAM,
            description = "PayPal Typosquatted Domain (paypa1.com)",
            sender = "+915432109876",
            body = "Your PayPal account requires verification. Visit http://paypa1.com/verify-account to confirm your identity. Account will be suspended if not verified in 12 hours.",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_11",
            category = Category.SCAM,
            description = "Netflix Subscription Suspended Phishing Site",
            sender = "+919812409812",
            body = "Netflix: Your payment was declined. Update billing information within 24 hours to keep streaming: http://netfIix-billing-update.com/signin",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_12",
            category = Category.SCAM,
            description = "AnyDesk / TeamViewer Remote Access Scam",
            sender = "+918912409124",
            body = "Bank Security Alert: Unauthorized transaction of Rs. 24,000 detected. Download AnyDesk app immediately and provide 9-digit code to cancel transfer."
        ),
        TestMessage(
            id = "SCAM_13",
            category = Category.SCAM,
            description = "Fake Income Tax Refund with APK Download Link",
            sender = "+917812901234",
            body = "Income Tax Dept: Approved tax refund of Rs. 18,450. Download Refund Filing Manager app to claim: http://incometax-refund.apk/app.apk",
            containsUrl = true
        ),

        // 4. Fake Jobs, Loan Traps & Courier Delivery Scams
        TestMessage(
            id = "SCAM_14",
            category = Category.SCAM,
            description = "Part-Time YouTube Video Liking Job Scam",
            sender = "+919988112244",
            body = "Earn Rs. 3,000 to Rs. 8,000 daily by liking YouTube videos from home! No experience required. Telegram HR coordinator: @youtube_earning_admin"
        ),
        TestMessage(
            id = "SCAM_15",
            category = Category.SCAM,
            description = "Customs Delivery Hold Demanding Release Fee",
            sender = "+918124901290",
            body = "India Post / Customs: Your international package is held at customs. Pay release fee of Rs. 480 within 6 hours to avoid return: http://indiapost-customs.cc",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_16",
            category = Category.SCAM,
            description = "Immediate 5-Lakh Loan Scam Demanding Advance Processing",
            sender = "+917812401245",
            body = "Loan of Rs. 5,00,000 approved without CIBIL check! Pay Rs. 2,500 file processing charge to release funds. Call loan manager: 09812409124."
        ),
        TestMessage(
            id = "SCAM_17",
            category = Category.SCAM,
            description = "WhatsApp Gold APK Malware Sideloading Lure",
            sender = "+919012489012",
            body = "Exclusive WhatsApp Gold edition released! Video call recording & invisible mode unlocked. Download official APK: http://whatsapp-gold-update.xyz/app",
            containsUrl = true
        ),

        // 5. Regional Tamil & Tanglish Scams
        TestMessage(
            id = "SCAM_18",
            category = Category.SCAM,
            description = "Tamil Scam: Bank Account Block & OTP Handover",
            sender = "+912109876543",
            body = "உங்கள் வங்கி கணக்கு முடக்கப்பட்டது. உடனே உங்கள் ஓடிபி மற்றும் கடவுச்சொல்லை அனுப்பவும். இல்லையெனில் கணக்கு நிரந்தரமாக நீக்கப்படும். அவசரம்!"
        ),
        TestMessage(
            id = "SCAM_19",
            category = Category.SCAM,
            description = "Tamil Scam: 10-Lakh Lottery Prize Lure",
            sender = "+919988112233",
            body = "வாழ்த்துகள்! நீங்கள் ரூ.10 லட்சம் பரிசு வென்றுள்ளீர்கள். பணத்தைப் பெற உடனே சரிபார்க்கவும் மற்றும் தொடர்பு கொள்ளவும்."
        ),
        TestMessage(
            id = "SCAM_20",
            category = Category.SCAM,
            description = "Tamil Scam: TNEB Power Cut Threat with Phishing Link",
            sender = "+918877665511",
            body = "உங்கள் மின்சாரக் கட்டணம் செலுத்தப்படவில்லை. மின் இணைப்பு உடனே துண்டிக்கப்படும். அவசரமாக கட்டணத்தை சரிபார்க்கவும்: http://tneb-bill.xyz",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_21",
            category = Category.SCAM,
            description = "Tamil Scam: Loan Approval Demanding Advance Fee",
            sender = "+917812901245",
            body = "ரூ.5,00,000 உடனடி கடன் ஒப்புதல்! கட்டணம் ரூ.2,000 செலுத்தி பணத்தைப் பெறவும். உடனே இந்த எண்ணை அழைக்கவும்: 09876543210."
        ),
        TestMessage(
            id = "SCAM_22",
            category = Category.SCAM,
            description = "Tanglish Scam: Bank Account Block Threat",
            sender = "+911098765432",
            body = "Ungal vangi kanakku block aagum. Seekiram otp anuppunga 9876543210 number-ku. Illa na kanakku neekkidum."
        ),
        TestMessage(
            id = "SCAM_23",
            category = Category.SCAM,
            description = "Tanglish Scam: 5-Lakh Lottery Claim Link",
            sender = "+917766554422",
            body = "Neenga 5 latcham panam win panniteenga. Link click pannunga udane claim panna http://prize-claim.top",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_24",
            category = Category.SCAM,
            description = "Tanglish Scam: Urgent KYC Verification Lure",
            sender = "+919812401245",
            body = "Aadhar card link pannala na account moodidum. Udane verify pannunga link click panni http://aadhar-kyc.site",
            containsUrl = true
        ),
        TestMessage(
            id = "SCAM_25",
            category = Category.SCAM,
            description = "Tanglish Scam: Part-Time Job Advance Payment Scam",
            sender = "+918912409812",
            body = "Veetla irundhu velai panni daily 2000 panam earn pannunga. Join panna 500 registration fees gpay pannunga."
        ),


        // ══════════════════════════════════════════════════════════════════════════
        // ── 10 BORDERLINE / AMBIGUOUS (Expected: WARNING / Review Required) ──────
        // ══════════════════════════════════════════════════════════════════════════

        TestMessage(
            id = "WARN_01",
            category = Category.BORDERLINE,
            description = "Unsolicited Pre-Approved Personal Loan with Bitly Shortlink",
            sender = "FASTLOAN",
            body = "Congratulations! You are pre-approved for an instant personal loan of Rs.2,00,000 at 9.9% APR. Apply now: https://bit.ly/fast-loan-app Limited period offer.",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_02",
            category = Category.BORDERLINE,
            description = "WFH High Salary Job Offer with TinyURL Link",
            sender = "+919988776655",
            body = "Earn Rs.25,00,00 per week working part-time from home. No interview required. Register before 6 PM: https://tinyurl.com/wfh-jobs-now",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_03",
            category = Category.BORDERLINE,
            description = "Credit Card Upgrade Offer with Shortened Redirect Link",
            sender = "CARDOFR",
            body = "Upgrade your lifetime-free Platinum credit card with 5X reward points. Offer valid till midnight: https://t.co/card-upgrade-offer",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_04",
            category = Category.BORDERLINE,
            description = "Third-Party Insurance Discount Promotion with Shortlink",
            sender = "POLICYNOW",
            body = "Save 40% on car & bike insurance renewals today! Compare top quotes and buy instantly: https://is.gd/insure-save",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_05",
            category = Category.BORDERLINE,
            description = "E-Commerce Flash Sale with Shortened Campaign Tracking Link",
            sender = "DEALSNOW",
            body = "Mega Clearance Sale: Up to 90% discount on branded footwear! Limited stock available. Shop deals: https://rb.gy/deals-flash",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_06",
            category = Category.BORDERLINE,
            description = "Crypto Trading Robot High Yield Promise with Shortlink",
            sender = "+918124901245",
            body = "Discover automated AI crypto trading strategies earning 15% weekly returns. Join private community: https://bit.ly/ai-crypto-bot",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_07",
            category = Category.BORDERLINE,
            description = "Real Estate Pre-Launch Villa Offer with Callback Link",
            sender = "HOMELAND",
            body = "Luxury 3BHK villas starting at Rs. 65 Lakhs near IT corridor. Zero pre-EMI till possession! Express interest: https://tinyurl.com/it-villas",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_08",
            category = Category.BORDERLINE,
            description = "Stock Market Intraday Advisory Tips with Shortened Channel Link",
            sender = "STOCKTIPS",
            body = "Get 95% accurate Nifty & BankNifty intraday calls daily! Join SEBI registered expert channel: https://t.co/nifty-tips-join",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_09",
            category = Category.BORDERLINE,
            description = "Online Rummy / Gaming Bonus Invitation with Shortlink",
            sender = "PLAYWIN",
            body = "Claim Rs. 1,500 joining bonus + 100% deposit match on India's top card gaming app: https://is.gd/play-rummy-bonus",
            containsUrl = true
        ),
        TestMessage(
            id = "WARN_10",
            category = Category.BORDERLINE,
            description = "Educational Certification Bootcamp Discount with Shortlink",
            sender = "EDUTECH",
            body = "Master Full-Stack AI engineering in 12 weeks. 100% placement support. Reserve early bird seat: https://rb.gy/ai-bootcamp",
            containsUrl = true
        )
    )

    /**
     * Runs the full test set through the LOCAL ML pipeline only (no Gemini).
     * Call this BEFORE making any code changes to capture baseline verdicts.
     * Call again AFTER changes to compare.
     *
     * Results are logged to logcat tag: DETECTION_TEST
     * Format: MSG_ID | CATEGORY | EXPECTED | URL | NLP | BODMAS | TYPO | REP | ML_PCT | VERDICT | PASS?
     */
    fun run(context: Context, analyzer: SpamAnalyzer, runLabel: String = "BASELINE") {
        if (!BuildConfig.DEBUG) {
            Log.w(TAG, "DetectionTestHarness: only runs in DEBUG builds. Skipping.")
            return
        }

        Log.i(TAG, "═══════════════════════════════════════════════════════════════")
        Log.i(TAG, "  DETECTION TEST RUN: $runLabel  (${testSet.size} messages)")
        Log.i(TAG, "═══════════════════════════════════════════════════════════════")
        Log.i(TAG, "ID  | CAT       | EXPECTED | URL%  | NLP%  | BODMAS% | TYPO% | REP% | ML%  | VERDICT   | PASS?")
        Log.i(TAG, "────────────────────────────────────────────────────────────────────────────────────────────────")

        var passCount = 0
        var failCount = 0
        val results = mutableListOf<String>()
        val falsePositives = mutableListOf<String>()
        val falseNegatives = mutableListOf<String>()

        for (msg in testSet) {
            val urls = extractUrlsFromText(msg.body)
            val indicators = mutableListOf<String>()
            val explainabilityItems = mutableListOf<SpamAnalyzer.ExplainabilityItem>()

            val ml = analyzer.runMlPipelinePublic(
                message = msg.body,
                urls = urls,
                indicators = indicators,
                explainabilityItems = explainabilityItems,
                reputationScore = 0.0f  // Fresh sender — no reputation history
            )

            val mlPct = (ml.finalScore * 100).toInt().coerceIn(0, 100)
            val localVerdict = when {
                mlPct >= 70 -> Verdict.DANGER
                mlPct >= 40 -> Verdict.WARNING
                else -> Verdict.SAFE
            }

            val expected = when (msg.category) {
                Category.LEGIT -> "SAFE"
                Category.SCAM -> "WARN/DANGER"
                Category.BORDERLINE -> "ANY"
            }

            val pass = when (msg.category) {
                Category.LEGIT -> localVerdict == Verdict.SAFE
                Category.SCAM -> localVerdict != Verdict.SAFE
                Category.BORDERLINE -> true  // Any verdict is documented, not auto-fail
            }

            val passStr = if (pass) "✓ PASS" else "✗ FAIL"
            if (pass) passCount++ else failCount++

            // Track false positives and false negatives for error analysis
            if (!pass) {
                if (msg.category == Category.LEGIT) {
                    falsePositives.add("${msg.id}: ${msg.description} (ML=$mlPct%, verdict=$localVerdict)")
                } else {
                    falseNegatives.add("${msg.id}: ${msg.description} (ML=$mlPct%, verdict=$localVerdict)")
                }
            }

            val row = "%-4s| %-9s | %-8s | %-5d | %-5d | %-7d | %-5d | %-4d | %-4d | %-9s | %s".format(
                msg.id,
                msg.category.name,
                expected,
                (ml.urlScore * 100).toInt(),
                (ml.nlpScore * 100).toInt(),
                (ml.bodmasScore * 100).toInt(),
                (ml.typosquatScore * 100).toInt(),
                (ml.reputationScore * 100).toInt(),
                mlPct,
                localVerdict.name,
                passStr
            )

            Log.i(TAG, row)
            results.add("[$runLabel] ${msg.id} | ${msg.category} | ${msg.description} | " +
                "URL=${(ml.urlScore*100).toInt()} NLP=${(ml.nlpScore*100).toInt()} " +
                "BODMAS=${(ml.bodmasScore*100).toInt()} TYPO=${(ml.typosquatScore*100).toInt()} " +
                "ML=$mlPct | $localVerdict | $passStr")

            // Special logging for Tamil messages — check heuristic fired
            if (msg.id == "S07" || msg.id == "S08") {
                Log.i(TAG, "  *** TAMIL/TANGLISH CHECK: ${msg.id} NLP_score=${(ml.nlpScore*100).toInt()}% " +
                    "(must be >=70 for Tamil heuristic to have fired as 1st model signal)")
            }
        }

        Log.i(TAG, "────────────────────────────────────────────────────────────────────────────────────────────────")
        Log.i(TAG, "SUMMARY [$runLabel]: PASS=$passCount  FAIL=$failCount  TOTAL=${testSet.size}")
        Log.i(TAG, "ACCURACY: ${"%.1f%%".format(passCount.toDouble() / testSet.size * 100)}")
        
        if (falsePositives.isNotEmpty()) {
            Log.i(TAG, "FALSE POSITIVES (${falsePositives.size}):")
            falsePositives.forEach { Log.i(TAG, "  FP: $it") }
        }
        if (falseNegatives.isNotEmpty()) {
            Log.i(TAG, "FALSE NEGATIVES (${falseNegatives.size}):")
            falseNegatives.forEach { Log.i(TAG, "  FN: $it") }
        }
        
        // Per-category accuracy
        val legitTotal = testSet.count { it.category == Category.LEGIT }
        val legitPass = testSet.count { it.category == Category.LEGIT && 
            (mlPctForMsg(analyzer, it) < 40) }
        val scamTotal = testSet.count { it.category == Category.SCAM }
        val scamPass = testSet.count { it.category == Category.SCAM && 
            (mlPctForMsg(analyzer, it) >= 40) }
        
        Log.i(TAG, "PER-CATEGORY: LEGIT=${legitPass}/${legitTotal} SCAM=${scamPass}/${scamTotal}")
        Log.i(TAG, "═══════════════════════════════════════════════════════════════")
    }

    private fun mlPctForMsg(analyzer: SpamAnalyzer, msg: TestMessage): Int {
        val urls = extractUrlsFromText(msg.body)
        val ml = analyzer.runMlPipelinePublic(msg.body, urls, mutableListOf(), mutableListOf(), 0.0f)
        return (ml.finalScore * 100).toInt().coerceIn(0, 100)
    }

    /**
     * Extracts URLs from message body using same pattern as SpamAnalyzer.
     */
    private fun extractUrlsFromText(text: String): List<String> =
        Regex("""(?i)https?://[^\s<>"']+""")
            .findAll(text)
            .map { it.value.trimEnd('.', ',', ';') }
            .distinct()
            .toList()
}
