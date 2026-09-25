"""
Part 3 — Isolated HF Benchmark: onnx-community/bert-tiny-finetuned-sms-spam-detection-ONNX
Compares the candidate model's predictions against the 60-message DetectionTestHarness ground-truth.

Run this OUTSIDE the Android app, from the project root:
  pip install transformers optimum[onnxruntime] numpy
  python hf_benchmark.py

No app code is modified. This is a read-only feasibility evaluation.
"""

from transformers import pipeline
import json

# ─── 60-Message Benchmark Suite (mirrors DetectionTestHarness.kt) ──────────────
# Format: (id, expected_category, body)
# LEGIT = must be SAFE, SCAM = must be SPAM, BORDERLINE = SAFE or SPAM acceptable
TEST_SUITE = [
    # ─── 25 LEGITIMATE ───────────────────────────────────────────────────
    ("LEGIT_01", "LEGIT", "Your OTP for SBI Net Banking is 847291. Valid for 10 minutes. Do not share this OTP with anyone. Ref No: TXN20240818. If not initiated by you, call 1800-11-2211. -SBI"),
    ("LEGIT_02", "LEGIT", "Rs.4,500 debited from your SBI A/c XX4821 on 18-Aug for UPI txn to Amazon. Available Balance: Rs.62,340. Not you? Call 1800-11-2211"),
    ("LEGIT_03", "LEGIT", "Your HDFC Bank Credit Card ending 4521 has a payment due of Rs.8,420 on 25-Aug-2024. Pay via NetBanking: www.hdfcbank.com or call 1800-202-6161"),
    ("LEGIT_04", "LEGIT", "Dear Customer, your ICICI Bank Home Loan EMI of Rs.23,450 has been auto-debited for Aug 2024. Outstanding balance: Rs.18,45,200. For queries: www.icicibank.com"),
    ("LEGIT_05", "LEGIT", "AXIS BANK: Your a/c XX9012 credited with Rs.55,000 on 18/08/24. Available Bal: Rs.91,234. For any query, visit www.axisbank.com or call 1860-419-5555"),
    ("LEGIT_06", "LEGIT", "Your Jio recharge of Rs.299 for 84 days is successful! Your services are active. For help: www.jio.com or call 199"),
    ("LEGIT_07", "LEGIT", "AIRTEL: Dear customer, your prepaid balance is Rs.45.50. Main balance expires on 30-Aug-2024. Recharge now at www.airtel.in"),
    ("LEGIT_08", "LEGIT", "TNEB Bill for account 1234567: Amount due Rs.1,245 before 25-Aug-2024. Pay at www.tnebnet.org or TNEB app. Helpline: 1912"),
    ("LEGIT_09", "LEGIT", "Your Indane LPG cylinder booking is confirmed. Delivery Ref: IND20240818. Expected delivery: 20-Aug. Track at www.indane.co.in"),
    ("LEGIT_10", "LEGIT", "Amazon.in: Your order #402-8901234-7654321 for 'boAt Rockerz 450' has been shipped via Delhivery. Track: www.amazon.in/track. Expected: Aug 20"),
    ("LEGIT_11", "LEGIT", "Flipkart: Your order OD987654321 for 'Samsung Galaxy M34' is out for delivery. Your OTP is 4782. Provide this to the delivery person. Do not share with others."),
    ("LEGIT_12", "LEGIT", "Myntra: Your order of 'Roadster Men's Jacket' (#MYN-2024-890123) has been dispatched. Estimated delivery by Aug 21. Track at app.myntra.com"),
    ("LEGIT_13", "LEGIT", "Swiggy: Your order from Domino's Pizza is confirmed! Order #SWG-20240818-449012. Estimated delivery: 35 mins. Track live in the Swiggy app."),
    ("LEGIT_14", "LEGIT", "Zomato: Your order from McDonald's (Order #ZOM-447812) is being prepared! Estimated delivery: 25-30 mins. Enjoy your meal!"),
    ("LEGIT_15", "LEGIT", "Your Uber ride is arriving! Driver: Rajesh Kumar. Vehicle: Maruti Swift (TN09 AB 1234). OTP: 7821. Share this OTP to start the ride."),
    ("LEGIT_16", "LEGIT", "IRCTC: Your ticket PNR 4507291834 for train 12671 NILAGIRI EXP on 19-Aug (Chennai to Coimbatore) is CONFIRMED. Coach: S4, Berth: 45."),
    ("LEGIT_17", "LEGIT", "Netflix: Your payment of Rs.649 for the Premium plan has been received. Your next billing date is 18-Sep-2024. Enjoy streaming!"),
    ("LEGIT_18", "LEGIT", "UIDAI: Your Aadhaar Update request is received. Service Request No: SRN2024081812345. Check status at myaadhaar.uidai.gov.in"),
    ("LEGIT_19", "LEGIT", "Apollo Hospitals: Appointment confirmed for Dr. Priya Sharma (Cardiology) on Aug 20, 2024 at 10:30 AM. Patient: Suresh Kumar. Ref: APL2024081890"),
    ("LEGIT_20", "LEGIT", "Your Pull Request #247 on messageguard/detection-engine was merged by @team-lead. View changes: https://github.com/messageguard/detection-engine/pull/247"),
    ("LEGIT_21", "LEGIT", "Enna aachu? Nan mall poren weekend la. Vaa kooda pona. Lunch treat panren!"),
    ("LEGIT_22", "LEGIT", "Dei tickets potta? FDFS la poganum. Book panna maranthutte."),
    ("LEGIT_23", "LEGIT", "Anna, 500 rs transfer pannunga. GPay la anuthuven. Salary vandha return panren."),
    ("LEGIT_24", "LEGIT", "Yaar da avan? Neethan sonna number la call panna marandhutte."),
    ("LEGIT_25", "LEGIT", "Meeting cancel aaguthu. Tomorrow morning 10am ku reschedule panrom. Ok va?"),

    # ─── 25 SCAM ─────────────────────────────────────────────────────────
    ("SCAM_01", "SCAM", "URGENT: Your SBI account has been blocked due to suspicious activity. Click immediately to unblock: http://sbi-secure-update.xyz/unblock Failure to act will result in permanent closure."),
    ("SCAM_02", "SCAM", "Your HDFC Bank Credit Card ending 4521 has been temporarily blocked. Please click to restore access: http://hdfcbank-secure.top/restore-card If not completed in 60 mins, card will be permanently blocked."),
    ("SCAM_03", "SCAM", "FINAL WARNING: Your HDFC account will be suspended in 2 hours due to incomplete KYC. Update immediately: https://bit.ly/hdfc-kyc-urgent Ignore at your own risk."),
    ("SCAM_04", "SCAM", "Dear ICICI user, your netbanking will be terminated today because PAN is not linked. Update PAN details here immediately: http://icici-pan-link.live/kyc"),
    ("SCAM_05", "SCAM", "PhonePe KYC Alert: Your wallet will be blocked within 24 hours. Call PhonePe manager 09876543210 or install KYC APK from http://phonepe-support.site"),
    ("SCAM_06", "SCAM", "CONGRATULATIONS! You have won Rs.25,00,000 in the KBC Lucky Draw! Claim your reward within 24 hours. Call our KBC executive: 09876543210. Lottery ID: KBC-2024."),
    ("SCAM_07", "SCAM", "Your reward of Rs.8500 is ready to be credited to your account. To receive, share the OTP sent to your registered number with our agent at 09988112233. This offer expires in 1 hour."),
    ("SCAM_08", "SCAM", "You are selected for Prime Minister Free Vehicle Yojana 2024! Pay registration fee of Rs. 1,500 to dispatch your car. Contact 09812401245 immediately."),
    ("SCAM_09", "SCAM", "Your UPI ID is compromised. We have initiated a transfer reversal of Rs.12,500. Click ACCEPT on the collect request we have sent to your UPI app to recover your funds."),
    ("SCAM_10", "SCAM", "Dear PayPal user, your account requires immediate verification. Login here: http://paypa1-secure.com/verify to avoid suspension."),
    ("SCAM_11", "SCAM", "NETFLIX ACCOUNT SUSPENDED: Your payment failed. Update billing at http://netfIix-support.site/billing immediately to continue watching."),
    ("SCAM_12", "SCAM", "You have a pending parcel from DHL awaiting customs clearance. Pay Rs.450 processing fee at: http://dhl-india-customs.online/pay to avoid return."),
    ("SCAM_13", "SCAM", "INCOME TAX DEPT: You have a pending refund of Rs.34,500. Install our secure refund app: http://incometax-refund.apk.site/download and submit your bank details."),
    ("SCAM_14", "SCAM", "Earn Rs.45,000/week liking YouTube videos from home. NO experience required. Flexible hours. WhatsApp 09812345678 to register NOW. Limited spots!"),
    ("SCAM_15", "SCAM", "SECURITY ALERT: Your device was detected accessing adult content. Your phone will be locked in 24h unless you pay Rs.2,000 fine at: http://cybercrime-fine.xyz"),
    ("SCAM_16", "SCAM", "To fix your phone issue, allow our technician remote access. Download AnyDesk from http://anydesk-support-india.com and share the 9-digit code shown."),
    ("SCAM_17", "SCAM", "Upgrade to WhatsApp Gold for exclusive features! Download now: http://whatsapp-gold-beta.com/install.apk"),
    ("SCAM_18", "SCAM", "SBI LOAN APPROVED: Rs.5,00,000 personal loan approved for you at 0% interest for 12 months! Pay advance processing fee Rs.2,500 via UPI to claim: 09812345678@paytm"),
    ("SCAM_19", "SCAM", "Your electricity connection will be cut tonight at 9:30 PM due to low CIBIL score. Call our officer immediately: 09876543210 to avoid disconnection."),
    ("SCAM_20", "SCAM", "HDFC: Suspicious login detected on your account from Delhi. If not you, click immediately to secure: http://hdfcsecurity-alert.com/lockdown"),
    ("SCAM_21", "SCAM", "Ungal bank account suspend aagum. Ungal KYC update seiya: http://sbi-kyc-update.xyz click pannunga. 24 manikku udhal neernga."),
    ("SCAM_22", "SCAM", "Vaanga da! 10 lakh lottery win panniteenga. Claim panna ithai click pannunga: http://lottery-claim-india.top"),
    ("SCAM_23", "SCAM", "Bhai, aapka account block ho gaya hai. Abhi verify karo: http://sbi-verify-now.xyz Agar nahi kiya to permanent close ho jayega."),
    ("SCAM_24", "SCAM", "Bank account block aaguthu mama. Idhai click pannu udane: http://hdfc-unblock.top ungal details enter pannunga."),
    ("SCAM_25", "SCAM", "PRIZE ALERT: Neenga selected aagiteenga. 5 lakh panam claim panna link click pannunga: http://prize-claim.top Ungal OTP share pannunga."),

    # ─── 10 BORDERLINE ───────────────────────────────────────────────────
    ("WARN_01", "BORDERLINE", "Congratulations! You are pre-approved for an instant personal loan of Rs.2,00,000 at 9.9% APR. Apply now: https://bit.ly/fast-loan-app Limited period offer."),
    ("WARN_02", "BORDERLINE", "Earn Rs.25,000 per week working part-time from home. No interview required. Register before 6 PM: https://tinyurl.com/wfh-jobs-now"),
    ("WARN_03", "BORDERLINE", "You have been pre-approved for HDFC Bank Platinum Credit Card with Rs.3,00,000 limit and zero annual fee. Apply in 2 min: https://t.co/hdfc-plat-card"),
    ("WARN_04", "BORDERLINE", "LIC Policy Renewal Reminder: Your policy no. 123456789 expires in 7 days. Renew online: https://is.gd/lic-renew-2024 or call 1800-33-4433"),
    ("WARN_05", "BORDERLINE", "FLAT 80% OFF Today Only! Up to Rs.2,000 cashback on Electronics at BigBazaar.com. Shop Now: https://rb.gy/bigbazaar-sale"),
    ("WARN_06", "BORDERLINE", "AI Trading Bot delivers 15–22% monthly returns. Join 10,000+ investors! Free demo session. WhatsApp 09898989898 or visit: https://cryptobot-india.in"),
    ("WARN_07", "BORDERLINE", "Luxury 3BHK villas starting at Rs. 65 Lakhs near IT corridor. Zero pre-EMI till possession! Express interest: https://tinyurl.com/it-villas"),
    ("WARN_08", "BORDERLINE", "Get 95% accurate Nifty & BankNifty intraday calls daily! Join SEBI registered expert channel: https://t.co/nifty-tips-join"),
    ("WARN_09", "BORDERLINE", "Claim Rs. 1,500 joining bonus + 100% deposit match on India's top card gaming app: https://is.gd/play-rummy-bonus"),
    ("WARN_10", "BORDERLINE", "Master Full-Stack AI engineering in 12 weeks. 100% placement support. Reserve early bird seat: https://rb.gy/ai-bootcamp"),
]

import sys
import os

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

def run_benchmark():
    model_id = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
    print(f"Loading Hugging Face model: {model_id} ...")
    try:
        classifier = pipeline("text-classification", model=model_id)
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}")
        return

    print(f"\n{'ID':<12} {'EXPECTED':<12} {'HF_LABEL':<10} {'HF_SCORE':>8}  {'AGREE?'}")
    print("-" * 70)

    agree_count = 0
    fp_alerts = []   # HF says SPAM but expected LEGIT
    fn_alerts = []   # HF says HAM but expected SCAM

    for msg_id, category, body in TEST_SUITE:
        truncated = body[:512]  # BERT-Tiny max tokens
        try:
            result = classifier(truncated)[0]
            label = result["label"]      # "LABEL_0" (ham) or "LABEL_1" (spam)
            score = result["score"]
            hf_verdict = "SPAM" if label == "LABEL_1" else "HAM"
        except Exception as e:
            label = "ERROR"
            score = 0.0
            hf_verdict = "ERROR"

        # Agreement logic
        if category == "LEGIT":
            agree = hf_verdict == "HAM"
        elif category == "SCAM":
            agree = hf_verdict == "SPAM"
        else:  # BORDERLINE — both are acceptable
            agree = True

        symbol = "PASS" if agree else "FAIL"
        if agree:
            agree_count += 1
        elif category == "LEGIT" and hf_verdict == "SPAM":
            fp_alerts.append((msg_id, body[:60]))
        elif category == "SCAM" and hf_verdict == "HAM":
            fn_alerts.append((msg_id, body[:60]))

        print(f"{msg_id:<12} {category:<12} {hf_verdict:<10} {score:>8.3f}  {symbol}")

    total = len(TEST_SUITE)
    print(f"\n{'-'*70}")
    print(f"Agreement: {agree_count}/{total} ({100*agree_count//total}%)")
    if fp_alerts:
        print(f"\n[!] FALSE POSITIVES (LEGIT flagged as SPAM by HuggingFace model):")
        for mid, text in fp_alerts:
            print(f"   {mid}: {text}...")
    if fn_alerts:
        print(f"\n[!] FALSE NEGATIVES (SCAM missed as HAM by HuggingFace model):")
        for mid, text in fn_alerts:
            print(f"   {mid}: {text}...")
    if not fp_alerts and not fn_alerts:
        print("\n[OK] No unexpected misclassifications detected.")

    # Verdict on integration
    print("\n===============================================================")
    if agree_count >= 55 and len(fp_alerts) == 0:
        print("INTEGRATION VERDICT: Strong agreement and ZERO false positives. Proceed to Part 4.")
    else:
        print("INTEGRATION VERDICT: HuggingFace model shows misclassifications on domain edge cases.")
        print(f"False Positives: {len(fp_alerts)}, False Negatives: {len(fn_alerts)}")
        print("Recommendation: Do NOT integrate without retraining on Indian SMS/Tamil/Tanglish datasets.")

if __name__ == "__main__":
    run_benchmark()
