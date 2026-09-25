"""
PS106 Threat Vision — Content Analyzer Service
================================================
Performs deep content analysis on email bodies:
- URL extraction and domain reputation classification
- Phishing NLP and urgency signal detection
- Spoofing heuristic checks (display name vs envelope)
- Suspicious TLD and link shortener detection
"""

import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ps106.content_analyzer")


# --------------------------------------------------------------------------- #
#  Known-bad / Known-suspicious domain lists (POC subset)
# --------------------------------------------------------------------------- #

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".buzz", ".loan", ".click",
    ".surf", ".gq", ".ml", ".cf", ".tk", ".ga", ".icu", ".cam",
    ".rest", ".monster", ".sbs", ".cfd",
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly",
    "short.url", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
}

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "microsoft.com",
    "outlook.com", "apple.com", "amazon.com", "facebook.com",
    "linkedin.com", "twitter.com", "github.com", "paypal.com",
    "netflix.com", "instagram.com", "whatsapp.com",
    "nptel.iitm.ac.in", "nptel.ac.in", "iitm.ac.in", "swayam.gov.in",
    "coursera.org", "edx.org", "udemy.com", "zoom.us", "google.co.in",
}

EDUCATIONAL_SENDER_KEYWORDS = {
    "onlinecourses", "nptel", "swayam", "coursera", "edx", "udemy", "canvas", "blackboard", "moodle"
}

URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "your account will be",
    "suspended", "verify your", "confirm your identity",
    "click here", "limited time", "expires today",
    "unauthorized access", "unusual activity",
    "update your payment", "confirm your payment",
    "you have been selected", "congratulations",
    "you've won", "claim your prize", "lottery",
    "inheritance", "million dollars",
]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm your password",
    "enter your pin", "share your otp", "social security",
    "bank account number", "credit card number",
    "cvv", "routing number", "verify your ssn",
]

SPOOFING_INDICATORS = [
    "noreply", "no-reply", "support@", "security@",
    "admin@", "helpdesk@", "alert@",
]

# Patterns for SENSITIVE_DATA_EXPOSURE detection
# Matches: email:password, password: value, API keys, OTP values, SSN-like strings
CREDENTIAL_EXPOSURE_PATTERNS = [
    # email + password combos
    (r'[\w.+-]+@[\w.-]+\.[a-z]{2,}\s*[:|]\s*\S{4,}', 'email:password credential pair'),
    # Explicit password labels
    (r'(?:password|passwd|pwd|pass)\s*[:=]\s*\S{4,}', 'plaintext password'),
    # API keys / tokens (generic)
    (r'(?:api[_-]?key|token|secret|access[_-]?key)\s*[:=]\s*[\w\-+/]{16,}', 'API key/token'),
    # OTP presented as static value in body
    (r'\bOTP\s*(?:is|:)\s*\d{4,8}\b', 'static OTP'),
    # Private keys
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'private key block'),
]


class ContentAnalyzer:
    """Analyzes email content for phishing, spoofing, and threat indicators."""

    @staticmethod
    def redact_pii(text: str) -> str:
        """Redact sensitive PII (emails, phone numbers, SSNs, credit cards) before logging or storage."""
        if not text:
            return ""
        # Redact email username (keeps 1st letter + domain)
        text = re.sub(
            r'\b([A-Za-z0-9._%+-]{1})[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b',
            r'\1***@\2',
            text
        )
        # Redact phone numbers
        text = re.sub(
            r'\b(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
            r'[REDACTED_PHONE]',
            text
        )
        # Redact Credit Cards / SSNs
        text = re.sub(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', r'[REDACTED_CARD]', text)
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', r'[REDACTED_SSN]', text)
        return text

    @staticmethod
    def extract_forwarding_metadata(body: str, subject: str) -> Dict[str, Any]:
        """
        Detect whether an email was forwarded and extract:
        - is_forwarded: bool
        - evidence_level: ORIGINAL HEADER EVIDENCE AVAILABLE | PARTIAL ORIGINAL EVIDENCE | FORWARDER-ONLY EVIDENCE | ORIGINAL SOURCE UNDETERMINABLE
        - original_sender: Optional[str]
        - original_date: Optional[str]
        - original_subject: Optional[str]
        - forwarder_commentary: str (wrapper text added by forwarder)
        - original_content: str (the quoted forwarded email text)
        """
        if not body:
            is_fwd_subject = bool(re.match(r"^(?:fwd?|fw):\s*", subject or "", re.IGNORECASE))
            return {
                "is_forwarded": is_fwd_subject,
                "evidence_level": "FORWARDER-ONLY EVIDENCE" if is_fwd_subject else "ORIGINAL SOURCE UNDETERMINABLE",
                "original_sender": None,
                "original_date": None,
                "original_subject": None,
                "forwarder_commentary": "",
                "original_content": "",
            }

        patterns = [
            # Standard Gmail / Outlook inline markers
            r"-+\s*Forwarded message\s*-+",
            r"-+\s*Original Message\s*-+",
            r"Begin forwarded message:?",
        ]

        marker_match = None
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                marker_match = m
                break

        is_fwd_subject = bool(re.match(r"^(?:fwd?|fw):\s*", subject or "", re.IGNORECASE))

        if not marker_match:
            # Check for From/Date/Subject header block directly
            alt_match = re.search(r"(?:^|\n)\s*From:\s*([^\n]+)\n\s*Date:\s*([^\n]+)", body, re.IGNORECASE)
            if alt_match and is_fwd_subject:
                forwarder_commentary = body[:alt_match.start()].strip()
                original_content = body[alt_match.start():].strip()
                orig_from_m = re.search(r"From:\s*([^\n]+)", original_content, re.IGNORECASE)
                orig_sender = orig_from_m.group(1).strip() if orig_from_m else None
                orig_date_m = re.search(r"Date:\s*([^\n]+)", original_content, re.IGNORECASE)
                orig_date = orig_date_m.group(1).strip() if orig_date_m else None
                orig_subj_m = re.search(r"Subject:\s*([^\n]+)", original_content, re.IGNORECASE)
                orig_subj = orig_subj_m.group(1).strip() if orig_subj_m else None

                evidence_level = "ORIGINAL HEADER EVIDENCE AVAILABLE" if (orig_sender and "@" in str(orig_sender)) else "PARTIAL ORIGINAL EVIDENCE"
                return {
                    "is_forwarded": True,
                    "evidence_level": evidence_level,
                    "original_sender": orig_sender,
                    "original_date": orig_date,
                    "original_subject": orig_subj,
                    "forwarder_commentary": forwarder_commentary,
                    "original_content": original_content,
                }

            if is_fwd_subject:
                return {
                    "is_forwarded": True,
                    "evidence_level": "FORWARDER-ONLY EVIDENCE",
                    "original_sender": None,
                    "original_date": None,
                    "original_subject": None,
                    "forwarder_commentary": body.strip(),
                    "original_content": body.strip(),
                }

            return {
                "is_forwarded": False,
                "evidence_level": "ORIGINAL SOURCE UNDETERMINABLE",
                "original_sender": None,
                "original_date": None,
                "original_subject": None,
                "forwarder_commentary": "",
                "original_content": body.strip(),
            }

        split_idx = marker_match.start()
        forwarder_commentary = body[:split_idx].strip()
        original_content = body[marker_match.end():].strip()

        orig_from_m = re.search(r"From:\s*([^\n]+)", original_content, re.IGNORECASE)
        orig_sender = orig_from_m.group(1).strip() if orig_from_m else None

        orig_date_m = re.search(r"Date:\s*([^\n]+)", original_content, re.IGNORECASE)
        orig_date = orig_date_m.group(1).strip() if orig_date_m else None

        orig_subj_m = re.search(r"Subject:\s*([^\n]+)", original_content, re.IGNORECASE)
        orig_subj = orig_subj_m.group(1).strip() if orig_subj_m else None

        if orig_sender and "@" in str(orig_sender):
            evidence_level = "ORIGINAL HEADER EVIDENCE AVAILABLE"
        elif orig_sender:
            evidence_level = "PARTIAL ORIGINAL EVIDENCE"
        else:
            evidence_level = "PARTIAL ORIGINAL EVIDENCE"

        return {
            "is_forwarded": True,
            "evidence_level": evidence_level,
            "original_sender": orig_sender,
            "original_date": orig_date,
            "original_subject": orig_subj,
            "forwarder_commentary": forwarder_commentary,
            "original_content": original_content,
        }

    def analyze(self, email_data: Dict[str, Any], domain_intel: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run full content analysis on parsed email data.

        Returns a dict with:
        - url_analysis: list of per-URL risk assessments
        - phishing_signals: detected urgency/credential-seeking phrases
        - spoofing_indicators: display name / envelope mismatches
        - content_risk_score: overall content risk (0-100)
        - risk_factors: human-readable list of risk factors
        - forwarding_analysis: deep forwarded-email forensics
        - categories: primaryCategory & secondaryCategories
        - domain_intel: domain WHOIS/DNS intelligence
        """
        text_body = email_data.get("text_body", "")
        html_body = email_data.get("html_body", "")
        sender = email_data.get("sender", "")
        reply_to = email_data.get("reply_to", "")
        subject = email_data.get("subject", "")
        urls = email_data.get("urls", [])

        # Step 0: Forwarded email extraction
        raw_body_text = text_body or html_body
        fwd_meta = self.extract_forwarding_metadata(raw_body_text, subject)

        # Content to analyze for attacker NLP: isolate original content if forwarded
        content_for_nlp = fwd_meta["original_content"] if fwd_meta["is_forwarded"] and fwd_meta["original_content"] else raw_body_text
        subject_for_nlp = fwd_meta["original_subject"] or subject

        body_lower = content_for_nlp.lower()
        subject_lower = (subject_for_nlp or "").lower()
        combined_text = f"{subject_lower} {body_lower}"

        risk_factors = []
        scores = []
        detected_categories = set()

        # 0. Domain Intelligence Risk (Newly Registered Domain Signal)
        sender_lower = (sender or "").lower()
        if domain_intel:
            sender_d_intel = domain_intel.get("sender_domain", {})
            domain_str = (sender_d_intel.get("domain") or "").lower().strip()
            age = sender_d_intel.get("age_days")

            is_domain_trusted = (
                domain_str in TRUSTED_DOMAINS
                or any(domain_str.endswith("." + td) for td in TRUSTED_DOMAINS)
                or domain_str.endswith((".ac.in", ".edu", ".edu.in", ".gov", ".gov.in"))
                or any(kw in domain_str for kw in EDUCATIONAL_SENDER_KEYWORDS)
                or any(kw in sender_lower for kw in EDUCATIONAL_SENDER_KEYWORDS)
            )

            if not is_domain_trusted:
                if sender_d_intel.get("is_young_domain"):
                    scores.append(85)
                    risk_factors.append(f"Newly registered domain: '{domain_str}' created {age} days ago (<30 days — high risk indicator)")
                    detected_categories.add("SUSPICIOUS")
                elif age is not None and age < 90:
                    scores.append(40)
                    risk_factors.append(f"Recent domain registration: '{domain_str}' created {age} days ago")

                if not sender_d_intel.get("has_mx", True) and sender_d_intel.get("status") == "RESOLVED":
                    # Only flag if this is a real email domain (contains a dot — not an app name or device label)
                    if domain_str and "." in domain_str and len(domain_str) > 4:
                        scores.append(60)
                        risk_factors.append(f"Domain '{domain_str}' lacks valid DNS MX mail exchange records")

        # 1. URL Analysis
        url_results = self._analyze_urls(urls)
        url_risk = max((u["risk_score"] for u in url_results), default=0)
        if url_risk > 0:
            scores.append(url_risk)
        if any(u["is_shortener"] for u in url_results):
            risk_factors.append("Contains link shortener(s) hiding final destination")
        if any(u["suspicious_tld"] for u in url_results):
            risk_factors.append("Links use suspicious top-level domain(s)")
        if any(u["ip_based"] for u in url_results):
            risk_factors.append("Link(s) use raw IP address instead of domain name")

        # 2. Phishing NLP — Urgency signals
        urgency_hits = [
            phrase for phrase in URGENCY_PHRASES
            if phrase in combined_text
        ]
        if urgency_hits:
            urgency_score = min(30 + len(urgency_hits) * 12, 90)
            scores.append(urgency_score)
            risk_factors.append(
                f"Urgency/social-engineering language: {', '.join(urgency_hits[:3])}"
            )

        # 3. Credential harvesting signals
        credential_hits = [
            phrase for phrase in CREDENTIAL_PHRASES
            if phrase in combined_text
        ]
        if credential_hits:
            scores.append(85)
            risk_factors.append(
                f"Credential harvesting language: {', '.join(credential_hits[:3])}"
            )

        # 4. Spoofing heuristics & Header Mismatch
        return_path = email_data.get("return_path", "")
        spoofing_results = self._check_spoofing(sender, reply_to, subject, return_path)
        if spoofing_results["is_suspicious"]:
            scores.append(spoofing_results["score"])
            risk_factors.extend(spoofing_results["factors"])

        # 5. Attachment minimum viable scan (MIME check + SHA-256 hash + password protection)
        attachments = email_data.get("attachments", [])
        dangerous_extensions = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".iso"}
        known_bad_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "44d88612fea8a8f36de82e1278abb02f", # MD5/SHA sample
        }
        for att in attachments:
            filename = att.get("filename", "").lower()
            mime_type = att.get("mime_type", "").lower()
            sha256_hash = att.get("sha256", "").lower()
            is_encrypted = att.get("is_encrypted", False) or att.get("password_protected", False)

            # Password protected check
            if is_encrypted:
                scores.append(75)
                risk_factors.append(f"Password-protected attachment detected: '{att.get('filename')}' (elevated risk — uninspectable)")

            # Known bad hash lookup
            if sha256_hash in known_bad_hashes:
                scores.append(100)
                risk_factors.append(f"Malicious attachment detected by SHA-256 threat DB: {sha256_hash[:12]}...")

            # MIME mismatch check (e.g. extension says .pdf but mime is application/x-executable)
            if filename.endswith(".pdf") and mime_type and "pdf" not in mime_type and "octet-stream" not in mime_type:
                scores.append(85)
                risk_factors.append(f"MIME-type mismatch: '{filename}' claims to be PDF but MIME is '{mime_type}'")

            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    scores.append(90)
                    risk_factors.append(f"Dangerous attachment extension: {att['filename']}")
                    break

        # 6. Hidden / mismatched link text in HTML
        if html_body:
            mismatch_count = self._check_link_text_mismatch(html_body)
            if mismatch_count > 0:
                scores.append(min(40 + mismatch_count * 15, 80))
                risk_factors.append(
                    f"{mismatch_count} link(s) with mismatched display text vs. actual URL"
                )

        # 7. SENSITIVE_DATA_EXPOSURE detection (HIGH severity — independent of sender trust)
        exposure_findings = []
        full_content_for_exposure = f"{subject_for_nlp} {content_for_nlp}"
        for pattern, label in CREDENTIAL_EXPOSURE_PATTERNS:
            matches = re.findall(pattern, full_content_for_exposure, re.IGNORECASE)
            for match in matches:
                # Mask the credential for storage/reporting
                masked = re.sub(r'([:=]\s*)(\S{2})(\S+)', r'\1\2***', match)
                exposure_findings.append({"type": label, "masked_sample": masked})
        if exposure_findings:
            scores.append(95)  # HIGH severity — cannot be overridden by sender trust
            detected_categories.add("SENSITIVE_DATA_EXPOSURE")
            risk_factors.append(
                f"SENSITIVE DATA EXPOSED: {', '.join(set(f['type'] for f in exposure_findings))} — credentials MASKED in report"
            )

        # Classify categories per SIH forensic requirement:
        # SAFE · SPAM · PHISHING · SPOOFED · IMPERSONATION · MALWARE · BEC · FRAUD · SUSPICIOUS
        if any(att.get("filename", "").lower().endswith(ext) for att in attachments for ext in dangerous_extensions) or any(att.get("sha256") in known_bad_hashes for att in attachments):
            detected_categories.add("MALWARE")
        if credential_hits or any(u.get("risk_score", 0) >= 50 for u in url_results):
            detected_categories.add("PHISHING")
        if spoofing_results.get("header_mismatch") or any("typosquat" in f.lower() for f in spoofing_results.get("factors", [])):
            detected_categories.add("SPOOFED")
        if any("display name mentions" in f.lower() or "impersonating" in f.lower() for f in spoofing_results.get("factors", [])):
            detected_categories.add("IMPERSONATION")
        if any(phrase in combined_text for phrase in ["million dollars", "inheritance", "lottery", "prize", "wire transfer", "payment required"]):
            detected_categories.add("FRAUD")
        if any(phrase in combined_text for phrase in ["urgent wire", "vendor payment", "update banking details", "executive request"]):
            detected_categories.add("BEC")
        if not detected_categories and urgency_hits:
            detected_categories.add("SPAM")

        content_risk = max(scores) if scores else 0

        # Determine Primary Category (priority order: highest threat first)
        if "SENSITIVE_DATA_EXPOSURE" in detected_categories:
            primary_cat = "SENSITIVE_DATA_EXPOSURE"
        elif "MALWARE" in detected_categories:
            primary_cat = "MALWARE"
        elif "PHISHING" in detected_categories:
            primary_cat = "PHISHING"
        elif "BEC" in detected_categories:
            primary_cat = "BEC"
        elif "FRAUD" in detected_categories:
            primary_cat = "FRAUD"
        elif "IMPERSONATION" in detected_categories:
            primary_cat = "IMPERSONATION"
        elif "SPOOFED" in detected_categories:
            primary_cat = "SPOOFED"
        elif "SPAM" in detected_categories:
            primary_cat = "SPAM"
        elif content_risk >= 30:
            primary_cat = "SUSPICIOUS"
        else:
            primary_cat = "SAFE"

        sec_cats = sorted(list(detected_categories - {primary_cat}))

        forwarding_analysis = {
            "is_forwarded": fwd_meta["is_forwarded"],
            "evidence_level": fwd_meta["evidence_level"],
            "forwarded_by": sender if fwd_meta["is_forwarded"] else None,
            "original_sender": fwd_meta["original_sender"],
            "original_date": fwd_meta["original_date"],
            "original_subject": fwd_meta["original_subject"],
            "forwarder_commentary": fwd_meta["forwarder_commentary"],
            "explanation": (
                f"Content originated from earlier message ({fwd_meta['evidence_level']}). "
                f"Original sender: {fwd_meta['original_sender'] or 'UNKNOWN'}. "
                f"Current sender ({sender}) is the forwarding party."
            ) if fwd_meta["is_forwarded"] else "Message originated directly from sender."
        }

        content_risk = max(scores) if scores else 0
        header_mismatch = spoofing_results.get("header_mismatch", False)
        origin_confidence = 85 if not header_mismatch else 30

        return {
            "url_analysis": url_results,
            "phishing_signals": urgency_hits,
            "credential_signals": credential_hits,
            "spoofing_indicators": spoofing_results,
            "header_mismatch": header_mismatch,
            "origin_confidence": origin_confidence,
            "content_risk_score": content_risk,
            "risk_factors": risk_factors if risk_factors else ["No content risk factors detected"],
            "primary_category": primary_cat,
            "secondary_categories": sec_cats,
            "forwarding_analysis": forwarding_analysis,
            "sensitive_data_exposure": exposure_findings,
        }

    def _analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze each URL for reputation and suspiciousness."""
        results = []
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.hostname or ""
                domain_lower = domain.lower()

                is_shortener = domain_lower in KNOWN_SHORTENERS
                is_trusted = any(
                    domain_lower == td or domain_lower.endswith(f".{td}")
                    for td in TRUSTED_DOMAINS
                ) or domain_lower.endswith((".ac.in", ".edu", ".edu.in", ".gov", ".gov.in"))
                suspicious_tld = any(
                    domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS
                )
                ip_based = bool(
                    re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)
                )

                # Risk scoring per URL
                risk = 0
                if ip_based:
                    risk = 70
                elif suspicious_tld:
                    risk = 60
                elif is_shortener:
                    risk = 45
                elif not is_trusted:
                    risk = 20  # Unknown domain, mild risk

                results.append({
                    "url": url,
                    "domain": domain_lower,
                    "is_shortener": is_shortener,
                    "is_trusted": is_trusted,
                    "suspicious_tld": suspicious_tld,
                    "ip_based": ip_based,
                    "risk_score": risk,
                })
            except Exception as e:
                logger.warning(f"Failed to parse URL '{url}': {e}")
                results.append({
                    "url": url,
                    "domain": "",
                    "is_shortener": False,
                    "is_trusted": False,
                    "suspicious_tld": False,
                    "ip_based": False,
                    "risk_score": 30,
                })
        return results

    def _check_spoofing(
        self, sender: str, reply_to: str, subject: str, return_path: str = ""
    ) -> Dict[str, Any]:
        """Check for sender spoofing indicators and header domain mismatches."""
        factors = []
        score = 0
        header_mismatch = False

        sender_lower = sender.lower()
        from_email_match = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", sender_lower)
        from_domain = from_email_match.group().split("@")[-1] if from_email_match else ""

        # Check display name vs email mismatch
        display_match = re.match(r'^"?(.+?)"?\s*<(.+?)>', sender)
        if display_match:
            display_name = display_match.group(1).lower()
            email_addr = display_match.group(2).lower()
            email_domain = email_addr.split("@")[-1] if "@" in email_addr else ""

            for trusted in TRUSTED_DOMAINS:
                brand = trusted.split(".")[0]
                if brand in display_name and brand not in email_domain:
                    score = max(score, 75)
                    factors.append(
                        f"Display name mentions '{brand}' but email domain is '{email_domain}'"
                    )
                # Freemail impersonating brand: e.g. paypal.security@gmail.com
                if email_domain in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com"):
                    local_part = email_addr.split("@")[0]
                    if brand in local_part:
                        score = max(score, 80)
                        factors.append(
                            f"Free-mail service '{email_domain}' impersonating corporate brand '{brand}' in username ('{local_part}')"
                        )

        # Check for homoglyph / lookalike typosquat domains (e.g., paypa1.com, netf1ix.com, goog1e.com)
        if from_domain:
            for trusted in TRUSTED_DOMAINS:
                brand = trusted.split(".")[0]
                # Lookalike substitutions: 1 for l, 0 for o, rn for m, vv for w
                normalized_from = (
                    from_domain.replace("1", "l")
                    .replace("0", "o")
                    .replace("rn", "m")
                    .replace("vv", "w")
                )
                if brand in normalized_from and brand not in from_domain:
                    score = max(score, 85)
                    factors.append(
                        f"Lookalike / typosquat domain detected: '{from_domain}' mimics legitimate brand '{brand}'"
                    )

        # Reply-To doesn't match From
        reply_domain = ""
        if reply_to:
            reply_email = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", reply_to.lower())
            if reply_email:
                reply_domain = reply_email.group().split("@")[-1]
                if from_domain and reply_domain and from_domain != reply_domain:
                    score = max(score, 65)
                    header_mismatch = True
                    factors.append(
                        f"Header mismatch: Reply-To domain ({reply_domain}) differs from sender domain ({from_domain})"
                    )

        # Return-Path doesn't match From / Reply-To
        return_domain = ""
        if return_path:
            return_email = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", return_path.lower())
            if return_email:
                return_domain = return_email.group().split("@")[-1]
                if from_domain and return_domain and from_domain != return_domain:
                    score = max(score, 65)
                    header_mismatch = True
                    factors.append(
                        f"Header mismatch: Return-Path domain ({return_domain}) differs from sender domain ({from_domain})"
                    )

        return {
            "is_suspicious": score > 0,
            "score": score,
            "header_mismatch": header_mismatch,
            "factors": factors,
        }

    @staticmethod
    def _check_link_text_mismatch(html: str) -> int:
        """Count links where displayed text looks like a URL but differs from href."""
        pattern = re.compile(
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        mismatch_count = 0
        for href, text in pattern.findall(html):
            text_clean = re.sub(r"<[^>]+>", "", text).strip()
            # If displayed text looks like a URL...
            if re.match(r"https?://", text_clean, re.IGNORECASE):
                href_domain = urlparse(href).hostname or ""
                text_domain = urlparse(text_clean).hostname or ""
                if href_domain and text_domain and href_domain != text_domain:
                    mismatch_count += 1
        return mismatch_count
