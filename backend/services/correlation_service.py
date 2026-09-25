"""
MessageGuard — SIH26106 Cross-Case Correlation Service
=====================================================
Provides cross-case indicator correlation and attribution support across
persisted forensic cases in SQLite:
- Normalizes IOCs: sender email, sender domain, originating IP, URL domains, attachment SHA-256
- Detects recurring threat infrastructure across historical investigations
- Computes transparent confidence (HIGH/MEDIUM/LOW)
- Strictly provides attribution support ("Related infrastructure observed"), never "Attacker identified"
- Fully additive: queries existing cases.db without altering core detection logic
"""

import re
import os
import sqlite3
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ps106.correlation")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports_storage", "cases.db")


def _init_correlation_tables():
    """Create additive tables for IOC indexing and cross-case tracking."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Stores atomic indicators linked to cases
            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT,
                    indicator_type TEXT,
                    indicator_value TEXT,
                    normalized_value TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(case_id) REFERENCES forensic_cases(case_id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicator_norm ON case_indicators(normalized_value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicator_case ON case_indicators(case_id)")
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize correlation tables: {e}")

_init_correlation_tables()


class CorrelationService:
    """Additive cross-case indicator correlation engine."""

    @staticmethod
    def normalize_indicator(indicator_type: str, value: str) -> str:
        """Standardize indicator values for accurate cross-case matching."""
        if not value:
            return ""
        val = str(value).strip().lower()
        if indicator_type in ("sender_email", "reply_to"):
            return val
        if indicator_type in ("sender_domain", "url_domain"):
            if "@" in val:
                val = val.split("@")[-1]
            if val.startswith("http://") or val.startswith("https://"):
                try:
                    val = urlparse(val).hostname or val
                except Exception:
                    pass
            return val.strip().strip("/")
        if indicator_type == "origin_ip":
            return val.strip()
        if indicator_type == "attachment_hash":
            return val.strip().lower()
        return val

    def index_case_indicators(self, case_id: str, case_data: Dict[str, Any]) -> int:
        """Extract and index atomic indicators from a completed case analysis."""
        indicators_to_insert = []
        now = case_data.get("timestamp") or ""

        # 1. Sender email and domain
        sender = case_data.get("email_metadata", {}).get("sender") or case_data.get("sender") or ""
        if sender:
            norm_email = self.normalize_indicator("sender_email", sender)
            indicators_to_insert.append((case_id, "sender_email", sender, norm_email, now))
            if "@" in sender:
                domain = sender.split("@")[-1].strip(">").strip()
                norm_dom = self.normalize_indicator("sender_domain", domain)
                indicators_to_insert.append((case_id, "sender_domain", domain, norm_dom, now))

        # 2. Originating IP
        orig_ip = case_data.get("geoip_data", {}).get("relay_chain_data", {}).get("earliest_reliable_observed_ip") \
                  or case_data.get("earliest_reliable_observed_ip")
        if orig_ip and orig_ip != "ORIGIN_NOT_DETERMINABLE":
            norm_ip = self.normalize_indicator("origin_ip", orig_ip)
            indicators_to_insert.append((case_id, "origin_ip", orig_ip, norm_ip, now))

        # 3. URL domains
        url_analysis = case_data.get("content_analysis", {}).get("url_analysis", [])
        for u in url_analysis:
            domain = u.get("domain") or ""
            if domain:
                norm_u_dom = self.normalize_indicator("url_domain", domain)
                indicators_to_insert.append((case_id, "url_domain", domain, norm_u_dom, now))

        # 4. Attachment hashes
        attachments = case_data.get("content_analysis", {}).get("attachments", [])
        for att in attachments:
            sha256 = att.get("sha256") or ""
            if sha256:
                norm_hash = self.normalize_indicator("attachment_hash", sha256)
                indicators_to_insert.append((case_id, "attachment_hash", sha256, norm_hash, now))

        if not indicators_to_insert:
            return 0

        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.executemany("""
                    INSERT INTO case_indicators (case_id, indicator_type, indicator_value, normalized_value, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, indicators_to_insert)
                conn.commit()
            return len(indicators_to_insert)
        except Exception as e:
            logger.error(f"Failed to index indicators for case {case_id}: {e}")
            return 0

    def correlate_case(self, case_id: str, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Find related historical cases that share indicators with the target case.
        Returns attribution support summary and explainable relationships.
        """
        # First index current indicators
        self.index_case_indicators(case_id, case_data)

        relationships = []
        related_cases = set()

        # Query all indicators for this case
        current_indicators = []
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT indicator_type, normalized_value, indicator_value 
                    FROM case_indicators WHERE case_id = ?
                """, (case_id,))
                current_indicators = cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to query indicators for case {case_id}: {e}")
            return {
                "related_case_count": 0,
                "related_cases": [],
                "relationships": [],
                "attribution_assessment": "INDETERMINATE",
                "attribution_confidence": "LOW",
                "explanation": "No correlation history available.",
            }

        # For each indicator, find other cases sharing the same normalized indicator
        for ind_type, norm_val, raw_val in current_indicators:
            if not norm_val or norm_val in ("gmail.com", "google.com", "yahoo.com", "outlook.com", "microsoft.com"):
                # Skip ubiquitous freemail domains to prevent false-positive grouping
                continue

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT DISTINCT ci.case_id, COALESCE(fc.verdict, 'UNKNOWN'), COALESCE(fc.primary_category, 'SUSPICIOUS'), COALESCE(fc.sender, ''), COALESCE(fc.timestamp, ci.timestamp)
                        FROM case_indicators ci
                        LEFT JOIN forensic_cases fc ON ci.case_id = fc.case_id
                        WHERE ci.normalized_value = ? AND ci.case_id != ?
                        LIMIT 10
                    """, (norm_val, case_id))
                    matches = cursor.fetchall()

                    for target_case_id, verdict, cat, sender, t_stamp in matches:
                        related_cases.add(target_case_id)

                        # Determine confidence & type based on indicator
                        if ind_type == "attachment_hash":
                            conf = "HIGH"
                            rel_type = "SHARES_ATTACHMENT_HASH"
                            expl = f"Identical malicious attachment SHA-256 payload ({norm_val[:12]}...) identified in case {target_case_id}."
                        elif ind_type == "origin_ip":
                            conf = "HIGH"
                            rel_type = "SHARES_ORIGIN_IP"
                            expl = f"Same earliest reliable observed infrastructure IP ({raw_val}) used in case {target_case_id}."
                        elif ind_type == "sender_domain":
                            conf = "MEDIUM"
                            rel_type = "SHARES_SENDER_DOMAIN"
                            expl = f"Shared sending domain ({raw_val}) observed in case {target_case_id}."
                        elif ind_type == "url_domain":
                            conf = "MEDIUM"
                            rel_type = "SHARES_URL_INFRASTRUCTURE"
                            expl = f"Shared landing/phishing URL domain ({raw_val}) referenced in case {target_case_id}."
                        else:
                            conf = "LOW"
                            rel_type = "RELATED_INDICATOR"
                            expl = f"Shared {ind_type} indicator ({raw_val}) linked to case {target_case_id}."

                        relationships.append({
                            "target_case_id": target_case_id,
                            "relationship_type": rel_type,
                            "matched_indicator": raw_val,
                            "indicator_type": ind_type,
                            "confidence": conf,
                            "explanation": expl,
                            "verdict": verdict,
                        })
            except Exception as e:
                logger.error(f"Correlation query failed for {norm_val}: {e}")

        # Compute structured Attribution Assessment (strictly support, not identity)
        has_high = any(r["confidence"] == "HIGH" for r in relationships)
        has_med = any(r["confidence"] == "MEDIUM" for r in relationships)

        if has_high:
            assessment = "REPEATED_THREAT_INFRASTRUCTURE_CONFIRMED"
            confidence = "HIGH"
            attribution_summary = (
                f"Observed infrastructure or payload correlates directly with {len(related_cases)} "
                f"prior incident(s) via matching origin IP or attachment hash."
            )
        elif has_med:
            assessment = "RELATED_DOMAIN_CLUSTER_INDICATED"
            confidence = "MEDIUM"
            attribution_summary = (
                f"Related threat domain infrastructure linked to {len(related_cases)} prior investigation(s)."
            )
        elif relationships:
            assessment = "WEAK_BEHAVIORAL_CORRELATION"
            confidence = "LOW"
            attribution_summary = "Minor indicator overlap observed across historical cases."
        else:
            assessment = "ISOLATED_INCIDENT"
            confidence = "LOW"
            attribution_summary = "No prior indicator matches found in local forensic database."

        return {
            "related_case_count": len(related_cases),
            "related_cases": list(related_cases)[:10],
            "relationships": relationships[:15],
            "attribution_assessment": assessment,
            "attribution_confidence": confidence,
            "attribution_summary": attribution_summary,
        }
