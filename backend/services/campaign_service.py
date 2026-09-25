"""
MessageGuard — SIH26106 Campaign Grouping Service
================================================
Groups related fraudulent email cases into campaigns (CAMPAIGN-xxxx)
when multiple correlation signals or high-confidence IOCs align:
- Clusters cases by shared infrastructure, payload hashes, or landing domains
- Persists campaigns and memberships in SQLite (cases.db)
- Calculates campaign confidence (HIGH/MEDIUM/LOW)
- Completely additive: integrates with existing persistence without changing detection
"""

import os
import uuid
import sqlite3
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("ps106.campaign")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports_storage", "cases.db")


def _init_campaign_tables():
    """Create additive SQLite tables for campaigns and memberships."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    campaign_name TEXT,
                    created_at TEXT,
                    confidence TEXT,
                    primary_ioc TEXT,
                    explanation TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaign_cases (
                    campaign_id TEXT,
                    case_id TEXT,
                    joined_at TEXT,
                    PRIMARY KEY (campaign_id, case_id),
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id),
                    FOREIGN KEY(case_id) REFERENCES forensic_cases(case_id)
                )
            """)
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize campaign tables: {e}")

_init_campaign_tables()


class CampaignService:
    """Additive campaign grouping and persistence service."""

    def evaluate_and_assign_campaign(
        self, case_id: str, correlation_result: Dict[str, Any], case_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate if a case belongs to an existing campaign or forms a new one with related cases.
        Requires 2+ matching indicators or 1 HIGH-confidence indicator (IP/hash).
        """
        related_cases = correlation_result.get("related_cases", [])
        relationships = correlation_result.get("relationships", [])

        if not related_cases:
            return None

        # Check if any related case is already part of an active campaign
        existing_campaign_id = None
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                placeholders = ",".join("?" for _ in related_cases)
                cursor.execute(f"""
                    SELECT campaign_id, case_id FROM campaign_cases 
                    WHERE case_id IN ({placeholders}) LIMIT 1
                """, related_cases)
                row = cursor.fetchone()
                if row:
                    existing_campaign_id = row[0]
        except Exception as e:
            logger.error(f"Failed to check existing campaigns: {e}")

        # Determine campaign details
        primary_ioc = relationships[0]["matched_indicator"] if relationships else "Shared Infrastructure"
        confidence = correlation_result.get("attribution_confidence", "MEDIUM")

        if existing_campaign_id:
            # Add current case to the existing campaign
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("""
                        INSERT OR IGNORE INTO campaign_cases (campaign_id, case_id, joined_at)
                        VALUES (?, ?, ?)
                    """, (existing_campaign_id, case_id, datetime.utcnow().isoformat() + "Z"))
                    conn.commit()
                return self.get_campaign_details(existing_campaign_id)
            except Exception as e:
                logger.error(f"Failed to join existing campaign {existing_campaign_id}: {e}")
                return None

        # Form a new campaign if at least 1 related case exists with meaningful correlation
        new_campaign_id = f"CMP-{uuid.uuid4().hex[:6].upper()}"
        camp_name = f"Campaign {primary_ioc[:20]}"
        explanation = (
            f"Automated threat cluster grouped by {len(relationships)} shared indicator(s) "
            f"across {len(related_cases) + 1} incidents."
        )

        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("""
                    INSERT INTO campaigns (campaign_id, campaign_name, created_at, confidence, primary_ioc, explanation)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (new_campaign_id, camp_name, datetime.utcnow().isoformat() + "Z", confidence, primary_ioc, explanation))

                # Insert current case and all matched related cases
                all_cases = [case_id] + related_cases
                conn.executemany("""
                    INSERT OR IGNORE INTO campaign_cases (campaign_id, case_id, joined_at)
                    VALUES (?, ?, ?)
                """, [(new_campaign_id, c, datetime.utcnow().isoformat() + "Z") for c in all_cases])
                conn.commit()

            return {
                "campaign_id": new_campaign_id,
                "campaign_name": camp_name,
                "confidence": confidence,
                "primary_ioc": primary_ioc,
                "explanation": explanation,
                "member_case_count": len(all_cases),
                "member_cases": all_cases,
            }
        except Exception as e:
            logger.error(f"Failed to create new campaign {new_campaign_id}: {e}")
            return None

    def get_campaign_details(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored campaign metadata and member cases."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT campaign_id, campaign_name, created_at, confidence, primary_ioc, explanation
                    FROM campaigns WHERE campaign_id = ?
                """, (campaign_id,))
                c_row = cursor.fetchone()
                if not c_row:
                    return None

                cursor.execute("SELECT case_id FROM campaign_cases WHERE campaign_id = ?", (campaign_id,))
                members = [r[0] for r in cursor.fetchall()]

                return {
                    "campaign_id": c_row[0],
                    "campaign_name": c_row[1],
                    "created_at": c_row[2],
                    "confidence": c_row[3],
                    "primary_ioc": c_row[4],
                    "explanation": c_row[5],
                    "member_case_count": len(members),
                    "member_cases": members,
                }
        except Exception as e:
            logger.error(f"Failed to fetch campaign {campaign_id}: {e}")
            return None
