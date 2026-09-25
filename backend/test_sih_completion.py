"""
Automated Verification Suite for SIH26106 Additive Completion:
- Cross-Case Correlation (IP, Domain, URL, Hash matching)
- Automated Campaign Grouping (CAMPAIGN-xxxx clustering)
- Searchable Case Management & Filtering (/api/cases)
- Graph-Based Relationship Analysis (/api/cases/{case_id}/graph)
- Privacy Masking & Configurable Retention Purge
"""

import os
import sys
import unittest
import tempfile
import sqlite3

# Set backend path
backend_dir = os.path.dirname(__file__)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.correlation_service import CorrelationService, DB_PATH
from services.campaign_service import CampaignService
from services.graph_service import InvestigationGraphService
from services.report_service import ReportService


class TestSIHCompletion(unittest.TestCase):

    def setUp(self):
        self.corr_svc = CorrelationService()
        self.camp_svc = CampaignService()
        self.graph_svc = InvestigationGraphService()
        self.rep_svc = ReportService()

    def test_01_cross_case_correlation(self):
        """Verify that two cases sharing origin IP and URL domain correlate deterministically."""
        case_a_id = "CASE-TEST-AAA1"
        case_a_data = {
            "timestamp": "2026-09-24T20:00:00Z",
            "email_metadata": {"sender": "phisher@bad-domain.xyz", "subject": "Urgent Invoice"},
            "verdict": "MALICIOUS",
            "risk_score": 90,
            "earliest_reliable_observed_ip": "198.51.100.45",
            "content_analysis": {
                "url_analysis": [{"url": "http://credential-theft.com/login", "domain": "credential-theft.com"}],
                "attachments": [{"filename": "invoice.exe", "sha256": "abcdef1234567890abcdef1234567890abcdef12"}]
            }
        }
        # Index Case A
        self.corr_svc.index_case_indicators(case_a_id, case_a_data)

        # Now test Case B which shares the origin IP and the landing domain
        case_b_id = "CASE-TEST-BBB2"
        case_b_data = {
            "timestamp": "2026-09-24T20:05:00Z",
            "email_metadata": {"sender": "spoof@another-actor.com", "subject": "Account Alert"},
            "verdict": "SUSPICIOUS",
            "risk_score": 75,
            "earliest_reliable_observed_ip": "198.51.100.45",
            "content_analysis": {
                "url_analysis": [{"url": "http://credential-theft.com/verify", "domain": "credential-theft.com"}],
                "attachments": []
            }
        }

        corr_res = self.corr_svc.correlate_case(case_b_id, case_b_data)
        self.assertGreaterEqual(corr_res["related_case_count"], 1)
        self.assertIn(case_a_id, corr_res["related_cases"])
        self.assertEqual(corr_res["attribution_confidence"], "HIGH")
        self.assertEqual(corr_res["attribution_assessment"], "REPEATED_THREAT_INFRASTRUCTURE_CONFIRMED")
        print(f"[PASS] Cross-case correlation passed: {corr_res['attribution_summary']}")

    def test_02_campaign_grouping(self):
        """Verify that related cases form or join an automated campaign cluster."""
        case_c_id = "CASE-TEST-CCC3"
        corr_mock = {
            "related_cases": ["CASE-TEST-AAA1", "CASE-TEST-BBB2"],
            "relationships": [
                {"matched_indicator": "credential-theft.com", "relationship_type": "SHARES_URL_INFRASTRUCTURE"}
            ],
            "attribution_confidence": "HIGH"
        }
        camp = self.camp_svc.evaluate_and_assign_campaign(case_c_id, corr_mock, {})
        self.assertIsNotNone(camp)
        self.assertTrue(camp["campaign_id"].startswith("CMP-"))
        self.assertGreaterEqual(camp["member_case_count"], 2)
        print(f"[PASS] Campaign grouping passed: {camp['campaign_id']} with {camp['member_case_count']} members")

    def test_03_graph_generation(self):
        """Verify that case evidence generates an explainable node-edge graph."""
        case_id = "CASE-TEST-GRAPH1"
        case_data = {
            "verdict": "MALICIOUS",
            "risk_score": 88,
            "email_metadata": {"sender": "ceo-fraud@spoofed-target.com"},
            "earliest_reliable_observed_ip": "203.0.113.10",
            "content_analysis": {
                "url_analysis": [{"domain": "fake-login-bank.xyz"}],
                "attachments": [{"filename": "payload.vbs", "sha256": "1234567890abcdef"}]
            }
        }
        graph = self.graph_svc.build_case_graph(case_id, case_data)
        self.assertGreater(graph["node_count"], 3)
        self.assertGreater(graph["edge_count"], 2)

        # Check for privacy masking on SENDER node
        sender_nodes = [n for n in graph["nodes"] if n["type"] == "SENDER"]
        self.assertTrue(len(sender_nodes) > 0)
        self.assertTrue("***@" in sender_nodes[0]["masked_label"])
        print(f"[PASS] Graph generation passed: {graph['node_count']} nodes, {graph['edge_count']} edges")

    def test_04_search_cases_and_privacy_masking(self):
        """Verify case filtering and privacy masking on sender addresses."""
        results = self.rep_svc.search_cases(limit=10)
        self.assertIsInstance(results, list)
        for r in results:
            if "@" in r["sender"]:
                self.assertIn("***@", r["sender"])
        print(f"[PASS] Searchable cases passed: {len(results)} cases returned with masked PII")

    def test_05_retention_controls(self):
        """Verify retention purge evaluates gracefully without crashing."""
        purge_res = self.rep_svc.purge_expired_cases(retention_days=365)
        self.assertEqual(purge_res["status"], "SUCCESS")
        self.assertEqual(purge_res["retention_days"], 365)
        print(f"[PASS] Retention policy purge passed: {purge_res['purged_count']} expired cases pruned")


if __name__ == "__main__":
    unittest.main()
