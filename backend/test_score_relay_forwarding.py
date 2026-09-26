import unittest
from types import SimpleNamespace

from main import (
    _has_forwarding_indicators,
    _request_has_full_email_payload,
    calculate_ps106_risk_score,
)


class RelayAndForwardingScoringTests(unittest.TestCase):
    def test_notification_snippet_is_not_treated_as_a_full_email(self):
        request = SimpleNamespace(
            body="",
            snippet="Short notification preview",
            authentication_results="",
            received_headers=[],
            urls=[],
        )

        self.assertFalse(_request_has_full_email_payload(request))

    def test_full_email_body_or_headers_use_direct_payload(self):
        body_request = SimpleNamespace(
            body="Full message body",
            authentication_results="",
            received_headers=[],
            urls=[],
        )
        headers_request = SimpleNamespace(
            body="",
            authentication_results="",
            received_headers=["Received: from relay"],
            urls=[],
        )

        self.assertTrue(_request_has_full_email_payload(body_request))
        self.assertTrue(_request_has_full_email_payload(headers_request))

    def test_geoip_anomaly_does_not_change_score_or_verdict(self):
        auth = {
            "spf": {"status": "PASS"},
            "dkim": {"status": "PASS"},
            "dmarc": {"status": "PASS"},
        }
        content = {"content_risk_score": 60, "primary_category": "PHISHING"}

        ordinary_relay = calculate_ps106_risk_score(
            auth, content, {"relay_analysis": {"anomaly_score": 0}}
        )
        anomalous_relay = calculate_ps106_risk_score(
            auth, content, {"relay_analysis": {"anomaly_score": 100}}
        )

        self.assertEqual(ordinary_relay["risk_score"], anomalous_relay["risk_score"])
        self.assertEqual(ordinary_relay["verdict"], anomalous_relay["verdict"])
        self.assertEqual(ordinary_relay["risk_score"], 36)

    def test_available_authentication_uses_sixty_forty_weighting(self):
        auth = {
            "spf": {"status": "FAIL"},
            "dkim": {"status": "UNKNOWN"},
            "dmarc": {"status": "UNKNOWN"},
        }
        content = {"content_risk_score": 50, "primary_category": "SUSPICIOUS"}

        result = calculate_ps106_risk_score(auth, content, {})

        self.assertEqual(result["score_breakdown"]["ml_content_models"]["score"], 50)
        self.assertEqual(result["score_breakdown"]["ml_content_models"]["weight"], 0.60)
        self.assertEqual(result["score_breakdown"]["gmail_api_auth"]["weight"], 0.40)
        self.assertEqual(result["risk_score"], int(50 * 0.60 + 53 * 0.40))

    def test_forwarded_phishing_content_cannot_be_diluted_below_its_score(self):
        auth_pass = {
            "spf": {"status": "PASS"},
            "dkim": {"status": "PASS"},
            "dmarc": {"status": "PASS"},
        }
        content = {
            "content_risk_score": 60,
            "primary_category": "PHISHING",
            "forwarding_analysis": {"is_forwarded": True},
        }

        result = calculate_ps106_risk_score(auth_pass, content, {})

        self.assertEqual(result["risk_score"], 60)
        self.assertEqual(result["verdict"], "SUSPICIOUS")

    def test_clean_forwarded_email_remains_safe(self):
        auth_pass = {
            "spf": {"status": "PASS"},
            "dkim": {"status": "PASS"},
            "dmarc": {"status": "PASS"},
        }
        content = {
            "content_risk_score": 0,
            "primary_category": "SAFE",
            "forwarding_analysis": {"is_forwarded": True},
        }

        result = calculate_ps106_risk_score(auth_pass, content, {})

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "SAFE")

    def test_subject_and_transport_headers_identify_forwarded_messages(self):
        self.assertTrue(
            _has_forwarding_indicators(
                {"subject": "Fwd: Account notice"},
                {"forwarding_analysis": {"is_forwarded": False}},
            )
        )
        self.assertTrue(
            _has_forwarding_indicators(
                {"raw_headers": {"resent-from": "origin@example.test"}},
                {"forwarding_analysis": {"is_forwarded": False}},
            )
        )
        self.assertTrue(
            _has_forwarding_indicators(
                {"raw_headers": {"X-Forwarded-For": "203.0.113.10"}},
                {"forwarding_analysis": {"is_forwarded": False}},
            )
        )
        self.assertFalse(
            _has_forwarding_indicators(
                {"subject": "Account notice", "raw_headers": {}},
                {"forwarding_analysis": {"is_forwarded": False}},
            )
        )


if __name__ == "__main__":
    unittest.main()
