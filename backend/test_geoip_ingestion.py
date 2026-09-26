import unittest
from unittest.mock import patch

import services.threat_intel_service as threat_intel_module
from services.email_providers import EmailEcosystemManager
from services.threat_intel_service import ThreatIntelService


class GeoIPIngestionTests(unittest.TestCase):
    def setUp(self):
        ThreatIntelService._geoip_cache.clear()
        self.ecosystems = EmailEcosystemManager()
        self.threat_intel = ThreatIntelService()

    def _raw_email(self, ip):
        return (
            "From: sender@example.test\r\n"
            "To: recipient@example.test\r\n"
            "Subject: Geolocation ingestion test\r\n"
            f"Received: from relay.example ([{ip}]) by mx.example.test\r\n"
            "\r\n"
            "Test message\r\n"
        ).encode()

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    def test_all_five_ingestion_adapters_preserve_and_resolve_each_relay_ip(self):
        adapter_inputs = [
            (
                "RFC822_EML",
                "8.8.8.8",
                lambda raw: self.ecosystems.rfc822_eml.ingest_eml_bytes(raw),
                self._raw_email("8.8.8.8"),
            ),
            (
                "MICROSOFT_GRAPH",
                "1.1.1.1",
                lambda _: self.ecosystems.outlook.ingest_graph_json(
                    {
                        "from": {"emailAddress": {"address": "sender@example.test"}},
                        "subject": "Geolocation ingestion test",
                        "body": {"contentType": "Text", "content": "Test message"},
                        "internetMessageHeaders": [
                            {
                                "name": "Received",
                                "value": "from relay.example ([1.1.1.1]) by mx.example.test",
                            }
                        ],
                    }
                ),
                b"",
            ),
            (
                "YAHOO_IMAP",
                "9.9.9.9",
                lambda raw: self.ecosystems.yahoo.ingest_yahoo_raw(raw),
                self._raw_email("9.9.9.9"),
            ),
            (
                "GENERIC_IMAP",
                "208.67.222.222",
                lambda raw: self.ecosystems.generic_imap.ingest_imap_message(raw),
                self._raw_email("208.67.222.222"),
            ),
            (
                "GMAIL",
                "2001:4860:4860::8888",
                lambda raw: self.ecosystems.gmail.ingest_gmail_mime(raw),
                self._raw_email("2001:4860:4860::8888"),
            ),
        ]
        provider_locations = {
            "8.8.8.8": "Mountain View",
            "1.1.1.1": "Sydney",
            "9.9.9.9": "New York",
            "208.67.222.222": "San Francisco",
            "2001:4860:4860::8888": "Mountain View",
        }

        with patch.object(
            self.threat_intel,
            "_try_ipinfo",
            side_effect=lambda ip: {
                "ip": ip,
                "city": provider_locations[ip],
                "source": "ipinfo.io",
            },
        ):
            for provider_name, expected_ip, ingest, raw in adapter_inputs:
                with self.subTest(provider=provider_name):
                    record = ingest(raw)
                    trigger_payload = self.ecosystems.normalize_and_convert_to_trigger(record)
                    relay_chain = self.threat_intel.build_relay_chain(
                        trigger_payload["received_headers"]
                    )
                    selected_ip = relay_chain["earliest_reliable_observed_ip"]
                    location = self.threat_intel.resolve_geoip(selected_ip)

                    self.assertEqual(selected_ip, expected_ip)
                    self.assertEqual(location["ip"], expected_ip)
                    self.assertEqual(location["city"], provider_locations[expected_ip])


if __name__ == "__main__":
    unittest.main()
