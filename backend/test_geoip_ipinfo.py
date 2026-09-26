import unittest
from unittest.mock import Mock, patch

import services.threat_intel_service as threat_intel_module
from services.threat_intel_service import ThreatIntelService


class IpinfoGeoIPTests(unittest.TestCase):
    def setUp(self):
        ThreatIntelService._geoip_cache.clear()
        self.service = ThreatIntelService()

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    @patch("services.threat_intel_service.requests.get")
    def test_ipinfo_location_is_normalized(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "timezone": "America/Los_Angeles",
            "org": "AS15169 Google LLC",
        }
        mock_get.return_value = response

        result = self.service._try_ipinfo("8.8.8.8")

        self.assertEqual(result["city"], "Mountain View")
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["lat"], 37.4056)
        self.assertEqual(result["lon"], -122.0775)
        self.assertEqual(result["as_number"], "AS15169")
        self.assertEqual(result["source"], "ipinfo.io")
        self.assertIn("Approximate infrastructure geolocation", result["disclaimer"])
        mock_get.assert_called_once_with(
            "https://ipinfo.io/8.8.8.8/json",
            params={"token": "test-token"},
            timeout=5,
        )
        response.raise_for_status.assert_called_once_with()

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    @patch("services.threat_intel_service.requests.get")
    def test_invalid_ipinfo_location_falls_back(self, mock_get):
        response = Mock()
        response.json.return_value = {"bogon": True}
        mock_get.return_value = response

        self.assertIsNone(self.service._try_ipinfo("8.8.8.8"))

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "")
    @patch("services.threat_intel_service.requests.get")
    def test_ipinfo_is_skipped_without_token(self, mock_get):
        self.assertIsNone(self.service._try_ipinfo("8.8.8.8"))
        mock_get.assert_not_called()

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    def test_configured_ipinfo_is_tried_before_free_providers(self):
        ipinfo_result = {"ip": "8.8.8.8", "source": "ipinfo.io"}
        with patch.object(self.service, "_try_ipinfo", return_value=ipinfo_result) as ipinfo:
            with patch.object(self.service, "_try_ip_api") as ip_api:
                result = self.service.resolve_geoip("8.8.8.8")

        self.assertIs(result, ipinfo_result)
        ipinfo.assert_called_once_with("8.8.8.8")
        ip_api.assert_not_called()

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    def test_private_ip_is_not_sent_to_geolocation_provider(self):
        with patch.object(self.service, "_try_ipinfo") as ipinfo:
            result = self.service.resolve_geoip("192.168.1.50")

        self.assertEqual(result["ip_classification"], "PRIVATE")
        self.assertIn("error", result)
        ipinfo.assert_not_called()

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    def test_failed_ipinfo_lookup_falls_back_to_free_provider(self):
        fallback_result = {"ip": "8.8.8.8", "source": "ip-api.com"}
        with patch.object(self.service, "_try_ipinfo", return_value=None):
            with patch.object(self.service, "_try_ip_api", return_value=fallback_result) as ip_api:
                result = self.service.resolve_geoip("8.8.8.8")

        self.assertIs(result, fallback_result)
        ip_api.assert_called_once_with("8.8.8.8")

    @patch.object(threat_intel_module, "IPINFO_TOKEN", "test-token")
    def test_distinct_public_ips_keep_distinct_geolocation_results(self):
        provider_results = {
            "8.8.8.8": {"ip": "8.8.8.8", "city": "Mountain View", "lat": 37.4056, "lon": -122.0775, "source": "ipinfo.io"},
            "1.1.1.1": {"ip": "1.1.1.1", "city": "Sydney", "lat": -33.494, "lon": 143.2104, "source": "ipinfo.io"},
        }
        with patch.object(
            self.service,
            "_try_ipinfo",
            side_effect=lambda ip: provider_results[ip],
        ):
            results = []
            for ip in ("8.8.8.8", "1.1.1.1", "8.8.8.8"):
                headers = [f"Received: from relay.example ([{ip}]) by mx.example.net"]
                relay_chain = self.service.build_relay_chain(headers)
                selected_ip = relay_chain["earliest_reliable_observed_ip"]
                results.append(self.service.resolve_geoip(selected_ip))

        self.assertEqual(
            [(item["ip"], item["city"]) for item in results],
            [
                ("8.8.8.8", "Mountain View"),
                ("1.1.1.1", "Sydney"),
                ("8.8.8.8", "Mountain View"),
            ],
        )
        self.assertNotEqual(
            (results[0]["lat"], results[0]["lon"]),
            (results[1]["lat"], results[1]["lon"]),
        )

    def test_compressed_ipv6_relay_is_extracted_without_truncation(self):
        headers = [
            "Received: from relay6.example ([2001:4860:4860::8888]) by mx.example.net"
        ]

        extracted = self.service.extract_ips_from_email(headers)
        chain = self.service.build_relay_chain(headers)

        self.assertEqual(extracted, ["2001:4860:4860::8888"])
        self.assertEqual(chain["earliest_reliable_observed_ip"], "2001:4860:4860::8888")
        self.assertEqual(chain["relay_chain"][0]["ip_classification"], "PUBLIC")

    def test_full_relay_chain_keeps_internal_hops_and_geolocates_public_only(self):
        headers = [
            "Received: from newest ([10.0.0.8]) by inbox.example; Tue, 2 Jun 2026 10:20:30 +0000",
            "Received: from edge ([8.8.8.8]) by mx.example; Tue, 2 Jun 2026 10:19:30 +0000",
            "Received: from workstation ([192.168.1.5]) by edge; Tue, 2 Jun 2026 10:18:30 +0000",
        ]
        chain = self.service.build_relay_chain(headers)
        public_geo = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "isp": "Example ISP",
        }

        with patch.object(self.service, "resolve_geoip") as resolve_geoip:
            enriched = self.service.enrich_relay_chain(chain, [public_geo])

        hops = enriched["relay_chain"]
        self.assertEqual(
            [(hop["ip"], hop["ip_classification"]) for hop in hops],
            [
                ("192.168.1.5", "PRIVATE"),
                ("8.8.8.8", "PUBLIC"),
                ("10.0.0.8", "PRIVATE"),
            ],
        )
        self.assertEqual(enriched["earliest_public_hop"], "8.8.8.8")
        self.assertIsNone(hops[0]["geolocation"])
        self.assertIn("Internal relay", hops[0]["note"])
        self.assertEqual(hops[1]["geolocation"], public_geo)
        self.assertIsNone(hops[2]["geolocation"])
        resolve_geoip.assert_not_called()

    def test_received_timestamp_is_not_mistaken_for_a_relay_ip(self):
        header = (
            "Received: from internal ([10.1.2.3]) by mx.example; "
            "Tue, 2 Jun 2026 10:20:30 +0000"
        )

        self.assertEqual(self.service.extract_ips_from_email([header]), [])
        chain = self.service.build_relay_chain([header])
        self.assertEqual(chain["relay_chain"][0]["ip"], "10.1.2.3")
        self.assertEqual(chain["relay_chain"][0]["ip_classification"], "PRIVATE")


if __name__ == "__main__":
    unittest.main()
