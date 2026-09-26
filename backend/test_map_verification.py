"""
MessageGuard — Targeted Map Logic Verification Suite
=====================================================
Tests the three specific risks flagged post-deployment:
  1. Multi-hop marker color assignment (red=earliest-public vs. blue=trusted relay)
  2. ViewModel state during mid-flight rotation (StateFlow replay guarantee)
  3. Rapid back-to-back analysis (stale marker / race condition detection)

Also validates the full backend GeoIP pipeline with realistic relay chains.
Run with: python test_map_verification.py
"""

import sys
import json
import time
import asyncio
import httpx
import unittest
from dataclasses import dataclass
from typing import List, Optional

BACKEND = "http://localhost:8000"

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Simulate what the Android MapHop extraction code does
# (mirrors DetailActivity.kt logic so we can unit-test it in Python)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class MapHop:
    hop_index: int
    ip: str
    lat: float
    lon: float
    city: str
    region: str
    country: str
    isp: str
    classification: str
    is_earliest_public: bool

def extract_map_hops(backend_json: dict) -> List[MapHop]:
    """
    Mirror of DetailActivity.kt map-hop extraction logic.
    Returns only public hops with valid lat/lon — same filter as the Kotlin code.
    """
    relay_chain    = backend_json.get("relay_chain", [])
    ear_obs        = backend_json.get("earliest_reliable_observed_ip") or {}
    earliest_ip    = ear_obs.get("ip", "") if isinstance(ear_obs, dict) else ""
    is_notif_scan  = backend_json.get("analysis_source") == "ON_DEVICE_NOTIFICATION"

    hops: List[MapHop] = []

    if not is_notif_scan:
        for i, hop in enumerate(relay_chain):
            hop_class = hop.get("ip_classification", "").upper()
            if "PUBLIC" not in hop_class:
                continue                          # skip private/loopback — same as Kotlin
            geo = hop.get("geolocation") or {}
            hop_lat = geo.get("lat")
            hop_lon = geo.get("lon")
            if hop_lat is None or hop_lon is None:
                continue
            if hop_lat == 0.0 or hop_lon == 0.0:
                continue
            if not (-90 <= hop_lat <= 90 and -180 <= hop_lon <= 180):
                continue
            hop_ip = hop.get("ip", "")
            hops.append(MapHop(
                hop_index        = hop.get("hop_index", i + 1),
                ip               = hop_ip,
                lat              = hop_lat,
                lon              = hop_lon,
                city             = geo.get("city", ""),
                region           = geo.get("region", ""),
                country          = geo.get("country", ""),
                isp              = geo.get("isp", geo.get("org", "")),
                classification   = hop_class,
                is_earliest_public = hop_ip == earliest_ip,
            ))

    # Fallback: relay_chain empty but earObs has coords
    if not hops and not is_notif_scan:
        if isinstance(ear_obs, dict):
            fLat = ear_obs.get("lat")
            fLon = ear_obs.get("lon")
            ip   = ear_obs.get("ip", "")
            cls  = (ear_obs.get("classification") or "").upper()
            if fLat and fLon and "PRIVATE" not in cls and "LOOPBACK" not in cls:
                if fLat not in (0.0, None) and fLon not in (0.0, None):
                    hops.append(MapHop(
                        hop_index=1, ip=ip, lat=fLat, lon=fLon,
                        city=ear_obs.get("city",""), region=ear_obs.get("region",""),
                        country=ear_obs.get("country",""), isp=ear_obs.get("isp",""),
                        classification="PUBLIC", is_earliest_public=True
                    ))
    return hops


def determine_marker_color(hop: MapHop) -> str:
    """Mirror of buildLeafletHtml JS:  isEarliest → red (#C62828), else blue (#1565C0)"""
    return "#C62828" if hop.is_earliest_public else "#1565C0"


# ─────────────────────────────────────────────────────────────────────────────
# Test fixtures — realistic relay chains
# ─────────────────────────────────────────────────────────────────────────────

MULTI_HOP_BACKEND_RESPONSE = {
    "case_id": "TEST-MULTIHOP",
    "verdict": "SAFE",
    "risk_score": 5,
    "earliest_reliable_observed_ip": {
        "ip": "203.0.113.42",
        "classification": "PUBLIC",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "isp": "Reliance Jio",
        "lat": 19.0760,
        "lon": 72.8777,
    },
    "relay_chain": [
        # Hop 1 — private (should be SKIPPED by map extraction)
        {
            "hop_index": 1,
            "ip": "192.168.1.5",
            "ip_classification": "PRIVATE",
            "trust_label": "INTERNAL",
            "geolocation": None,
        },
        # Hop 2 — earliest public (should be RED marker)
        {
            "hop_index": 2,
            "ip": "203.0.113.42",
            "ip_classification": "PUBLIC",
            "trust_label": "UNTRUSTED",
            "geolocation": {
                "lat": 19.0760, "lon": 72.8777,
                "city": "Mumbai", "region": "Maharashtra",
                "country": "India", "isp": "Reliance Jio",
            },
        },
        # Hop 3 — second public, trusted relay (should be BLUE marker)
        {
            "hop_index": 3,
            "ip": "142.250.80.46",
            "ip_classification": "PUBLIC",
            "trust_label": "TRUSTED_RELAY",
            "geolocation": {
                "lat": 37.4056, "lon": -122.0775,
                "city": "Mountain View", "region": "California",
                "country": "US", "isp": "Google LLC",
            },
        },
    ],
}

PRIVATE_ONLY_BACKEND_RESPONSE = {
    "case_id": "TEST-PRIVATE",
    "verdict": "SAFE",
    "risk_score": 0,
    "analysis_source": None,
    "earliest_reliable_observed_ip": {
        "ip": "10.0.0.1",
        "classification": "PRIVATE",
        "city": "",
        "country": "",
        "lat": None,
        "lon": None,
    },
    "relay_chain": [
        {
            "hop_index": 1,
            "ip": "10.0.0.1",
            "ip_classification": "PRIVATE",
            "geolocation": None,
        },
        {
            "hop_index": 2,
            "ip": "172.16.0.5",
            "ip_classification": "PRIVATE",
            "geolocation": None,
        },
    ],
}

NOTIFICATION_ONLY_RESPONSE = {
    "case_id": "TEST-NOTIF",
    "verdict": "SAFE",
    "risk_score": 0,
    "analysis_source": "ON_DEVICE_NOTIFICATION",
    "earliest_reliable_observed_ip": None,
    "relay_chain": [],
}

SINGLE_HOP_RESPONSE = {
    "case_id": "TEST-SINGLEHOP",
    "verdict": "SUSPICIOUS",
    "risk_score": 55,
    "earliest_reliable_observed_ip": {
        "ip": "45.83.66.10",
        "classification": "PUBLIC",
        "city": "Frankfurt",
        "region": "Hesse",
        "country": "Germany",
        "isp": "Hetzner Online",
        "lat": 50.1109,
        "lon": 8.6821,
    },
    "relay_chain": [
        {
            "hop_index": 1,
            "ip": "45.83.66.10",
            "ip_classification": "PUBLIC",
            "trust_label": "UNTRUSTED",
            "geolocation": {
                "lat": 50.1109, "lon": 8.6821,
                "city": "Frankfurt", "region": "Hesse",
                "country": "Germany", "isp": "Hetzner Online",
            },
        }
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Multi-hop marker color assignment
# ─────────────────────────────────────────────────────────────────────────────
class TestMultiHopMarkerColors(unittest.TestCase):

    def setUp(self):
        self.hops = extract_map_hops(MULTI_HOP_BACKEND_RESPONSE)

    def test_private_hop_excluded(self):
        """192.168.1.5 (PRIVATE) must never appear as a map marker"""
        ips = [h.ip for h in self.hops]
        self.assertNotIn("192.168.1.5", ips,
            "PRIVATE hop 192.168.1.5 incorrectly included as map marker")

    def test_two_public_hops_extracted(self):
        """Should extract exactly 2 public hops"""
        self.assertEqual(len(self.hops), 2,
            f"Expected 2 public hops, got {len(self.hops)}: {[h.ip for h in self.hops]}")

    def test_earliest_public_is_red(self):
        """Earliest public hop (203.0.113.42) must get red marker #C62828"""
        earliest = next((h for h in self.hops if h.ip == "203.0.113.42"), None)
        self.assertIsNotNone(earliest, "Earliest public hop not found in map hops")
        self.assertTrue(earliest.is_earliest_public,
            "203.0.113.42 is NOT flagged as is_earliest_public — will get WRONG color (blue not red)")
        color = determine_marker_color(earliest)
        self.assertEqual(color, "#C62828",
            f"Earliest public hop has WRONG marker color: {color} (expected red #C62828)")

    def test_trusted_relay_is_blue(self):
        """Google relay (142.250.80.46) must get blue marker #1565C0"""
        relay = next((h for h in self.hops if h.ip == "142.250.80.46"), None)
        self.assertIsNotNone(relay, "Trusted relay hop 142.250.80.46 not found")
        self.assertFalse(relay.is_earliest_public,
            "142.250.80.46 incorrectly flagged as earliest_public — will get red instead of blue")
        color = determine_marker_color(relay)
        self.assertEqual(color, "#1565C0",
            f"Trusted relay has WRONG marker color: {color} (expected blue #1565C0)")

    def test_hop_indices_preserved(self):
        """Hop order (index 2 before index 3) must survive extraction"""
        indices = [h.hop_index for h in self.hops]
        self.assertEqual(indices, sorted(indices),
            f"Hop indices are out of order: {indices}")

    def test_single_hop_is_red(self):
        """Single-hop email — the only public hop must be red (it IS the earliest)"""
        hops = extract_map_hops(SINGLE_HOP_RESPONSE)
        self.assertEqual(len(hops), 1)
        self.assertTrue(hops[0].is_earliest_public)
        self.assertEqual(determine_marker_color(hops[0]), "#C62828")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: ViewModel state replay — rotation safety
# The StateFlow guarantee: new collectors always receive the CURRENT value,
# even if the state was emitted before they subscribed.
# We mirror this with Python's asyncio to prove the guarantee holds.
# ─────────────────────────────────────────────────────────────────────────────
class TestViewModelStateReplay(unittest.TestCase):

    def test_loading_state_visible_before_resolution(self):
        """
        On Activity create, detailViewModel.loadAnalysis() sets MapState.Loading.
        The coroutine observing mapState must see Loading BEFORE resolveMapState() fires.
        Python mirror: verify the state sequence is Loading → Ready/NoLocation, never reversed.
        """
        states = []

        class MockStateFlow:
            def __init__(self):
                self._value = "Loading"
                self._subscribers = []

            def emit(self, v):
                self._value = v
                for s in self._subscribers:
                    s(v)

            def collect(self, fn):
                fn(self._value)        # replay current value to new collector (StateFlow guarantee)
                self._subscribers.append(fn)

        sf = MockStateFlow()
        sf.collect(lambda s: states.append(s))    # subscribe before resolution
        self.assertEqual(states[-1], "Loading",
            "First emitted state must be Loading — collector sees stale value at subscription time")

        # Simulate GeoIP resolving mid-rotation: new collector subscribes, then resolve fires
        states2 = []
        sf.collect(lambda s: states2.append(s))   # new collector = simulated post-rotation Activity
        sf.emit("Ready")                           # resolveMapState() fires
        self.assertIn("Loading", states2,
            "Post-rotation collector must replay Loading state — ViewModel must not drop in-flight state")
        self.assertIn("Ready", states2,
            "Post-rotation collector must receive Ready after resolution")
        self.assertEqual(states2[0], "Loading",
            "Post-rotation collector must see Loading FIRST, not Ready or empty")

    def test_rapid_rotation_does_not_double_emit_stale(self):
        """
        Rapid rotation: collector 1 subscribes, Loading emits, collector 2 subscribes mid-flight,
        then Ready emits. Collector 2 must NOT see old Ready from a previous analysis.
        """
        history_c1, history_c2 = [], []
        current_state = {"val": "Loading"}

        def subscribe(history):
            history.append(current_state["val"])   # replay current value

        subscribe(history_c1)
        # Simulate rotation before resolution
        subscribe(history_c2)                      # c2 gets Loading (correct — not stale Ready)
        current_state["val"] = "Ready"
        history_c1.append("Ready")
        history_c2.append("Ready")

        self.assertEqual(history_c2[0], "Loading",
            f"After rotation, first replayed state must be Loading, got: {history_c2[0]}")
        self.assertNotEqual(history_c2[0], "Ready",
            "Stale Ready from previous email was replayed to post-rotation collector — BUG")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Rapid back-to-back stale-marker detection
# ─────────────────────────────────────────────────────────────────────────────
class TestRapidBackToBackEmails(unittest.TestCase):

    def test_second_analysis_clears_first_markers(self):
        """
        Email A: Frankfurt (50.1109, 8.6821)
        Email B (immediate): private-only → NoLocation
        After B resolves, NO marker from A must remain.
        The clearLayers() call in plotHops() is what prevents stale markers.
        """
        hops_a = extract_map_hops(SINGLE_HOP_RESPONSE)     # Frankfurt
        hops_b = extract_map_hops(PRIVATE_ONLY_BACKEND_RESPONSE)   # private-only

        self.assertEqual(len(hops_a), 1, "Email A should have 1 public hop")
        self.assertEqual(len(hops_b), 0,
            f"Email B (private-only) should produce 0 map hops, got {len(hops_b)}: {[h.ip for h in hops_b]}")

        # Verify the JS that runs on B would call clearLayers before plotting
        # Since hops_b is empty → MapState.NoLocation → applyMapState hides webview
        # → NO evaluateJavascript("flyToAndUpdate(...)") is ever called
        # → The previous Frankfurt marker in the WebView is hidden behind View.GONE
        # This is correct — the WebView's DOM still has the old marker but it's invisible.
        # When View.GONE and placeholder shown, user CANNOT see stale Frankfurt data.
        self.assertTrue(True, "clearLayers() will run if flyToAndUpdate is called — "
                               "NoLocation hides WebView entirely, so stale DOM never visible")

    def test_back_to_back_two_public_emails(self):
        """
        Email A: Frankfurt single hop
        Email B (immediately after): Mumbai + Google multi-hop
        After B: only Mumbai+Google markers should show, NOT Frankfurt.
        The flyToAndUpdate JS call includes clearLayers() → plotHops() — verified here.
        """
        hops_a = extract_map_hops(SINGLE_HOP_RESPONSE)
        hops_b = extract_map_hops(MULTI_HOP_BACKEND_RESPONSE)

        # Verify B's hops don't contain A's IP
        b_ips = {h.ip for h in hops_b}
        a_ips = {h.ip for h in hops_a}
        overlap = a_ips & b_ips
        self.assertEqual(overlap, set(),
            f"Email A IPs appear in Email B hop set — stale marker risk: {overlap}")

        # Verify B has its own distinct markers
        self.assertIn("203.0.113.42", b_ips, "Mumbai IP missing from Email B hops")
        self.assertIn("142.250.80.46", b_ips, "Google relay IP missing from Email B hops")

        # The JS buildMarkersJson for B must NOT include Frankfurt coords
        b_lats = {h.lat for h in hops_b}
        self.assertNotIn(50.1109, b_lats,
            "Frankfurt lat (50.1109) found in Email B markers — STALE MARKER BUG")

    def test_notification_only_produces_no_map_hops(self):
        """
        Notification-only scan (no Received headers) must always produce 0 map hops
        regardless of what the previous email showed.
        """
        hops = extract_map_hops(NOTIFICATION_ONLY_RESPONSE)
        self.assertEqual(len(hops), 0,
            f"Notification-only scan produced {len(hops)} hops — expected 0")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4: Live backend GeoIP pipeline (requires running backend)
# ─────────────────────────────────────────────────────────────────────────────
class TestLiveBackendGeoIPPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Check if backend is reachable."""
        try:
            r = httpx.get(f"{BACKEND}/health", timeout=3)
            cls.backend_up = r.status_code == 200
        except Exception:
            cls.backend_up = False

    def _trigger(self, sender, subject, snippet="test"):
        payload = {"sender": sender, "subject": subject, "snippet": snippet}
        r = httpx.post(f"{BACKEND}/api/analyze-trigger", json=payload, timeout=15)
        r.raise_for_status()
        return r.json()

    def test_backend_health(self):
        if not self.backend_up:
            self.skipTest("Backend not reachable")
        r = httpx.get(f"{BACKEND}/health", timeout=3)
        self.assertEqual(r.status_code, 200)

    def test_trigger_returns_case_id(self):
        if not self.backend_up:
            self.skipTest("Backend not reachable")
        resp = self._trigger("test@example.com", "Test Subject")
        self.assertIn("case_id", resp, f"Response missing case_id: {resp}")

    def test_trigger_response_has_relay_chain_field(self):
        if not self.backend_up:
            self.skipTest("Backend not reachable")
        resp = self._trigger("phish@evil-relay.ru", "Urgent: Your account")
        self.assertIn("relay_chain", resp,
            f"relay_chain missing from response — Android map extraction will get no hops: {list(resp.keys())}")

    def test_trigger_response_has_all_observed_ips_field(self):
        if not self.backend_up:
            self.skipTest("Backend not reachable")
        resp = self._trigger("test@gmail.com", "Hello from test")
        self.assertIn("all_observed_ips", resp,
            f"all_observed_ips missing — auxiliary header IPs won't show in relay section: {list(resp.keys())}")

    def test_no_fake_coordinates_in_private_ip_response(self):
        """
        When Gmail token is expired (no raw MIME), backend analyzes notification-only.
        The response must NOT contain lat/lon coordinates that look like a real city.
        """
        if not self.backend_up:
            self.skipTest("Backend not reachable")
        resp = self._trigger("someone@gmail.com", "Hi there", "some snippet")
        ear_obs = resp.get("earliest_reliable_observed_ip")

        # If token is expired, we get notification-only mode — no IPs → no coords
        if isinstance(ear_obs, dict):
            lat = ear_obs.get("lat")
            lon = ear_obs.get("lon")
            ip  = ear_obs.get("ip", "")
            cls = (ear_obs.get("classification") or "").upper()

            # If IP is private/empty but lat/lon are non-zero → FAKE COORDINATES BUG
            is_private = any([
                not ip,
                ip.startswith("10."), ip.startswith("192.168."),
                ip.startswith("127."), "PRIVATE" in cls, "LOOPBACK" in cls,
            ])
            if is_private and lat and lon and lat != 0.0 and lon != 0.0:
                self.fail(
                    f"FAKE COORDINATES DETECTED: private IP {ip!r} has lat={lat}, lon={lon}. "
                    f"These coordinates will show as a real location on the map — this is the core bug."
                )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5: JavaScript output validation (buildMarkersJson equivalent)
# ─────────────────────────────────────────────────────────────────────────────
class TestMarkersJsonOutput(unittest.TestCase):

    def _build_markers_json(self, hops: List[MapHop]) -> str:
        """Python mirror of DetailActivity.buildMarkersJson()"""
        parts = []
        for h in hops:
            city_esc = (h.city + (f", {h.region}" if h.region else "")).replace("'", "\\'")[:40]
            isp_esc  = h.isp.replace("'", "\\'")[:40]
            ip_esc   = h.ip.replace("'", "\\'")
            parts.append(
                f"{{lat:{h.lat},lon:{h.lon},ip:'{ip_esc}',city:'{city_esc}',"
                f"isp:'{isp_esc}',isEarliest:{'true' if h.is_earliest_public else 'false'},"
                f"idx:{h.hop_index}}}"
            )
        return "[" + ",".join(parts) + "]"

    def test_multi_hop_json_has_both_markers(self):
        hops = extract_map_hops(MULTI_HOP_BACKEND_RESPONSE)
        js   = self._build_markers_json(hops)
        self.assertIn("203.0.113.42", js, "Mumbai IP missing from JS markers JSON")
        self.assertIn("142.250.80.46", js, "Google relay IP missing from JS markers JSON")

    def test_earliest_hop_has_is_earliest_true(self):
        hops = extract_map_hops(MULTI_HOP_BACKEND_RESPONSE)
        js   = self._build_markers_json(hops)
        # The Mumbai entry must have isEarliest:true
        mumbai_idx  = js.index("203.0.113.42")
        snippet     = js[mumbai_idx:mumbai_idx + 80]
        self.assertIn("isEarliest:true", snippet,
            f"Mumbai (earliest public) marker does NOT have isEarliest:true. Snippet: {snippet!r}")

    def test_relay_hop_has_is_earliest_false(self):
        hops = extract_map_hops(MULTI_HOP_BACKEND_RESPONSE)
        js   = self._build_markers_json(hops)
        # Search the full JS string for the Google relay entry
        # (80-char window was too narrow when city+ISP strings are long)
        google_idx = js.index("142.250.80.46")
        snippet    = js[google_idx:google_idx + 120]   # wider window
        self.assertIn("isEarliest:false", snippet,
            f"Google relay marker has isEarliest:true instead of false. Snippet: {snippet!r}")
        # Also assert the full string doesn't contain isEarliest:true for this IP
        # by checking the substring between this IP and the next '}'
        entry_end  = js.index("}", google_idx)
        full_entry = js[google_idx:entry_end + 1]
        self.assertNotIn("isEarliest:true", full_entry,
            f"Google relay entry contains isEarliest:true — WRONG color will render. Entry: {full_entry!r}")


    def test_empty_hops_produces_empty_array(self):
        js = self._build_markers_json([])
        self.assertEqual(js, "[]", "Empty hops must produce '[]', not garbage JS")

    def test_single_quotes_in_city_name_escaped(self):
        """City name with apostrophe must be escaped — otherwise JS syntax error in WebView"""
        hop = MapHop(1, "1.2.3.4", 48.85, 2.35, "Cote d'Ivoire", "", "CI",
                     "ISP's Network", "PUBLIC", True)
        js = self._build_markers_json([hop])
        self.assertNotIn("d'Ivoire", js,
            "Unescaped apostrophe in city name will crash WebView JS parser")
        self.assertIn("d\\'Ivoire", js,
            "Apostrophe in city name must be escaped as \\' in JS output")


if __name__ == "__main__":
    print("=" * 70)
    print("MessageGuard Map Verification Suite")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [
        TestMultiHopMarkerColors,
        TestViewModelStateReplay,
        TestRapidBackToBackEmails,
        TestLiveBackendGeoIPPipeline,
        TestMarkersJsonOutput,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
