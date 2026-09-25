"""
PS106 Threat Vision — Threat Intelligence Service
===================================================
Provides network-layer threat intelligence:
- IP classification (PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL, RESERVED, INVALID) via `ipaddress`
- Infrastructure type detection (DATACENTER_CLOUD, VPN_PROXY, TOR_EXIT, HOSTING_PROVIDER, RESIDENTIAL, UNKNOWN)
- Ordered RFC 822 Received-header relay chain reconstruction with per-hop trust scoring
- Earliest reliable observed infrastructure IP determination (never "attacker IP")
- Approximate infrastructure GeoIP resolution with mandatory forensic disclaimer
"""

import re
import ipaddress
import logging
from typing import List, Dict, Any, Optional

import requests

logger = logging.getLogger("ps106.threat_intel")

GEOIP_API_BASE = "http://ip-api.com/json"

GEO_DISCLAIMER = (
    "Approximate infrastructure geolocation based on IP registry data. "
    "This does NOT establish the sender's physical location."
)

# Known ASNs / org keywords for major cloud, hosting, and anonymization providers
CLOUD_INDICATORS = [
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "cloudflare", "ovh", "hetzner", "linode", "akamai", "oracle",
    "alibaba", "fastly"
]

VPN_PROXY_INDICATORS = [
    "nordvpn", "expressvpn", "surfshark", "mullvad", "cyberghost",
    "private internet access", "protonvpn", "vpn", "proxy", "tor exit"
]

HOSTING_INDICATORS = [
    "hosting", "server", "data center", "datacenter", "vps", "dedicated",
    "rackspace", "godaddy", "bluehost", "hostgator"
]

TRUSTED_MTA_KEYWORDS = [
    "google.com", "gmail.com", "outlook.com", "microsoft.com",
    "protection.outlook.com", "amazonses.com", "sendgrid.net", "mailgun.org"
]


class ThreatIntelService:
    """Network-layer threat intelligence and forensic relay-chain reconstruction."""

    @staticmethod
    def classify_ip(ip_str: str) -> str:
        """
        Classify IP into standard forensic categories via the ipaddress standard library:
        PUBLIC | PRIVATE | LOOPBACK | LINK_LOCAL | RESERVED | INVALID
        """
        if not ip_str or not isinstance(ip_str, str):
            return "INVALID"
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.is_loopback:
                return "LOOPBACK"
            if ip.is_private:
                return "PRIVATE"
            if ip.is_link_local:
                return "LINK_LOCAL"
            if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return "RESERVED"
            if ip.is_global:
                return "PUBLIC"
            return "RESERVED"
        except ValueError:
            return "INVALID"

    @staticmethod
    def detect_infrastructure_type(ip_str: str, asn_org: str = "") -> str:
        """
        Determine network infrastructure type from IP classification and ASN/org:
        DATACENTER_CLOUD | VPN_PROXY | TOR_EXIT | HOSTING_PROVIDER | RESIDENTIAL | UNKNOWN
        """
        org_lower = (asn_org or "").lower()

        if any(v in org_lower for v in VPN_PROXY_INDICATORS):
            return "VPN_PROXY"
        if "tor" in org_lower:
            return "TOR_EXIT"
        if any(c in org_lower for c in CLOUD_INDICATORS):
            return "DATACENTER_CLOUD"
        if any(h in org_lower for h in HOSTING_INDICATORS):
            return "HOSTING_PROVIDER"

        # Check IP classification
        ip_class = ThreatIntelService.classify_ip(ip_str)
        if ip_class != "PUBLIC":
            return "INTERNAL_RESERVED"

        if org_lower:
            return "RESIDENTIAL"
        return "UNKNOWN"

    def extract_ips_from_email(self, received_headers: List[str]) -> List[str]:
        """Extract public routable relay IP addresses from RFC 822 'Received' headers."""
        ips = []
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

        for header in received_headers:
            header_str = str(header)
            found = ip_pattern.findall(header_str)
            for ip in found:
                if self.classify_ip(ip) == "PUBLIC" and ip not in ips:
                    ips.append(ip)

        logger.info(f"Extracted {len(ips)} public routable relay IPs: {ips}")
        return ips

    def build_relay_chain(self, raw_received_headers: List[str]) -> Dict[str, Any]:
        """
        Reconstruct the chronological transmission path from RFC 822 Received headers.

        Headers arrive top-to-bottom (most recent recipient hop to oldest sender hop).
        We reverse to chronological order (earliest hop first).

        Per-hop Trust Enum:
          OBSERVED | TRUSTED_RELAY | SUSPICIOUS_RELAY | POSSIBLY_FORGED | UNKNOWN

        Identifies 'earliest_reliable_observed_ip' or flags 'origin_not_determinable'.
        """
        if not raw_received_headers:
            return {
                "relay_chain": [],
                "earliest_reliable_observed_ip": None,
                "origin_not_determinable": True,
                "reason": "No Received headers present in email metadata.",
                "total_hops": 0,
            }

        parsed_hops = []
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        from_pattern = re.compile(r"from\s+([^\s;()]+)", re.IGNORECASE)
        by_pattern = re.compile(r"by\s+([^\s;()]+)", re.IGNORECASE)

        # Process top-down, then reverse to chronological (earliest hop at index 0)
        reversed_headers = list(reversed(raw_received_headers))

        for idx, header in enumerate(reversed_headers):
            header_str = str(header).strip()
            found_ips = ip_pattern.findall(header_str)
            extracted_ip = None
            for cand in found_ips:
                if self.classify_ip(cand) == "PUBLIC":
                    extracted_ip = cand
                    break
            if not extracted_ip and found_ips:
                extracted_ip = found_ips[0]

            from_match = from_pattern.search(header_str)
            by_match = by_pattern.search(header_str)

            from_host = from_match.group(1) if from_match else "unknown"
            by_host = by_match.group(1) if by_match else "unknown"

            # Assign Trust Label
            # OBSERVED | TRUSTED_RELAY | SUSPICIOUS_RELAY | POSSIBLY_FORGED | UNKNOWN
            trust_label = "OBSERVED"
            trust_reason = "Standard relay hop observation"

            # Forgery checks: missing 'by' MTA or malformed syntax
            if not by_match or by_host == "unknown":
                trust_label = "POSSIBLY_FORGED"
                trust_reason = "Missing 'by' MTA field in Received header syntax"
            elif any(tm in by_host.lower() for tm in TRUSTED_MTA_KEYWORDS):
                trust_label = "TRUSTED_RELAY"
                trust_reason = f"Received and signed by trusted major mail provider ({by_host})"
            elif extracted_ip:
                ip_class = self.classify_ip(extracted_ip)
                if ip_class != "PUBLIC":
                    trust_label = "SUSPICIOUS_RELAY"
                    trust_reason = f"Hop claims non-routable {ip_class} address in transmission path"
                else:
                    trust_label = "OBSERVED"
                    trust_reason = "External routing infrastructure observed"

            parsed_hops.append({
                "hop_index": idx + 1,
                "from_host": from_host,
                "by_host": by_host,
                "ip": extracted_ip,
                "ip_classification": self.classify_ip(extracted_ip) if extracted_ip else "NONE",
                "trust_label": trust_label,
                "trust_reason": trust_reason,
            })

        # Identify earliest reliable observed hop
        # Walk forwards; select the earliest hop that is TRUSTED_RELAY or valid PUBLIC OBSERVED
        earliest_reliable_ip = None
        earliest_hop_idx = None

        for hop in parsed_hops:
            if hop["trust_label"] in ("TRUSTED_RELAY", "OBSERVED"):
                if hop["ip"] and hop["ip_classification"] == "PUBLIC":
                    earliest_reliable_ip = hop["ip"]
                    earliest_hop_idx = hop["hop_index"]
                    break

        origin_not_determinable = earliest_reliable_ip is None
        reason = (
            f"Earliest reliable observed relay identified at hop {earliest_hop_idx}."
            if not origin_not_determinable
            else "No verifiable public IP hop found before breaks or external unverified headers in relay chain."
        )

        return {
            "relay_chain": parsed_hops,
            "hop_count": len(parsed_hops),
            "total_hops": len(parsed_hops),
            "earliest_reliable_observed_ip": earliest_reliable_ip or "ORIGIN_NOT_DETERMINABLE",
            "origin_not_determinable": origin_not_determinable,
            "reason": reason,
            "disclaimer": GEO_DISCLAIMER,
        }

    def resolve_geoip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a single IP to its GeoIP data using ip-api.com with mandatory disclaimer.
        """
        ip_class = self.classify_ip(ip)
        if ip_class != "PUBLIC":
            return {
                "ip": ip,
                "ip_classification": ip_class,
                "error": f"{ip_class} address — not an Internet origin",
                "disclaimer": GEO_DISCLAIMER,
            }

        try:
            resp = requests.get(
                f"{GEOIP_API_BASE}/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
                timeout=5,
            )
            data = resp.json()

            if data.get("status") == "success":
                asn_org = f"{data.get('as', '')} {data.get('org', '')} {data.get('isp', '')}"
                infra_type = self.detect_infrastructure_type(ip, asn_org)
                return {
                    "ip": ip,
                    "ip_classification": "PUBLIC",
                    "infrastructure_type": infra_type,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "timezone": data.get("timezone", ""),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", ""),
                    "as_number": data.get("as", ""),
                    "disclaimer": GEO_DISCLAIMER,
                }
            else:
                logger.warning(f"GeoIP lookup failed for {ip}: {data.get('message', 'unknown error')}")
                return {
                    "ip": ip,
                    "ip_classification": "PUBLIC",
                    "error": data.get("message", "Lookup failed"),
                    "disclaimer": GEO_DISCLAIMER,
                }

        except requests.RequestException as e:
            logger.error(f"GeoIP request failed for {ip}: {e}")
            return {
                "ip": ip,
                "ip_classification": "PUBLIC",
                "error": str(e),
                "disclaimer": GEO_DISCLAIMER,
            }

    def resolve_all_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Resolve GeoIP data for extracted public IPs (capped at 10)."""
        results = []
        for ip in ips[:10]:
            result = self.resolve_geoip(ip)
            if result:
                results.append(result)
        return results

    def analyze_relay_path(self, geoip_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze resolved relay path for infrastructure risk and multi-jurisdiction hops."""
        if not geoip_results:
            return {
                "anomaly_score": 0,
                "flags": ["No relay IPs to analyze"],
                "disclaimer": GEO_DISCLAIMER,
            }

        countries = set()
        flags = []
        anomaly_score = 0

        high_risk_countries = {"RU", "CN", "NG", "KP", "IR"}

        for geo in geoip_results:
            if "error" in geo:
                continue

            cc = geo.get("country_code", "")
            if cc:
                countries.add(cc)

            if cc in high_risk_countries:
                anomaly_score += 25
                flags.append(f"Relay through high-risk jurisdiction: {geo.get('country', cc)}")

            infra_type = geo.get("infrastructure_type", "UNKNOWN")
            if infra_type in ("VPN_PROXY", "TOR_EXIT"):
                anomaly_score += 20
                flags.append(f"Anonymization infrastructure detected: {geo.get('isp', '')} ({infra_type})")
            elif infra_type in ("DATACENTER_CLOUD", "HOSTING_PROVIDER"):
                flags.append(f"Commercial cloud/hosting infrastructure: {geo.get('isp', '')}")

        if len(countries) > 3:
            anomaly_score += 20
            flags.append(f"Message traversed {len(countries)} separate country jurisdictions")

        return {
            "anomaly_score": min(anomaly_score, 100),
            "countries": list(countries),
            "relay_count": len(geoip_results),
            "flags": flags if flags else ["Relay path appears normal"],
            "disclaimer": GEO_DISCLAIMER,
        }
