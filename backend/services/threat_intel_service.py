"""
MessageGuard — SIH26106 Threat Intelligence Service
===================================================
Provides network-layer threat intelligence:
- IP classification (PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL, RESERVED, INVALID) via `ipaddress`
- Infrastructure type detection (DATACENTER_CLOUD, VPN_PROXY, TOR_EXIT, HOSTING_PROVIDER, RESIDENTIAL, UNKNOWN)
- Ordered RFC 822 Received-header relay chain reconstruction with per-hop trust scoring
- Earliest reliable observed infrastructure IP determination (never "attacker IP")
- Approximate infrastructure GeoIP resolution with mandatory forensic disclaimer
"""

import os
import re
import ipaddress
import logging
from typing import List, Dict, Any, Optional

import requests

logger = logging.getLogger("ps106.threat_intel")

GEOIP_API_BASE = "http://ip-api.com/json"
IP_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]+(?![0-9A-Za-z])"
    r"|(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"
)

# Optional IPinfo token — set IPINFO_TOKEN to prefer the key-backed provider.
IPINFO_TOKEN: Optional[str] = os.environ.get("IPINFO_TOKEN")

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

    GEO_DISCLAIMER = GEO_DISCLAIMER

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
            if ip.is_link_local:
                return "LINK_LOCAL"
            if ip.is_private:
                return "PRIVATE"
            if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return "RESERVED"
            if ip.is_global:
                return "PUBLIC"
            return "RESERVED"
        except ValueError:
            return "INVALID"

    @classmethod
    def classify_ip_details(cls, ip_str: str) -> Dict[str, Any]:
        """
        Classify IP with comprehensive ipaddress properties:
        Returns version, classification, and boolean flags (is_public, is_private, is_loopback, is_link_local, is_global, geo_available).
        """
        classification = cls.classify_ip(ip_str)
        is_pub = classification == "PUBLIC"
        is_loop = False
        is_ll = False
        is_priv = False
        version = None
        is_global = False
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            version = ip_obj.version
            is_global = getattr(ip_obj, "is_global", False)
            is_loop = ip_obj.is_loopback
            is_ll = ip_obj.is_link_local
            is_priv = ip_obj.is_private and not is_loop and not is_ll
        except Exception:
            pass

        return {
            "ip": ip_str.strip() if ip_str else "",
            "ip_version": version,
            "classification": classification,
            "is_public": is_pub,
            "is_private": is_priv,
            "is_loopback": is_loop,
            "is_link_local": is_ll,
            "is_global": is_global,
            "geo_available": is_pub,
        }

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

    @staticmethod
    def _extract_ip_candidates(text: str) -> List[str]:
        """Extract and validate complete IPv4/IPv6 literals from a header fragment."""
        candidates = []
        for candidate in IP_CANDIDATE_PATTERN.findall(text):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def extract_ips_from_email(self, received_headers: List[str]) -> List[str]:
        """Extract public routable relay IP addresses from RFC 822 'Received' headers."""
        ips = []

        # Walk from bottom up (earliest to latest)
        for header in reversed(received_headers):
            header_str = re.sub(r"[\[\]]", " ", str(header).split(";", 1)[0])
            for ip in self._extract_ip_candidates(header_str):
                if self.classify_ip(ip) == "PUBLIC" and ip not in ips:
                    ips.append(ip)

        logger.info(f"Extracted {len(ips)} public routable relay IPs: {ips}")
        return ips

    def extract_all_observed_ips(
        self,
        received_headers: List[str],
        aux_headers: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Forensically extract and retain EVERY observed IP address from RFC 822 Received
        and aux headers (X-Originating-IP, X-Sender-IP, Authentication-Results).

        Preserves chronological chain of custody without discarding non-public,
        internal, loopback, or link-local IPs.
        """
        all_observed: List[Dict[str, Any]] = []
        seen_ips = set()

        # 1. Received headers (bottom-up / chronological: sender-side to recipient-side)
        for hop_idx, header in enumerate(reversed(received_headers)):
            header_str = re.sub(r"[\[\]]", " ", str(header).split(";", 1)[0])
            for ip in self._extract_ip_candidates(header_str):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    details = self.classify_ip_details(ip)
                    details["source_header"] = "Received"
                    details["hop_index"] = hop_idx + 1
                    all_observed.append(details)

        # 2. Aux headers
        if aux_headers:
            for k in ["x-originating-ip", "x-sender-ip"]:
                val = aux_headers.get(k) or aux_headers.get(k.lower())
                if val:
                    for ip in self._extract_ip_candidates(re.sub(r"[\[\]]", " ", str(val))):
                        if ip not in seen_ips:
                            seen_ips.add(ip)
                            details = self.classify_ip_details(ip)
                            details["source_header"] = k
                            details["hop_index"] = None
                            all_observed.append(details)

            auth_res = aux_headers.get("authentication-results") or aux_headers.get("Authentication-Results") or ""
            if auth_res:
                for ip in self._extract_ip_candidates(auth_res):
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        details = self.classify_ip_details(ip)
                        details["source_header"] = "Authentication-Results"
                        details["hop_index"] = None
                        all_observed.append(details)

        return all_observed

    def build_relay_chain(self, raw_received_headers: List[str], aux_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Reconstruct the chronological transmission path from RFC 822 Received headers.

        Headers arrive top-to-bottom (most recent recipient hop to oldest sender hop).
        We reverse to chronological order (earliest hop first).

        Per-hop Trust Enum:
          OBSERVED | TRUSTED_RELAY | SUSPICIOUS_RELAY | POSSIBLY_FORGED | UNKNOWN

        Identifies 'earliest_reliable_observed_ip' or flags 'origin_not_determinable'.
        Cross-checks Authentication-Results and X-Originating-IP when present.
        """
        all_observed_ips = self.extract_all_observed_ips(raw_received_headers or [], aux_headers=aux_headers)

        if not raw_received_headers:
            # Check aux headers if Received headers are absent
            aux_ip = None
            aux_source = None
            if aux_headers:
                for k in ["x-originating-ip", "x-sender-ip"]:
                    val = aux_headers.get(k) or aux_headers.get(k.lower())
                    if val:
                        cand = val.strip("[] \t\r\n")
                        if self.classify_ip(cand) == "PUBLIC":
                            aux_ip = cand
                            aux_source = k
                            break

            if aux_ip:
                return {
                    "relay_chain": [],
                    "all_observed_ips": all_observed_ips,
                    "hop_count": 0,
                    "total_hops": 0,
                    "earliest_public_hop": aux_ip,
                    "earliest_reliable_observed_ip": aux_ip,
                    "origin_not_determinable": False,
                    "selection_reason": f"Identified from {aux_source} header (Received headers absent).",
                    "reason": f"Identified from {aux_source} header.",
                    "disclaimer": GEO_DISCLAIMER,
                }

            return {
                "relay_chain": [],
                "all_observed_ips": all_observed_ips,
                "earliest_public_hop": None,
                "earliest_reliable_observed_ip": None,
                "origin_not_determinable": True,
                "selection_reason": "No Received headers present in email metadata.",
                "reason": "No Received headers present in email metadata.",
                "total_hops": 0,
                "disclaimer": GEO_DISCLAIMER,
            }

        parsed_hops = []
        from_pattern = re.compile(r"from\s+([^\s;()]+)", re.IGNORECASE)
        by_pattern = re.compile(r"by\s+([^\s;()]+)", re.IGNORECASE)

        # Process top-down, then reverse to chronological (earliest hop at index 0)
        reversed_headers = list(reversed(raw_received_headers))

        for idx, header in enumerate(reversed_headers):
            header_str = str(header).strip()
            # The semicolon starts the Received timestamp, which can contain
            # colon/dot sequences that otherwise resemble malformed IP literals.
            clean_hdr = re.sub(r"[\[\]]", " ", header_str.split(";", 1)[0])
            found_ips = self._extract_ip_candidates(clean_hdr)
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
                "note": (
                    "Public routable relay; approximate geolocation may be available."
                    if extracted_ip and self.classify_ip(extracted_ip) == "PUBLIC"
                    else (
                        "Internal relay — not routable; no geolocation applicable."
                        if extracted_ip
                        else "No IP address observed in this Received header."
                    )
                ),
                "trust_label": trust_label,
                "trust_reason": trust_reason,
            })

        # Identify earliest reliable observed hop
        # Walk forwards (earliest hop first); select the first non-private/public hop
        earliest_reliable_ip = None
        earliest_hop_idx = None
        selection_reason = ""
        all_internal = True

        for hop in parsed_hops:
            if hop["ip"] and hop["ip_classification"] == "PUBLIC":
                all_internal = False
                earliest_reliable_ip = hop["ip"]
                earliest_hop_idx = hop["hop_index"]
                selection_reason = f"Hop {earliest_hop_idx} was the earliest publicly routable IP in the transmission path."
                break

        # If not found in Received chain, cross-check aux headers (Authentication-Results, X-Originating-IP)
        if not earliest_reliable_ip and aux_headers:
            for k in ["x-originating-ip", "x-sender-ip"]:
                val = aux_headers.get(k) or aux_headers.get(k.lower())
                if val:
                    cand = val.strip("[] \t\r\n")
                    if self.classify_ip(cand) == "PUBLIC":
                        earliest_reliable_ip = cand
                        all_internal = False
                        selection_reason = f"Cross-checked from authenticated {k} header."
                        break

            if not earliest_reliable_ip:
                auth_res = aux_headers.get("authentication-results") or ""
                auth_ip_match = re.search(r"sender\s+IP\s+is\s+([0-9a-fA-F.:]+)", auth_res, re.IGNORECASE)
                if auth_ip_match:
                    cand = auth_ip_match.group(1).strip()
                    if self.classify_ip(cand) == "PUBLIC":
                        earliest_reliable_ip = cand
                        all_internal = False
                        selection_reason = "Extracted from SPF sender IP evaluation in Authentication-Results."

        # Check if there were hops but they were all non-public (internal network)
        if all_internal and parsed_hops:
            origin_not_determinable = True
            reason = "No external relay detected — email originated within a private or local network"
            selection_reason = "All observed hops represent private, loopback, or non-routable addresses."
        else:
            origin_not_determinable = earliest_reliable_ip is None
            reason = (
                f"Earliest reliable observed relay identified at hop {earliest_hop_idx}."
                if earliest_hop_idx
                else selection_reason or "No verifiable public IP hop found before breaks or external unverified headers in relay chain."
            )

        return {
            "relay_chain": parsed_hops,
            "all_observed_ips": all_observed_ips,
            "hop_count": len(parsed_hops),
            "total_hops": len(parsed_hops),
            "earliest_public_hop": earliest_reliable_ip,
            "earliest_reliable_observed_ip": earliest_reliable_ip or "ORIGIN_NOT_DETERMINABLE",
            "origin_not_determinable": origin_not_determinable,
            "selection_reason": selection_reason,
            "reason": reason,
            "disclaimer": GEO_DISCLAIMER,
        }

    def enrich_relay_chain(
        self,
        relay_chain_data: Dict[str, Any],
        resolved_ips: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Attach GeoIP results to public hops and explicit notes to other hops."""
        resolved_by_ip = {
            item.get("ip"): item
            for item in resolved_ips
            if item.get("ip")
        }
        for hop in relay_chain_data.get("relay_chain", []):
            hop_ip = hop.get("ip")
            if hop.get("ip_classification") == "PUBLIC" and hop_ip:
                hop_geo = resolved_by_ip.get(hop_ip)
                hop["geolocation"] = (
                    hop_geo if hop_geo and not hop_geo.get("error") else None
                )
                hop["note"] = (
                    "Public routable relay; approximate infrastructure location shown."
                    if hop["geolocation"]
                    else "Public relay; geolocation lookup unavailable."
                )
            else:
                hop["geolocation"] = None
                if hop_ip:
                    hop["note"] = (
                        f"Internal relay ({hop.get('ip_classification', 'NON_PUBLIC').lower()}) "
                        "— not routable; no geolocation applicable."
                    )

        relay_chain_data["earliest_public_hop"] = relay_chain_data.get(
            "earliest_reliable_observed_ip"
        )
        return relay_chain_data

    _geoip_cache: Dict[str, Dict[str, Any]] = {}

    # ── GeoIP private provider methods ──────────────────────────────────────

    def _try_ipinfo(self, ip: str) -> Optional[Dict[str, Any]]:
        """IPinfo's token-backed IP geolocation endpoint."""
        if not IPINFO_TOKEN:
            return None

        try:
            resp = requests.get(
                f"https://ipinfo.io/{ip}/json",
                params={"token": IPINFO_TOKEN},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict) or not data.get("country") or data.get("bogon"):
                logger.warning("ipinfo.io: response contained no public-IP location for %s", ip)
                return None

            latitude = longitude = None
            location = data.get("loc", "")
            if isinstance(location, str):
                try:
                    latitude_text, longitude_text = location.split(",", 1)
                    latitude, longitude = float(latitude_text), float(longitude_text)
                except (TypeError, ValueError):
                    logger.warning("ipinfo.io: invalid coordinates for %s", ip)

            organization = data.get("org") or ""
            as_number = organization.split(" ", 1)[0] if organization.startswith("AS") else ""
            return {
                "ip": ip,
                "ip_classification": "PUBLIC",
                "infrastructure_type": self.detect_infrastructure_type(ip, organization),
                "country": data.get("country", "Unknown"),
                "country_code": data.get("country", ""),
                "region": data.get("region", ""),
                "city": data.get("city", "Unknown"),
                "lat": latitude,
                "lon": longitude,
                "timezone": data.get("timezone", ""),
                "isp": organization or "Unknown",
                "org": organization,
                "as_number": as_number,
                "source": "ipinfo.io",
                "disclaimer": GEO_DISCLAIMER,
            }
        except Exception as e:
            logger.warning(
                "ipinfo.io: lookup failed for %s (%s)",
                ip,
                type(e).__name__,
            )
        return None

    def _try_ip_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """Primary: ip-api.com — 45 req/min free, no key needed."""
        try:
            resp = requests.get(
                f"{GEOIP_API_BASE}/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
                timeout=4,
            )
            data = resp.json()
            if data.get("status") == "success":
                asn_org = f"{data.get('as', '')} {data.get('org', '')} {data.get('isp', '')}"
                return {
                    "ip": ip,
                    "ip_classification": "PUBLIC",
                    "infrastructure_type": self.detect_infrastructure_type(ip, asn_org),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", "Unknown"),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "timezone": data.get("timezone", ""),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", ""),
                    "as_number": data.get("as", ""),
                    "source": "ip-api.com",
                    "disclaimer": GEO_DISCLAIMER,
                }
            logger.warning(f"ip-api.com: non-success for {ip}: {data.get('message')}")
        except Exception as e:
            logger.warning(f"ip-api.com: exception for {ip}: {e}")
        return None

    def _try_freeipapi(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fallback-1: freeipapi.com — no key, no strict rate limit."""
        try:
            resp = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=5)
            data = resp.json()
            if data.get("countryName"):
                asn_org = data.get("isp") or ""
                return {
                    "ip": ip,
                    "ip_classification": "PUBLIC",
                    "infrastructure_type": self.detect_infrastructure_type(ip, asn_org),
                    "country": data.get("countryName", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("cityName", "Unknown"),
                    "lat": float(data.get("latitude", 0.0)),
                    "lon": float(data.get("longitude", 0.0)),
                    "timezone": data.get("timeZone", ""),
                    "isp": data.get("isp") or "Unknown",
                    "org": data.get("isp") or "",
                    "as_number": None,
                    "source": "freeipapi.com",
                    "disclaimer": GEO_DISCLAIMER,
                }
            logger.warning(f"freeipapi.com: no countryName for {ip}")
        except Exception as e:
            logger.warning(f"freeipapi.com: exception for {ip}: {e}")
        return None

    def _try_ipwho(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fallback-2: ipwho.is — no key, generous limits."""
        try:
            resp = requests.get(f"https://ipwho.is/{ip}", timeout=4)
            data = resp.json()
            if data.get("success") is True:
                connection = data.get("connection", {})
                asn_org = f"{connection.get('asn', '')} {connection.get('org', '')} {connection.get('isp', '')}"
                return {
                    "ip": ip,
                    "ip_classification": "PUBLIC",
                    "infrastructure_type": self.detect_infrastructure_type(ip, asn_org),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("country_code", ""),
                    "region": data.get("region", ""),
                    "city": data.get("city", "Unknown"),
                    "lat": float(data.get("latitude", 0.0)),
                    "lon": float(data.get("longitude", 0.0)),
                    "timezone": data.get("timezone", {}).get("id", ""),
                    "isp": connection.get("isp", "Unknown"),
                    "org": connection.get("org", ""),
                    "as_number": f"AS{connection.get('asn', '')} {connection.get('org', '')}".strip(),
                    "source": "ipwho.is",
                    "disclaimer": GEO_DISCLAIMER,
                }
            logger.warning(f"ipwho.is: non-success for {ip}")
        except Exception as e:
            logger.error(f"ipwho.is: exception for {ip}: {e}")
        return None

    def resolve_geoip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a public IP using IPinfo when configured, then the free fallback
        chain (ip-api.com, freeipapi.com, and ipwho.is).

        Each failed provider is logged and the next one is tried automatically.
        Results are cached in-memory to avoid repeated lookups and respect limits.
        The `source` field on every successful result shows which provider answered.
        """
        ip_clean = (ip or "").strip()
        if ip_clean in self._geoip_cache:
            return self._geoip_cache[ip_clean]

        ip_class = self.classify_ip(ip_clean)
        if ip_class != "PUBLIC":
            res = {
                "ip": ip_clean,
                "ip_classification": ip_class,
                "error": f"{ip_class} address — not an Internet origin",
                "disclaimer": GEO_DISCLAIMER,
            }
            self._geoip_cache[ip_clean] = res
            return res

        # Prefer the configured key-backed provider; retain free providers as fallbacks.
        if IPINFO_TOKEN:
            result = self._try_ipinfo(ip_clean)
            if result:
                logger.info("GeoIP resolved via ipinfo.io for %s", ip_clean)
                self._geoip_cache[ip_clean] = result
                return result

        # Provider chain: ip-api → freeipapi → ipwho
        result = self._try_ip_api(ip_clean)
        if result:
            logger.info(f"GeoIP resolved via ip-api.com for {ip_clean}")
            self._geoip_cache[ip_clean] = result
            return result

        result = self._try_freeipapi(ip_clean)
        if result:
            logger.info(f"GeoIP resolved via freeipapi.com (fallback-1) for {ip_clean}")
            self._geoip_cache[ip_clean] = result
            return result

        result = self._try_ipwho(ip_clean)
        if result:
            logger.info(f"GeoIP resolved via ipwho.is (fallback-2) for {ip_clean}")
            self._geoip_cache[ip_clean] = result
            return result

        error_res = {
            "ip": ip_clean,
            "ip_classification": "PUBLIC",
            "error": "All GeoIP providers failed or rate-limited",
            "source": "none",
            "disclaimer": GEO_DISCLAIMER,
        }
        logger.error(f"All GeoIP providers exhausted for {ip_clean}")
        self._geoip_cache[ip_clean] = error_res
        return error_res

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
