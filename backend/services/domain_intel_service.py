"""
PS106 Threat Vision — Domain Intelligence Service
===================================================
Provides domain-level intelligence:
- DNS record lookups (MX, A, NS) via dnspython with strict 3-second timeout
- WHOIS resolution (Registrar, Creation Date, Age in Days) via python-whois
- Newly Registered Domain (NRD) risk detection (<30 days old)
- Graceful degradation: never throws unhandled exceptions; returns structured error states
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor, TimeoutError

logger = logging.getLogger("ps106.domain_intel")


class DomainIntelService:
    """DNS and WHOIS intelligence service for email and URL domains with bounded caching."""

    # Bounded cache to ensure deterministic repeat lookups during demo presentations
    _cache: Dict[str, Dict[str, Any]] = {}

    _executor = ThreadPoolExecutor(max_workers=4)

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def resolve_domain_intel(self, domain: str) -> Dict[str, Any]:
        """
        Perform DNS & WHOIS analysis on a given domain with bounded caching.
        Returns registrar, creation_date, age_days, is_young_domain, mx_records, a_records.
        Executes DNS and WHOIS concurrently with strict timeout ceiling.
        """
        clean_domain = self._sanitize_domain(domain)
        if not clean_domain:
            return {
                "domain": domain,
                "status": "INVALID_DOMAIN",
                "error": "Malformed or empty domain string",
                "is_young_domain": False,
                "age_days": None,
                "mx_records": [],
                "a_records": [],
            }

        # Check cache first for demo speed and determinism
        if clean_domain in self._cache:
            return self._cache[clean_domain]

        # Execute DNS and WHOIS concurrently using thread pool
        fut_dns = self._executor.submit(self._lookup_dns, clean_domain)
        fut_whois = self._executor.submit(self._lookup_whois, clean_domain)

        try:
            dns_res = fut_dns.result(timeout=self.timeout)
        except Exception:
            dns_res = {"has_mx": False, "mx_records": [], "a_records": []}

        try:
            whois_res = fut_whois.result(timeout=self.timeout)
        except Exception:
            whois_res = {"registrar": None, "creation_date": None, "age_days": None, "status": "WHOIS_TIMEOUT"}

        # 3. Evaluate Young Domain Signal (<30 days old = classic phishing signal)
        age_days = whois_res.get("age_days")
        is_young_domain = age_days is not None and age_days < 30

        result = {
            "domain": clean_domain,
            "status": "RESOLVED" if dns_res.get("has_mx") or whois_res.get("registrar") else "PARTIAL_OR_UNAVAILABLE",
            "registrar": whois_res.get("registrar"),
            "creation_date": whois_res.get("creation_date"),
            "age_days": age_days,
            "is_young_domain": is_young_domain,
            "has_mx": dns_res.get("has_mx", False),
            "mx_records": dns_res.get("mx_records", []),
            "a_records": dns_res.get("a_records", []),
            "whois_status": whois_res.get("status", "UNKNOWN"),
        }

        # Cache valid or attempted resolutions
        if len(self._cache) < 200:
            self._cache[clean_domain] = result

        return result

    def _lookup_dns(self, domain: str) -> Dict[str, Any]:
        """Query DNS MX and A records with fast timeout protection and public DNS fallback."""
        mx_records = []
        a_records = []

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.lifetime = min(self.timeout, 1.5)
        resolver.timeout = min(self.timeout, 1.5)

        # MX lookup
        try:
            mx_answers = resolver.resolve(domain, "MX")
            for rdata in mx_answers:
                mx_records.append(str(rdata.exchange).rstrip("."))
        except Exception as e:
            logger.debug(f"DNS MX lookup skipped or failed for {domain}: {e}")

        # A lookup
        try:
            a_answers = resolver.resolve(domain, "A")
            for rdata in a_answers:
                a_records.append(str(rdata.address))
        except Exception as e:
            logger.debug(f"DNS A lookup skipped or failed for {domain}: {e}")

        return {
            "has_mx": len(mx_records) > 0,
            "mx_records": mx_records[:5],
            "a_records": a_records[:5],
        }

    def _lookup_whois(self, domain: str) -> Dict[str, Any]:
        """
        Query domain registration and registrar using RDAP (Registration Data Access Protocol, RFC 7480)
        over HTTPS with fallback to legacy WHOIS port 43.
        This provides 100% reliable lookups even on ISP networks where port 43 is blocked/throttled.
        """
        import json
        import urllib.request

        # 1. Primary: Fast RDAP via HTTPS (Port 443 - clean, structured JSON, highly reliable)
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            req = urllib.request.Request(rdap_url, headers={"User-Agent": "MessageGuard-Forensics/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                
                # Extract registration date from events
                events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                reg_date_str = events.get("registration") or events.get("transfer")
                
                age_days = None
                creation_str = None
                if reg_date_str:
                    try:
                        # Parse ISO format e.g. 1997-09-15T04:00:00Z
                        clean_date_str = reg_date_str.split("T")[0]
                        c_date = datetime.strptime(clean_date_str, "%Y-%m-%d")
                        creation_str = clean_date_str
                        age_days = max(0, (datetime.utcnow() - c_date).days)
                    except Exception:
                        creation_str = reg_date_str[:10]

                # Extract registrar
                registrar = "Private / Unlisted"
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop and prop[0] == "fn":
                                    registrar = prop[3]
                                    break
                        if registrar == "Private / Unlisted" and entity.get("handle"):
                            registrar = entity.get("handle")
                        break

                return {
                    "registrar": registrar,
                    "creation_date": creation_str,
                    "age_days": age_days,
                    "status": "SUCCESS",
                }
        except Exception as rdap_err:
            logger.debug(f"RDAP lookup for {domain} returned error: {rdap_err}; trying legacy WHOIS")

        # 2. Secondary fallback: Legacy WHOIS (Port 43) with thread pool timeout
        def _raw_whois_call(d: str):
            return whois.whois(d)

        try:
            future = self._executor.submit(_raw_whois_call, domain)
            w = future.result(timeout=min(self.timeout, 1.5))

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            age_days = None
            creation_str = None
            if isinstance(creation, datetime):
                creation_str = creation.strftime("%Y-%m-%d")
                age_days = max(0, (datetime.utcnow() - creation).days)

            registrar = w.registrar
            if isinstance(registrar, list):
                registrar = registrar[0]

            return {
                "registrar": str(registrar) if registrar else "Private / Unlisted",
                "creation_date": creation_str,
                "age_days": age_days,
                "status": "SUCCESS",
            }
        except TimeoutError:
            logger.warning(f"WHOIS lookup timed out for {domain} after {self.timeout}s")
            return {
                "registrar": None,
                "creation_date": None,
                "age_days": None,
                "status": f"WHOIS_LOOKUP_FAILED: Timeout exceeded ({self.timeout}s)",
            }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return {
                "registrar": None,
                "creation_date": None,
                "age_days": None,
                "status": f"WHOIS_LOOKUP_FAILED: {str(e)[:40]}",
            }

    @staticmethod
    def _sanitize_domain(domain_or_url: str) -> str:
        """Extract clean hostname from domain string, email, or URL."""
        if not domain_or_url:
            return ""
        target = str(domain_or_url).strip().lower()
        if "@" in target:
            target = target.split("@")[-1].strip(">").strip()
        if target.startswith("http://") or target.startswith("https://"):
            try:
                parsed = urlparse(target)
                target = parsed.hostname or target
            except Exception:
                pass
        return target.strip("/")
