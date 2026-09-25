import time
import sys
from backend.services.domain_intel_service import DomainIntelService

svc = DomainIntelService(timeout=3.0)

test_domains = ["chase.com", "microsoft.com", "apple.com"]
print("--- COLD LOOKUP WALL-CLOCK TEST ---")
for d in test_domains:
    svc._cache.clear()
    t0 = time.time()
    res = svc.resolve_domain_intel(d)
    dt = time.time() - t0
    print(f"Domain: {d:<16} | Wall-clock: {dt:.2f}s | Status: {res.get('status')} | Whois: {res.get('whois_status')} | Age: {res.get('age_days')} days")
    assert dt <= 4.0, f"Wall-clock {dt}s exceeded 4.0s ceiling for {d}"
print("All lookups passed within strict timeout bounds!")
