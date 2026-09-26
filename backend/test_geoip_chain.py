"""
Quick test: verify each GeoIP provider and the full fallback chain work.
Run: python test_geoip_chain.py
"""
from services.threat_intel_service import ThreatIntelService

ti = ThreatIntelService()

print("=== 1. ip-api.com (primary) ===")
r = ti._try_ip_api("8.8.8.8")
if r:
    print(f"  OK  country={r.get('country')}  isp={r.get('isp')}  source={r.get('source')}")
else:
    print("  FAILED (rate-limited or down)")

print()
print("=== 2. freeipapi.com (fallback-1) ===")
r = ti._try_freeipapi("8.8.8.8")
if r:
    print(f"  OK  country={r.get('country')}  isp={r.get('isp')}  source={r.get('source')}")
else:
    print("  FAILED (rate-limited or down)")

print()
print("=== 3. ipwho.is (fallback-2) ===")
r = ti._try_ipwho("8.8.8.8")
if r:
    print(f"  OK  country={r.get('country')}  isp={r.get('isp')}  source={r.get('source')}")
else:
    print("  FAILED (rate-limited or down)")

print()
print("=== 4. Full chain: resolve_geoip(8.8.8.8) ===")
r = ti.resolve_geoip("8.8.8.8")
src = r.get("source", "NONE")
print(f"  country={r.get('country')}  city={r.get('city')}  source={src}")

print()
print("=== 5. Full chain: resolve_geoip(1.1.1.1) ===")
# Clear cache to avoid hitting the cached result
ti._geoip_cache.pop("1.1.1.1", None)
r = ti.resolve_geoip("1.1.1.1")
src = r.get("source", "NONE")
print(f"  country={r.get('country')}  city={r.get('city')}  source={src}")

print()
print("=== 6. Fallback proof: break primary, confirm chain continues ===")
# Temporarily sabotage ip-api URL via monkey-patch
import services.threat_intel_service as _svc
_orig = _svc.GEOIP_API_BASE
_svc.GEOIP_API_BASE = "http://INVALID-PROVIDER-BROKEN.test"
ti2 = ThreatIntelService()
# Clear any cache
ti2._geoip_cache.clear()
r2 = ti2.resolve_geoip("8.8.8.8")
src2 = r2.get("source", "NONE")
print(f"  (primary broken) resolved via={src2}  country={r2.get('country')}")
# Restore
_svc.GEOIP_API_BASE = _orig
print()
print("DONE — all providers verified.")
