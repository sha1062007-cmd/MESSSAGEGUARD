import sys
import os
import time
sys.path.append(os.path.abspath("."))

from services.report_service import ReportService, _report_store, DB_PATH, REPORTS_DIR
from services.domain_intel_service import DomainIntelService

print("====================================================")
print("1. TESTING PERSISTENCE ACROSS RESTART SIMULATION")
print("====================================================")
report_service = ReportService()

# Create dummy analysis result
mock_analysis = {
    "verdict": "MALICIOUS",
    "risk_score": 92,
    "email_metadata": {
        "sender": "attacker@evil-domain.com",
        "to": "user@victim.com",
        "subject": "Wire transfer requested",
        "date": "2026-09-24T22:00:00Z",
        "message_id": "<persist-test-123@evil.com>",
    },
    "authentication": {
        "domain_authorization_status": "DOMAIN_UNAUTHORIZED",
        "forensic_note": "SPF failed."
    },
    "content_analysis": {
        "primary_category": "BEC",
        "secondary_categories": ["FRAUD"],
        "content_risk_score": 90,
        "risk_factors": ["Wire transfer request"],
    },
    "geoip_data": {
        "relay_ips": ["203.0.113.5"],
        "resolved_ips": [],
        "relay_analysis": {},
        "relay_chain_data": {},
    },
    "score_breakdown": {
        "content": {"score": 90, "weight": 60},
        "auth": {"score": 95, "weight": 40},
    },
}

# 1. Generate Report
case_id = report_service.generate_report(mock_analysis)
print(f"Generated case ID: {case_id}")
pdf_on_disk = os.path.join(REPORTS_DIR, f"{case_id}.pdf")
print(f"PDF exists on disk: {os.path.exists(pdf_on_disk)} (Size: {os.path.getsize(pdf_on_disk)} bytes)")

# 2. Simulate Backend Crash / Restart (Wipe in-memory store completely)
print("\n--- Simulating complete backend crash / process restart ---")
_report_store.clear()
print(f"In-memory store count after wipe: {len(_report_store)}")

# 3. Retrieve Report by Case ID
recovered_pdf = report_service.get_report(case_id)
print(f"Recovered PDF from persistent storage: {recovered_pdf is not None} ({len(recovered_pdf) if recovered_pdf else 0} bytes)")
assert recovered_pdf is not None and len(recovered_pdf) > 1000, "Persistence recovery failed!"

# 4. List Reports from SQLite
all_reports = report_service.list_reports()
print(f"Listed {len(all_reports)} cases from persistent SQLite database.")
found_case = any(c["case_id"] == case_id for c in all_reports)
print(f"Target case present in SQLite list: {found_case}")
assert found_case, "Case record missing in SQLite!"

print("\n====================================================")
print("2. TESTING WHOIS DETERMINISM & BOUNDED CACHE")
print("====================================================")
d_intel = DomainIntelService(timeout=2.0)

t0 = time.time()
res1 = d_intel.resolve_domain_intel("chase.com")
t1 = time.time()
print(f"Lookup 1 (Network fetch): {res1['domain']} in {t1 - t0:.3f}s, Age: {res1['age_days']} days, Status: {res1['status']}")

t2 = time.time()
res2 = d_intel.resolve_domain_intel("chase.com")
t3 = time.time()
print(f"Lookup 2 (Cache hit): {res2['domain']} in {t3 - t2:.5f}s, Age: {res2['age_days']} days, Status: {res2['status']}")

assert res1["age_days"] == res2["age_days"], "Cache determinism mismatch!"
assert (t3 - t2) < 0.01, "Cache hit did not return instantly!"

print("\nALL PERSISTENCE AND DETERMINISM TESTS PASSED!")
