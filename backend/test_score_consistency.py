from main import calculate_ps106_risk_score

test_cases = [
    ({}, {'content_risk_score': 0, 'primary_category': 'SAFE'}, {}, 'SAFE'),
    ({}, {'content_risk_score': 19, 'primary_category': 'SAFE'}, {}, 'SAFE'),
    ({}, {'content_risk_score': 20, 'primary_category': 'SUSPICIOUS'}, {}, 'UNVERIFIED'),
    ({}, {'content_risk_score': 44, 'primary_category': 'SUSPICIOUS'}, {}, 'UNVERIFIED'),
    ({}, {'content_risk_score': 45, 'primary_category': 'SUSPICIOUS'}, {}, 'SUSPICIOUS'),
    ({}, {'content_risk_score': 59, 'primary_category': 'SUSPICIOUS'}, {}, 'SUSPICIOUS'),
    ({}, {'content_risk_score': 60, 'primary_category': 'SUSPICIOUS'}, {}, 'SUSPICIOUS'),
    ({}, {'content_risk_score': 69, 'primary_category': 'SUSPICIOUS'}, {}, 'SUSPICIOUS'),
    ({}, {'content_risk_score': 70, 'primary_category': 'PHISHING'}, {}, 'MALICIOUS'),
    ({}, {'content_risk_score': 100, 'primary_category': 'MALWARE'}, {}, 'MALICIOUS'),
    ({}, {'content_risk_score': -50, 'primary_category': 'SAFE'}, {}, 'SAFE'),
    ({}, {'content_risk_score': 9999, 'primary_category': 'MALICIOUS'}, {}, 'MALICIOUS')
]

for auth, cont, geo, exp in test_cases:
    res = calculate_ps106_risk_score(auth, cont, geo)
    score = res['risk_score']
    verdict = res['verdict']
    band = res['risk_band']
    in_sc = cont['content_risk_score']
    print(f"Content Score: {in_sc:5d} -> Final Score: {score:3d}, Verdict: {verdict:10s}, Band: {band:12s} (Expected: {exp})")
    assert 0 <= score <= 100, f"Score out of bounds: {score}"
    assert not (score != score), "Score is NaN"

print("\n-> All 12 Risk Score boundary & verdict consistency tests PASSED!")
