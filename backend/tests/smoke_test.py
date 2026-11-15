"""
Live HTTP Smoke Test against running FastAPI server for NitiQ.
"""

import json
import urllib.request


def http_get(url: str):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode())


def http_post(url: str, data: dict):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode())


def main():
    base = "http://127.0.0.1:8000"

    # 1. Health
    health = http_get(f"{base}/api/health")
    print("HEALTH CHECK:")
    print(f"  Product: {health['product']}, Status: {health['status']}, Version: {health['version']}")

    # 2. Assessment: Weak vs Strong
    weak_ass = http_post(f"{base}/api/assessment", {"profile_id": "weak_org"})
    strong_ass = http_post(f"{base}/api/assessment", {"profile_id": "strong_org"})

    print("\n--- WEAK PROFILE ASSESSMENT ---")
    w_head = weak_ass["headline_metrics"]
    print(f"  Blast Radius: {w_head['blast_radius_composite_pct']}%")
    print(f"  Estimated TTD: {w_head['time_to_detect_hours']}h")
    print(f"  Recovery Time: {w_head['recovery_time_hours']}h (Status: {w_head['rto_status']})")
    print(f"  Maturity Score: {w_head['overall_maturity_score']}/100 (Tier: {w_head['maturity_tier']})")

    print("\n--- STRONG PROFILE ASSESSMENT ---")
    s_head = strong_ass["headline_metrics"]
    print(f"  Blast Radius: {s_head['blast_radius_composite_pct']}%")
    print(f"  Estimated TTD: {s_head['time_to_detect_hours']}h")
    print(f"  Recovery Time: {s_head['recovery_time_hours']}h (Status: {s_head['rto_status']})")
    print(f"  Maturity Score: {s_head['overall_maturity_score']}/100 (Tier: {s_head['maturity_tier']})")

    # 3. What-If Comparison
    whatif = http_post(
        f"{base}/api/whatif/compare",
        {
            "profile_id": "weak_org",
            "remediations": {
                "immutable_backups": True,
                "edr_on_servers": True,
                "remove_local_admin": True,
            },
        },
    )
    print("\n--- WHAT-IF COMPARISON SUMMARY (Weak Org + Immutability + EDR + Least Privilege) ---")
    for comp in whatif["comparison_summary"]:
        print(f"  {comp['metric_name']}: {comp['baseline_value']} {comp['unit']} -> {comp['remediated_value']} {comp['unit']} | {comp['interpretation']}")

    # 4. Remediation Ranking
    rankings = http_post(f"{base}/api/whatif/remediation-ranking", {"profile_id": "weak_org"})
    print("\n--- TOP REMEDIATION CANDIDATES (Ranked by Risk Reduction / Effort) ---")
    for cand in rankings["candidates"]:
        print(f"  #{cand['rank']} {cand['name']} | Effort: {cand['implementation_effort']}/5 | ROI: {cand['roi_score']} | Risk Reduction: {cand['composite_risk_reduction']}")

    print("\n[SUCCESS] Live HTTP smoke test completed with 100% valid JSON responses.")


if __name__ == "__main__":
    main()
