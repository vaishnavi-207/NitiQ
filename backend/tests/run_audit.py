"""
Phase 1 Deep Audit Script for NitiQ.
Queries real running endpoints and validates all requirements from user prompt.
"""

import json
import urllib.request
import urllib.error
import sys


def req(method: str, url: str, data: dict = None):
    headers = {"Content-Type": "application/json"} if data else {}
    body = json.dumps(data).encode("utf-8") if data else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as resp:
            status_code = resp.getcode()
            res_body = json.loads(resp.read().decode("utf-8"))
            return status_code, res_body
    except urllib.error.HTTPError as e:
        status_code = e.code
        try:
            err_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            err_body = str(e)
        return status_code, err_body


def audit():
    base = "http://127.0.0.1:8000"
    results = {}

    # 1. Health Endpoint
    st, body = req("GET", f"{base}/api/health")
    results["health"] = {"status": st, "body": body}

    # 2. Organization Profiles Endpoint
    st, body = req("GET", f"{base}/api/organizations")
    results["organizations_list"] = {"status": st, "body": body}

    st, body = req("GET", f"{base}/api/organizations/weak_org")
    results["organization_weak_detail"] = {
        "status": st,
        "sample": {
            "id": body["id"],
            "name": body["name"],
            "users_count": len(body["users"]),
            "hosts_count": len(body["hosts"]),
            "shares_count": len(body["file_shares"]),
            "backups_count": len(body["backup_repositories"]),
        },
    }

    # 3. Assessment Endpoint: Weak, Average, Strong comparison
    profiles = ["weak_org", "average_org", "strong_org"]
    profiles_comparison = {}
    for pid in profiles:
        st, body = req("POST", f"{base}/api/assessment", {"profile_id": pid})
        head = body["headline_metrics"]
        profiles_comparison[pid] = {
            "status": st,
            "blast_radius_composite_pct": head["blast_radius_composite_pct"],
            "time_to_detect_hours": head["time_to_detect_hours"],
            "recovery_time_hours": head["recovery_time_hours"],
            "rto_status": head["rto_status"],
            "required_rto_hours": head["required_rto_hours"],
            "rto_gap_hours": head["rto_gap_hours"],
            "overall_maturity_score": head["overall_maturity_score"],
            "maturity_tier": head["maturity_tier"],
            "worst_case_pz": body["worst_case_patient_zero"]["entity_id"],
        }
    results["profiles_comparison"] = profiles_comparison

    # 4. What-If Comparison: None vs Each remediation individually vs All combined
    remediations_list = [
        ("none", {}),
        ("enforce_mfa_admin", {"enforce_mfa_admin": True}),
        ("immutable_backups", {"immutable_backups": True}),
        ("finance_segmentation", {"finance_segmentation": True}),
        ("remove_local_admin", {"remove_local_admin": True}),
        ("offline_backup_copy", {"offline_backup_copy": True}),
        ("edr_on_servers", {"edr_on_servers": True}),
        (
            "all_combined",
            {
                "enforce_mfa_admin": True,
                "immutable_backups": True,
                "finance_segmentation": True,
                "remove_local_admin": True,
                "offline_backup_copy": True,
                "edr_on_servers": True,
            },
        ),
    ]

    whatif_results = {}
    for name, controls in remediations_list:
        st, body = req(
            "POST",
            f"{base}/api/whatif/compare",
            {"profile_id": "weak_org", "remediations": controls},
        )
        whatif_results[name] = {
            "status": st,
            "baseline_blast_radius": body["baseline_blast_radius"]["composite_blast_radius_pct"],
            "remediated_blast_radius": body["remediated_blast_radius"]["composite_blast_radius_pct"],
            "baseline_ttd": body["baseline_ttd"]["estimated_ttd_hours"],
            "remediated_ttd": body["remediated_ttd"]["estimated_ttd_hours"],
            "baseline_recovery": body["baseline_recovery"]["estimated_recovery_hours"],
            "remediated_recovery": body["remediated_recovery"]["estimated_recovery_hours"],
            "remediated_rto_status": body["remediated_recovery"]["rto_status"],
            "baseline_maturity": body["baseline_maturity"]["overall_score"],
            "remediated_maturity": body["remediated_maturity"]["overall_score"],
        }
    results["whatif_results"] = whatif_results

    # 5. What-If Remediation Ranking
    st, body = req(
        "POST",
        f"{base}/api/whatif/remediation-ranking",
        {"profile_id": "weak_org"},
    )
    results["remediation_ranking"] = {
        "status": st,
        "formula": body["formula_documentation"],
        "candidates": [
            {
                "rank": c["rank"],
                "name": c["name"],
                "effort": c["implementation_effort"],
                "risk_reduction": c["composite_risk_reduction"],
                "roi_score": c["roi_score"],
            }
            for c in body["candidates"]
        ],
    }

    # 6. Error & Edge Case Checks
    # A. Non-existent organization
    st_404, body_404 = req("GET", f"{base}/api/organizations/nonexistent_xyz")
    # B. Missing graph node / invalid patient zero
    st_bad_pz, body_bad_pz = req(
        "POST",
        f"{base}/api/simulation/run",
        {"profile_id": "weak_org", "patient_zero_id": "nonexistent_hacker_123"},
    )
    # C. Invalid / zero throughput in recovery
    st_rec_zero, body_rec_zero = req(
        "POST",
        f"{base}/api/recovery/estimate",
        {"profile_id": "weak_org", "compromised_data_gb": 0.0},
    )
    # D. Schema validation with missing segment reference
    broken_org = {
        "id": "broken_test",
        "name": "Broken Test",
        "required_rto_hours": 24.0,
        "required_rpo_hours": 12.0,
        "network_segments": [
            {"id": "seg-1", "name": "S1", "cidr": "10.0.0.0/24", "zone_type": "workstations"}
        ],
        "hosts": [
            {
                "id": "h-1",
                "hostname": "H1",
                "ip_address": "10.0.0.5",
                "segment_id": "seg-missing",
            }
        ],
    }
    st_val, body_val = req("POST", f"{base}/api/organizations/validate", broken_org)

    results["edge_cases"] = {
        "nonexistent_org": {"status": st_404, "body": body_404},
        "invalid_patient_zero": {"status": st_bad_pz, "body": body_bad_pz},
        "recovery_zero_data": {
            "status": st_rec_zero,
            "recovery_hours": body_rec_zero.get("estimated_recovery_hours"),
            "rto_status": body_rec_zero.get("rto_status"),
        },
        "schema_validation_broken_ref": {"status": st_val, "body": body_val},
    }

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    audit()
