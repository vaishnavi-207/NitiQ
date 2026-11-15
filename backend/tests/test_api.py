"""
Integration tests for NitiQ FastAPI endpoints using starlette TestClient.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_root_and_health():
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["product"] == "NitiQ"

    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    data = res_health.json()
    assert data["product"] == "NitiQ"
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data


def test_get_assumptions():
    res = client.get("/api/assumptions")
    assert res.status_code == 200
    data = res.json()
    assert "step_duration_minutes" in data
    assert "encryption_throughput_mb_s" in data


def test_get_organizations():
    res = client.get("/api/organizations")
    assert res.status_code == 200
    orgs = res.json()
    assert len(orgs) >= 3
    ids = [o["id"] for o in orgs]
    assert "weak_org" in ids
    assert "strong_org" in ids


def test_get_specific_organization():
    res = client.get("/api/organizations/weak_org")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "weak_org"
    assert len(data["users"]) == 40
    assert len(data["hosts"]) == 23

    res_404 = client.get("/api/organizations/nonexistent_org")
    assert res_404.status_code == 404


def test_validate_organization_endpoint(weak_profile):
    # Valid submission
    res_valid = client.post("/api/organizations/validate", json=weak_profile.model_dump())
    assert res_valid.status_code == 200
    assert res_valid.json()["valid"] is True

    # Invalid submission
    invalid_data = weak_profile.model_dump()
    invalid_data["hosts"][0]["segment_id"] = "seg-broken-ref"
    res_invalid = client.post("/api/organizations/validate", json=invalid_data)
    assert res_invalid.status_code == 422


def test_assessment_endpoint():
    res = client.post("/api/assessment", json={"profile_id": "weak_org"})
    assert res.status_code == 200
    data = res.json()
    assert data["organization_id"] == "weak_org"
    assert "headline_metrics" in data
    assert "simulation" in data
    assert "recovery" in data
    assert "scoring" in data


def test_simulation_run_endpoint():
    payload = {
        "profile_id": "weak_org",
        "patient_zero_id": "user-02",
        "max_hours": 12.0,
    }
    res = client.post("/api/simulation/run", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["patient_zero_id"] == "user-02"
    assert "blast_radius" in data
    assert "timeline" in data


def test_simulation_patient_zero_ranking_endpoint():
    payload = {
        "profile_id": "weak_org",
        "max_candidates": 5,
    }
    res = client.post("/api/simulation/patient-zero-ranking", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_evaluated"] == 5
    assert len(data["rankings"]) == 5


def test_recovery_estimate_endpoint():
    payload = {
        "profile_id": "weak_org",
        "compromised_data_gb": 3500.0,
        "compromised_hosts_count": 8,
        "backups_compromised": False,
    }
    res = client.post("/api/recovery/estimate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["estimated_recovery_hours"] > 0
    assert "rto_status" in data
    assert "recovery_breakdown" in data


def test_scoring_evaluate_endpoint():
    res = client.post("/api/scoring/evaluate", json={"profile_id": "strong_org"})
    assert res.status_code == 200
    data = res.json()
    assert data["overall_score"] > 80.0
    assert data["maturity_tier"] == "Optimized"


def test_whatif_compare_endpoint():
    payload = {
        "profile_id": "weak_org",
        "remediations": {
            "enforce_mfa_admin": True,
            "immutable_backups": True,
            "edr_on_servers": True,
        },
        "patient_zero_id": "user-02",
    }
    res = client.post("/api/whatif/compare", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "baseline_blast_radius" in data
    assert "remediated_blast_radius" in data
    assert "comparison_summary" in data


def test_whatif_remediation_ranking_endpoint():
    payload = {
        "profile_id": "weak_org",
        "patient_zero_id": "user-02",
    }
    res = client.post("/api/whatif/remediation-ranking", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert len(data["candidates"]) == 6
    assert data["candidates"][0]["rank"] == 1
