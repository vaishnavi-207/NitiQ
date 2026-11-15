"""
Unit tests for deterministic time-stepped ransomware spread simulation.
"""

import pytest
from backend.app.simulation.engine import run_simulation, evaluate_patient_zero_rankings
from backend.app.simulation.assumptions import SimulationAssumptions


def test_simulation_reproducibility(weak_profile):
    res1 = run_simulation(weak_profile, patient_zero_id="user-02")
    res2 = run_simulation(weak_profile, patient_zero_id="user-02")

    assert res1.blast_radius.composite_blast_radius_pct == res2.blast_radius.composite_blast_radius_pct
    assert res1.blast_radius.compromised_hosts == res2.blast_radius.compromised_hosts
    assert res1.blast_radius.encrypted_data_gb == res2.blast_radius.encrypted_data_gb
    assert res1.total_steps == res2.total_steps


def test_simulation_timeline_monotonicity(weak_profile):
    res = run_simulation(weak_profile, patient_zero_id="user-02")
    prev_comp = 0
    prev_enc = 0.0

    for step in res.timeline:
        assert step.total_compromised_count >= prev_comp
        assert step.encrypted_data_gb >= prev_enc
        prev_comp = step.total_compromised_count
        prev_enc = step.encrypted_data_gb


def test_backup_compromise_weak_vs_strong(weak_profile, strong_profile):
    weak_res = run_simulation(weak_profile, patient_zero_id="user-02")
    strong_res = run_simulation(strong_profile, patient_zero_id="user-02")

    # In weak org, un-isolated online NAS backups get compromised
    assert weak_res.blast_radius.backups_compromised_flag is True

    # In strong org, immutable & airgapped backups survive
    assert strong_res.blast_radius.immutable_backups_survived is True
    assert strong_res.blast_radius.backup_repositories_compromised == 0


def test_patient_zero_ranking(weak_profile):
    rankings = evaluate_patient_zero_rankings(weak_profile, max_candidates=10)
    assert rankings.total_evaluated == 10
    assert len(rankings.rankings) == 10
    assert rankings.worst_case_patient_zero.rank == 1

    # Check sort order: descending by risk_score
    for i in range(len(rankings.rankings) - 1):
        assert rankings.rankings[i].risk_score >= rankings.rankings[i + 1].risk_score


def test_invalid_patient_zero_raises_error(weak_profile):
    with pytest.raises(ValueError, match="does not exist in organization profile"):
        run_simulation(weak_profile, patient_zero_id="non-existent-user")
