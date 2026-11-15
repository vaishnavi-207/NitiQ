"""
Unit tests for recovery-time estimation and RTO gap calculations.
"""

from backend.app.recovery.calculator import calculate_recovery_time


def test_recovery_time_strong_profile_within_rto(strong_profile):
    res = calculate_recovery_time(
        strong_profile,
        compromised_data_gb=1000.0,
        compromised_hosts_count=2,
        backups_compromised=False,
    )
    assert res.estimated_recovery_hours > 0
    assert res.rto_status == "WITHIN_RTO"
    assert res.rto_gap_hours <= 0
    assert res.is_model_estimate is True


def test_recovery_time_catastrophic_when_backups_wiped(weak_profile):
    # Weak profile has no immutable or offline backups
    res = calculate_recovery_time(
        weak_profile,
        compromised_data_gb=5000.0,
        compromised_hosts_count=10,
        backups_compromised=True,
    )
    assert res.rto_status == "CATASTROPHIC_DATA_LOSS"
    assert res.estimated_recovery_hours >= 168.0
    assert any("No immutable or air-gapped copies exist" in b for b in res.top_blockers)


def test_zero_compromised_data_edge_case(strong_profile):
    res = calculate_recovery_time(
        strong_profile,
        compromised_data_gb=0.0,
        compromised_hosts_count=0,
        backups_compromised=False,
    )
    assert res.total_data_to_restore_gb == 0.0
    assert res.estimated_recovery_hours >= 0.0
    assert res.rto_status == "WITHIN_RTO"


def test_empty_backup_repos_edge_case(minimal_profile):
    minimal_profile.backup_repositories = []
    res = calculate_recovery_time(minimal_profile)
    assert res.rto_status == "CATASTROPHIC_DATA_LOSS"
    assert any("No backup repositories registered" in b for b in res.top_blockers)
