"""
Unit tests for What-If scenario engine and remediation candidate ranking.
"""

from backend.app.models.whatif import RemediationControls
from backend.app.whatif.engine import apply_remediations, run_whatif_comparison
from backend.app.whatif.ranking import rank_remediation_candidates


def test_whatif_does_not_mutate_source_profile(weak_profile):
    orig_hosts_edr = [h.edr_installed for h in weak_profile.hosts]
    orig_users_mfa = [u.mfa_enabled for u in weak_profile.users]

    controls = RemediationControls(
        enforce_mfa_admin=True,
        immutable_backups=True,
        finance_segmentation=True,
        remove_local_admin=True,
        offline_backup_copy=True,
        edr_on_servers=True,
    )

    cloned = apply_remediations(weak_profile, controls)

    # Cloned profile was modified
    assert any(h.edr_installed for h in cloned.hosts)
    assert any(u.mfa_enabled for u in cloned.users)

    # Source profile remained untouched
    assert [h.edr_installed for h in weak_profile.hosts] == orig_hosts_edr
    assert [u.mfa_enabled for u in weak_profile.users] == orig_users_mfa


def test_whatif_comparison_metrics_improved(weak_profile):
    controls = RemediationControls(
        immutable_backups=True,
        edr_on_servers=True,
        remove_local_admin=True,
    )
    res = run_whatif_comparison(weak_profile, controls, patient_zero_id="user-02")

    # Blast radius should decrease
    assert res.remediated_blast_radius.composite_blast_radius_pct <= res.baseline_blast_radius.composite_blast_radius_pct
    # Maturity score should increase
    assert res.remediated_maturity.overall_score >= res.baseline_maturity.overall_score
    # Recovery hours should decrease or stay same
    assert res.remediated_recovery.estimated_recovery_hours <= res.baseline_recovery.estimated_recovery_hours


def test_empty_remediations_preserves_metrics(weak_profile):
    empty_controls = RemediationControls()
    res = run_whatif_comparison(weak_profile, empty_controls, patient_zero_id="user-02")

    assert res.remediated_blast_radius.composite_blast_radius_pct == res.baseline_blast_radius.composite_blast_radius_pct
    assert res.remediated_maturity.overall_score == res.baseline_maturity.overall_score


def test_remediation_candidate_ranking(weak_profile):
    ranking_res = rank_remediation_candidates(weak_profile, patient_zero_id="user-02")

    assert len(ranking_res.candidates) == 6
    assert "Remediation Ranking Formula" in ranking_res.formula_documentation

    # Check that candidates are sorted descending by ROI
    for i in range(len(ranking_res.candidates) - 1):
        c1 = ranking_res.candidates[i]
        c2 = ranking_res.candidates[i + 1]
        assert c1.roi_score >= c2.roi_score
        assert c1.implementation_effort >= 1  # Never zero division
