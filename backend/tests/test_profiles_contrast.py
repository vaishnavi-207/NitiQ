"""
Unit tests validating that Weak, Average, and Strong profiles yield
materially and visibly contrasting results across all three headline metrics.
"""

from backend.app.simulation.engine import run_simulation
from backend.app.recovery.calculator import calculate_recovery_time
from backend.app.scoring.nist_csf import evaluate_maturity_score


def test_headline_metrics_contrast(weak_profile, strong_profile):
    patient_zero = "user-02"

    w_sim = run_simulation(weak_profile, patient_zero_id=patient_zero)
    s_sim = run_simulation(strong_profile, patient_zero_id=patient_zero)

    w_rec = calculate_recovery_time(
        weak_profile,
        compromised_data_gb=w_sim.blast_radius.encrypted_data_gb,
        compromised_hosts_count=w_sim.blast_radius.compromised_hosts,
        backups_compromised=w_sim.blast_radius.backups_compromised_flag,
    )
    s_rec = calculate_recovery_time(
        strong_profile,
        compromised_data_gb=s_sim.blast_radius.encrypted_data_gb,
        compromised_hosts_count=s_sim.blast_radius.compromised_hosts,
        backups_compromised=s_sim.blast_radius.backups_compromised_flag,
    )

    w_mat = evaluate_maturity_score(weak_profile)
    s_mat = evaluate_maturity_score(strong_profile)

    # 1. Metric 1: Blast Radius
    # Weak blast radius must be materially greater than strong blast radius
    assert w_sim.blast_radius.composite_blast_radius_pct > s_sim.blast_radius.composite_blast_radius_pct
    assert w_sim.blast_radius.backups_compromised_flag is True
    assert s_sim.blast_radius.backups_compromised_flag is False

    # 2. Metric 2: Estimated Time-to-Detect (TTD)
    # Strong org with active EDR & SOC detects much faster than weak org
    assert w_sim.detection.estimated_ttd_hours > s_sim.detection.estimated_ttd_hours

    # 3. Metric 3: Recovery Time vs RTO
    # Weak org experiences catastrophic backup loss (168h+), Strong org recovers quickly (<10h)
    assert w_rec.estimated_recovery_hours > s_rec.estimated_recovery_hours
    assert w_rec.rto_status == "CATASTROPHIC_DATA_LOSS"
    assert s_rec.rto_status == "WITHIN_RTO"

    # 4. Maturity Scoring
    # Weak is Tier Developing / Initial; Strong is Tier Optimized
    assert w_mat.overall_score < s_mat.overall_score
    assert w_mat.overall_score < 40.0
    assert s_mat.overall_score > 80.0
