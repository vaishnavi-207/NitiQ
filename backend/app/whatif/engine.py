"""
NitiQ - What-If Engine
Applies defensive remediation overrides without mutating the source organization profile,
and generates side-by-side metric comparisons.
"""

from typing import List, Optional
from backend.app.models.organization import (
    OrganizationProfile,
    BackupRepository,
    EdgeType,
)
from backend.app.models.whatif import (
    RemediationControls,
    MetricComparison,
    WhatIfComparisonResponse,
)
from backend.app.simulation.engine import (
    run_simulation,
    evaluate_patient_zero_rankings,
)
from backend.app.recovery.calculator import calculate_recovery_time
from backend.app.scoring.nist_csf import evaluate_maturity_score


def apply_remediations(
    profile: OrganizationProfile,
    remediations: RemediationControls,
) -> OrganizationProfile:
    """
    Creates a deep clone of the organization profile and applies the specified
    remediation overrides non-destructively.
    """
    clone = profile.model_copy(deep=True)

    # 1. MFA on admin accounts
    if remediations.enforce_mfa_admin:
        for u in clone.users:
            if u.is_domain_admin or u.is_local_admin:
                u.mfa_enabled = True

    # 2. Immutable backups
    if remediations.immutable_backups:
        for b in clone.backup_repositories:
            b.is_immutable = True

    # 3. Finance network segmentation
    if remediations.finance_segmentation:
        finance_seg_ids = set()
        for seg in clone.network_segments:
            if seg.zone_type.lower() == "finance" or "finance" in seg.id.lower():
                seg.is_isolated = True
                seg.firewall_rules_strict = True
                finance_seg_ids.add(seg.id)

        # Filter out direct cross-segment lateral edges into finance from non-admin hosts
        if finance_seg_ids:
            finance_host_ids = {
                h.id for h in clone.hosts if h.segment_id in finance_seg_ids
            }
            clone.edges = [
                e for e in clone.edges
                if not (
                    e.target_id in finance_host_ids
                    and e.relationship_type == EdgeType.SAME_SEGMENT
                )
            ]

    # 4. Removal of local admin rights
    if remediations.remove_local_admin:
        for h in clone.hosts:
            h.local_admin_restricted = True
            h.has_unquoted_service_path = False
        for u in clone.users:
            if not u.is_domain_admin:
                u.is_local_admin = False

    # 5. Offline backup copy
    if remediations.offline_backup_copy:
        has_offline = any(b.is_offline for b in clone.backup_repositories)
        if not has_offline:
            # Add an offline immutable repository
            target_seg = clone.network_segments[0].id if clone.network_segments else "seg-backup"
            clone.backup_repositories.append(
                BackupRepository(
                    id="backup-offline-vault",
                    name="Air-Gapped Immutable Backup Vault",
                    segment_id=target_seg,
                    backup_type="offline_airgap",
                    is_immutable=True,
                    is_offline=True,
                    domain_joined=False,
                    credential_isolated=True,
                    storage_capacity_tb=100.0,
                    restore_throughput_mb_s=65.0,
                    last_restore_test_days=14,
                    snapshot_frequency_hours=12,
                )
            )

    # 6. EDR on servers and hosts
    if remediations.edr_on_servers:
        for h in clone.hosts:
            h.edr_installed = True
            h.edr_active = True
        for dc in clone.domain_controllers:
            dc.edr_installed = True
            dc.edr_active = True
        clone.security_controls.automated_containment = True

    return clone


def run_whatif_comparison(
    profile: OrganizationProfile,
    remediations: RemediationControls,
    patient_zero_id: Optional[str] = None,
) -> WhatIfComparisonResponse:
    """
    Executes baseline vs remediated comparison across Blast Radius,
    Time-to-Detect, Recovery Time, and NIST CSF Maturity.
    """
    # Determine patient zero to evaluate
    if not patient_zero_id:
        pz_ranking = evaluate_patient_zero_rankings(profile)
        patient_zero_id = pz_ranking.worst_case_patient_zero.entity_id

    # Baseline calculations
    base_sim = run_simulation(profile, patient_zero_id=patient_zero_id)
    base_rec = calculate_recovery_time(
        profile,
        compromised_data_gb=base_sim.blast_radius.encrypted_data_gb,
        compromised_hosts_count=base_sim.blast_radius.compromised_hosts,
        backups_compromised=base_sim.blast_radius.backups_compromised_flag,
    )
    base_mat = evaluate_maturity_score(profile)

    # Remediated calculations
    remediated_profile = apply_remediations(profile, remediations)
    rem_sim = run_simulation(remediated_profile, patient_zero_id=patient_zero_id)
    rem_rec = calculate_recovery_time(
        remediated_profile,
        compromised_data_gb=rem_sim.blast_radius.encrypted_data_gb,
        compromised_hosts_count=rem_sim.blast_radius.compromised_hosts,
        backups_compromised=rem_sim.blast_radius.backups_compromised_flag,
    )
    rem_mat = evaluate_maturity_score(remediated_profile)

    # Build comparison summary
    comparisons: List[MetricComparison] = []

    # 1. Composite Blast Radius
    b_br = base_sim.blast_radius.composite_blast_radius_pct
    r_br = rem_sim.blast_radius.composite_blast_radius_pct
    diff_br = round(r_br - b_br, 2)
    pct_br = round((diff_br / b_br * 100.0) if b_br > 0 else 0.0, 1)
    comparisons.append(
        MetricComparison(
            metric_name="Composite Blast Radius",
            baseline_value=b_br,
            remediated_value=r_br,
            absolute_change=diff_br,
            percentage_change=pct_br,
            unit="%",
            improved=diff_br < 0,
            interpretation=f"Blast radius reduced from {b_br}% to {r_br}%" if diff_br < 0 else "No change in blast radius",
        )
    )

    # 2. Time-to-Detect (TTD) Proxy
    b_ttd = base_sim.detection.estimated_ttd_hours
    r_ttd = rem_sim.detection.estimated_ttd_hours
    diff_ttd = round(r_ttd - b_ttd, 2)
    pct_ttd = round((diff_ttd / b_ttd * 100.0) if b_ttd > 0 else 0.0, 1)
    comparisons.append(
        MetricComparison(
            metric_name="Estimated Time-to-Detect (TTD)",
            baseline_value=b_ttd,
            remediated_value=r_ttd,
            absolute_change=diff_ttd,
            percentage_change=pct_ttd,
            unit="hours",
            improved=diff_ttd < 0,
            interpretation=f"Detection accelerated by {abs(diff_ttd):.1f} hours" if diff_ttd < 0 else "Detection latency unchanged",
        )
    )

    # 3. Recovery Time
    b_rec = base_rec.estimated_recovery_hours
    r_rec = rem_rec.estimated_recovery_hours
    diff_rec = round(r_rec - b_rec, 2)
    pct_rec = round((diff_rec / b_rec * 100.0) if b_rec > 0 else 0.0, 1)

    # Catastrophic to restorable is a major defensive improvement
    if base_rec.rto_status == "CATASTROPHIC_DATA_LOSS" and rem_rec.rto_status != "CATASTROPHIC_DATA_LOSS":
        rec_improved = True
        rec_interp = f"Backups protected from total destruction; restorable recovery restored ({base_rec.rto_status} -> {rem_rec.rto_status})"
    elif diff_rec < 0:
        rec_improved = True
        rec_interp = f"Recovery time shortened by {abs(diff_rec):.1f} hours ({base_rec.rto_status} -> {rem_rec.rto_status})"
    elif diff_rec == 0:
        rec_improved = False
        rec_interp = f"Recovery duration unchanged ({base_rec.rto_status})"
    else:
        rec_improved = False
        rec_interp = f"Recovery duration changed by {diff_rec:+.1f} hours ({base_rec.rto_status} -> {rem_rec.rto_status})"

    comparisons.append(
        MetricComparison(
            metric_name="Estimated Recovery Time",
            baseline_value=b_rec,
            remediated_value=r_rec,
            absolute_change=diff_rec,
            percentage_change=pct_rec,
            unit="hours",
            improved=rec_improved,
            interpretation=rec_interp,
        )
    )

    # 4. NIST CSF Maturity Score
    b_mat_sc = base_mat.overall_score
    r_mat_sc = rem_mat.overall_score
    diff_mat = round(r_mat_sc - b_mat_sc, 2)
    pct_mat = round((diff_mat / b_mat_sc * 100.0) if b_mat_sc > 0 else 0.0, 1)
    comparisons.append(
        MetricComparison(
            metric_name="NIST CSF Maturity Score",
            baseline_value=b_mat_sc,
            remediated_value=r_mat_sc,
            absolute_change=diff_mat,
            percentage_change=pct_mat,
            unit="points",
            improved=diff_mat > 0,
            interpretation=f"Defensive posture gained +{diff_mat:.1f} maturity points (Level {base_mat.maturity_level} -> Level {rem_mat.maturity_level})",
        )
    )

    return WhatIfComparisonResponse(
        applied_controls=remediations,
        patient_zero_evaluated=patient_zero_id,
        baseline_blast_radius=base_sim.blast_radius,
        remediated_blast_radius=rem_sim.blast_radius,
        baseline_ttd=base_sim.detection,
        remediated_ttd=rem_sim.detection,
        baseline_recovery=base_rec,
        remediated_recovery=rem_rec,
        baseline_maturity=base_mat,
        remediated_maturity=rem_mat,
        comparison_summary=comparisons,
    )
