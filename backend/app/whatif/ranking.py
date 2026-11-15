"""
NitiQ - Remediation Candidate Ranking Engine
Ranks defensive remediation candidates by quantified risk reduction divided by implementation effort.
"""

from typing import List
from backend.app.models.organization import OrganizationProfile
from backend.app.models.whatif import (
    RemediationControls,
    RemediationCandidate,
    RemediationRankingResponse,
)
from backend.app.simulation.engine import (
    run_simulation,
    evaluate_patient_zero_rankings,
)
from backend.app.recovery.calculator import calculate_recovery_time
from backend.app.scoring.nist_csf import evaluate_maturity_score
from backend.app.whatif.engine import apply_remediations


CANDIDATE_DEFINITIONS = [
    {
        "key": "enforce_mfa_admin",
        "name": "Enforce MFA on Privileged Admin Accounts",
        "description": "Mandate phishing-resistant multi-factor authentication across all domain and local administrators.",
        "effort": 2,
        "controls": RemediationControls(enforce_mfa_admin=True),
    },
    {
        "key": "immutable_backups",
        "name": "Enable Backup Repository Immutability",
        "description": "Activate object locking / WORM immutability on primary backup repositories to prevent ransomware encryption and wiping.",
        "effort": 3,
        "controls": RemediationControls(immutable_backups=True),
    },
    {
        "key": "finance_segmentation",
        "name": "Finance Network Microsegmentation & Firewalls",
        "description": "Strictly isolate accounting, ERP, and payroll servers from client workstation VLANs with stateful firewalls.",
        "effort": 4,
        "controls": RemediationControls(finance_segmentation=True),
    },
    {
        "key": "remove_local_admin",
        "name": "Revoke Local Administrator Privileges",
        "description": "Remove default local admin rights from client workstations, forcing privilege escalation barriers for attackers.",
        "effort": 3,
        "controls": RemediationControls(remove_local_admin=True),
    },
    {
        "key": "offline_backup_copy",
        "name": "Establish Air-Gapped Offline Backup Copy",
        "description": "Deploy physically disconnected or air-gapped backup storage with dedicated, non-domain-joined credentials.",
        "effort": 2,
        "controls": RemediationControls(offline_backup_copy=True),
    },
    {
        "key": "edr_on_servers",
        "name": "Deploy Active EDR Fleet Across All Servers",
        "description": "Install and activate endpoint detection and response with automated isolation across 100% of hosts and servers.",
        "effort": 2,
        "controls": RemediationControls(edr_on_servers=True),
    },
]


FORMULA_DOCUMENTATION = (
    "Remediation Ranking Formula: "
    "1. Composite Risk Reduction (RR) = 0.45 * (Blast Radius Reduction %) + "
    "0.35 * (Relative Recovery Hours Saved %) + 0.20 * (Maturity Score Increase * 2.0). "
    "2. Implementation Effort is scaled from 1 (lowest friction) to 5 (highest architectural complexity). "
    "3. Priority ROI Ratio = RR / max(1, Effort). "
    "All values are deterministic model approximations rounded to 2 decimal places."
)


def rank_remediation_candidates(
    profile: OrganizationProfile,
    patient_zero_id: str = None,
) -> RemediationRankingResponse:
    """
    Evaluates each remediation candidate individually against the baseline organization.
    Computes delta in Blast Radius, Recovery Time, and Maturity Score,
    then ranks by Risk Reduction / Effort ROI ratio.
    """
    # 1. Determine baseline patient zero
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

    base_br = base_sim.blast_radius.composite_blast_radius_pct
    base_rec_hrs = base_rec.estimated_recovery_hours
    base_mat_pts = base_mat.overall_score

    candidates: List[RemediationCandidate] = []

    for defn in CANDIDATE_DEFINITIONS:
        # Clone and apply single candidate
        rem_prof = apply_remediations(profile, defn["controls"])
        rem_sim = run_simulation(rem_prof, patient_zero_id=patient_zero_id)
        rem_rec = calculate_recovery_time(
            rem_prof,
            compromised_data_gb=rem_sim.blast_radius.encrypted_data_gb,
            compromised_hosts_count=rem_sim.blast_radius.compromised_hosts,
            backups_compromised=rem_sim.blast_radius.backups_compromised_flag,
        )
        rem_mat = evaluate_maturity_score(rem_prof)

        # Delta calculations
        delta_br = max(0.0, base_br - rem_sim.blast_radius.composite_blast_radius_pct)
        if base_rec.rto_status == "CATASTROPHIC_DATA_LOSS" and rem_rec.rto_status != "CATASTROPHIC_DATA_LOSS":
            # Protecting backups from complete destruction is a primary recovery achievement
            rel_rec_pct = 60.0
            delta_rec = max(0.0, base_rec_hrs - rem_rec.estimated_recovery_hours)
        else:
            delta_rec = max(0.0, base_rec_hrs - rem_rec.estimated_recovery_hours)
            rel_rec_pct = min(100.0, (delta_rec / max(1.0, base_rec_hrs)) * 100.0)
        delta_mat = max(0.0, rem_mat.overall_score - base_mat_pts)

        # Risk reduction formula
        risk_reduction = (
            0.45 * delta_br
            + 0.35 * rel_rec_pct
            + 0.20 * (delta_mat * 2.0)
        )

        effort = max(1, defn["effort"])
        roi = round(risk_reduction / effort, 2)

        candidates.append(
            RemediationCandidate(
                control_key=defn["key"],
                name=defn["name"],
                description=defn["description"],
                implementation_effort=effort,
                blast_radius_reduction_pct=round(delta_br, 2),
                recovery_hours_saved=round(delta_rec, 2),
                maturity_score_increase=round(delta_mat, 2),
                composite_risk_reduction=round(risk_reduction, 2),
                roi_score=roi,
                rank=0,
            )
        )

    # Sort descending by ROI score, then by composite risk reduction
    candidates.sort(key=lambda c: (c.roi_score, c.composite_risk_reduction), reverse=True)

    for idx, c in enumerate(candidates, start=1):
        c.rank = idx

    return RemediationRankingResponse(
        formula_documentation=FORMULA_DOCUMENTATION,
        candidates=candidates,
    )
