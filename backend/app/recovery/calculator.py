"""
NitiQ - Recovery Time Estimation Engine
Calculates deterministic recovery time estimates, RTO gap, and identifies top blockers.
"""

from typing import List, Dict, Optional
from backend.app.models.organization import OrganizationProfile
from backend.app.models.recovery import (
    RecoveryEstimateResponse,
    RecoveryStepItem,
)


def calculate_recovery_time(
    profile: OrganizationProfile,
    compromised_data_gb: Optional[float] = None,
    compromised_hosts_count: Optional[int] = None,
    backups_compromised: Optional[bool] = None,
) -> RecoveryEstimateResponse:
    """
    Computes deterministic recovery time based on data volume, backup characteristics,
    throughput, testing recency, and operational runbooks.
    """
    # 1. Determine data volume to restore
    if compromised_data_gb is None:
        compromised_data_gb = sum(s.data_volume_gb for s in profile.file_shares)
    compromised_data_gb = max(0.0, float(compromised_data_gb))

    # 2. Determine hosts to restore
    if compromised_hosts_count is None:
        compromised_hosts_count = len(profile.hosts) + len(profile.domain_controllers)
    compromised_hosts_count = max(0, int(compromised_hosts_count))

    # 3. Analyze backup repositories
    repos = profile.backup_repositories
    top_blockers: List[str] = []
    backup_summary: Dict[str, str] = {}

    if not repos:
        top_blockers.append("No backup repositories registered in organization profile.")
        return RecoveryEstimateResponse(
            estimated_recovery_hours=336.0,  # 2 weeks rebuild from scratch
            required_rto_hours=profile.required_rto_hours,
            rto_gap_hours=round(336.0 - profile.required_rto_hours, 2),
            rto_status="CATASTROPHIC_DATA_LOSS",
            total_data_to_restore_gb=compromised_data_gb,
            effective_throughput_mb_s=0.0,
            top_blockers=top_blockers,
            recovery_breakdown=[
                RecoveryStepItem(
                    step_name="Rebuild from Scratch",
                    duration_hours=336.0,
                    description="No usable backups. Full manual reconfiguration and historical reconstruction required.",
                )
            ],
            backup_status_summary={"status": "No backups configured"},
        )

    # Check surviving repositories
    surviving_repos = []
    for r in repos:
        is_compromised = False
        if backups_compromised:
            if not r.is_immutable and not r.is_offline:
                is_compromised = True
        if not is_compromised:
            surviving_repos.append(r)
            backup_summary[r.id] = (
                f"Surviving ({'Immutable' if r.is_immutable else ''}"
                f"{' Offline Airgap' if r.is_offline else ''} {r.backup_type})"
            )
        else:
            backup_summary[r.id] = "Compromised (Non-immutable online storage wiped)"

    # If all backups compromised and none survive
    if not surviving_repos:
        top_blockers.append(
            "Primary and secondary backups compromised. No immutable or air-gapped copies exist."
        )
        if not profile.runbook_available:
            top_blockers.append("No technical disaster recovery runbook available.")
        return RecoveryEstimateResponse(
            estimated_recovery_hours=168.0,  # 1 week minimum manual reconstruction
            required_rto_hours=profile.required_rto_hours,
            rto_gap_hours=round(168.0 - profile.required_rto_hours, 2),
            rto_status="CATASTROPHIC_DATA_LOSS",
            total_data_to_restore_gb=compromised_data_gb,
            effective_throughput_mb_s=0.0,
            top_blockers=top_blockers,
            recovery_breakdown=[
                RecoveryStepItem(
                    step_name="Forensic Reconstruction & Manual Rebuild",
                    duration_hours=168.0,
                    description="Catastrophic loss of backup repository integrity. Requires manual cold system re-creation.",
                )
            ],
            backup_status_summary=backup_summary,
        )

    # Choose best surviving repository for restore throughput
    best_repo = max(surviving_repos, key=lambda r: r.restore_throughput_mb_s)
    effective_throughput = max(1.0, best_repo.restore_throughput_mb_s)

    # Check for domain-joined backup vulnerability
    for r in repos:
        if r.domain_joined and not r.credential_isolated:
            top_blockers.append(
                f"Backup repo '{r.name}' is domain-joined without isolated credentials; exposed to Domain Admin takeover."
            )

    # Physical airgap retrieval overhead
    offline_retrieval_hours = 0.0
    if best_repo.is_offline:
        offline_retrieval_hours = 3.0  # Time to physically retrieve and mount airgapped tapes/media

    # Data transfer time calculation
    # throughput in GB/hr = (effective_throughput MB/s * 3600) / 1024
    throughput_gb_per_hour = (effective_throughput * 3600.0) / 1024.0
    data_transfer_hours = compromised_data_gb / throughput_gb_per_hour if throughput_gb_per_hour > 0 else 0.0

    if effective_throughput < 30.0:
        top_blockers.append(
            f"Low restore throughput ({effective_throughput} MB/s) creates data bottleneck for {compromised_data_gb:.0f} GB."
        )

    # Infrastructure & Host rebuild time (parallel streams of 5 hosts per batch)
    host_rebuild_batches = (compromised_hosts_count + 4) // 5
    infra_prep_hours = max(2.0, host_rebuild_batches * 1.5)

    # Runbook and Incident Response coordination overhead
    ir_triage_hours = 2.0
    if not profile.incident_response_plan:
        ir_triage_hours += 6.0
        top_blockers.append("No formalized incident response plan; increases initial triage latency by 6 hours.")

    if not profile.runbook_available:
        infra_prep_hours += 4.0
        top_blockers.append("No step-by-step recovery runbook; manual procedure testing delays restore by 4 hours.")

    # Restore test recency penalty
    min_test_days = min(r.last_restore_test_days for r in surviving_repos)
    test_penalty_hours = 0.0
    if min_test_days > 180:
        test_penalty_hours = max(2.0, data_transfer_hours * 0.25)
        top_blockers.append(
            f"Backups untested in {min_test_days} days. Adds 25% unpracticed restore procedure penalty ({test_penalty_hours:.1f}h)."
        )
    elif min_test_days > 90:
        test_penalty_hours = max(1.0, data_transfer_hours * 0.10)
        top_blockers.append(f"Last restore rehearsal was {min_test_days} days ago (>90 day recommended interval).")

    # Verification and sanity testing
    verification_hours = max(1.5, compromised_data_gb * 0.0005)

    total_hours = (
        ir_triage_hours
        + offline_retrieval_hours
        + infra_prep_hours
        + data_transfer_hours
        + test_penalty_hours
        + verification_hours
    )

    rto_gap = total_hours - profile.required_rto_hours
    rto_status = "WITHIN_RTO" if rto_gap <= 0.0 else "EXCEEDS_RTO"

    breakdown = [
        RecoveryStepItem(
            step_name="IR Triage & Containment Verification",
            duration_hours=round(ir_triage_hours, 2),
            description="Isolate compromised segments, verify perimeter security before restore begins.",
        ),
    ]

    if offline_retrieval_hours > 0:
        breakdown.append(
            RecoveryStepItem(
                step_name="Air-Gapped Media Retrieval & Mount",
                duration_hours=round(offline_retrieval_hours, 2),
                description="Physical transport and cryptographic verification of offline immutable storage media.",
            )
        )

    breakdown.extend([
        RecoveryStepItem(
            step_name="Host & Hypervisor Re-imaging",
            duration_hours=round(infra_prep_hours, 2),
            description=f"Provision clean golden images for {compromised_hosts_count} compromised hosts.",
        ),
        RecoveryStepItem(
            step_name="File Share & Data Restore",
            duration_hours=round(data_transfer_hours, 2),
            description=f"Transfer {compromised_data_gb:.1f} GB from {best_repo.name} at {effective_throughput} MB/s.",
        ),
        RecoveryStepItem(
            step_name="Untested Procedure Overhead",
            duration_hours=round(test_penalty_hours, 2),
            description=f"Friction from stale restore tests (last verified {min_test_days} days ago).",
        ),
        RecoveryStepItem(
            step_name="Integrity Verification & Service Resumption",
            duration_hours=round(verification_hours, 2),
            description="Database consistency checks, user acceptance smoke testing, and DNS cutover.",
        ),
    ])

    return RecoveryEstimateResponse(
        estimated_recovery_hours=round(total_hours, 2),
        required_rto_hours=profile.required_rto_hours,
        rto_gap_hours=round(rto_gap, 2),
        rto_status=rto_status,
        total_data_to_restore_gb=round(compromised_data_gb, 2),
        effective_throughput_mb_s=round(effective_throughput, 2),
        top_blockers=top_blockers,
        recovery_breakdown=breakdown,
        backup_status_summary=backup_summary,
    )
