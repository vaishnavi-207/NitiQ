"""
NitiQ - Deterministic NIST CSF Maturity Scoring Engine
Calculates transparent 0-100 maturity score across Identify, Protect, Detect, Respond, Recover.
"""

from typing import List, Dict
from backend.app.models.organization import OrganizationProfile
from backend.app.models.scoring import (
    MaturityScoreResponse,
    FunctionScore,
    ControlScoreItem,
)


def evaluate_maturity_score(profile: OrganizationProfile) -> MaturityScoreResponse:
    """
    Evaluates defensive maturity across the five NIST Cybersecurity Framework core functions:
    Identify (20), Protect (20), Detect (20), Respond (20), Recover (20) = 100 Total Points.
    """
    controls: List[ControlScoreItem] = []

    # ---------------------------------------------------------
    # 1. IDENTIFY (Max 20)
    # ---------------------------------------------------------
    # ID.AM-1: Asset inventory & network segment mapping (7 pts)
    has_segments = len(profile.network_segments) >= 3
    has_classified_hosts = len(profile.hosts) > 0
    if has_segments and has_classified_hosts:
        id_am1_pts = 7.0
        id_am1_status = "IMPLEMENTED"
        id_am1_desc = f"Inventory covers {len(profile.hosts)} hosts across {len(profile.network_segments)} network segments."
    elif has_classified_hosts:
        id_am1_pts = 3.5
        id_am1_status = "PARTIAL"
        id_am1_desc = "Basic host inventory present, but network segmentation is rudimentary."
    else:
        id_am1_pts = 0.0
        id_am1_status = "NOT_IMPLEMENTED"
        id_am1_desc = "Uncataloged asset inventory."

    controls.append(
        ControlScoreItem(
            control_id="ID.AM-1",
            function="Identify",
            name="Asset Inventory & Zone Mapping",
            max_points=7.0,
            awarded_points=id_am1_pts,
            status=id_am1_status,
            rationale=id_am1_desc,
        )
    )

    # ID.RA-1: Vulnerability & Patch Hygiene (7 pts)
    total_hosts = len(profile.hosts) + len(profile.domain_controllers)
    vuln_hosts = sum(
        1 for h in list(profile.hosts) + list(profile.domain_controllers)
        if h.patch_level == "critical_missing" or h.has_unquoted_service_path
    )
    clean_pct = ((total_hosts - vuln_hosts) / total_hosts) if total_hosts > 0 else 1.0
    id_ra1_pts = round(clean_pct * 7.0, 1)
    id_ra1_status = "IMPLEMENTED" if clean_pct >= 0.9 else ("PARTIAL" if clean_pct >= 0.5 else "NOT_IMPLEMENTED")
    controls.append(
        ControlScoreItem(
            control_id="ID.RA-1",
            function="Identify",
            name="Patch Hygiene & Vulnerability Management",
            max_points=7.0,
            awarded_points=id_ra1_pts,
            status=id_ra1_status,
            rationale=f"{clean_pct * 100:.1f}% of endpoints are free of critical unpatched flaws or misconfigurations.",
        )
    )

    # ID.SC-1: Data Classification & Critical Asset Visibility (6 pts)
    classified_shares = sum(1 for s in profile.file_shares if s.critical_data)
    id_sc1_pts = 6.0 if classified_shares > 0 else 2.0
    id_sc1_status = "IMPLEMENTED" if classified_shares > 0 else "PARTIAL"
    controls.append(
        ControlScoreItem(
            control_id="ID.SC-1",
            function="Identify",
            name="Data Classification & Critical Asset Identification",
            max_points=6.0,
            awarded_points=id_sc1_pts,
            status=id_sc1_status,
            rationale=f"{classified_shares} critical data shares formally classified with defined sensitivity.",
        )
    )

    # ---------------------------------------------------------
    # 2. PROTECT (Max 20)
    # ---------------------------------------------------------
    # PR.AC-1: Least Privilege & Local Admin Restriction (6 pts)
    local_admin_restricted_hosts = sum(1 for h in profile.hosts if h.local_admin_restricted)
    la_pct = (local_admin_restricted_hosts / len(profile.hosts)) if profile.hosts else 1.0
    pr_ac1_pts = round(la_pct * 6.0, 1)
    pr_ac1_status = "IMPLEMENTED" if la_pct >= 0.9 else ("PARTIAL" if la_pct >= 0.5 else "NOT_IMPLEMENTED")
    controls.append(
        ControlScoreItem(
            control_id="PR.AC-1",
            function="Protect",
            name="Least Privilege & Local Admin Restrictions",
            max_points=6.0,
            awarded_points=pr_ac1_pts,
            status=pr_ac1_status,
            rationale=f"Local administrator privileges restricted on {la_pct * 100:.1f}% of client endpoints.",
        )
    )

    # PR.AC-7: Multi-Factor Authentication Enforcement (5 pts)
    admin_users = [u for u in profile.users if u.is_domain_admin or u.is_local_admin]
    admin_mfa = sum(1 for u in admin_users if u.mfa_enabled)
    admin_mfa_pct = (admin_mfa / len(admin_users)) if admin_users else 1.0

    all_users_mfa = sum(1 for u in profile.users if u.mfa_enabled)
    all_mfa_pct = (all_users_mfa / len(profile.users)) if profile.users else 1.0

    pr_ac7_pts = round((admin_mfa_pct * 3.0) + (all_mfa_pct * 2.0), 1)
    pr_ac7_status = "IMPLEMENTED" if (admin_mfa_pct >= 0.95 and all_mfa_pct >= 0.8) else ("PARTIAL" if admin_mfa_pct >= 0.5 else "NOT_IMPLEMENTED")
    controls.append(
        ControlScoreItem(
            control_id="PR.AC-7",
            function="Protect",
            name="Multi-Factor Authentication (MFA)",
            max_points=5.0,
            awarded_points=pr_ac7_pts,
            status=pr_ac7_status,
            rationale=f"MFA enforced on {admin_mfa_pct * 100:.0f}% of administrators and {all_mfa_pct * 100:.0f}% of general users.",
        )
    )

    # PR.AC-5: Network Segmentation & Isolation (5 pts)
    seg_count = len([s for s in profile.network_segments if s.is_isolated or s.firewall_rules_strict])
    if profile.security_controls.network_microsegmentation:
        pr_ac5_pts = 5.0
        pr_ac5_status = "IMPLEMENTED"
        pr_ac5_desc = "Strict zero-trust microsegmentation active between workstations and servers."
    elif seg_count >= 2:
        pr_ac5_pts = 3.5
        pr_ac5_status = "PARTIAL"
        pr_ac5_desc = f"{seg_count} sensitive zones (e.g. finance/backup) strictly firewalled."
    else:
        pr_ac5_pts = 1.0
        pr_ac5_status = "NOT_IMPLEMENTED"
        pr_ac5_desc = "Flat or minimally segmented internal network perimeter."
    controls.append(
        ControlScoreItem(
            control_id="PR.AC-5",
            function="Protect",
            name="Network Segmentation & Perimeter Isolation",
            max_points=5.0,
            awarded_points=pr_ac5_pts,
            status=pr_ac5_status,
            rationale=pr_ac5_desc,
        )
    )

    # PR.DS-1: Backup Storage Immutability & Credential Isolation (4 pts)
    has_immutable = any(b.is_immutable for b in profile.backup_repositories)
    has_offline = any(b.is_offline for b in profile.backup_repositories)
    cred_isolated = any(b.credential_isolated for b in profile.backup_repositories)

    if (has_immutable or has_offline) and cred_isolated:
        pr_ds1_pts = 4.0
        pr_ds1_status = "IMPLEMENTED"
        pr_ds1_desc = "Immutable or offline backups deployed with dedicated non-domain credentials."
    elif has_immutable or has_offline:
        pr_ds1_pts = 2.5
        pr_ds1_status = "PARTIAL"
        pr_ds1_desc = "Immutable/air-gapped storage exists, but credentials share domain trusts."
    else:
        pr_ds1_pts = 0.5
        pr_ds1_status = "NOT_IMPLEMENTED"
        pr_ds1_desc = "Backups are standard writable shares vulnerable to ransomware tampering."
    controls.append(
        ControlScoreItem(
            control_id="PR.DS-1",
            function="Protect",
            name="Backup Immutability & Credential Isolation",
            max_points=4.0,
            awarded_points=pr_ds1_pts,
            status=pr_ds1_status,
            rationale=pr_ds1_desc,
        )
    )

    # ---------------------------------------------------------
    # 3. DETECT (Max 20)
    # ---------------------------------------------------------
    # DE.CM-1: Endpoint Detection and Response (EDR) (8 pts)
    active_edr = sum(
        1 for h in list(profile.hosts) + list(profile.domain_controllers)
        if h.edr_installed and h.edr_active
    )
    edr_pct = (active_edr / total_hosts) if total_hosts > 0 else 0.0
    de_cm1_pts = round(edr_pct * 8.0, 1)
    de_cm1_status = "IMPLEMENTED" if edr_pct >= 0.9 else ("PARTIAL" if edr_pct >= 0.4 else "NOT_IMPLEMENTED")
    controls.append(
        ControlScoreItem(
            control_id="DE.CM-1",
            function="Detect",
            name="Endpoint Detection & Response (EDR) Fleet Coverage",
            max_points=8.0,
            awarded_points=de_cm1_pts,
            status=de_cm1_status,
            rationale=f"EDR active and reporting on {edr_pct * 100:.1f}% of managed hosts.",
        )
    )

    # DE.CM-7: Centralized Logging & SIEM (5 pts)
    de_cm7_pts = 5.0 if profile.security_controls.centralized_logging else 1.0
    de_cm7_status = "IMPLEMENTED" if profile.security_controls.centralized_logging else "NOT_IMPLEMENTED"
    controls.append(
        ControlScoreItem(
            control_id="DE.CM-7",
            function="Detect",
            name="Centralized Audit Logging & SIEM Ingestion",
            max_points=5.0,
            awarded_points=de_cm7_pts,
            status=de_cm7_status,
            rationale="Security audit logs forwarded to central SIEM for aggregation." if profile.security_controls.centralized_logging else "Logs remain local on endpoints with no centralized correlation.",
        )
    )

    # DE.DP-1: SOC Monitoring 24/7 (4 pts)
    de_dp1_pts = 4.0 if profile.security_controls.soc_monitoring_24_7 else 1.0
    de_dp1_status = "IMPLEMENTED" if profile.security_controls.soc_monitoring_24_7 else "NOT_IMPLEMENTED"
    controls.append(
        ControlScoreItem(
            control_id="DE.DP-1",
            function="Detect",
            name="Continuous 24/7 SOC Alert Monitoring",
            max_points=4.0,
            awarded_points=de_dp1_pts,
            status=de_dp1_status,
            rationale="24/7 SOC surveillance active with dedicated escalation paths." if profile.security_controls.soc_monitoring_24_7 else "Monitoring limited to business hours with delayed alert triage.",
        )
    )

    # DE.AE-1: Honeypots & Canary Tripwires (3 pts)
    de_ae1_pts = 3.0 if profile.security_controls.honeytokens_or_canary_files else 0.0
    de_ae1_status = "IMPLEMENTED" if profile.security_controls.honeytokens_or_canary_files else "NOT_IMPLEMENTED"
    controls.append(
        ControlScoreItem(
            control_id="DE.AE-1",
            function="Detect",
            name="Canary Decoys & Honeytoken Tripwires",
            max_points=3.0,
            awarded_points=de_ae1_pts,
            status=de_ae1_status,
            rationale="Early-warning file shares and honeytokens deployed in sensitive file directories." if profile.security_controls.honeytokens_or_canary_files else "No deceptive early-detection decoy tripwires deployed.",
        )
    )

    # ---------------------------------------------------------
    # 4. RESPOND (Max 20)
    # ---------------------------------------------------------
    # RS.RP-1: Incident Response Plan (8 pts)
    rs_rp1_pts = 8.0 if profile.incident_response_plan else 0.0
    rs_rp1_status = "IMPLEMENTED" if profile.incident_response_plan else "NOT_IMPLEMENTED"
    controls.append(
        ControlScoreItem(
            control_id="RS.RP-1",
            function="Respond",
            name="Formally Documented Incident Response Plan",
            max_points=8.0,
            awarded_points=rs_rp1_pts,
            status=rs_rp1_status,
            rationale="Comprehensive IR policy and crisis management workflow established." if profile.incident_response_plan else "No formal incident response governance plan.",
        )
    )

    # RS.MI-1: Automated Host Containment (7 pts)
    rs_mi1_pts = 7.0 if profile.security_controls.automated_containment else 2.0
    rs_mi1_status = "IMPLEMENTED" if profile.security_controls.automated_containment else "PARTIAL"
    controls.append(
        ControlScoreItem(
            control_id="RS.MI-1",
            function="Respond",
            name="Automated Network Isolation & Containment",
            max_points=7.0,
            awarded_points=rs_mi1_pts,
            status=rs_mi1_status,
            rationale="EDR playbooks automatically isolate compromised endpoints upon ransomware heuristics." if profile.security_controls.automated_containment else "Manual containment required via network switch or firewall intervention.",
        )
    )

    # RS.CO-1: Escalation & Communications Protocols (5 pts)
    rs_co1_pts = 5.0 if profile.incident_response_plan else 1.0
    rs_co1_status = "IMPLEMENTED" if profile.incident_response_plan else "NOT_IMPLEMENTED"
    controls.append(
        ControlScoreItem(
            control_id="RS.CO-1",
            function="Respond",
            name="Emergency Communications & Crisis Hierarchy",
            max_points=5.0,
            awarded_points=rs_co1_pts,
            status=rs_co1_status,
            rationale="Executive communication tree and legal breach reporting pathways pre-defined." if profile.incident_response_plan else "Ad-hoc communication hierarchy during security incidents.",
        )
    )

    # ---------------------------------------------------------
    # 5. RECOVER (Max 20)
    # ---------------------------------------------------------
    # RC.RP-1: Disaster Recovery Runbooks (8 pts)
    rc_rp1_pts = 8.0 if profile.runbook_available else 0.0
    rc_rp1_status = "IMPLEMENTED" if profile.runbook_available else "NOT_IMPLEMENTED"
    controls.append(
        ControlScoreItem(
            control_id="RC.RP-1",
            function="Recover",
            name="Disaster Recovery Runbooks & Playbooks",
            max_points=8.0,
            awarded_points=rc_rp1_pts,
            status=rc_rp1_status,
            rationale="Engineered step-by-step restoration playbooks for bare-metal and share restoration." if profile.runbook_available else "No recovery runbooks; reliance on tribal knowledge.",
        )
    )

    # RC.IM-1: Regular Backup Restore Rehearsal (7 pts)
    min_test_days = min((b.last_restore_test_days for b in profile.backup_repositories), default=365)
    if min_test_days <= 30:
        rc_im1_pts = 7.0
        rc_im1_status = "IMPLEMENTED"
        rc_im1_desc = f"Verified restore drill conducted within last {min_test_days} days."
    elif min_test_days <= 90:
        rc_im1_pts = 5.0
        rc_im1_status = "PARTIAL"
        rc_im1_desc = f"Last verified restore rehearsal was {min_test_days} days ago."
    elif min_test_days <= 180:
        rc_im1_pts = 2.5
        rc_im1_status = "PARTIAL"
        rc_im1_desc = f"Restore testing is stale ({min_test_days} days ago)."
    else:
        rc_im1_pts = 0.0
        rc_im1_status = "NOT_IMPLEMENTED"
        rc_im1_desc = f"Backups untested in {min_test_days} days."
    controls.append(
        ControlScoreItem(
            control_id="RC.IM-1",
            function="Recover",
            name="Regular Backup Restore Testing",
            max_points=7.0,
            awarded_points=rc_im1_pts,
            status=rc_im1_status,
            rationale=rc_im1_desc,
        )
    )

    # RC.CO-1: RTO & RPO Alignment & Bandwidth (5 pts)
    high_throughput = any(b.restore_throughput_mb_s >= 80.0 for b in profile.backup_repositories)
    if high_throughput and profile.required_rto_hours >= 12.0:
        rc_co1_pts = 5.0
        rc_co1_status = "IMPLEMENTED"
        rc_co1_desc = "Backup hardware and pipe throughput matches required business RTO."
    elif any(b.restore_throughput_mb_s >= 30.0 for b in profile.backup_repositories):
        rc_co1_pts = 3.0
        rc_co1_status = "PARTIAL"
        rc_co1_desc = "Moderate restore throughput; may strain aggressive RTO targets."
    else:
        rc_co1_pts = 1.0
        rc_co1_status = "NOT_IMPLEMENTED"
        rc_co1_desc = "Insufficient restore throughput to satisfy required RTO."
    controls.append(
        ControlScoreItem(
            control_id="RC.CO-1",
            function="Recover",
            name="Recovery Objective (RTO/RPO) Resource Alignment",
            max_points=5.0,
            awarded_points=rc_co1_pts,
            status=rc_co1_status,
            rationale=rc_co1_desc,
        )
    )

    # Sum by function
    function_totals: Dict[str, float] = {
        "Identify": 0.0,
        "Protect": 0.0,
        "Detect": 0.0,
        "Respond": 0.0,
        "Recover": 0.0,
    }
    for c in controls:
        function_totals[c.function] += c.awarded_points

    function_scores = {
        fn: FunctionScore(
            function=fn,
            score=round(pts, 1),
            max_score=20.0,
            percentage=round((pts / 20.0) * 100.0, 1),
        )
        for fn, pts in function_totals.items()
    }

    overall_score = round(sum(function_totals.values()), 1)
    overall_score = max(0.0, min(100.0, overall_score))

    # 5 Maturity Levels
    # 0-20: Initial, 21-40: Developing, 41-60: Defined, 61-80: Managed, 81-100: Optimized
    if overall_score <= 20.0:
        mat_level = 1
        mat_tier = "Initial"
    elif overall_score <= 40.0:
        mat_level = 2
        mat_tier = "Developing"
    elif overall_score <= 60.0:
        mat_level = 3
        mat_tier = "Defined"
    elif overall_score <= 80.0:
        mat_level = 4
        mat_tier = "Managed"
    else:
        mat_level = 5
        mat_tier = "Optimized"

    return MaturityScoreResponse(
        overall_score=overall_score,
        maturity_level=mat_level,
        maturity_tier=mat_tier,
        function_scores=function_scores,
        controls_breakdown=controls,
    )
