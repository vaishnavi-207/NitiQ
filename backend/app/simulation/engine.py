"""
NitiQ - Deterministic Ransomware Spread Simulation Engine
Simulates lateral movement, privilege escalation, share encryption, and backup reachability
in discrete deterministic time steps.
"""

from typing import List, Dict, Set, Tuple, Optional
import networkx as nx
from backend.app.models.organization import (
    OrganizationProfile,
    Host,
    DomainController,
    FileShare,
    BackupRepository,
    User,
    NetworkSegment,
)
from backend.app.simulation.assumptions import SimulationAssumptions, DEFAULT_ASSUMPTIONS
from backend.app.simulation.graph import build_network_graph, find_domain_admin_path
from backend.app.models.simulation import (
    TimelineStep,
    BlastRadiusMetrics,
    DetectionMetrics,
    SimulationResult,
    PatientZeroRankingEntry,
    PatientZeroRankingResponse,
)


def run_simulation(
    profile: OrganizationProfile,
    patient_zero_id: str,
    assumptions: Optional[SimulationAssumptions] = None,
    max_hours: float = 24.0,
) -> SimulationResult:
    """
    Executes a deterministic, discrete time-stepped ransomware propagation simulation.
    All calculations are reproducible and explainable.
    """
    if assumptions is None:
        assumptions = DEFAULT_ASSUMPTIONS

    graph = build_network_graph(profile)

    if not graph.has_node(patient_zero_id):
        raise ValueError(
            f"Patient zero entity '{patient_zero_id}' does not exist in organization profile."
        )

    # Lookup patient zero metadata
    pz_attrs = graph.nodes[patient_zero_id]
    pz_type = pz_attrs.get("entity_type", "unknown").capitalize()
    pz_name = pz_attrs.get("name", patient_zero_id)
    pz_dept = pz_attrs.get("department", "Unknown")

    # Map lookups for rapid querying
    hosts_map = {h.id: h for h in profile.hosts}
    dcs_map = {dc.id: dc for dc in profile.domain_controllers}
    shares_map = {s.id: s for s in profile.file_shares}
    backups_map = {b.id: b for b in profile.backup_repositories}
    users_map = {u.id: u for u in profile.users}
    segments_map = {seg.id: seg for seg in profile.network_segments}

    all_host_ids = set(hosts_map.keys()) | set(dcs_map.keys())
    all_share_ids = set(shares_map.keys())
    all_backup_ids = set(backups_map.keys())

    # Critical assets set
    critical_asset_ids: Set[str] = set()
    for hid, h in hosts_map.items():
        if h.is_critical:
            critical_asset_ids.add(hid)
    for dcid in dcs_map.keys():
        critical_asset_ids.add(dcid)
    for sid, s in shares_map.items():
        if s.critical_data:
            critical_asset_ids.add(sid)

    # State tracking
    compromised_nodes: Set[str] = set()
    scheduled_compromises: Dict[str, float] = {}  # node_id -> time_minutes
    node_discovery_time: Dict[str, float] = {}

    # Encryption tracking
    encrypted_shares: Set[str] = set()
    share_encryption_progress: Dict[str, float] = {sid: 0.0 for sid in all_share_ids}  # GB encrypted

    # Detection tracking
    detection_triggered = False
    detection_step: Optional[int] = None
    detection_time_minutes: Optional[float] = None
    detection_mechanism = "No detection within simulation window"

    # Seed patient zero
    scheduled_compromises[patient_zero_id] = 0.0
    node_discovery_time[patient_zero_id] = 0.0

    # If patient zero is a user, also compromise their initial workstation immediately
    if pz_type == "User":
        for u, v, d in graph.out_edges(patient_zero_id, data=True):
            if d.get("relationship_type") in ("logged_in_on", "admin_on") and v in all_host_ids:
                scheduled_compromises[v] = 0.0
                node_discovery_time[v] = 0.0

    timeline: List[TimelineStep] = []
    step_minutes = assumptions.step_duration_minutes
    max_steps = min(assumptions.max_simulation_steps, int((max_hours * 60.0) // step_minutes) + 1)

    domain_admin_compromised = False
    step_index = 0

    while step_index < max_steps:
        current_time = step_index * step_minutes
        newly_compromised_this_step: List[str] = []

        # 1. Activate newly scheduled compromises whose ready_time <= current_time
        ready_nodes = [
            nid for nid, rtime in scheduled_compromises.items()
            if rtime <= current_time and nid not in compromised_nodes
        ]

        for nid in sorted(ready_nodes):
            compromised_nodes.add(nid)
            newly_compromised_this_step.append(nid)

            # Check if domain controller or domain admin was compromised
            if nid in dcs_map or (nid in users_map and users_map[nid].is_domain_admin):
                domain_admin_compromised = True

        # Check detection mechanisms
        if not detection_triggered:
            # Check Canary files
            canary_triggered = False
            if profile.security_controls.honeytokens_or_canary_files:
                for sid in compromised_nodes:
                    if sid in all_share_ids:
                        canary_triggered = True
                        break

            # Check EDR alerts
            edr_alerts_count = sum(
                1 for hid in compromised_nodes
                if (hid in hosts_map and hosts_map[hid].edr_installed and hosts_map[hid].edr_active) or
                   (hid in dcs_map and dcs_map[hid].edr_installed and dcs_map[hid].edr_active)
            )

            # SOC triage time
            soc_delay = (
                assumptions.soc_24_7_alert_delay_hours * 60.0
                if profile.security_controls.soc_monitoring_24_7
                else assumptions.soc_alert_delay_hours * 60.0
            )

            if canary_triggered:
                detection_triggered = True
                detection_step = step_index
                detection_time_minutes = current_time + 15.0
                detection_mechanism = "Canary File / Honeytoken Tripwire"
            elif edr_alerts_count >= 2:
                detection_triggered = True
                detection_step = step_index
                detection_time_minutes = current_time + soc_delay
                detection_mechanism = (
                    f"EDR Behavioral Telemetry ({edr_alerts_count} agents alerted) + "
                    f"{'24/7 SOC Triage' if profile.security_controls.soc_monitoring_24_7 else 'Standard SOC Triage'}"
                )
            elif domain_admin_compromised and profile.security_controls.centralized_logging:
                detection_triggered = True
                detection_step = step_index
                detection_time_minutes = current_time + soc_delay
                detection_mechanism = "SIEM Alert: Privileged Domain Admin Activity"

        # Determine actively contained hosts (EDR isolation)
        contained_hosts: Set[str] = set()
        if detection_triggered and detection_time_minutes is not None:
            containment_delay = 15.0 if profile.security_controls.automated_containment else 60.0
            if current_time >= (detection_time_minutes + containment_delay):
                for hid in compromised_nodes:
                    h = hosts_map.get(hid) or dcs_map.get(hid)
                    if h and h.edr_installed and h.edr_active:
                        contained_hosts.add(hid)

        # 2. Advance encryption for compromised shares
        enc_gb_per_host_step = (
            assumptions.encryption_throughput_mb_s * 60.0 * step_minutes
        ) / 1024.0

        for sid, s in shares_map.items():
            if sid in compromised_nodes and sid not in encrypted_shares:
                # Contained host cannot continue encrypting
                if s.host_id in contained_hosts:
                    continue
                share_encryption_progress[sid] += enc_gb_per_host_step
                if share_encryption_progress[sid] >= s.data_volume_gb:
                    share_encryption_progress[sid] = s.data_volume_gb
                    encrypted_shares.add(sid)

        # 3. Lateral spread evaluation from all currently compromised nodes
        current_comp_hosts = [n for n in compromised_nodes if n in all_host_ids]
        current_comp_users = [n for n in compromised_nodes if n in users_map]

        for host_id in current_comp_hosts:
            # Contained hosts cannot move laterally
            if host_id in contained_hosts:
                continue

            host_obj = hosts_map.get(host_id) or dcs_map.get(host_id)
            host_seg = segments_map.get(host_obj.segment_id) if host_obj else None

            # Outgoing neighbors
            for _, target_id, edge_data in graph.out_edges(host_id, data=True):
                rel_type = edge_data.get("relationship_type", "")

                # A. Host -> FileShare encryption targeting
                if target_id in all_share_ids and target_id not in scheduled_compromises:
                    target_share = shares_map[target_id]
                    # Check if share is in an isolated segment
                    share_seg = segments_map.get(target_share.segment_id)
                    if share_seg and (share_seg.is_isolated or share_seg.firewall_rules_strict):
                        if host_obj and host_obj.segment_id != share_seg.id and not domain_admin_compromised:
                            continue
                    scheduled_compromises[target_id] = current_time + 5.0
                    node_discovery_time[target_id] = current_time + 5.0

                # B. Host -> BackupRepository reachability
                elif target_id in all_backup_ids and target_id not in scheduled_compromises:
                    backup_obj = backups_map[target_id]
                    if backup_obj.is_offline or backup_obj.is_immutable:
                        continue

                    # If domain-joined and domain admin compromised, or explicit edge
                    if rel_type == "backup_reachable" or (backup_obj.domain_joined and domain_admin_compromised and not backup_obj.credential_isolated):
                        delay = assumptions.hop_delay_cross_segment_minutes
                        scheduled_compromises[target_id] = current_time + delay
                        node_discovery_time[target_id] = current_time + delay

                # C. Host -> Host lateral movement
                elif target_id in all_host_ids and target_id not in scheduled_compromises:
                    target_host = hosts_map.get(target_id) or dcs_map.get(target_id)
                    target_seg = segments_map.get(target_host.segment_id) if target_host else None

                    # Least-privilege barrier on peer workstation spread
                    if rel_type == "same_segment":
                        if target_host and target_host.local_admin_restricted and not target_host.has_unquoted_service_path:
                            continue

                    # Segmentation barrier on isolated zones (e.g. Finance)
                    if target_seg and (target_seg.is_isolated or target_seg.firewall_rules_strict):
                        if host_obj and host_obj.segment_id != target_seg.id:
                            if rel_type not in ("admin_on",) or not domain_admin_compromised:
                                continue

                    # Credential reuse barrier to Domain Controller
                    if rel_type == "credential_reuse":
                        if target_id in dcs_map:
                            # If admin accounts have MFA enforced, credential reuse to DC is blocked
                            admin_mfa = any(u.mfa_enabled for u in users_map.values() if u.is_domain_admin)
                            if admin_mfa:
                                continue

                    # Compute traversal delay
                    delay = 0.0

                    if host_obj and target_host and host_obj.segment_id == target_host.segment_id:
                        delay += assumptions.hop_delay_same_segment_minutes
                    else:
                        delay += assumptions.hop_delay_cross_segment_minutes

                    if target_host and not target_host.local_admin_restricted:
                        pass
                    elif target_host and target_host.has_unquoted_service_path:
                        delay += 10.0
                    else:
                        delay += assumptions.hop_delay_privilege_escalation_minutes

                    if target_host and target_host.edr_installed and target_host.edr_active:
                        delay += assumptions.hop_delay_edr_penalty_minutes

                    scheduled_compromises[target_id] = current_time + delay
                    node_discovery_time[target_id] = current_time + delay

                # D. Host -> User (credential harvesting on host)
                elif target_id in users_map and target_id not in scheduled_compromises:
                    u_obj = users_map[target_id]
                    if u_obj.mfa_enabled:
                        continue  # MFA prevents lateral offline credential reuse
                    delay = 15.0
                    scheduled_compromises[target_id] = current_time + delay
                    node_discovery_time[target_id] = current_time + delay

        # Spread from compromised users (e.g. pivoting to hosts they administer)
        for u_id in current_comp_users:
            u_obj = users_map[u_id]
            # MFA blocks automated remote administrative logon
            if u_obj.mfa_enabled and u_id != patient_zero_id:
                continue

            for _, target_id, edge_data in graph.out_edges(u_id, data=True):
                rel_type = edge_data.get("relationship_type", "")
                if target_id in all_host_ids and target_id not in scheduled_compromises:
                    if rel_type in ("admin_on", "logged_in_on"):
                        delay = 15.0
                        target_host = hosts_map.get(target_id) or dcs_map.get(target_id)
                        if target_host and target_host.edr_installed and target_host.edr_active:
                            delay += assumptions.hop_delay_edr_penalty_minutes
                        scheduled_compromises[target_id] = current_time + delay
                        node_discovery_time[target_id] = current_time + delay

        # Check backup compromise via Domain Admin if domain is fully compromised
        if domain_admin_compromised:
            for bid, b_obj in backups_map.items():
                if bid not in scheduled_compromises:
                    if not b_obj.is_offline and not b_obj.is_immutable:
                        if b_obj.domain_joined and not b_obj.credential_isolated:
                            scheduled_compromises[bid] = current_time + assumptions.hop_delay_cross_segment_minutes
            # Check Canary files
            canary_triggered = False
            if profile.security_controls.honeytokens_or_canary_files:
                for sid in compromised_nodes:
                    if sid in all_share_ids:
                        canary_triggered = True
                        break

            # Check EDR alerts
            edr_alerts_count = sum(
                1 for hid in compromised_nodes
                if (hid in hosts_map and hosts_map[hid].edr_installed and hosts_map[hid].edr_active) or
                   (hid in dcs_map and dcs_map[hid].edr_installed and dcs_map[hid].edr_active)
            )

            # SOC triage time
            soc_delay = (
                assumptions.soc_24_7_alert_delay_hours * 60.0
                if profile.security_controls.soc_monitoring_24_7
                else assumptions.soc_alert_delay_hours * 60.0
            )

            if canary_triggered:
                detection_triggered = True
                detection_step = step_index
                detection_time_minutes = current_time + 15.0
                detection_mechanism = "Canary File / Honeytoken Tripwire"
            elif edr_alerts_count >= 2:
                detection_triggered = True
                detection_step = step_index
                detection_time_minutes = current_time + soc_delay
                detection_mechanism = (
                    f"EDR Behavioral Telemetry ({edr_alerts_count} agents alerted) + "
                    f"{'24/7 SOC Triage' if profile.security_controls.soc_monitoring_24_7 else 'Standard SOC Triage'}"
                )
            elif domain_admin_compromised and profile.security_controls.centralized_logging:
                detection_triggered = True
                detection_step = step_index
                detection_time_minutes = current_time + soc_delay
                detection_mechanism = "SIEM Alert: Privileged Domain Admin Activity"

        # Record timeline step
        comp_hosts = sum(1 for n in compromised_nodes if n in all_host_ids)
        comp_shares = sum(1 for n in compromised_nodes if n in all_share_ids)
        comp_backups = sum(1 for n in compromised_nodes if n in all_backup_ids)
        total_encrypted_gb = sum(share_encryption_progress.values())

        event_desc = (
            f"Step {step_index} ({current_time:.0f}m): "
            f"{len(newly_compromised_this_step)} newly compromised entities. "
            f"Active: {comp_hosts} hosts, {comp_shares} shares, {total_encrypted_gb:.1f} GB data encrypted."
        )

        timeline.append(
            TimelineStep(
                step_index=step_index,
                elapsed_minutes=current_time,
                newly_compromised=newly_compromised_this_step,
                total_compromised_count=len(compromised_nodes),
                compromised_hosts_count=comp_hosts,
                compromised_shares_count=comp_shares,
                compromised_backups_count=comp_backups,
                encrypted_data_gb=round(total_encrypted_gb, 2),
                detection_triggered=detection_triggered,
                event_description=event_desc,
            )
        )

        # Termination conditions: no new scheduled items ready and nothing pending
        pending_schedules = [
            t for nid, t in scheduled_compromises.items() if nid not in compromised_nodes
        ]
        unencrypted_accessible_shares = [
            sid for sid in compromised_nodes
            if sid in all_share_ids and sid not in encrypted_shares
        ]
        if not pending_schedules and not unencrypted_accessible_shares and step_index > 0:
            step_index += 1
            break

        step_index += 1

    # Final tally calculations
    total_hosts_count = len(all_host_ids)
    comp_hosts_count = sum(1 for n in compromised_nodes if n in all_host_ids)
    host_comp_pct = (comp_hosts_count / total_hosts_count * 100.0) if total_hosts_count > 0 else 0.0

    total_shares_count = len(all_share_ids)
    comp_shares_count = sum(1 for n in compromised_nodes if n in all_share_ids)
    share_comp_pct = (comp_shares_count / total_shares_count * 100.0) if total_shares_count > 0 else 0.0

    total_data_gb = sum(s.data_volume_gb for s in profile.file_shares)
    encrypted_data_gb = sum(share_encryption_progress.values())
    data_enc_pct = (encrypted_data_gb / total_data_gb * 100.0) if total_data_gb > 0 else 0.0

    total_critical = len(critical_asset_ids)
    comp_critical = sum(1 for n in compromised_nodes if n in critical_asset_ids)
    critical_comp_pct = (comp_critical / total_critical * 100.0) if total_critical > 0 else 0.0

    comp_dcs_count = sum(1 for dcid in dcs_map.keys() if dcid in compromised_nodes)
    da_reached = domain_admin_compromised or comp_dcs_count > 0

    total_backups_count = len(all_backup_ids)
    comp_backups_count = sum(1 for bid in all_backup_ids if bid in compromised_nodes)
    backups_compromised_flag = comp_backups_count > 0

    # Immutable backups surviving check
    immutable_survived = any(
        b.is_immutable or b.is_offline for b in profile.backup_repositories
    )

    # Composite blast radius percentage
    # 35% host + 35% data + 20% critical assets + 10% DC/DA
    composite_br = (
        0.35 * host_comp_pct
        + 0.35 * data_enc_pct
        + 0.20 * critical_comp_pct
        + 0.10 * (100.0 if da_reached else 0.0)
    )

    # Detection proxy calculation
    # Telemetry coverage = % of hosts with active EDR
    active_edr_hosts = sum(
        1 for h in list(profile.hosts) + list(profile.domain_controllers)
        if h.edr_installed and h.edr_active
    )
    telemetry_pct = (active_edr_hosts / total_hosts_count * 100.0) if total_hosts_count > 0 else 0.0

    if detection_time_minutes is not None:
        estimated_ttd_hours = round(detection_time_minutes / 60.0, 2)
    else:
        # Default fallback estimate based on telemetry coverage
        # High coverage detects faster, low coverage takes 12-24+ hours
        estimated_ttd_hours = round(max(0.5, 24.0 * (1.0 - (telemetry_pct / 100.0) * 0.8)), 2)
        detection_mechanism = "Post-Incident Forensic Triage (No Early Warning)"

    blast_radius = BlastRadiusMetrics(
        total_hosts=total_hosts_count,
        compromised_hosts=comp_hosts_count,
        host_compromise_pct=round(host_comp_pct, 2),
        total_file_shares=total_shares_count,
        compromised_file_shares=comp_shares_count,
        file_share_compromise_pct=round(share_comp_pct, 2),
        total_data_gb=round(total_data_gb, 2),
        encrypted_data_gb=round(encrypted_data_gb, 2),
        data_encrypted_pct=round(data_enc_pct, 2),
        total_critical_assets=total_critical,
        critical_assets_compromised=comp_critical,
        critical_asset_compromise_pct=round(critical_comp_pct, 2),
        domain_controllers_compromised=comp_dcs_count,
        domain_admin_reached=da_reached,
        total_backup_repositories=total_backups_count,
        backup_repositories_compromised=comp_backups_count,
        backups_compromised_flag=backups_compromised_flag,
        immutable_backups_survived=immutable_survived,
        composite_blast_radius_pct=round(composite_br, 2),
    )

    detection_metrics = DetectionMetrics(
        estimated_ttd_hours=estimated_ttd_hours,
        detection_mechanism=detection_mechanism,
        detection_step=detection_step,
        telemetry_coverage_pct=round(telemetry_pct, 2),
    )

    da_path = find_domain_admin_path(graph, patient_zero_id)

    return SimulationResult(
        patient_zero_id=patient_zero_id,
        patient_zero_name=pz_name,
        patient_zero_type=pz_type,
        department=pz_dept,
        total_steps=len(timeline),
        duration_hours=round((len(timeline) * step_minutes) / 60.0, 2),
        blast_radius=blast_radius,
        detection=detection_metrics,
        timeline=timeline,
        privilege_escalation_path=da_path,
        assumptions_used=assumptions,
    )


def evaluate_patient_zero_rankings(
    profile: OrganizationProfile,
    assumptions: Optional[SimulationAssumptions] = None,
    max_candidates: Optional[int] = None,
) -> PatientZeroRankingResponse:
    """
    Evaluates all users and hosts as candidate patient zeros.
    Ranks them by composite risk score (blast radius + data loss + backup compromise).
    """
    if assumptions is None:
        assumptions = DEFAULT_ASSUMPTIONS

    candidate_ids: List[Tuple[str, str, str, str]] = []  # (id, name, type, dept)

    for u in profile.users:
        candidate_ids.append((u.id, u.name, "User", u.department))
    for h in profile.hosts:
        candidate_ids.append((h.id, h.hostname, "Host", "Infrastructure"))
    for dc in profile.domain_controllers:
        candidate_ids.append((dc.id, dc.hostname, "Host", "Domain Services"))

    if max_candidates and len(candidate_ids) > max_candidates:
        candidate_ids = candidate_ids[:max_candidates]

    results: List[PatientZeroRankingEntry] = []

    for cid, cname, ctype, cdept in candidate_ids:
        sim = run_simulation(
            profile=profile,
            patient_zero_id=cid,
            assumptions=assumptions,
            max_hours=12.0,  # Fast evaluation window for ranking
        )
        br = sim.blast_radius
        # Risk score calculation: 0-100
        # Combines blast radius pct, backup compromise (+20 pts), DA reached (+15 pts)
        risk = br.composite_blast_radius_pct
        if br.backups_compromised_flag:
            risk = min(100.0, risk + 20.0)
        if br.domain_admin_reached:
            risk = min(100.0, risk + 10.0)

        results.append(
            PatientZeroRankingEntry(
                rank=0,  # assigned after sort
                entity_id=cid,
                entity_name=cname,
                entity_type=ctype,
                department=cdept,
                host_compromise_pct=br.host_compromise_pct,
                data_encrypted_pct=br.data_encrypted_pct,
                critical_asset_compromise_pct=br.critical_asset_compromise_pct,
                domain_admin_reached=br.domain_admin_reached,
                backups_compromised=br.backups_compromised_flag,
                estimated_ttd_hours=sim.detection.estimated_ttd_hours,
                risk_score=round(risk, 2),
            )
        )

    # Sort descending by risk_score, then by data_encrypted_pct
    results.sort(key=lambda r: (r.risk_score, r.data_encrypted_pct), reverse=True)

    for idx, entry in enumerate(results, start=1):
        entry.rank = idx

    worst_case = results[0] if results else PatientZeroRankingEntry(
        rank=1,
        entity_id="none",
        entity_name="None",
        entity_type="Host",
        department="N/A",
        host_compromise_pct=0.0,
        data_encrypted_pct=0.0,
        critical_asset_compromise_pct=0.0,
        domain_admin_reached=False,
        backups_compromised=False,
        estimated_ttd_hours=0.0,
        risk_score=0.0,
    )

    return PatientZeroRankingResponse(
        worst_case_patient_zero=worst_case,
        rankings=results,
        total_evaluated=len(results),
    )
