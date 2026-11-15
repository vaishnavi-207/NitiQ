"""
Script to generate valid synthetic Weak, Average, and Strong organization profiles for NitiQ.
Ensures ~40 users, 25 hosts, 10 shares, 2 backup repositories, network segments, and valid edges.
"""

import json
from pathlib import Path
from backend.app.models.organization import (
    OrganizationProfile,
    User,
    Host,
    DomainController,
    FileShare,
    BackupRepository,
    NetworkSegment,
    RelationshipEdge,
    EdgeType,
    SecurityControls,
)


def create_network_segments(profile_type: str):
    is_strong = profile_type == "strong"
    is_avg = profile_type == "average"

    return [
        NetworkSegment(
            id="seg-workstations",
            name="Workstation User Subnet",
            cidr="10.0.10.0/24",
            zone_type="workstations",
            is_isolated=False,
            firewall_rules_strict=False,
        ),
        NetworkSegment(
            id="seg-finance",
            name="Finance & Payroll Isolated Zone",
            cidr="10.0.20.0/24",
            zone_type="finance",
            is_isolated=is_strong or is_avg,
            firewall_rules_strict=is_strong,
        ),
        NetworkSegment(
            id="seg-it-admin",
            name="IT Management & Core Services",
            cidr="10.0.30.0/24",
            zone_type="it_admin",
            is_isolated=is_strong,
            firewall_rules_strict=is_strong,
        ),
        NetworkSegment(
            id="seg-servers",
            name="Corporate Application & File Servers",
            cidr="10.0.40.0/24",
            zone_type="datacenter",
            is_isolated=is_strong,
            firewall_rules_strict=is_strong,
        ),
        NetworkSegment(
            id="seg-backup",
            name="Backup Infrastructure Storage Zone",
            cidr="10.0.50.0/24",
            zone_type="backup",
            is_isolated=is_strong,
            firewall_rules_strict=is_strong,
        ),
    ]


def create_users(profile_type: str):
    is_strong = profile_type == "strong"
    is_avg = profile_type == "average"

    # 40 users across departments
    departments = [
        ("IT", ["SysAdmin", "Network Engineer", "Helpdesk Lead", "SecOps Analyst", "DBA"]),
        ("Finance", ["CFO", "Finance Director", "Payroll Lead", "Billing Analyst", "Accounts Payable", "Auditor"]),
        ("HR", ["HR VP", "HR Generalist", "Recruiter", "People Ops Specialist", "Benefits Coordinator"]),
        ("Engineering", ["Principal Architect", "DevOps Engineer", "Frontend Dev", "Backend Dev", "QA Lead", "Site Reliability Engineer", "Platform Eng", "Data Scientist"]),
        ("Sales", ["Sales VP", "Account Exec 1", "Account Exec 2", "Sales Ops", "BDR 1", "BDR 2"]),
        ("Operations", ["COO", "Ops Director", "Supply Chain Lead", "Logistics Mgr", "Procurement Specialist", "Facilities Mgr", "Warehouse Lead", "Compliance Officer", "Vendor Mgr", "Admin Assistant"]),
    ]

    users = []
    uid = 1
    for dept, roles in departments:
        for role in roles:
            uname = f"{dept.lower()}_{role.lower().replace(' ', '_')}"
            user_id = f"user-{uid:02d}"

            # Admin flags
            is_da = False
            is_la = False
            mfa = False

            if dept == "IT":
                if role in ("SysAdmin", "Network Engineer"):
                    is_da = True
                    is_la = True
                    mfa = is_strong or is_avg  # avg has mfa on admin
                elif role in ("Helpdesk Lead", "SecOps Analyst", "DBA"):
                    is_la = True
                    mfa = is_strong or is_avg
            elif profile_type == "weak":
                # In weak org, standard users have local admin rights!
                is_la = True
                mfa = False
            elif profile_type == "average":
                if role in ("CFO", "DevOps Engineer"):
                    is_la = True
                    mfa = True
                else:
                    is_la = False
                    mfa = False
            elif profile_type == "strong":
                # In strong org, only dedicated tier-0 has DA, no users have standard LA, 100% MFA
                is_la = False
                mfa = True

            phish_pct = 45.0 if profile_type == "weak" else (22.0 if is_avg else 5.0)
            pwd_age = 240 if profile_type == "weak" else (90 if is_avg else 30)

            users.append(
                User(
                    id=user_id,
                    name=f"{role} ({dept})",
                    department=dept,
                    role=role,
                    is_domain_admin=is_da,
                    is_local_admin=is_la,
                    mfa_enabled=mfa,
                    phishing_prone_percentage=phish_pct,
                    password_last_changed_days=pwd_age,
                )
            )
            uid += 1

    return users


def create_hosts_and_dcs(profile_type: str):
    is_strong = profile_type == "strong"
    is_avg = profile_type == "average"

    # 2 Domain Controllers in IT Admin zone
    dcs = [
        DomainController(
            id="dc-01",
            hostname="CORP-DC-01",
            ip_address="10.0.30.10",
            segment_id="seg-it-admin",
            os="Windows Server 2022",
            is_critical=True,
            edr_installed=is_strong or is_avg,
            edr_active=is_strong or is_avg,
            patch_level="updated" if (is_strong or is_avg) else "critical_missing",
            local_admin_restricted=True,
            has_unquoted_service_path=False,
            ad_forest="corp.nitiq.internal",
            ldap_signing_enforced=is_strong,
        ),
        DomainController(
            id="dc-02",
            hostname="CORP-DC-02",
            ip_address="10.0.30.11",
            segment_id="seg-it-admin",
            os="Windows Server 2022",
            is_critical=True,
            edr_installed=is_strong or is_avg,
            edr_active=is_strong,
            patch_level="updated" if is_strong else "delayed",
            local_admin_restricted=True,
            has_unquoted_service_path=False,
            ad_forest="corp.nitiq.internal",
            ldap_signing_enforced=is_strong,
        ),
    ]

    # 23 standard hosts: 15 workstations, 3 finance hosts, 5 application/file servers
    hosts = []

    # 15 workstations
    for i in range(1, 16):
        hid = f"host-ws-{i:02d}"
        edr_inst = is_strong or (is_avg and i <= 10)
        edr_act = is_strong or (is_avg and i <= 8)
        la_rest = is_strong or (is_avg and i > 5)
        unquoted = (profile_type == "weak" and i in (1, 4, 7))

        hosts.append(
            Host(
                id=hid,
                hostname=f"WS-CLIENT-{i:02d}",
                ip_address=f"10.0.10.{20 + i}",
                segment_id="seg-workstations",
                os="Windows 11 Enterprise",
                is_critical=False,
                is_domain_controller=False,
                edr_installed=edr_inst,
                edr_active=edr_act,
                patch_level="updated" if is_strong else ("delayed" if is_avg else "critical_missing"),
                local_admin_restricted=la_rest,
                has_unquoted_service_path=unquoted,
            )
        )

    # 3 Finance server/hosts
    for i in range(1, 4):
        hid = f"host-fin-{i:02d}"
        hosts.append(
            Host(
                id=hid,
                hostname=f"FIN-SRV-{i:02d}",
                ip_address=f"10.0.20.{10 + i}",
                segment_id="seg-finance",
                os="Windows Server 2019",
                is_critical=True,
                is_domain_controller=False,
                edr_installed=is_strong or is_avg,
                edr_active=is_strong,
                patch_level="updated" if is_strong else "delayed",
                local_admin_restricted=True,
                has_unquoted_service_path=False,
            )
        )

    # 5 Corporate application / file servers
    srv_names = ["FILE-SRV-01", "ERP-SRV-01", "HR-SRV-01", "DEV-SRV-01", "OPS-SRV-01"]
    for i, sname in enumerate(srv_names, start=1):
        hid = f"host-srv-{i:02d}"
        hosts.append(
            Host(
                id=hid,
                hostname=sname,
                ip_address=f"10.0.40.{10 + i}",
                segment_id="seg-servers",
                os="Windows Server 2022",
                is_critical=True if i in (1, 2) else False,
                is_domain_controller=False,
                edr_installed=is_strong or is_avg,
                edr_active=is_strong or (is_avg and i != 1),
                patch_level="updated" if is_strong else ("delayed" if is_avg else "critical_missing"),
                local_admin_restricted=is_strong or is_avg,
                has_unquoted_service_path=(profile_type == "weak" and i == 1),
            )
        )

    return hosts, dcs


def create_file_shares(profile_type: str):
    # 10 file shares
    share_defs = [
        ("share-corp-docs", "Corporate Documents", "host-srv-01", "seg-servers", 2500.0, False, "General"),
        ("share-fin-payroll", "Payroll & Compensation Records", "host-fin-01", "seg-finance", 1200.0, True, "Finance"),
        ("share-fin-erp", "ERP Financial Ledger", "host-fin-02", "seg-finance", 4500.0, True, "Finance"),
        ("share-fin-tax", "Quarterly Tax Filings", "host-fin-03", "seg-finance", 800.0, True, "Finance"),
        ("share-hr-confidential", "HR Personnel Files", "host-srv-03", "seg-servers", 1500.0, True, "HR"),
        ("share-dev-repo", "Source Code & Build Artifacts", "host-srv-04", "seg-servers", 6000.0, True, "Engineering"),
        ("share-ops-sc", "Supply Chain Contracts", "host-srv-05", "seg-servers", 1800.0, False, "Operations"),
        ("share-it-tools", "IT Deployment & Admin Tools", "host-srv-01", "seg-servers", 1100.0, False, "IT"),
        ("share-sales-crm", "Sales CRM Export Archives", "host-srv-01", "seg-servers", 2200.0, False, "Sales"),
        ("share-legal-ip", "Executive & Legal Patents", "host-srv-01", "seg-servers", 900.0, True, "Legal"),
    ]

    shares = []
    for sid, sname, hid, seg_id, vol, is_crit, dept in share_defs:
        shares.append(
            FileShare(
                id=sid,
                name=sname,
                host_id=hid,
                segment_id=seg_id,
                data_volume_gb=vol,
                critical_data=is_crit,
                department=dept,
                sensitive_data_type="Confidential" if is_crit else "Internal",
                unencrypted=(profile_type != "strong"),
            )
        )
    return shares


def create_backup_repositories(profile_type: str):
    if profile_type == "weak":
        return [
            BackupRepository(
                id="backup-nas-01",
                name="Central NAS Backup Share",
                segment_id="seg-workstations",  # Flat on workstation subnet!
                backup_type="nas",
                is_immutable=False,
                is_offline=False,
                domain_joined=True,
                credential_isolated=False,
                storage_capacity_tb=30.0,
                restore_throughput_mb_s=25.0,
                last_restore_test_days=400,
                snapshot_frequency_hours=24,
            ),
            BackupRepository(
                id="backup-nas-02",
                name="Secondary DR NAS Appliance",
                segment_id="seg-servers",
                backup_type="nas",
                is_immutable=False,
                is_offline=False,
                domain_joined=True,
                credential_isolated=False,
                storage_capacity_tb=30.0,
                restore_throughput_mb_s=20.0,
                last_restore_test_days=450,
                snapshot_frequency_hours=48,
            ),
        ]
    elif profile_type == "average":
        return [
            BackupRepository(
                id="backup-san-01",
                name="Enterprise SAN Backup Target",
                segment_id="seg-backup",
                backup_type="san",
                is_immutable=False,
                is_offline=False,
                domain_joined=True,
                credential_isolated=False,
                storage_capacity_tb=60.0,
                restore_throughput_mb_s=55.0,
                last_restore_test_days=110,
                snapshot_frequency_hours=12,
            ),
            BackupRepository(
                id="backup-cloud-01",
                name="Cloud Storage Replica",
                segment_id="seg-backup",
                backup_type="immutable_cloud",
                is_immutable=True,
                is_offline=False,
                domain_joined=False,
                credential_isolated=True,
                storage_capacity_tb=50.0,
                restore_throughput_mb_s=40.0,
                last_restore_test_days=95,
                snapshot_frequency_hours=24,
            ),
        ]
    else:  # strong
        return [
            BackupRepository(
                id="backup-immutable-vault",
                name="Zero-Trust Immutable S3 Object Vault",
                segment_id="seg-backup",
                backup_type="immutable_cloud",
                is_immutable=True,
                is_offline=False,
                domain_joined=False,
                credential_isolated=True,
                storage_capacity_tb=100.0,
                restore_throughput_mb_s=120.0,
                last_restore_test_days=14,
                snapshot_frequency_hours=4,
            ),
            BackupRepository(
                id="backup-offline-airgap",
                name="Cold Air-Gapped LTO Tape Vault",
                segment_id="seg-backup",
                backup_type="offline_airgap",
                is_immutable=True,
                is_offline=True,
                domain_joined=False,
                credential_isolated=True,
                storage_capacity_tb=80.0,
                restore_throughput_mb_s=85.0,
                last_restore_test_days=21,
                snapshot_frequency_hours=24,
            ),
        ]


def create_edges(profile_type: str, users, hosts, dcs, shares, backups):
    edges = []

    # 1. User login edges (each user logs into a workstation)
    for idx, u in enumerate(users):
        ws_idx = (idx % 15) + 1
        ws_id = f"host-ws-{ws_idx:02d}"
        edges.append(
            RelationshipEdge(
                source_id=u.id,
                target_id=ws_id,
                relationship_type=EdgeType.LOGGED_IN_ON,
            )
        )

    # 2. Admin privileges
    # IT SysAdmin (user-01) is admin on all servers and DCs
    edges.append(
        RelationshipEdge(
            source_id="user-01",
            target_id="dc-01",
            relationship_type=EdgeType.ADMIN_ON,
        )
    )
    edges.append(
        RelationshipEdge(
            source_id="user-01",
            target_id="dc-02",
            relationship_type=EdgeType.ADMIN_ON,
        )
    )
    for h in hosts:
        if "srv" in h.id or "fin" in h.id:
            edges.append(
                RelationshipEdge(
                    source_id="user-01",
                    target_id=h.id,
                    relationship_type=EdgeType.ADMIN_ON,
                )
            )

    # In weak profile: user-02 (Network Eng) has admin on all workstations and credential reuse
    if profile_type == "weak":
        for i in range(1, 16):
            edges.append(
                RelationshipEdge(
                    source_id="user-02",
                    target_id=f"host-ws-{i:02d}",
                    relationship_type=EdgeType.ADMIN_ON,
                )
            )
            # Credential reuse between client workstations and DC!
            if i in (1, 5, 9):
                edges.append(
                    RelationshipEdge(
                        source_id=f"host-ws-{i:02d}",
                        target_id="dc-01",
                        relationship_type=EdgeType.CREDENTIAL_REUSE,
                    )
                )

        # Workstations can directly reach weak backup share
        edges.append(
            RelationshipEdge(
                source_id="host-ws-01",
                target_id="backup-nas-01",
                relationship_type=EdgeType.BACKUP_REACHABLE,
            )
        )
        edges.append(
            RelationshipEdge(
                source_id="host-ws-05",
                target_id="backup-nas-01",
                relationship_type=EdgeType.BACKUP_REACHABLE,
            )
        )

    # 3. Share write access (Host -> FileShare via can_write)
    # File servers can write to their hosted shares
    for s in shares:
        edges.append(
            RelationshipEdge(
                source_id=s.host_id,
                target_id=s.id,
                relationship_type=EdgeType.CAN_WRITE,
            )
        )

    # In weak profile, workstations have direct unsegmented can_write to critical shares
    if profile_type == "weak":
        for i in range(1, 8):
            edges.append(
                RelationshipEdge(
                    source_id=f"host-ws-{i:02d}",
                    target_id="share-corp-docs",
                    relationship_type=EdgeType.CAN_WRITE,
                )
            )
            edges.append(
                RelationshipEdge(
                    source_id=f"host-ws-{i:02d}",
                    target_id="share-fin-payroll",
                    relationship_type=EdgeType.CAN_WRITE,
                )
            )

    return edges


def generate_profiles():
    out_dir = Path("sample_data")
    out_dir.mkdir(exist_ok=True)

    configs = [
        ("weak", "Weak Security Posture Organization", 48.0, 24.0, False, False, SecurityControls(
            centralized_logging=False,
            soc_monitoring_24_7=False,
            honeytokens_or_canary_files=False,
            automated_containment=False,
            privileged_access_management=False,
            network_microsegmentation=False,
            regular_restore_testing=False,
        )),
        ("average", "Average Security Posture Organization", 24.0, 12.0, True, False, SecurityControls(
            centralized_logging=True,
            soc_monitoring_24_7=False,
            honeytokens_or_canary_files=False,
            automated_containment=False,
            privileged_access_management=False,
            network_microsegmentation=False,
            regular_restore_testing=True,
        )),
        ("strong", "Strong Security Posture Organization", 12.0, 4.0, True, True, SecurityControls(
            centralized_logging=True,
            soc_monitoring_24_7=True,
            honeytokens_or_canary_files=True,
            automated_containment=True,
            privileged_access_management=True,
            network_microsegmentation=True,
            regular_restore_testing=True,
        )),
    ]

    for ptype, pname, rto, rpo, irp, rb, sec in configs:
        segments = create_network_segments(ptype)
        users = create_users(ptype)
        hosts, dcs = create_hosts_and_dcs(ptype)
        shares = create_file_shares(ptype)
        backups = create_backup_repositories(ptype)
        edges = create_edges(ptype, users, hosts, dcs, shares, backups)

        prof = OrganizationProfile(
            id=f"{ptype}_org",
            name=f"NitiQ Synthetic {ptype.capitalize()} Enterprise",
            description=f"Synthetic enterprise organization modeling a {ptype} defense profile.",
            industry="Financial Services & FinTech",
            required_rto_hours=rto,
            required_rpo_hours=rpo,
            incident_response_plan=irp,
            runbook_available=rb,
            security_controls=sec,
            users=users,
            hosts=hosts,
            domain_controllers=dcs,
            file_shares=shares,
            backup_repositories=backups,
            network_segments=segments,
            edges=edges,
        )

        target_file = out_dir / f"{ptype}_org.json"
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(prof.model_dump_json(indent=2))

        print(f"Generated {target_file}: {len(users)} users, {len(hosts) + len(dcs)} hosts, {len(shares)} shares, {len(backups)} backups, {len(edges)} edges.")


if __name__ == "__main__":
    generate_profiles()
