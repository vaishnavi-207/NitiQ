# NitiQ Organization Schema Specification

## Overview

**NitiQ** assesses enterprise ransomware readiness through quantified, reproducible simulation models. The foundation of this model is the **Organization Profile**, a structured, graph-compatible schema representing an enterprise's identity structure, compute infrastructure, file repositories, backup targets, network segmentation boundaries, and active access pathways.

All organization profiles are strictly validated using Pydantic v2 schemas and verified against graph referential constraints.

---

## 1. Top-Level Organization Profile (`OrganizationProfile`)

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | Unique identifier (e.g. `weak_org`, `finance_corp_prod`). |
| `name` | `string` | Yes | Human-readable organization name. |
| `description` | `string` | No | Architectural or contextual description. |
| `industry` | `string` | No | Vertical sector (e.g. `Financial Services`, `Healthcare`). |
| `required_rto_hours` | `float` | Yes | Target Recovery Time Objective in hours (e.g., `24.0`). Must be > 0. |
| `required_rpo_hours` | `float` | Yes | Target Recovery Point Objective in hours (e.g., `12.0`). Must be > 0. |
| `incident_response_plan` | `boolean` | Yes | Indicates presence of an authorized technical incident response plan. |
| `runbook_available` | `boolean` | Yes | Indicates availability of verified technical disaster recovery runbooks. |
| `security_controls` | `SecurityControls` | Yes | Global defensive posture switches (logging, SOC, canary files, etc.). |
| `users` | `User[]` | Yes | List of user accounts in the domain. |
| `hosts` | `Host[]` | Yes | Standard servers and client workstations. |
| `domain_controllers` | `DomainController[]`| Yes | Active Directory Domain Controllers. |
| `file_shares` | `FileShare[]` | Yes | Network shares and file repositories. |
| `backup_repositories` | `BackupRepository[]`| Yes | Target backup repositories and storage vaults. |
| `network_segments` | `NetworkSegment[]` | Yes | Network subnets and security zones. |
| `edges` | `RelationshipEdge[]`| Yes | Explicit relationship and lateral movement access edges. |

---

## 2. Entity Types

### 2.1 User (`User`)
Represents human identities in the organization.

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | `string` | Required | Unique user identifier (e.g. `user-01`). |
| `name` | `string` | Required | Display name or title. |
| `department` | `string` | Required | Functional group (`IT`, `Finance`, `HR`, `Engineering`, etc.). |
| `role` | `string` | Required | Job role. |
| `is_domain_admin` | `boolean` | `false` | Grants Tier-0 domain administration privileges. |
| `is_local_admin` | `boolean` | `false` | Grants local workstation administrative rights. |
| `mfa_enabled` | `boolean` | `false` | Whether multi-factor authentication is enforced. |
| `phishing_prone_percentage` | `float` | `20.0` | Simulated phishing susceptibility metric (0–100%). |
| `password_last_changed_days` | `integer` | `90` | Password age in days. |

### 2.2 Host (`Host`)
Represents compute instances (workstations, database servers, application hosts).

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | `string` | Required | Unique host identifier (e.g. `host-ws-01`). |
| `hostname` | `string` | Required | Network NetBIOS/DNS hostname. |
| `ip_address` | `string` | Required | IPv4 address (e.g. `10.0.10.21`). |
| `segment_id` | `string` | Required | Reference to a valid `NetworkSegment.id`. |
| `os` | `string` | `Windows 11` | Operating system flavor. |
| `is_critical` | `boolean` | `false` | Flags high-value business assets. |
| `is_domain_controller`| `boolean` | `false` | Set to true if running AD DS. |
| `edr_installed` | `boolean` | `false` | Whether EDR sensor is deployed. |
| `edr_active` | `boolean` | `false` | Whether EDR sensor is actively reporting and containing. |
| `patch_level` | `string` | `updated` | `critical_missing`, `delayed`, or `updated`. |
| `local_admin_restricted`| `boolean` | `true` | Restricts standard user elevation. |
| `has_unquoted_service_path`| `boolean`| `false` | Synthetic privilege escalation vulnerability. |

### 2.3 Domain Controller (`DomainController`)
Extends `Host` with identity infrastructure properties.
- `is_domain_controller` is always `true`.
- `is_critical` is always `true`.
- `ad_forest`: Domain forest root (e.g., `corp.nitiq.internal`).
- `ldap_signing_enforced`: Boolean indicating LDAP signing and channel binding.

### 2.4 File Share (`FileShare`)
Represents structured and unstructured corporate file repositories.

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | `string` | Required | Unique share identifier (e.g. `share-fin-payroll`). |
| `name` | `string` | Required | Share display name. |
| `host_id` | `string` | Required | Must reference an existing `Host.id` or `DomainController.id`. |
| `segment_id` | `string` | Required | Must reference an existing `NetworkSegment.id`. |
| `data_volume_gb` | `float` | Required | Total data payload in gigabytes (> 0). |
| `critical_data` | `boolean` | `false` | Flags sensitive/business-critical repositories. |
| `department` | `string` | `General` | Owning business department. |
| `sensitive_data_type`| `string`| `Confidential` | Classification tag. |
| `unencrypted` | `boolean` | `true` | Unencrypted at rest. |

### 2.5 Backup Repository (`BackupRepository`)
Represents backup storage appliances, cloud buckets, and tape vaults.

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | `string` | Required | Unique identifier (e.g. `backup-nas-01`). |
| `name` | `string` | Required | Name of backup repository. |
| `segment_id` | `string` | Required | Must reference a valid `NetworkSegment.id`. |
| `host_id` | `string` | `null` | Optional associated storage host. |
| `backup_type` | `string` | `nas` | `immutable_cloud`, `nas`, `san`, `tape`, `offline_airgap`. |
| `is_immutable` | `boolean` | `false` | Object locking / WORM immutability active. |
| `is_offline` | `boolean` | `false` | Physically air-gapped from network. |
| `domain_joined` | `boolean` | `true` | Shares domain trust and credentials. |
| `credential_isolated`| `boolean`| `false` | Uses dedicated non-domain credentials. |
| `restore_throughput_mb_s`| `float`| `50.0` | Sustained restore bandwidth (> 0). |
| `last_restore_test_days`| `integer`| `90` | Elapsed days since last verified restore drill. |
| `snapshot_frequency_hours`| `integer`| `24` | Backup cadence. |

### 2.6 Network Segment (`NetworkSegment`)
Represents network VLANs and routing security perimeters.

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | `string` | Required | Segment identifier (e.g. `seg-workstations`). |
| `name` | `string` | Required | Zone description. |
| `cidr` | `string` | Required | IP subnet mask (e.g. `10.0.10.0/24`). |
| `zone_type` | `string` | Required | `workstations`, `finance`, `it_admin`, `dmz`, `backup`, `datacenter`. |
| `is_isolated` | `boolean` | `false` | Enforces strict network perimeter isolation. |
| `firewall_rules_strict` | `boolean` | `false` | Filters lateral cross-VLAN packets. |

---

## 3. Relationship Edge Types (`RelationshipEdge`)

All propagation paths in NitiQ are defined by directed edges:
`source_id -> target_id` with `relationship_type`:

| Edge Type | Valid Source | Valid Target | Propagation Semantic |
|---|---|---|---|
| `member_of` | User / Host / Share | Segment | Topological membership. |
| `admin_on` | User | Host / DomainController | Administrative authority. Enables lateral traversal and privilege takeover. |
| `logged_in_on` | User | Host | Interactive session. Attacker compromise allows credential harvesting. |
| `can_write` | Host / User | FileShare | Direct file modification. Triggers file share encryption. |
| `same_segment` | Host | Host | Unrestricted layer-2/layer-3 lateral communication. |
| `backup_reachable` | Host | BackupRepository | Network route to backup storage. |
| `credential_reuse` | Host / User | Host / DomainController | Shared passwords / Kerberos ticket pass-through. |

---

## 4. Referential Validation Rules

NitiQ enforces the following validation checks prior to running simulations:
1. **Unique IDs**: Node IDs must be unique across all entities (Users, Hosts, DCs, Shares, Backups, Segments).
2. **Segment Integrity**: Every Host, DC, FileShare, and BackupRepository must reference an existing `NetworkSegment.id`.
3. **Share Hosting Integrity**: Every FileShare must reference a valid `Host.id` or `DomainController.id`.
4. **Edge Consistency**: Both `source_id` and `target_id` must reference valid entities, and the types must match semantic constraints (e.g. `admin_on` requires `User -> Host/DC`).
5. **Clear Error Reporting**: On failure, the API returns diagnostic HTTP 422 JSON detailing the exact offending node or edge.
