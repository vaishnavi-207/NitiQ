"""
NitiQ - Organization Schemas & Relationship Models
Defines all enterprise entities, relationships, and graph validation logic.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field, field_validator, model_validator


class EdgeType(str, Enum):
    MEMBER_OF = "member_of"
    ADMIN_ON = "admin_on"
    LOGGED_IN_ON = "logged_in_on"
    CAN_WRITE = "can_write"
    SAME_SEGMENT = "same_segment"
    BACKUP_REACHABLE = "backup_reachable"
    CREDENTIAL_REUSE = "credential_reuse"


class User(BaseModel):
    id: str = Field(..., description="Unique user identifier, e.g. user-alice")
    name: str
    department: str = Field(..., description="Department, e.g. IT, Finance, HR, Engineering")
    role: str = Field(..., description="Job role, e.g. IT Administrator, Payroll Specialist")
    is_domain_admin: bool = False
    is_local_admin: bool = False
    mfa_enabled: bool = False
    phishing_prone_percentage: float = Field(default=20.0, ge=0.0, le=100.0)
    password_last_changed_days: int = Field(default=90, ge=0)


class Host(BaseModel):
    id: str = Field(..., description="Unique host identifier, e.g. host-ws-01")
    hostname: str
    ip_address: str
    segment_id: str
    os: str = "Windows 11"
    is_critical: bool = False
    is_domain_controller: bool = False
    edr_installed: bool = False
    edr_active: bool = False
    patch_level: str = Field(default="updated", description="critical_missing, delayed, updated")
    local_admin_restricted: bool = True
    has_unquoted_service_path: bool = False


class DomainController(Host):
    is_domain_controller: bool = True
    is_critical: bool = True
    ad_forest: str = "corp.local"
    ldap_signing_enforced: bool = True


class FileShare(BaseModel):
    id: str = Field(..., description="Unique share identifier, e.g. share-finance")
    name: str
    host_id: str = Field(..., description="Host on which share resides")
    segment_id: str
    data_volume_gb: float = Field(..., gt=0, description="Volume of data in GB")
    critical_data: bool = False
    department: str = "General"
    sensitive_data_type: str = "Confidential"
    unencrypted: bool = True


class BackupRepository(BaseModel):
    id: str = Field(..., description="Unique backup repo identifier, e.g. backup-repo-01")
    name: str
    segment_id: str
    host_id: Optional[str] = None
    backup_type: str = Field(default="nas", description="immutable_cloud, nas, san, tape, offline_airgap")
    is_immutable: bool = False
    is_offline: bool = False
    domain_joined: bool = True
    credential_isolated: bool = False
    storage_capacity_tb: float = Field(default=50.0, gt=0)
    restore_throughput_mb_s: float = Field(default=50.0, gt=0, description="Restore speed in MB/s")
    last_restore_test_days: int = Field(default=90, ge=0)
    snapshot_frequency_hours: int = Field(default=24, gt=0)


class NetworkSegment(BaseModel):
    id: str = Field(..., description="Unique network segment identifier, e.g. seg-workstations")
    name: str
    cidr: str
    zone_type: str = Field(..., description="workstations, finance, it_admin, dmz, backup, datacenter")
    is_isolated: bool = False
    firewall_rules_strict: bool = False


class RelationshipEdge(BaseModel):
    source_id: str
    target_id: str
    relationship_type: EdgeType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityControls(BaseModel):
    centralized_logging: bool = False
    soc_monitoring_24_7: bool = False
    honeytokens_or_canary_files: bool = False
    automated_containment: bool = False
    privileged_access_management: bool = False
    network_microsegmentation: bool = False
    regular_restore_testing: bool = False


class OrganizationProfile(BaseModel):
    id: str
    name: str
    description: str = ""
    industry: str = "Technology"
    required_rto_hours: float = Field(default=24.0, gt=0, description="Required Recovery Time Objective (hours)")
    required_rpo_hours: float = Field(default=12.0, gt=0, description="Required Recovery Point Objective (hours)")
    incident_response_plan: bool = True
    runbook_available: bool = True
    security_controls: SecurityControls = Field(default_factory=SecurityControls)

    users: List[User] = Field(default_factory=list)
    hosts: List[Host] = Field(default_factory=list)
    domain_controllers: List[DomainController] = Field(default_factory=list)
    file_shares: List[FileShare] = Field(default_factory=list)
    backup_repositories: List[BackupRepository] = Field(default_factory=list)
    network_segments: List[NetworkSegment] = Field(default_factory=list)
    edges: List[RelationshipEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references_and_unique_ids(self) -> "OrganizationProfile":
        # 1. Check for duplicate IDs across all entities
        all_entities: Dict[str, str] = {}  # id -> entity_type

        def register(eid: str, etype: str):
            if eid in all_entities:
                raise ValueError(
                    f"Duplicate ID '{eid}' detected in '{etype}'. Already registered as '{all_entities[eid]}'."
                )
            all_entities[eid] = etype

        for u in self.users:
            register(u.id, "User")
        for h in self.hosts:
            register(h.id, "Host")
        for dc in self.domain_controllers:
            register(dc.id, "DomainController")
        for s in self.file_shares:
            register(s.id, "FileShare")
        for b in self.backup_repositories:
            register(b.id, "BackupRepository")
        for seg in self.network_segments:
            register(seg.id, "NetworkSegment")

        # 2. Check segment references on hosts, shares, backup repos
        valid_seg_ids = {seg.id for seg in self.network_segments}
        for h in self.hosts:
            if h.segment_id not in valid_seg_ids:
                raise ValueError(
                    f"Host '{h.id}' references non-existent segment_id '{h.segment_id}'. Available segments: {sorted(valid_seg_ids)}"
                )
        for dc in self.domain_controllers:
            if dc.segment_id not in valid_seg_ids:
                raise ValueError(
                    f"DomainController '{dc.id}' references non-existent segment_id '{dc.segment_id}'. Available segments: {sorted(valid_seg_ids)}"
                )
        for s in self.file_shares:
            if s.segment_id not in valid_seg_ids:
                raise ValueError(
                    f"FileShare '{s.id}' references non-existent segment_id '{s.segment_id}'. Available segments: {sorted(valid_seg_ids)}"
                )
            # Check host_id for share
            if s.host_id not in all_entities or all_entities[s.host_id] not in ("Host", "DomainController"):
                raise ValueError(
                    f"FileShare '{s.id}' references invalid host_id '{s.host_id}'. Must reference an existing Host or DomainController."
                )
        for b in self.backup_repositories:
            if b.segment_id not in valid_seg_ids:
                raise ValueError(
                    f"BackupRepository '{b.id}' references non-existent segment_id '{b.segment_id}'. Available segments: {sorted(valid_seg_ids)}"
                )
            if b.host_id and b.host_id not in all_entities:
                raise ValueError(
                    f"BackupRepository '{b.id}' references non-existent host_id '{b.host_id}'."
                )

        # 3. Check all relationship edges
        for idx, edge in enumerate(self.edges):
            if edge.source_id not in all_entities:
                raise ValueError(
                    f"Edge #{idx} ({edge.relationship_type.value}) references missing source_id '{edge.source_id}'."
                )
            if edge.target_id not in all_entities:
                raise ValueError(
                    f"Edge #{idx} ({edge.relationship_type.value}) references missing target_id '{edge.target_id}'."
                )

            # Check logical relationship pairings
            src_type = all_entities[edge.source_id]
            tgt_type = all_entities[edge.target_id]

            if edge.relationship_type == EdgeType.ADMIN_ON:
                if src_type != "User" or tgt_type not in ("Host", "DomainController"):
                    raise ValueError(
                        f"admin_on edge requires User -> Host/DomainController, got {src_type} ('{edge.source_id}') -> {tgt_type} ('{edge.target_id}')"
                    )
            elif edge.relationship_type == EdgeType.LOGGED_IN_ON:
                if src_type != "User" or tgt_type not in ("Host", "DomainController"):
                    raise ValueError(
                        f"logged_in_on edge requires User -> Host/DomainController, got {src_type} ('{edge.source_id}') -> {tgt_type} ('{edge.target_id}')"
                    )
            elif edge.relationship_type == EdgeType.CAN_WRITE:
                if tgt_type != "FileShare":
                    raise ValueError(
                        f"can_write edge target must be a FileShare, got {tgt_type} ('{edge.target_id}')"
                    )
            elif edge.relationship_type == EdgeType.BACKUP_REACHABLE:
                if tgt_type != "BackupRepository":
                    raise ValueError(
                        f"backup_reachable edge target must be a BackupRepository, got {tgt_type} ('{edge.target_id}')"
                    )

        return self
