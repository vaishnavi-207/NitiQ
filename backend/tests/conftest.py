"""
Pytest configuration and shared fixtures for NitiQ.
"""

import pytest
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
from backend.app.data.loader import load_profile_by_id


@pytest.fixture
def weak_profile() -> OrganizationProfile:
    return load_profile_by_id("weak_org")


@pytest.fixture
def average_profile() -> OrganizationProfile:
    return load_profile_by_id("average_org")


@pytest.fixture
def strong_profile() -> OrganizationProfile:
    return load_profile_by_id("strong_org")


@pytest.fixture
def minimal_profile() -> OrganizationProfile:
    """Minimal 3-node profile for exact edge-case testing."""
    return OrganizationProfile(
        id="minimal_test_org",
        name="Minimal Test Organization",
        required_rto_hours=12.0,
        required_rpo_hours=4.0,
        incident_response_plan=True,
        runbook_available=True,
        security_controls=SecurityControls(),
        network_segments=[
            NetworkSegment(
                id="seg-test",
                name="Test Subnet",
                cidr="10.0.0.0/24",
                zone_type="workstations",
            )
        ],
        users=[
            User(
                id="u-admin",
                name="Admin User",
                department="IT",
                role="Administrator",
                is_domain_admin=True,
                is_local_admin=True,
                mfa_enabled=False,
            )
        ],
        hosts=[
            Host(
                id="h-01",
                hostname="TEST-WS-01",
                ip_address="10.0.0.10",
                segment_id="seg-test",
                edr_installed=False,
                edr_active=False,
                local_admin_restricted=True,
            )
        ],
        domain_controllers=[],
        file_shares=[
            FileShare(
                id="s-01",
                name="Test Data Share",
                host_id="h-01",
                segment_id="seg-test",
                data_volume_gb=500.0,
            )
        ],
        backup_repositories=[
            BackupRepository(
                id="b-01",
                name="Test Backup NAS",
                segment_id="seg-test",
                restore_throughput_mb_s=50.0,
                last_restore_test_days=30,
            )
        ],
        edges=[
            RelationshipEdge(
                source_id="u-admin",
                target_id="h-01",
                relationship_type=EdgeType.ADMIN_ON,
            ),
            RelationshipEdge(
                source_id="h-01",
                target_id="s-01",
                relationship_type=EdgeType.CAN_WRITE,
            ),
        ],
    )
