"""
Unit tests for Organization schemas and relationship validation.
"""

import pytest
from pydantic import ValidationError
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


def test_valid_minimal_profile_passes(minimal_profile):
    assert minimal_profile.id == "minimal_test_org"
    assert len(minimal_profile.users) == 1
    assert len(minimal_profile.hosts) == 1
    assert len(minimal_profile.file_shares) == 1


def test_duplicate_entity_id_raises_helpful_error():
    with pytest.raises(ValueError, match="Duplicate ID 'duplicate-id' detected"):
        OrganizationProfile(
            id="test_dup_org",
            name="Duplicate Org",
            users=[
                User(id="duplicate-id", name="User 1", department="IT", role="Admin"),
            ],
            hosts=[
                Host(id="duplicate-id", hostname="HOST-01", ip_address="10.0.0.1", segment_id="seg-1"),
            ],
            network_segments=[
                NetworkSegment(id="seg-1", name="Segment 1", cidr="10.0.0.0/24", zone_type="workstations")
            ],
        )


def test_invalid_segment_reference_raises_error():
    with pytest.raises(ValueError, match="references non-existent segment_id 'seg-nonexistent'"):
        OrganizationProfile(
            id="test_seg_org",
            name="Invalid Segment Org",
            hosts=[
                Host(id="h-01", hostname="HOST-01", ip_address="10.0.0.1", segment_id="seg-nonexistent"),
            ],
            network_segments=[
                NetworkSegment(id="seg-valid", name="Valid Seg", cidr="10.0.0.0/24", zone_type="workstations")
            ],
        )


def test_invalid_share_host_reference_raises_error():
    with pytest.raises(ValueError, match="references invalid host_id 'h-missing'"):
        OrganizationProfile(
            id="test_share_org",
            name="Invalid Share Host Org",
            file_shares=[
                FileShare(id="s-01", name="Share", host_id="h-missing", segment_id="seg-1", data_volume_gb=100.0)
            ],
            network_segments=[
                NetworkSegment(id="seg-1", name="Valid Seg", cidr="10.0.0.0/24", zone_type="workstations")
            ],
        )


def test_invalid_edge_source_raises_error():
    with pytest.raises(ValueError, match="references missing source_id 'user-ghost'"):
        OrganizationProfile(
            id="test_edge_org",
            name="Invalid Edge Org",
            network_segments=[
                NetworkSegment(id="seg-1", name="Valid Seg", cidr="10.0.0.0/24", zone_type="workstations")
            ],
            hosts=[
                Host(id="h-01", hostname="HOST-01", ip_address="10.0.0.1", segment_id="seg-1"),
            ],
            edges=[
                RelationshipEdge(source_id="user-ghost", target_id="h-01", relationship_type=EdgeType.ADMIN_ON)
            ],
        )


def test_invalid_edge_type_pairing_raises_error():
    with pytest.raises(ValueError, match="admin_on edge requires User -> Host/DomainController"):
        OrganizationProfile(
            id="test_edge_type_org",
            name="Invalid Edge Type Org",
            network_segments=[
                NetworkSegment(id="seg-1", name="Valid Seg", cidr="10.0.0.0/24", zone_type="workstations")
            ],
            hosts=[
                Host(id="h-01", hostname="HOST-01", ip_address="10.0.0.1", segment_id="seg-1"),
                Host(id="h-02", hostname="HOST-02", ip_address="10.0.0.2", segment_id="seg-1"),
            ],
            edges=[
                # Host -> Host cannot have relationship_type admin_on (must be User -> Host)
                RelationshipEdge(source_id="h-01", target_id="h-02", relationship_type=EdgeType.ADMIN_ON)
            ],
        )
