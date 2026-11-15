"""
NitiQ - Network Graph Builder
Constructs and validates a NetworkX directed graph from OrganizationProfile.
"""

from typing import Dict, Any, List, Optional, Set
import networkx as nx
from backend.app.models.organization import (
    OrganizationProfile,
    EdgeType,
)


def build_network_graph(profile: OrganizationProfile) -> nx.DiGraph:
    """
    Constructs a directed NetworkX graph representing the organization's entities,
    permissions, logins, network topology, and access paths.
    """
    g = nx.DiGraph(
        id=profile.id,
        name=profile.name,
        required_rto_hours=profile.required_rto_hours,
        required_rpo_hours=profile.required_rpo_hours,
    )

    # 1. Add Network Segments
    for seg in profile.network_segments:
        g.add_node(
            seg.id,
            entity_type="network_segment",
            name=seg.name,
            cidr=seg.cidr,
            zone_type=seg.zone_type,
            is_isolated=seg.is_isolated,
            firewall_rules_strict=seg.firewall_rules_strict,
        )

    # 2. Add Users
    for u in profile.users:
        g.add_node(
            u.id,
            entity_type="user",
            name=u.name,
            department=u.department,
            role=u.role,
            is_domain_admin=u.is_domain_admin,
            is_local_admin=u.is_local_admin,
            mfa_enabled=u.mfa_enabled,
            phishing_prone_percentage=u.phishing_prone_percentage,
            password_last_changed_days=u.password_last_changed_days,
        )

    # 3. Add Standard Hosts
    for h in profile.hosts:
        g.add_node(
            h.id,
            entity_type="host",
            name=h.hostname,
            ip_address=h.ip_address,
            segment_id=h.segment_id,
            os=h.os,
            is_critical=h.is_critical,
            is_domain_controller=False,
            edr_installed=h.edr_installed,
            edr_active=h.edr_active,
            patch_level=h.patch_level,
            local_admin_restricted=h.local_admin_restricted,
            has_unquoted_service_path=h.has_unquoted_service_path,
        )
        # Link host to its segment
        g.add_edge(h.id, h.segment_id, relationship_type="in_segment")
        g.add_edge(h.segment_id, h.id, relationship_type="contains_host")

    # 4. Add Domain Controllers
    for dc in profile.domain_controllers:
        g.add_node(
            dc.id,
            entity_type="host",
            name=dc.hostname,
            ip_address=dc.ip_address,
            segment_id=dc.segment_id,
            os=dc.os,
            is_critical=True,
            is_domain_controller=True,
            edr_installed=dc.edr_installed,
            edr_active=dc.edr_active,
            patch_level=dc.patch_level,
            local_admin_restricted=dc.local_admin_restricted,
            has_unquoted_service_path=dc.has_unquoted_service_path,
            ad_forest=dc.ad_forest,
            ldap_signing_enforced=dc.ldap_signing_enforced,
        )
        # Link DC to its segment
        g.add_edge(dc.id, dc.segment_id, relationship_type="in_segment")
        g.add_edge(dc.segment_id, dc.id, relationship_type="contains_host")

    # 5. Add File Shares
    for s in profile.file_shares:
        g.add_node(
            s.id,
            entity_type="file_share",
            name=s.name,
            host_id=s.host_id,
            segment_id=s.segment_id,
            data_volume_gb=s.data_volume_gb,
            critical_data=s.critical_data,
            department=s.department,
            sensitive_data_type=s.sensitive_data_type,
            unencrypted=s.unencrypted,
        )
        # Host hosts share
        g.add_edge(s.host_id, s.id, relationship_type="hosts_share")
        # Bidirectional access from host to share
        g.add_edge(s.id, s.host_id, relationship_type="share_hosted_on")

    # 6. Add Backup Repositories
    for b in profile.backup_repositories:
        g.add_node(
            b.id,
            entity_type="backup_repository",
            name=b.name,
            segment_id=b.segment_id,
            host_id=b.host_id,
            backup_type=b.backup_type,
            is_immutable=b.is_immutable,
            is_offline=b.is_offline,
            domain_joined=b.domain_joined,
            credential_isolated=b.credential_isolated,
            storage_capacity_tb=b.storage_capacity_tb,
            restore_throughput_mb_s=b.restore_throughput_mb_s,
            last_restore_test_days=b.last_restore_test_days,
            snapshot_frequency_hours=b.snapshot_frequency_hours,
        )
        g.add_edge(b.id, b.segment_id, relationship_type="in_segment")
        if b.host_id and g.has_node(b.host_id):
            g.add_edge(b.host_id, b.id, relationship_type="hosts_backup")

    # 7. Add Explicit Relationships from Profile
    for edge in profile.edges:
        g.add_edge(
            edge.source_id,
            edge.target_id,
            relationship_type=edge.relationship_type.value,
            **edge.metadata,
        )

    # 8. Add implicit intra-segment communication edges between hosts if not microsegmented
    microseg = profile.security_controls.network_microsegmentation
    if not microseg:
        segment_to_hosts: Dict[str, List[str]] = {}
        for h in list(profile.hosts) + list(profile.domain_controllers):
            segment_to_hosts.setdefault(h.segment_id, []).append(h.id)

        for seg_id, hosts in segment_to_hosts.items():
            for i in range(len(hosts)):
                for j in range(i + 1, len(hosts)):
                    h1, h2 = hosts[i], hosts[j]
                    if not g.has_edge(h1, h2):
                        g.add_edge(h1, h2, relationship_type="same_segment")
                    if not g.has_edge(h2, h1):
                        g.add_edge(h2, h1, relationship_type="same_segment")

    return g


def find_domain_admin_path(graph: nx.DiGraph, start_node: str) -> List[str]:
    """
    Finds the shortest privilege escalation / lateral path from start_node
    to any Domain Controller or Domain Admin user.
    Returns the path of node IDs, or empty list if no path exists.
    """
    if not graph.has_node(start_node):
        return []

    target_nodes: Set[str] = set()
    for node_id, attrs in graph.nodes(data=True):
        if attrs.get("is_domain_controller", False) or attrs.get("is_domain_admin", False):
            target_nodes.add(node_id)

    if start_node in target_nodes:
        return [start_node]

    shortest_path: List[str] = []
    min_len = float("inf")

    # We only traverse valid propagation edge types
    valid_propagation_edges = {
        "admin_on",
        "logged_in_on",
        "credential_reuse",
        "same_segment",
        "member_of",
    }

    # Filter subgraph for valid propagation
    sub_edges = [
        (u, v)
        for u, v, d in graph.edges(data=True)
        if d.get("relationship_type") in valid_propagation_edges
    ]
    sub_g = nx.DiGraph()
    sub_g.add_nodes_from(graph.nodes(data=True))
    sub_g.add_edges_from(sub_edges)

    for target in target_nodes:
        if nx.has_path(sub_g, start_node, target):
            try:
                p = nx.shortest_path(sub_g, start_node, target)
                if len(p) < min_len:
                    min_len = len(p)
                    shortest_path = p
            except nx.NetworkXNoPath:
                pass

    return shortest_path
