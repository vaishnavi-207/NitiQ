"""
Unit tests for NetworkX graph construction and path finding.
"""

from backend.app.simulation.graph import build_network_graph, find_domain_admin_path


def test_build_network_graph_weak_org(weak_profile):
    g = build_network_graph(weak_profile)
    assert g.number_of_nodes() > 70  # users (40) + hosts (23) + dcs (2) + shares (10) + backups (2) + segments (5)
    assert g.has_node("user-01")
    assert g.has_node("dc-01")
    assert g.has_node("host-ws-01")
    assert g.nodes["dc-01"]["is_domain_controller"] is True


def test_find_domain_admin_path_exists(weak_profile):
    g = build_network_graph(weak_profile)
    # user-01 is admin on dc-01
    path = find_domain_admin_path(g, "user-01")
    assert len(path) >= 1
    assert path[0] == "user-01"


def test_find_domain_admin_path_from_workstation(weak_profile):
    g = build_network_graph(weak_profile)
    # In weak profile, host-ws-01 has CREDENTIAL_REUSE to dc-01
    path = find_domain_admin_path(g, "host-ws-01")
    assert len(path) >= 2
    assert path[0] == "host-ws-01"
    assert path[-1] in ("dc-01", "dc-02", "user-01")


def test_find_domain_admin_path_nonexistent_node(weak_profile):
    g = build_network_graph(weak_profile)
    path = find_domain_admin_path(g, "non-existent-node")
    assert path == []
