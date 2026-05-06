"""Tests for graph model and traversal."""
import pytest
from privmap.graph.model import (
    Edge, EdgeType, EscalationPath, Node, NodeType, PrivilegeGraph, Severity,
)
from privmap.graph.traversal import find_escalation_paths, is_sink_node


@pytest.fixture
def graph():
    return PrivilegeGraph()


def _add_user(graph, name, uid, shell="/bin/bash"):
    n = Node(
        id=f"user:{name}", node_type=NodeType.USER, name=name,
        properties={"uid": uid, "gid": uid, "shell": shell},
    )
    return graph.add_node(n)


def _add_group(graph, name, gid):
    n = Node(
        id=f"group:{name}", node_type=NodeType.GROUP, name=name,
        properties={"gid": gid},
    )
    return graph.add_node(n)


class TestPrivilegeGraph:
    def test_add_node(self, graph):
        node = _add_user(graph, "alice", 1000)
        assert graph.node_count == 1
        assert graph.get_node("user:alice") == node

    def test_add_duplicate_node_merges(self, graph):
        _add_user(graph, "alice", 1000)
        n2 = Node(
            id="user:alice", node_type=NodeType.USER, name="alice",
            properties={"uid": 1000, "extra": True},
        )
        graph.add_node(n2)
        assert graph.node_count == 1
        assert graph.get_node("user:alice").properties["extra"] is True

    def test_add_edge(self, graph):
        _add_user(graph, "alice", 1000)
        _add_group(graph, "docker", 999)
        edge = Edge(
            source_id="user:alice", target_id="group:docker",
            edge_type=EdgeType.MEMBER_OF,
        )
        graph.add_edge(edge)
        assert graph.edge_count == 1

    def test_get_neighbors(self, graph):
        _add_user(graph, "alice", 1000)
        _add_group(graph, "docker", 999)
        graph.add_edge(Edge(
            source_id="user:alice", target_id="group:docker",
            edge_type=EdgeType.MEMBER_OF,
        ))
        neighbors = graph.get_neighbors("user:alice")
        assert len(neighbors) == 1
        assert neighbors[0][0].name == "docker"

    def test_edge_deduplication(self, graph):
        _add_user(graph, "alice", 1000)
        _add_group(graph, "docker", 999)
        for _ in range(3):
            graph.add_edge(Edge(
                source_id="user:alice", target_id="group:docker",
                edge_type=EdgeType.MEMBER_OF,
            ))
        assert graph.edge_count == 1


class TestTraversal:
    def test_direct_sudo_path(self, graph):
        _add_user(graph, "bob", 1000)
        root = _add_user(graph, "root", 0)

        sudo = Node(
            id="sudo:bob:ALL", node_type=NodeType.SUDO_RULE,
            name="bob -> ALL",
            properties={"command": "ALL", "nopasswd": True},
        )
        graph.add_node(sudo)

        graph.add_edge(Edge(
            source_id="user:bob", target_id="sudo:bob:ALL",
            edge_type=EdgeType.GRANTS, properties={"nopasswd": True},
        ))
        graph.add_edge(Edge(
            source_id="sudo:bob:ALL", target_id="user:root",
            edge_type=EdgeType.GRANTS, properties={"command": "ALL"},
        ))

        paths = find_escalation_paths(graph, source_users=["bob"])
        assert len(paths) >= 1
        assert paths[0].source.name == "bob"
        assert paths[0].sink.name in ("root", "bob -> ALL")

    def test_no_path_for_nologin(self, graph):
        _add_user(graph, "daemon", 2, shell="/usr/sbin/nologin")
        _add_user(graph, "root", 0)
        paths = find_escalation_paths(graph)
        assert len(paths) == 0

    def test_writable_cron_path(self, graph):
        _add_user(graph, "www-data", 33)
        _add_user(graph, "root", 0)

        script = Node(
            id="file:/etc/cron.daily/cleanup.sh",
            node_type=NodeType.FILE, name="/etc/cron.daily/cleanup.sh",
            properties={"path": "/etc/cron.daily/cleanup.sh", "world_writable": True},
        )
        graph.add_node(script)

        cron = Node(
            id="cron:/etc/cron.daily/cleanup.sh",
            node_type=NodeType.CRON_JOB, name="cleanup",
            properties={"run_as": "root"},
        )
        graph.add_node(cron)

        # www-data can write the script
        graph.add_edge(Edge(
            source_id="user:www-data",
            target_id="file:/etc/cron.daily/cleanup.sh",
            edge_type=EdgeType.CAN_WRITE,
        ))
        # Cron executes the script
        graph.add_edge(Edge(
            source_id="cron:/etc/cron.daily/cleanup.sh",
            target_id="file:/etc/cron.daily/cleanup.sh",
            edge_type=EdgeType.EXECUTES,
        ))
        # Cron runs as root
        graph.add_edge(Edge(
            source_id="cron:/etc/cron.daily/cleanup.sh",
            target_id="user:root",
            edge_type=EdgeType.RUNS_AS,
        ))
        # Script -> root (via cron execution context)
        graph.add_edge(Edge(
            source_id="file:/etc/cron.daily/cleanup.sh",
            target_id="user:root",
            edge_type=EdgeType.RUNS_AS,
            properties={"via": "cron"},
        ))

        paths = find_escalation_paths(graph, source_users=["www-data"])
        assert len(paths) >= 1


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_ge(self):
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert Severity.HIGH >= Severity.MEDIUM
