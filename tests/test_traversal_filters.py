"""Tests for the traversal-time filters in privmap.graph.traversal.

These pin down the three filter layers that decide whether a candidate
escalation path is reported or dropped:

- ``AUTH_REQUIRED_SUID`` -> never a free escalation path.
- ``KNOWN_SAFE_CAP_BINARIES`` -> capability binaries that are safe by
  package design.
- ``GTFOBINS_SUID`` allowlist -> a SUID_EXEC edge is only a real
  escalation when the binary is on this list.

Each was introduced to suppress a specific class of false positive.
Without tests these are easy to regress when the lists are tuned.
"""
import pytest

from privmap.graph.model import (
    Edge, EdgeType, Node, NodeType, PrivilegeGraph,
)
from privmap.graph.traversal import (
    AUTH_REQUIRED_SUID,
    GTFOBINS_SUID,
    KNOWN_SAFE_CAP_BINARIES,
    find_escalation_paths,
    is_sink_node,
    is_source_principal,
)


def _make_graph_with_users():
    """A minimal graph: root, www-data (with shell), nobody (nologin)."""
    g = PrivilegeGraph()
    g.add_node(Node(
        id="user:root", node_type=NodeType.USER, name="root",
        properties={"uid": 0, "gid": 0, "shell": "/bin/bash"},
    ))
    g.add_node(Node(
        id="user:www-data", node_type=NodeType.USER, name="www-data",
        properties={"uid": 33, "gid": 33, "shell": "/bin/bash"},
    ))
    g.add_node(Node(
        id="user:nobody", node_type=NodeType.USER, name="nobody",
        properties={"uid": 65534, "gid": 65534, "shell": "/usr/sbin/nologin"},
    ))
    return g


def _add_suid_binary(graph, path, owner="root"):
    """Add a SUID_BINARY node, a RUNS_AS edge to root, and a SUID_EXEC
    edge from www-data. Returns the binary's node id."""
    binary_name = path.rsplit("/", 1)[-1]
    node_id = f"suid:{path}"
    graph.add_node(Node(
        id=node_id, node_type=NodeType.SUID_BINARY, name=path,
        properties={"path": path, "binary": binary_name, "owner": owner, "suid": True},
    ))
    if owner == "root":
        graph.add_edge(Edge(
            source_id=node_id, target_id="user:root",
            edge_type=EdgeType.RUNS_AS, properties={"suid": True, "path": path},
        ))
    graph.add_edge(Edge(
        source_id="user:www-data", target_id=node_id,
        edge_type=EdgeType.SUID_EXEC, properties={"path": path},
    ))
    return node_id


class TestAuthRequiredSuidFilter:
    """SUID binaries that gate access behind a credential prompt
    (su, sudo, pkexec, mount, etc.) must not produce escalation paths."""

    @pytest.mark.parametrize("binary", [
        "/usr/bin/su",
        "/usr/bin/sudo",
        "/usr/bin/pkexec",
        "/usr/bin/doas",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/lib/openssh/ssh-keysign",
    ])
    def test_auth_required_binary_does_not_produce_path(self, binary):
        graph = _make_graph_with_users()
        _add_suid_binary(graph, binary)
        paths = find_escalation_paths(graph, source_users=["www-data"])
        assert paths == [], (
            f"{binary} is auth-required and must not produce an "
            f"escalation path, but got {len(paths)} path(s)"
        )

    def test_filter_set_contains_known_auth_binaries(self):
        # Sanity check: if any of these get removed from the allowlist
        # the filter loses coverage.
        for name in ["su", "sudo", "pkexec", "mount", "passwd"]:
            assert name in AUTH_REQUIRED_SUID

    def test_auth_required_takes_priority_over_gtfobins(self):
        # pkexec used to be in GTFOBINS_SUID. The filter must reject it
        # via AUTH_REQUIRED before the GTFOBins check runs.
        assert "pkexec" in AUTH_REQUIRED_SUID
        # And critically it must not also be in GTFOBINS_SUID (which
        # would let it through if AUTH_REQUIRED check were dropped).
        assert "pkexec" not in GTFOBINS_SUID


class TestGtfobinsSuidFilter:
    """SUID binaries are only escalation paths if they are on the
    GTFOBins shell-escape list."""

    @pytest.mark.parametrize("binary", [
        "/usr/bin/find",
        "/usr/bin/vim",
        "/usr/bin/gdb",
        "/usr/bin/python3",
        "/usr/bin/perl",
        "/usr/bin/bash",
        "/usr/bin/tar",
        "/usr/bin/cp",
    ])
    def test_gtfobins_binary_produces_path(self, binary):
        graph = _make_graph_with_users()
        _add_suid_binary(graph, binary)
        paths = find_escalation_paths(graph, source_users=["www-data"])
        assert len(paths) >= 1, (
            f"{binary} is on the GTFOBins list and should produce an "
            f"escalation path"
        )

    @pytest.mark.parametrize("binary", [
        "/usr/bin/some-random-suid",
        "/opt/vendor/proprietary-tool",
        "/usr/lib/some-utility",
    ])
    def test_non_gtfobins_binary_does_not_produce_path(self, binary):
        # A SUID-root binary that is not on the shell-escape list is a
        # hardening concern but not a free escalation path.
        graph = _make_graph_with_users()
        _add_suid_binary(graph, binary)
        paths = find_escalation_paths(graph, source_users=["www-data"])
        assert paths == [], (
            f"{binary} is not on GTFOBins and should not produce a path"
        )


class TestKnownSafeCapBinaries:
    """Capability binaries on the known-safe list (ping, mtr, etc.)
    must not produce escalation paths even though they carry caps that
    would otherwise be a sink."""

    def _add_cap_chain(self, graph, binary_path, cap="cap_sys_admin"):
        """Build the user -> CAN_EXEC -> file -> HAS_CAPABILITY -> cap
        -> GRANTS -> root chain that the traversal would normally walk."""
        binary_name = binary_path.rsplit("/", 1)[-1]
        file_id = f"file:{binary_path}"
        cap_id = f"capability:{cap}:{binary_path}"
        graph.add_node(Node(
            id=file_id, node_type=NodeType.FILE, name=binary_path,
            properties={"path": binary_path, "binary_name": binary_name},
        ))
        graph.add_node(Node(
            id=cap_id, node_type=NodeType.CAPABILITY, name=cap,
            properties={
                "capability": cap, "binary": binary_path,
                "binary_name": binary_name, "dangerous": True,
            },
        ))
        graph.add_edge(Edge(
            source_id="user:www-data", target_id=file_id,
            edge_type=EdgeType.CAN_EXEC,
            properties={"reason": "capability-binary", "path": binary_path},
        ))
        graph.add_edge(Edge(
            source_id=file_id, target_id=cap_id,
            edge_type=EdgeType.HAS_CAPABILITY, properties={},
        ))
        graph.add_edge(Edge(
            source_id=cap_id, target_id="user:root",
            edge_type=EdgeType.GRANTS,
            properties={"capability": cap, "binary": binary_path},
        ))

    @pytest.mark.parametrize("binary", [
        "/usr/bin/ping",
        "/usr/bin/mtr",
        "/usr/bin/traceroute",
        "/usr/lib/snapd/snap-confine",
        "/usr/sbin/chronyd",
    ])
    def test_known_safe_binary_produces_no_path(self, binary):
        graph = _make_graph_with_users()
        self._add_cap_chain(graph, binary)
        paths = find_escalation_paths(graph, source_users=["www-data"])
        assert paths == [], (
            f"{binary} carries caps by design and must not produce a path"
        )

    def test_safelist_contains_expected_binaries(self):
        for name in ["ping", "mtr", "snap-confine", "chronyd"]:
            assert name in KNOWN_SAFE_CAP_BINARIES


class TestSinkAndSourcePredicates:
    """The traversal entry-point predicates."""

    def test_root_is_a_sink(self):
        root = Node(
            id="user:root", node_type=NodeType.USER, name="root",
            properties={"uid": 0},
        )
        assert is_sink_node(root) is True

    def test_nonroot_user_is_not_a_sink(self):
        u = Node(
            id="user:www-data", node_type=NodeType.USER, name="www-data",
            properties={"uid": 33},
        )
        assert is_sink_node(u) is False

    def test_sudo_all_is_a_sink(self):
        rule = Node(
            id="sudo:alice:ALL", node_type=NodeType.SUDO_RULE, name="alice -> ALL",
            properties={"command": "ALL"},
        )
        assert is_sink_node(rule) is True

    def test_dangerous_cap_on_unsafe_binary_is_sink(self):
        cap = Node(
            id="capability:cap_setuid:/usr/bin/foo",
            node_type=NodeType.CAPABILITY, name="cap_setuid",
            properties={"binary_name": "foo"},
        )
        assert is_sink_node(cap) is True

    def test_dangerous_cap_on_safe_binary_is_not_sink(self):
        cap = Node(
            id="capability:cap_setuid:/usr/bin/ping",
            node_type=NodeType.CAPABILITY, name="cap_setuid",
            properties={"binary_name": "ping"},
        )
        assert is_sink_node(cap) is False

    def test_normal_user_with_shell_is_a_source(self):
        u = Node(
            id="user:www-data", node_type=NodeType.USER, name="www-data",
            properties={"uid": 33, "shell": "/bin/bash"},
        )
        assert is_source_principal(u) is True

    def test_root_is_not_a_source(self):
        u = Node(
            id="user:root", node_type=NodeType.USER, name="root",
            properties={"uid": 0, "shell": "/bin/bash"},
        )
        assert is_source_principal(u) is False

    @pytest.mark.parametrize("shell", [
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/bin/false",
    ])
    def test_nologin_shells_are_not_sources(self, shell):
        u = Node(
            id="user:nobody", node_type=NodeType.USER, name="nobody",
            properties={"uid": 65534, "shell": shell},
        )
        assert is_source_principal(u) is False
