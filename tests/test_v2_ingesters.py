"""Tests for the v2.0 ingesters.

Covers the new check categories added in v2.0: group-writable detection,
login-time scripts, ld.so configuration, polkit, doas, NFS exports,
fstab, host trust, container markers, PAM, and config-arg INFLUENCES_EXEC
edges. Each ingester is exercised against a tmp_path-rooted fake system
so we can write controlled fixtures and verify the resulting graph state.
"""
import os
import stat
import textwrap

import pytest

from privmap.graph.model import (
    Edge, EdgeType, Node, NodeType, PrivilegeGraph,
)
from privmap.ingestion.identity import IdentityIngester
from privmap.ingestion.filesystem import FilesystemIngester
from privmap.ingestion.boot import BootIngester
from privmap.ingestion.auth import AuthIngester
from privmap.ingestion.network import NetworkIngester
from privmap.ingestion.container import ContainerIngester
from privmap.ingestion.pam import PAMIngester
from privmap.ingestion.execution import ExecutionIngester


# ----- helpers -----

def _make_etc(tmp_path, passwd=None, group=None):
    """Populate /etc/passwd and /etc/group under tmp_path."""
    etc = tmp_path / "etc"
    etc.mkdir(exist_ok=True)
    if passwd is None:
        passwd = textwrap.dedent("""\
            root:x:0:0:root:/root:/bin/bash
            alice:x:1000:1000::/home/alice:/bin/bash
            wwwdev:x:1001:1001::/home/wwwdev:/bin/bash
        """)
    if group is None:
        group = textwrap.dedent("""\
            root:x:0:
            adm:x:4:wwwdev
            sudo:x:27:alice
        """)
    (etc / "passwd").write_text(passwd)
    (etc / "group").write_text(group)
    return etc


def _populate_identity(tmp_path):
    """Build a graph with the standard test identity baseline already loaded."""
    _make_etc(tmp_path)
    graph = PrivilegeGraph()
    IdentityIngester(root_path=str(tmp_path)).ingest(graph)
    return graph


# ===== Group-writable detection =====

class TestGroupWritable:
    """The filesystem walk should emit CAN_WRITE edges for each user in a
    group-writable file's group. This was the v1 demo-blocker.

    These tests use snapshot mode so they can inject arbitrary ownership
    via the group_writable_files.txt fixture (regular pytest runs as a
    non-root user cannot chown to arbitrary uids/gids)."""

    def _setup_snapshot(self, tmp_path):
        """Make tmp_path look like an extracted snapshot directory."""
        graph = _populate_identity(tmp_path)
        suid_dir = tmp_path / "suid"
        suid_dir.mkdir()
        return graph, suid_dir

    def test_group_writable_emits_per_member_edges(self, tmp_path):
        graph, suid_dir = self._setup_snapshot(tmp_path)
        # Format: mode owner group path
        (suid_dir / "group_writable_files.txt").write_text(
            "664 root adm /etc/logrotate.d/myapp\n"
        )
        FilesystemIngester(
            root_path=str(tmp_path), snapshot_mode=True,
        ).ingest(graph)

        # wwwdev is in adm, alice is not.
        wwwdev_edges = [
            e for e in graph.get_edges_from("user:wwwdev")
            if e.edge_type == EdgeType.CAN_WRITE
            and "/etc/logrotate.d/myapp" in e.target_id
        ]
        alice_edges = [
            e for e in graph.get_edges_from("user:alice")
            if e.edge_type == EdgeType.CAN_WRITE
            and "/etc/logrotate.d/myapp" in e.target_id
        ]
        assert len(wwwdev_edges) == 1
        assert len(alice_edges) == 0
        assert wwwdev_edges[0].properties.get("group") == "adm"

    def test_root_group_emits_no_edges(self, tmp_path):
        """Files owned by root:root should never produce CAN_WRITE edges."""
        graph, suid_dir = self._setup_snapshot(tmp_path)
        (suid_dir / "group_writable_files.txt").write_text(
            "664 root root /etc/boring.conf\n"
        )
        FilesystemIngester(
            root_path=str(tmp_path), snapshot_mode=True,
        ).ingest(graph)

        for u in ["user:wwwdev", "user:alice"]:
            for e in graph.get_edges_from(u):
                if e.edge_type == EdgeType.CAN_WRITE:
                    assert "boring.conf" not in e.target_id

    def test_world_writable_produces_edges_for_all_users(self, tmp_path):
        """World-writable file via the snapshot world_writable list."""
        graph, suid_dir = self._setup_snapshot(tmp_path)
        (suid_dir / "world_writable_files.txt").write_text(
            "/etc/script.sh\n"
        )
        FilesystemIngester(
            root_path=str(tmp_path), snapshot_mode=True,
        ).ingest(graph)

        alice_edges = [
            e for e in graph.get_edges_from("user:alice")
            if e.edge_type == EdgeType.CAN_WRITE
            and "script.sh" in e.target_id
        ]
        wwwdev_edges = [
            e for e in graph.get_edges_from("user:wwwdev")
            if e.edge_type == EdgeType.CAN_WRITE
            and "script.sh" in e.target_id
        ]
        assert len(alice_edges) == 1
        assert len(wwwdev_edges) == 1
        assert alice_edges[0].properties.get("reason") == "world-writable"


# ===== INFLUENCES_EXEC from config args =====

class TestConfigArgInfluences:
    def test_logrotate_config_arg_creates_influence_edge(self, tmp_path):
        """A cron running ``logrotate /etc/logrotate.d/myapp`` should emit
        INFLUENCES_EXEC from the config file to the cron."""
        graph = _populate_identity(tmp_path)

        # Plant the cron file
        cron_d = tmp_path / "etc" / "cron.daily"
        cron_d.mkdir()
        (cron_d / "myapp-logs").write_text(
            "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.d/myapp\n"
        )

        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)

        # Find the INFLUENCES_EXEC edge from /etc/logrotate.d/myapp.
        cfg_id = "file:/etc/logrotate.d/myapp"
        edges = graph.get_edges_from(cfg_id)
        influence_edges = [
            e for e in edges if e.edge_type == EdgeType.INFLUENCES_EXEC
        ]
        assert len(influence_edges) == 1
        assert influence_edges[0].properties.get("mechanism") == "command-line config argument"

    def test_find_arg_is_not_treated_as_config(self, tmp_path):
        """``find /etc -name foo`` should NOT create an INFLUENCES_EXEC edge
        from /etc, because /etc is a search root, not a config file."""
        graph = _populate_identity(tmp_path)

        cron_d = tmp_path / "etc" / "cron.daily"
        cron_d.mkdir()
        (cron_d / "cleanup").write_text(
            "#!/bin/sh\n/usr/bin/find /etc -name foo -delete\n"
        )

        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)
        # No file node should have been created for /etc as a config arg.
        for n in graph.get_nodes():
            if n.id == "file:/etc":
                pytest.fail("/etc should not be a config arg node")


# ===== Login-time scripts (boot.py) =====

class TestLoginScripts:
    def test_profile_d_script_emits_executed_at_login(self, tmp_path):
        graph = _populate_identity(tmp_path)
        profile_d = tmp_path / "etc" / "profile.d"
        profile_d.mkdir()
        (profile_d / "00-test.sh").write_text("export FOO=bar\n")

        BootIngester(root_path=str(tmp_path)).ingest(graph)

        node_id = "profile_script:/etc/profile.d/00-test.sh"
        assert graph.get_node(node_id) is not None
        edges = [
            e for e in graph.get_edges_from(node_id)
            if e.edge_type == EdgeType.EXECUTED_AT_LOGIN
        ]
        assert len(edges) >= 1
        assert edges[0].target_id == "user:root"

    def test_world_writable_profile_d_emits_can_write(self, tmp_path):
        graph = _populate_identity(tmp_path)
        profile_d = tmp_path / "etc" / "profile.d"
        profile_d.mkdir()
        script = profile_d / "vuln.sh"
        script.write_text("# vulnerable\n")
        os.chmod(script, 0o666)

        BootIngester(root_path=str(tmp_path)).ingest(graph)

        # Every user should have a CAN_WRITE edge.
        wwwdev_edges = [
            e for e in graph.get_edges_from("user:wwwdev")
            if e.edge_type == EdgeType.CAN_WRITE
            and "profile_script:/etc/profile.d/vuln.sh" == e.target_id
        ]
        assert len(wwwdev_edges) == 1


# ===== ld.so =====

class TestLdSo:
    def test_ld_so_preload_emits_influence_to_root(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "ld.so.preload").write_text("")

        BootIngester(root_path=str(tmp_path)).ingest(graph)

        node_id = "ldpreload_file:/etc/ld.so.preload"
        assert graph.get_node(node_id) is not None
        edges = [
            e for e in graph.get_edges_from(node_id)
            if e.edge_type == EdgeType.INFLUENCES_EXEC
        ]
        assert len(edges) == 1
        assert edges[0].target_id == "user:root"
        assert edges[0].properties.get("mechanism") == "dynamic linker"


# ===== doas =====

class TestDoas:
    def test_simple_permit_rule(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "doas.conf").write_text(
            "permit nopass alice as root\n"
        )

        AuthIngester(root_path=str(tmp_path)).ingest(graph)

        rules = graph.get_nodes_by_type(NodeType.DOAS_RULE)
        assert len(rules) == 1
        assert rules[0].properties.get("principal") == "alice"
        assert rules[0].properties.get("target") == "root"
        assert rules[0].properties.get("nopass") is True

    def test_deny_rule_does_not_grant(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "doas.conf").write_text(
            "deny alice as root\n"
        )

        AuthIngester(root_path=str(tmp_path)).ingest(graph)

        rules = graph.get_nodes_by_type(NodeType.DOAS_RULE)
        assert len(rules) == 1
        # No GRANTS edges should have been emitted for a deny rule.
        for edge in graph.get_edges_from("user:alice"):
            if edge.edge_type == EdgeType.GRANTS:
                assert "doas_rule" not in edge.target_id


# ===== NFS exports =====

class TestNfsExports:
    def test_no_root_squash_emits_finding(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "exports").write_text(
            "/srv/share 192.168.1.0/24(rw,no_root_squash,async)\n"
        )

        NetworkIngester(root_path=str(tmp_path)).ingest(graph)

        exports = graph.get_nodes_by_type(NodeType.NFS_EXPORT)
        assert len(exports) == 1
        assert "no_root_squash" in exports[0].properties.get("risky_options", [])

    def test_safe_export_has_no_risky_options(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "exports").write_text(
            "/srv/share 192.168.1.0/24(ro,sync,root_squash)\n"
        )

        NetworkIngester(root_path=str(tmp_path)).ingest(graph)

        exports = graph.get_nodes_by_type(NodeType.NFS_EXPORT)
        assert len(exports) == 1
        assert "risky_options" not in exports[0].properties


# ===== fstab =====

class TestFstab:
    def test_tmp_without_nosuid_is_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "fstab").write_text(
            "tmpfs /tmp tmpfs defaults 0 0\n"
        )

        NetworkIngester(root_path=str(tmp_path)).ingest(graph)

        fstab_node = graph.get_node("file:/etc/fstab")
        assert fstab_node is not None
        findings = fstab_node.properties.get("fstab_findings", [])
        assert any("/tmp" in f["mountpoint"] for f in findings)

    def test_tmp_with_nosuid_is_clean(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "fstab").write_text(
            "tmpfs /tmp tmpfs nosuid,nodev 0 0\n"
        )

        NetworkIngester(root_path=str(tmp_path)).ingest(graph)
        # No fstab node should be created if there were no findings.
        assert graph.get_node("file:/etc/fstab") is None


# ===== Container markers =====

class TestContainer:
    def test_dockerenv_marker_creates_node(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / ".dockerenv").touch()

        ContainerIngester(root_path=str(tmp_path)).ingest(graph)

        marker = graph.get_node("container_marker:host")
        assert marker is not None
        assert marker.properties.get("container_type") == "docker"
        assert any("dockerenv" in m for m in marker.properties.get("markers", []))

    def test_no_container_no_node(self, tmp_path):
        graph = _populate_identity(tmp_path)
        ContainerIngester(root_path=str(tmp_path)).ingest(graph)
        assert graph.get_node("container_marker:host") is None


# ===== PAM =====

class TestPAM:
    def test_nullok_on_pam_unix_is_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        pam_d = tmp_path / "etc" / "pam.d"
        pam_d.mkdir(parents=True)
        (pam_d / "login").write_text(
            "auth sufficient pam_unix.so nullok\n"
        )

        PAMIngester(root_path=str(tmp_path)).ingest(graph)

        node = graph.get_node("pam_file:/etc/pam.d/login")
        assert node is not None
        findings = node.properties.get("findings", [])
        assert any("nullok" in f["issue"] for f in findings)

    def test_pam_rootok_in_su_is_normal(self, tmp_path):
        """pam_rootok on the 'su' service is expected; should NOT be flagged."""
        graph = _populate_identity(tmp_path)
        pam_d = tmp_path / "etc" / "pam.d"
        pam_d.mkdir(parents=True)
        (pam_d / "su").write_text(
            "auth sufficient pam_rootok.so\n"
        )

        PAMIngester(root_path=str(tmp_path)).ingest(graph)

        node = graph.get_node("pam_file:/etc/pam.d/su")
        assert node is not None
        # 'su' should have no findings for pam_rootok.
        findings = node.properties.get("findings", [])
        assert not any("pam_rootok" in f["module"] for f in findings)

    def test_pam_rootok_on_other_service_is_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        pam_d = tmp_path / "etc" / "pam.d"
        pam_d.mkdir(parents=True)
        (pam_d / "weird").write_text(
            "auth sufficient pam_rootok.so\n"
        )

        PAMIngester(root_path=str(tmp_path)).ingest(graph)

        node = graph.get_node("pam_file:/etc/pam.d/weird")
        findings = node.properties.get("findings", [])
        assert any("pam_rootok" in f["module"] for f in findings)


# ===== Host trust =====

class TestHostTrust:
    def test_hosts_equiv_emits_trust_edge(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "hosts.equiv").write_text(
            "trustedhost\n"
            "+\n"  # universally trusted, very bad
        )

        NetworkIngester(root_path=str(tmp_path)).ingest(graph)

        node = graph.get_node("file:/etc/hosts.equiv")
        assert node is not None
        edges = [
            e for e in graph.get_edges_from(node.id)
            if e.edge_type == EdgeType.TRUSTS
        ]
        assert len(edges) >= 1
