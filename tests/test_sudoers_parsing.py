"""Tests for sudoers and shadow parsing in IdentityIngester.

These pin down the corrections shipped in v1.0.1:

- ``NOPASSWD:`` / ``PASSWD:`` tags are recognised by position, not by
  substring; a path argument containing the literal string does not
  flip the flag.
- Shadow entries with ``!``, ``!!``, or ``*`` in the hash field are
  classified as locked accounts, not as empty-password accounts.
- An actually-empty hash field is classified as empty_password.

The tests drive the ingester against tiny tmp_path-rooted snapshots so
no real filesystem state is read.
"""
import textwrap

import pytest

from privmap.graph.model import EdgeType, NodeType, PrivilegeGraph
from privmap.ingestion.identity import IdentityIngester


@pytest.fixture
def fake_root(tmp_path):
    """Build a minimal /etc layout under tmp_path so IdentityIngester
    can be pointed at it as root_path."""
    etc = tmp_path / "etc"
    etc.mkdir()
    # Always include a couple of users so sudoers rules have someone to
    # bind to.
    (etc / "passwd").write_text(textwrap.dedent("""\
        root:x:0:0:root:/root:/bin/bash
        alice:x:1000:1000::/home/alice:/bin/bash
        bob:x:1001:1001::/home/bob:/bin/bash
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    """))
    (etc / "group").write_text(textwrap.dedent("""\
        root:x:0:
        sudo:x:27:alice
        wheel:x:998:bob
    """))
    return tmp_path


def _run(fake_root, sudoers_content=None, shadow_content=None):
    """Wire fake_root, write any extra config files, run the ingester,
    return the resulting graph."""
    if sudoers_content is not None:
        (fake_root / "etc" / "sudoers").write_text(sudoers_content)
    if shadow_content is not None:
        (fake_root / "etc" / "shadow").write_text(shadow_content)
    graph = PrivilegeGraph()
    IdentityIngester(root_path=str(fake_root)).ingest(graph)
    return graph


def _sudo_rules(graph):
    return graph.get_nodes_by_type(NodeType.SUDO_RULE)


def _user(graph, name):
    return graph.get_node(f"user:{name}")


class TestNopasswdParsing:
    """The NOPASSWD tag must be detected at tag position, not as a
    substring inside a path argument."""

    def test_simple_nopasswd(self, fake_root):
        graph = _run(fake_root, "alice ALL=(ALL) NOPASSWD: ALL\n")
        rules = _sudo_rules(graph)
        assert len(rules) == 1
        assert rules[0].properties["nopasswd"] is True

    def test_passwd_default(self, fake_root):
        graph = _run(fake_root, "alice ALL=(ALL) ALL\n")
        rules = _sudo_rules(graph)
        assert len(rules) == 1
        assert rules[0].properties["nopasswd"] is False

    def test_explicit_passwd_tag(self, fake_root):
        graph = _run(fake_root, "alice ALL=(ALL) PASSWD: /bin/foo\n")
        rules = _sudo_rules(graph)
        assert len(rules) == 1
        assert rules[0].properties["nopasswd"] is False

    def test_nopasswd_substring_in_path_does_not_flip_flag(self, fake_root):
        # If the parser were doing a naive substring search for "NOPASSWD:"
        # this rule would be classified as nopasswd. It must not be.
        graph = _run(fake_root, "alice ALL=(ALL) /opt/NOPASSWD:helper\n")
        rules = _sudo_rules(graph)
        assert len(rules) == 1
        assert rules[0].properties["nopasswd"] is False
        assert rules[0].properties["binary"] == "/opt/NOPASSWD:helper"

    def test_nopasswd_in_one_rule_does_not_taint_another(self, fake_root):
        # alice has a NOPASSWD rule, bob has a regular rule against a
        # different binary. The flags should not bleed across.
        graph = _run(fake_root, textwrap.dedent("""\
            alice ALL=(ALL) NOPASSWD: /bin/systemctl
            bob ALL=(ALL) /bin/mount
        """))
        alice = _user(graph, "alice")
        bob = _user(graph, "bob")

        def grants_nopasswd(user):
            return [
                edge.properties.get("nopasswd")
                for edge in graph.get_edges_from(user.id)
                if edge.edge_type == EdgeType.GRANTS
            ]

        assert grants_nopasswd(alice) == [True]
        assert grants_nopasswd(bob) == [False]


class TestSudoersStructure:
    """The parser must produce SUDO_RULE nodes and GRANTS edges for
    valid sudoers lines, and ignore noise lines."""

    def test_comment_and_blank_lines_ignored(self, fake_root):
        graph = _run(fake_root, textwrap.dedent("""\
            # This is a comment

            alice ALL=(ALL) ALL
            # Another comment
        """))
        assert len(_sudo_rules(graph)) == 1

    def test_defaults_lines_ignored(self, fake_root):
        graph = _run(fake_root, textwrap.dedent("""\
            Defaults env_reset
            Defaults mail_badpass
            alice ALL=(ALL) ALL
        """))
        assert len(_sudo_rules(graph)) == 1

    def test_group_rule_creates_grants_edge_from_group(self, fake_root):
        graph = _run(fake_root, "%sudo ALL=(ALL) ALL\n")
        sudo_grp = graph.get_node("group:sudo")
        assert sudo_grp is not None
        out_edges = graph.get_edges_from(sudo_grp.id)
        grants = [e for e in out_edges if e.edge_type == EdgeType.GRANTS]
        assert len(grants) == 1

    def test_runas_target_user_recorded(self, fake_root):
        graph = _run(fake_root, "alice ALL=(www-data) /usr/bin/systemctl\n")
        rules = _sudo_rules(graph)
        assert len(rules) == 1
        assert rules[0].properties["runas_user"] == "www-data"

    def test_runas_defaults_to_root_when_omitted(self, fake_root):
        graph = _run(fake_root, "alice ALL=ALL\n")
        rules = _sudo_rules(graph)
        assert len(rules) == 1
        assert rules[0].properties["runas_user"] == "root"


class TestShadowClassification:
    """Locked vs empty vs hashed-password distinction."""

    @pytest.fixture
    def graph_with_shadow(self, fake_root):
        def _build(shadow):
            return _run(fake_root, sudoers_content="", shadow_content=shadow)
        return _build

    def test_locked_with_bang_prefix(self, graph_with_shadow):
        graph = graph_with_shadow("alice:!$y$realhashbytes:19000:0:99999:7:::\n")
        alice = _user(graph, "alice")
        assert alice.properties["account_locked"] is True
        assert alice.properties["has_password"] is False
        # A locked account is NOT an empty-password account.
        assert alice.properties.get("empty_password", False) is False

    def test_locked_with_double_bang(self, graph_with_shadow):
        graph = graph_with_shadow("alice:!!:19000:0:99999:7:::\n")
        alice = _user(graph, "alice")
        assert alice.properties["account_locked"] is True
        assert alice.properties.get("empty_password", False) is False

    def test_locked_with_asterisk(self, graph_with_shadow):
        graph = graph_with_shadow("alice:*:19000:0:99999:7:::\n")
        alice = _user(graph, "alice")
        assert alice.properties["account_locked"] is True
        assert alice.properties.get("empty_password", False) is False

    def test_truly_empty_password(self, graph_with_shadow):
        # Empty second field is a passwordless account.
        graph = graph_with_shadow("alice::19000:0:99999:7:::\n")
        alice = _user(graph, "alice")
        assert alice.properties["account_locked"] is False
        assert alice.properties["empty_password"] is True
        assert alice.properties["has_password"] is False

    def test_real_password_hash(self, graph_with_shadow):
        # A SHA-512 hash starts with "$6$"; sufficiently long; not locked.
        hash_field = "$6$saltsalt$" + "h" * 86
        graph = graph_with_shadow(f"alice:{hash_field}:19000:0:99999:7:::\n")
        alice = _user(graph, "alice")
        assert alice.properties["account_locked"] is False
        assert alice.properties["has_password"] is True
        assert alice.properties.get("empty_password", False) is False
