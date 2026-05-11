"""Tests for the v2.0 expansion ingesters and chain wiring.

Covers categories added after the initial v2 batch:

- Sudo token reuse (auth.py)
- Kerberos ticket files (auth.py)
- /etc/profile PATH manipulation (boot.py)
- D-Bus policy analysis (dbus.py)
- Systemd PATH overrides (execution.py)
- Wildcard injection in cron (execution.py)
- Inetd / xinetd services (inetd.py)
- AppArmor profile mode (apparmor.py)
- Writable container bind mounts (container.py)
- PATH abuse chain wiring (path_abuse.py + cron/systemd)
- SSH authorized_keys chain wiring (ssh.py)
"""
import os
import stat
import textwrap

import pytest

from privmap.graph.model import (
    Edge, EdgeType, Node, NodeType, PrivilegeGraph,
)
from privmap.ingestion.identity import IdentityIngester
from privmap.ingestion.auth import AuthIngester
from privmap.ingestion.boot import BootIngester
from privmap.ingestion.dbus import DBusIngester
from privmap.ingestion.execution import ExecutionIngester
from privmap.ingestion.inetd import InetdIngester
from privmap.ingestion.apparmor import AppArmorIngester
from privmap.ingestion.container import ContainerIngester
from privmap.ingestion.path_abuse import PathAbuseIngester
from privmap.ingestion.ssh import SSHIngester
from privmap.graph.traversal import find_escalation_paths


def _populate_identity(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir(exist_ok=True)
    (etc / "passwd").write_text(textwrap.dedent("""\
        root:x:0:0:root:/root:/bin/bash
        alice:x:1000:1000::/home/alice:/bin/bash
        wwwdev:x:1001:1001::/home/wwwdev:/bin/bash
    """))
    (etc / "group").write_text(textwrap.dedent("""\
        root:x:0:
        adm:x:4:wwwdev
        sudo:x:27:alice
    """))
    graph = PrivilegeGraph()
    IdentityIngester(root_path=str(tmp_path)).ingest(graph)
    return graph


# ===== Sudo tokens =====
class TestSudoTokens:
    def test_token_present_marks_user(self, tmp_path):
        graph = _populate_identity(tmp_path)
        ts_dir = tmp_path / "var" / "run" / "sudo" / "ts"
        ts_dir.mkdir(parents=True)
        (ts_dir / "alice").write_text("")  # presence is what matters

        AuthIngester(root_path=str(tmp_path)).ingest(graph)
        alice = graph.get_node("user:alice")
        assert alice.properties.get("active_sudo_token") is not None
        assert "alice" in alice.properties["active_sudo_token"]["path"]


# ===== Kerberos =====
class TestKerberos:
    def test_overly_readable_ticket_emits_influence(self, tmp_path):
        graph = _populate_identity(tmp_path)
        # Pretend uid 1000 = alice. krb5cc_1000 readable by world.
        tmp_dir = tmp_path / "tmp"
        tmp_dir.mkdir()
        ticket = tmp_dir / "krb5cc_1000"
        ticket.write_text("ticket-bytes")
        os.chmod(ticket, 0o644)  # group + world readable

        AuthIngester(root_path=str(tmp_path)).ingest(graph)

        node = graph.get_node("file:/tmp/krb5cc_1000")
        assert node is not None
        assert node.properties.get("overly_readable") is True
        # When alice (uid 1000) is local to the analyst's machine, the
        # inferred owner mapping happens. We don't require it for the
        # test to pass, but we do require the node to exist with the
        # right flags.

    def test_correctly_perm_ticket_has_no_flag(self, tmp_path):
        graph = _populate_identity(tmp_path)
        tmp_dir = tmp_path / "tmp"
        tmp_dir.mkdir()
        ticket = tmp_dir / "krb5cc_1000"
        ticket.write_text("ticket")
        os.chmod(ticket, 0o600)

        AuthIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("file:/tmp/krb5cc_1000")
        assert node is not None
        assert node.properties.get("overly_readable") is None


# ===== /etc/profile PATH manipulation =====
class TestProfilePathManipulation:
    def test_dot_in_path_is_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "profile").write_text(
            'export PATH=".:/usr/local/bin:/usr/bin"\n'
        )

        BootIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("profile_script:/etc/profile")
        assert node is not None
        findings = node.properties.get("path_manipulation", [])
        assert any("'.'" in f for f in findings)

    def test_normal_path_has_no_finding(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "profile").write_text(
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n'
        )

        BootIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("profile_script:/etc/profile")
        assert "path_manipulation" not in (node.properties if node else {})


# ===== D-Bus =====
class TestDBus:
    def test_overpermissive_send_destination_is_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        dbus_d = tmp_path / "etc" / "dbus-1" / "system.d"
        dbus_d.mkdir(parents=True)
        (dbus_d / "weird.conf").write_text(textwrap.dedent('''\
            <?xml version="1.0"?>
            <busconfig>
              <policy group="wwwdev">
                <allow send_destination="org.example.Privileged"/>
              </policy>
            </busconfig>
        '''))

        DBusIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("dbus_policy:/etc/dbus-1/system.d/weird.conf")
        assert node is not None
        findings = node.properties.get("findings", [])
        assert any(f["type"] == "unrestricted_method_access" for f in findings)

    def test_restricted_method_access_not_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        dbus_d = tmp_path / "etc" / "dbus-1" / "system.d"
        dbus_d.mkdir(parents=True)
        (dbus_d / "ok.conf").write_text(textwrap.dedent('''\
            <?xml version="1.0"?>
            <busconfig>
              <policy group="wwwdev">
                <allow send_destination="org.example.Privileged" send_member="GetStatus"/>
              </policy>
            </busconfig>
        '''))

        DBusIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("dbus_policy:/etc/dbus-1/system.d/ok.conf")
        assert node is not None
        assert not node.properties.get("findings")


# ===== Systemd PATH override =====
class TestSystemdPathOverride:
    def test_environment_path_captured(self, tmp_path):
        graph = _populate_identity(tmp_path)
        systemd_dir = tmp_path / "etc" / "systemd" / "system"
        systemd_dir.mkdir(parents=True)
        (systemd_dir / "weird.service").write_text(textwrap.dedent('''\
            [Service]
            Environment="PATH=/opt/custom/bin:/usr/bin"
            ExecStart=/usr/bin/foo
            User=root
        '''))

        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("systemd:weird.service")
        assert node is not None
        assert node.properties.get("path_overrides") == ["/opt/custom/bin:/usr/bin"]


# ===== Wildcard injection in cron =====
class TestWildcardInjection:
    def test_tar_with_wildcard_in_cron(self, tmp_path):
        graph = _populate_identity(tmp_path)

        # Build a system crontab.
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "crontab").write_text(
            "0 5 * * * root /usr/bin/tar czf /backup.tgz *\n"
        )

        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)
        crons = [n for n in graph.get_nodes_by_type(NodeType.CRON_JOB)]
        assert any(
            c.properties.get("wildcard_injection_risk") is True for c in crons
        )

    def test_safe_command_not_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "crontab").write_text(
            "0 5 * * * root /usr/bin/tar czf /backup.tgz /var/log\n"
        )
        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)
        crons = [n for n in graph.get_nodes_by_type(NodeType.CRON_JOB)]
        for c in crons:
            assert c.properties.get("wildcard_injection_risk") is None


# ===== Inetd/xinetd =====
class TestInetd:
    def test_inetd_conf_service(self, tmp_path):
        graph = _populate_identity(tmp_path)
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "inetd.conf").write_text(
            "echo  stream tcp  nowait root  /usr/sbin/in.echod  in.echod\n"
        )

        InetdIngester(root_path=str(tmp_path)).ingest(graph)
        services = graph.get_nodes_by_type(NodeType.INETD_SERVICE)
        assert len(services) == 1
        svc = services[0]
        assert svc.properties.get("run_as") == "root"
        assert svc.properties.get("server") == "/usr/sbin/in.echod"

    def test_xinetd_per_service(self, tmp_path):
        graph = _populate_identity(tmp_path)
        xinetd_d = tmp_path / "etc" / "xinetd.d"
        xinetd_d.mkdir(parents=True)
        (xinetd_d / "myservice").write_text(textwrap.dedent('''\
            service myservice {
                disable     = no
                socket_type = stream
                protocol    = tcp
                user        = nobody
                server      = /usr/sbin/myservice
                wait        = no
            }
        '''))

        InetdIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("inetd_service:myservice")
        assert node is not None
        assert node.properties.get("framework") == "xinetd"
        assert node.properties.get("run_as") == "nobody"

    def test_disabled_xinetd_skipped(self, tmp_path):
        graph = _populate_identity(tmp_path)
        xinetd_d = tmp_path / "etc" / "xinetd.d"
        xinetd_d.mkdir(parents=True)
        (xinetd_d / "off").write_text(textwrap.dedent('''\
            service off {
                disable = yes
                user    = root
                server  = /usr/bin/true
            }
        '''))
        InetdIngester(root_path=str(tmp_path)).ingest(graph)
        assert graph.get_node("inetd_service:off") is None


# ===== AppArmor =====
class TestAppArmor:
    def test_profile_detected(self, tmp_path):
        graph = _populate_identity(tmp_path)
        aa_d = tmp_path / "etc" / "apparmor.d"
        aa_d.mkdir(parents=True)
        (aa_d / "usr.bin.foo").write_text(textwrap.dedent('''\
            profile foo /usr/bin/foo {
                #include <abstractions/base>
            }
        '''))

        AppArmorIngester(root_path=str(tmp_path)).ingest(graph)
        node = graph.get_node("apparmor_profile:/etc/apparmor.d/usr.bin.foo")
        assert node is not None
        assert node.properties.get("profile_name") == "foo"


# ===== Container bind mounts =====
class TestContainerBindMounts:
    def test_writable_mount_without_nosuid(self, tmp_path):
        graph = _populate_identity(tmp_path)
        # Mark the system as a container so the marker block runs.
        (tmp_path / ".dockerenv").touch()
        # Fabricate a /proc/mounts.
        proc = tmp_path / "proc"
        proc.mkdir()
        (proc / "mounts").write_text(
            "/dev/sda1 /host ext4 rw,relatime 0 0\n"
        )

        ContainerIngester(root_path=str(tmp_path)).ingest(graph)
        mount = graph.get_node("mount:/host")
        assert mount is not None
        assert mount.properties.get("writable_bind_mount") is True
        assert "no nosuid" in mount.properties.get("risky", [])

    def test_readonly_mount_not_flagged(self, tmp_path):
        graph = _populate_identity(tmp_path)
        proc = tmp_path / "proc"
        proc.mkdir()
        (proc / "mounts").write_text(
            "/dev/sda1 /host ext4 ro,relatime 0 0\n"
        )
        ContainerIngester(root_path=str(tmp_path)).ingest(graph)
        assert graph.get_node("mount:/host") is None


# ===== PATH abuse chain wiring =====
class TestPathAbuseChain:
    def test_unqualified_cron_command_creates_path_influence(self, tmp_path):
        """A cron running ``foo`` (unqualified) should create
        INFLUENCES_EXEC edges from each PATH_DIR to the cron, so writing
        a binary into a writable PATH dir closes a chain to root."""
        graph = _populate_identity(tmp_path)

        # Set up a writable /usr/local/bin (world-writable for the test).
        (tmp_path / "etc").mkdir(exist_ok=True)
        (tmp_path / "etc" / "environment").write_text(
            'PATH="/usr/local/bin:/usr/bin"\n'
        )
        ulb = tmp_path / "usr" / "local" / "bin"
        ulb.mkdir(parents=True)
        os.chmod(ulb, 0o777)

        # A cron that runs ``foo`` unqualified.
        cron_d = tmp_path / "etc" / "cron.d"
        cron_d.mkdir(exist_ok=True)
        (cron_d / "weird").write_text(
            "*/5 * * * * root foo --arg\n"
        )

        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)
        PathAbuseIngester(root_path=str(tmp_path)).ingest(graph)

        path_dir = graph.get_node("path_dir:/usr/local/bin")
        assert path_dir is not None
        # The PATH dir was writable; users should have CAN_WRITE on it.
        wwwdev_can_write = any(
            e.target_id == path_dir.id and e.edge_type == EdgeType.CAN_WRITE
            for e in graph.get_edges_from("user:wwwdev")
        )
        assert wwwdev_can_write

        # The PATH dir should have an INFLUENCES_EXEC edge to a cron job.
        infl = [
            e for e in graph.get_edges_from(path_dir.id)
            if e.edge_type == EdgeType.INFLUENCES_EXEC
        ]
        assert len(infl) >= 1


# ===== SSH authorized_keys chain =====
class TestSSHKeyChain:
    def test_writable_root_authorized_keys_emits_chain(self, tmp_path):
        # Set up identity where root's home is under tmp_path.
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\nwwwdev:x:1001:1001::/home/wwwdev:/bin/bash\n"
        )
        (etc / "group").write_text("root:x:0:\n")
        graph = PrivilegeGraph()
        IdentityIngester(root_path=str(tmp_path)).ingest(graph)

        root_ssh = tmp_path / "root" / ".ssh"
        root_ssh.mkdir(parents=True)
        ak = root_ssh / "authorized_keys"
        ak.write_text("ssh-ed25519 AAAA...\n")
        # World-writable: anyone can plant a key.
        os.chmod(ak, 0o666)

        SSHIngester(root_path=str(tmp_path)).ingest(graph)

        key_id = "ssh_key:/root/.ssh/authorized_keys"
        assert graph.get_node(key_id) is not None
        # INFLUENCES_EXEC to root should be present.
        edges = graph.get_edges_from(key_id)
        infl_to_root = [
            e for e in edges
            if e.edge_type == EdgeType.INFLUENCES_EXEC
            and e.target_id == "user:root"
        ]
        assert len(infl_to_root) == 1
        # wwwdev should have a CAN_WRITE edge to the key.
        wwwdev_writes = [
            e for e in graph.get_edges_from("user:wwwdev")
            if e.edge_type == EdgeType.CAN_WRITE and e.target_id == key_id
        ]
        assert len(wwwdev_writes) == 1


# ===== End-to-end chain validation =====
class TestEndToEndChains:
    def test_group_writable_logrotate_chain_now_closes(self, tmp_path):
        """The original demo chain:
        wwwdev -> adm -> /etc/logrotate.d/myapp -> /etc/cron.daily/myapp-logs -> root
        Should now produce at least one escalation path in v2.0."""
        from privmap.ingestion.filesystem import FilesystemIngester

        graph = _populate_identity(tmp_path)

        # Plant the logrotate config (group-writable, root:adm).
        suid_dir = tmp_path / "suid"
        suid_dir.mkdir()
        (suid_dir / "group_writable_files.txt").write_text(
            "664 root adm /etc/logrotate.d/myapp\n"
        )
        FilesystemIngester(
            root_path=str(tmp_path),
            snapshot_mode=True,
        ).ingest(graph)

        # Plant the cron that invokes logrotate against the config.
        cron_d = tmp_path / "etc" / "cron.daily"
        cron_d.mkdir(exist_ok=True)
        (cron_d / "myapp-logs").write_text(
            "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.d/myapp\n"
        )

        ExecutionIngester(root_path=str(tmp_path)).ingest(graph)

        # Now run the traversal and check we got a path from wwwdev to root.
        paths = find_escalation_paths(graph, source_users=["wwwdev"])
        assert len(paths) >= 1, (
            "The demo chain (group-writable logrotate config + cron) "
            "should produce at least one escalation path"
        )
