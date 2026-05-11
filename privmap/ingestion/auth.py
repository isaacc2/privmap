"""Authentication-related surfaces beyond /etc/sudoers.

This ingester covers what was previously not modelled:

- /etc/doas.conf (the OpenBSD doas configuration, present on some Linux
  distributions as a sudo alternative).
- Sudo version capture (without CVE matching, which is out of scope; we
  just record the version string so a downstream consumer can pair with a
  vulnerability scanner).
- /etc/sudoers and /etc/sudoers.d/* file *permissions* (writability), as
  opposed to their parsed rule content which lives in identity.py. A
  writable sudoers file is a direct path to root.
- /etc/security/* (limits.conf, access.conf, namespace.conf) - PAM-adjacent
  controls whose writability affects authentication.

PAM auth file parsing lives in its own module (pam.py) because it is its
own grammar.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
from typing import Optional

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class AuthIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs_to_root(self, fs_path: str) -> str:
        return os.path.join(self.root, fs_path.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_doas(graph)
        self._ingest_sudo_version(graph)
        self._ingest_sudoers_permissions(graph)
        self._ingest_security_dir(graph)
        self._ingest_sudo_tokens(graph)
        self._ingest_kerberos_tickets(graph)

    # ----- doas -----
    def _ingest_doas(self, graph: PrivilegeGraph) -> None:
        doas_conf = self._abs_to_root("/etc/doas.conf")
        if not os.path.isfile(doas_conf):
            return
        try:
            with open(doas_conf, "r") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        # doas rules have the form:
        #   permit [options] <identity> [as target] [cmd command [args ...]]
        for lineno, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(
                r"^(permit|deny)\s+(nopass\s+|persist\s+|nolog\s+|keepenv\s+)*"
                r"(\S+)\s*(?:as\s+(\S+))?\s*(?:cmd\s+(.+))?$",
                line,
            )
            if not m:
                continue
            action, _flags_str, principal, target, cmd = m.groups()
            target = target or "root"
            cmd_clean = (cmd or "").strip() or "ALL"
            rule_id = f"doas_rule:{principal}:{cmd_clean}"
            nopass = "nopass" in line
            rule_node = Node(
                id=rule_id,
                node_type=NodeType.DOAS_RULE,
                name=f"{principal} -> {target}: {cmd_clean}",
                properties={
                    "principal": principal,
                    "target": target,
                    "command": cmd_clean,
                    "nopass": nopass,
                    "action": action,
                    "source_file": "/etc/doas.conf",
                    "source_line": lineno,
                },
            )
            graph.add_node(rule_node)
            if action != "permit":
                continue

            principal_node_id = (
                f"group:{principal[1:]}" if principal.startswith(":")
                else f"user:{principal}"
            )
            if graph.get_node(principal_node_id):
                graph.add_edge(Edge(
                    source_id=principal_node_id,
                    target_id=rule_id,
                    edge_type=EdgeType.GRANTS,
                    properties={"nopass": nopass},
                ))

            target_node_id = f"user:{target}"
            if graph.get_node(target_node_id):
                graph.add_edge(Edge(
                    source_id=rule_id,
                    target_id=target_node_id,
                    edge_type=EdgeType.GRANTS,
                    properties={"command": cmd_clean, "nopass": nopass},
                ))

    # ----- sudo version -----
    def _ingest_sudo_version(self, graph: PrivilegeGraph) -> None:
        """Record sudo's version string (no CVE matching).

        In snapshot mode we look for a captured ``meta/sudo_version.txt``.
        In live mode we shell out to ``sudo --version``.
        """
        version: Optional[str] = None
        if self.snapshot:
            ver_file = os.path.join(self.root, "meta", "sudo_version.txt")
            if os.path.isfile(ver_file):
                try:
                    with open(ver_file, "r") as f:
                        version = f.readline().strip()
                except (OSError, PermissionError):
                    version = None
        else:
            sudo_bin = shutil.which("sudo")
            if sudo_bin:
                try:
                    result = subprocess.run(
                        [sudo_bin, "--version"],
                        capture_output=True, text=True, timeout=5,
                    )
                    for line in result.stdout.splitlines():
                        m = re.search(r"Sudo version (\S+)", line)
                        if m:
                            version = m.group(1)
                            break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass

        if version:
            root_node = graph.get_node("user:root")
            if root_node is not None:
                root_node.properties.setdefault("sudo_version", version)

    # ----- sudoers file permissions -----
    def _ingest_sudoers_permissions(self, graph: PrivilegeGraph) -> None:
        """A writable /etc/sudoers (or anything in /etc/sudoers.d/) is an
        immediate path to root. The filesystem walk may miss this if the
        file is not in the default scan_paths or if it has unusual modes
        (e.g. world-readable but with an ACL granting write to a group),
        so we double-check here."""
        candidates = [self._abs_to_root("/etc/sudoers")]
        sudoers_d = self._abs_to_root("/etc/sudoers.d")
        if os.path.isdir(sudoers_d):
            try:
                for name in os.listdir(sudoers_d):
                    if name.startswith(".") or "~" in name:
                        continue
                    full = os.path.join(sudoers_d, name)
                    if os.path.isfile(full):
                        candidates.append(full)
            except (OSError, PermissionError):
                pass

        import grp
        import pwd

        for real_path in candidates:
            if not os.path.isfile(real_path):
                continue
            try:
                st = os.lstat(real_path)
            except (OSError, PermissionError):
                continue
            mode = st.st_mode

            # /etc/sudoers itself is reported by its real path on the target.
            logical_path = real_path[len(self.root):] if real_path.startswith(self.root) else real_path
            if not logical_path.startswith("/"):
                logical_path = "/" + logical_path

            node_id = f"file:{logical_path}"
            props = {
                "path": logical_path,
                "mode": oct(stat.S_IMODE(mode)),
                "is_sudoers_file": True,
            }
            try:
                props["owner"] = pwd.getpwuid(st.st_uid).pw_name
            except (KeyError, ImportError):
                props["owner"] = str(st.st_uid)
            try:
                props["group"] = grp.getgrgid(st.st_gid).gr_name
            except (KeyError, ImportError):
                props["group"] = str(st.st_gid)

            node = Node(
                id=node_id,
                node_type=NodeType.FILE,
                name=logical_path,
                properties=props,
            )
            graph.add_node(node)

            if mode & stat.S_IWOTH:
                for user_node in graph.get_nodes_by_type(NodeType.USER):
                    if user_node.properties.get("uid") == 0:
                        continue
                    graph.add_edge(Edge(
                        source_id=user_node.id,
                        target_id=node_id,
                        edge_type=EdgeType.CAN_WRITE,
                        properties={"reason": "world-writable sudoers"},
                    ))
            if (mode & stat.S_IWGRP) and not (mode & stat.S_IWOTH):
                gname = props.get("group")
                if isinstance(gname, str) and gname != "root":
                    group_node = graph.get_node(f"group:{gname}")
                    if group_node:
                        for edge in graph.get_edges_to(group_node.id):
                            if edge.edge_type != EdgeType.MEMBER_OF:
                                continue
                            member = graph.get_node(edge.source_id)
                            if member and member.properties.get("uid") != 0:
                                graph.add_edge(Edge(
                                    source_id=member.id,
                                    target_id=node_id,
                                    edge_type=EdgeType.CAN_WRITE,
                                    properties={
                                        "reason": "group-writable sudoers",
                                        "group": gname,
                                    },
                                ))

    # ----- sudo tokens -----
    def _ingest_sudo_tokens(self, graph: PrivilegeGraph) -> None:
        """Enumerate live sudo timestamp tokens in /var/run/sudo/ts/.

        Each file represents a user whose sudo auth is currently cached.
        If you control that uid's session, you can sudo without
        re-prompting. The presence of an active token is a property on
        the user node, not a free escalation by itself, but it's
        meaningful pentest context.
        """
        for ts_dir in ("/var/run/sudo/ts", "/var/db/sudo/ts"):
            full = self._abs_to_root(ts_dir)
            if not os.path.isdir(full):
                continue
            try:
                entries = os.listdir(full)
            except (OSError, PermissionError):
                continue
            for name in entries:
                # Files are named after the username.
                user_node = graph.get_node(f"user:{name}")
                if user_node is None:
                    continue
                token_path = os.path.join(full, name)
                try:
                    st = os.lstat(token_path)
                except (OSError, PermissionError):
                    continue
                user_node.properties.setdefault(
                    "active_sudo_token", {
                        "path": os.path.join(ts_dir, name),
                        "mtime": int(st.st_mtime),
                    },
                )

    # ----- Kerberos tickets -----
    def _ingest_kerberos_tickets(self, graph: PrivilegeGraph) -> None:
        """Scan /tmp and /var/tmp for ``krb5cc_*`` ticket cache files.

        A ticket cache file readable by another user lets that user reuse
        the ticket. Mode 0600 is correct; group/world readable is a
        finding. The file naming convention is ``krb5cc_<uid>[_random]``.
        """
        import pwd

        for base in ("/tmp", "/var/tmp"):
            full_base = self._abs_to_root(base)
            if not os.path.isdir(full_base):
                continue
            try:
                entries = os.listdir(full_base)
            except (OSError, PermissionError):
                continue
            for name in entries:
                if not name.startswith("krb5cc_"):
                    continue
                real = os.path.join(full_base, name)
                logical = os.path.join(base, name)
                try:
                    st = os.lstat(real)
                except (OSError, PermissionError):
                    continue
                node_id = f"file:{logical}"
                # Extract the uid from the filename for owner inference.
                uid_part = name[len("krb5cc_"):].split("_", 1)[0]
                owner_name = None
                try:
                    owner_uid = int(uid_part)
                    try:
                        owner_name = pwd.getpwuid(owner_uid).pw_name
                    except (KeyError, ImportError):
                        pass
                except ValueError:
                    pass
                props = {
                    "path": logical,
                    "mode": oct(stat.S_IMODE(st.st_mode)),
                    "kerberos_ticket": True,
                    "owner_uid_from_name": uid_part,
                }
                if owner_name:
                    props["owner_inferred"] = owner_name
                if st.st_mode & (stat.S_IRGRP | stat.S_IROTH):
                    props["overly_readable"] = True
                node = Node(
                    id=node_id,
                    node_type=NodeType.FILE,
                    name=logical,
                    properties=props,
                )
                graph.add_node(node)

                # If the ticket file is overly readable, any user can
                # reuse it. Emit a TRUSTS-like INFLUENCES_EXEC edge to
                # the user the ticket belongs to.
                if owner_name and (st.st_mode & (stat.S_IRGRP | stat.S_IROTH)):
                    target_id = f"user:{owner_name}"
                    if graph.get_node(target_id):
                        graph.add_edge(Edge(
                            source_id=node_id,
                            target_id=target_id,
                            edge_type=EdgeType.INFLUENCES_EXEC,
                            properties={
                                "mechanism": "Kerberos ticket reuse",
                                "target_user": owner_name,
                            },
                        ))

    # ----- /etc/security/* -----
    def _ingest_security_dir(self, graph: PrivilegeGraph) -> None:
        sec_dir = self._abs_to_root("/etc/security")
        if not os.path.isdir(sec_dir):
            return
        try:
            entries = os.listdir(sec_dir)
        except (OSError, PermissionError):
            return
        for name in entries:
            full = os.path.join(sec_dir, name)
            if not os.path.isfile(full):
                continue
            logical_path = os.path.join("/etc/security", name)
            try:
                st = os.lstat(full)
            except (OSError, PermissionError):
                continue

            node_id = f"file:{logical_path}"
            props = {
                "path": logical_path,
                "mode": oct(stat.S_IMODE(st.st_mode)),
                "security_config": True,
            }
            node = Node(
                id=node_id,
                node_type=NodeType.FILE,
                name=logical_path,
                properties=props,
            )
            graph.add_node(node)

            # Any non-root write to a /etc/security/* file is reported.
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                if graph.get_node("user:root"):
                    graph.add_edge(Edge(
                        source_id=node_id,
                        target_id="user:root",
                        edge_type=EdgeType.INFLUENCES_EXEC,
                        properties={
                            "path": logical_path,
                            "mechanism": "PAM security config",
                        },
                    ))
