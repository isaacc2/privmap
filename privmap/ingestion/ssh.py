"""SSH-related surfaces.

Inspects:

- /etc/ssh/sshd_config for risky settings (PermitRootLogin yes,
  PasswordAuthentication yes for root, AuthorizedKeysFile redirection).
- /etc/ssh/ssh_host_*_key permissions (private host keys must be 0600
  root:root; group-readable keys are a serious finding).
- ~/.ssh/authorized_keys per user (writable by anyone else is escalation;
  presence of unexpected keys is informational).
- ~/.ssh/id_* private keys with overly permissive modes.

Each SSH key file becomes a SSH_KEY node; writability gets flagged with
CAN_WRITE edges. A writable authorized_keys file on root's account is one
of the simplest direct paths to root.
"""
from __future__ import annotations

import logging
import os
import stat
from typing import List, Optional

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


_RISKY_SSHD_SETTINGS = {
    "PermitRootLogin": {"yes", "without-password", "prohibit-password"},
    "PasswordAuthentication": {"yes"},
    "PermitEmptyPasswords": {"yes"},
    "X11Forwarding": {"yes"},  # informational rather than escalation
}


class SSHIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_sshd_config(graph)
        self._ingest_host_keys(graph)
        self._ingest_user_keys(graph)

    # ----- sshd_config -----
    def _ingest_sshd_config(self, graph: PrivilegeGraph) -> None:
        cfg = self._abs("/etc/ssh/sshd_config")
        if not os.path.isfile(cfg):
            return
        try:
            with open(cfg, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        findings: List[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0], parts[1].strip()
            risky_values = _RISKY_SSHD_SETTINGS.get(key)
            if risky_values and value.lower() in risky_values:
                findings.append(f"{key} {value}")

        node_id = "file:/etc/ssh/sshd_config"
        try:
            st = os.lstat(cfg)
        except (OSError, PermissionError):
            return
        props = {
            "path": "/etc/ssh/sshd_config",
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "is_sshd_config": True,
        }
        if findings:
            props["risky_settings"] = findings
        node = Node(
            id=node_id,
            node_type=NodeType.FILE,
            name="/etc/ssh/sshd_config",
            properties=props,
        )
        graph.add_node(node)
        if findings and graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={
                    "mechanism": "sshd_config",
                    "findings": findings,
                },
            ))

    # ----- host keys -----
    def _ingest_host_keys(self, graph: PrivilegeGraph) -> None:
        ssh_dir = self._abs("/etc/ssh")
        if not os.path.isdir(ssh_dir):
            return
        try:
            entries = os.listdir(ssh_dir)
        except (OSError, PermissionError):
            return
        for name in entries:
            if not name.startswith("ssh_host_") or not (
                name.endswith("_key") or name == "ssh_host_key"
            ):
                continue
            real = os.path.join(ssh_dir, name)
            logical = os.path.join("/etc/ssh", name)
            try:
                st = os.lstat(real)
            except (OSError, PermissionError):
                continue
            node_id = f"ssh_key:{logical}"
            props = {
                "path": logical,
                "mode": oct(stat.S_IMODE(st.st_mode)),
                "is_private_key": True,
                "scope": "host",
            }
            if st.st_mode & (stat.S_IRGRP | stat.S_IROTH):
                props["overly_readable"] = True
            node = Node(
                id=node_id,
                node_type=NodeType.SSH_KEY,
                name=logical,
                properties=props,
            )
            graph.add_node(node)

    # ----- per-user keys -----
    def _ingest_user_keys(self, graph: PrivilegeGraph) -> None:
        """Walk every user's home directory for SSH key material."""
        # Build a list of (username, home) pairs from the graph.
        users = []
        for u in graph.get_nodes_by_type(NodeType.USER):
            home = u.properties.get("home")
            if isinstance(home, str) and home.startswith("/"):
                users.append((u.name, home))

        for username, home in users:
            ssh_dir = self._abs(home + "/.ssh")
            if not os.path.isdir(ssh_dir):
                continue
            try:
                entries = os.listdir(ssh_dir)
            except (OSError, PermissionError):
                continue
            for name in entries:
                real = os.path.join(ssh_dir, name)
                logical = os.path.join(home, ".ssh", name)
                try:
                    st = os.lstat(real)
                except (OSError, PermissionError):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue

                is_authorized = (name == "authorized_keys")
                is_private = name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
                if not (is_authorized or is_private):
                    continue

                node_id = f"ssh_key:{logical}"
                props = {
                    "path": logical,
                    "mode": oct(stat.S_IMODE(st.st_mode)),
                    "owner": username,
                    "scope": "user",
                    "is_authorized_keys": is_authorized,
                    "is_private_key": is_private,
                }
                if is_private and (st.st_mode & (stat.S_IRGRP | stat.S_IROTH)):
                    props["overly_readable"] = True
                node = Node(
                    id=node_id,
                    node_type=NodeType.SSH_KEY,
                    name=logical,
                    properties=props,
                )
                graph.add_node(node)

                # If the user is root and the file is authorized_keys, any
                # path that lets a non-root principal write here is direct
                # root takeover.
                if is_authorized and graph.get_node(f"user:{username}"):
                    target_user = f"user:{username}"
                    graph.add_edge(Edge(
                        source_id=node_id,
                        target_id=target_user,
                        edge_type=EdgeType.INFLUENCES_EXEC,
                        properties={
                            "mechanism": "authorized_keys",
                            "target_user": username,
                        },
                    ))

                # Emit write edges if anything other than the owner can write.
                self._emit_write_edges(graph, node_id, st, owner_name=username)

    def _emit_write_edges(
        self,
        graph: PrivilegeGraph,
        node_id: str,
        st,
        owner_name: Optional[str] = None,
    ) -> None:
        import grp
        mode = st.st_mode
        if mode & stat.S_IWOTH:
            for u in graph.get_nodes_by_type(NodeType.USER):
                if u.properties.get("uid") == 0 or u.name == owner_name:
                    continue
                graph.add_edge(Edge(
                    source_id=u.id,
                    target_id=node_id,
                    edge_type=EdgeType.CAN_WRITE,
                    properties={"reason": "world-writable ssh key file"},
                ))
        if (mode & stat.S_IWGRP) and not (mode & stat.S_IWOTH):
            try:
                gname = grp.getgrgid(st.st_gid).gr_name
            except (KeyError, ImportError):
                gname = None
            if gname and gname != "root":
                group_node = graph.get_node(f"group:{gname}")
                if group_node:
                    for edge in graph.get_edges_to(group_node.id):
                        if edge.edge_type != EdgeType.MEMBER_OF:
                            continue
                        member = graph.get_node(edge.source_id)
                        if member and member.name != owner_name:
                            graph.add_edge(Edge(
                                source_id=member.id,
                                target_id=node_id,
                                edge_type=EdgeType.CAN_WRITE,
                                properties={
                                    "reason": "group-writable ssh key file",
                                    "group": gname,
                                },
                            ))
