"""Network surfaces: listening ports, NFS exports, host trust files, fstab.

What this covers:

- /etc/exports - NFS shares. ``no_root_squash`` means any client root can
  write as root on the export, which is a remote escalation primitive.
  ``no_all_squash`` is similar for non-root.
- /etc/fstab - mount options. ``nosuid`` missing on /tmp or /home, or
  ``no_root_squash`` on an NFS mount, is a hardening finding.
- /etc/hosts.equiv and ~/.rhosts - historical r-command host trust.
  Effectively grants password-less login from listed hosts.
- /etc/hosts writability - affects every name resolution as root.
- Listening TCP/UDP ports parsed from /proc/net/tcp[6] and /proc/net/udp[6].
  Each becomes a NETWORK_LISTENER node with a LISTENS_ON edge from the
  owning process (if we can resolve the inode -> process mapping).

The listener data is informational at the moment; future work could pair
it with running-process node properties to flag exposed services running
as root.
"""
from __future__ import annotations

import logging
import os
import re
import stat
from typing import Dict

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class NetworkIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_exports(graph)
        self._ingest_fstab(graph)
        self._ingest_host_trust(graph)
        self._ingest_hosts_file(graph)
        self._ingest_listeners(graph)

    # ----- /etc/exports -----
    def _ingest_exports(self, graph: PrivilegeGraph) -> None:
        exports = self._abs("/etc/exports")
        if not os.path.isfile(exports):
            return
        try:
            with open(exports, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return
        for lineno, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: path host(options) [host(options) ...]
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            export_path = parts[0]
            rest = parts[1]
            # Find all option blocks.
            for m in re.finditer(r"(\S+?)\(([^)]*)\)", rest):
                client = m.group(1)
                opts = [o.strip() for o in m.group(2).split(",")]
                opt_set = set(opts)
                risky = []
                if "no_root_squash" in opt_set:
                    risky.append("no_root_squash")
                if "no_all_squash" in opt_set:
                    risky.append("no_all_squash")
                if "rw" in opt_set and "no_root_squash" in opt_set:
                    risky.append("writable-as-root")

                node_id = f"nfs_export:{export_path}@{client}:{lineno}"
                props = {
                    "export_path": export_path,
                    "client": client,
                    "options": opts,
                    "source_line": lineno,
                }
                if risky:
                    props["risky_options"] = risky
                node = Node(
                    id=node_id,
                    node_type=NodeType.NFS_EXPORT,
                    name=f"{export_path} -> {client}",
                    properties=props,
                )
                graph.add_node(node)

                if risky and graph.get_node("user:root"):
                    graph.add_edge(Edge(
                        source_id=node_id,
                        target_id="user:root",
                        edge_type=EdgeType.INFLUENCES_EXEC,
                        properties={
                            "mechanism": "NFS no_root_squash",
                            "client": client,
                        },
                    ))

    # ----- /etc/fstab -----
    def _ingest_fstab(self, graph: PrivilegeGraph) -> None:
        fstab = self._abs("/etc/fstab")
        if not os.path.isfile(fstab):
            return
        try:
            with open(fstab, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return
        findings = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 4:
                continue
            _device, mountpoint, fstype, options = fields[0], fields[1], fields[2], fields[3]
            opts = set(o.strip() for o in options.split(","))
            risky = []
            if mountpoint in ("/tmp", "/var/tmp", "/home") and "nosuid" not in opts:
                risky.append(f"{mountpoint} mounted without nosuid")
            if fstype == "nfs" and "no_root_squash" in opts:
                risky.append(f"{mountpoint} NFS mount with no_root_squash")
            if "exec" in opts and mountpoint in ("/tmp", "/var/tmp"):
                # explicit exec on a tmp mount is unusual but rarely an actual issue
                pass
            if risky:
                findings.append({"mountpoint": mountpoint, "fstype": fstype, "risky": risky})

        if findings:
            node_id = "file:/etc/fstab"
            node = Node(
                id=node_id,
                node_type=NodeType.FILE,
                name="/etc/fstab",
                properties={
                    "path": "/etc/fstab",
                    "fstab_findings": findings,
                },
            )
            graph.add_node(node)
            if graph.get_node("user:root"):
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id="user:root",
                    edge_type=EdgeType.INFLUENCES_EXEC,
                    properties={
                        "mechanism": "fstab",
                        "findings": [f["mountpoint"] for f in findings],
                    },
                ))

    # ----- host trust (hosts.equiv, .rhosts) -----
    def _ingest_host_trust(self, graph: PrivilegeGraph) -> None:
        for trust_file in ["/etc/hosts.equiv", "/etc/shosts.equiv"]:
            full = self._abs(trust_file)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", errors="replace") as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue
            entries = [
                line.strip() for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if not entries:
                continue
            node_id = f"file:{trust_file}"
            node = Node(
                id=node_id,
                node_type=NodeType.FILE,
                name=trust_file,
                properties={
                    "path": trust_file,
                    "trust_entries": entries,
                    "is_host_trust": True,
                },
            )
            graph.add_node(node)
            if graph.get_node("user:root"):
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id="user:root",
                    edge_type=EdgeType.TRUSTS,
                    properties={"mechanism": "hosts.equiv", "entries": entries},
                ))

        # Per-user .rhosts files.
        for u in graph.get_nodes_by_type(NodeType.USER):
            home = u.properties.get("home")
            if not isinstance(home, str):
                continue
            rh = self._abs(home + "/.rhosts")
            if not os.path.isfile(rh):
                continue
            try:
                with open(rh, "r", errors="replace") as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue
            entries = [
                line.strip() for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if not entries:
                continue
            logical = os.path.join(home, ".rhosts")
            node_id = f"file:{logical}"
            node = Node(
                id=node_id,
                node_type=NodeType.FILE,
                name=logical,
                properties={
                    "path": logical,
                    "trust_entries": entries,
                    "is_user_rhosts": True,
                    "for_user": u.name,
                },
            )
            graph.add_node(node)
            graph.add_edge(Edge(
                source_id=node_id,
                target_id=u.id,
                edge_type=EdgeType.TRUSTS,
                properties={"mechanism": ".rhosts", "entries": entries},
            ))

    # ----- /etc/hosts writability -----
    def _ingest_hosts_file(self, graph: PrivilegeGraph) -> None:
        hosts = self._abs("/etc/hosts")
        if not os.path.isfile(hosts):
            return
        try:
            st = os.lstat(hosts)
        except (OSError, PermissionError):
            return
        if not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            return
        node_id = "file:/etc/hosts"
        node = Node(
            id=node_id,
            node_type=NodeType.FILE,
            name="/etc/hosts",
            properties={
                "path": "/etc/hosts",
                "mode": oct(stat.S_IMODE(st.st_mode)),
                "writable_by_non_root": True,
            },
        )
        graph.add_node(node)
        if graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={"mechanism": "/etc/hosts name resolution"},
            ))

    # ----- listening ports -----
    def _ingest_listeners(self, graph: PrivilegeGraph) -> None:
        """Parse /proc/net/{tcp,tcp6,udp,udp6}. Each LISTEN entry becomes a
        NETWORK_LISTENER node. We resolve inode -> process via /proc/*/fd
        in live mode only; in snapshot mode that mapping is left blank."""
        # /proc state lookup: which /proc do we use?
        if self.snapshot:
            proc_root = os.path.join(self.root, "proc")
        else:
            proc_root = self._abs("/proc")
        if not os.path.isdir(proc_root):
            return

        # Map socket inode -> pid (live mode only).
        inode_to_pid: Dict[str, str] = {}
        if not self.snapshot:
            try:
                for entry in os.listdir(proc_root):
                    if not entry.isdigit():
                        continue
                    fd_dir = os.path.join(proc_root, entry, "fd")
                    if not os.path.isdir(fd_dir):
                        continue
                    try:
                        for fd in os.listdir(fd_dir):
                            try:
                                link = os.readlink(os.path.join(fd_dir, fd))
                            except (OSError, PermissionError):
                                continue
                            m = re.match(r"socket:\[(\d+)\]", link)
                            if m:
                                inode_to_pid[m.group(1)] = entry
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                pass

        for fname, proto in [
            ("tcp", "tcp"), ("tcp6", "tcp6"),
            ("udp", "udp"), ("udp6", "udp6"),
        ]:
            path = os.path.join(proc_root, "net", fname)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", errors="replace") as f:
                    lines = f.readlines()
            except (OSError, PermissionError):
                continue

            for line in lines[1:]:  # skip header
                parts = line.split()
                if len(parts) < 10:
                    continue
                # local_address column format: HEXIP:HEXPORT
                local = parts[1]
                state = parts[3]
                inode = parts[9]
                # State 0A = TCP LISTEN; UDP entries are typically state 07.
                if proto.startswith("tcp") and state != "0A":
                    continue
                try:
                    _, port_hex = local.rsplit(":", 1)
                    port = int(port_hex, 16)
                except ValueError:
                    continue

                pid = inode_to_pid.get(inode)
                node_id = f"network_listener:{proto}:{port}"
                node = Node(
                    id=node_id,
                    node_type=NodeType.NETWORK_LISTENER,
                    name=f"{proto}:{port}",
                    properties={
                        "protocol": proto,
                        "port": port,
                        "inode": inode,
                        "pid": pid,
                    },
                )
                graph.add_node(node)

                # Link the owning process if we resolved a pid.
                if pid:
                    # Find any PROCESS node with this pid.
                    for p in graph.get_nodes_by_type(NodeType.PROCESS):
                        if str(p.properties.get("pid")) == pid:
                            graph.add_edge(Edge(
                                source_id=p.id,
                                target_id=node_id,
                                edge_type=EdgeType.LISTENS_ON,
                                properties={"port": port, "protocol": proto},
                            ))
                            break
