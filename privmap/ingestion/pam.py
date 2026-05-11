"""PAM authentication-stack analysis.

Parses /etc/pam.d/* and flags entries that bypass or weaken authentication:

- pam_rootok.so on services other than ``su`` itself (a root-only bypass
  applied to a wrong service is a backdoor).
- pam_permit.so unconditionally allowing auth.
- nullok on pam_unix.so (empty-password accept).
- pam_wheel.so without ``group=`` restriction (anyone in 'wheel' becomes
  authoritative).

For each /etc/pam.d/<service> file we emit a PAM_FILE node. If we found
risky lines, we emit an INFLUENCES_EXEC edge to root with the findings as
the edge property - these are not deterministic graph paths but they are
real authentication weaknesses worth flagging.
"""
from __future__ import annotations

import logging
import os
import re
import stat
from typing import Dict, List

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


# Patterns that indicate authentication bypass.
_RISKY_MODULES = [
    ("pam_rootok.so", "allows uid-0 to skip authentication; only ``su`` should use this"),
    ("pam_permit.so", "unconditionally allows authentication"),
    ("pam_succeed_if.so .*uid eq 0", "bypasses auth for uid 0 without further checks"),
]


class PAMIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        pam_d = self._abs("/etc/pam.d")
        if not os.path.isdir(pam_d):
            return

        try:
            entries = os.listdir(pam_d)
        except (OSError, PermissionError):
            return

        for name in sorted(entries):
            real = os.path.join(pam_d, name)
            logical = os.path.join("/etc/pam.d", name)
            if not os.path.isfile(real):
                continue
            self._ingest_pam_file(graph, logical, real)

    def _ingest_pam_file(
        self, graph: PrivilegeGraph, logical: str, real: str,
    ) -> None:
        try:
            with open(real, "r", errors="replace") as f:
                content = f.read()
            st = os.lstat(real)
        except (OSError, PermissionError):
            return

        findings: List[Dict[str, str]] = []
        service = os.path.basename(logical)

        for lineno, line in enumerate(content.splitlines(), 1):
            raw = line
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Skip @include directives.
            if line.startswith("@include"):
                continue

            for pattern, description in _RISKY_MODULES:
                if re.search(pattern, line):
                    # pam_rootok on the 'su' service is normal; flag elsewhere.
                    if "pam_rootok.so" in pattern and service in (
                        "su", "su-l", "sudo",
                    ):
                        continue
                    findings.append({
                        "line_number": str(lineno),
                        "module": pattern,
                        "raw": raw,
                        "issue": description,
                    })

            # pam_unix nullok = empty-password accept
            if "pam_unix.so" in line and "nullok" in line:
                findings.append({
                    "line_number": str(lineno),
                    "module": "pam_unix.so",
                    "raw": raw,
                    "issue": "nullok accepts empty passwords",
                })

            # pam_wheel without group= is implicit "wheel" group only;
            # without trust=allowfrom that's the default. Flag if not present.
            if "pam_wheel.so" in line and "group=" not in line:
                findings.append({
                    "line_number": str(lineno),
                    "module": "pam_wheel.so",
                    "raw": raw,
                    "issue": "no explicit group= restriction (defaults to 'wheel')",
                })

        node_id = f"pam_file:{logical}"
        props = {
            "path": logical,
            "service": service,
            "mode": oct(stat.S_IMODE(st.st_mode)),
        }
        if findings:
            props["findings"] = findings
        node = Node(
            id=node_id,
            node_type=NodeType.PAM_FILE,
            name=logical,
            properties=props,
        )
        graph.add_node(node)

        if findings and graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={
                    "mechanism": "PAM stack",
                    "service": service,
                    "findings_count": len(findings),
                },
            ))

        # Writability of a PAM config file is itself critical.
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            self._emit_write_edges(graph, node_id, st)

    def _emit_write_edges(self, graph: PrivilegeGraph, node_id: str, st) -> None:
        import grp
        mode = st.st_mode
        if mode & stat.S_IWOTH:
            for u in graph.get_nodes_by_type(NodeType.USER):
                if u.properties.get("uid") == 0:
                    continue
                graph.add_edge(Edge(
                    source_id=u.id,
                    target_id=node_id,
                    edge_type=EdgeType.CAN_WRITE,
                    properties={"reason": "world-writable PAM file"},
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
                        if member and member.properties.get("uid") != 0:
                            graph.add_edge(Edge(
                                source_id=member.id,
                                target_id=node_id,
                                edge_type=EdgeType.CAN_WRITE,
                                properties={
                                    "reason": "group-writable PAM file",
                                    "group": gname,
                                },
                            ))
