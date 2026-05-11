"""D-Bus system bus policy analysis.

D-Bus policy XML in /etc/dbus-1/system.d/*.conf and
/usr/share/dbus-1/system.d/*.conf controls which uids/gids can invoke
methods on which services on the system bus. Most system services run
as root, so an overly permissive policy is a remote-procedure-call to
root.

We don't actually evaluate the methods, only flag policies that:
- ``<allow ... own="..."/>`` for a service owned by root.
- ``<allow send_destination="..."/>`` granted to any non-root user/group
  without a method restriction (`send_member`/`send_interface`).
- ``<allow user="root"/>`` or ``user="*"`` blocks (catch-all permits).

This is heuristic; D-Bus policy semantics are subtle. We're flagging
configurations worth manual review, not deterministic exploits.
"""
from __future__ import annotations

import logging
import os
import re
from typing import List
from xml.etree import ElementTree as ET

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


_POLICY_DIRS = [
    "/etc/dbus-1/system.d",
    "/usr/share/dbus-1/system.d",
    "/etc/dbus-1/session.d",
    "/usr/share/dbus-1/session.d",
]


class DBusIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        for d in _POLICY_DIRS:
            full = self._abs(d)
            if not os.path.isdir(full):
                continue
            try:
                entries = os.listdir(full)
            except (OSError, PermissionError):
                continue
            for name in entries:
                if not name.endswith(".conf"):
                    continue
                self._ingest_policy_file(
                    graph,
                    logical=os.path.join(d, name),
                    real=os.path.join(full, name),
                )

    def _ingest_policy_file(
        self, graph: PrivilegeGraph, logical: str, real: str,
    ) -> None:
        try:
            with open(real, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        # Parse the policy XML. D-Bus configs use the busconfig DOCTYPE
        # which may make strict parsers unhappy; fall back to regex on
        # parse failure.
        findings: List[dict] = []
        try:
            # Strip the DOCTYPE so ElementTree doesn't error.
            cleaned = re.sub(
                r"<!DOCTYPE[^>]+>", "", content, flags=re.DOTALL,
            )
            root = ET.fromstring(cleaned)
            for policy in root.iter("policy"):
                principal_attrs = {
                    k: v for k, v in policy.attrib.items()
                    if k in ("user", "group", "at_console", "context")
                }
                for allow in policy.iter("allow"):
                    attrs = allow.attrib
                    f = self._evaluate_allow(principal_attrs, attrs)
                    if f:
                        findings.append(f)
        except ET.ParseError:
            # Fallback: extract <policy ...><allow .../></policy> with regex.
            for m in re.finditer(
                r'<policy([^>]*)>(.*?)</policy>',
                content,
                re.DOTALL,
            ):
                policy_attr_str = m.group(1)
                principal_attrs = dict(re.findall(r'(\w+)="([^"]*)"', policy_attr_str))
                principal_attrs = {
                    k: v for k, v in principal_attrs.items()
                    if k in ("user", "group", "at_console", "context")
                }
                for am in re.finditer(r'<allow\s+([^/]+?)\s*/>', m.group(2)):
                    attrs = dict(re.findall(r'(\w+)="([^"]*)"', am.group(1)))
                    f = self._evaluate_allow(principal_attrs, attrs)
                    if f:
                        findings.append(f)

        node_id = f"dbus_policy:{logical}"
        props = {"path": logical, "policy_file": True}
        if findings:
            props["findings"] = findings
        node = Node(
            id=node_id,
            node_type=NodeType.DBUS_POLICY,
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
                    "mechanism": "D-Bus policy",
                    "findings_count": len(findings),
                },
            ))

    def _evaluate_allow(self, principal: dict, attrs: dict) -> dict:
        """Decide whether a given <allow ...> is over-permissive."""
        # <allow> with no send_member/send_interface restriction grants
        # access to ALL methods on the destination.
        if "send_destination" in attrs:
            has_method_restriction = (
                "send_member" in attrs or "send_interface" in attrs
            )
            grants_to = principal.get("group") or principal.get("user")
            if grants_to and not has_method_restriction:
                if grants_to not in ("root", "messagebus"):
                    return {
                        "type": "unrestricted_method_access",
                        "principal": principal,
                        "destination": attrs["send_destination"],
                    }
        # Policies that allow owning a well-known name from a non-root context.
        if "own" in attrs:
            grants_to = principal.get("group") or principal.get("user")
            if grants_to and grants_to not in ("root", "messagebus"):
                return {
                    "type": "name_ownership",
                    "principal": principal,
                    "name": attrs["own"],
                }
        # Universal allow (no principal restriction, just <allow .../>).
        if not principal and "send_destination" in attrs:
            return {
                "type": "universal_send",
                "destination": attrs["send_destination"],
            }
        return {}
