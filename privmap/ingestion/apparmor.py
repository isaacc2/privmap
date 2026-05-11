"""AppArmor profile enumeration.

We list profiles under /etc/apparmor.d/ and check their state in
/sys/kernel/security/apparmor/profiles. Profiles in *complain* mode
(or unloaded) don't enforce, so even if a binary "has an AppArmor
profile" it may still be exploitable.

Deep policy analysis (which rules grant what) is out of scope; we flag
profiles in complain mode and writability of profile files themselves.
"""
from __future__ import annotations

import logging
import os
import stat
from typing import Dict

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class AppArmorIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        profile_modes = self._load_profile_modes()

        apparmor_d = self._abs("/etc/apparmor.d")
        if not os.path.isdir(apparmor_d):
            return

        try:
            entries = os.listdir(apparmor_d)
        except (OSError, PermissionError):
            return

        for name in entries:
            real = os.path.join(apparmor_d, name)
            if not os.path.isfile(real):
                continue
            logical = os.path.join("/etc/apparmor.d", name)
            self._ingest_profile(graph, logical, real, profile_modes)

    def _load_profile_modes(self) -> Dict[str, str]:
        """Read /sys/kernel/security/apparmor/profiles to map name -> mode."""
        modes: Dict[str, str] = {}
        modes_file = self._abs("/sys/kernel/security/apparmor/profiles")
        if not os.path.isfile(modes_file):
            return modes
        try:
            with open(modes_file, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    # Format: "<profile_name> (mode)"
                    if "(" in line and line.endswith(")"):
                        pname, _, rest = line.rpartition(" (")
                        modes[pname.strip()] = rest[:-1]
        except (OSError, PermissionError):
            pass
        return modes

    def _ingest_profile(
        self,
        graph: PrivilegeGraph,
        logical: str,
        real: str,
        modes: Dict[str, str],
    ) -> None:
        try:
            st = os.lstat(real)
        except (OSError, PermissionError):
            return

        # Best-effort: pull the first `profile <name>` declaration.
        profile_name = None
        complain_mode = False
        try:
            with open(real, "r", errors="replace") as f:
                content = f.read(8192)
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("profile "):
                    parts = line.split(None, 2)
                    if len(parts) >= 2:
                        profile_name = parts[1]
                    if " complain " in line or line.endswith(" complain") or "(complain)" in line:
                        complain_mode = True
                    break
        except (OSError, PermissionError):
            pass

        mode_from_sysfs = modes.get(profile_name or "", "")
        if mode_from_sysfs == "complain":
            complain_mode = True

        node_id = f"apparmor_profile:{logical}"
        props = {
            "path": logical,
            "file_mode": oct(stat.S_IMODE(st.st_mode)),
            "profile_name": profile_name,
            "runtime_mode": mode_from_sysfs or "unknown",
        }
        if complain_mode:
            props["enforce_disabled"] = True
        node = Node(
            id=node_id,
            node_type=NodeType.APPARMOR_PROFILE,
            name=logical,
            properties=props,
        )
        graph.add_node(node)

        # Writable profile file is itself an issue.
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            if graph.get_node("user:root"):
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id="user:root",
                    edge_type=EdgeType.INFLUENCES_EXEC,
                    properties={
                        "mechanism": "AppArmor profile is writable",
                    },
                ))
