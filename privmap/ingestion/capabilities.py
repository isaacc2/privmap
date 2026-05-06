"""Ingest Linux capabilities from binaries and running processes."""
from __future__ import annotations

import logging
import os
import re
import stat
import subprocess
from typing import Set, Tuple

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)

DANGEROUS_CAPS = {
    "cap_sys_admin",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_setuid",
    "cap_setgid",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_fowner",
    "cap_chown",
    "cap_net_admin",
    "cap_net_raw",
    "cap_mknod",
    "cap_sys_chroot",
}

# Binaries that legitimately carry capabilities as part of normal system operation.
# These use caps internally for a narrow purpose and drop/contain them before the
# caller can leverage them. Flagging these produces noise with no actionable finding.
# This list mirrors the approach taken by mainstream auditing tools (lynis, linux-exploit-suggester)
# and aligns with default package configurations on Debian, Ubuntu, RHEL, and Fedora.
KNOWN_SAFE_CAP_BINARIES = {
    # Networking utilities — need cap_net_raw / cap_net_bind_service
    "ping",
    "ping4",
    "ping6",
    "mtr",
    "mtr-packet",
    "traceroute",
    "traceroute6",
    "arping",
    "clockdiff",
    # Snap sandboxing — uses caps to build sandbox, drops before exec
    "snap-confine",
    # Systemd components — cap_sys_admin etc. for internal use only
    "systemd-detect-virt",
    # Gnome keyring — cap_ipc_lock
    "gnome-keyring-daemon",
    # Industrial I/O — cap_net_admin for device access
    "iio-sensor-proxy",
    # Chrony / NTP — cap_sys_time
    "chronyd",
    "ntpd",
}


def _user_can_execute(
    binary_path: str,
    uid: int,
    gid: int,
    supplementary_gids: Set[int],
    root_path: str = "/",
) -> bool:
    """Check if a user with the given uid/gid/groups can execute a binary.

    Falls through user -> group -> other so that a user who is also in
    the file's group still gets group access if the user-bit is unset.
    """
    try:
        st = os.stat(binary_path)
    except (OSError, PermissionError):
        return True

    mode = st.st_mode
    file_uid = st.st_uid
    file_gid = st.st_gid

    if uid == 0:
        return True

    # If the user owns the file and has user-execute, they can execute
    if uid == file_uid and (mode & stat.S_IXUSR):
        return True

    # If the user is in the file's group (primary or supplementary)
    # and group-execute is set, they can execute
    if (file_gid == gid or file_gid in supplementary_gids) and (mode & stat.S_IXGRP):
        return True

    # Otherwise check the other-execute bit
    return bool(mode & stat.S_IXOTH)


def _resolve_user_groups(
    graph: PrivilegeGraph, user_node: Node
) -> Tuple[int, int, Set[int]]:
    """Resolve a user's UID, primary GID, and set of supplementary GIDs from the graph."""
    uid = user_node.properties.get("uid", -1)
    gid = user_node.properties.get("gid", -1)
    supplementary: Set[int] = set()

    # Walk MEMBER_OF edges to collect group GIDs
    for neighbor, edge in graph.get_neighbors(user_node.id):
        if edge.edge_type == EdgeType.MEMBER_OF and neighbor.node_type == NodeType.GROUP:
            group_gid = neighbor.properties.get("gid")
            if group_gid is not None:
                supplementary.add(group_gid)

    return uid, gid, supplementary


class CapabilityIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def ingest(self, graph: PrivilegeGraph) -> None:
        if self.snapshot:
            self._ingest_snapshot(graph)
        else:
            self._ingest_live(graph)

    def _ingest_live(self, graph: PrivilegeGraph) -> None:
        try:
            result = subprocess.run(
                ["getcap", "-r", "/"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 or result.stdout:
                self._parse_getcap_output(graph, result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug("getcap not available or timed out: %s", e)

        # Process capabilities from /proc
        self._ingest_proc_caps(graph)

    def _ingest_snapshot(self, graph: PrivilegeGraph) -> None:
        caps_file = self._path("caps", "file_capabilities.txt")
        if os.path.isfile(caps_file):
            with open(caps_file, "r") as f:
                self._parse_getcap_output(graph, f.read())

    def _parse_getcap_output(self, graph: PrivilegeGraph, output: str) -> None:
        """Parse output like: /usr/bin/ping cap_net_raw=ep"""
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Format: /path/to/binary = cap_list or /path/to/binary cap_list
            match = re.match(r"^(\S+)\s*=?\s*(.+)$", line)
            if not match:
                continue

            binary_path = match.group(1)
            caps_str = match.group(2).strip()
            binary_name = os.path.basename(binary_path)

            # Skip known-safe binaries — these carry caps for legitimate internal
            # use and don't expose them to the caller in an exploitable way.
            if binary_name in KNOWN_SAFE_CAP_BINARIES:
                logger.debug(
                    "Skipping known-safe capability binary: %s (%s)",
                    binary_name, binary_path,
                )
                continue

            # Parse individual capabilities
            caps: Set[str] = set()
            for part in re.split(r"[,\s]+", caps_str):
                part = part.strip().lower()
                cap_match = re.match(r"(cap_\w+)", part)
                if cap_match:
                    caps.add(cap_match.group(1))

            if not caps:
                continue

            dangerous = caps & DANGEROUS_CAPS
            if not dangerous:
                continue

            # Add file node for the binary
            file_id = f"file:{binary_path}"
            file_node = Node(
                id=file_id,
                node_type=NodeType.FILE,
                name=binary_path,
                properties={"path": binary_path, "binary_name": binary_name},
            )
            graph.add_node(file_node)

            # Add capability nodes only for dangerous caps
            for cap in dangerous:
                cap_id = f"capability:{cap}:{binary_path}"
                cap_node = Node(
                    id=cap_id,
                    node_type=NodeType.CAPABILITY,
                    name=cap,
                    properties={
                        "capability": cap,
                        "binary": binary_path,
                        "binary_name": binary_name,
                        "dangerous": True,
                    },
                )
                graph.add_node(cap_node)

                graph.add_edge(Edge(
                    source_id=file_id,
                    target_id=cap_id,
                    edge_type=EdgeType.HAS_CAPABILITY,
                    properties={"caps_raw": caps_str},
                ))

                # Dangerous cap can lead to root
                root_node = graph.get_node("user:root")
                if root_node:
                    graph.add_edge(Edge(
                        source_id=cap_id,
                        target_id="user:root",
                        edge_type=EdgeType.GRANTS,
                        properties={
                            "capability": cap,
                            "binary": binary_path,
                        },
                    ))

            # Create CAN_EXEC edges only for users who can actually execute the binary,
            # based on file ownership, group, and mode bits.
            binary_full_path = binary_path
            if self.snapshot:
                # In snapshot mode we can't stat the original path; skip perm check
                # and fall through to conservative behavior (all non-root users).
                binary_full_path = None

            for user_node in graph.get_nodes_by_type(NodeType.USER):
                # Skip root — root can already do everything
                if user_node.properties.get("uid") == 0:
                    continue

                uid, gid, supp_gids = _resolve_user_groups(graph, user_node)

                if binary_full_path is not None:
                    if not _user_can_execute(binary_full_path, uid, gid, supp_gids):
                        continue

                graph.add_edge(Edge(
                    source_id=user_node.id,
                    target_id=file_id,
                    edge_type=EdgeType.CAN_EXEC,
                    properties={"reason": "capability-binary", "path": binary_path},
                ))

    def _ingest_proc_caps(self, graph: PrivilegeGraph) -> None:
        """Parse capability sets from /proc/[pid]/status."""
        proc_path = self._path("proc")
        if not os.path.isdir(proc_path):
            return

        for entry in os.listdir(proc_path):
            if not entry.isdigit():
                continue
            status_path = os.path.join(proc_path, entry, "status")
            if not os.path.isfile(status_path):
                continue

            try:
                with open(status_path, "r") as f:
                    status_data = {}
                    for line in f:
                        if ":" in line:
                            key, val = line.split(":", 1)
                            status_data[key.strip()] = val.strip()

                cap_eff = status_data.get("CapEff", "0")
                name = status_data.get("Name", f"pid:{entry}")
                uid_line = status_data.get("Uid", "")
                uid_parts = uid_line.split()
                effective_uid = int(uid_parts[1]) if len(uid_parts) > 1 else -1

                # Only interesting if non-root process has caps
                if effective_uid == 0:
                    continue

                cap_int = int(cap_eff, 16)
                if cap_int > 0:
                    proc_id = f"process:{entry}:{name}"
                    proc_node = Node(
                        id=proc_id,
                        node_type=NodeType.PROCESS,
                        name=f"{name} (pid {entry})",
                        properties={
                            "pid": int(entry),
                            "effective_uid": effective_uid,
                            "cap_eff": cap_eff,
                            "process_name": name,
                        },
                    )
                    graph.add_node(proc_node)
            except (OSError, PermissionError, ValueError):
                continue