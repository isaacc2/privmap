"""Container detection.

Privmap is a privilege analyzer, not a container-escape exploit kit. What
we record here is contextual: whether the analyzed system *is* a container,
which class of container it is, and whether obvious breakout artefacts are
present (the docker socket mounted in, privileged mode markers, etc.).
Downstream consumers can cross-reference this with running processes.
"""
from __future__ import annotations

import logging
import os
import re
from typing import List, Optional

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class ContainerIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_markers(graph)
        self._ingest_writable_mounts(graph)

    def _ingest_writable_mounts(self, graph: PrivilegeGraph) -> None:
        """Parse /proc/mounts. Bind mounts without ``nosuid`` (or
        equivalent flag) that are writable from inside the container are
        a SUID persistence vector.
        """
        mounts_file = self._abs("/proc/mounts")
        if not os.path.isfile(mounts_file):
            return
        try:
            with open(mounts_file, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            device, mountpoint, fstype, options = fields[0], fields[1], fields[2], fields[3]
            # Only flag mounts under typical container-relevant locations.
            if not (
                mountpoint.startswith("/host")
                or mountpoint.startswith("/mnt")
                or mountpoint.startswith("/var/lib")
                or mountpoint == "/"
            ):
                continue
            opt_set = set(options.split(","))
            if "ro" in opt_set:
                continue
            risky = []
            if "nosuid" not in opt_set:
                risky.append("no nosuid")
            if "nodev" not in opt_set and fstype != "tmpfs":
                risky.append("no nodev")
            if not risky:
                continue
            node_id = f"mount:{mountpoint}"
            node = Node(
                id=node_id,
                node_type=NodeType.MOUNT,
                name=mountpoint,
                properties={
                    "device": device,
                    "mountpoint": mountpoint,
                    "fstype": fstype,
                    "options": sorted(opt_set),
                    "risky": risky,
                    "writable_bind_mount": True,
                },
            )
            graph.add_node(node)
            if graph.get_node("user:root"):
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id="user:root",
                    edge_type=EdgeType.INFLUENCES_EXEC,
                    properties={
                        "mechanism": "writable bind mount without nosuid",
                        "mountpoint": mountpoint,
                    },
                ))

    def _ingest_markers(self, graph: PrivilegeGraph) -> None:
        markers: List[str] = []
        ctype: Optional[str] = None

        dockerenv = self._abs("/.dockerenv")
        if os.path.exists(dockerenv):
            markers.append("/.dockerenv present")
            ctype = "docker"

        lxc_marker = self._abs("/run/.containerenv")
        if os.path.exists(lxc_marker):
            markers.append("/run/.containerenv present")
            if ctype is None:
                ctype = "podman/lxc"

        cgroup_path = self._abs("/proc/1/cgroup")
        if os.path.isfile(cgroup_path):
            try:
                with open(cgroup_path, "r", errors="replace") as f:
                    content = f.read()
                if re.search(r"\bdocker\b|\bcontainerd\b", content):
                    markers.append("/proc/1/cgroup references docker")
                    ctype = ctype or "docker"
                if re.search(r"\bkubepods\b", content):
                    markers.append("/proc/1/cgroup references kubepods")
                    ctype = ctype or "kubernetes"
                if "lxc" in content:
                    markers.append("/proc/1/cgroup references lxc")
                    ctype = ctype or "lxc"
            except (OSError, PermissionError):
                pass

        # Docker socket mounted into the container is a breakout primitive.
        breakout_artifacts: List[str] = []
        for sock in ("/var/run/docker.sock", "/run/docker.sock"):
            full = self._abs(sock)
            if os.path.exists(full):
                breakout_artifacts.append(f"{sock} accessible from inside")

        # If /proc/self/status shows CapEff = 0x*f covering all caps, we're
        # privileged. Approximate by comparing CapBnd against the kernel's
        # full cap mask.
        proc_status = self._abs("/proc/self/status")
        if os.path.isfile(proc_status):
            try:
                with open(proc_status, "r", errors="replace") as f:
                    for line in f:
                        if line.startswith("CapEff:"):
                            cap_eff = line.split()[1]
                            try:
                                cap_int = int(cap_eff, 16)
                                # Linux currently defines 41 capabilities;
                                # 0x1ffffffffff is all 41 set. Any process
                                # with this cap mask is effectively root.
                                if cap_int >= (1 << 40):
                                    breakout_artifacts.append(
                                        f"process has full effective capabilities (CapEff={cap_eff})"
                                    )
                            except ValueError:
                                pass
            except (OSError, PermissionError):
                pass

        if not markers:
            # Not in a container, and no markers. Nothing to add.
            return

        node_id = "container_marker:host"
        node = Node(
            id=node_id,
            node_type=NodeType.CONTAINER_MARKER,
            name=ctype or "container",
            properties={
                "container_type": ctype or "unknown",
                "markers": markers,
                "breakout_artifacts": breakout_artifacts,
            },
        )
        graph.add_node(node)

        # If we found breakout artefacts, the marker is itself a sink-ish
        # indicator: a process with these privileges can almost certainly
        # reach root on the host.
        if breakout_artifacts and graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={
                    "mechanism": "container breakout",
                    "artifacts": breakout_artifacts,
                },
            ))
