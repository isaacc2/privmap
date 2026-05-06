"""Ingest running process data from /proc."""
from __future__ import annotations

import logging
import os
from typing import Dict

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class ProcessIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def ingest(self, graph: PrivilegeGraph) -> None:
        proc_path = self._path("proc")
        if not os.path.isdir(proc_path):
            logger.debug("No /proc directory found at %s", proc_path)
            return

        for entry in os.listdir(proc_path):
            if not entry.isdigit():
                continue
            self._ingest_process(graph, proc_path, entry)

    def _ingest_process(
        self, graph: PrivilegeGraph, proc_path: str, pid: str
    ) -> None:
        status_path = os.path.join(proc_path, pid, "status")
        if not os.path.isfile(status_path):
            return

        try:
            status_data: Dict[str, str] = {}
            with open(status_path, "r") as f:
                for line in f:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        status_data[key.strip()] = val.strip()

            name = status_data.get("Name", f"pid:{pid}")
            uid_line = status_data.get("Uid", "")
            gid_line = status_data.get("Gid", "")

            uid_parts = uid_line.split()
            gid_parts = gid_line.split()

            real_uid = int(uid_parts[0]) if len(uid_parts) > 0 else -1
            effective_uid = int(uid_parts[1]) if len(uid_parts) > 1 else -1
            real_gid = int(gid_parts[0]) if len(gid_parts) > 0 else -1
            effective_gid = int(gid_parts[1]) if len(gid_parts) > 1 else -1

            # Get command line
            cmdline = ""
            cmdline_path = os.path.join(proc_path, pid, "cmdline.txt")
            if not os.path.isfile(cmdline_path):
                cmdline_path = os.path.join(proc_path, pid, "cmdline")
            if os.path.isfile(cmdline_path):
                try:
                    with open(cmdline_path, "r") as f:
                        cmdline = f.read().replace("\x00", " ").strip()
                except (OSError, PermissionError):
                    pass

            # Get executable path
            exe_path = ""
            exe_link_path = os.path.join(proc_path, pid, "exe_link.txt")
            if os.path.isfile(exe_link_path):
                try:
                    with open(exe_link_path, "r") as f:
                        exe_path = f.read().strip()
                except (OSError, PermissionError):
                    pass
            elif not self.snapshot:
                try:
                    exe_path = os.readlink(os.path.join(proc_path, pid, "exe"))
                except (OSError, PermissionError):
                    pass

            proc_id = f"process:{pid}:{name}"
            props = {
                "pid": int(pid),
                "process_name": name,
                "real_uid": real_uid,
                "effective_uid": effective_uid,
                "real_gid": real_gid,
                "effective_gid": effective_gid,
                "cmdline": cmdline,
                "exe_path": exe_path,
            }

            # Get supplementary groups
            groups_line = status_data.get("Groups", "")
            if groups_line:
                props["supplementary_groups"] = [
                    int(g) for g in groups_line.split() if g.isdigit()
                ]

            proc_node = Node(
                id=proc_id,
                node_type=NodeType.PROCESS,
                name=f"{name} (pid {pid})",
                properties=props,
            )
            graph.add_node(proc_node)

            # RUNS_AS edge — process runs as effective UID user
            if effective_uid == 0:
                root_node = graph.get_node("user:root")
                if root_node:
                    graph.add_edge(Edge(
                        source_id=proc_id,
                        target_id="user:root",
                        edge_type=EdgeType.RUNS_AS,
                        properties={"effective_uid": 0},
                    ))

                    # If root process executes a writable file, that's interesting
                    if exe_path:
                        file_id = f"file:{exe_path}"
                        if graph.get_node(file_id):
                            graph.add_edge(Edge(
                                source_id=proc_id,
                                target_id=file_id,
                                edge_type=EdgeType.EXECUTES,
                                properties={"pid": int(pid)},
                            ))

        except (OSError, PermissionError, ValueError) as e:
            logger.debug("Error processing /proc/%s: %s", pid, e)
