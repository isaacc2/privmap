"""$PATH abuse vectors.

Looks at every directory on the system $PATH (taken from /etc/environment,
/etc/profile, /etc/login.defs, and a sensible default fallback) and flags:

- Writable PATH directories.
- Writable shell scripts (`.sh`) on PATH.
- Broken symlinks on PATH (a non-owner can create the link target and
  steal the next invocation).
- PATH entries that don't exist (an opportunity to plant them if their
  parent is writable).

Each PATH directory becomes a PATH_DIR node. Writability emits the usual
CAN_WRITE edges; presence of a writable item on PATH that root subsequently
invokes is a graph-reachable escalation chain via the existing EXECUTES
machinery in execution.py.
"""
from __future__ import annotations

import logging
import os
import re
import stat
from typing import List, Set

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class PathAbuseIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        path_dirs = self._discover_path()
        for path_dir in path_dirs:
            self._ingest_dir(graph, path_dir)
        # Once PATH_DIR nodes exist, connect them to any cron/systemd
        # whose command starts with an unqualified binary name. If the
        # user can write to any PATH dir, planting a binary of that name
        # hijacks the privileged execution.
        self._connect_unqualified_invocations(graph, path_dirs)

    def _discover_path(self) -> List[str]:
        """Pull $PATH from /etc/environment, /etc/login.defs, /etc/profile."""
        candidates: List[str] = []

        env_file = self._abs("/etc/environment")
        if os.path.isfile(env_file):
            try:
                with open(env_file, "r", errors="replace") as f:
                    for line in f:
                        m = re.match(r'^\s*PATH\s*=\s*"?([^"\n]+)"?', line)
                        if m:
                            candidates.append(m.group(1))
                            break
            except (OSError, PermissionError):
                pass

        login_defs = self._abs("/etc/login.defs")
        if os.path.isfile(login_defs):
            try:
                with open(login_defs, "r", errors="replace") as f:
                    for line in f:
                        m = re.match(r"^\s*(?:ENV_PATH|ENV_SUPATH)\s+(?:PATH=)?(.+)", line)
                        if m:
                            candidates.append(m.group(1).strip())
            except (OSError, PermissionError):
                pass

        # Snapshot mode: collector captured $PATH at runtime.
        if self.snapshot:
            path_txt = self._abs("/etc/path.txt")
            if os.path.isfile(path_txt):
                try:
                    with open(path_txt, "r", errors="replace") as f:
                        candidates.append(f.read().strip())
                except (OSError, PermissionError):
                    pass

        if not candidates:
            candidates.append(_DEFAULT_PATH)

        seen: Set[str] = set()
        out: List[str] = []
        for c in candidates:
            for d in c.split(":"):
                d = d.strip()
                if d and d not in seen:
                    seen.add(d)
                    out.append(d)
        return out

    def _connect_unqualified_invocations(
        self, graph: PrivilegeGraph, path_dirs: List[str],
    ) -> None:
        """For every CRON_JOB or SYSTEMD_UNIT whose command starts with
        an unqualified binary name, emit INFLUENCES_EXEC edges from each
        PATH_DIR node to the privileged execution context. Walking
        ``user -> CAN_WRITE -> path_dir -> INFLUENCES_EXEC -> cron ->
        RUNS_AS -> root`` then becomes a valid escalation chain.
        """
        path_dir_ids = [f"path_dir:{d}" for d in path_dirs]

        def has_unqualified_head(cmd: str) -> bool:
            tokens = cmd.split()
            if not tokens:
                return False
            i = 0
            while i < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
                i += 1
            if i >= len(tokens):
                return False
            head = tokens[i]
            # Unqualified = no slash. Strip a leading systemd prefix.
            head = re.sub(r"^[-+!]+", "", head)
            return "/" not in head

        for node in graph.get_nodes_by_type(NodeType.CRON_JOB):
            cmd = node.properties.get("command", "")
            if cmd and has_unqualified_head(cmd):
                self._emit_path_influence(graph, path_dir_ids, node.id, cmd)

        for node in graph.get_nodes_by_type(NodeType.SYSTEMD_UNIT):
            cmds = node.properties.get("exec_commands", [])
            if not isinstance(cmds, list):
                continue
            for cmd in cmds:
                if has_unqualified_head(cmd):
                    self._emit_path_influence(graph, path_dir_ids, node.id, cmd)
                    break

    def _emit_path_influence(
        self,
        graph: PrivilegeGraph,
        path_dir_ids: List[str],
        target_id: str,
        cmd: str,
    ) -> None:
        for path_dir_id in path_dir_ids:
            if graph.get_node(path_dir_id) is None:
                continue
            graph.add_edge(Edge(
                source_id=path_dir_id,
                target_id=target_id,
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={
                    "mechanism": "unqualified binary on PATH",
                    "command": cmd,
                },
            ))

    def _ingest_dir(self, graph: PrivilegeGraph, logical_dir: str) -> None:
        real_dir = self._abs(logical_dir)

        try:
            st = os.lstat(real_dir)
            exists = True
        except (OSError, PermissionError):
            st = None
            exists = False

        node_id = f"path_dir:{logical_dir}"
        props = {
            "path": logical_dir,
            "exists": exists,
        }
        if st is not None:
            props["mode"] = oct(stat.S_IMODE(st.st_mode))
            props["uid"] = st.st_uid
            props["gid"] = st.st_gid
        node = Node(
            id=node_id,
            node_type=NodeType.PATH_DIR,
            name=logical_dir,
            properties=props,
        )
        graph.add_node(node)

        # If the PATH dir itself is writable, emit CAN_WRITE edges from
        # the right principals directly to this PATH_DIR node. Doing it
        # here (rather than relying on the filesystem walk) makes the
        # path_abuse module self-contained and gives the graph a
        # PATH_DIR -> INFLUENCES_EXEC -> cron edge connected directly to
        # the same writable target.
        if st is not None:
            mode = st.st_mode
            if mode & stat.S_IWOTH:
                props["world_writable"] = True
                for u in graph.get_nodes_by_type(NodeType.USER):
                    if u.properties.get("uid") == 0:
                        continue
                    graph.add_edge(Edge(
                        source_id=u.id,
                        target_id=node_id,
                        edge_type=EdgeType.CAN_WRITE,
                        properties={"reason": "world-writable PATH dir"},
                    ))
            if (mode & stat.S_IWGRP) and not (mode & stat.S_IWOTH):
                import grp
                try:
                    gname = grp.getgrgid(st.st_gid).gr_name
                except (KeyError, ImportError):
                    gname = None
                if gname and gname != "root":
                    group_node = graph.get_node(f"group:{gname}")
                    if group_node:
                        props["group_writable"] = True
                        props["group"] = gname
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
                                        "reason": "group-writable PATH dir",
                                        "group": gname,
                                    },
                                ))

        if not exists:
            return

        # Walk the directory looking for writable shell scripts on PATH.
        try:
            entries = os.listdir(real_dir)
        except (OSError, PermissionError):
            return
        for name in entries:
            real_entry = os.path.join(real_dir, name)
            logical_entry = os.path.join(logical_dir, name)
            try:
                est = os.lstat(real_entry)
            except (OSError, PermissionError):
                continue

            if stat.S_ISLNK(est.st_mode):
                # Broken symlink on PATH is exploitable.
                try:
                    target = os.readlink(real_entry)
                except OSError:
                    continue
                # Resolve relative to the real entry
                target_abs = target if os.path.isabs(target) else os.path.join(real_dir, target)
                if not os.path.exists(target_abs):
                    file_id = f"file:{logical_entry}"
                    node = Node(
                        id=file_id,
                        node_type=NodeType.FILE,
                        name=logical_entry,
                        properties={
                            "path": logical_entry,
                            "broken_symlink": True,
                            "symlink_target": target,
                            "on_path_dir": logical_dir,
                        },
                    )
                    graph.add_node(node)
                continue

            # Plain shell script on PATH: if writable by a non-owner, it's
            # an escalation if any privileged context invokes it by name.
            if (
                stat.S_ISREG(est.st_mode)
                and (name.endswith(".sh") or os.access(real_entry, os.X_OK))
                and (est.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
            ):
                file_id = f"file:{logical_entry}"
                fprops = {
                    "path": logical_entry,
                    "on_path_dir": logical_dir,
                    "mode": oct(stat.S_IMODE(est.st_mode)),
                    "writable_on_path": True,
                }
                fnode = Node(
                    id=file_id,
                    node_type=NodeType.FILE,
                    name=logical_entry,
                    properties=fprops,
                )
                graph.add_node(fnode)
