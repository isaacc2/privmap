"""Ingest filesystem permissions: SUID/SGID, world-writable, ACLs, symlinks."""
from __future__ import annotations

import logging
import os
import stat
import subprocess
from typing import Callable, List, Optional

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)

# Same signature as builder.ProgressCallback. Decoupled to avoid a circular
# import when the ingester is exercised directly.
ProgressCallback = Callable[[str, Optional[str]], None]

KNOWN_SAFE_SUID_BINARIES = {
    "chrome-sandbox",
    "firejail",
    "bwrap",
    "fusermount",
    "fusermount3",
    "polkit-agent-helper-1",
}

EXCLUDED_PATH_PREFIXES = (
    "/usr/share",
    "/usr/src",
    "/usr/include",
    "/usr/lib/locale",
    "/usr/lib/python",
    "/usr/lib/x86_64-linux-gnu/locale",
    "/var/log",
    "/var/cache",
    "/var/lib/docker",
    "/var/lib/snapd",
    "/var/lib/flatpak",
    "/proc",
    "/sys",
    "/snap",
)

class FilesystemIngester:
    def __init__(
        self,
        root_path: str = "/",
        scan_paths: Optional[List[str]] = None,
        snapshot_mode: bool = False,
        progress: Optional[ProgressCallback] = None,
    ) -> None:
        self.root = root_path
        self.scan_paths = scan_paths or ["/etc", "/usr", "/opt", "/tmp", "/var"]
        self.snapshot = snapshot_mode
        self._progress = progress or (lambda phase, detail: None)

    def _path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def ingest(self, graph: PrivilegeGraph) -> None:
        if self.snapshot:
            self._ingest_snapshot(graph)
        else:
            self._ingest_live(graph)

    def _ingest_live(self, graph: PrivilegeGraph) -> None:
        for scan_path in self.scan_paths:
            full_path = self._path(scan_path.lstrip("/"))
            if not os.path.isdir(full_path):
                continue
            self._walk_directory(graph, full_path)
        self._ingest_acls(graph)

    def _ingest_snapshot(self, graph: PrivilegeGraph) -> None:
        # Parse SUID/SGID from snapshot files
        suid_file = self._path("suid", "suid_binaries.txt")
        if os.path.isfile(suid_file):
            with open(suid_file, "r") as f:
                for line in f:
                    path = line.strip()
                    if path:
                        self._add_suid_node(graph, path, is_sgid=False)

        sgid_file = self._path("suid", "sgid_binaries.txt")
        if os.path.isfile(sgid_file):
            with open(sgid_file, "r") as f:
                for line in f:
                    path = line.strip()
                    if path:
                        self._add_suid_node(graph, path, is_sgid=True)

        # Parse world-writable files
        ww_file = self._path("suid", "world_writable_files.txt")
        if os.path.isfile(ww_file):
            with open(ww_file, "r") as f:
                for line in f:
                    path = line.strip()
                    if path:
                        self._add_world_writable_node(graph, path, is_dir=False)

        ww_dirs = self._path("suid", "world_writable_dirs.txt")
        if os.path.isfile(ww_dirs):
            with open(ww_dirs, "r") as f:
                for line in f:
                    path = line.strip()
                    if path:
                        self._add_world_writable_node(graph, path, is_dir=True)

        # Parse permissions file
        perms_file = self._path("suid", "permissions.txt")
        if os.path.isfile(perms_file):
            self._parse_permissions_file(graph, perms_file)

        # Parse ACLs from snapshot
        acl_file = self._path("acl", "acls.txt")
        if os.path.isfile(acl_file):
            self._parse_acl_file(graph, acl_file)

        # Parse symlinks
        symlinks_file = self._path("suid", "symlinks.txt")
        if os.path.isfile(symlinks_file):
            with open(symlinks_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if " -> " in line:
                        link, target = line.split(" -> ", 1)
                        self._check_symlink(graph, link.strip(), target.strip())

    def _walk_directory(self, graph: PrivilegeGraph, base_path: str) -> None:
        file_count = 0
        try:
            for dirpath, dirnames, filenames in os.walk(base_path, followlinks=False):
                dirnames[:] = [
                    d for d in dirnames
                    if not any(
                        os.path.join(dirpath, d).startswith(prefix)
                        for prefix in EXCLUDED_PATH_PREFIXES
                    )
                ]

                self._check_path(graph, dirpath, is_dir=True)

                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    self._check_path(graph, fpath, is_dir=False)
                    file_count += 1
                    if file_count % 5000 == 0:
                        self._progress(
                            "Walking filesystem",
                            f"{base_path}: {file_count:,} files",
                        )
                        logger.info("  Walked %d files in %s...", file_count, base_path)

                    if os.path.islink(fpath):
                        try:
                            target = os.readlink(fpath)
                            self._check_symlink(graph, fpath, target)
                        except OSError:
                            pass
            self._progress(
                "Walking filesystem",
                f"{base_path}: {file_count:,} files (done)",
            )
            logger.info("  Completed walk of %s: %d files", base_path, file_count)
        except PermissionError:
            logger.debug("Permission denied walking: %s", base_path)

    def _check_path(self, graph: PrivilegeGraph, fpath: str, is_dir: bool) -> None:
        try:
            st = os.lstat(fpath)
        except (OSError, PermissionError):
            return

        mode = st.st_mode

        # SUID binary
        if stat.S_ISREG(mode) and (mode & stat.S_ISUID):
            self._add_suid_node(graph, fpath, is_sgid=False, stat_result=st)

        # SGID binary
        if stat.S_ISREG(mode) and (mode & stat.S_ISGID):
            self._add_suid_node(graph, fpath, is_sgid=True, stat_result=st)

        # World-writable. Skip files inside a sticky directory (e.g. /tmp, /var/tmp)
        # because the sticky bit prevents non-owners from replacing or unlinking
        # them, so the world-writable bit isn't actually exploitable.
        if mode & stat.S_IWOTH:
            if not is_dir and self._parent_is_sticky(fpath):
                logger.debug("Skipping world-writable in sticky dir: %s", fpath)
            else:
                self._add_world_writable_node(graph, fpath, is_dir=is_dir, stat_result=st)

    @staticmethod
    def _parent_is_sticky(fpath: str) -> bool:
        try:
            parent_st = os.stat(os.path.dirname(fpath))
        except (OSError, PermissionError):
            return False
        return bool(parent_st.st_mode & stat.S_ISVTX)

    def _add_suid_node(
        self,
        graph: PrivilegeGraph,
        fpath: str,
        is_sgid: bool = False,
        stat_result=None,
    ) -> None:
        import pwd
        import grp

        binary_name = os.path.basename(fpath)
        if binary_name in KNOWN_SAFE_SUID_BINARIES:
            logger.debug("Skipping known-safe SUID binary: %s (%s)", binary_name, fpath)
            return

        node_id = f"suid:{fpath}"

        props = {"path": fpath, "binary": binary_name, "sgid": is_sgid, "suid": not is_sgid}
        if stat_result:
            props["mode"] = oct(stat.S_IMODE(stat_result.st_mode))
            try:
                props["owner"] = pwd.getpwuid(stat_result.st_uid).pw_name
            except (KeyError, ImportError):
                props["owner"] = str(stat_result.st_uid)
            try:
                props["group"] = grp.getgrgid(stat_result.st_gid).gr_name
            except (KeyError, ImportError):
                props["group"] = str(stat_result.st_gid)

        node = Node(
            id=node_id,
            node_type=NodeType.SUID_BINARY,
            name=fpath,
            properties=props,
        )
        graph.add_node(node)

        # If SUID root, create edge to root
        owner = props.get("owner", "")
        if owner == "root" or (stat_result and stat_result.st_uid == 0):
            root_node = graph.get_node("user:root")
            if root_node:
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id="user:root",
                    edge_type=EdgeType.RUNS_AS,
                    properties={"suid": True, "path": fpath},
                ))

            # All users can potentially execute SUID binaries
            for user_node in graph.get_nodes_by_type(NodeType.USER):
                graph.add_edge(Edge(
                    source_id=user_node.id,
                    target_id=node_id,
                    edge_type=EdgeType.SUID_EXEC,
                    properties={"path": fpath},
                ))

    def _add_world_writable_node(
        self,
        graph: PrivilegeGraph,
        fpath: str,
        is_dir: bool = False,
        stat_result=None,
    ) -> None:
        ntype = NodeType.DIRECTORY if is_dir else NodeType.FILE
        node_id = f"{'dir' if is_dir else 'file'}:{fpath}"

        props = {"path": fpath, "world_writable": True}
        if stat_result:
            props["mode"] = oct(stat.S_IMODE(stat_result.st_mode))
            props["sticky"] = bool(stat_result.st_mode & stat.S_ISVTX)

        node = Node(id=node_id, node_type=ntype, name=fpath, properties=props)
        graph.add_node(node)

        # All users can write to world-writable resources
        for user_node in graph.get_nodes_by_type(NodeType.USER):
            graph.add_edge(Edge(
                source_id=user_node.id,
                target_id=node_id,
                edge_type=EdgeType.CAN_WRITE,
                properties={"reason": "world-writable"},
            ))

    def _check_symlink(self, graph: PrivilegeGraph, link: str, target: str) -> None:
        sensitive_targets = {
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config",
        }
        if target in sensitive_targets:
            node_id = f"file:{link}"
            node = Node(
                id=node_id,
                node_type=NodeType.FILE,
                name=link,
                properties={
                    "symlink": True,
                    "symlink_target": target,
                    "path": link,
                    "sensitive_target": True,
                },
            )
            graph.add_node(node)

    def _ingest_acls(self, graph: PrivilegeGraph) -> None:
        """Parse ACLs using getfacl on live systems."""
        try:
            subprocess.run(["getfacl", "--version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            logger.debug("getfacl not available, skipping ACL ingestion")
            return

        for scan_path in self.scan_paths:
            full_path = self._path(scan_path.lstrip("/"))
            if not os.path.isdir(full_path):
                continue
            try:
                result = subprocess.run(
                    ["getfacl", "-R", full_path],
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    self._parse_acl_output(graph, result.stdout)
            except subprocess.TimeoutExpired:
                # An ACL scan that times out has produced incomplete output —
                # surface this loudly so a user doesn't trust a clean report.
                logger.warning(
                    "ACL scan timed out on %s; results for this path are incomplete. "
                    "Consider narrowing --scan-paths.", full_path,
                )
            except OSError as e:
                logger.debug("ACL scan failed for %s: %s", full_path, e)

    def _parse_acl_output(self, graph: PrivilegeGraph, output: str) -> None:
        """Parse getfacl output and add ACL-based edges.

        Honors both ``user:NAME:`` entries (named-user ACL) and ``group:NAME:``
        entries (named-group ACL). Most real escalation paths via ACLs go
        through groups, so ignoring group entries underreports findings.
        """
        current_file = None
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("# file:"):
                current_file = line.split(":", 1)[1].strip()
                continue
            if not current_file:
                continue

            parts = line.split(":")
            if len(parts) < 3:
                continue
            kind, name, perms = parts[0], parts[1], parts[2]
            # Skip the bare "user::" / "group::" / "other::" mode entries —
            # those duplicate the standard mode bits handled elsewhere.
            if not name or "w" not in perms:
                continue

            file_id = f"file:{current_file}"

            if kind == "user":
                principal_id = f"user:{name}"
                principals = [principal_id] if graph.get_node(principal_id) else []
            elif kind == "group":
                group_id = f"group:{name}"
                if not graph.get_node(group_id):
                    continue
                # Expand the group into its member users — MEMBER_OF runs
                # user -> group, so we walk incoming edges on the group.
                principals = [
                    edge.source_id
                    for edge in graph.get_edges_to(group_id)
                    if edge.edge_type == EdgeType.MEMBER_OF
                ]
            else:
                continue

            if not principals:
                continue

            file_node = Node(
                id=file_id,
                node_type=NodeType.FILE,
                name=current_file,
                properties={"path": current_file, "acl_writable": True},
            )
            graph.add_node(file_node)
            for principal_id in principals:
                graph.add_edge(Edge(
                    source_id=principal_id,
                    target_id=file_id,
                    edge_type=EdgeType.CAN_WRITE,
                    properties={
                        "reason": f"ACL ({kind})",
                        "acl_perms": perms,
                        "acl_principal": name,
                    },
                ))

    def _parse_acl_file(self, graph: PrivilegeGraph, acl_path: str) -> None:
        try:
            with open(acl_path, "r") as f:
                self._parse_acl_output(graph, f.read())
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read ACL file %s: %s", acl_path, e)

    def _parse_permissions_file(self, graph: PrivilegeGraph, perms_path: str) -> None:
        """Parse the permissions.txt from snapshot (mode owner group path)."""
        try:
            with open(perms_path, "r") as f:
                for line in f:
                    parts = line.strip().split(None, 3)
                    if len(parts) < 4:
                        continue
                    mode_s, owner, group, fpath = parts
                    try:
                        mode = int(mode_s, 8)
                    except ValueError:
                        continue

                    # Check for owner-writable sensitive files
                    if owner != "root" and (mode & 0o200):
                        file_node = Node(
                            id=f"file:{fpath}",
                            node_type=NodeType.FILE,
                            name=fpath,
                            properties={
                                "path": fpath,
                                "mode": oct(mode),
                                "owner": owner,
                                "group": group,
                            },
                        )
                        graph.add_node(file_node)

                        user_id = f"user:{owner}"
                        if graph.get_node(user_id):
                            graph.add_edge(Edge(
                                source_id=user_id,
                                target_id=file_node.id,
                                edge_type=EdgeType.CAN_WRITE,
                                properties={"reason": "owner-writable", "mode": oct(mode)},
                            ))
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read permissions file %s: %s", perms_path, e)
