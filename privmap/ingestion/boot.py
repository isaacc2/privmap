"""Boot, login, and library-loading surfaces.

Covers code paths that execute *implicitly* when a user logs in or when
any binary launches:

- /etc/profile, /etc/bash.bashrc, /etc/profile.d/* (executed at login by
  every interactive shell).
- /etc/skel/* (templates for new user home directories).
- /etc/ld.so.preload (loaded into every dynamically linked process).
- /etc/ld.so.conf and /etc/ld.so.conf.d/* (control the dynamic linker
  search path).
- Polkit JS rules under /etc/polkit-1/rules.d and /usr/share/polkit-1/rules.d.

Writability on any of these is a fast path to root because the privileged
side reads them without question.
"""
from __future__ import annotations

import logging
import os
import stat

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


# Files that are sourced at every interactive login.
_LOGIN_TIME_SCRIPTS = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zprofile",
    "/etc/zsh/zshrc",
    "/etc/csh.cshrc",
    "/etc/csh.login",
]

# Directories whose contents are sourced at login.
_LOGIN_TIME_DIRS = [
    "/etc/profile.d",
    "/etc/bashrc.d",
]

# Library-loading control surfaces. Writing any of these affects every
# dynamically linked process the next time it runs.
_LDSO_FILES = [
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
]
_LDSO_DIRS = [
    "/etc/ld.so.conf.d",
]

# Polkit rule directories.
_POLKIT_DIRS = [
    "/etc/polkit-1/rules.d",
    "/usr/share/polkit-1/rules.d",
    "/etc/polkit-1/localauthority",
]


class BootIngester:
    """Captures login-time scripts, library-loading control, polkit rules."""

    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def _abs_to_root(self, fs_path: str) -> str:
        """Map an absolute target-system path to where it lives under root_path."""
        return os.path.join(self.root, fs_path.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_login_scripts(graph)
        self._ingest_ldso(graph)
        self._ingest_polkit(graph)
        self._ingest_skel(graph)

    # ----- login-time scripts -----
    def _ingest_login_scripts(self, graph: PrivilegeGraph) -> None:
        for script_path in _LOGIN_TIME_SCRIPTS:
            full = self._abs_to_root(script_path)
            if os.path.isfile(full):
                self._add_login_script(graph, script_path, full)

        for dir_path in _LOGIN_TIME_DIRS:
            full_dir = self._abs_to_root(dir_path)
            if not os.path.isdir(full_dir):
                continue
            try:
                for name in os.listdir(full_dir):
                    fpath = os.path.join(dir_path, name)
                    full = os.path.join(full_dir, name)
                    if os.path.isfile(full):
                        self._add_login_script(graph, fpath, full)
            except (OSError, PermissionError) as e:
                logger.debug("Cannot list %s: %s", full_dir, e)

    def _add_login_script(
        self, graph: PrivilegeGraph, logical_path: str, real_path: str,
    ) -> None:
        try:
            st = os.lstat(real_path)
        except (OSError, PermissionError):
            return

        node_id = f"profile_script:{logical_path}"
        props = self._perm_props(st)
        props["path"] = logical_path

        # Flag dangerous PATH manipulation. Login scripts that prepend
        # `.` or `~` to PATH cause root (when it logs in) to execute
        # commands from the cwd or the user's home directory.
        try:
            with open(real_path, "r", errors="replace") as f:
                content = f.read(8192)
        except (OSError, PermissionError):
            content = ""
        path_findings = []
        import re as _re
        for m in _re.finditer(
            r'(?:^|\n)\s*(?:export\s+)?PATH\s*=\s*"?([^"\n]+)"?', content,
        ):
            path_value = m.group(1)
            entries = path_value.split(":")
            for entry in entries:
                e = entry.strip()
                # Treat empty PATH entries and "." as dangerous (they
                # both translate to cwd). "~" expands to the login user's
                # home, which root won't share.
                if e in ("", ".", "./", "~", "~/"):
                    path_findings.append(
                        f"PATH includes cwd-equivalent entry: {e!r} in {path_value}"
                    )
        if path_findings:
            props["path_manipulation"] = path_findings

        node = Node(
            id=node_id,
            node_type=NodeType.PROFILE_SCRIPT,
            name=logical_path,
            properties=props,
        )
        graph.add_node(node)

        # The script executes as whichever user logs in. Because root is a
        # plausible login target on every system with a console, emit an
        # EXECUTED_AT_LOGIN edge to root specifically.
        if graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.EXECUTED_AT_LOGIN,
                properties={"path": logical_path, "context": "interactive login"},
            ))

        self._emit_write_edges(graph, node_id, st, real_path)

    # ----- ld.so -----
    def _ingest_ldso(self, graph: PrivilegeGraph) -> None:
        for fpath in _LDSO_FILES:
            full = self._abs_to_root(fpath)
            if os.path.isfile(full):
                self._add_ldso_node(graph, fpath, full)

        for dir_path in _LDSO_DIRS:
            full_dir = self._abs_to_root(dir_path)
            if not os.path.isdir(full_dir):
                continue
            try:
                for name in os.listdir(full_dir):
                    fpath = os.path.join(dir_path, name)
                    full = os.path.join(full_dir, name)
                    if os.path.isfile(full):
                        self._add_ldso_node(graph, fpath, full)
            except (OSError, PermissionError) as e:
                logger.debug("Cannot list %s: %s", full_dir, e)

    def _add_ldso_node(
        self, graph: PrivilegeGraph, logical_path: str, real_path: str,
    ) -> None:
        try:
            st = os.lstat(real_path)
        except (OSError, PermissionError):
            return

        node_id = f"ldpreload_file:{logical_path}"
        props = self._perm_props(st)
        props["path"] = logical_path
        node = Node(
            id=node_id,
            node_type=NodeType.LDPRELOAD_FILE,
            name=logical_path,
            properties=props,
        )
        graph.add_node(node)

        # An LD_PRELOAD-class file influences every binary that loads next.
        # Conservatively model it as "influences any root process": if a root
        # process exists, writing this file gets you root execution.
        if graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={
                    "path": logical_path,
                    "mechanism": "dynamic linker",
                },
            ))

        self._emit_write_edges(graph, node_id, st, real_path)

    # ----- polkit -----
    def _ingest_polkit(self, graph: PrivilegeGraph) -> None:
        for dir_path in _POLKIT_DIRS:
            full_dir = self._abs_to_root(dir_path)
            if not os.path.isdir(full_dir):
                continue
            try:
                entries = os.listdir(full_dir)
            except (OSError, PermissionError) as e:
                logger.debug("Cannot list %s: %s", full_dir, e)
                continue
            for name in entries:
                fpath = os.path.join(dir_path, name)
                full = os.path.join(full_dir, name)
                if not os.path.isfile(full):
                    continue
                self._add_polkit_node(graph, fpath, full)

    def _add_polkit_node(
        self, graph: PrivilegeGraph, logical_path: str, real_path: str,
    ) -> None:
        try:
            st = os.lstat(real_path)
        except (OSError, PermissionError):
            return

        node_id = f"polkit_rule:{logical_path}"
        props = self._perm_props(st)
        props["path"] = logical_path
        # Best-effort look for unix-group:* references so the report can
        # flag overprivileged rules without us writing a JS parser.
        try:
            with open(real_path, "r", errors="replace") as f:
                content = f.read(4096)
            for marker in ("unix-group:sudo", "unix-group:admin", "unix-group:wheel"):
                if marker in content:
                    props.setdefault("admin_groups", []).append(marker.split(":")[1])
        except (OSError, PermissionError):
            pass
        node = Node(
            id=node_id,
            node_type=NodeType.POLKIT_RULE,
            name=logical_path,
            properties=props,
        )
        graph.add_node(node)

        if graph.get_node("user:root"):
            graph.add_edge(Edge(
                source_id=node_id,
                target_id="user:root",
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={"path": logical_path, "mechanism": "polkit"},
            ))

        self._emit_write_edges(graph, node_id, st, real_path)

    # ----- /etc/skel -----
    def _ingest_skel(self, graph: PrivilegeGraph) -> None:
        skel = self._abs_to_root("/etc/skel")
        if not os.path.isdir(skel):
            return
        try:
            entries = os.listdir(skel)
        except (OSError, PermissionError):
            return
        for name in entries:
            full = os.path.join(skel, name)
            if not os.path.isfile(full):
                continue
            logical_path = os.path.join("/etc/skel", name)
            try:
                st = os.lstat(full)
            except (OSError, PermissionError):
                continue
            node_id = f"login_hook:{logical_path}"
            props = self._perm_props(st)
            props["path"] = logical_path
            props["skel_template"] = True
            node = Node(
                id=node_id,
                node_type=NodeType.LOGIN_HOOK,
                name=logical_path,
                properties=props,
            )
            graph.add_node(node)
            self._emit_write_edges(graph, node_id, st, full)

    # ----- shared perm helpers -----
    def _perm_props(self, st) -> dict:
        return {
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
        }

    def _emit_write_edges(
        self, graph: PrivilegeGraph, node_id: str, st, real_path: str,
    ) -> None:
        """Emit CAN_WRITE edges based on the file's mode bits.

        World-writable: every user can write.
        Group-writable: every member of the file's group can write.
        Owner-writable + non-root owner: that user can write.
        """
        import grp
        import pwd

        mode = st.st_mode

        if mode & stat.S_IWOTH:
            for user_node in graph.get_nodes_by_type(NodeType.USER):
                if user_node.properties.get("uid") == 0:
                    continue
                graph.add_edge(Edge(
                    source_id=user_node.id,
                    target_id=node_id,
                    edge_type=EdgeType.CAN_WRITE,
                    properties={"reason": "world-writable"},
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
                                    "reason": "group-writable",
                                    "group": gname,
                                },
                            ))

        if (mode & stat.S_IWUSR) and st.st_uid != 0:
            try:
                uname = pwd.getpwuid(st.st_uid).pw_name
            except (KeyError, ImportError):
                uname = None
            if uname:
                owner_node = graph.get_node(f"user:{uname}")
                if owner_node:
                    graph.add_edge(Edge(
                        source_id=owner_node.id,
                        target_id=node_id,
                        edge_type=EdgeType.CAN_WRITE,
                        properties={"reason": "owner-writable"},
                    ))
