"""Ingest identity data: passwd, shadow, group, sudoers."""
from __future__ import annotations

import logging
import os
import re
from typing import Dict, List, Tuple

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class IdentityIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_passwd(graph)
        self._ingest_group(graph)
        self._ingest_shadow(graph)
        self._ingest_sudoers(graph)

    # ── /etc/passwd ──
    def _ingest_passwd(self, graph: PrivilegeGraph) -> None:
        path = self._path("etc", "passwd")
        if not os.path.isfile(path):
            logger.warning("passwd not found: %s", path)
            return

        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username, _, uid_s, gid_s, gecos, home, shell = (
                    parts[0], parts[1], parts[2], parts[3],
                    parts[4], parts[5], parts[6],
                )
                try:
                    uid = int(uid_s)
                    gid = int(gid_s)
                except ValueError:
                    continue

                node = Node(
                    id=f"user:{username}",
                    node_type=NodeType.USER,
                    name=username,
                    properties={
                        "uid": uid,
                        "gid": gid,
                        "gecos": gecos,
                        "home": home,
                        "shell": shell,
                    },
                )
                graph.add_node(node)

    # ── /etc/group ──
    def _ingest_group(self, graph: PrivilegeGraph) -> None:
        path = self._path("etc", "group")
        if not os.path.isfile(path):
            logger.warning("group file not found: %s", path)
            return

        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                groupname, _, gid_s, members_s = (
                    parts[0], parts[1], parts[2], parts[3],
                )
                try:
                    gid = int(gid_s)
                except ValueError:
                    continue

                group_node = Node(
                    id=f"group:{groupname}",
                    node_type=NodeType.GROUP,
                    name=groupname,
                    properties={"gid": gid},
                )
                graph.add_node(group_node)

                # Add primary group membership for users with matching GID
                for user_node in graph.get_nodes_by_type(NodeType.USER):
                    if user_node.properties.get("gid") == gid:
                        graph.add_edge(Edge(
                            source_id=user_node.id,
                            target_id=group_node.id,
                            edge_type=EdgeType.MEMBER_OF,
                            properties={"membership": "primary"},
                        ))

                # Add supplementary group members
                members = [m.strip() for m in members_s.split(",") if m.strip()]
                for member in members:
                    user_id = f"user:{member}"
                    if graph.get_node(user_id):
                        graph.add_edge(Edge(
                            source_id=user_id,
                            target_id=group_node.id,
                            edge_type=EdgeType.MEMBER_OF,
                            properties={"membership": "supplementary"},
                        ))

    # ── /etc/shadow ──
    def _ingest_shadow(self, graph: PrivilegeGraph) -> None:
        path = self._path("etc", "shadow")
        if not os.path.isfile(path):
            logger.debug("shadow not readable: %s", path)
            return

        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue
                    username = parts[0]
                    password_hash = parts[1]

                    node = graph.get_node(f"user:{username}")
                    if node:
                        locked = password_hash.startswith("!") or \
                                 password_hash.startswith("*") or \
                                 password_hash == "!!" or \
                                 password_hash == ""
                        node.properties["account_locked"] = locked
                        node.properties["has_password"] = (
                            not locked and len(password_hash) > 2
                        )
                        # Detect weak/empty password hashes
                        if password_hash == "" or password_hash == "!":
                            node.properties["empty_password"] = True
        except PermissionError:
            logger.debug("Cannot read shadow file (permission denied)")

    # ── /etc/sudoers ──
    def _ingest_sudoers(self, graph: PrivilegeGraph) -> None:
        main_sudoers = self._path("etc", "sudoers")
        files_to_parse: List[str] = []

        if os.path.isfile(main_sudoers):
            files_to_parse.append(main_sudoers)

        sudoers_d = self._path("etc", "sudoers.d")
        if os.path.isdir(sudoers_d):
            for fname in sorted(os.listdir(sudoers_d)):
                fpath = os.path.join(sudoers_d, fname)
                if os.path.isfile(fpath) and not fname.startswith(".") and "~" not in fname:
                    files_to_parse.append(fpath)

        aliases: Dict[str, List[str]] = {
            "User_Alias": {},
            "Runas_Alias": {},
            "Cmnd_Alias": {},
            "Host_Alias": {},
        }

        raw_rules: List[str] = []
        for fpath in files_to_parse:
            try:
                with open(fpath, "r") as f:
                    continuation = ""
                    for line in f:
                        line = line.rstrip("\n")
                        # Handle line continuations
                        if line.endswith("\\"):
                            continuation += line[:-1]
                            continue
                        line = continuation + line
                        continuation = ""
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        # Parse aliases
                        alias_match = re.match(
                            r"^(User_Alias|Runas_Alias|Cmnd_Alias|Host_Alias)\s+"
                            r"(\w+)\s*=\s*(.+)$",
                            line,
                        )
                        if alias_match:
                            alias_type, name, values = alias_match.groups()
                            aliases[alias_type][name] = [
                                v.strip() for v in values.split(",")
                            ]
                            continue

                        # Defaults lines — skip
                        if line.startswith("Defaults"):
                            continue

                        # Include directives
                        inc_match = re.match(r"^[#@]include(?:dir)?\s+(.+)$", line)
                        if inc_match:
                            continue

                        raw_rules.append(line)
            except (PermissionError, OSError) as e:
                logger.debug("Cannot read sudoers file %s: %s", fpath, e)

        # Parse sudo rules
        for rule in raw_rules:
            self._parse_sudo_rule(graph, rule, aliases)

    def _parse_sudo_rule(
        self,
        graph: PrivilegeGraph,
        rule: str,
        aliases: Dict[str, Dict[str, List[str]]],
    ) -> None:
        """Parse a single sudoers rule line and add nodes/edges to graph."""
        # Format: user/group HOST = (runas) [NOPASSWD:] command [, command ...]
        match = re.match(
            r"^(%?\w[\w.-]*)\s+\S+\s*=\s*(.+)$",
            rule,
        )
        if not match:
            return

        principal_spec, cmd_spec = match.groups()

        # Determine if it's a group rule
        is_group = principal_spec.startswith("%")
        principal_name = principal_spec.lstrip("%")

        # Expand aliases
        principals = self._expand_alias(
            principal_name,
            aliases.get("User_Alias", {}),
            is_group,
        )

        # Parse runas and commands
        runas_user = "root"
        runas_match = re.match(r"^\(([^)]*)\)\s*(.+)$", cmd_spec)
        if runas_match:
            runas_spec, cmd_spec = runas_match.groups()
            if runas_spec:
                runas_user = runas_spec.split(":")[0].strip()
                if runas_user == "ALL":
                    runas_user = "root"

        nopasswd = False
        if "NOPASSWD:" in cmd_spec:
            nopasswd = True
            cmd_spec = cmd_spec.replace("NOPASSWD:", "").strip()
        if "PASSWD:" in cmd_spec:
            cmd_spec = cmd_spec.replace("PASSWD:", "").strip()

        # Split commands
        commands = [c.strip() for c in cmd_spec.split(",")]

        # Expand command aliases
        expanded_commands: List[str] = []
        for cmd in commands:
            cmd_base = cmd.split()[0] if cmd.split() else cmd
            if cmd_base in aliases.get("Cmnd_Alias", {}):
                expanded_commands.extend(aliases["Cmnd_Alias"][cmd_base])
            else:
                expanded_commands.append(cmd)

        # Filter negated commands
        negated = {c.lstrip("!").strip() for c in expanded_commands if c.startswith("!")}
        expanded_commands = [c for c in expanded_commands if not c.startswith("!")]

        for principal_name, is_grp in principals:
            for cmd in expanded_commands:
                if cmd in negated:
                    continue

                cmd_clean = cmd.strip()
                cmd_binary = cmd_clean.split()[0] if cmd_clean.split() else cmd_clean
                rule_id = f"sudo:{principal_name}:{cmd_binary}"

                sudo_node = Node(
                    id=rule_id,
                    node_type=NodeType.SUDO_RULE,
                    name=f"{principal_name} -> {cmd_clean}",
                    properties={
                        "command": cmd_clean,
                        "binary": cmd_binary,
                        "runas_user": runas_user,
                        "nopasswd": nopasswd,
                    },
                )
                graph.add_node(sudo_node)

                # Edge: principal -> sudo rule
                if is_grp:
                    group_id = f"group:{principal_name}"
                    if graph.get_node(group_id):
                        graph.add_edge(Edge(
                            source_id=group_id,
                            target_id=rule_id,
                            edge_type=EdgeType.GRANTS,
                            properties={"nopasswd": nopasswd},
                        ))
                else:
                    user_id = f"user:{principal_name}"
                    if graph.get_node(user_id):
                        graph.add_edge(Edge(
                            source_id=user_id,
                            target_id=rule_id,
                            edge_type=EdgeType.GRANTS,
                            properties={"nopasswd": nopasswd},
                        ))

                # Edge: sudo rule -> target user
                target_id = f"user:{runas_user}"
                if graph.get_node(target_id):
                    graph.add_edge(Edge(
                        source_id=rule_id,
                        target_id=target_id,
                        edge_type=EdgeType.GRANTS,
                        properties={
                            "command": cmd_clean,
                            "nopasswd": nopasswd,
                        },
                    ))

    def _expand_alias(
        self,
        name: str,
        user_aliases: Dict[str, List[str]],
        is_group: bool,
    ) -> List[Tuple[str, bool]]:
        if name in user_aliases:
            result = []
            for expanded in user_aliases[name]:
                expanded = expanded.strip()
                if expanded.startswith("%"):
                    result.append((expanded.lstrip("%"), True))
                else:
                    result.append((expanded, False))
            return result
        return [(name, is_group)]
