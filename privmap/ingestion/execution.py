"""Ingest execution contexts: cron, systemd, init.d."""
from __future__ import annotations

import logging
import os
import re
from typing import Dict, List

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class ExecutionIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_cron(graph)
        self._ingest_systemd(graph)
        self._ingest_initd(graph)

    # ── Cron ──
    def _ingest_cron(self, graph: PrivilegeGraph) -> None:
        # System crontab
        self._parse_system_crontab(graph, self._path("etc", "crontab"))

        # cron.d
        cron_d = self._path("etc", "cron.d") if not self.snapshot else self._path("cron", "cron.d")
        if os.path.isdir(cron_d):
            for fname in os.listdir(cron_d):
                fpath = os.path.join(cron_d, fname)
                if os.path.isfile(fpath):
                    self._parse_system_crontab(graph, fpath)

        # Periodic cron directories
        for period in ["cron.daily", "cron.hourly", "cron.weekly", "cron.monthly"]:
            if self.snapshot:
                cron_dir = self._path("cron", period)
            else:
                cron_dir = self._path("etc", period)
            if os.path.isdir(cron_dir):
                self._parse_cron_directory(graph, cron_dir, period)

        # Per-user crontabs
        if self.snapshot:
            user_cron_dir = self._path("cron", "user_crontabs")
        else:
            user_cron_dir = self._path("var", "spool", "cron", "crontabs")
        if os.path.isdir(user_cron_dir):
            for username in os.listdir(user_cron_dir):
                fpath = os.path.join(user_cron_dir, username)
                if os.path.isfile(fpath):
                    self._parse_user_crontab(graph, fpath, username)

    def _parse_system_crontab(self, graph: PrivilegeGraph, fpath: str) -> None:
        if not os.path.isfile(fpath):
            return
        try:
            with open(fpath, "r") as f:
                env_vars: Dict[str, str] = {}
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Environment variable
                    env_match = re.match(r"^(\w+)\s*=\s*(.+)$", line)
                    if env_match:
                        env_vars[env_match.group(1)] = env_match.group(2)
                        continue

                    # Cron entry: min hour dom mon dow user command
                    parts = line.split(None, 6)
                    if len(parts) >= 7:
                        schedule = " ".join(parts[:5])
                        run_as = parts[5]
                        command = parts[6]
                        self._add_cron_node(
                            graph, fpath, schedule, run_as, command, env_vars
                        )
                    # Some crontabs use @reboot etc
                    elif len(parts) >= 3 and parts[0].startswith("@"):
                        schedule = parts[0]
                        run_as = parts[1]
                        command = " ".join(parts[2:])
                        self._add_cron_node(
                            graph, fpath, schedule, run_as, command, env_vars
                        )
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read crontab %s: %s", fpath, e)

    def _parse_cron_directory(
        self, graph: PrivilegeGraph, dirpath: str, period: str
    ) -> None:
        """Parse scripts in /etc/cron.{daily,hourly,...} — run as root."""
        for fname in os.listdir(dirpath):
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue

            cron_id = f"cron:{fpath}"
            cron_node = Node(
                id=cron_id,
                node_type=NodeType.CRON_JOB,
                name=fpath,
                properties={
                    "source": fpath,
                    "period": period,
                    "run_as": "root",
                    "script": fpath,
                },
            )
            graph.add_node(cron_node)

            # Cron runs as root
            root_node = graph.get_node("user:root")
            if root_node:
                graph.add_edge(Edge(
                    source_id=cron_id,
                    target_id="user:root",
                    edge_type=EdgeType.RUNS_AS,
                    properties={"period": period},
                ))

            # Cron executes the script file
            file_id = f"file:{fpath}"
            file_node = Node(
                id=file_id,
                node_type=NodeType.FILE,
                name=fpath,
                properties={"path": fpath},
            )
            graph.add_node(file_node)

            graph.add_edge(Edge(
                source_id=cron_id,
                target_id=file_id,
                edge_type=EdgeType.EXECUTES,
                properties={"period": period},
            ))

    def _parse_user_crontab(
        self, graph: PrivilegeGraph, fpath: str, username: str
    ) -> None:
        try:
            with open(fpath, "r") as f:
                env_vars: Dict[str, str] = {}
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    env_match = re.match(r"^(\w+)\s*=\s*(.+)$", line)
                    if env_match:
                        env_vars[env_match.group(1)] = env_match.group(2)
                        continue

                    # User crontab: min hour dom mon dow command (no user field)
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        schedule = " ".join(parts[:5])
                        command = parts[5]
                        self._add_cron_node(
                            graph, fpath, schedule, username, command, env_vars
                        )
                    elif len(parts) >= 2 and parts[0].startswith("@"):
                        schedule = parts[0]
                        command = " ".join(parts[1:])
                        self._add_cron_node(
                            graph, fpath, schedule, username, command, env_vars
                        )
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read user crontab %s: %s", fpath, e)

    def _add_cron_node(
        self,
        graph: PrivilegeGraph,
        source_file: str,
        schedule: str,
        run_as: str,
        command: str,
        env_vars: Dict[str, str],
    ) -> None:
        cron_id = f"cron:{source_file}:{command[:80]}"
        cron_node = Node(
            id=cron_id,
            node_type=NodeType.CRON_JOB,
            name=f"{run_as}: {command[:80]}",
            properties={
                "source": source_file,
                "schedule": schedule,
                "run_as": run_as,
                "command": command,
                "env": env_vars,
            },
        )
        graph.add_node(cron_node)

        # RUNS_AS edge
        user_id = f"user:{run_as}"
        if graph.get_node(user_id):
            graph.add_edge(Edge(
                source_id=cron_id,
                target_id=user_id,
                edge_type=EdgeType.RUNS_AS,
                properties={"schedule": schedule},
            ))

        # EXECUTES edge — extract script/binary from command
        scripts = self._extract_executables(command)
        for script in scripts:
            file_id = f"file:{script}"
            file_node = Node(
                id=file_id,
                node_type=NodeType.FILE,
                name=script,
                properties={"path": script},
            )
            graph.add_node(file_node)
            graph.add_edge(Edge(
                source_id=cron_id,
                target_id=file_id,
                edge_type=EdgeType.EXECUTES,
                properties={"command": command},
            ))

    def _extract_executables(self, command: str) -> List[str]:
        """Extract absolute paths to executables from a command string."""
        executables = []
        # Match absolute paths
        for match in re.finditer(r"(/[\w./-]+)", command):
            path = match.group(1)
            if not path.endswith("/"):
                executables.append(path)
        return executables if executables else []

    # ── Systemd ──
    def _ingest_systemd(self, graph: PrivilegeGraph) -> None:
        if self.snapshot:
            systemd_base = self._path("systemd")
            if os.path.isdir(systemd_base):
                for subdir in os.listdir(systemd_base):
                    full = os.path.join(systemd_base, subdir)
                    if os.path.isdir(full):
                        self._scan_systemd_dir(graph, full)
        else:
            systemd_paths = [
                "/etc/systemd/system",
                "/usr/lib/systemd/system",
                "/lib/systemd/system",
                "/run/systemd/system",
            ]
            for spath in systemd_paths:
                full = self._path(spath.lstrip("/"))
                if os.path.isdir(full):
                    self._scan_systemd_dir(graph, full)

    def _scan_systemd_dir(self, graph: PrivilegeGraph, dirpath: str) -> None:
        for root, dirs, files in os.walk(dirpath):
            for fname in files:
                if fname.endswith(".service") or fname.endswith(".timer"):
                    fpath = os.path.join(root, fname)
                    self._parse_systemd_unit(graph, fpath)

    def _parse_systemd_unit(self, graph: PrivilegeGraph, fpath: str) -> None:
        try:
            with open(fpath, "r") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        unit_name = os.path.basename(fpath)
        unit_id = f"systemd:{unit_name}"

        props = {"path": fpath, "unit": unit_name}

        # Parse key directives
        exec_cmds = []
        for directive in ["ExecStart", "ExecStartPre", "ExecStartPost",
                         "ExecStop", "ExecReload"]:
            for match in re.finditer(
                rf"^{directive}\s*=\s*(.+)$", content, re.MULTILINE
            ):
                cmd = match.group(1).strip()
                # Strip systemd prefixes (-, +, !, !!)
                cmd = re.sub(r"^[-+!]+", "", cmd).strip()
                exec_cmds.append(cmd)

        user_match = re.search(r"^User\s*=\s*(\S+)$", content, re.MULTILINE)
        group_match = re.search(r"^Group\s*=\s*(\S+)$", content, re.MULTILINE)

        run_as = user_match.group(1) if user_match else "root"
        run_group = group_match.group(1) if group_match else None

        props["run_as"] = run_as
        props["run_group"] = run_group
        props["exec_commands"] = exec_cmds

        # Check for dangerous directives
        if re.search(r"^PrivilegedPort\s*=\s*true", content, re.MULTILINE | re.IGNORECASE):
            props["privileged_port"] = True
        if re.search(r"^AmbientCapabilities\s*=", content, re.MULTILINE):
            cap_match = re.search(
                r"^AmbientCapabilities\s*=\s*(.+)$", content, re.MULTILINE
            )
            if cap_match:
                props["ambient_capabilities"] = cap_match.group(1).strip()

        unit_node = Node(
            id=unit_id,
            node_type=NodeType.SYSTEMD_UNIT,
            name=unit_name,
            properties=props,
        )
        graph.add_node(unit_node)

        # RUNS_AS edge
        user_id = f"user:{run_as}"
        if graph.get_node(user_id):
            graph.add_edge(Edge(
                source_id=unit_id,
                target_id=user_id,
                edge_type=EdgeType.RUNS_AS,
                properties={"unit": unit_name},
            ))

        # EXECUTES edges for each command
        for cmd in exec_cmds:
            scripts = self._extract_executables_from_cmd(cmd)
            for script in scripts:
                file_id = f"file:{script}"
                file_node = Node(
                    id=file_id,
                    node_type=NodeType.FILE,
                    name=script,
                    properties={"path": script},
                )
                graph.add_node(file_node)
                graph.add_edge(Edge(
                    source_id=unit_id,
                    target_id=file_id,
                    edge_type=EdgeType.EXECUTES,
                    properties={"command": cmd},
                ))

    def _extract_executables_from_cmd(self, cmd: str) -> List[str]:
        paths = []
        for match in re.finditer(r"(/[\w./-]+)", cmd):
            path = match.group(1)
            if not path.endswith("/"):
                paths.append(path)
        return paths

    # ── Init.d ──
    def _ingest_initd(self, graph: PrivilegeGraph) -> None:
        if self.snapshot:
            initd_dir = self._path("initd")
        else:
            initd_dir = self._path("etc", "init.d")

        if not os.path.isdir(initd_dir):
            return

        for fname in os.listdir(initd_dir):
            fpath = os.path.join(initd_dir, fname)
            if not os.path.isfile(fpath):
                continue

            script_id = f"initd:{fname}"
            script_node = Node(
                id=script_id,
                node_type=NodeType.INITD_SCRIPT,
                name=fname,
                properties={"path": fpath, "run_as": "root"},
            )
            graph.add_node(script_node)

            # Init.d scripts run as root
            root_node = graph.get_node("user:root")
            if root_node:
                graph.add_edge(Edge(
                    source_id=script_id,
                    target_id="user:root",
                    edge_type=EdgeType.RUNS_AS,
                ))

            # Script file node
            file_id = f"file:{fpath}"
            file_node = Node(
                id=file_id,
                node_type=NodeType.FILE,
                name=fpath,
                properties={"path": fpath},
            )
            graph.add_node(file_node)
            graph.add_edge(Edge(
                source_id=script_id,
                target_id=file_id,
                edge_type=EdgeType.EXECUTES,
            ))
