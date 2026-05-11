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
            try:
                entries = os.listdir(user_cron_dir)
            except (PermissionError, OSError) as e:
                # /var/spool/cron/crontabs is mode 0730 root:crontab on Debian-
                # family systems - unreadable to non-root callers. Warn but
                # continue so unprivileged users still get a partial scan.
                logger.warning(
                    "Cannot read user crontab dir %s: %s. "
                    "Run as root for complete results.", user_cron_dir, e,
                )
                entries = []
            for username in entries:
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
        """Parse scripts in /etc/cron.{daily,hourly,...} - run as root."""
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

            # Read script content and extract any binaries it invokes plus
            # their config-file arguments. This is what closes the chain
            # for the classic "writable logrotate config + root cron" case.
            try:
                with open(fpath, "r", errors="replace") as f:
                    script_content = f.read()
            except (OSError, PermissionError):
                script_content = ""

            for line in script_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Drop a leading shebang's `#!`/`exec` prefix etc.
                line = re.sub(r"^\s*(?:exec|eval)\s+", "", line)
                for config in self._extract_config_arguments(line):
                    cfg_id = f"file:{config}"
                    cfg_node = Node(
                        id=cfg_id,
                        node_type=NodeType.FILE,
                        name=config,
                        properties={"path": config, "config_arg_of": line},
                    )
                    graph.add_node(cfg_node)
                    graph.add_edge(Edge(
                        source_id=cfg_id,
                        target_id=cron_id,
                        edge_type=EdgeType.INFLUENCES_EXEC,
                        properties={
                            "mechanism": "command-line config argument",
                            "command": line,
                            "source_file": fpath,
                        },
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
        cron_props = {
            "source": source_file,
            "schedule": schedule,
            "run_as": run_as,
            "command": command,
            "env": env_vars,
        }
        # Wildcard injection: a cron like ``tar czf /backup *`` lets a
        # writer in the cwd plant a file named ``--checkpoint=exec=...``.
        if self._has_wildcard_injection_risk(command):
            cron_props["wildcard_injection_risk"] = True

        cron_node = Node(
            id=cron_id,
            node_type=NodeType.CRON_JOB,
            name=f"{run_as}: {command[:80]}",
            properties=cron_props,
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

        # EXECUTES edge - extract script/binary from command
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

        # INFLUENCES_EXEC edges from any config-file path arguments back to
        # the cron job. Patterns like ``logrotate /etc/logrotate.d/myapp``
        # mean the config file partially controls the privileged execution:
        # someone who can write the config can hijack the cron's privilege.
        for config in self._extract_config_arguments(command):
            cfg_id = f"file:{config}"
            cfg_node = Node(
                id=cfg_id,
                node_type=NodeType.FILE,
                name=config,
                properties={"path": config, "config_arg_of": command},
            )
            graph.add_node(cfg_node)
            graph.add_edge(Edge(
                source_id=cfg_id,
                target_id=cron_id,
                edge_type=EdgeType.INFLUENCES_EXEC,
                properties={
                    "mechanism": "command-line config argument",
                    "command": command,
                },
            ))

    def _has_wildcard_injection_risk(self, command: str) -> bool:
        """Heuristic: does the command use a glob in argv to a tool that
        treats argv items as options? Classic vector: ``tar *`` in cwd."""
        risky_tools = (
            "tar", "rsync", "chown", "chmod", "7z", "zip", "unzip",
            "scp", "find",
        )
        for segment in re.split(r"(?:\|\||&&|;|\|)", command):
            tokens = segment.strip().split()
            if not tokens:
                continue
            i = 0
            while i < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
                i += 1
            if i >= len(tokens):
                continue
            head = os.path.basename(tokens[i]).lower()
            if head not in risky_tools:
                continue
            for arg in tokens[i + 1:]:
                # Standalone glob (not inside quotes - argv to this process
                # was already split, so any literal * means cwd expansion).
                if arg == "*" or arg.startswith("*") or arg.endswith("*"):
                    return True
        return False

    def _extract_config_arguments(self, command: str) -> List[str]:
        """Pull config-file-like absolute paths from command arguments.

        We only consider paths that look like config files: living under
        common config locations (``/etc/...``, ``/usr/local/etc/...``,
        ``/opt/.../conf/...``) and not ending in ``/``. This is a heuristic
        to capture things like ``logrotate /etc/logrotate.d/myapp`` where
        the second arg is a config the binary reads, without false-positive
        matching every directory listed in a ``find /etc ...`` command.
        """
        results: List[str] = []
        for segment in re.split(r"(?:\|\||&&|;|\||\bthen\b|\bdo\b)", command):
            tokens = segment.strip().split()
            i = 0
            while i < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
                i += 1
            # tokens[i] is the binary; everything after is args.
            for token in tokens[i + 1:]:
                if not token.startswith("/"):
                    continue
                if token.endswith("/"):
                    continue
                # Heuristic: config-y locations only. Excludes things like
                # ``find /etc -name foo`` where /etc is a search root.
                if (
                    token.startswith("/etc/")
                    and not token.endswith("/etc")
                    and "/etc/" not in token[5:]  # avoid /etc/something/etc/
                ):
                    if "." in os.path.basename(token) or "/" in token[5:]:
                        # something like /etc/logrotate.d/foo or /etc/foo.conf
                        results.append(token)
                elif token.startswith("/usr/local/etc/") or token.startswith("/opt/"):
                    if "." in os.path.basename(token) or "/" in token.rsplit("/", 1)[0]:
                        results.append(token)
        return results

    def _extract_executables(self, command: str) -> List[str]:
        """Extract the executable path(s) from a command string.

        Only returns the actual program being invoked, not every path-looking
        argument. ``find /etc -name foo`` should yield ``/usr/bin/find`` (or
        just ``find``), not ``["/usr/bin/find", "/etc"]``.

        Walks pipe / && / ; / | separators so a chained command
        ``/usr/bin/foo && /usr/bin/bar`` yields both binaries.
        """
        executables: List[str] = []
        # Split on shell command separators so each segment is one invocation.
        for segment in re.split(r"(?:\|\||&&|;|\||\bthen\b|\bdo\b)", command):
            seg = segment.strip()
            if not seg:
                continue
            # Drop leading env-var assignments: FOO=bar BAZ=qux /usr/bin/cmd ...
            tokens = seg.split()
            i = 0
            while i < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
                i += 1
            if i >= len(tokens):
                continue
            head = tokens[i]
            # Only emit absolute paths - relative names depend on $PATH and
            # would create ambiguous file nodes.
            if head.startswith("/") and not head.endswith("/"):
                executables.append(head)
        return executables

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

        # Systemd PATH overrides: ``Environment="PATH=..."``.
        # If the unit runs as root and uses unqualified binary names,
        # writability of any directory on this PATH is a privesc chain.
        path_overrides = []
        for env_match in re.finditer(
            r'^Environment\s*=\s*"?PATH=([^"\n]+)"?', content, re.MULTILINE,
        ):
            path_overrides.append(env_match.group(1).strip())
        if path_overrides:
            props["path_overrides"] = path_overrides

        # Wildcard injection. Flag any ExecStart that contains an unquoted
        # ``*`` in a position likely to be argv expansion.
        wildcard_findings = []
        for cmd in exec_cmds:
            if re.search(r"(?:^|\s)[^'\"]*?\*(?:\s|$)", cmd) and "find " not in cmd[:20]:
                # ``find ... *`` is sometimes legitimate. Heuristic only.
                wildcard_findings.append(cmd)
        if wildcard_findings:
            props["wildcard_commands"] = wildcard_findings

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

            # Config-arg INFLUENCES_EXEC edges, same as cron.
            for config in self._extract_config_arguments(cmd):
                cfg_id = f"file:{config}"
                cfg_node = Node(
                    id=cfg_id,
                    node_type=NodeType.FILE,
                    name=config,
                    properties={"path": config, "config_arg_of": cmd},
                )
                graph.add_node(cfg_node)
                graph.add_edge(Edge(
                    source_id=cfg_id,
                    target_id=unit_id,
                    edge_type=EdgeType.INFLUENCES_EXEC,
                    properties={
                        "mechanism": "ExecStart config argument",
                        "command": cmd,
                    },
                ))

    def _extract_executables_from_cmd(self, cmd: str) -> List[str]:
        # ExecStart= directives are a single command (with arguments), not a
        # shell pipeline, so we only need the head token. Reusing the cron
        # logic keeps behavior consistent.
        return self._extract_executables(cmd)

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
