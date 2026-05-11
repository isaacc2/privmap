"""Legacy network super-server enumeration.

Covers:

- /etc/inetd.conf - line-per-service config for inetd. Each service
  has a name, socket type, protocol, wait/nowait, user, and command.
- /etc/xinetd.conf and /etc/xinetd.d/<service> - xinetd's per-service
  configuration. Each defines a service running as a specific user
  with a specific server binary.

A service that runs as root and accepts arbitrary input is similar in
shape to a systemd unit running as root: the binary it execs is part
of the privilege chain. We emit:

- INETD_SERVICE node per service
- RUNS_AS edge to the service's user
- EXECUTES edge to the server binary if it's an absolute path
"""
from __future__ import annotations

import logging
import os
import re

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


class InetdIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_inetd_conf(graph)
        self._ingest_xinetd(graph)

    # ----- inetd.conf -----
    def _ingest_inetd_conf(self, graph: PrivilegeGraph) -> None:
        conf = self._abs("/etc/inetd.conf")
        if not os.path.isfile(conf):
            return
        try:
            with open(conf, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        # Format: name type proto {wait|nowait}[.max] user[:group] server [args]
        for lineno, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            name, sock_type, proto, wait, user_spec, server_and_args = parts
            user = user_spec.split(":", 1)[0]
            tokens = server_and_args.split(None, 1)
            server = tokens[0]
            args = tokens[1] if len(tokens) > 1 else ""

            node_id = f"inetd_service:{name}"
            node = Node(
                id=node_id,
                node_type=NodeType.INETD_SERVICE,
                name=name,
                properties={
                    "source_file": "/etc/inetd.conf",
                    "source_line": lineno,
                    "socket_type": sock_type,
                    "protocol": proto,
                    "wait": wait,
                    "run_as": user,
                    "server": server,
                    "args": args,
                    "framework": "inetd",
                },
            )
            graph.add_node(node)

            user_id = f"user:{user}"
            if graph.get_node(user_id):
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id=user_id,
                    edge_type=EdgeType.RUNS_AS,
                    properties={"service": name},
                ))

            if server.startswith("/"):
                file_id = f"file:{server}"
                file_node = Node(
                    id=file_id,
                    node_type=NodeType.FILE,
                    name=server,
                    properties={"path": server},
                )
                graph.add_node(file_node)
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id=file_id,
                    edge_type=EdgeType.EXECUTES,
                    properties={"args": args},
                ))

    # ----- xinetd -----
    def _ingest_xinetd(self, graph: PrivilegeGraph) -> None:
        # Per-service files
        xinetd_d = self._abs("/etc/xinetd.d")
        if os.path.isdir(xinetd_d):
            try:
                entries = os.listdir(xinetd_d)
            except (OSError, PermissionError):
                entries = []
            for name in entries:
                real = os.path.join(xinetd_d, name)
                if not os.path.isfile(real):
                    continue
                self._parse_xinetd_service(graph, real, name)

        # Single-file xinetd.conf can also embed service blocks.
        single = self._abs("/etc/xinetd.conf")
        if os.path.isfile(single):
            self._parse_xinetd_service(graph, single, source_label="xinetd.conf")

    def _parse_xinetd_service(
        self, graph: PrivilegeGraph, real_path: str, source_label: str,
    ) -> None:
        try:
            with open(real_path, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return

        # service NAME { key = value ... }
        for m in re.finditer(
            r"service\s+(\S+)\s*\{([^}]*)\}", content, re.DOTALL,
        ):
            name = m.group(1)
            block = m.group(2)
            props_dict = {}
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    props_dict[key.strip()] = value.strip()

            disabled = props_dict.get("disable", "no").lower() in ("yes", "true", "1")
            if disabled:
                continue

            user = props_dict.get("user", "root")
            server = props_dict.get("server", "")
            args = props_dict.get("server_args", "")

            node_id = f"inetd_service:{name}"
            node = Node(
                id=node_id,
                node_type=NodeType.INETD_SERVICE,
                name=name,
                properties={
                    "source_file": real_path,
                    "framework": "xinetd",
                    "run_as": user,
                    "server": server,
                    "args": args,
                    "raw_props": props_dict,
                },
            )
            graph.add_node(node)

            user_id = f"user:{user}"
            if graph.get_node(user_id):
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id=user_id,
                    edge_type=EdgeType.RUNS_AS,
                    properties={"service": name},
                ))

            if server.startswith("/"):
                file_id = f"file:{server}"
                file_node = Node(
                    id=file_id,
                    node_type=NodeType.FILE,
                    name=server,
                    properties={"path": server},
                )
                graph.add_node(file_node)
                graph.add_edge(Edge(
                    source_id=node_id,
                    target_id=file_id,
                    edge_type=EdgeType.EXECUTES,
                    properties={"args": args},
                ))
