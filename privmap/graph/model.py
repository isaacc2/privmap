"""Core graph data model - nodes, edges, and the privilege graph."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class NodeType(enum.Enum):
    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    FILE = "file"
    DIRECTORY = "directory"
    SOCKET = "socket"
    DEVICE = "device"
    PROCESS = "process"
    CRON_JOB = "cron_job"
    SYSTEMD_UNIT = "systemd_unit"
    INITD_SCRIPT = "initd_script"
    SUDO_RULE = "sudo_rule"
    SUID_BINARY = "suid_binary"
    CAPABILITY = "capability"

    # v2.0 additions
    PROFILE_SCRIPT = "profile_script"     # /etc/profile.d/*, /etc/bash.bashrc, /etc/profile
    LDPRELOAD_FILE = "ldpreload_file"     # /etc/ld.so.preload, /etc/ld.so.conf, conf.d/*
    POLKIT_RULE = "polkit_rule"           # /etc/polkit-1/rules.d/*, /usr/share/polkit-1/rules.d/*
    PAM_FILE = "pam_file"                 # /etc/pam.d/*
    SSH_KEY = "ssh_key"                   # authorized_keys, host keys, private keys
    NFS_EXPORT = "nfs_export"             # entries from /etc/exports
    CONTAINER_MARKER = "container_marker" # signals execution context (docker, lxc, k8s)
    NETWORK_LISTENER = "network_listener" # bound ports
    PATH_DIR = "path_dir"                 # directory on $PATH
    LOGIN_HOOK = "login_hook"             # /etc/skel/*, .bashrc-class files
    DOAS_RULE = "doas_rule"               # /etc/doas.conf entries
    SECRET_FINDING = "secret_finding"     # credentials surfaced (env vars, config strings)
    DBUS_POLICY = "dbus_policy"           # /etc/dbus-1/system.d/*.conf rules
    INETD_SERVICE = "inetd_service"       # /etc/inetd.conf, /etc/xinetd.d/*
    APPARMOR_PROFILE = "apparmor_profile" # /etc/apparmor.d/*
    MOUNT = "mount"                       # entries from /proc/mounts (bind mounts, etc.)


class EdgeType(enum.Enum):
    MEMBER_OF = "MEMBER_OF"
    OWNS = "OWNS"
    CAN_WRITE = "CAN_WRITE"
    CAN_READ = "CAN_READ"
    CAN_EXEC = "CAN_EXEC"
    EXECUTES = "EXECUTES"
    RUNS_AS = "RUNS_AS"
    GRANTS = "GRANTS"
    WRITABLE_BY = "WRITABLE_BY"
    HAS_CAPABILITY = "HAS_CAPABILITY"
    SUID_EXEC = "SUID_EXEC"

    # v2.0 additions
    EXECUTED_AT_LOGIN = "EXECUTED_AT_LOGIN"   # script -> user (the user whose login triggers it)
    INFLUENCES_EXEC = "INFLUENCES_EXEC"       # config/preload -> binary/process whose behavior it changes
    LISTENS_ON = "LISTENS_ON"                 # process -> network_listener
    TRUSTS = "TRUSTS"                          # host trust (hosts.equiv, .rhosts)
    EXPOSES = "EXPOSES"                       # process -> secret_finding (cred exposure)


class Severity(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


@dataclass
class Node:
    id: str
    node_type: NodeType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Node):
            return NotImplemented
        return self.id == other.id

    @property
    def display_name(self) -> str:
        return f"{self.node_type.value}:{self.name}"


@dataclass
class Edge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.source_id}--{self.edge_type.value}-->{self.target_id}"


@dataclass
class EscalationPath:
    """A concrete privilege escalation path through the graph."""
    nodes: List[Node]
    edges: List[Edge]
    source: Node
    sink: Node
    severity: Optional[Severity] = None
    risk_description: str = ""
    remediation: str = ""
    exploitability_score: float = 0.0
    impact_score: float = 0.0

    @property
    def hop_count(self) -> int:
        return len(self.edges)

    @property
    def path_key(self) -> str:
        return " -> ".join(n.display_name for n in self.nodes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.display_name,
            "sink": self.sink.display_name,
            "hops": self.hop_count,
            "severity": self.severity.value if self.severity else None,
            "risk": self.risk_description,
            "remediation": self.remediation,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "chain": [
                {
                    "node": n.display_name,
                    "node_type": n.node_type.value,
                    "properties": n.properties,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "from": e.source_id,
                    "to": e.target_id,
                    "type": e.edge_type.value,
                    "properties": e.properties,
                }
                for e in self.edges
            ],
        }


class PrivilegeGraph:
    """Directed property graph for privilege relationships."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._adjacency: Dict[str, List[Edge]] = {}
        self._reverse_adjacency: Dict[str, List[Edge]] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._adjacency.values())

    def add_node(self, node: Node) -> Node:
        if node.id in self._nodes:
            existing = self._nodes[node.id]
            existing.properties.update(node.properties)
            return existing
        self._nodes[node.id] = node
        self._adjacency.setdefault(node.id, [])
        self._reverse_adjacency.setdefault(node.id, [])
        return node

    def add_edge(self, edge: Edge) -> Edge:
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            raise ValueError(
                f"Both nodes must exist before adding edge: "
                f"{edge.source_id} -> {edge.target_id}"
            )
        for existing in self._adjacency.get(edge.source_id, []):
            if (
                existing.target_id == edge.target_id
                and existing.edge_type == edge.edge_type
            ):
                existing.properties.update(edge.properties)
                return existing
        self._adjacency[edge.source_id].append(edge)
        self._reverse_adjacency.setdefault(edge.target_id, [])
        self._reverse_adjacency[edge.target_id].append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def get_nodes(self) -> List[Node]:
        return list(self._nodes.values())

    def get_edges_from(self, node_id: str) -> List[Edge]:
        return self._adjacency.get(node_id, [])

    def get_edges_to(self, node_id: str) -> List[Edge]:
        return self._reverse_adjacency.get(node_id, [])

    def get_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def get_neighbors(self, node_id: str) -> List[Tuple[Node, Edge]]:
        result = []
        for edge in self._adjacency.get(node_id, []):
            target = self._nodes.get(edge.target_id)
            if target:
                result.append((target, edge))
        return result

    def has_inbound_edge(self, node_id: str, edge_type: EdgeType) -> bool:
        return any(
            e.edge_type == edge_type
            for e in self._reverse_adjacency.get(node_id, [])
        )

    def get_inbound_edges(self, node_id: str, edge_type: EdgeType) -> List[Edge]:
        return [
            e for e in self._reverse_adjacency.get(node_id, [])
            if e.edge_type == edge_type
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.value,
                    "name": n.name,
                    "properties": n.properties,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.edge_type.value,
                    "properties": e.properties,
                }
                for edges in self._adjacency.values()
                for e in edges
            ],
        }

    def to_networkx(self):
        """Export to networkx DiGraph for external analysis."""
        import networkx as nx

        G = nx.DiGraph()
        for node in self._nodes.values():
            G.add_node(
                node.id,
                node_type=node.node_type.value,
                name=node.name,
                **node.properties,
            )
        for edges in self._adjacency.values():
            for edge in edges:
                G.add_edge(
                    edge.source_id,
                    edge.target_id,
                    edge_type=edge.edge_type.value,
                    **edge.properties,
                )
        return G
