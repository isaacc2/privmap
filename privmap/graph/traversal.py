"""DFS reachability analysis with edge-semantic filtering."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

from privmap.graph.model import (
    Edge, EdgeType, EscalationPath, Node, NodeType, PrivilegeGraph,
)

logger = logging.getLogger(__name__)

# Sinks: node types + properties that represent privilege escalation targets
DANGEROUS_CAPABILITIES = {
    "cap_sys_admin", "cap_dac_override", "cap_setuid", "cap_setgid",
    "cap_sys_ptrace", "cap_sys_module", "cap_dac_read_search",
    "cap_fowner", "cap_chown", "cap_sys_rawio",
}

# SUID binaries known to allow shell escapes (GTFOBins-informed)
GTFOBINS_SUID = {
    "bash", "sh", "dash", "zsh", "csh", "ksh", "fish",
    "python", "python2", "python3", "perl", "ruby", "lua",
    "vim", "vi", "nano", "emacs", "less", "more", "man",
    "find", "nmap", "awk", "gawk", "sed",
    "env", "nice", "ionice", "strace", "ltrace",
    "gdb", "docker", "pkexec", "cp", "mv",
    "tar", "zip", "unzip", "rsync",
    "ssh", "scp", "socat", "nc", "ncat",
    "node", "php", "tclsh", "wish",
    "doas", "su",
}

# Sudo commands known to allow shell escapes
SUDO_SHELL_ESCAPE = {
    "vim", "vi", "nano", "emacs", "less", "more", "man",
    "find", "awk", "gawk", "nmap", "python", "python3",
    "python2", "perl", "ruby", "lua", "env", "ftp", "gdb",
    "git", "pico", "rvim", "scp", "sftp", "socat", "ssh",
    "tar", "zip", "bash", "sh", "dash", "zsh", "csh",
    "docker", "journalctl", "systemctl", "mount",
    "strace", "ltrace", "tclsh", "node", "php",
    "apt-get", "apt", "yum", "dnf", "pip", "pip3",
    "cpan", "gem",
}

# Capability binaries that are part of standard system packages and use caps
# internally without exposing them to the caller. These are not exploitable
# through normal execution. Matches the allowlist in ingestion/capabilities.py;
# duplicated here as a safety net in case a snapshot or older graph still
# contains edges for these binaries.
KNOWN_SAFE_CAP_BINARIES = {
    "ping", "ping4", "ping6",
    "mtr", "mtr-packet",
    "traceroute", "traceroute6",
    "arping", "clockdiff",
    "snap-confine",
    "systemd-detect-virt",
    "gnome-keyring-daemon",
    "iio-sensor-proxy",
    "chronyd", "ntpd",
}


def is_sink_node(node: Node) -> bool:
    """Determine if a node is a high-value escalation target."""
    if node.node_type == NodeType.USER:
        if node.properties.get("uid") == 0:
            return True
    if node.node_type == NodeType.SUDO_RULE:
        cmd = node.properties.get("command", "")
        if cmd == "ALL":
            return True
    if node.node_type == NodeType.CAPABILITY:
        cap_name = node.name.lower()
        if cap_name in DANGEROUS_CAPABILITIES:
            # Check if this cap is on a known-safe binary — if so, not a real sink
            binary_name = node.properties.get("binary_name", "")
            if binary_name in KNOWN_SAFE_CAP_BINARIES:
                return False
            return True
    return False


def is_source_principal(node: Node) -> bool:
    """Determine if a node is a non-privileged starting point."""
    if node.node_type != NodeType.USER:
        return False
    uid = node.properties.get("uid", -1)
    if uid == 0:
        return False
    shell = node.properties.get("shell", "")
    if shell.endswith("nologin") or shell.endswith("/false"):
        return False
    return True


def _is_known_safe_cap_path(path_nodes: List[Node]) -> bool:
    """Check if a path traverses a known-safe capability binary.

    Returns True if the path contains a file node for a binary in the
    known-safe list followed by a capability node — indicating the path
    relies on caps that aren't actually exploitable.
    """
    for i, node in enumerate(path_nodes):
        if node.node_type == NodeType.FILE:
            binary_name = node.properties.get("binary_name", "")
            if not binary_name:
                binary_name = node.name.rsplit("/", 1)[-1] if "/" in node.name else node.name
            if binary_name in KNOWN_SAFE_CAP_BINARIES:
                # Check if the next node in the chain is a capability
                if i + 1 < len(path_nodes) and path_nodes[i + 1].node_type == NodeType.CAPABILITY:
                    return True
    return False


def _validate_write_execute_chain(
    graph: PrivilegeGraph, path_nodes: List[Node], path_edges: List[Edge]
) -> bool:
    """Validate that CAN_WRITE edges lead to resources that are actually executed."""
    for i, edge in enumerate(path_edges):
        if edge.edge_type == EdgeType.CAN_WRITE:
            target_id = edge.target_id
            # Check if this writable resource is executed by something privileged
            inbound_exec = graph.get_inbound_edges(target_id, EdgeType.EXECUTES)
            outbound_from_target = graph.get_edges_from(target_id)
            has_exec_context = (
                len(inbound_exec) > 0
                or any(e.edge_type == EdgeType.EXECUTES for e in outbound_from_target)
                or any(e.edge_type == EdgeType.RUNS_AS for e in outbound_from_target)
            )
            # Also valid if next edge in path is EXECUTES or RUNS_AS
            if i + 1 < len(path_edges):
                next_edge = path_edges[i + 1]
                if next_edge.edge_type in (EdgeType.EXECUTES, EdgeType.RUNS_AS):
                    has_exec_context = True
            if not has_exec_context:
                return False
    return True


def find_escalation_paths(
    graph: PrivilegeGraph,
    source_users: Optional[List[str]] = None,
    max_depth: int = 10,
) -> List[EscalationPath]:
    """Find all privilege escalation paths from source principals to sinks."""
    paths: List[EscalationPath] = []

    # Determine source nodes
    if source_users:
        sources = []
        for uname in source_users:
            node = graph.get_node(f"user:{uname}")
            if node:
                sources.append(node)
            else:
                logger.warning("User '%s' not found in graph", uname)
    else:
        sources = [n for n in graph.get_nodes() if is_source_principal(n)]

    sinks = {n.id for n in graph.get_nodes() if is_sink_node(n)}
    logger.info("Traversal: %d sources, %d sinks", len(sources), len(sinks))

    for source in sources:
        source_paths = _dfs_find_paths(graph, source, sinks, max_depth)
        paths.extend(source_paths)

    # Deduplicate by path_key
    seen: Set[str] = set()
    unique: List[EscalationPath] = []
    for p in paths:
        if p.path_key not in seen:
            seen.add(p.path_key)
            unique.append(p)

    logger.info("Found %d unique escalation paths", len(unique))
    return unique


def _dfs_find_paths(
    graph: PrivilegeGraph,
    source: Node,
    sinks: Set[str],
    max_depth: int,
) -> List[EscalationPath]:
    """Depth-first search from source to any sink node."""
    results: List[EscalationPath] = []
    visited: Set[str] = set()

    def dfs(
        current: Node,
        path_nodes: List[Node],
        path_edges: List[Edge],
        depth: int,
    ) -> None:
        if depth > max_depth:
            return

        if current.id in sinks and len(path_nodes) > 1:
            # Validate the path is semantically sound
            if not _validate_write_execute_chain(graph, path_nodes, path_edges):
                return
            # Filter out paths through known-safe capability binaries
            if _is_known_safe_cap_path(path_nodes):
                return

            results.append(
                EscalationPath(
                    nodes=list(path_nodes),
                    edges=list(path_edges),
                    source=path_nodes[0],
                    sink=current,
                )
            )
            return

        visited.add(current.id)

        for neighbor, edge in graph.get_neighbors(current.id):
            if neighbor.id in visited:
                continue

            # Special handling: GRANTS edges originating from sudo rule nodes.
            # Only filter when the source is actually a SUDO_RULE — GRANTS edges
            # from users (user -> sudo_rule) and capabilities should pass through.
            if edge.edge_type == EdgeType.GRANTS and current.node_type == NodeType.SUDO_RULE:
                cmd = current.properties.get("command", "")
                binary = cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd
                if cmd != "ALL" and binary.lower() not in SUDO_SHELL_ESCAPE:
                    continue

            path_nodes.append(neighbor)
            path_edges.append(edge)
            dfs(neighbor, path_nodes, path_edges, depth + 1)
            path_nodes.pop()
            path_edges.pop()

        visited.discard(current.id)

    dfs(source, [source], [], 0)
    return results