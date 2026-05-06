"""Score escalation paths on exploitability and impact."""
from __future__ import annotations

import os

from privmap.graph.model import EdgeType, EscalationPath, NodeType, Severity

# Sudo rules with arguments locked down are harder to exploit than unrestricted
# ones. We reduce exploitability when the command includes arguments, since the
# user can't freely choose what to run. This isn't foolproof (some argument
# patterns are still exploitable) but significantly reduces false-positive
# CRITICAL ratings on rules like: user ALL=(root) /usr/bin/systemctl restart nginx
_RESTRICTED_SUDO_PENALTY = 2.0


def score_path(path: EscalationPath) -> None:
    """Score a path and assign severity. Mutates the path in place."""
    exploitability = _compute_exploitability(path)
    impact = _compute_impact(path)

    path.exploitability_score = exploitability
    path.impact_score = impact

    combined = (exploitability * 0.6) + (impact * 0.4)

    if combined >= 8.0:
        path.severity = Severity.CRITICAL
    elif combined >= 6.0:
        path.severity = Severity.HIGH
    elif combined >= 4.0:
        path.severity = Severity.MEDIUM
    elif combined >= 2.0:
        path.severity = Severity.LOW
    else:
        path.severity = Severity.INFO


def _compute_exploitability(path: EscalationPath) -> float:
    """Score 0-10 based on how easy the path is to exploit."""
    score = 10.0

    # Penalize long chains
    hops = path.hop_count
    if hops > 5:
        score -= 5.0
    elif hops > 3:
        score -= 2.5
    elif hops > 1:
        score -= 0.5

    # Check for timing dependencies (cron = must wait)
    has_cron_dependency = False
    has_sudo_nopasswd = False
    has_suid = False
    has_restricted_sudo = False

    for edge in path.edges:
        if edge.edge_type == EdgeType.EXECUTES:
            # Check if source is a cron job
            src_node = None
            for n in path.nodes:
                if n.id == edge.source_id:
                    src_node = n
                    break
            if src_node and src_node.node_type == NodeType.CRON_JOB:
                has_cron_dependency = True

        if edge.edge_type == EdgeType.GRANTS:
            if edge.properties.get("nopasswd"):
                has_sudo_nopasswd = True

            # Check for argument-restricted sudo rules. A command like
            # "/usr/bin/systemctl restart nginx" has args after the binary,
            # which limits what the user can actually do.
            cmd = edge.properties.get("command", "")
            if cmd and cmd != "ALL":
                parts = cmd.strip().split()
                if len(parts) > 1:
                    has_restricted_sudo = True

        if edge.edge_type == EdgeType.SUID_EXEC:
            has_suid = True

    if has_cron_dependency:
        score -= 2.0  # Must wait for cron trigger

    if has_sudo_nopasswd:
        score += 1.0  # No password needed is easier

    if has_suid:
        score += 0.5  # Direct execution, no waiting

    if has_restricted_sudo:
        score -= _RESTRICTED_SUDO_PENALTY

    # Direct sudo ALL -> root is trivial
    if hops <= 2 and any(
        e.edge_type == EdgeType.GRANTS and
        e.properties.get("command") == "ALL"
        for e in path.edges
    ):
        score = 10.0

    return max(0.0, min(10.0, score))


def _compute_impact(path: EscalationPath) -> float:
    """Score 0-10 based on what the sink grants."""
    sink = path.sink

    # Root access = maximum impact
    if sink.node_type == NodeType.USER and sink.properties.get("uid") == 0:
        return 10.0

    # Sudo ALL = equivalent to root
    if sink.node_type == NodeType.SUDO_RULE:
        cmd = sink.properties.get("command", "")
        if cmd == "ALL":
            return 10.0
        # Argument-restricted sudo command — partial access
        parts = cmd.strip().split()
        if len(parts) > 1:
            return 5.0
        return 7.0  # Unrestricted single command, possible shell escape

    # Dangerous capability
    if sink.node_type == NodeType.CAPABILITY:
        cap = sink.name.lower()
        if cap in ("cap_sys_admin", "cap_dac_override", "cap_setuid"):
            return 9.0
        if cap in ("cap_sys_ptrace", "cap_sys_module", "cap_sys_rawio"):
            return 8.0
        return 6.0

    # Lateral movement to another user
    if sink.node_type == NodeType.USER:
        return 5.0

    return 3.0