"""Generate per-path remediation suggestions."""
from __future__ import annotations

import os
from typing import List

from privmap.graph.model import EdgeType, EscalationPath, NodeType


def generate_remediation(path: EscalationPath) -> None:
    """Generate a risk description and remediation for the path. Mutates in place."""
    steps: List[str] = []
    risks: List[str] = []

    for i, edge in enumerate(path.edges):
        source_node = None
        target_node = None
        for n in path.nodes:
            if n.id == edge.source_id:
                source_node = n
            if n.id == edge.target_id:
                target_node = n

        if edge.edge_type == EdgeType.CAN_WRITE and target_node:
            file_path = target_node.properties.get("path", target_node.name)
            mode = target_node.properties.get("mode", "")
            reason = edge.properties.get("reason", "")

            if reason == "world-writable":
                risks.append(
                    f"World-writable file {file_path} (mode: {mode})"
                )
                steps.append(
                    f"chmod o-w {file_path}"
                )
                owner = target_node.properties.get("owner", "root")
                steps.append(
                    f"chown {owner}:root {file_path}"
                )
            elif reason == "ACL":
                risks.append(
                    f"ACL grants write access to {file_path}"
                )
                user_name = source_node.name if source_node else "user"
                steps.append(
                    f"setfacl -x u:{user_name} {file_path}"
                )
            else:
                risks.append(
                    f"Writable file {file_path} (mode: {mode})"
                )
                steps.append(
                    f"chmod 644 {file_path}; chown root:root {file_path}"
                )

        elif edge.edge_type == EdgeType.GRANTS:
            cmd = edge.properties.get("command", "")
            nopasswd = edge.properties.get("nopasswd", False)

            if cmd == "ALL":
                risks.append(
                    f"Unrestricted sudo access"
                    f"{' (NOPASSWD)' if nopasswd else ''}"
                )
                if source_node:
                    steps.append(
                        f"Restrict sudo rules for {source_node.name} to specific commands"
                    )
            elif target_node and target_node.node_type == NodeType.SUDO_RULE:
                binary = target_node.properties.get("binary", cmd)
                binary_name = os.path.basename(binary) if "/" in binary else binary
                risks.append(
                    f"Sudo rule allows {binary_name}"
                    f"{' (NOPASSWD)' if nopasswd else ''} — may permit shell escape"
                )
                # Suggest sudoedit for editors
                if binary_name in ("vim", "vi", "nano", "emacs"):
                    steps.append(
                        f"Replace sudo {binary_name} rule with sudoedit"
                    )
                else:
                    steps.append(
                        f"Remove or restrict sudo rule for {binary_name}"
                    )

        elif edge.edge_type == EdgeType.SUID_EXEC:
            if target_node:
                binary = target_node.properties.get("binary", target_node.name)
                path_str = target_node.properties.get("path", target_node.name)
                risks.append(
                    f"SUID binary {binary} ({path_str}) allows privilege escalation"
                )
                steps.append(
                    f"chmod u-s {path_str}"
                )
                steps.append(
                    f"Consider using capabilities instead: setcap cap_needed+ep {path_str}"
                )

        elif edge.edge_type == EdgeType.HAS_CAPABILITY:
            if target_node:
                cap = target_node.name
                binary = target_node.properties.get("binary", "")
                risks.append(
                    f"Binary {binary} has dangerous capability {cap}"
                )
                steps.append(
                    f"setcap -r {binary}"
                )
                steps.append(
                    f"Review if {cap} is strictly necessary for {os.path.basename(binary)}"
                )

        elif edge.edge_type == EdgeType.EXECUTES:
            if source_node and target_node:
                if source_node.node_type == NodeType.CRON_JOB:
                    run_as = source_node.properties.get("run_as", "root")
                    script = target_node.properties.get("path", target_node.name)
                    risks.append(
                        f"Cron job runs {script} as {run_as}"
                    )
                    steps.append(
                        f"Ensure {script} is owned by root and not writable by others"
                    )
                elif source_node.node_type == NodeType.SYSTEMD_UNIT:
                    unit = source_node.name
                    script = target_node.properties.get("path", target_node.name)
                    risks.append(
                        f"Systemd unit {unit} executes {script}"
                    )
                    steps.append(
                        f"Ensure {script} is owned by root with mode 755 or stricter"
                    )

        elif edge.edge_type == EdgeType.MEMBER_OF:
            if target_node:
                group = target_node.name
                if group in ("docker", "lxd", "disk", "adm", "shadow"):
                    risks.append(
                        f"Membership in privileged group '{group}'"
                    )
                    if source_node:
                        steps.append(
                            f"Remove {source_node.name} from group {group} unless required"
                        )

    path.risk_description = "; ".join(risks) if risks else "Privilege escalation path detected"
    path.remediation = "; ".join(steps) if steps else "Review and restrict permissions along this path"
