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
            elif reason == "group-writable":
                group = edge.properties.get("group", "")
                risks.append(
                    f"Group-writable file {file_path} (group: {group}, mode: {mode})"
                )
                steps.append(
                    f"chmod g-w {file_path}"
                )
                steps.append(
                    f"chown root:root {file_path}"
                )
            elif reason == "owner-writable":
                risks.append(
                    f"Owner-writable file {file_path} owned by non-root (mode: {mode})"
                )
                steps.append(
                    f"chown root:root {file_path}"
                )
                steps.append(
                    f"chmod 644 {file_path}"
                )
            elif reason and reason.startswith("ACL"):
                risks.append(
                    f"ACL grants write access to {file_path}"
                )
                principal = edge.properties.get("acl_principal", "")
                if principal:
                    if "group" in reason:
                        steps.append(f"setfacl -x g:{principal} {file_path}")
                    else:
                        steps.append(f"setfacl -x u:{principal} {file_path}")
                else:
                    user_name = source_node.name if source_node else "user"
                    steps.append(f"setfacl -x u:{user_name} {file_path}")
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
                    f"{' (NOPASSWD)' if nopasswd else ''} - may permit shell escape"
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

        elif edge.edge_type == EdgeType.EXECUTED_AT_LOGIN:
            if source_node and target_node:
                script = source_node.properties.get("path", source_node.name)
                user = target_node.name
                risks.append(
                    f"{script} is sourced when {user} logs in"
                )
                steps.append(
                    f"chown root:root {script}; chmod 644 {script}"
                )

        elif edge.edge_type == EdgeType.INFLUENCES_EXEC:
            if source_node and target_node:
                mech = edge.properties.get("mechanism", "indirect")
                src_path = source_node.properties.get("path", source_node.name)
                tgt = target_node.name
                risks.append(
                    f"{src_path} controls how {tgt} runs ({mech})"
                )
                if "ld" in mech.lower() or "preload" in mech.lower():
                    steps.append(
                        f"chown root:root {src_path}; chmod 644 {src_path}"
                    )
                elif "config" in mech.lower():
                    steps.append(
                        f"chown root:root {src_path}; chmod 644 {src_path}"
                    )
                elif "pam" in mech.lower() or "PAM" in mech:
                    steps.append(
                        f"Review {src_path} for pam_rootok/pam_permit/nullok directives"
                    )
                else:
                    steps.append(
                        f"Audit ownership and permissions on {src_path}"
                    )

        elif edge.edge_type == EdgeType.TRUSTS:
            if source_node:
                src = source_node.properties.get("path", source_node.name)
                risks.append(
                    f"Host-trust file {src} grants password-less access"
                )
                steps.append(
                    f"Remove or restrict {src}; r-command trust is generally deprecated"
                )

        elif edge.edge_type == EdgeType.EXPOSES:
            if target_node:
                keys = target_node.properties.get("keys", [])
                pid = target_node.properties.get("pid", "?")
                risks.append(
                    f"Process pid {pid} exposes credentials in its environment "
                    f"({', '.join(keys[:3])}{'...' if len(keys) > 3 else ''})"
                )
                steps.append(
                    "Read credentials from files (mode 0600) instead of environment variables"
                )

        elif edge.edge_type == EdgeType.MEMBER_OF:
            if target_node:
                group = target_node.name
                if group in ("sudo", "wheel", "admin"):
                    risks.append(
                        f"Membership in admin group '{group}' grants full root via sudo (intended for admin accounts)"
                    )
                    if source_node:
                        steps.append(
                            f"If {source_node.name} is not an admin account, remove from {group} group"
                        )
                elif group in ("docker", "lxd", "disk", "adm", "shadow"):
                    risks.append(
                        f"Membership in privileged group '{group}'"
                    )
                    if source_node:
                        steps.append(
                            f"Remove {source_node.name} from group {group} unless required"
                        )

    path.risk_description = "; ".join(risks) if risks else "Privilege escalation path detected"
    path.remediation = "; ".join(steps) if steps else "Review and restrict permissions along this path"
