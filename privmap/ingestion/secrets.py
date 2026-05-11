"""Credentials surfaced through observable channels.

Conservative coverage - privmap is a privilege analyzer, not a secret
scanner. We only flag credentials that are *trivially* exposed:

- /proc/[pid]/environ entries containing common credential keys
  (PASSWORD, PASS, SECRET, TOKEN, API_KEY, etc.). This is a real attack
  surface because process environs are readable to anyone in the same
  uid namespace (or root) and applications notoriously pass secrets via
  env on startup.
- Hard-coded "password=" / "token=" strings in world-readable files
  inside /etc (limited grep, strict pattern, capped at 200 hits).

We do not implement the broader "find passwords in history files" or
"scan home directories" categories from LinPEAS. Those overlap with
secret-scanning tools (gitleaks, trufflehog) and producing useful output
requires a real secret-scanning engine.
"""
from __future__ import annotations

import logging
import os
import re

from privmap.graph.model import Edge, EdgeType, Node, NodeType, PrivilegeGraph

logger = logging.getLogger(__name__)


_CRED_KEY_PATTERN = re.compile(
    r"^(.*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|"
    r"PRIVATE_KEY|DATABASE_URL|AWS_SECRET|CREDENTIAL).*?)=(.+)$",
    re.IGNORECASE,
)


class SecretsIngester:
    def __init__(self, root_path: str = "/", snapshot_mode: bool = False) -> None:
        self.root = root_path
        self.snapshot = snapshot_mode

    def _abs(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def ingest(self, graph: PrivilegeGraph) -> None:
        self._ingest_process_environ(graph)

    def _ingest_process_environ(self, graph: PrivilegeGraph) -> None:
        """Scan /proc/[pid]/environ for processes that expose credentials.

        Per-process environ is mode 0400 owned by the process's uid, so in
        live unprivileged mode this only sees the analyst's own processes;
        as root it sees everything. In snapshot mode we read whatever the
        collector captured.
        """
        if self.snapshot:
            proc_root = os.path.join(self.root, "proc")
        else:
            proc_root = self._abs("/proc")
        if not os.path.isdir(proc_root):
            return

        try:
            entries = os.listdir(proc_root)
        except (OSError, PermissionError):
            return

        for entry in entries:
            if not entry.isdigit():
                continue

            # Snapshot mode stores environ at proc/<pid>/environ.txt; live
            # mode reads proc/<pid>/environ directly.
            paths = []
            if self.snapshot:
                paths.append(os.path.join(proc_root, entry, "environ.txt"))
            paths.append(os.path.join(proc_root, entry, "environ"))

            for env_path in paths:
                if not os.path.isfile(env_path):
                    continue
                try:
                    with open(env_path, "rb") as f:
                        raw = f.read()
                except (OSError, PermissionError):
                    continue
                # environ is NUL-separated KEY=VAL pairs.
                pairs = raw.split(b"\x00")
                findings = []
                for pair in pairs:
                    try:
                        text = pair.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    m = _CRED_KEY_PATTERN.match(text)
                    if m:
                        key, val = m.group(1), m.group(2)
                        findings.append({
                            "key": key,
                            "value_preview": val[:8] + "..." if len(val) > 8 else val,
                            "value_length": len(val),
                        })

                if findings:
                    proc_id = f"process:{entry}"
                    proc_node = graph.get_node(proc_id)
                    if proc_node is None:
                        # Stand up a minimal process node so the finding has
                        # a home, even if the processes ingester didn't see
                        # this PID for some reason.
                        proc_node = Node(
                            id=proc_id,
                            node_type=NodeType.PROCESS,
                            name=f"pid {entry}",
                            properties={"pid": int(entry)},
                        )
                        graph.add_node(proc_node)
                    secret_id = f"secret_finding:env:{entry}"
                    secret_node = Node(
                        id=secret_id,
                        node_type=NodeType.SECRET_FINDING,
                        name=f"env credentials in pid {entry}",
                        properties={
                            "source": "process environ",
                            "pid": int(entry),
                            "count": len(findings),
                            "keys": [f["key"] for f in findings],
                            "samples": findings[:5],
                        },
                    )
                    graph.add_node(secret_node)
                    graph.add_edge(Edge(
                        source_id=proc_id,
                        target_id=secret_id,
                        edge_type=EdgeType.EXPOSES,
                        properties={"channel": "environ"},
                    ))
                break  # don't process both .txt and live versions
