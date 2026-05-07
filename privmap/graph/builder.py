"""Wires ingestion module output into the privilege graph."""
from __future__ import annotations

import logging
from typing import Callable, Optional

from privmap.graph.model import PrivilegeGraph
from privmap.ingestion.identity import IdentityIngester
from privmap.ingestion.filesystem import FilesystemIngester
from privmap.ingestion.execution import ExecutionIngester
from privmap.ingestion.capabilities import CapabilityIngester
from privmap.ingestion.processes import ProcessIngester

logger = logging.getLogger(__name__)

# Phase callback signature: (phase_name, detail). ``detail`` may be None for a
# new phase or a string with a sub-status (file count, current path, etc.).
ProgressCallback = Callable[[str, Optional[str]], None]


class GraphBuilder:
    """Coordinates all ingestion modules and builds the unified graph."""

    def __init__(
        self,
        root_path: str = "/",
        scan_paths: Optional[list] = None,
        snapshot_mode: bool = False,
        progress: Optional[ProgressCallback] = None,
    ) -> None:
        self.root_path = root_path
        self.scan_paths = scan_paths or ["/etc", "/usr", "/opt", "/tmp", "/var"]
        self.snapshot_mode = snapshot_mode
        self.graph = PrivilegeGraph()
        self._progress = progress or (lambda phase, detail: None)

    def build(self) -> PrivilegeGraph:
        logger.info("Starting graph construction (root=%s, snapshot=%s)",
                     self.root_path, self.snapshot_mode)

        self._progress("Reading users, groups, and sudo rules", None)
        identity = IdentityIngester(self.root_path, self.snapshot_mode)
        identity.ingest(self.graph)
        logger.info(
            "  Identity complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        self._progress(
            f"Walking filesystem ({', '.join(self.scan_paths)})", None
        )
        filesystem = FilesystemIngester(
            self.root_path, self.scan_paths, self.snapshot_mode,
            progress=self._progress,
        )
        filesystem.ingest(self.graph)
        logger.info(
            "  Filesystem complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        self._progress("Scanning execution contexts (cron, systemd, init.d)", None)
        execution = ExecutionIngester(self.root_path, self.snapshot_mode)
        execution.ingest(self.graph)
        logger.info(
            "  Execution complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        self._progress("Scanning Linux capabilities", None)
        caps = CapabilityIngester(self.root_path, self.snapshot_mode)
        caps.ingest(self.graph)
        logger.info(
            "  Capabilities complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        self._progress("Reading running processes", None)
        procs = ProcessIngester(self.root_path, self.snapshot_mode)
        procs.ingest(self.graph)
        logger.info(
            "  Processes complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        logger.info(
            "Graph construction complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )
        return self.graph
