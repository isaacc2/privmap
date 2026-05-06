"""Wires ingestion module output into the privilege graph."""
from __future__ import annotations

import logging
from typing import Optional

from privmap.graph.model import PrivilegeGraph
from privmap.ingestion.identity import IdentityIngester
from privmap.ingestion.filesystem import FilesystemIngester
from privmap.ingestion.execution import ExecutionIngester
from privmap.ingestion.capabilities import CapabilityIngester
from privmap.ingestion.processes import ProcessIngester

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Coordinates all ingestion modules and builds the unified graph."""

    def __init__(
        self,
        root_path: str = "/",
        scan_paths: Optional[list] = None,
        snapshot_mode: bool = False,
    ) -> None:
        self.root_path = root_path
        self.scan_paths = scan_paths or ["/etc", "/usr", "/opt", "/tmp", "/var"]
        self.snapshot_mode = snapshot_mode
        self.graph = PrivilegeGraph()

    def build(self) -> PrivilegeGraph:
        logger.info("Starting graph construction (root=%s, snapshot=%s)",
                     self.root_path, self.snapshot_mode)

        # Phase 1: Identity (users, groups, sudo)
        logger.info("Phase 1: Ingesting identity data...")
        identity = IdentityIngester(self.root_path, self.snapshot_mode)
        identity.ingest(self.graph)
        logger.info(
            "  Identity complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        # Phase 2: Filesystem permissions
        logger.info("Phase 2: Ingesting filesystem permissions...")
        filesystem = FilesystemIngester(
            self.root_path, self.scan_paths, self.snapshot_mode
        )
        filesystem.ingest(self.graph)
        logger.info(
            "  Filesystem complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        # Phase 3: Execution contexts (cron, systemd, init.d)
        logger.info("Phase 3: Ingesting execution contexts...")
        execution = ExecutionIngester(self.root_path, self.snapshot_mode)
        execution.ingest(self.graph)
        logger.info(
            "  Execution complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        # Phase 4: Capabilities
        logger.info("Phase 4: Ingesting capabilities...")
        caps = CapabilityIngester(self.root_path, self.snapshot_mode)
        caps.ingest(self.graph)
        logger.info(
            "  Capabilities complete: %d nodes, %d edges",
            self.graph.node_count, self.graph.edge_count,
        )

        # Phase 5: Running processes (skip in snapshot mode unless /proc captured)
        logger.info("Phase 5: Ingesting process data...")
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
