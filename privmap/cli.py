"""privmap CLI — entry point and argument parsing."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tarfile
import tempfile
from typing import List, Optional

from privmap import __version__
from privmap.graph.builder import GraphBuilder
from privmap.graph.model import Severity
from privmap.analysis.paths import analyze_paths
from privmap.output.cli_output import render_cli
from privmap.output.json_export import export_json
from privmap.output.markdown_export import export_markdown


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="privmap",
        description="Linux privilege graph engine — trace escalation paths.",
    )
    parser.add_argument(
        "--version", action="version", version=f"privmap {__version__}"
    )
    parser.add_argument(
        "--snapshot",
        metavar="PATH",
        help="Path to a snapshot archive (.tar.gz) for offline analysis.",
    )
    parser.add_argument(
        "--user", "-u",
        action="append",
        dest="users",
        metavar="USERNAME",
        help="Analyse specific user(s). Can be repeated.",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["cli", "json", "markdown"],
        default="cli",
        help="Output format (default: cli).",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="Minimum severity to display (default: low).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum traversal depth (default: 10).",
    )
    parser.add_argument(
        "--scan-paths",
        metavar="PATHS",
        help="Comma-separated list of paths to scan (default: /etc,/usr,/opt,/tmp,/var).",
    )
    parser.add_argument(
        "--export-graph",
        metavar="FILE",
        help="Export full graph as JSON to the specified file.",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Return non-zero exit code if paths at or above min-severity are found.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug).",
    )

    return parser.parse_args(argv)


def setup_logging(verbosity: int) -> None:
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    logger = logging.getLogger("privmap")

    # Determine root path
    root_path = "/"
    snapshot_mode = False
    temp_dir = None

    if args.snapshot:
        snapshot_mode = True
        if not os.path.isfile(args.snapshot):
            print(f"Error: Snapshot file not found: {args.snapshot}", file=sys.stderr)
            return 1

        # Extract snapshot to temp directory
        temp_dir = tempfile.mkdtemp(prefix="privmap_snapshot_")
        logger.info("Extracting snapshot to %s", temp_dir)
        try:
            with tarfile.open(args.snapshot, "r:gz") as tar:
                tar.extractall(temp_dir)
        except (tarfile.TarError, OSError) as e:
            print(f"Error extracting snapshot: {e}", file=sys.stderr)
            return 1

        # Find the snapshot directory inside the extracted archive
        entries = os.listdir(temp_dir)
        if len(entries) == 1 and os.path.isdir(os.path.join(temp_dir, entries[0])):
            root_path = os.path.join(temp_dir, entries[0])
        else:
            root_path = temp_dir

    # Parse scan paths
    scan_paths = None
    if args.scan_paths:
        scan_paths = [p.strip() for p in args.scan_paths.split(",")]

    # Severity filter
    min_severity = Severity(args.min_severity.upper())

    try:
        # Build graph
        builder = GraphBuilder(
            root_path=root_path,
            scan_paths=scan_paths,
            snapshot_mode=snapshot_mode,
        )
        graph = builder.build()

        # Analyze paths
        paths = analyze_paths(
            graph,
            source_users=args.users,
            max_depth=args.max_depth,
            min_severity=min_severity,
        )

        # Export full graph if requested
        if args.export_graph:
            graph_json = json.dumps(graph.to_dict(), indent=2, default=str)
            with open(args.export_graph, "w") as f:
                f.write(graph_json)
            logger.info("Graph exported to %s", args.export_graph)

        # Output
        if args.output == "json":
            print(export_json(paths, graph))
        elif args.output == "markdown":
            print(export_markdown(paths, graph))
        else:
            from rich.console import Console
            console = Console(stderr=True) if args.exit_code else Console()
            render_cli(paths, graph, console)

        # Exit code
        if args.exit_code and paths:
            return 1
        return 0

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        # Clean up temp directory
        if temp_dir and os.path.isdir(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
