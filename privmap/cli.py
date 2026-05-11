"""privmap CLI - entry point and argument parsing."""
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
        description="Linux privilege graph engine - trace escalation paths.",
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
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output. Errors still go to stderr.",
    )

    return parser.parse_args(argv)


# Hard limits on snapshot extraction to defend against malicious or malformed archives.
# 2 GiB total uncompressed, 200k members - comfortable headroom for a legitimate
# whole-system snapshot, low enough to refuse a tar/zip bomb.
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_SNAPSHOT_MEMBERS = 200_000


def _safe_extract_tar(tar: tarfile.TarFile, dest: str) -> None:
    """Extract a tar archive while refusing path traversal, absolute paths,
    symlinks/hardlinks pointing outside the destination, special device files,
    and archives that exceed the size/member-count budget.

    Mitigates CVE-2007-4559 across all supported Python versions; on 3.12+ this
    is roughly equivalent to passing ``filter="data"``.
    """
    dest_real = os.path.realpath(dest)
    total_bytes = 0
    member_count = 0

    for member in tar:
        member_count += 1
        if member_count > _MAX_SNAPSHOT_MEMBERS:
            raise ValueError(
                f"snapshot exceeds member limit ({_MAX_SNAPSHOT_MEMBERS})"
            )
        total_bytes += member.size
        if total_bytes > _MAX_SNAPSHOT_BYTES:
            raise ValueError(
                f"snapshot exceeds size limit ({_MAX_SNAPSHOT_BYTES} bytes)"
            )

        # Reject device, FIFO, and other special files outright. A snapshot
        # only ever needs regular files, directories, and symlinks.
        if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError(f"refusing special file in snapshot: {member.name!r}")

        # Reject absolute paths and any traversal that escapes ``dest``.
        target = os.path.realpath(os.path.join(dest, member.name))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            raise ValueError(f"unsafe path in snapshot: {member.name!r}")

        # For links, also resolve the link target relative to its containing
        # directory and ensure it stays inside ``dest``.
        if member.issym() or member.islnk():
            link_target = member.linkname
            if os.path.isabs(link_target):
                raise ValueError(
                    f"absolute link target in snapshot: {member.name!r} -> {link_target!r}"
                )
            link_real = os.path.realpath(
                os.path.join(os.path.dirname(target), link_target)
            )
            if not (link_real == dest_real or link_real.startswith(dest_real + os.sep)):
                raise ValueError(
                    f"link escapes snapshot root: {member.name!r} -> {link_target!r}"
                )

        tar.extract(member, dest)


class _NullStatus:
    """No-op stand-in for rich.console.Status when progress is suppressed.

    Mirrors the bits of the Status API the CLI actually uses (``__enter__``,
    ``__exit__``, ``update``) so the with-block doesn't need a branch.
    """

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def update(self, *args, **kwargs) -> None:
        return None


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
                _safe_extract_tar(tar, temp_dir)
        except (tarfile.TarError, OSError, ValueError) as e:
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

    # Progress spinner - always on stderr so it doesn't pollute json/markdown
    # output, and so a user piping `privmap > report.json` still sees it.
    # Suppressed by --quiet, in non-TTY environments, and when -v/-vv is on
    # (raw log lines are more useful then than a transient spinner).
    from rich.console import Console
    progress_console = Console(stderr=True)
    show_progress = (
        not args.quiet
        and args.verbose == 0
        and progress_console.is_terminal
    )

    try:
        status_cm = (
            progress_console.status("[bold cyan]Initialising[/bold cyan]")
            if show_progress
            else _NullStatus()
        )

        with status_cm as status:
            def progress_cb(phase: str, detail: Optional[str]) -> None:
                msg = f"[bold cyan]{phase}[/bold cyan]"
                if detail:
                    msg += f"  [dim]{detail}[/dim]"
                status.update(msg)

            builder = GraphBuilder(
                root_path=root_path,
                scan_paths=scan_paths,
                snapshot_mode=snapshot_mode,
                progress=progress_cb,
            )
            graph = builder.build()

            progress_cb("Tracing escalation paths", None)
            paths = analyze_paths(
                graph,
                source_users=args.users,
                max_depth=args.max_depth,
                min_severity=min_severity,
            )

        # Spinner is closed before any output is rendered so the redrawn
        # spinner line doesn't interleave with the report.
        if show_progress:
            progress_console.print(
                f"[green]✓[/green] Analysis complete: "
                f"[bold]{graph.node_count}[/bold] nodes, "
                f"[bold]{graph.edge_count}[/bold] edges, "
                f"[bold]{len(paths)}[/bold] paths"
            )

        if args.export_graph:
            graph_json = json.dumps(graph.to_dict(), indent=2, default=str)
            with open(args.export_graph, "w") as f:
                f.write(graph_json)
            logger.info("Graph exported to %s", args.export_graph)

        if args.output == "json":
            print(export_json(paths, graph))
        elif args.output == "markdown":
            print(export_markdown(paths, graph))
        else:
            console = Console(stderr=True) if args.exit_code else Console()
            render_cli(paths, graph, console)

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
