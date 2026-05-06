"""Tests for scoring module."""
import pytest
from privmap.graph.model import (
    Edge, EdgeType, EscalationPath, Node, NodeType, Severity,
)
from privmap.analysis.scoring import score_path


def _make_path(hops, has_nopasswd=False, sink_uid=0):
    source = Node(id="user:test", node_type=NodeType.USER, name="test",
                  properties={"uid": 1000})
    sink = Node(id="user:root", node_type=NodeType.USER, name="root",
                properties={"uid": sink_uid})

    nodes = [source]
    edges = []
    for i in range(hops):
        if i == hops - 1:
            nodes.append(sink)
            edges.append(Edge(
                source_id=nodes[-2].id, target_id=sink.id,
                edge_type=EdgeType.GRANTS,
                properties={"nopasswd": has_nopasswd, "command": "ALL"},
            ))
        else:
            mid = Node(id=f"mid:{i}", node_type=NodeType.GROUP, name=f"mid{i}",
                       properties={})
            nodes.append(mid)
            edges.append(Edge(
                source_id=nodes[-2].id, target_id=mid.id,
                edge_type=EdgeType.MEMBER_OF,
            ))

    return EscalationPath(
        nodes=nodes, edges=edges, source=source, sink=sink,
    )


class TestScoring:
    def test_short_nopasswd_is_critical(self):
        path = _make_path(1, has_nopasswd=True)
        score_path(path)
        assert path.severity == Severity.CRITICAL

    def test_long_path_lower_severity(self):
        path = _make_path(6)
        score_path(path)
        assert path.severity.rank < Severity.CRITICAL.rank
