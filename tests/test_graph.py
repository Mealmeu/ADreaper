from adreaper.core.graph import ADGraph, EdgeType, NodeType


def test_add_and_merge_nodes():
    g = ADGraph()
    g.add_node("S-1-5-21-1", NodeType.USER, "alice", {"enabled": True})
    # merging updates properties, does not duplicate
    g.add_node("s-1-5-21-1", NodeType.USER, "alice", {"admin_count": True})
    assert len(g) == 1
    n = g.get("S-1-5-21-1")
    assert n is not None
    assert n.properties["enabled"] is True
    assert n.properties["admin_count"] is True


def test_edges_dedup():
    g = ADGraph()
    g.add_node("A", NodeType.USER, "a")
    g.add_node("B", NodeType.GROUP, "b")
    g.add_edge("A", "B", EdgeType.MEMBER_OF)
    g.add_edge("A", "B", EdgeType.MEMBER_OF)
    assert len(g.edges) == 1


def test_shortest_path():
    g = ADGraph()
    for n in ("U", "G1", "G2", "DA"):
        g.add_node(n, NodeType.GROUP, n)
    g.add_edge("U", "G1", EdgeType.MEMBER_OF)
    g.add_edge("G1", "G2", EdgeType.MEMBER_OF)
    g.add_edge("G2", "DA", EdgeType.ADMIN_TO)
    path = g.shortest_path("U", "DA")
    assert path is not None
    assert [step[0] for step in path] == ["U", "G1", "G2", "DA"]
    assert g.shortest_path("DA", "U") is None  # directed


def test_persistence_roundtrip(tmp_path):
    g = ADGraph()
    g.add_node("A", NodeType.USER, "alice")
    g.add_node("B", NodeType.GROUP, "admins")
    g.add_edge("A", "B", EdgeType.MEMBER_OF, {"via": "test"})
    p = g.save(tmp_path / "graph.json")
    g2 = ADGraph.load(p)
    assert len(g2) == 2
    assert len(g2.edges) == 1
    assert g2.edges[0].properties["via"] == "test"


def test_counts():
    g = ADGraph()
    g.add_node("A", NodeType.USER, "a")
    g.add_node("B", NodeType.USER, "b")
    g.add_node("C", NodeType.GROUP, "c")
    g.add_edge("A", "C", EdgeType.MEMBER_OF)
    c = g.counts()
    assert c["User"] == 2
    assert c["Group"] == 1
    assert c["Edges"] == 1
