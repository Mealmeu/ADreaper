from adreaper.core import loader
from adreaper.core.graph import ADGraph, EdgeType, NodeType
from adreaper.modules.analysis.graph_export import select_relevant, to_dot, to_mermaid


def _small_graph():
    g = ADGraph()
    g.add_node("S-1-5-21-9-1105", NodeType.USER, "alice")
    g.add_node("S-1-5-21-9-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    g.add_edge("S-1-5-21-9-1105", "S-1-5-21-9-512", EdgeType.MEMBER_OF)
    return g


def test_mermaid_basic_structure():
    g = _small_graph()
    nodes, edges = select_relevant(g, 60)
    mmd = to_mermaid(nodes, edges)
    assert mmd.startswith("flowchart LR")
    assert "MemberOf" in mmd
    assert "alice" in mmd and "Domain Admins" in mmd
    assert "classDef hv" in mmd
    assert " hv;" in mmd  # the high-value group got the hv class assignment


def test_mermaid_owned_class():
    g = _small_graph()
    g.mark_owned("S-1-5-21-9-1105")
    mmd = to_mermaid(*select_relevant(g, 60))
    assert " owned;" in mmd


def test_mermaid_label_escaping():
    g = ADGraph()
    g.add_node("X", NodeType.USER, 'we"ird|name')
    mmd = to_mermaid(*select_relevant(g, 60))
    assert '"' not in mmd.split("classDef")[0].replace('("', "").replace('")', "") or "'" in mmd
    assert "we'ird/name" in mmd


def test_dot_basic_structure():
    g = _small_graph()
    dot = to_dot(*select_relevant(g, 60))
    assert dot.startswith("digraph adreaper {")
    assert "->" in dot
    assert 'label="MemberOf"' in dot
    assert dot.rstrip().endswith("}")


def test_select_relevant_returns_all_when_small():
    g = _small_graph()
    nodes, edges = select_relevant(g, 60)
    assert len(nodes) == 2 and len(edges) == 1


def test_select_relevant_focuses_when_large():
    g = ADGraph()
    g.add_node("A", NodeType.GROUP, "Admins", {"high_value": True})
    for n in ("B", "C", "D", "E"):
        g.add_node(n, NodeType.USER, n)
    g.add_edge("B", "A", EdgeType.MEMBER_OF)
    g.add_edge("C", "A", EdgeType.MEMBER_OF)
    nodes, edges = select_relevant(g, 3)
    ids = {n.id for n in nodes}
    assert len(nodes) <= 3
    assert "A" in ids                       # the high-value seed is kept
    assert all(e.source in ids and e.target in ids for e in edges)


def test_module_discovered():
    assert "analysis/graph_export" in loader.discover(force=True)
