from adreaper.core.context import EngagementContext
from adreaper.core.graph import EdgeType, NodeType
from adreaper.modules.analysis.pathfinder import PathFinder, render_path


def _ctx_with_path(tmp_path):
    ctx = EngagementContext(domain="corp.local", output_dir=tmp_path)
    g = ctx.graph
    g.add_node("S-1-5-21-1105", NodeType.USER, "alice", {"enabled": True})
    g.add_node("S-1-5-21-1200", NodeType.GROUP, "IT Support")
    g.add_node("S-1-5-21-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    g.add_edge("S-1-5-21-1105", "S-1-5-21-1200", EdgeType.MEMBER_OF)
    g.add_edge("S-1-5-21-1200", "S-1-5-21-512", EdgeType.MEMBER_OF)
    return ctx


def test_pathfinder_finds_membership_path(tmp_path):
    ctx = _ctx_with_path(tmp_path)
    mod = PathFinder()
    mod.set_option("start", "alice")
    result = mod.run(ctx)
    assert result.success
    assert result.data["paths"]
    joined = "\n".join(result.data["paths"])
    assert "alice" in joined and "Domain Admins" in joined
    assert "MemberOf" in joined
    # a readable paths file is written to loot
    assert (ctx.loot_dir() / "attack_paths.txt").exists()


def test_pathfinder_auto_high_value_goal(tmp_path):
    ctx = _ctx_with_path(tmp_path)
    mod = PathFinder()  # no start/goal -> all users to all high-value
    result = mod.run(ctx)
    assert result.success
    assert any("Domain Admins" in p for p in result.data["paths"])


def test_pathfinder_empty_graph_fails(tmp_path):
    ctx = EngagementContext(domain="corp.local", output_dir=tmp_path)
    result = PathFinder().run(ctx)
    assert not result.success
    assert "empty" in result.error


def test_render_path(tmp_path):
    ctx = _ctx_with_path(tmp_path)
    path = ctx.graph.shortest_path("S-1-5-21-1105", "S-1-5-21-512")
    rendered = render_path(ctx.graph, path)
    assert rendered == "alice -[MemberOf]-> IT Support -[MemberOf]-> Domain Admins"
