from adreaper.core.context import EngagementContext
from adreaper.core.graph import ADGraph, EdgeType, NodeType
from adreaper.modules.analysis.bloodhound_export import BloodHoundExport, build_bloodhound


def _graph():
    g = ADGraph()
    g.add_node("S-1-5-21-1-1105", NodeType.USER, "alice", {"enabled": True, "dn": "CN=alice,DC=corp,DC=local"})
    g.add_node("S-1-5-21-1-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    g.add_node("S-1-5-21-1-1000", NodeType.COMPUTER, "WS01", {"dns": "ws01.corp.local"})
    g.add_node("CORP.LOCAL", NodeType.DOMAIN, "corp.local", {"sid": "S-1-5-21-1"})
    g.add_edge("S-1-5-21-1-1105", "S-1-5-21-1-512", EdgeType.MEMBER_OF)
    g.add_edge("S-1-5-21-1-1105", "S-1-5-21-1-1000", EdgeType.GENERIC_ALL)
    g.add_edge("S-1-5-21-1-1105", "CORP.LOCAL", EdgeType.DC_SYNC)
    return g


def test_build_structure_and_counts():
    files = build_bloodhound(_graph(), "CORP.LOCAL", "S-1-5-21-1")
    assert set(files) == {"users", "groups", "computers", "domains"}
    assert files["users"]["meta"]["type"] == "users"
    assert files["users"]["meta"]["count"] == 1
    assert files["groups"]["meta"]["count"] == 1
    assert files["computers"]["meta"]["count"] == 1
    assert files["domains"]["meta"]["count"] == 1


def test_user_upn_and_props():
    files = build_bloodhound(_graph(), "CORP.LOCAL", "S-1-5-21-1")
    alice = files["users"]["data"][0]
    assert alice["ObjectIdentifier"] == "S-1-5-21-1-1105"
    assert alice["Properties"]["name"] == "ALICE@CORP.LOCAL"
    assert alice["Properties"]["domainsid"] == "S-1-5-21-1"


def test_group_membership():
    files = build_bloodhound(_graph(), "CORP.LOCAL", "S-1-5-21-1")
    da = files["groups"]["data"][0]
    members = [m["ObjectIdentifier"] for m in da["Members"]]
    assert "S-1-5-21-1-1105" in members
    assert da["Members"][0]["ObjectType"] == "User"
    assert da["Properties"]["highvalue"] is True


def test_ace_on_computer():
    files = build_bloodhound(_graph(), "CORP.LOCAL", "S-1-5-21-1")
    ws = files["computers"]["data"][0]
    rights = {a["RightName"] for a in ws["Aces"]}
    assert "GenericAll" in rights
    assert ws["Aces"][0]["PrincipalSID"] == "S-1-5-21-1-1105"
    assert ws["Aces"][0]["PrincipalType"] == "User"


def test_dcsync_expands_to_two_aces():
    files = build_bloodhound(_graph(), "CORP.LOCAL", "S-1-5-21-1")
    dom = files["domains"]["data"][0]
    rights = {a["RightName"] for a in dom["Aces"]}
    assert {"GetChanges", "GetChangesAll"}.issubset(rights)


def test_module_writes_files_and_zip(tmp_path):
    ctx = EngagementContext(domain="corp.local", output_dir=tmp_path)
    ctx.graph.merge(_graph())
    mod = BloodHoundExport()
    result = mod.run(ctx)
    assert result.success
    assert "zip" in result.data
    zpath = tmp_path / "corp.local" / "corp.local_bloodhound.zip"
    assert zpath.exists()
    # per-type json files exist too
    assert (tmp_path / "corp.local" / "corp.local_users.json").exists()


def test_empty_graph_fails(tmp_path):
    ctx = EngagementContext(domain="corp.local", output_dir=tmp_path)
    assert not BloodHoundExport().run(ctx).success
