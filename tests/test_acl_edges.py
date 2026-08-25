from adreaper.core.graph import EdgeType, Node, NodeType
from adreaper.modules.recon.acl_enum import (
    ACE_ALLOWED,
    ACE_ALLOWED_OBJECT,
    GUID_ALLOWED_TO_ACT,
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_WRITE_MEMBER,
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_DS_FULL_CONTROL,
    RIGHT_DS_WRITE_PROP,
    RIGHT_GENERIC_ALL,
    RIGHT_GENERIC_WRITE,
    RIGHT_WRITE_DACL,
    RIGHT_WRITE_OWNER,
    _interesting,
    _spn_host,
    is_dcsync,
    mask_edges,
)


def test_generic_all_and_full_control():
    assert mask_edges(ACE_ALLOWED, RIGHT_GENERIC_ALL, None) == [EdgeType.GENERIC_ALL]
    assert mask_edges(ACE_ALLOWED, RIGHT_DS_FULL_CONTROL, None) == [EdgeType.GENERIC_ALL]


def test_write_dacl_owner_genericwrite():
    assert EdgeType.WRITE_DACL in mask_edges(ACE_ALLOWED, RIGHT_WRITE_DACL, None)
    assert EdgeType.WRITE_OWNER in mask_edges(ACE_ALLOWED, RIGHT_WRITE_OWNER, None)
    assert EdgeType.GENERIC_WRITE in mask_edges(ACE_ALLOWED, RIGHT_GENERIC_WRITE, None)


def test_object_extended_rights():
    assert mask_edges(ACE_ALLOWED_OBJECT, RIGHT_DS_CONTROL_ACCESS,
                      GUID_FORCE_CHANGE_PASSWORD) == [EdgeType.FORCE_CHANGE_PASSWORD]
    assert mask_edges(ACE_ALLOWED_OBJECT, RIGHT_DS_WRITE_PROP,
                      GUID_WRITE_MEMBER) == [EdgeType.ADD_MEMBER]
    assert mask_edges(ACE_ALLOWED_OBJECT, RIGHT_DS_WRITE_PROP,
                      GUID_ALLOWED_TO_ACT) == [EdgeType.ADD_ALLOWED_TO_ACT]


def test_all_extended_rights_non_object():
    assert mask_edges(ACE_ALLOWED, RIGHT_DS_CONTROL_ACCESS, None) == [EdgeType.ALL_EXTENDED_RIGHTS]


def test_denied_ace_yields_nothing():
    assert mask_edges(0x01, RIGHT_GENERIC_ALL, None) == []


def test_is_dcsync():
    assert is_dcsync({"getchanges", "getchanges_all"})
    assert not is_dcsync({"getchanges"})
    assert not is_dcsync({"getchanges_all"})


def test_spn_host():
    assert _spn_host("MSSQLSvc/db.corp.local:1433") == "db.corp.local"
    assert _spn_host("HOST/WS01") == "ws01"


def test_interesting_filters():
    alice = Node("S-1-5-21-1-1105", NodeType.USER, "alice")
    da = Node("S-1-5-21-1-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    idx = {alice.id: alice, da.id: da}
    obj = "S-1-5-21-1-9999"
    # a known non-privileged principal is interesting
    assert _interesting("S-1-5-21-1-1105", idx, obj)
    # SYSTEM is skipped
    assert not _interesting("S-1-5-18", idx, obj)
    # high-value (admin) trustee is skipped (admin-over-x is not privesc)
    assert not _interesting("S-1-5-21-1-512", idx, obj)
    # unknown principal (not enumerated) is skipped
    assert not _interesting("S-1-5-21-1-4242", idx, obj)
    # a Domain/Enterprise-Admin RID is skipped even if present
    assert not _interesting("S-1-5-21-1-519", idx, obj)


def test_acl_module_discovered():
    from adreaper.core import loader
    assert "recon/acl_enum" in loader.discover(force=True)


def test_acl_empty_graph_guard(tmp_path):
    # The empty-graph guard runs before any ldap3/impacket import, so this is
    # testable without the AD stack installed.
    from adreaper.core.context import EngagementContext
    from adreaper.modules.recon.acl_enum import AclEnum

    ctx = EngagementContext(domain="corp.local", dc_ip="10.0.0.1", output_dir=tmp_path)
    result = AclEnum().run(ctx)
    assert not result.success
    assert "graph is empty" in result.error


def test_acl_edge_creates_attack_path(tmp_path):
    """An ACL control edge should become a one-hop path to Domain Admin."""
    from adreaper.core.context import EngagementContext
    from adreaper.modules.analysis.pathfinder import PathFinder

    ctx = EngagementContext(domain="corp.local", output_dir=tmp_path)
    ctx.graph.add_node("S-1-5-21-1-1105", NodeType.USER, "alice", {"enabled": True})
    ctx.graph.add_node("S-1-5-21-1-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    # alice has GenericAll over Domain Admins (e.g. via a delegated ACL)
    ctx.graph.add_edge("S-1-5-21-1-1105", "S-1-5-21-1-512", EdgeType.GENERIC_ALL)

    result = PathFinder().run(ctx)
    assert result.success
    joined = "\n".join(result.data["paths"])
    assert "alice -[GenericAll]-> Domain Admins" in joined
    # one hop to DA is CRITICAL
    assert any(f.severity.value == "CRITICAL" for f in result.findings)
