from adreaper.core import loader
from adreaper.core.context import Credential, EngagementContext
from adreaper.core.graph import EdgeType, NodeType
from adreaper.core.module import Severity
from adreaper.core.report import Report


def test_discovery_finds_recon_modules():
    mods = loader.discover(force=True)
    assert "recon/ldap_enum" in mods
    assert "recon/smb_enum" in mods
    assert "recon/dns_enum" in mods
    # every discovered module carries a name and description
    for name, cls in mods.items():
        assert cls.name == name
        assert cls.description


def test_categories_grouping():
    cats = loader.categories()
    assert "recon" in cats
    assert len(cats["recon"]) >= 3


def test_report_generation(tmp_path):
    ctx = EngagementContext(
        domain="corp.local",
        dc_ip="10.0.0.10",
        credential=Credential("alice", "pw", "corp.local"),
        output_dir=tmp_path,
    )
    ctx.graph.add_node("S-1-5-21-500", NodeType.USER, "administrator")
    ctx.graph.add_node("S-1-5-21-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    ctx.graph.add_edge("S-1-5-21-500", "S-1-5-21-512", EdgeType.MEMBER_OF)

    rep = Report()
    r = ctx.graph  # noqa
    from adreaper.core.module import ModuleResult

    mr = ModuleResult(module="recon/ldap_enum")
    mr.add_finding("Kerberoastable account: svc_sql", Severity.HIGH, target="svc_sql")
    mr.finish()
    rep.add(mr)

    paths = rep.write(ctx)
    assert paths["report"].exists()
    assert paths["results"].exists()
    assert paths["graph"].exists()

    md = paths["report"].read_text(encoding="utf-8")
    assert "corp.local" in md
    assert "Kerberoastable" in md
    assert "HIGH" in md
