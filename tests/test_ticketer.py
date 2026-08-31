from adreaper.core import loader
from adreaper.core.graph import ADGraph, NodeType
from adreaper.modules.kerberos.ticketer import (
    DEFAULT_GROUPS,
    default_groups,
    derive_domain_sid,
    equivalent_command,
    ticket_ccache_name,
    usage_hint,
    validate_forge_request,
)

SID = "S-1-5-21-111-222-333"
NT = "a" * 32


def test_validate_golden_ok():
    assert validate_forge_request("golden", "corp.local", SID, "Administrator", NT, "", "") == []


def test_validate_requires_key():
    probs = validate_forge_request("golden", "corp.local", SID, "Administrator", "", "", "")
    assert any("need a key" in p for p in probs)


def test_validate_requires_domain_sid():
    probs = validate_forge_request("golden", "corp.local", "", "Administrator", NT, "", "")
    assert any("domain SID" in p for p in probs)


def test_validate_silver_requires_spn():
    probs = validate_forge_request("silver", "corp.local", SID, "Administrator", NT, "", "")
    assert any("spn" in p for p in probs)
    assert validate_forge_request("silver", "corp.local", SID, "bob", "", "deadbeef",
                                  "cifs/host.corp.local") == []


def test_validate_bad_kind_and_missing_domain():
    probs = validate_forge_request("platinum", "", SID, "Administrator", NT, "", "")
    assert any("unknown kind" in p for p in probs)
    assert any("domain is required" in p for p in probs)


def test_ccache_names():
    assert ticket_ccache_name("golden", "Administrator") == "Administrator_golden.ccache"
    assert ticket_ccache_name("silver", "svc", "cifs/host.dom") == "svc@cifs_host.dom_silver.ccache"


def test_equivalent_command_golden_and_silver():
    g = equivalent_command("golden", "corp.local", SID, "Administrator", NT, "", "")
    assert g == f"impacket-ticketer -nthash {NT} -domain-sid {SID} -domain corp.local Administrator"
    s = equivalent_command("silver", "corp.local", SID, "bob", "", "KEY", "cifs/host")
    assert "-aesKey KEY" in s and "-spn cifs/host" in s and s.endswith(" bob")


def test_equivalent_command_custom_groups_and_id():
    c = equivalent_command("golden", "corp.local", SID, "svc", NT, "", "",
                           groups="512", user_id=1337)
    assert "-groups 512" in c and "-user-id 1337" in c


def test_derive_domain_sid():
    g = ADGraph()
    g.add_node("corp", NodeType.DOMAIN, "corp.local", {"sid": SID})
    assert derive_domain_sid(g) == SID
    g2 = ADGraph()
    g2.add_node("S-1-5-21-111-222-333-1105", NodeType.USER, "alice")
    assert derive_domain_sid(g2) == SID
    assert derive_domain_sid(ADGraph()) == ""


def test_default_groups_and_usage_hint():
    assert default_groups() == DEFAULT_GROUPS
    assert "KRB5CCNAME" in usage_hint("/loot/x_golden.ccache")


def test_module_discovered():
    assert "kerberos/ticketer" in loader.discover(force=True)
