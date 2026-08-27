from adreaper.core import loader
from adreaper.core.graph import Node, NodeType
from adreaper.modules.recon.gpo_enum import _interesting, parse_gplink

DN1 = "cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=corp,DC=local"
DN2 = "cn={6AC1786C-016F-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=corp,DC=local"


def test_parse_single_enabled_link():
    links = parse_gplink(f"[LDAP://{DN1};0]")
    assert len(links) == 1
    assert links[0]["dn"] == DN1
    assert links[0]["disabled"] is False
    assert links[0]["enforced"] is False


def test_parse_enforced_and_order():
    links = parse_gplink(f"[LDAP://{DN1};0][LDAP://{DN2};2]")
    assert [l["dn"] for l in links] == [DN1, DN2]
    assert links[0]["enforced"] is False
    assert links[1]["enforced"] is True


def test_parse_disabled_flag():
    links = parse_gplink(f"[LDAP://{DN1};1]")
    assert links[0]["disabled"] is True


def test_parse_enforced_and_disabled():
    links = parse_gplink(f"[LDAP://{DN1};3]")
    assert links[0]["disabled"] is True and links[0]["enforced"] is True


def test_parse_strips_server_prefix():
    links = parse_gplink(f"[LDAP://dc01.corp.local/{DN1};0]")
    assert links[0]["dn"] == DN1


def test_parse_empty_and_garbage():
    assert parse_gplink("") == []
    assert parse_gplink("   ") == []
    # malformed flags default to 0 (enabled, not enforced)
    links = parse_gplink(f"[LDAP://{DN1};x]")
    assert links and links[0]["disabled"] is False


def test_interesting_filters():
    idx = {
        "S-1-5-21-9-1105": Node("S-1-5-21-9-1105", NodeType.USER, "alice"),
        "S-1-5-21-9-512": Node("S-1-5-21-9-512", NodeType.GROUP, "Domain Admins",
                               {"high_value": True}),
    }
    gpo_id = "GPO-1"
    assert _interesting("S-1-5-21-9-1105", idx, gpo_id)          # known low-priv user
    assert not _interesting("S-1-5-21-9-512", idx, gpo_id)       # high-value -> expected
    assert not _interesting("S-1-5-21-9-9999", idx, gpo_id)      # unknown trustee
    assert not _interesting("S-1-5-18", idx, gpo_id)             # SYSTEM
    assert not _interesting(gpo_id, idx, gpo_id)                 # self


def test_module_discovered():
    assert "recon/gpo_enum" in loader.discover(force=True)
