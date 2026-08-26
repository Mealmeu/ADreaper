from adreaper.core import loader
from adreaper.core.context import Credential, EngagementContext
from adreaper.core.graph import NodeType
from adreaper.modules.recon.session_enum import (
    _clean,
    _find_computer,
    _hashes,
    _match_user,
)


def _ctx():
    ctx = EngagementContext(domain="corp.local")
    ctx.graph.add_node("S-1-5-21-1-1105", NodeType.USER, "alice")
    ctx.graph.add_node("S-1-5-21-1-1106", NodeType.USER, "bob")
    ctx.graph.add_node("S-1-5-21-1-1000", NodeType.COMPUTER, "WS01",
                       properties={"ip": "10.0.0.5", "dns": "ws01.corp.local"})
    return ctx


def test_clean_strips_nulls_and_space():
    assert _clean("alice\x00") == "alice"
    assert _clean("  DC01\x00 ") == "DC01"
    assert _clean(None) == ""


def test_match_user_variants():
    ctx = _ctx()
    assert _match_user(ctx, "alice").name == "alice"
    assert _match_user(ctx, "CORP\\Alice").name == "alice"
    assert _match_user(ctx, "bob@corp.local").name == "bob"
    assert _match_user(ctx, "nobody") is None


def test_find_computer_by_name_ip_dns():
    ctx = _ctx()
    assert _find_computer(ctx, "WS01").id == "S-1-5-21-1-1000"
    assert _find_computer(ctx, "10.0.0.5").id == "S-1-5-21-1-1000"
    assert _find_computer(ctx, "ws01.corp.local").id == "S-1-5-21-1-1000"
    assert _find_computer(ctx, "dc99") is None


def test_hashes():
    assert _hashes(Credential(nt_hash="")) == ("", "")
    lm, nt = _hashes(Credential(nt_hash="ff" * 16))
    assert lm == "aad3b435b51404eeaad3b435b51404ee"
    assert nt == "ff" * 16
    assert _hashes(Credential(nt_hash="dead:beef")) == ("dead", "beef")


def test_module_discovered():
    assert "recon/session_enum" in loader.discover(force=True)
