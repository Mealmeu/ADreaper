from adreaper.core import loader
from adreaper.core.graph import ADGraph, NodeType
from adreaper.modules.credentials.dcsync import (
    is_krbtgt,
    parse_secret_line,
    select_targets,
)

EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def test_select_targets_explicit_dedups_and_strips_domain():
    assert select_targets(ADGraph(), ["CORP\\Alice", "alice", "bob"]) == ["Alice", "bob"]


def test_select_targets_default_is_krbtgt_only_on_empty_graph():
    assert select_targets(ADGraph(), []) == ["krbtgt"]


def test_select_targets_adds_high_value_and_owned_users():
    g = ADGraph()
    g.add_node("S-1-1", NodeType.USER, "svc_adm", {"high_value": True})
    g.add_node("S-1-2", NodeType.USER, "jdoe", {"owned": True})
    g.add_node("S-1-3", NodeType.USER, "bob")            # neither -> excluded
    g.add_node("S-1-4", NodeType.GROUP, "Domain Admins", {"high_value": True})  # not a user
    picks = select_targets(g, [])
    assert picks[0] == "krbtgt"
    assert set(picks) == {"krbtgt", "svc_adm", "jdoe"}


def test_parse_secret_ntlm_line():
    line = f"CORP\\krbtgt:502:{EMPTY_LM}:{EMPTY_NT}:::"
    p = parse_secret_line(line)
    assert p == {"user": "CORP\\krbtgt", "rid": "502",
                 "lmhash": EMPTY_LM, "nthash": EMPTY_NT}


def test_parse_secret_rejects_kerberos_key_line():
    assert parse_secret_line("CORP\\krbtgt:aes256-cts-hmac-sha1-96:abcdef0123") is None


def test_parse_secret_rejects_cleartext_and_malformed():
    assert parse_secret_line("user:CLEARTEXT:hunter2") is None
    assert parse_secret_line("") is None
    assert parse_secret_line("nope") is None
    assert parse_secret_line(f"u:502:{EMPTY_LM}:deadbeef:::") is None  # nt hash too short


def test_is_krbtgt():
    assert is_krbtgt("CORP\\krbtgt")
    assert is_krbtgt("krbtgt@corp.local")
    assert is_krbtgt("KRBTGT")
    assert not is_krbtgt("CORP\\alice")


def test_module_discovered():
    assert "credentials/dcsync" in loader.discover(force=True)
