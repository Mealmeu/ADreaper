from adreaper.core import loader
from adreaper.core.console import Console, search_modules
from adreaper.core.context import EngagementContext


def test_search_modules_by_name_and_category():
    loader.discover(force=True)
    mods = list(loader.all_modules().values())
    names = {m.name for m in search_modules(mods, "kerberos")}
    assert "kerberos/kerberoast" in names and "kerberos/asreproast" in names
    assert {m.name for m in search_modules(mods, "laps")} == {"recon/laps_enum"}


def test_search_modules_empty_and_miss():
    mods = list(loader.all_modules().values())
    assert search_modules(mods, "") == []
    assert search_modules(mods, "   ") == []
    assert search_modules(mods, "zzzz-no-such") == []


def test_search_is_sorted():
    mods = list(loader.all_modules().values())
    hits = search_modules(mods, "recon")
    assert [m.name for m in hits] == sorted(m.name for m in hits)


def _console():
    return Console(EngagementContext())


def test_dispatch_use_and_back():
    c = _console()
    assert c._dispatch("use recon/ldap_enum") is True
    assert c.module is not None and c.module.name == "recon/ldap_enum"
    c._dispatch("back")
    assert c.module is None


def test_dispatch_unknown_module_keeps_state():
    c = _console()
    c._dispatch("use bogus/nope")
    assert c.module is None


def test_dispatch_set_globals():
    c = _console()
    c._dispatch("set domain corp.local")
    c._dispatch("set dc-ip 10.0.0.10")
    c._dispatch("set username alice")
    assert c.ctx.domain == "corp.local"
    assert c.ctx.dc_ip == "10.0.0.10"
    assert c.ctx.credential.username == "alice"


def test_use_seeds_module_target_from_context():
    c = _console()
    c._dispatch("set dc-ip 10.0.0.10")
    c._dispatch("use recon/ldap_enum")
    assert c.module.opt("target") == "10.0.0.10"


def test_dispatch_exit_returns_false():
    c = _console()
    assert c._dispatch("exit") is False
    assert c._dispatch("quit") is False


def test_dispatch_unknown_command_survives():
    c = _console()
    assert c._dispatch("frobnicate now") is True


def test_dispatch_run_without_module_is_safe():
    c = _console()
    assert c._dispatch("run") is True   # logs error, no crash, no module selected
