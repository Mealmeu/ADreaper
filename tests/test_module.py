import pytest

from adreaper.core.context import Credential, EngagementContext
from adreaper.core.module import BaseModule, Option, OptionType, Severity


class _Demo(BaseModule):
    name = "test/demo"
    description = "demo"
    options = [
        Option("host", "target host", required=True),
        Option("port", "port", default=445, type=OptionType.INT),
        Option("ssl", "use ssl", default=False, type=OptionType.BOOL),
        Option("mode", "mode", default="a", choices=["a", "b"]),
    ]

    def run(self, ctx):
        r = self.result()
        r.add_finding("ran", Severity.INFO)
        return r.finish()


def test_option_coercion():
    m = _Demo()
    m.set_option("port", "636")
    assert m.opt("port") == 636
    m.set_option("ssl", "true")
    assert m.opt("ssl") is True
    m.set_option("ssl", "no")
    assert m.opt("ssl") is False


def test_choices_enforced():
    m = _Demo()
    with pytest.raises(ValueError):
        m.set_option("mode", "z")


def test_required_validation():
    m = _Demo()
    assert any("host" in p for p in m.validate())
    m.set_option("host", "10.0.0.1")
    assert m.validate() == []


def test_set_options_ignores_unknown():
    m = _Demo()
    m.set_options({"host": "h", "domain": "corp.local"})  # 'domain' is not a module opt
    assert m.opt("host") == "h"


def test_severity_rank():
    assert Severity.CRITICAL.rank > Severity.LOW.rank


def test_result_and_run():
    m = _Demo()
    m.set_option("host", "x")
    ctx = EngagementContext(domain="corp.local", credential=Credential("u", "p", "corp.local"))
    result = m.run(ctx)
    assert result.success
    assert len(result.findings) == 1
    assert result.to_dict()["module"] == "test/demo"


def test_credential_hash_normalization():
    c = Credential(username="u", nt_hash="a" * 32)
    assert c.normalized_hash().startswith("aad3b435b51404eeaad3b435b51404ee:")
    c2 = Credential(username="u", nt_hash="lm:nt")
    assert c2.normalized_hash() == "lm:nt"
    assert Credential().normalized_hash() == ""
