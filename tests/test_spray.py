from adreaper.core import loader
from adreaper.modules.credentials.password_spray import (
    _classify_error,
    _normalize_hash,
    plan_spray,
)


def test_plan_spray_respects_threshold():
    # threshold 3 -> at most 2 failed rounds
    rounds, warn = plan_spray(num_secrets=5, threshold=3, force=False)
    assert rounds == 2
    assert "trimming" in warn


def test_plan_spray_unknown_threshold_is_conservative():
    rounds, warn = plan_spray(num_secrets=5, threshold=0, force=False)
    assert rounds == 1
    assert warn


def test_plan_spray_single_secret_no_warning():
    rounds, warn = plan_spray(num_secrets=1, threshold=0, force=False)
    assert rounds == 1
    assert warn == ""


def test_plan_spray_threshold_one_refuses():
    rounds, _ = plan_spray(num_secrets=3, threshold=1, force=False)
    assert rounds == 0  # caller refuses to spray


def test_plan_spray_force_overrides():
    rounds, warn = plan_spray(num_secrets=10, threshold=2, force=True)
    assert rounds == 10
    assert "force" in warn


def test_classify_error():
    assert _classify_error(Exception("STATUS_LOGON_FAILURE")) == "invalid"
    assert _classify_error(Exception("... STATUS_ACCOUNT_LOCKED_OUT ...")) == "locked"
    assert _classify_error(Exception("STATUS_PASSWORD_EXPIRED")) == "expired"
    assert _classify_error(Exception("weird")) == "invalid"


def test_normalize_hash():
    assert _normalize_hash("a" * 32) == "aad3b435b51404eeaad3b435b51404ee:" + "a" * 32
    assert _normalize_hash("lm:nt") == "lm:nt"


def test_new_modules_discovered():
    mods = loader.discover(force=True)
    for name in ("kerberos/asreproast", "kerberos/kerberoast",
                 "analysis/pathfinder", "credentials/password_spray"):
        assert name in mods, f"{name} not discovered"
