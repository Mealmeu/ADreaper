from adreaper.core import loader
from adreaper.modules.adcs.esc_enum import (
    ANY_PURPOSE,
    CERT_REQUEST_AGENT,
    CLIENT_AUTH,
    _is_low_priv,
    assess_template,
    derive_ekus,
)


def _tmpl(**kw):
    base = {
        "name": "T", "enabled": True, "enrollee_supplies_subject": False,
        "manager_approval": False, "authorized_signatures": 0, "ekus": [CLIENT_AUTH],
        "client_auth": True, "any_purpose": False, "enrollment_agent": False,
        "low_priv_enroll": True, "low_priv_control": False, "controllers": [],
    }
    base.update(kw)
    return base


def test_derive_ekus():
    assert derive_ekus([]) == (True, True, False)          # empty = any purpose
    assert derive_ekus([CLIENT_AUTH]) == (True, False, False)
    assert derive_ekus([ANY_PURPOSE]) == (True, True, False)
    assert derive_ekus([CERT_REQUEST_AGENT]) == (False, False, True)
    assert derive_ekus(["1.2.3.4.5"]) == (False, False, False)


def test_esc1_detected():
    findings = assess_template(_tmpl(enrollee_supplies_subject=True, client_auth=True))
    escs = {f["esc"] for f in findings}
    assert "ESC1" in escs
    assert next(f for f in findings if f["esc"] == "ESC1")["severity"] == "CRITICAL"


def test_esc1_blocked_by_manager_approval():
    findings = assess_template(_tmpl(enrollee_supplies_subject=True, manager_approval=True))
    assert "ESC1" not in {f["esc"] for f in findings}


def test_esc1_blocked_by_authorized_signatures():
    findings = assess_template(_tmpl(enrollee_supplies_subject=True, authorized_signatures=1))
    assert "ESC1" not in {f["esc"] for f in findings}


def test_esc2_any_purpose():
    findings = assess_template(_tmpl(any_purpose=True, ekus=[ANY_PURPOSE]))
    assert "ESC2" in {f["esc"] for f in findings}


def test_esc3_enrollment_agent():
    findings = assess_template(_tmpl(enrollment_agent=True, ekus=[CERT_REQUEST_AGENT]))
    assert "ESC3" in {f["esc"] for f in findings}


def test_esc4_independent_of_enrollment():
    # low-priv control flags ESC4 even when not low-priv enrollable
    findings = assess_template(_tmpl(low_priv_enroll=False, low_priv_control=True))
    escs = {f["esc"] for f in findings}
    assert escs == {"ESC4"}


def test_not_enrollable_yields_no_esc123():
    findings = assess_template(_tmpl(low_priv_enroll=False, enrollee_supplies_subject=True))
    assert not ({"ESC1", "ESC2", "ESC3"} & {f["esc"] for f in findings})


def test_is_low_priv():
    assert _is_low_priv("S-1-5-11")            # Authenticated Users
    assert _is_low_priv("S-1-5-21-1-513")      # Domain Users RID
    assert not _is_low_priv("S-1-5-21-1-1105")  # a normal user


def test_module_discovered():
    assert "adcs/esc_enum" in loader.discover(force=True)
