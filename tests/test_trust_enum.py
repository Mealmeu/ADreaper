from adreaper.core import loader
from adreaper.modules.recon.trust_enum import (
    TA_FOREST_TRANSITIVE,
    TA_QUARANTINED_DOMAIN,
    TA_USES_RC4_ENCRYPTION,
    TA_WITHIN_FOREST,
    assess_trust,
    attribute_flags,
)


def _codes(findings):
    return {f["code"] for f in findings}


def test_attribute_flags():
    flags = attribute_flags(TA_FOREST_TRANSITIVE | TA_QUARANTINED_DOMAIN)
    assert "FOREST_TRANSITIVE" in flags
    assert "QUARANTINED (SID filtering)" in flags


def test_forest_trust_without_sid_filtering_is_high():
    labels, findings = assess_trust("partner.local", 3, 2, TA_FOREST_TRANSITIVE)
    assert labels["direction"] == "Bidirectional"
    assert labels["type"] == "Uplevel (AD)"
    assert labels["sid_filtering"] == "DISABLED"
    codes = _codes(findings)
    assert "SID_FILTER_FOREST" in codes
    hi = next(f for f in findings if f["code"] == "SID_FILTER_FOREST")
    assert hi["severity"] == "HIGH"


def test_forest_trust_with_quarantine_is_clean():
    _, findings = assess_trust("p", 2, 2, TA_FOREST_TRANSITIVE | TA_QUARANTINED_DOMAIN)
    assert "SID_FILTER_FOREST" not in _codes(findings)
    assert "SID_FILTER_EXTERNAL" not in _codes(findings)


def test_external_trust_without_filtering_is_medium():
    _, findings = assess_trust("ext.local", 2, 2, 0)
    codes = _codes(findings)
    assert "SID_FILTER_EXTERNAL" in codes
    assert next(f for f in findings if f["code"] == "SID_FILTER_EXTERNAL")["severity"] == "MEDIUM"


def test_within_forest_has_sid_filtering():
    labels, findings = assess_trust("child.corp.local", 3, 2, TA_WITHIN_FOREST)
    assert labels["sid_filtering"] == "enabled"
    assert "SID_FILTER_FOREST" not in _codes(findings)
    assert "SID_FILTER_EXTERNAL" not in _codes(findings)


def test_rc4_flagged():
    _, findings = assess_trust("p", 2, 2, TA_WITHIN_FOREST | TA_USES_RC4_ENCRYPTION)
    assert "RC4" in _codes(findings)


def test_inbound_surface_only_when_inbound_and_unfiltered():
    _, out = assess_trust("p", 1, 2, 0)   # inbound, external, no filtering
    assert "INBOUND_SURFACE" in _codes(out)
    _, out2 = assess_trust("p", 2, 2, 0)  # outbound only
    assert "INBOUND_SURFACE" not in _codes(out2)


def test_module_discovered():
    assert "recon/trust_enum" in loader.discover(force=True)
