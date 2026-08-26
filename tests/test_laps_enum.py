from adreaper.core import loader
from adreaper.core.graph import Node, NodeType
from adreaper.modules.recon.laps_enum import (
    ACE_ALLOWED,
    ACE_ALLOWED_OBJECT,
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_DS_READ_PROP,
    RIGHT_GENERIC_ALL,
    _interesting,
    _is_expected,
    can_read_laps,
)

LAPS = {"11111111-1111-1111-1111-111111111111"}
OTHER = "22222222-2222-2222-2222-222222222222"


def test_generic_all_can_read():
    assert can_read_laps(ACE_ALLOWED, RIGHT_GENERIC_ALL, None, LAPS)


def test_all_extended_rights_can_read():
    # control access with no specific object type = all extended rights
    assert can_read_laps(ACE_ALLOWED, RIGHT_DS_CONTROL_ACCESS, None, LAPS)


def test_control_access_on_laps_guid_can_read():
    assert can_read_laps(ACE_ALLOWED_OBJECT, RIGHT_DS_CONTROL_ACCESS,
                         "11111111-1111-1111-1111-111111111111", LAPS)


def test_read_prop_on_laps_guid_can_read():
    assert can_read_laps(ACE_ALLOWED_OBJECT, RIGHT_DS_READ_PROP,
                         "11111111-1111-1111-1111-111111111111", LAPS)


def test_read_all_props_cannot_read_confidential():
    # READ_PROP with no object type does NOT bypass the confidentiality bit
    assert not can_read_laps(ACE_ALLOWED, RIGHT_DS_READ_PROP, None, LAPS)


def test_control_access_on_other_guid_cannot_read():
    assert not can_read_laps(ACE_ALLOWED_OBJECT, RIGHT_DS_CONTROL_ACCESS, OTHER, LAPS)


def test_denied_ace_never_reads():
    assert not can_read_laps(0x01, RIGHT_GENERIC_ALL, None, LAPS)


def test_no_rights_cannot_read():
    assert not can_read_laps(ACE_ALLOWED, 0x0, None, LAPS)


def test_interesting_filters_self_and_apex():
    assert _interesting("S-1-5-21-9-1105", "S-1-5-21-9-1000")
    assert not _interesting("S-1-5-21-9-1000", "S-1-5-21-9-1000")   # self
    assert not _interesting("S-1-5-18", "X")                        # SYSTEM
    assert not _interesting("S-1-5-21-9-512", "X")                  # Domain Admins RID


def test_is_expected():
    da = Node("S-1-5-21-9-512", NodeType.GROUP, "Domain Admins")
    user = Node("S-1-5-21-9-1105", NodeType.USER, "alice")
    hv = Node("S-1-5-21-9-1", NodeType.USER, "svc", {"high_value": True})
    assert _is_expected(da)       # well-known privileged name
    assert _is_expected(hv)       # flagged high_value
    assert not _is_expected(user)


def test_module_discovered():
    assert "recon/laps_enum" in loader.discover(force=True)
