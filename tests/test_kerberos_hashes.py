from adreaper.modules.kerberos.common import (
    ETYPE_AES256,
    ETYPE_RC4,
    format_asrep_hash,
    format_tgs_hash,
)


def test_asrep_rc4_format():
    cipher = bytes([0x11]) * 32
    h = format_asrep_hash(ETYPE_RC4, "alice", "corp.local", cipher)
    assert h.startswith("$krb5asrep$23$alice@CORP.LOCAL:")
    checksum, data = h.split(":", 1)[1].split("$")
    assert checksum == "11" * 16     # first 16 bytes
    assert data == "11" * 16         # remaining bytes


def test_tgs_rc4_layout():
    cipher = bytes([0xAB]) * 40
    h = format_tgs_hash(ETYPE_RC4, "svc_sql", "corp.local", "MSSQL/db.corp.local", cipher)
    assert h.startswith("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQL/db.corp.local*$")
    tail = h.split("*$", 1)[1]
    checksum, data = tail.split("$")
    assert checksum == "ab" * 16     # RC4: checksum at the front
    assert data == "ab" * 24


def test_tgs_aes_layout():
    # AES puts the 12-byte checksum at the tail
    cipher = bytes(range(30))
    h = format_tgs_hash(ETYPE_AES256, "svc", "corp.local", "HTTP/web", cipher)
    tail = h.split("*$", 1)[1]
    checksum, data = tail.split("$")
    assert len(checksum) == 12 * 2   # trailing 12 bytes
    assert len(data) == (30 - 12) * 2
    assert h.startswith("$krb5tgs$18$*svc$CORP.LOCAL$HTTP/web*$")
