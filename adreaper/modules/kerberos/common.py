"""Pure helpers shared by the Kerberos modules.

Hash formatting is kept dependency-free (stdlib only) so it can be unit-tested
without impacket and without a live KDC. The output strings match the formats
John the Ripper / hashcat expect (asrep = hashcat 18200, tgs = hashcat 13100).
"""

from __future__ import annotations

from binascii import hexlify

# selected Kerberos encryption type numbers
ETYPE_RC4 = 23
ETYPE_AES128 = 17
ETYPE_AES256 = 18


def format_asrep_hash(etype: int, user: str, realm: str, cipher: bytes) -> str:
    """Format an AS-REP encrypted part into a crackable `$krb5asrep$` string."""
    realm = realm.upper()
    checksum = hexlify(cipher[:16]).decode()
    data = hexlify(cipher[16:]).decode()
    return f"$krb5asrep${etype}${user}@{realm}:{checksum}${data}"


def format_tgs_hash(etype: int, user: str, realm: str, spn: str, cipher: bytes) -> str:
    """Format a TGS ticket encrypted part into a crackable `$krb5tgs$` string.

    RC4 keeps the checksum at the front of the cipher; AES puts the 12-byte
    checksum at the tail — hashcat/JtR expect them ordered accordingly.
    """
    realm = realm.upper()
    if etype == ETYPE_RC4:
        checksum = hexlify(cipher[:16]).decode()
        data = hexlify(cipher[16:]).decode()
        return f"$krb5tgs${etype}$*{user}${realm}${spn}*${checksum}${data}"
    # AES128/256 (and any other): checksum is the trailing 12 bytes
    checksum = hexlify(cipher[-12:]).decode()
    data = hexlify(cipher[:-12]).decode()
    return f"$krb5tgs${etype}$*{user}${realm}${spn}*${checksum}${data}"


def crack_hint(kind: str) -> str:
    """One-line cracking hint for the operator."""
    if kind == "asrep":
        return "crack with: hashcat -m 18200 hashes.txt wordlist  |  john --format=krb5asrep"
    return "crack with: hashcat -m 13100 hashes.txt wordlist  |  john --format=krb5tgs"
