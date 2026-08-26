from adreaper.core import loader
from adreaper.modules.credentials.gpp_decrypt import (
    decrypt_cpassword,
    extract_credentials,
)

# Public MS14-025 test vectors.
VECTORS = {
    "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw": "Local*P4ssword!",
    "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ":
        "GPPstillStandingStrong2k18",
}

GROUPS_XML = """<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)"
        changed="2015-02-13 06:00:00" uid="{D5FE7352}">
    <Properties action="U" newName="" fullName="" description=""
      cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
      changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0"
      userName="Administrator (built-in)"/>
  </User>
</Groups>"""


def test_decrypt_known_vectors():
    for blob, expected in VECTORS.items():
        assert decrypt_cpassword(blob) == expected


def test_decrypt_empty_is_empty():
    assert decrypt_cpassword("") == ""


def test_extract_from_groups_xml():
    creds = extract_credentials(GROUPS_XML)
    assert len(creds) == 1
    c = creds[0]
    assert c["user"] == "Administrator (built-in)"
    assert c["plaintext"] == "Local*P4ssword!"
    assert c["source"] == "local user/group"


def test_extract_ignores_files_without_cpassword():
    xml = '<Groups><User><Properties userName="x" action="U"/></User></Groups>'
    assert extract_credentials(xml) == []


def test_extract_handles_garbage():
    assert extract_credentials("not xml at all") == []
    assert extract_credentials("") == []


def test_module_discovered():
    assert "credentials/gpp_decrypt" in loader.discover(force=True)
