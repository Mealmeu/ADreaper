"""Active Directory trust enumeration.

Reads the `trustedDomain` objects in the domain and turns them into TRUSTS edges
plus honest risk findings. Trusts are the seams attackers cross between domains
and forests; the security-relevant question is almost never "does a trust exist"
but "is SID filtering enforced, which way does it flow, and is it still on RC4".

LDAP-only recon (no exploitation). Pairs with `analysis/pathfinder`, which will
happily walk a freshly discovered TRUSTS edge into a partner domain.
"""

from __future__ import annotations

import struct
from typing import Any

from adreaper.core.context import EngagementContext
from adreaper.core.graph import EdgeType, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# trustDirection
TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
# trustType
TRUST_TYPE = {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 3: "MIT (Kerberos realm)", 4: "DCE"}

# trustAttributes bit flags (MS-ADTS 6.1.6.7.9)
TA_NON_TRANSITIVE = 0x1
TA_UPLEVEL_ONLY = 0x2
TA_QUARANTINED_DOMAIN = 0x4        # SID filtering ENABLED
TA_FOREST_TRANSITIVE = 0x8
TA_CROSS_ORGANIZATION = 0x10
TA_WITHIN_FOREST = 0x20
TA_TREAT_AS_EXTERNAL = 0x40
TA_USES_RC4_ENCRYPTION = 0x80
TA_CROSS_ORG_NO_TGT_DELEGATION = 0x200
TA_PIM_TRUST = 0x400

_ATTR_NAMES = [
    (TA_NON_TRANSITIVE, "NON_TRANSITIVE"),
    (TA_UPLEVEL_ONLY, "UPLEVEL_ONLY"),
    (TA_QUARANTINED_DOMAIN, "QUARANTINED (SID filtering)"),
    (TA_FOREST_TRANSITIVE, "FOREST_TRANSITIVE"),
    (TA_CROSS_ORGANIZATION, "CROSS_ORGANIZATION"),
    (TA_WITHIN_FOREST, "WITHIN_FOREST"),
    (TA_TREAT_AS_EXTERNAL, "TREAT_AS_EXTERNAL"),
    (TA_USES_RC4_ENCRYPTION, "USES_RC4"),
    (TA_PIM_TRUST, "PIM_TRUST"),
]


class TrustEnum(BaseModule):
    name = "recon/trust_enum"
    description = "Enumerate AD domain/forest trusts and flag SID-filtering / RC4 risk."
    author = "Mealmeu"
    category = "recon"
    requires = ["ldap3"]
    references = [
        "https://attack.mitre.org/techniques/T1482/",
        "https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/",
    ]
    options = [
        Option("target", "DC host/IP to bind (defaults to --dc-ip / engagement target)",
               type=OptionType.STRING),
        Option("ssl", "Use LDAPS (port 636)", default=False, type=OptionType.BOOL),
        Option("port", "LDAP port (default 389, or 636 with ssl)", type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no DC target (use --dc-ip or --target)").finish()

        from ldap3 import ALL, ANONYMOUS, NTLM, SUBTREE, Connection, Server  # type: ignore
        from ldap3.core.exceptions import LDAPException  # type: ignore

        use_ssl = bool(self.opt("ssl"))
        port = int(self.opt("port") or (636 if use_ssl else 389))
        cred = ctx.credential
        try:
            server = Server(target, port=port, use_ssl=use_ssl, get_info=ALL,
                            connect_timeout=ctx.timeout)
            if cred.is_empty:
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
            else:
                user = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
                conn = Connection(server, user=user,
                                  password=cred.normalized_hash() or cred.password,
                                  authentication=NTLM, auto_bind=True)
        except LDAPException as e:
            return res.fail(f"LDAP bind failed: {e}").finish()
        except Exception as e:
            return res.fail(f"LDAP connection error: {e}").finish()

        base_dn = _base_dn(server, ctx.domain)
        if not base_dn:
            return res.fail("could not determine base DN").finish()

        domain_id = (ctx.domain or base_dn).upper()
        ctx.graph.add_node(domain_id, NodeType.DOMAIN, ctx.domain or base_dn, {"dn": base_dn})

        try:
            conn.search(base_dn, "(objectClass=trustedDomain)", search_scope=SUBTREE,
                        attributes=["trustPartner", "flatName", "trustDirection",
                                    "trustType", "trustAttributes", "securityIdentifier"])
            entries = list(conn.entries)
        except Exception as e:
            return res.fail(f"trust search failed: {e}").finish()

        if not entries:
            res.add_finding("No domain trusts found", Severity.INFO,
                            description="This domain has no outbound/inbound trust relationships.")
            return res.finish()

        log.ok("found %d trust(s)", len(entries))
        for e in entries:
            self._handle_trust(ctx, res, domain_id, e)
        res.data["trusts"] = len(entries)
        return res.finish()

    def _handle_trust(self, ctx, res, domain_id, entry) -> None:
        a = entry.entry_attributes_as_dict
        partner = _first(a, "trustPartner") or _first(a, "flatName") or "?"
        direction = _as_int(_first(a, "trustDirection"))
        ttype = _as_int(_first(a, "trustType"))
        attributes = _as_int(_first(a, "trustAttributes"))
        sid = _sid_str(_first(a, "securityIdentifier"))

        labels, findings = assess_trust(partner, direction, ttype, attributes)

        partner_id = sid or partner.upper()
        ctx.graph.add_node(partner_id, NodeType.DOMAIN, partner,
                           {"sid": sid, "foreign": True})
        props = {"direction": labels["direction"], "type": labels["type"],
                 "sid_filtering": labels["sid_filtering"]}
        # Edge direction: bidirectional/outbound => we trust partner (source=us).
        if direction in (2, 3):
            ctx.graph.add_edge(domain_id, partner_id, EdgeType.TRUSTS, props)
        if direction in (1, 3):
            ctx.graph.add_edge(partner_id, domain_id, EdgeType.TRUSTS, props)

        res.add_finding(
            f"Trust: {partner} [{labels['direction']}, {labels['type']}]",
            Severity.INFO,
            description=f"SID filtering: {labels['sid_filtering']}; "
                        f"attributes: {', '.join(labels['flags']) or 'none'}.",
            target=partner,
        )
        for f in findings:
            res.add_finding(f["title"], Severity(f["severity"]),
                            description=f["description"],
                            target=partner,
                            references=["https://attack.mitre.org/techniques/T1134/005/"])


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def attribute_flags(mask: int) -> list[str]:
    return [name for bit, name in _ATTR_NAMES if mask & bit]


def assess_trust(partner: str, direction: int, ttype: int, attributes: int):
    """Return (labels, findings). `findings` are risk dicts; labels are display strings."""
    within_forest = bool(attributes & TA_WITHIN_FOREST)
    forest_transitive = bool(attributes & TA_FOREST_TRANSITIVE)
    quarantined = bool(attributes & TA_QUARANTINED_DOMAIN)
    uses_rc4 = bool(attributes & TA_USES_RC4_ENCRYPTION)
    # Intra-forest trusts don't use SID filtering by design; it's "enabled" there.
    sid_filtering = within_forest or quarantined

    labels = {
        "direction": TRUST_DIRECTION.get(direction, f"Unknown({direction})"),
        "type": TRUST_TYPE.get(ttype, f"Unknown({ttype})"),
        "sid_filtering": "enabled" if sid_filtering else "DISABLED",
        "flags": attribute_flags(attributes),
    }

    findings: list[dict] = []
    inbound = direction in (1, 3)

    if not sid_filtering and forest_transitive:
        findings.append({
            "severity": "HIGH", "code": "SID_FILTER_FOREST",
            "title": f"Forest trust to {partner} without SID filtering",
            "description": "SID history injection across this forest trust can forge "
                           "membership in privileged groups (e.g. Enterprise Admins).",
        })
    elif not sid_filtering and not within_forest:
        findings.append({
            "severity": "MEDIUM", "code": "SID_FILTER_EXTERNAL",
            "title": f"External trust to {partner} without SID filtering",
            "description": "Without quarantine (SID filtering), a compromised partner "
                           "domain can inject SID history to escalate into this domain.",
        })

    if uses_rc4:
        findings.append({
            "severity": "LOW", "code": "RC4",
            "title": f"Trust with {partner} still negotiates RC4",
            "description": "RC4 trust keys are weak and ease cross-realm ticket attacks; "
                           "prefer AES.",
        })

    if inbound and not sid_filtering:
        findings.append({
            "severity": "LOW", "code": "INBOUND_SURFACE",
            "title": f"Inbound trust from {partner} widens attack surface",
            "description": "Principals from the partner can authenticate into this domain.",
        })

    return labels, findings


def _base_dn(server, domain: str) -> str:
    try:
        dnc = server.info.other.get("defaultNamingContext")
        if dnc:
            return dnc[0] if isinstance(dnc, (list, tuple)) else str(dnc)
    except Exception:
        pass
    if domain:
        return ",".join(f"DC={p}" for p in domain.split("."))
    return ""


def _first(a: dict, key: str, default: str = "") -> Any:
    v = a.get(key)
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v if v is not None else default


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _sid_str(raw: Any) -> str:
    if raw is None or raw == "":
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        return _decode_sid(bytes(raw))
    return str(raw)


def _decode_sid(b: bytes) -> str:
    if len(b) < 8:
        return ""
    revision, sub_count = b[0], b[1]
    authority = int.from_bytes(b[2:8], "big")
    sid = f"S-{revision}-{authority}"
    for i in range(sub_count):
        off = 8 + i * 4
        if off + 4 > len(b):
            break
        sid += "-" + str(struct.unpack("<I", b[off:off + 4])[0])
    return sid
