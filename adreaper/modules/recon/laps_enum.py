"""LAPS readable-password audit.

LAPS (Local Administrator Password Solution) randomises each machine's local
admin password and stores it on the computer object — legacy LAPS in the
confidential `ms-Mcs-AdmPwd` attribute, Windows LAPS in `msLAPS-Password` /
`msLAPS-EncryptedPassword`. Reading it is gated by the computer object's DACL, so
the real question this module answers is: **which principals can read the LAPS
password of which machines** — every unexpected reader is a lateral-movement edge
to local admin on that host.

It resolves the (environment-specific) LAPS attribute GUIDs from the schema,
then walks each computer's security descriptor for principals granted the read.
Read-only LDAP recon; nothing is modified. Run `recon/ldap_enum` first so the
computer nodes exist.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import HIGH_VALUE_NAMES as _HV
from adreaper.core.graph import EdgeType, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# ACE types
ACE_ALLOWED = 0x00
ACE_ALLOWED_OBJECT = 0x05

# access-mask bits
RIGHT_GENERIC_ALL = 0x10000000
RIGHT_DS_CONTROL_ACCESS = 0x00000100
RIGHT_DS_READ_PROP = 0x00000010

# LAPS attribute lDAPDisplayNames we resolve to schemaIDGUIDs
LAPS_ATTRS = ["ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"]

# system / apex trustees whose read access is expected, not a finding
SKIP_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9"}
SKIP_RIDS = {512, 516, 518, 519, 520}


class LapsEnum(BaseModule):
    name = "recon/laps_enum"
    description = "Audit which principals can read LAPS local-admin passwords."
    author = "Mealmeu"
    category = "recon"
    requires = ["ldap3", "impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1552/",
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html",
    ]
    options = [
        Option("target", "DC host/IP to bind (defaults to --dc-ip)", type=OptionType.STRING),
        Option("ssl", "Use LDAPS (port 636)", default=False, type=OptionType.BOOL),
        Option("port", "LDAP port (default 389, or 636 with ssl)", type=OptionType.INT),
        Option("page_size", "LDAP paged search size", default=500, type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no DC target (use --dc-ip or --target)").finish()

        from ldap3 import ALL, ANONYMOUS, NTLM, SUBTREE, Connection, Server  # type: ignore
        from ldap3.core.exceptions import LDAPException  # type: ignore
        from ldap3.protocol.microsoft import security_descriptor_control  # type: ignore

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
        config_nc = _config_nc(server, ctx.domain)
        schema_nc = f"CN=Schema,{config_nc}"

        laps_guids, kinds = self._resolve_laps_guids(conn, schema_nc, SUBTREE)
        if not laps_guids:
            res.add_finding("LAPS not deployed (schema has no LAPS attribute)", Severity.INFO,
                            description="No ms-Mcs-AdmPwd or msLAPS-Password attribute in the schema; "
                                        "local admin passwords are likely static/shared — a separate risk.")
            return res.finish()
        log.ok("LAPS present: %s", ", ".join(sorted(kinds)))

        controls = security_descriptor_control(sdflags=0x04)  # DACL
        page = int(self.opt("page_size", 500))
        sid_index = {n.id: n for n in ctx.graph.nodes if n.id.startswith("S-1-")}

        stats = {"managed": 0, "computers": 0, "reader_edges": 0}
        try:
            entries = conn.extend.standard.paged_search(
                search_base=base_dn, search_filter="(objectClass=computer)",
                search_scope=SUBTREE, paged_size=page, generator=True, controls=controls,
                attributes=["distinguishedName", "sAMAccountName", "objectSid",
                            "nTSecurityDescriptor", "ms-Mcs-AdmPwdExpirationTime",
                            "msLAPS-PasswordExpirationTime"],
            )
        except Exception as e:
            return res.fail(f"computer search failed: {e}").finish()

        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry.get("attributes", {}) or {}
            stats["computers"] += 1
            managed = bool(_first(a.get("ms-Mcs-AdmPwdExpirationTime"))
                           or _first(a.get("msLAPS-PasswordExpirationTime")))
            if managed:
                stats["managed"] += 1
            comp = self._computer_node(ctx, a, entry.get("dn", ""), managed)
            if comp is None:
                continue
            readers = self._sd_readers(_raw(a.get("nTSecurityDescriptor")), laps_guids)
            for sid in readers:
                if not _interesting(sid, comp.id):
                    continue
                ctx.graph.add_edge(sid.upper(), comp.id, EdgeType.READ_LAPS_PASSWORD)
                stats["reader_edges"] += 1
                who = sid_index.get(sid.upper())
                name = who.name if who else sid
                if who is None or not _is_expected(who):
                    res.add_finding(
                        f"LAPS password of {comp.name} readable by {name}",
                        Severity.HIGH,
                        description="This principal can read the LAPS-managed local administrator "
                                    "password of the computer — a direct path to local admin on it.",
                        target=comp.name,
                        references=["https://attack.mitre.org/techniques/T1552/"],
                    )

        if stats["managed"] == 0:
            res.add_finding("LAPS schema present but no managed computers found", Severity.MEDIUM,
                            description="The LAPS attributes exist but no computer carries a password "
                                        "expiration time — LAPS may not be applied to any host.")
        log.ok("LAPS: %d/%d computers managed; %d reader edge(s)",
               stats["managed"], stats["computers"], stats["reader_edges"])
        res.data.update(stats)
        return res.finish()

    # -- schema resolution ------------------------------------------------

    def _resolve_laps_guids(self, conn, schema_nc, scope):
        from impacket.uuid import bin_to_string  # type: ignore

        guids: set[str] = set()
        kinds: set[str] = set()
        for attr in LAPS_ATTRS:
            try:
                conn.search(schema_nc, f"(lDAPDisplayName={attr})", search_scope=scope,
                            attributes=["schemaIDGUID"])
            except Exception as e:
                log.debug("schema lookup for %s failed: %s", attr, e)
                continue
            for entry in conn.response:
                if entry.get("type") != "searchResEntry":
                    continue
                raw = _raw(entry["attributes"].get("schemaIDGUID"))
                if raw:
                    try:
                        guids.add(bin_to_string(raw).lower())
                        kinds.add(attr)
                    except Exception:
                        continue
        return guids, kinds

    def _computer_node(self, ctx, a, dn, managed):
        sid = _sid_of(a.get("objectSid"))
        node = ctx.graph.get(sid) if sid else None
        name = _first(a.get("sAMAccountName")) or _rdn(dn)
        if node is None and sid:
            node = ctx.graph.add_node(sid, NodeType.COMPUTER, name.rstrip("$"), {"dn": dn})
        if node is not None:
            node.properties["laps"] = managed
        return node

    def _sd_readers(self, sd_raw: bytes, laps_guids: set) -> list[str]:
        """Return trustee SIDs that can read a LAPS attribute on this object."""
        if not sd_raw:
            return []
        from impacket.ldap import ldaptypes  # type: ignore
        from impacket.uuid import bin_to_string  # type: ignore

        out: list[str] = []
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
            dacl = sd["Dacl"]
            if not dacl:
                return out
            for ace in dacl["Data"]:
                ace_type = ace["AceType"]
                if ace_type not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
                    continue
                body = ace["Ace"]
                try:
                    mask = int(body["Mask"]["Mask"])
                    sid = body["Sid"].formatCanonical()
                except Exception:
                    continue
                guid = None
                if ace_type == ACE_ALLOWED_OBJECT and (body["Flags"] & 0x01):
                    try:
                        guid = bin_to_string(body["ObjectType"]).lower()
                    except Exception:
                        guid = None
                if can_read_laps(ace_type, mask, guid, laps_guids):
                    out.append(sid)
        except Exception as e:
            log.debug("LAPS SD parse failed: %s", e)
        return out


# ---------------------------------------------------------------------------
# pure logic (unit-tested)
# ---------------------------------------------------------------------------

def can_read_laps(ace_type: int, mask: int, guid: Optional[str], laps_guids) -> bool:
    """Decide whether one allowed ACE grants read of a confidential LAPS attribute.

    The LAPS password attribute is confidential, so reading it requires either
    full control, all-extended-rights / control-access, or an explicit
    control-access / read-property grant targeting the LAPS attribute GUID.
    """
    if ace_type not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
        return False
    laps = {g.lower() for g in laps_guids}
    g = guid.lower() if guid else None

    if mask & RIGHT_GENERIC_ALL:
        return True
    # all-extended-rights (control access with no specific object type)
    if (mask & RIGHT_DS_CONTROL_ACCESS) and g is None:
        return True
    if g in laps:
        if mask & (RIGHT_DS_CONTROL_ACCESS | RIGHT_DS_READ_PROP):
            return True
    return False


def _is_expected(node) -> bool:
    """High-value principals reading LAPS is expected (admins), not a finding."""
    return bool(node.properties.get("high_value") or node.name.lower() in _HV)


def _interesting(sid: str, object_id: str) -> bool:
    if not sid or sid.upper() == object_id.upper():
        return False
    if sid in SKIP_SIDS:
        return False
    rid = _rid(sid)
    return rid not in SKIP_RIDS


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _rid(sid: str) -> Optional[int]:
    try:
        return int(sid.rsplit("-", 1)[-1])
    except (ValueError, AttributeError):
        return None


def _first(v, default=""):
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v if v is not None else default


def _sid_of(v) -> str:
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    return str(v) if v is not None else ""


def _rdn(dn: str) -> str:
    return dn.split(",", 1)[0].split("=", 1)[-1] if dn else ""


def _raw(v) -> bytes:
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return b""


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


def _config_nc(server, domain: str) -> str:
    try:
        cnc = server.info.other.get("configurationNamingContext")
        if cnc:
            return cnc[0] if isinstance(cnc, (list, tuple)) else str(cnc)
    except Exception:
        pass
    dc = ",".join(f"DC={p}" for p in domain.split("."))
    return f"CN=Configuration,{dc}"
