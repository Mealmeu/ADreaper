"""ACL / delegation edge collector — the enrichment that makes attack paths real.

recon/ldap_enum builds the nodes and group-membership edges. This module reads
each object's `nTSecurityDescriptor` (DACL) plus the delegation attributes and
turns *control* relationships into graph edges: GenericAll, WriteDacl,
WriteOwner, ForceChangePassword, AddMember, AllExtendedRights, Owns, DCSync,
constrained delegation (AllowedToDelegate) and RBCD (AddAllowedToAct).

Once these land in the graph, analysis/pathfinder walks them for free — a
low-priv user with `GenericAll` on a privileged group becomes a one-hop path to
Domain Admin with no code change in the finder.

Run recon/ldap_enum first so the nodes exist; this module wires edges onto them.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import HIGH_VALUE_NAMES as _HV
from adreaper.core.graph import EdgeType, Node, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# ---- ACE types (MS-DTYP) --------------------------------------------------
ACE_ALLOWED = 0x00
ACE_ALLOWED_OBJECT = 0x05

# ---- access-mask bits -----------------------------------------------------
RIGHT_GENERIC_ALL = 0x10000000
RIGHT_GENERIC_WRITE = 0x40000000
RIGHT_WRITE_DACL = 0x00040000
RIGHT_WRITE_OWNER = 0x00080000
RIGHT_DS_CONTROL_ACCESS = 0x00000100
RIGHT_DS_WRITE_PROP = 0x00000020
# combined object full-control bits often seen instead of GENERIC_ALL
RIGHT_DS_FULL_CONTROL = 0x000F01FF

# ---- well-known rights / property GUIDs (lowercase) -----------------------
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"

# trustees whose control is uninteresting for privesc (system / self / already-apex)
SKIP_SIDS = {"S-1-5-18", "S-1-5-10", "S-1-3-0", "S-1-5-9", "S-1-5-32-544"}
SKIP_RIDS = {512, 516, 518, 519, 520}  # Domain/Enterprise/Schema Admins, DCs, GPC owners


class AclEnum(BaseModule):
    name = "recon/acl_enum"
    description = "Collect ACL, delegation, RBCD and DCSync control edges into the graph."
    author = "Mealmeu"
    category = "recon"
    requires = ["ldap3", "impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1222/001/",
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
        if len(ctx.graph) == 0:
            return res.fail("graph is empty — run recon/ldap_enum first").finish()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no DC target (use --dc-ip or --target)").finish()

        from ldap3 import ALL, ANONYMOUS, NTLM, Connection, Server  # type: ignore
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
        controls = security_descriptor_control(sdflags=0x07)  # owner+group+dacl, no SACL
        attrs = ["distinguishedName", "objectSid", "nTSecurityDescriptor",
                 "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo",
                 "sAMAccountName"]
        page = int(self.opt("page_size", 500))

        sid_index = {n.id: n for n in ctx.graph.nodes if n.id.startswith("S-1-")}
        dn_index = {str(n.properties.get("dn", "")).upper(): n
                    for n in ctx.graph.nodes if n.properties.get("dn")}

        log.info("collecting ACL/delegation edges (base %s)", base_dn)
        stats = {"acl": 0, "owns": 0, "dcsync": 0, "rbcd": 0, "delegate": 0, "objects": 0}

        try:
            entries = conn.extend.standard.paged_search(
                search_base=base_dn, search_filter="(objectClass=*)",
                search_scope="SUBTREE", attributes=attrs, paged_size=page,
                generator=True, controls=controls,
            )
        except Exception as e:
            return res.fail(f"ACL search failed: {e}").finish()

        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry.get("attributes", {}) or {}
            dn = entry["dn"]
            obj = self._resolve_object(a, dn, sid_index, dn_index)
            if obj is None:
                continue
            stats["objects"] += 1
            is_domain = dn.upper() == base_dn.upper() or obj.type == NodeType.DOMAIN

            sd_raw = _raw(a.get("nTSecurityDescriptor"))
            if sd_raw:
                self._process_sd(ctx, obj, sd_raw, sid_index, res, stats, is_domain)

            self._process_delegation(ctx, obj, a, sid_index, dn_index, res, stats)

        try:
            conn.unbind()
        except Exception:
            pass

        edges_added = stats["acl"] + stats["owns"] + stats["dcsync"] + stats["rbcd"] + stats["delegate"]
        log.ok("processed %d objects; added %d control edge(s) [acl=%d owns=%d dcsync=%d rbcd=%d deleg=%d]",
               stats["objects"], edges_added, stats["acl"], stats["owns"],
               stats["dcsync"], stats["rbcd"], stats["delegate"])
        res.data.update(stats)
        res.data["edges_added"] = edges_added
        return res.finish()

    # -- object / trustee resolution -------------------------------------

    def _resolve_object(self, a, dn, sid_index, dn_index) -> Optional[Node]:
        sid = _sid_of(a.get("objectSid"))
        if sid and sid.upper() in sid_index:
            return sid_index[sid.upper()]
        return dn_index.get(dn.upper())

    # -- security descriptor ---------------------------------------------

    def _process_sd(self, ctx, obj, sd_raw, sid_index, res, stats, is_domain) -> None:
        from impacket.ldap import ldaptypes  # type: ignore
        from impacket.uuid import bin_to_string  # type: ignore

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
        except Exception as e:
            log.debug("SD parse failed for %s: %s", obj.name, e)
            return

        # Owner -> Owns
        try:
            owner = sd["OwnerSid"].formatCanonical()
        except Exception:
            owner = None
        if owner and _interesting(owner, sid_index, obj.id):
            ctx.graph.add_edge(owner.upper(), obj.id, EdgeType.OWNS)
            stats["owns"] += 1
            self._maybe_finding(res, sid_index, owner, obj, EdgeType.OWNS)

        dacl = sd["Dacl"]
        if not dacl:
            return
        # per-trustee extended rights, to detect DCSync on the domain object
        ext_rights: dict[str, set[str]] = {}

        for ace in dacl["Data"]:
            ace_type = ace["AceType"]
            if ace_type not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
                continue
            body = ace["Ace"]
            try:
                mask = int(body["Mask"]["Mask"])
                trustee = body["Sid"].formatCanonical()
            except Exception:
                continue
            if not _interesting(trustee, sid_index, obj.id):
                continue

            guid = None
            if ace_type == ACE_ALLOWED_OBJECT and (body["Flags"] & 0x01):
                try:
                    guid = bin_to_string(body["ObjectType"]).lower()
                except Exception:
                    guid = None

            # aggregate extended rights on the domain object for DCSync
            if is_domain and (mask & RIGHT_DS_CONTROL_ACCESS) and guid:
                if guid == GUID_GET_CHANGES:
                    ext_rights.setdefault(trustee.upper(), set()).add("getchanges")
                elif guid == GUID_GET_CHANGES_ALL:
                    ext_rights.setdefault(trustee.upper(), set()).add("getchanges_all")

            for etype in mask_edges(ace_type, mask, guid):
                ctx.graph.add_edge(trustee.upper(), obj.id, etype)
                stats["acl"] += 1
                self._maybe_finding(res, sid_index, trustee, obj, etype)

        # DCSync = GetChanges + GetChangesAll held by the same trustee on the domain
        for trustee, rights in ext_rights.items():
            if is_dcsync(rights) and _interesting(trustee, sid_index, obj.id):
                ctx.graph.add_edge(trustee, obj.id, EdgeType.DC_SYNC)
                stats["dcsync"] += 1
                src = sid_index.get(trustee)
                res.add_finding(
                    f"DCSync rights: {src.name if src else trustee} can replicate domain secrets",
                    Severity.CRITICAL,
                    description="Holds GetChanges + GetChangesAll on the domain; can extract all "
                                "domain password hashes (incl. krbtgt) via DRSUAPI.",
                    target=src.name if src else trustee,
                    references=["https://attack.mitre.org/techniques/T1003/006/"],
                )

    # -- delegation attributes -------------------------------------------

    def _process_delegation(self, ctx, obj, a, sid_index, dn_index, res, stats) -> None:
        # Constrained delegation: this principal -> the target service hosts
        spns = _as_list(a.get("msDS-AllowedToDelegateTo"))
        for spn in spns:
            host = _spn_host(spn)
            target_node = _find_computer(ctx, host)
            if target_node:
                ctx.graph.add_edge(obj.id, target_node.id, EdgeType.ALLOWED_TO_DELEGATE,
                                   {"spn": spn})
                stats["delegate"] += 1
            res.add_finding(
                f"Constrained delegation: {obj.name} -> {spn}",
                Severity.HIGH,
                description="Principal can impersonate users to the target service (S4U2Proxy).",
                target=obj.name,
                references=["https://attack.mitre.org/techniques/T1558/003/"],
            )

        # RBCD: principals listed in msDS-AllowedToActOnBehalfOfOtherIdentity can
        # impersonate to THIS computer.
        rbcd_raw = _raw(a.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
        if rbcd_raw:
            for trustee in _sd_trustees(rbcd_raw):
                if _interesting(trustee, sid_index, obj.id):
                    ctx.graph.add_edge(trustee.upper(), obj.id, EdgeType.ADD_ALLOWED_TO_ACT)
                    stats["rbcd"] += 1
                    src = sid_index.get(trustee.upper())
                    res.add_finding(
                        f"Resource-based constrained delegation to {obj.name}",
                        Severity.HIGH,
                        description=f"{src.name if src else trustee} may impersonate any user to "
                                    f"{obj.name} (RBCD).",
                        target=obj.name,
                        references=["https://attack.mitre.org/techniques/T1558/003/"],
                    )

    # -- findings for control over high-value objects --------------------

    def _maybe_finding(self, res, sid_index, trustee_sid, obj: Node, etype: EdgeType) -> None:
        if not (obj.properties.get("high_value") or obj.name.lower() in _HV):
            return
        src = sid_index.get(trustee_sid.upper())
        if src is not None and (src.properties.get("high_value") or src.name.lower() in _HV):
            return  # admin over admin is expected, not a finding
        who = src.name if src else trustee_sid
        res.add_finding(
            f"Dangerous ACL: {who} has {etype.value} over high-value {obj.name}",
            Severity.HIGH,
            description=f"A non-privileged principal controls a high-value object via {etype.value}; "
                        "this is a direct privilege-escalation edge.",
            target=obj.name,
            references=["https://attack.mitre.org/techniques/T1222/001/"],
        )


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def mask_edges(ace_type: int, mask: int, guid: Optional[str]) -> list[EdgeType]:
    """Map one allowed ACE (type, access mask, optional object GUID) to edges.

    DCSync is intentionally *not* returned here — it requires aggregating two
    extended rights per trustee and is handled by the caller.
    """
    if ace_type not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
        return []
    guid = guid.lower() if guid else None

    # full control subsumes everything else
    if (mask & RIGHT_GENERIC_ALL) or (mask & RIGHT_DS_FULL_CONTROL) == RIGHT_DS_FULL_CONTROL:
        return [EdgeType.GENERIC_ALL]

    edges: list[EdgeType] = []
    if mask & RIGHT_WRITE_DACL:
        edges.append(EdgeType.WRITE_DACL)
    if mask & RIGHT_WRITE_OWNER:
        edges.append(EdgeType.WRITE_OWNER)
    if mask & RIGHT_GENERIC_WRITE:
        edges.append(EdgeType.GENERIC_WRITE)

    if ace_type == ACE_ALLOWED_OBJECT and guid:
        if mask & RIGHT_DS_CONTROL_ACCESS:
            if guid == GUID_FORCE_CHANGE_PASSWORD:
                edges.append(EdgeType.FORCE_CHANGE_PASSWORD)
        if mask & RIGHT_DS_WRITE_PROP:
            if guid == GUID_WRITE_MEMBER:
                edges.append(EdgeType.ADD_MEMBER)
            elif guid == GUID_ALLOWED_TO_ACT:
                edges.append(EdgeType.ADD_ALLOWED_TO_ACT)
    else:
        # non-object allowed ACE granting control-access = all extended rights
        if mask & RIGHT_DS_CONTROL_ACCESS:
            edges.append(EdgeType.ALL_EXTENDED_RIGHTS)
        if mask & RIGHT_DS_WRITE_PROP:
            edges.append(EdgeType.GENERIC_WRITE)
    return edges


def is_dcsync(rights: set[str]) -> bool:
    """DCSync needs both replication rights held by the same trustee."""
    return {"getchanges", "getchanges_all"}.issubset(rights)


def _rid(sid: str) -> Optional[int]:
    try:
        return int(sid.rsplit("-", 1)[-1])
    except (ValueError, AttributeError):
        return None


def _interesting(sid: str, sid_index: dict, object_id: str) -> bool:
    """Only keep control edges from principals we know that aren't system/apex."""
    if not sid:
        return False
    su = sid.upper()
    if su == object_id.upper():
        return False
    if sid in SKIP_SIDS:
        return False
    rid = _rid(sid)
    if rid in SKIP_RIDS:
        return False
    node = sid_index.get(su)
    if node is None:
        return False  # trustee not among enumerated principals
    if node.properties.get("high_value") or node.name.lower() in _HV:
        return False
    return True


def _spn_host(spn: str) -> str:
    # "MSSQLSvc/db.corp.local:1433" -> "db.corp.local"
    part = spn.split("/", 1)[-1]
    return part.split(":", 1)[0].split("/", 1)[0].strip().lower()


def _find_computer(ctx, host: str):
    if not host:
        return None
    for n in ctx.graph.nodes_of(NodeType.COMPUTER):
        dns = str(n.properties.get("dns", "")).lower()
        if host in (n.name.lower(), n.name.lower() + "$", dns):
            return n
    return None


def _raw(v):
    if v is None or v == "":
        return b""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, (list, tuple)) and v:
        first = v[0]
        return bytes(first) if isinstance(first, (bytes, bytearray)) else b""
    return b""


def _sid_of(v):
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if v is None:
        return ""
    return str(v)


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def _sd_trustees(raw: bytes) -> list[str]:
    """Return trustee SIDs from a raw security descriptor's DACL (for RBCD)."""
    from impacket.ldap import ldaptypes  # type: ignore

    out: list[str] = []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        dacl = sd["Dacl"]
        if not dacl:
            return out
        for ace in dacl["Data"]:
            if ace["AceType"] in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
                try:
                    out.append(ace["Ace"]["Sid"].formatCanonical())
                except Exception:
                    continue
    except Exception as e:
        log.debug("RBCD SD parse failed: %s", e)
    return out


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
