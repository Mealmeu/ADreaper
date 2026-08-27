"""GPO enumeration and GpLink mapping.

Group Policy is a favourite escalation vector: whoever can *edit* a GPO controls
every user and computer in the OUs it is linked to (scripts, scheduled tasks,
restricted groups, immediate installs). This module:

- inventories every `groupPolicyContainer` as a GPO node,
- parses each OU / domain `gPLink` into GpLink edges (honouring enforced/disabled
  link flags),
- reads each GPO's DACL and turns *edit* rights held by non-privileged principals
  into control edges, flagging the ones whose GPO is actually linked somewhere.

Once the GpLink and control edges are in the graph, `analysis/pathfinder` can walk
"low-priv user -> GenericWrite -> GPO -> GpLink -> OU (full of computers)".

Read-only LDAP recon. Run `recon/ldap_enum` first so principals resolve.
"""

from __future__ import annotations

import re
from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import HIGH_VALUE_NAMES as _HV
from adreaper.core.graph import EdgeType, Node, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity
from adreaper.modules.recon.acl_enum import ACE_ALLOWED, ACE_ALLOWED_OBJECT, mask_edges

# gPLink option flags
GPLINK_DISABLED = 0x1
GPLINK_ENFORCED = 0x2

# edges that mean "can modify this GPO"
_EDIT_EDGES = {EdgeType.GENERIC_ALL, EdgeType.GENERIC_WRITE,
               EdgeType.WRITE_DACL, EdgeType.WRITE_OWNER}

SKIP_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9"}
SKIP_RIDS = {512, 516, 518, 519, 520}

_GPLINK_BLOCK = re.compile(r"\[(?P<url>[^\]]+)\]")


class GpoEnum(BaseModule):
    name = "recon/gpo_enum"
    description = "Enumerate GPOs, GpLink edges, and who can edit each GPO."
    author = "Mealmeu"
    category = "recon"
    requires = ["ldap3", "impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1484/001/",
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
        domain_id = (ctx.domain or base_dn).upper()
        ctx.graph.add_node(domain_id, NodeType.DOMAIN, ctx.domain or base_dn, {"dn": base_dn})
        page = int(self.opt("page_size", 500))
        controls = security_descriptor_control(sdflags=0x04)
        sid_index = {n.id: n for n in ctx.graph.nodes if n.id.startswith("S-1-")}

        # 1) GPO inventory (keep SD raw + DN->node for later)
        gpo_by_dn: dict[str, Node] = {}
        gpo_sd: dict[str, bytes] = {}
        n_gpo = self._enum_gpos(conn, base_dn, page, controls, ctx, gpo_by_dn, gpo_sd)

        # 2) container gPLinks -> GpLink edges
        linked_gpo_ids: dict[str, list[str]] = {}
        n_links = self._enum_links(conn, base_dn, page, ctx, domain_id, gpo_by_dn, linked_gpo_ids)

        # 3) GPO DACLs -> edit control edges + findings
        n_edges = 0
        for dn, gpo in gpo_by_dn.items():
            n_edges += self._process_gpo_sd(ctx, res, gpo, gpo_sd.get(dn, b""),
                                            sid_index, linked_gpo_ids.get(gpo.id, []))

        log.ok("GPOs=%d, GpLink edges=%d, GPO-control edges=%d", n_gpo, n_links, n_edges)
        res.data.update({"gpos": n_gpo, "gplinks": n_links, "control_edges": n_edges})
        if n_gpo == 0:
            res.add_finding("No GPOs found", Severity.INFO)
        return res.finish()

    # -- 1) GPOs ----------------------------------------------------------

    def _enum_gpos(self, conn, base_dn, page, controls, ctx, gpo_by_dn, gpo_sd) -> int:
        count = 0
        for entry in _paged(conn, base_dn, "(objectClass=groupPolicyContainer)",
                            ["displayName", "distinguishedName", "gPCFileSysPath",
                             "objectGUID", "nTSecurityDescriptor"], page, controls):
            a = entry.get("attributes", {}) or {}
            dn = entry.get("dn", "")
            name = _first(a.get("displayName")) or _rdn(dn)
            gid = (_first(a.get("objectGUID")) or dn).upper()
            node = ctx.graph.add_node(gid, NodeType.GPO, str(name),
                                      {"dn": dn, "path": _first(a.get("gPCFileSysPath"))})
            gpo_by_dn[dn.upper()] = node
            sd = _raw(a.get("nTSecurityDescriptor"))
            if sd:
                gpo_sd[dn.upper()] = sd
            count += 1
        return count

    # -- 2) links ---------------------------------------------------------

    def _enum_links(self, conn, base_dn, page, ctx, domain_id, gpo_by_dn, linked) -> int:
        count = 0
        for entry in _paged(conn, base_dn,
                            "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                            ["distinguishedName", "gPLink", "name"], page, None):
            a = entry.get("attributes", {}) or {}
            dn = entry.get("dn", "")
            gplink = _first(a.get("gPLink"))
            if not gplink:
                continue
            container = self._container_node(ctx, dn, domain_id, base_dn,
                                             _first(a.get("name")))
            for link in parse_gplink(gplink):
                if link["disabled"]:
                    continue
                gpo = gpo_by_dn.get(link["dn"].upper())
                if gpo is None:
                    continue
                ctx.graph.add_edge(gpo.id, container.id, EdgeType.GP_LINK,
                                   {"enforced": link["enforced"]})
                linked.setdefault(gpo.id, []).append(container.name)
                count += 1
        return count

    def _container_node(self, ctx, dn, domain_id, base_dn, name) -> Node:
        if dn.upper() == base_dn.upper():
            return ctx.graph.get(domain_id)
        return ctx.graph.add_node(dn.upper(), NodeType.OU, str(name) or _rdn(dn), {"dn": dn})

    # -- 3) GPO control ---------------------------------------------------

    def _process_gpo_sd(self, ctx, res, gpo, sd_raw, sid_index, linked_ous) -> int:
        if not sd_raw:
            return 0
        from impacket.ldap import ldaptypes  # type: ignore
        from impacket.uuid import bin_to_string  # type: ignore

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
            dacl = sd["Dacl"]
        except Exception as e:
            log.debug("GPO SD parse failed for %s: %s", gpo.name, e)
            return 0
        if not dacl:
            return 0

        added = 0
        seen: set[tuple[str, str]] = set()
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
            if not _interesting(trustee, sid_index, gpo.id):
                continue
            guid = None
            if ace_type == ACE_ALLOWED_OBJECT and (body["Flags"] & 0x01):
                try:
                    guid = bin_to_string(body["ObjectType"]).lower()
                except Exception:
                    guid = None
            for etype in mask_edges(ace_type, mask, guid):
                if etype not in _EDIT_EDGES:
                    continue
                key = (trustee.upper(), etype.value)
                if key in seen:
                    continue
                seen.add(key)
                ctx.graph.add_edge(trustee.upper(), gpo.id, etype)
                added += 1
                self._finding(res, sid_index, trustee, gpo, etype, linked_ous)
        return added

    def _finding(self, res, sid_index, trustee, gpo, etype, linked_ous) -> None:
        src = sid_index.get(trustee.upper())
        who = src.name if src else trustee
        if linked_ous:
            res.add_finding(
                f"GPO hijack: {who} can edit '{gpo.name}' (linked to {', '.join(linked_ous)})",
                Severity.HIGH,
                description=f"A non-privileged principal holds {etype.value} over a GPO that is "
                            f"applied to {len(linked_ous)} container(s); editing it yields code "
                            "execution on every user/computer in scope.",
                target=gpo.name,
                references=["https://attack.mitre.org/techniques/T1484/001/"],
            )
        else:
            res.add_finding(
                f"{who} can edit unlinked GPO '{gpo.name}' ({etype.value})",
                Severity.LOW,
                description="The GPO is not currently linked, so impact is latent until it is.",
                target=gpo.name,
            )


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def parse_gplink(gplink: str) -> list[dict]:
    """Parse a gPLink attribute into ordered link dicts.

    gPLink looks like `[LDAP://cn={GUID},...;0][LDAP://server/cn={GUID2},...;2]`
    where the trailing integer is a bit flag: 1 = link disabled, 2 = enforced.
    Returns [{dn, enforced, disabled}] preserving link order.
    """
    out: list[dict] = []
    if not gplink:
        return out
    for m in _GPLINK_BLOCK.finditer(gplink):
        url = m.group("url")
        if ";" not in url:
            continue
        path, _, flags = url.rpartition(";")
        try:
            opt = int(flags.strip())
        except ValueError:
            opt = 0
        dn = path.strip()
        low = dn.lower()
        if low.startswith("ldap://"):
            dn = dn[7:]
            # drop an optional "server/" prefix before the DN
            if "/" in dn and dn.split("/", 1)[0].lower() != "cn=":
                head, _, tail = dn.partition("/")
                if "=" not in head:      # head was a server name, not part of the DN
                    dn = tail
        out.append({
            "dn": dn.strip(),
            "disabled": bool(opt & GPLINK_DISABLED),
            "enforced": bool(opt & GPLINK_ENFORCED),
        })
    return out


def _interesting(sid: str, sid_index: dict, object_id: str) -> bool:
    if not sid or sid.upper() == object_id.upper():
        return False
    if sid in SKIP_SIDS:
        return False
    if _rid(sid) in SKIP_RIDS:
        return False
    node = sid_index.get(sid.upper())
    if node is None:
        return False
    if node.properties.get("high_value") or node.name.lower() in _HV:
        return False
    return True


def _rid(sid: str) -> Optional[int]:
    try:
        return int(sid.rsplit("-", 1)[-1])
    except (ValueError, AttributeError):
        return None


def _paged(conn, base_dn, filt, attrs, page, controls):
    from ldap3 import SUBTREE  # type: ignore
    try:
        gen = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=filt, search_scope=SUBTREE,
            attributes=attrs, paged_size=page, generator=True, controls=controls,
        )
    except Exception as e:
        log.warn("paged search failed for %s: %s", filt, e)
        return
    for entry in gen:
        if entry.get("type") == "searchResEntry":
            yield entry


def _first(v, default=""):
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v if v is not None else default


def _raw(v) -> bytes:
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return b""


def _rdn(dn: str) -> str:
    return dn.split(",", 1)[0].split("=", 1)[-1] if dn else ""


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
