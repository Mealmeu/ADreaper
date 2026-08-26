"""LDAP enumeration — the backbone recon module.

Binds to a domain controller (anonymous, password, or pass-the-hash over NTLM),
enumerates users / groups / computers / the domain object, and pushes them into
the shared attack graph with MemberOf edges. Along the way it flags the classic
low-hanging AD misconfigurations: AS-REP-roastable accounts, Kerberoastable
service accounts, unconstrained delegation, and a permissive machine account
quota.
"""

from __future__ import annotations

import struct
from typing import Any, Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import EdgeType, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# userAccountControl bit flags
UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UAC_PASSWD_NOTREQD = 0x0020

# well-known privileged RIDs / SIDs
HIGH_VALUE_RIDS = {512, 516, 518, 519, 520, 548, 549}
HIGH_VALUE_SIDS = {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551"}


class LdapEnum(BaseModule):
    name = "recon/ldap_enum"
    description = "Enumerate users/groups/computers over LDAP and build the attack graph."
    author = "Mealmeu"
    category = "recon"
    requires = ["ldap3"]
    references = [
        "https://attack.mitre.org/techniques/T1087/002/",
        "https://attack.mitre.org/techniques/T1558/003/",
    ]
    options = [
        Option("target", "DC host/IP to bind (defaults to --dc-ip / engagement target)",
               type=OptionType.STRING),
        Option("ssl", "Use LDAPS (port 636)", default=False, type=OptionType.BOOL),
        Option("port", "LDAP port (default 389, or 636 with ssl)", type=OptionType.INT),
        Option("page_size", "LDAP paged search size", default=500, type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no DC target (use --dc-ip or --target)").finish()

        from ldap3 import ALL, ANONYMOUS, NTLM, Connection, Server  # type: ignore
        from ldap3.core.exceptions import LDAPException  # type: ignore

        use_ssl = bool(self.opt("ssl"))
        port = int(self.opt("port") or (636 if use_ssl else 389))
        cred = ctx.credential

        try:
            server = Server(target, port=port, use_ssl=use_ssl, get_info=ALL,
                            connect_timeout=ctx.timeout)
            if cred.is_empty:
                log.info("LDAP anonymous bind to %s:%d", target, port)
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
            else:
                user = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
                secret = cred.normalized_hash() or cred.password
                log.info("LDAP NTLM bind as %s to %s:%d", user, target, port)
                conn = Connection(server, user=user, password=secret,
                                  authentication=NTLM, auto_bind=True)
        except LDAPException as e:
            return res.fail(f"LDAP bind failed: {e}").finish()
        except Exception as e:
            return res.fail(f"LDAP connection error: {e}").finish()

        base_dn = _base_dn(server, ctx.domain)
        if not base_dn:
            return res.fail("could not determine base DN").finish()
        log.ok("bound; base DN = %s", base_dn)

        domain_id = (ctx.domain or base_dn).upper()
        ctx.graph.add_node(domain_id, NodeType.DOMAIN, ctx.domain or base_dn, {"dn": base_dn})

        page = int(self.opt("page_size", 500))
        dn_to_sid: dict[str, str] = {}

        self._enum_domain_policy(conn, base_dn, ctx, res, domain_id)
        n_groups = self._enum_groups(conn, base_dn, ctx, res, page, dn_to_sid)
        n_users = self._enum_users(conn, base_dn, ctx, res, page, dn_to_sid, domain_id)
        n_comps = self._enum_computers(conn, base_dn, ctx, res, page, dn_to_sid, domain_id)

        # Second pass: wire MemberOf edges now that DN->SID is fully known.
        self._wire_membership(conn, base_dn, ctx, page, dn_to_sid)

        log.ok("enumerated %d users, %d groups, %d computers", n_users, n_groups, n_comps)
        res.data.update({"users": n_users, "groups": n_groups, "computers": n_comps})
        try:
            conn.unbind()
        except Exception:
            pass
        return res.finish()

    # -- domain policy ----------------------------------------------------

    def _enum_domain_policy(self, conn, base_dn, ctx, res, domain_id) -> None:
        from ldap3 import BASE  # type: ignore

        attrs = ["ms-DS-MachineAccountQuota", "minPwdLength", "lockoutThreshold",
                 "maxPwdAge", "objectSid"]
        try:
            conn.search(base_dn, "(objectClass=domain)", search_scope=BASE, attributes=attrs)
        except Exception as e:
            log.warn("domain policy read failed: %s", e)
            return
        if not conn.response:
            return
        a = _attrs(conn.response[0])
        maq = _as_int(_first(a, "ms-DS-MachineAccountQuota"))
        sid = _sid_str(_first(a, "objectSid"))
        lt = _as_int(_first(a, "lockoutThreshold"))
        dom_node = ctx.graph.get(domain_id)
        if dom_node is not None:
            if sid:
                dom_node.properties["sid"] = sid
            # stash policy on the domain node so credentials modules can be lockout-safe
            dom_node.properties["lockout_threshold"] = lt
            dom_node.properties["machine_account_quota"] = maq
        res.data["domain_policy"] = {
            "machine_account_quota": maq,
            "min_pwd_length": _as_int(_first(a, "minPwdLength")),
            "lockout_threshold": lt,
        }
        if maq and maq > 0:
            res.add_finding(
                "MachineAccountQuota allows domain-user computer creation",
                Severity.MEDIUM,
                description=(
                    f"ms-DS-MachineAccountQuota = {maq}. Any authenticated user can join "
                    f"up to {maq} computer account(s), enabling RBCD and noPac-style attacks. "
                    "Set it to 0 and delegate machine creation explicitly."
                ),
                target=ctx.domain,
                references=["https://attack.mitre.org/techniques/T1078/"],
            )
        lt = _as_int(_first(a, "lockoutThreshold"))
        if lt == 0:
            res.add_finding(
                "No account lockout policy",
                Severity.LOW,
                description="lockoutThreshold = 0: passwords can be sprayed without lockout.",
                target=ctx.domain,
            )

    # -- groups -----------------------------------------------------------

    def _enum_groups(self, conn, base_dn, ctx, res, page, dn_to_sid) -> int:
        attrs = ["sAMAccountName", "objectSid", "distinguishedName", "adminCount"]
        count = 0
        for entry in _paged(conn, base_dn, "(objectClass=group)", attrs, page):
            a = _attrs(entry)
            dn = entry["dn"]
            sid = _sid_str(_first(a, "objectSid"))
            name = _first(a, "sAMAccountName") or _rdn(dn)
            node_id = sid or dn.upper()
            dn_to_sid[dn.upper()] = node_id
            rid = _rid(sid)
            high = (rid in HIGH_VALUE_RIDS) or (sid in HIGH_VALUE_SIDS)
            ctx.graph.add_node(node_id, NodeType.GROUP, name, {
                "dn": dn, "sid": sid, "high_value": high,
                "admin_count": bool(_as_int(_first(a, "adminCount"))),
            })
            count += 1
        return count

    # -- users ------------------------------------------------------------

    def _enum_users(self, conn, base_dn, ctx, res, page, dn_to_sid, domain_id) -> int:
        attrs = ["sAMAccountName", "objectSid", "distinguishedName", "userAccountControl",
                 "servicePrincipalName", "adminCount", "description"]
        filt = "(&(objectCategory=person)(objectClass=user))"
        count = 0
        for entry in _paged(conn, base_dn, filt, attrs, page):
            a = _attrs(entry)
            dn = entry["dn"]
            sid = _sid_str(_first(a, "objectSid"))
            sam = _first(a, "sAMAccountName") or _rdn(dn)
            uac = _as_int(_first(a, "userAccountControl"))
            spns = _as_list(a.get("servicePrincipalName"))
            disabled = bool(uac & UAC_ACCOUNTDISABLE)
            node_id = sid or dn.upper()
            dn_to_sid[dn.upper()] = node_id
            asrep_roastable = bool(uac & UAC_DONT_REQ_PREAUTH)
            kerberoastable = bool(spns) and sam.lower() != "krbtgt"
            props = {
                "dn": dn, "sid": sid, "enabled": not disabled,
                "spn": spns, "admin_count": bool(_as_int(_first(a, "adminCount"))),
                "description": _first(a, "description"),
                "dont_require_preauth": asrep_roastable,
                "kerberoastable": kerberoastable,
            }
            ctx.graph.add_node(node_id, NodeType.USER, sam, props)
            count += 1

            # -- findings --
            if (uac & UAC_DONT_REQ_PREAUTH) and not disabled:
                res.add_finding(
                    f"AS-REP roastable account: {sam}",
                    Severity.HIGH,
                    description=("Kerberos pre-authentication is disabled; an AS-REP hash can be "
                                 "requested offline and cracked without any credentials."),
                    target=sam,
                    references=["https://attack.mitre.org/techniques/T1558/004/"],
                )
            if spns and sam.lower() != "krbtgt" and not disabled:
                res.add_finding(
                    f"Kerberoastable account: {sam}",
                    Severity.HIGH,
                    description="User account has a servicePrincipalName; its TGS can be roasted offline.",
                    evidence="\n".join(spns),
                    target=sam,
                    references=["https://attack.mitre.org/techniques/T1558/003/"],
                )
            if (uac & UAC_TRUSTED_FOR_DELEGATION) and not disabled:
                res.add_finding(
                    f"Account trusted for unconstrained delegation: {sam}",
                    Severity.HIGH,
                    description="Compromise yields TGTs of any user that authenticates to it.",
                    target=sam,
                    references=["https://attack.mitre.org/techniques/T1558/"],
                )
            if (uac & UAC_PASSWD_NOTREQD) and not disabled:
                res.add_finding(
                    f"Account does not require a password: {sam}",
                    Severity.MEDIUM, target=sam,
                )
        return count

    # -- computers --------------------------------------------------------

    def _enum_computers(self, conn, base_dn, ctx, res, page, dn_to_sid, domain_id) -> int:
        attrs = ["sAMAccountName", "objectSid", "distinguishedName", "dNSHostName",
                 "operatingSystem", "userAccountControl"]
        count = 0
        for entry in _paged(conn, base_dn, "(objectClass=computer)", attrs, page):
            a = _attrs(entry)
            dn = entry["dn"]
            sid = _sid_str(_first(a, "objectSid"))
            sam = _first(a, "sAMAccountName") or _rdn(dn)
            uac = _as_int(_first(a, "userAccountControl"))
            node_id = sid or dn.upper()
            dn_to_sid[dn.upper()] = node_id
            unconstrained = bool(uac & UAC_TRUSTED_FOR_DELEGATION)
            ctx.graph.add_node(node_id, NodeType.COMPUTER, sam.rstrip("$"), {
                "dn": dn, "sid": sid, "dns": _first(a, "dNSHostName"),
                "os": _first(a, "operatingSystem"), "unconstrained_delegation": unconstrained,
            })
            count += 1
            if unconstrained:
                res.add_finding(
                    f"Computer trusted for unconstrained delegation: {sam}",
                    Severity.HIGH,
                    description=("Any user (including Domain Admins) authenticating to this host "
                                 "leaves a usable TGT in its memory."),
                    target=sam,
                    references=["https://attack.mitre.org/techniques/T1558/"],
                )
        return count

    # -- membership edges -------------------------------------------------

    def _wire_membership(self, conn, base_dn, ctx, page, dn_to_sid) -> None:
        """Add MemberOf edges for users, groups, and computers (nested groups included)."""
        attrs = ["memberOf", "distinguishedName"]
        filt = "(|(objectClass=user)(objectClass=group)(objectClass=computer))"
        edges = 0
        for entry in _paged(conn, base_dn, filt, attrs, page):
            a = _attrs(entry)
            src_dn = entry["dn"].upper()
            src = dn_to_sid.get(src_dn)
            if not src:
                continue
            for grp_dn in _as_list(a.get("memberOf")):
                dst = dn_to_sid.get(grp_dn.upper())
                if dst:
                    ctx.graph.add_edge(src, dst, EdgeType.MEMBER_OF)
                    edges += 1
        if edges:
            log.info("added %d MemberOf edges", edges)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _base_dn(server, domain: str) -> str:
    """Determine the search base: defaultNamingContext, else a DC context, else
    derive it from the domain name."""
    try:
        dnc = server.info.other.get("defaultNamingContext")
        if dnc:
            return dnc[0] if isinstance(dnc, (list, tuple)) else str(dnc)
    except Exception:
        pass
    try:
        for nc in (server.info.naming_contexts or []):
            if str(nc).upper().startswith("DC="):
                return str(nc)
    except Exception:
        pass
    if domain:
        return ",".join(f"DC={p}" for p in domain.split("."))
    return ""


def _paged(conn, base_dn, filt, attrs, page):
    """Yield searchResEntry dicts via ldap3 paged search."""
    from ldap3 import SUBTREE  # type: ignore

    try:
        gen = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=filt, search_scope=SUBTREE,
            attributes=attrs, paged_size=page, generator=True,
        )
    except Exception as e:
        log.warn("paged search failed for %s: %s", filt, e)
        return
    for entry in gen:
        if entry.get("type") == "searchResEntry":
            yield entry


def _attrs(entry: dict) -> dict:
    return entry.get("attributes", {}) or {}


def _first(a: dict, key: str, default: str = "") -> Any:
    v = a.get(key)
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v if v is not None else default


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _rdn(dn: str) -> str:
    return dn.split(",", 1)[0].split("=", 1)[-1] if dn else ""


def _sid_str(raw: Any) -> str:
    """Return a canonical S-1-5-... string from ldap3 output (str or raw bytes)."""
    if raw is None or raw == "":
        return ""
    if isinstance(raw, str):
        return raw if raw.startswith("S-1-") else raw
    if isinstance(raw, (bytes, bytearray)):
        return _decode_sid(bytes(raw))
    return str(raw)


def _decode_sid(b: bytes) -> str:
    if len(b) < 8:
        return ""
    revision = b[0]
    sub_count = b[1]
    authority = int.from_bytes(b[2:8], "big")
    sid = f"S-{revision}-{authority}"
    for i in range(sub_count):
        off = 8 + i * 4
        if off + 4 > len(b):
            break
        sid += "-" + str(struct.unpack("<I", b[off:off + 4])[0])
    return sid


def _rid(sid: str) -> Optional[int]:
    if not sid or "-" not in sid:
        return None
    try:
        return int(sid.rsplit("-", 1)[-1])
    except ValueError:
        return None
