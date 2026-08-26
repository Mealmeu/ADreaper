"""Session and local-admin edge collector (HasSession / AdminTo).

Touches each target host to answer the two questions that turn a flat inventory
into a real attack graph:

- **HasSession** — who is logged on where (SRVSVC NetrSessionEnum). Compromising
  a host yields the credentials/tickets of everyone with a live session on it.
- **AdminTo** — which principals are local administrators of a host (SAMR local
  Administrators alias). These are the direct lateral-movement edges.

Both need network access to the host and usually valid domain credentials. This
is host-touching recon, so keep it scoped to authorized targets.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import EdgeType, Node, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

LOCAL_ADMIN_RID = 544  # BUILTIN\Administrators


class SessionEnum(BaseModule):
    name = "recon/session_enum"
    description = "Collect HasSession and AdminTo edges by touching target hosts."
    author = "Mealmeu"
    category = "recon"
    requires = ["impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1049/",
        "https://attack.mitre.org/techniques/T1069/001/",
    ]
    options = [
        Option("target", "Host(s) to query, comma-separated (default: graph computers)",
               type=OptionType.STRING),
        Option("method", "sessions | localadmin | both", default="both",
               type=OptionType.STRING, choices=["sessions", "localadmin", "both"]),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        targets = self._targets(ctx)
        if not targets:
            return res.fail(
                "no targets: run recon/ldap_enum/smb_enum first, or pass -o target=host1,host2"
            ).finish()
        method = self.opt("method", "both")
        log.info("session/admin enum on %d host(s) [%s]", len(targets), method)

        stats = {"sessions": 0, "adminto": 0, "hosts": 0}
        for address, node in targets:
            stats["hosts"] += 1
            if method in ("sessions", "both"):
                stats["sessions"] += self._sessions(ctx, address, node, res)
            if method in ("localadmin", "both"):
                stats["adminto"] += self._local_admins(ctx, address, node, res)

        log.ok("collected %d HasSession + %d AdminTo edge(s) across %d host(s)",
               stats["sessions"], stats["adminto"], stats["hosts"])
        res.data.update(stats)
        return res.finish()

    # -- targets ----------------------------------------------------------

    def _targets(self, ctx: EngagementContext) -> list[tuple[str, Node]]:
        raw = self.opt("target")
        out: list[tuple[str, Node]] = []
        if raw:
            for host in [h.strip() for h in raw.split(",") if h.strip()]:
                node = _find_computer(ctx, host) or ctx.graph.add_node(
                    host.upper(), NodeType.COMPUTER, host, {"ip": host})
                out.append((host, node))
            return out
        for n in ctx.graph.nodes_of(NodeType.COMPUTER):
            addr = n.properties.get("ip") or n.properties.get("dns") or n.name
            if addr:
                out.append((str(addr), n))
        return out

    # -- HasSession (SRVSVC) ---------------------------------------------

    def _sessions(self, ctx, address, node, res) -> int:
        from impacket.dcerpc.v5 import srvs, transport  # type: ignore
        from impacket.dcerpc.v5.rpcrt import DCERPCException  # type: ignore

        cred = ctx.credential
        lm, nt = _hashes(cred)
        added = 0
        try:
            rpc = transport.SMBTransport(address, 445, r"\srvsvc", cred.username, cred.password,
                                         cred.domain, lm, nt)
            rpc.set_connect_timeout(ctx.timeout)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrSessionEnum(dce, NULL="\x00", clientName=NULL_STR, userName=NULL_STR, level=10)
        except (DCERPCException, Exception) as e:
            log.debug("session enum on %s failed: %s", address, e)
            return 0
        try:
            for s in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                username = _clean(s["sesi10_username"])
                if not username or username.endswith("$"):
                    continue
                user_node = _match_user(ctx, username)
                if user_node:
                    ctx.graph.add_edge(node.id, user_node.id, EdgeType.HAS_SESSION,
                                       {"host": address})
                    added += 1
        except Exception as e:
            log.debug("parsing sessions on %s failed: %s", address, e)
        if added:
            res.add_finding(
                f"{added} user session(s) on {node.name}",
                Severity.LOW,
                description="Compromising this host exposes the tokens/credentials of these sessions.",
                target=node.name,
            )
        return added

    # -- AdminTo (SAMR local Administrators) -----------------------------

    def _local_admins(self, ctx, address, node, res) -> int:
        from impacket.dcerpc.v5 import samr, transport  # type: ignore

        cred = ctx.credential
        lm, nt = _hashes(cred)
        added = 0
        try:
            rpc = transport.SMBTransport(address, 445, r"\samr", cred.username, cred.password,
                                         cred.domain, lm, nt)
            rpc.set_connect_timeout(ctx.timeout)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            member_sids = _samr_local_admins(samr, dce)
        except Exception as e:
            log.debug("local-admin enum on %s failed: %s", address, e)
            return 0
        for sid in member_sids:
            principal = ctx.graph.get(sid)
            if principal is None:
                continue
            ctx.graph.add_edge(principal.id, node.id, EdgeType.ADMIN_TO, {"host": address})
            added += 1
        if added:
            res.add_finding(
                f"{added} local administrator principal(s) on {node.name}",
                Severity.MEDIUM,
                description="These principals can move laterally to / fully control this host.",
                target=node.name,
            )
        return added


# ---------------------------------------------------------------------------
# impacket SAMR helper (kept isolated; imports passed in)
# ---------------------------------------------------------------------------

def _samr_local_admins(samr, dce) -> list[str]:
    """Return SIDs of the BUILTIN\\Administrators alias members on the host."""
    sids: list[str] = []
    conn = samr.hSamrConnect(dce)
    handle = conn["ServerHandle"]
    # enumerate domains; the builtin domain hosts the Administrators alias
    domains = samr.hSamrEnumerateDomainsInSamServer(dce, handle)["Buffer"]["Buffer"]
    for d in domains:
        name = d["Name"]
        sid_resp = samr.hSamrLookupDomainInSamServer(dce, handle, name)
        domain_sid = sid_resp["DomainId"]
        dom = samr.hSamrOpenDomain(dce, handle, domainId=domain_sid)
        dom_handle = dom["DomainHandle"]
        try:
            alias = samr.hSamrOpenAlias(dce, dom_handle, aliasId=LOCAL_ADMIN_RID)
        except Exception:
            continue
        members = samr.hSamrGetMembersInAlias(dce, alias["AliasHandle"])
        for m in members["Members"]["Sids"]:
            try:
                sids.append(m["SidPointer"].formatCanonical())
            except Exception:
                continue
    return sids


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

NULL_STR = "\x00"


def _clean(v) -> str:
    s = str(v) if v is not None else ""
    return s.replace("\x00", "").strip()


def _hashes(cred) -> tuple[str, str]:
    norm = cred.normalized_hash()
    if norm:
        lm, nt = norm.split(":", 1)
        return lm, nt
    return "", ""


def _match_user(ctx, username: str) -> Optional[Node]:
    """Match a session username (possibly DOMAIN\\user or user@dom) to a graph user."""
    name = username.split("\\")[-1].split("@")[0].strip().lower()
    for n in ctx.graph.nodes_of(NodeType.USER):
        if n.name.lower() == name:
            return n
    return None


def _find_computer(ctx, host: str) -> Optional[Node]:
    h = host.lower()
    for n in ctx.graph.nodes_of(NodeType.COMPUTER):
        if h in (n.name.lower(), n.name.lower() + "$",
                 str(n.properties.get("dns", "")).lower(),
                 str(n.properties.get("ip", "")).lower()):
            return n
    return None
