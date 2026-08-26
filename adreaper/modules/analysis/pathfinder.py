"""Attack-path finder — the BloodHound "shortest path to Domain Admin" idea.

Walks the collected graph from a set of *start* principals (the accounts you
control, or one you name) to *high-value* targets (Domain Admins & friends, or a
target you name) and reports the shortest privilege-escalation paths it finds.

It reads whatever edges the collectors have produced — in v0.x that's group
membership, so it surfaces nested-group paths into privileged groups. As ACL /
session / delegation edges are added by future modules, the same search reports
richer paths with no code change here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import ADGraph, Node, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class PathFinder(BaseModule):
    name = "analysis/pathfinder"
    description = "Find shortest privilege-escalation paths to high-value targets."
    author = "Mealmeu"
    category = "analysis"
    requires = []  # pure graph analysis, no external deps
    references = ["https://bloodhound.readthedocs.io/"]
    options = [
        Option("start", "Start principal name/SID (default: owned accounts, else all users)",
               type=OptionType.STRING),
        Option("goal", "Target principal name/SID (default: all high-value nodes)",
               type=OptionType.STRING),
        Option("graph", "Load graph.json from this path if the live graph is empty",
               type=OptionType.STRING),
        Option("max_paths", "Maximum paths to report", default=25, type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        graph = self._resolve_graph(ctx)
        if graph is None or len(graph) == 0:
            return res.fail(
                "graph is empty — run recon/ldap_enum first, or pass -o graph=<graph.json>"
            ).finish()

        starts = self._resolve_starts(graph)
        goals = self._resolve_goals(graph)
        if not starts:
            return res.fail("no start principals found").finish()
        if not goals:
            return res.fail("no high-value targets found (try -o goal=<name>)").finish()

        log.info("searching paths: %d start(s) -> %d goal(s)", len(starts), len(goals))
        max_paths = int(self.opt("max_paths", 25))

        found: list[tuple[int, str, list]] = []  # (length, rendered, raw_path)
        seen_pairs = set()
        for s in starts:
            for g in goals:
                if s.id == g.id or (s.id, g.id) in seen_pairs:
                    continue
                seen_pairs.add((s.id, g.id))
                path = graph.shortest_path(s.id, g.id)
                if path and len(path) > 1:
                    found.append((len(path), render_path(graph, path), path))

        found.sort(key=lambda x: x[0])
        found = found[:max_paths]

        if not found:
            res.add_finding(
                "No attack paths found to high-value targets",
                Severity.INFO,
                description="With the currently collected edges, no path reaches a high-value "
                            "target. Collect more edges (ACLs, sessions, delegation) to deepen this.",
            )
            return res.finish()

        for length, rendered, _ in found:
            hops = length - 1
            sev = Severity.CRITICAL if hops <= 2 else Severity.HIGH
            res.add_finding(
                f"Attack path ({hops} hop{'s' if hops != 1 else ''}): {rendered.splitlines()[0]}",
                sev,
                description=f"A {hops}-hop path leads to a high-value target.",
                evidence=rendered,
                references=["https://attack.mitre.org/tactics/TA0004/"],
            )
        res.data["paths"] = [r for _, r, _ in found]
        log.ok("found %d attack path(s) to high-value targets", len(found))

        # Persist a readable paths file next to the report.
        try:
            out = ctx.loot_dir() / "attack_paths.txt"
            out.write_text("\n\n".join(r for _, r, _ in found), encoding="utf-8")
            log.ok("paths -> %s", out)
        except Exception as e:
            log.debug("could not write paths file: %s", e)

        return res.finish()

    # -- helpers ----------------------------------------------------------

    def _resolve_graph(self, ctx: EngagementContext) -> Optional[ADGraph]:
        if len(ctx.graph):
            return ctx.graph
        gpath = self.opt("graph")
        if not gpath:
            # try the conventional location for this domain
            candidate = ctx.loot_dir() / "graph.json"
            gpath = str(candidate) if candidate.exists() else ""
        if gpath and Path(gpath).exists():
            log.info("loading graph from %s", gpath)
            loaded = ADGraph.load(gpath)
            ctx.graph.merge(loaded)
            return ctx.graph
        return ctx.graph if len(ctx.graph) else None

    def _resolve_starts(self, graph: ADGraph) -> list[Node]:
        start = self.opt("start")
        if start:
            return _lookup(graph, start)
        owned = graph.owned_nodes()
        if owned:
            return owned
        return graph.nodes_of(NodeType.USER)

    def _resolve_goals(self, graph: ADGraph) -> list[Node]:
        goal = self.opt("goal")
        if goal:
            return _lookup(graph, goal)
        return graph.high_value_nodes()


def _lookup(graph: ADGraph, ident: str) -> list[Node]:
    n = graph.get(ident)
    if n:
        return [n]
    return graph.find(ident)


def render_path(graph: ADGraph, path: list[tuple[str, str]]) -> str:
    """Render a path as `alice -[MemberOf]-> IT -[MemberOf]-> Domain Admins`."""
    parts: list[str] = []
    for i, (node_id, edge) in enumerate(path):
        node = graph.get(node_id)
        label = node.name if node else node_id
        if i == 0:
            parts.append(label)
        else:
            parts.append(f" -[{edge}]-> {label}")
    return "".join(parts)
