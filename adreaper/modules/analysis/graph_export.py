"""Render the attack graph to Mermaid and Graphviz DOT for quick visualisation.

BloodHound is the heavyweight way to look at the graph; sometimes you just want
a picture. This emits:

- `graph.mmd`  — Mermaid `flowchart` (paste into any Markdown viewer / mermaid.live)
- `graph.dot`  — Graphviz DOT (`dot -Tsvg graph.dot -o graph.svg`)

Nodes are shaped by kind and tinted when they're high-value or owned; edges carry
the relationship label (MemberOf, AdminTo, ReadLAPSPassword, ...). On a large
graph it focuses on the interesting core — high-value and owned principals plus
their immediate neighbours — so the diagram stays readable.

Pure transformation of the in-memory graph; no network, no external deps.
"""

from __future__ import annotations

from adreaper.core.context import EngagementContext
from adreaper.core.graph import ADGraph, Edge, Node, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# Mermaid node templates and class per node kind
_MERMAID_SHAPE = {
    NodeType.USER: '{id}("{label}")',
    NodeType.GROUP: '{id}["{label}"]',
    NodeType.COMPUTER: '{id}(["{label}"])',
    NodeType.DOMAIN: '{id}{{{{"{label}"}}}}',
}
_CLASSDEFS = [
    "classDef user fill:#e8f0fe,stroke:#4285f4,color:#1a1a1a;",
    "classDef group fill:#fff4e5,stroke:#d24b16,color:#1a1a1a;",
    "classDef computer fill:#e9f7ef,stroke:#2e8b57,color:#1a1a1a;",
    "classDef domain fill:#f3e8fd,stroke:#8b5cf6,color:#1a1a1a;",
    "classDef other fill:#eef1f4,stroke:#6b7280,color:#1a1a1a;",
    "classDef hv fill:#ffd9df,stroke:#b3123b,color:#1a1a1a,stroke-width:3px;",
    "classDef owned fill:#fde68a,stroke:#b45309,color:#1a1a1a,stroke-width:3px;",
]
_CLASS_FOR = {
    NodeType.USER: "user", NodeType.GROUP: "group",
    NodeType.COMPUTER: "computer", NodeType.DOMAIN: "domain",
}
_DOT_COLOR = {
    NodeType.USER: "#4285f4", NodeType.GROUP: "#d24b16",
    NodeType.COMPUTER: "#2e8b57", NodeType.DOMAIN: "#8b5cf6",
}


class GraphExport(BaseModule):
    name = "analysis/graph_export"
    description = "Export the attack graph as Mermaid and Graphviz DOT diagrams."
    author = "Mealmeu"
    category = "analysis"
    requires = []  # pure transformation
    references = ["https://mermaid.js.org/", "https://graphviz.org/"]
    options = [
        Option("format", "mermaid | dot | both", default="both", type=OptionType.STRING,
               choices=["mermaid", "dot", "both"]),
        Option("max_nodes", "Focus the diagram when the graph exceeds this", default=60,
               type=OptionType.INT),
        Option("graph", "Load graph.json if the live graph is empty", type=OptionType.STRING),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        graph = self._resolve_graph(ctx)
        if graph is None or len(graph) == 0:
            return res.fail("graph is empty — run recon first, or -o graph=<graph.json>").finish()

        max_nodes = int(self.opt("max_nodes", 60))
        nodes, edges = select_relevant(graph, max_nodes)
        focused = len(nodes) < len(graph.nodes)
        fmt = self.opt("format", "both")
        loot = ctx.loot_dir()
        written = []

        if fmt in ("mermaid", "both"):
            p = loot / "graph.mmd"
            p.write_text(to_mermaid(nodes, edges), encoding="utf-8")
            written.append(p)
        if fmt in ("dot", "both"):
            p = loot / "graph.dot"
            p.write_text(to_dot(nodes, edges), encoding="utf-8")
            written.append(p)

        log.ok("graph diagram: %d node(s), %d edge(s)%s -> %s",
               len(nodes), len(edges), " (focused)" if focused else "",
               ", ".join(p.name for p in written))
        res.data.update({"nodes": len(nodes), "edges": len(edges), "focused": focused,
                         "files": [str(p) for p in written]})
        res.add_finding(
            f"Attack-graph diagram exported ({len(nodes)} nodes, {len(edges)} edges)",
            Severity.INFO,
            description="Render graph.mmd at mermaid.live or `dot -Tsvg graph.dot -o graph.svg`."
                        + (" Focused on high-value/owned core." if focused else ""),
        )
        return res.finish()

    def _resolve_graph(self, ctx: EngagementContext):
        if len(ctx.graph):
            return ctx.graph
        gpath = self.opt("graph") or ""
        if not gpath:
            candidate = ctx.loot_dir() / "graph.json"
            gpath = str(candidate) if candidate.exists() else ""
        if gpath:
            from pathlib import Path
            if Path(gpath).exists():
                ctx.graph.merge(ADGraph.load(gpath))
        return ctx.graph if len(ctx.graph) else None


# ---------------------------------------------------------------------------
# pure transformation (unit-tested)
# ---------------------------------------------------------------------------

def select_relevant(graph: ADGraph, max_nodes: int) -> tuple[list[Node], list[Edge]]:
    """Return (nodes, edges) to draw. All of it if small; else the high-value /
    owned core plus their immediate neighbours, capped at max_nodes."""
    all_nodes = graph.nodes
    if len(all_nodes) <= max_nodes:
        keep_ids = {n.id for n in all_nodes}
        return all_nodes, [e for e in graph.edges if e.source in keep_ids and e.target in keep_ids]

    seeds = {n.id for n in graph.high_value_nodes()} | {n.id for n in graph.owned_nodes()}
    keep = set(seeds)
    for e in graph.edges:
        if e.source in seeds or e.target in seeds:
            keep.add(e.source)
            keep.add(e.target)
        if len(keep) >= max_nodes:
            break
    keep = set(list(keep)[:max_nodes])
    nodes = [n for n in all_nodes if n.id in keep]
    edges = [e for e in graph.edges if e.source in keep and e.target in keep]
    return nodes, edges


def to_mermaid(nodes: list[Node], edges: list[Edge]) -> str:
    idmap = {n.id: f"n{i}" for i, n in enumerate(nodes)}
    lines = ["flowchart LR"]
    classed: list[tuple[str, str]] = []
    for n in nodes:
        nid = idmap[n.id]
        tmpl = _MERMAID_SHAPE.get(n.type, '{id}["{label}"]')
        lines.append("  " + tmpl.format(id=nid, label=_mermaid_label(n.name)))
        classed.append((nid, _mermaid_class(n)))
    for e in edges:
        s, t = idmap.get(e.source), idmap.get(e.target)
        if s and t:
            lines.append(f"  {s} -->|{_mermaid_label(e.type.value)}| {t}")
    for nid, cls in classed:
        lines.append(f"  class {nid} {cls};")
    lines.extend("  " + c for c in _CLASSDEFS)
    return "\n".join(lines) + "\n"


def to_dot(nodes: list[Node], edges: list[Edge]) -> str:
    idmap = {n.id: f"n{i}" for i, n in enumerate(nodes)}
    lines = ["digraph adreaper {", '  rankdir=LR;',
             '  node [style=filled,fontname="Helvetica",shape=box];']
    for n in nodes:
        nid = idmap[n.id]
        fill, pen = _dot_style(n)
        lines.append(f'  {nid} [label="{_dot_label(n.name)}",fillcolor="{fill}"'
                     f',color="{pen}",shape={_dot_shape(n.type)}];')
    for e in edges:
        s, t = idmap.get(e.source), idmap.get(e.target)
        if s and t:
            lines.append(f'  {s} -> {t} [label="{_dot_label(e.type.value)}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


# -- label / style helpers --------------------------------------------------

def _mermaid_label(s: str) -> str:
    return str(s).replace('"', "'").replace("\n", " ").replace("|", "/")


def _mermaid_class(n: Node) -> str:
    if n.properties.get("owned"):
        return "owned"
    if n.properties.get("high_value"):
        return "hv"
    return _CLASS_FOR.get(n.type, "other")


def _dot_label(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _dot_shape(t: NodeType) -> str:
    return {NodeType.USER: "ellipse", NodeType.COMPUTER: "box3d",
            NodeType.DOMAIN: "hexagon"}.get(t, "box")


def _dot_style(n: Node) -> tuple[str, str]:
    if n.properties.get("owned"):
        return "#fde68a", "#b45309"
    if n.properties.get("high_value"):
        return "#ffd9df", "#b3123b"
    base = _DOT_COLOR.get(n.type, "#6b7280")
    return "#eef1f4", base
