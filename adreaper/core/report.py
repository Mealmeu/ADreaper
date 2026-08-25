"""Reporting engine.

Aggregates `ModuleResult`s plus the engagement graph into engagement artifacts:
a human-readable Markdown report, a machine-readable JSON results file, and the
serialized attack graph. Everything lands under the per-domain loot directory.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from adreaper.core.context import EngagementContext
from adreaper.core.module import ModuleResult, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


class Report:
    """Collects module results across a run and renders the artifacts."""

    def __init__(self) -> None:
        self.results: list[ModuleResult] = []

    def add(self, result: ModuleResult) -> None:
        self.results.append(result)

    # -- rendering --------------------------------------------------------

    def _all_findings(self):
        findings = []
        for r in self.results:
            findings.extend(r.findings)
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
        return findings

    def to_markdown(self, ctx: EngagementContext) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: list[str] = []
        lines.append(f"# ADreaper engagement report — {ctx.domain or 'unknown domain'}")
        lines.append("")
        lines.append(f"*Generated {now} · authorized assessment*")
        lines.append("")
        lines.append("## Engagement")
        lines.append("")
        lines.append(f"- **Domain:** {ctx.domain or '—'}")
        lines.append(f"- **DC / target:** {ctx.primary_target() or '—'}")
        lines.append(f"- **Identity:** {ctx.credential.display()}")
        lines.append(f"- **Modules run:** {len(self.results)}")
        lines.append("")

        # Findings summary table
        findings = self._all_findings()
        by_sev: dict[Severity, int] = {s: 0 for s in _SEV_ORDER}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        lines.append("## Findings summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for s in _SEV_ORDER:
            lines.append(f"| {_SEV_EMOJI[s]} {s.value} | {by_sev.get(s, 0)} |")
        lines.append("")

        # Graph stats
        counts = ctx.graph.counts()
        if len(ctx.graph):
            lines.append("## Attack graph")
            lines.append("")
            lines.append("| Object | Count |")
            lines.append("|--------|-------|")
            for k, v in counts.items():
                lines.append(f"| {k} | {v} |")
            lines.append("")

        # Detailed findings
        if findings:
            lines.append("## Findings")
            lines.append("")
            for f in findings:
                lines.append(f"### {_SEV_EMOJI[f.severity]} {f.title}")
                lines.append("")
                if f.target:
                    lines.append(f"- **Target:** `{f.target}`")
                lines.append(f"- **Severity:** {f.severity.value}")
                if f.description:
                    lines.append("")
                    lines.append(f.description)
                if f.evidence:
                    lines.append("")
                    lines.append("```")
                    lines.append(f.evidence.rstrip())
                    lines.append("```")
                if f.references:
                    lines.append("")
                    lines.append("References: " + ", ".join(f.references))
                lines.append("")

        # Per-module log
        lines.append("## Module run log")
        lines.append("")
        lines.append("| Module | Result | Findings | Time |")
        lines.append("|--------|--------|----------|------|")
        for r in self.results:
            status = "✅ ok" if r.success else f"❌ {r.error or 'failed'}"
            lines.append(f"| `{r.module}` | {status} | {len(r.findings)} | {r.duration:.1f}s |")
        lines.append("")
        return "\n".join(lines)

    def to_json(self, ctx: EngagementContext) -> dict:
        return {
            "domain": ctx.domain,
            "target": ctx.primary_target(),
            "identity": ctx.credential.display(),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "graph_counts": ctx.graph.counts(),
            "results": [r.to_dict() for r in self.results],
        }

    def write(self, ctx: EngagementContext) -> dict[str, Path]:
        """Write report.md, results.json, and graph.json. Returns their paths."""
        loot = ctx.loot_dir()
        md_path = loot / "report.md"
        json_path = loot / "results.json"
        graph_path = loot / "graph.json"

        md_path.write_text(self.to_markdown(ctx), encoding="utf-8")
        json_path.write_text(json.dumps(self.to_json(ctx), indent=2), encoding="utf-8")
        if len(ctx.graph):
            ctx.graph.save(graph_path)

        out = {"report": md_path, "results": json_path}
        if len(ctx.graph):
            out["graph"] = graph_path
        return out
