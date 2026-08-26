"""Reporting engine.

Aggregates `ModuleResult`s plus the engagement graph into engagement artifacts:
a human-readable Markdown report, a machine-readable JSON results file, and the
serialized attack graph. Everything lands under the per-domain loot directory.
"""

from __future__ import annotations

import html
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
_SEV_COLOR = {
    Severity.CRITICAL: "#b3123b",
    Severity.HIGH: "#d24b16",
    Severity.MEDIUM: "#c08a00",
    Severity.LOW: "#2563a8",
    Severity.INFO: "#6b7280",
}


def _esc(v) -> str:
    return html.escape(str(v), quote=True)


_CSS = """
:root{--bg:#f6f7f9;--fg:#1a1d21;--mut:#5b6470;--card:#ffffff;--line:#e2e6ea;--code:#eef1f4;}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--fg:#e6e9ee;--mut:#9aa4b0;
--card:#171b21;--line:#2a313a;--code:#1e242c;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
main{max-width:940px;margin:0 auto;padding:32px 20px 64px;}
.hdr{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:8px;}
h1{font-size:1.7rem;margin:0;}
h2{font-size:1.15rem;margin:34px 0 12px;border-left:3px solid var(--mut);padding-left:10px;}
h3{font-size:1rem;margin:0;}
.sub{color:var(--mut);margin:6px 0 0;}
table{border-collapse:collapse;width:100%;}
.kv th{ text-align:left;color:var(--mut);font-weight:600;width:180px;padding:5px 10px;vertical-align:top;}
.kv td{padding:5px 10px;}
.cards{display:flex;gap:12px;flex-wrap:wrap;}
.card{flex:1 1 110px;background:var(--card);border:1px solid var(--line);
border-top:3px solid var(--c);border-radius:8px;padding:14px;text-align:center;}
.card .num{font-size:1.9rem;font-weight:700;color:var(--c);}
.card .lbl{color:var(--mut);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;}
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);
border-radius:8px;padding:14px 16px;margin:12px 0;}
.fhdr{display:flex;align-items:center;gap:10px;}
.badge{background:var(--c);color:#fff;font-size:.7rem;font-weight:700;letter-spacing:.05em;
padding:2px 8px;border-radius:20px;white-space:nowrap;}
.meta{color:var(--mut);font-size:.85rem;margin:8px 0 4px;}
code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:.88em;}
pre{background:var(--code);padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:.85rem;}
.refs a{color:var(--c);font-size:.8rem;word-break:break-all;}
.log th{text-align:left;color:var(--mut);border-bottom:1px solid var(--line);padding:6px 8px;}
.log td{padding:6px 8px;border-bottom:1px solid var(--line);}
.log .ok{color:#2e8b57;}.log .bad{color:#c0392b;}
footer{margin-top:40px;color:var(--mut);font-size:.8rem;text-align:center;
border-top:1px solid var(--line);padding-top:16px;}
"""


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

    def to_html(self, ctx: EngagementContext) -> str:
        """Render a self-contained, styled HTML report (no external assets)."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        findings = self._all_findings()
        by_sev: dict[Severity, int] = {s: 0 for s in _SEV_ORDER}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        p: list[str] = []
        p.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
        p.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
        p.append(f"<title>ADreaper report — {_esc(ctx.domain or 'unknown')}</title>")
        p.append(f"<style>{_CSS}</style></head><body><main>")

        p.append("<header class='hdr'>")
        p.append(f"<h1>ADreaper engagement report</h1>")
        p.append(f"<p class='sub'>{_esc(ctx.domain or 'unknown domain')} · generated {_esc(now)} "
                 "· <strong>authorized assessment</strong></p>")
        p.append("</header>")

        # engagement metadata
        p.append("<section><h2>Engagement</h2><table class='kv'>")
        for k, v in [("Domain", ctx.domain or "—"),
                     ("DC / target", ctx.primary_target() or "—"),
                     ("Identity", ctx.credential.display()),
                     ("Modules run", len(self.results))]:
            p.append(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>")
        p.append("</table></section>")

        # severity summary cards
        p.append("<section><h2>Findings summary</h2><div class='cards'>")
        for s in _SEV_ORDER:
            p.append(
                f"<div class='card' style='--c:{_SEV_COLOR[s]}'>"
                f"<div class='num'>{by_sev.get(s, 0)}</div>"
                f"<div class='lbl'>{_esc(s.value)}</div></div>"
            )
        p.append("</div></section>")

        # graph stats
        if len(ctx.graph):
            p.append("<section><h2>Attack graph</h2><table class='kv'>")
            for k, v in ctx.graph.counts().items():
                p.append(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>")
            p.append("</table></section>")

        # detailed findings
        if findings:
            p.append("<section><h2>Findings</h2>")
            for f in findings:
                color = _SEV_COLOR[f.severity]
                p.append(f"<article class='finding' style='--c:{color}'>")
                p.append(f"<div class='fhdr'><span class='badge'>{_esc(f.severity.value)}</span>"
                         f"<h3>{_esc(f.title)}</h3></div>")
                if f.target:
                    p.append(f"<p class='meta'>Target: <code>{_esc(f.target)}</code></p>")
                if f.description:
                    p.append(f"<p>{_esc(f.description)}</p>")
                if f.evidence:
                    p.append(f"<pre>{_esc(f.evidence.rstrip())}</pre>")
                if f.references:
                    links = " · ".join(
                        f"<a href='{_esc(r)}' rel='noreferrer noopener'>{_esc(r)}</a>"
                        for r in f.references
                    )
                    p.append(f"<p class='refs'>{links}</p>")
                p.append("</article>")
            p.append("</section>")

        # module log
        p.append("<section><h2>Module run log</h2><table class='log'>")
        p.append("<thead><tr><th>Module</th><th>Result</th><th>Findings</th><th>Time</th></tr></thead><tbody>")
        for r in self.results:
            status = "ok" if r.success else f"failed: {r.error or '—'}"
            cls = "ok" if r.success else "bad"
            p.append(f"<tr><td><code>{_esc(r.module)}</code></td>"
                     f"<td class='{cls}'>{_esc(status)}</td>"
                     f"<td>{len(r.findings)}</td><td>{r.duration:.1f}s</td></tr>")
        p.append("</tbody></table></section>")

        p.append("<footer>ADreaper · authorized security assessment tooling · MIT</footer>")
        p.append("</main></body></html>")
        return "".join(p)

    def write(self, ctx: EngagementContext) -> dict[str, Path]:
        """Write report.md, results.json, and graph.json. Returns their paths."""
        loot = ctx.loot_dir()
        md_path = loot / "report.md"
        html_path = loot / "report.html"
        json_path = loot / "results.json"
        graph_path = loot / "graph.json"

        md_path.write_text(self.to_markdown(ctx), encoding="utf-8")
        html_path.write_text(self.to_html(ctx), encoding="utf-8")
        json_path.write_text(json.dumps(self.to_json(ctx), indent=2), encoding="utf-8")
        if len(ctx.graph):
            ctx.graph.save(graph_path)

        out = {"report": md_path, "html": html_path, "results": json_path}
        if len(ctx.graph):
            out["graph"] = graph_path
        return out
