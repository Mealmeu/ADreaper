from examples.demo import build_demo, main
from adreaper.core.report import risk_score, severity_counts


def test_build_demo_populates_graph_and_findings():
    ctx, rep = build_demo()
    assert len(ctx.graph) >= 5
    findings = rep._all_findings()
    assert len(findings) >= 6
    _, rating = risk_score(severity_counts(findings))
    assert rating == "Critical"          # the demo includes a DCSync CRITICAL


def test_build_demo_html_has_scoring_and_attack():
    ctx, rep = build_demo()
    html = rep.to_html(ctx)
    assert "Risk score" in html
    assert "Kerberoasting" in html and "DCSync" in html


def test_main_writes_all_artifacts(tmp_path):
    main(tmp_path)
    loot = tmp_path / "corp.local"
    for name in ["report.md", "report.html", "results.json", "graph.json",
                 "graph.mmd", "graph.dot", "corp.local_bloodhound.zip"]:
        assert (loot / name).exists(), f"missing {name}"
