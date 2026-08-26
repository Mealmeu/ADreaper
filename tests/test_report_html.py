from adreaper.core.context import Credential, EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.module import ModuleResult, Severity
from adreaper.core.report import Report


def _report():
    r = Report()
    res = ModuleResult(module="adcs/esc_enum")
    res.add_finding("ESC1 on template WebServer", Severity.CRITICAL,
                    description="Requester supplies SAN.", target="WebServer",
                    references=["https://example.test/esc1"])
    res.add_finding("Injection <script>alert(1)</script>", Severity.LOW,
                    evidence="user=alice password='<b>pw</b>'")
    res.finish()
    r.add(res)
    return r


def _ctx():
    ctx = EngagementContext(domain="corp.local", dc_ip="10.0.0.1",
                            credential=Credential(username="svc", domain="CORP", password="x"))
    ctx.graph.add_node("S-1-5-21-1-500", NodeType.USER, "administrator")
    return ctx


def test_html_is_self_contained_and_structured():
    html = _report().to_html(_ctx())
    assert html.startswith("<!doctype html>")
    assert "<title>ADreaper report" in html
    assert "corp.local" in html
    assert "<style>" in html                     # inline CSS, no external asset
    assert "authorized assessment" in html
    # severity cards + module log present
    assert "Findings summary" in html
    assert "adcs/esc_enum" in html


def test_html_escapes_untrusted_text():
    html = _report().to_html(_ctx())
    assert "<script>alert(1)</script>" not in html      # never emitted raw
    assert "&lt;script&gt;" in html                      # escaped instead
    assert "&lt;b&gt;pw&lt;/b&gt;" in html               # evidence escaped too


def test_html_counts_reflect_findings():
    html = _report().to_html(_ctx())
    # one CRITICAL and one LOW finding were added
    assert "CRITICAL" in html
    assert "LOW" in html
