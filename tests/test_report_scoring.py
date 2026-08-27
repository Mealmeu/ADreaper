from adreaper.core.context import EngagementContext
from adreaper.core.module import Finding, ModuleResult, Severity
from adreaper.core.report import (
    Report,
    _extract_attack_ids,
    attack_coverage,
    risk_score,
    severity_counts,
)

KERBEROAST = "https://attack.mitre.org/techniques/T1558/003/"
DCSYNC = "https://attack.mitre.org/techniques/T1003/006/"
TRUST = "https://attack.mitre.org/techniques/T1482/"


def _f(sev, refs=None):
    return Finding(title="t", severity=sev, references=refs or [])


def test_severity_counts():
    c = severity_counts([_f(Severity.HIGH), _f(Severity.HIGH), _f(Severity.LOW)])
    assert c[Severity.HIGH] == 2 and c[Severity.LOW] == 1 and c[Severity.CRITICAL] == 0


def test_risk_score_empty_is_hardened():
    assert risk_score(severity_counts([])) == (0, "Hardened")


def test_risk_score_rating_is_worst_severity():
    score, rating = risk_score(severity_counts([_f(Severity.HIGH), _f(Severity.MEDIUM)]))
    assert rating == "High"
    assert score == 15 + 6


def test_risk_score_critical_and_cap():
    score, rating = risk_score(severity_counts([_f(Severity.CRITICAL)] * 3))
    assert rating == "Critical"
    assert score == 100  # 3*40 capped at 100


def test_extract_attack_ids():
    assert _extract_attack_ids([KERBEROAST]) == {"T1558.003"}
    assert _extract_attack_ids([TRUST]) == {"T1482"}
    assert _extract_attack_ids(["https://example.com/not-attack"]) == set()
    assert _extract_attack_ids(None) == set()


def test_attack_coverage_counts_and_sort():
    findings = [_f(Severity.HIGH, [KERBEROAST]), _f(Severity.HIGH, [KERBEROAST]),
                _f(Severity.CRITICAL, [DCSYNC])]
    rows = attack_coverage(findings)
    # both Credential Access; sorted by (tactic, id) -> T1003.006 first
    assert rows[0]["id"] == "T1003.006" and rows[0]["count"] == 1
    kerb = next(r for r in rows if r["id"] == "T1558.003")
    assert kerb["count"] == 2 and kerb["name"] == "Kerberoasting"


def test_attack_coverage_unmapped():
    rows = attack_coverage([_f(Severity.INFO, ["https://attack.mitre.org/techniques/T9999/"])])
    assert rows == [{"id": "T9999", "name": "(unmapped technique)",
                     "tactic": "Other", "count": 1}]


def test_report_renders_with_scoring():
    ctx = EngagementContext(domain="corp.local")
    r = Report()
    res = ModuleResult(module="recon/ldap_enum")
    res.add_finding("Kerberoastable svc", Severity.HIGH, references=[KERBEROAST])
    r.add(res)
    md = r.to_markdown(ctx)
    html = r.to_html(ctx)
    js = r.to_json(ctx)
    assert "## Risk score" in md and "MITRE ATT&CK coverage" in md
    assert "Risk score" in html and "Kerberoasting" in html
    assert js["risk_rating"] == "High" and js["risk_score"] == 15
    assert any(row["id"] == "T1558.003" for row in js["attack_coverage"])
