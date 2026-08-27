"""Offline demo — build a realistic engagement and render every artifact.

This needs no Active Directory: it hand-builds a small but representative attack
graph and a set of findings (Kerberoasting, DCSync, GPP, forest-trust SID
history, GPO hijack, LAPS exposure), then produces exactly what a real ADreaper
run would drop in the loot directory:

    report.md / report.html / results.json / graph.json
    graph.mmd / graph.dot                (analysis/graph_export)
    corp.local_bloodhound.zip + json     (analysis/bloodhound_export)

Run it to see the tooling's output, or as a smoke test of the whole pipeline:

    python examples/demo.py            # writes ./demo_loot/corp.local/
"""

from __future__ import annotations

import sys
from pathlib import Path

# allow `python examples/demo.py` without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adreaper.core.context import Credential, EngagementContext
from adreaper.core.graph import EdgeType, NodeType
from adreaper.core.module import ModuleResult, Severity
from adreaper.core.report import Report

A = "https://attack.mitre.org/techniques/"


def build_demo() -> tuple[EngagementContext, Report]:
    """Return a populated (context, report) pair — no I/O, safe to call in tests."""
    ctx = EngagementContext(
        domain="corp.local", dc_ip="10.10.0.10",
        credential=Credential(username="jdoe", domain="CORP", password="•"),
    )
    g = ctx.graph
    g.add_node("S-1-5-21-9-1105", NodeType.USER, "jdoe", {"owned": True})
    g.add_node("S-1-5-21-9-1106", NodeType.USER, "svc_sql", {"spn": True})
    g.add_node("S-1-5-21-9-512", NodeType.GROUP, "Domain Admins", {"high_value": True})
    g.add_node("S-1-5-21-9-1000", NodeType.COMPUTER, "WS01", {"os": "Windows 10", "laps": True})
    g.add_node("S-1-5-21-9-1001", NodeType.COMPUTER, "DC01", {"os": "Windows Server 2022"})
    g.add_node("corp.local", NodeType.DOMAIN, "corp.local", {"sid": "S-1-5-21-9"})
    g.add_edge("S-1-5-21-9-1105", "S-1-5-21-9-1000", EdgeType.ADMIN_TO)
    g.add_edge("S-1-5-21-9-1106", "S-1-5-21-9-512", EdgeType.MEMBER_OF)
    g.add_edge("S-1-5-21-9-1105", "S-1-5-21-9-1106", EdgeType.FORCE_CHANGE_PASSWORD)

    rep = Report()
    for module, title, sev, kw in _FINDINGS:
        r = ModuleResult(module=module)
        r.add_finding(title, sev, **kw)
        rep.add(r.finish())
    return ctx, rep


_FINDINGS = [
    ("kerberos/kerberoast", "Kerberoastable service account svc_sql", Severity.HIGH,
     {"description": "Account exposes an SPN and is crackable offline (RC4 TGS).",
      "target": "svc_sql", "references": [A + "T1558/003/"]}),
    ("recon/acl_enum", "DCSync rights: svc_sql can replicate domain secrets", Severity.CRITICAL,
     {"description": "Holds GetChanges + GetChangesAll on the domain; can extract krbtgt.",
      "target": "svc_sql", "references": [A + "T1003/006/"]}),
    ("credentials/gpp_decrypt", "GPP credential recovered: svc_backup", Severity.HIGH,
     {"description": "Password stored in SYSVOL GPP, decryptable by any domain user.",
      "evidence": "Groups.xml  user=svc_backup  password='GPPstillStandingStrong2k18'",
      "target": "10.10.0.10", "references": [A + "T1552/006/"]}),
    ("recon/trust_enum", "Forest trust to dev.corp without SID filtering", Severity.HIGH,
     {"description": "SID history injection across this forest trust can forge Enterprise Admins.",
      "target": "dev.corp", "references": [A + "T1134/005/", A + "T1482/"]}),
    ("recon/gpo_enum", "GPO hijack: jdoe can edit 'Workstation Baseline' (linked to Workstations)",
     Severity.HIGH,
     {"description": "Non-privileged principal holds GenericWrite over a linked GPO.",
      "target": "Workstation Baseline", "references": [A + "T1484/001/"]}),
    ("recon/laps_enum", "LAPS password of WS01 readable by Helpdesk", Severity.HIGH,
     {"description": "Helpdesk can read the LAPS local-admin password of WS01.",
      "target": "WS01", "references": [A + "T1552/"]}),
    ("recon/ldap_enum", "Machine account quota is 10", Severity.MEDIUM,
     {"description": "Any user can join 10 computers — enables RBCD attacks.",
      "target": "corp.local"}),
    ("recon/ldap_enum", "Enumerated 42 users, 15 groups, 8 computers", Severity.INFO,
     {"target": "corp.local", "references": [A + "T1087/002/"]}),
]


def main(out_dir: str | Path = "demo_loot") -> dict:
    ctx, rep = build_demo()
    ctx.output_dir = Path(out_dir)

    written = rep.write(ctx)                       # md / html / json / graph.json
    from adreaper.modules.analysis.graph_export import GraphExport
    from adreaper.modules.analysis.bloodhound_export import BloodHoundExport
    GraphExport().run(ctx)                         # graph.mmd / graph.dot
    BloodHoundExport().run(ctx)                    # SharpHound json + zip

    loot = ctx.loot_dir()
    print(f"demo engagement written to {loot}")
    for p in sorted(loot.iterdir()):
        print(f"  {p.name}")
    return {k: str(v) for k, v in written.items()}


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo_loot")
