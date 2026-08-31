from adreaper.core import loader
from adreaper.core.graph import ADGraph, EdgeType, NodeType
from adreaper.modules.kerberos.s4u import (
    pick_impersonation_target,
    plan_s4u_attacks,
)


def _graph():
    g = ADGraph()
    g.add_node("S-1-1", NodeType.USER, "svc_web", {"owned": True})
    g.add_node("S-1-2", NodeType.COMPUTER, "DB01", {"dns": "db01.corp.local"})
    g.add_node("S-1-3", NodeType.USER, "admin", {"high_value": True})
    g.add_node("S-1-4", NodeType.USER, "attacker", {"owned": True})
    g.add_node("S-1-5", NodeType.COMPUTER, "FILE01")
    g.add_edge("S-1-1", "S-1-2", EdgeType.ALLOWED_TO_DELEGATE,
               {"spn": "MSSQLSvc/db01.corp.local:1433"})
    g.add_edge("S-1-4", "S-1-5", EdgeType.ADD_ALLOWED_TO_ACT)
    return g


def test_pick_impersonation_target():
    assert pick_impersonation_target(_graph()) == "admin"
    assert pick_impersonation_target(ADGraph()) == "Administrator"


def test_plan_constrained_and_rbcd():
    g = _graph()
    plans = plan_s4u_attacks(g, "corp.local", pick_impersonation_target(g))
    assert len(plans) == 2
    # constrained sorts before rbcd; both controllable (owned controllers)
    con, rb = plans
    assert con["kind"] == "constrained" and con["controllable"] is True
    assert con["controller"] == "svc_web" and con["impersonate"] == "admin"
    assert con["target_host"] == "db01.corp.local"
    assert "getST" in con["command"] and "-impersonate 'admin'" in con["command"]
    assert "MSSQLSvc/db01.corp.local:1433" in con["command"]

    assert rb["kind"] == "rbcd" and rb["controller"] == "attacker"
    assert rb["target_host"] == "FILE01" and rb["spn"] == "cifs/FILE01"


def test_plan_marks_uncontrolled_delegation():
    g = ADGraph()
    g.add_node("S-2-1", NodeType.USER, "svc_x")           # not owned
    g.add_node("S-2-2", NodeType.COMPUTER, "APP01")
    g.add_edge("S-2-1", "S-2-2", EdgeType.ALLOWED_TO_DELEGATE, {"spn": "http/app01"})
    plans = plan_s4u_attacks(g, "corp.local", "Administrator")
    assert len(plans) == 1 and plans[0]["controllable"] is False


def test_actionable_plans_sort_first():
    g = _graph()
    g.add_node("S-1-6", NodeType.USER, "svc_y")           # not owned
    g.add_node("S-1-7", NodeType.COMPUTER, "WEB01")
    g.add_edge("S-1-6", "S-1-7", EdgeType.ALLOWED_TO_DELEGATE, {"spn": "http/web01"})
    plans = plan_s4u_attacks(g, "corp.local", "admin")
    # every controllable plan comes before any non-controllable one
    flags = [p["controllable"] for p in plans]
    assert flags == sorted(flags, reverse=True)


def test_module_discovered():
    assert "kerberos/s4u" in loader.discover(force=True)
