"""Export the collected graph to SharpHound-style JSON for BloodHound.

Turns ADreaper's unified graph into the per-type JSON files BloodHound imports
(users / groups / computers / domains), mapping our nodes and edges onto the
SharpHound schema:

- MemberOf     -> the group's `Members`
- ACL edges    -> the target object's `Aces` (GenericAll, WriteDacl, ...)
- DCSync       -> GetChanges + GetChangesAll aces on the domain
- AllowedToDelegate / AddAllowedToAct -> delegation lists
- HasSession / AdminTo -> computer Sessions / LocalAdmins

The result lets an operator collect with ADreaper and pivot into the BloodHound
GUI for interactive path hunting. Output is written per-type and bundled into a
single `<domain>_bloodhound.zip` ready to upload.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import ADGraph, EdgeType, Node, NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# SharpHound meta version accepted by BloodHound 4.3+/CE.
_META_VERSION = 5

# ACL edge -> BloodHound Ace RightName
_ACE_RIGHT = {
    EdgeType.GENERIC_ALL: "GenericAll",
    EdgeType.GENERIC_WRITE: "GenericWrite",
    EdgeType.WRITE_DACL: "WriteDacl",
    EdgeType.WRITE_OWNER: "WriteOwner",
    EdgeType.OWNS: "Owns",
    EdgeType.FORCE_CHANGE_PASSWORD: "ForceChangePassword",
    EdgeType.ADD_MEMBER: "AddMember",
    EdgeType.ALL_EXTENDED_RIGHTS: "AllExtendedRights",
    EdgeType.READ_LAPS_PASSWORD: "ReadLAPSPassword",
}

_BH_TYPE = {
    NodeType.USER: "User",
    NodeType.GROUP: "Group",
    NodeType.COMPUTER: "Computer",
    NodeType.DOMAIN: "Domain",
    NodeType.OU: "OU",
    NodeType.GPO: "GPO",
}


class BloodHoundExport(BaseModule):
    name = "analysis/bloodhound_export"
    description = "Export the attack graph to SharpHound JSON for BloodHound."
    author = "Mealmeu"
    category = "analysis"
    requires = []  # pure transformation
    references = ["https://bloodhound.readthedocs.io/"]
    options = [
        Option("graph", "Load graph.json if the live graph is empty", type=OptionType.STRING),
        Option("zip", "Bundle the JSON files into a single .zip", default=True,
               type=OptionType.BOOL),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        graph = self._resolve_graph(ctx)
        if graph is None or len(graph) == 0:
            return res.fail("graph is empty — run recon first, or -o graph=<graph.json>").finish()

        domain = (ctx.domain or _guess_domain(graph)).upper()
        domain_sid = _domain_sid(graph)
        files = build_bloodhound(graph, domain, domain_sid)

        loot = ctx.loot_dir()
        prefix = _safe(ctx.domain or "domain")
        written: list[Path] = []
        for kind, payload in files.items():
            p = loot / f"{prefix}_{kind}.json"
            p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            written.append(p)

        counts = {k: v["meta"]["count"] for k, v in files.items()}
        log.ok("exported %s", ", ".join(f"{v} {k}" for k, v in counts.items()))

        out_paths = {"json_files": [str(p) for p in written]}
        if bool(self.opt("zip")):
            zpath = loot / f"{prefix}_bloodhound.zip"
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
                for p in written:
                    zf.write(p, arcname=p.name)
            log.ok("bundle -> %s", zpath)
            out_paths["zip"] = str(zpath)

        res.data.update({"counts": counts, **out_paths})
        res.add_finding(
            f"BloodHound export ready ({sum(counts.values())} objects)",
            Severity.INFO,
            description="Upload the generated JSON/zip in the BloodHound GUI to hunt paths interactively.",
        )
        return res.finish()

    def _resolve_graph(self, ctx: EngagementContext) -> Optional[ADGraph]:
        if len(ctx.graph):
            return ctx.graph
        gpath = self.opt("graph") or ""
        if not gpath:
            candidate = ctx.loot_dir() / "graph.json"
            gpath = str(candidate) if candidate.exists() else ""
        if gpath and Path(gpath).exists():
            log.info("loading graph from %s", gpath)
            ctx.graph.merge(ADGraph.load(gpath))
        return ctx.graph if len(ctx.graph) else None


# ---------------------------------------------------------------------------
# pure transformation (unit-tested)
# ---------------------------------------------------------------------------

def build_bloodhound(graph: ADGraph, domain: str, domain_sid: str) -> dict[str, dict]:
    """Return {kind: sharphound_file_dict} for users/groups/computers/domains."""
    # index edges by target and by source for O(1) assembly
    by_target: dict[str, list] = {}
    by_source: dict[str, list] = {}
    for e in graph.edges:
        by_target.setdefault(e.target, []).append(e)
        by_source.setdefault(e.source, []).append(e)

    users, groups, computers, domains = [], [], [], []
    for n in graph.nodes:
        obj = _base_object(n, domain, domain_sid)
        _attach_aces(obj, n, by_target, graph)
        if n.type == NodeType.USER:
            _attach_delegation(obj, n, by_source, graph)
            users.append(obj)
        elif n.type == NodeType.GROUP:
            obj["Members"] = _members(n, by_target, graph)
            groups.append(obj)
        elif n.type == NodeType.COMPUTER:
            _attach_delegation(obj, n, by_source, graph)
            _attach_sessions_admins(obj, n, by_source, by_target, graph)
            computers.append(obj)
        elif n.type == NodeType.DOMAIN:
            obj.setdefault("Trusts", [])
            obj.setdefault("ChildObjects", [])
            obj.setdefault("Links", [])
            domains.append(obj)

    return {
        "users": _file("users", users),
        "groups": _file("groups", groups),
        "computers": _file("computers", computers),
        "domains": _file("domains", domains),
    }


def _file(kind: str, data: list) -> dict:
    return {"data": data, "meta": {"methods": 0, "type": kind,
                                   "count": len(data), "version": _META_VERSION}}


def _base_object(n: Node, domain: str, domain_sid: str) -> dict:
    props = {
        "name": _upn(n, domain),
        "domain": domain,
        "domainsid": domain_sid,
        "distinguishedname": str(n.properties.get("dn", "")),
        "highvalue": bool(n.properties.get("high_value")),
    }
    if n.type in (NodeType.USER, NodeType.COMPUTER):
        props["enabled"] = bool(n.properties.get("enabled", True))
        props["hasspn"] = bool(n.properties.get("spn"))
        props["unconstraineddelegation"] = bool(n.properties.get("unconstrained_delegation"))
        props["dontreqpreauth"] = bool(n.properties.get("dont_require_preauth"))
        if n.properties.get("os"):
            props["operatingsystem"] = n.properties["os"]
    if n.type == NodeType.COMPUTER:
        props["haslaps"] = bool(n.properties.get("laps"))
    obj = {
        "ObjectIdentifier": n.id,
        "Properties": props,
        "Aces": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    }
    return obj


def _attach_aces(obj: dict, n: Node, by_target: dict, graph: ADGraph) -> None:
    aces = []
    for e in by_target.get(n.id, []):
        src = graph.get(e.source)
        ptype = _BH_TYPE.get(src.type, "Base") if src else "Base"
        if e.type in _ACE_RIGHT:
            aces.append(_ace(e.source, ptype, _ACE_RIGHT[e.type]))
        elif e.type == EdgeType.DC_SYNC:
            aces.append(_ace(e.source, ptype, "GetChanges"))
            aces.append(_ace(e.source, ptype, "GetChangesAll"))
    obj["Aces"] = aces


def _members(group: Node, by_target: dict, graph: ADGraph) -> list:
    out = []
    for e in by_target.get(group.id, []):
        if e.type == EdgeType.MEMBER_OF:
            src = graph.get(e.source)
            out.append({"ObjectIdentifier": e.source,
                        "ObjectType": _BH_TYPE.get(src.type, "Base") if src else "Base"})
    return out


def _attach_delegation(obj: dict, n: Node, by_source: dict, graph: ADGraph) -> None:
    allowed = []
    for e in by_source.get(n.id, []):
        if e.type == EdgeType.ALLOWED_TO_DELEGATE:
            tgt = graph.get(e.target)
            allowed.append({"ObjectIdentifier": e.target,
                            "ObjectType": _BH_TYPE.get(tgt.type, "Computer") if tgt else "Computer"})
    if allowed:
        obj["AllowedToDelegate"] = allowed


def _attach_sessions_admins(obj: dict, n: Node, by_source: dict, by_target: dict,
                            graph: ADGraph) -> None:
    sessions = []
    for e in by_source.get(n.id, []):
        if e.type == EdgeType.HAS_SESSION:
            sessions.append({"UserSID": e.target, "ComputerSID": n.id})
    admins, act = [], []
    for e in by_target.get(n.id, []):
        if e.type == EdgeType.ADMIN_TO:
            src = graph.get(e.source)
            admins.append({"ObjectIdentifier": e.source,
                           "ObjectType": _BH_TYPE.get(src.type, "Base") if src else "Base"})
        elif e.type == EdgeType.ADD_ALLOWED_TO_ACT:
            src = graph.get(e.source)
            act.append({"ObjectIdentifier": e.source,
                        "ObjectType": _BH_TYPE.get(src.type, "Base") if src else "Base"})
    obj["Sessions"] = {"Collected": bool(sessions), "FailureReason": None, "Results": sessions}
    obj["LocalAdmins"] = {"Collected": bool(admins), "FailureReason": None, "Results": admins}
    if act:
        obj["AllowedToAct"] = act


def _ace(sid: str, ptype: str, right: str) -> dict:
    return {"PrincipalSID": sid, "PrincipalType": ptype, "RightName": right, "IsInherited": False}


def _upn(n: Node, domain: str) -> str:
    if n.type == NodeType.DOMAIN:
        return domain
    base = n.name.rstrip("$")
    return f"{base.upper()}@{domain}" if "@" not in base else base.upper()


def _domain_sid(graph: ADGraph) -> str:
    for d in graph.nodes_of(NodeType.DOMAIN):
        if d.properties.get("sid"):
            return str(d.properties["sid"])
    # derive from any principal SID (strip the RID)
    for n in graph.nodes:
        if n.id.startswith("S-1-5-21-") and n.id.count("-") >= 6:
            return n.id.rsplit("-", 1)[0]
    return ""


def _guess_domain(graph: ADGraph) -> str:
    d = graph.nodes_of(NodeType.DOMAIN)
    return d[0].name if d else "UNKNOWN"


def _safe(name: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name) or "domain"
