"""The central Active Directory attack graph.

Every module can push nodes (users, groups, computers, domains, ...) and edges
(MemberOf, AdminTo, HasSession, ...) into one shared graph. This is what lets
ADreaper correlate the output of independent collectors the way BloodHound does,
and is the substrate a future attack-path finder walks.

The model is deliberately BloodHound-compatible in spirit (node kinds + typed
directed edges) so a BloodHound-format export can be added without reshaping data.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional


class NodeType(str, Enum):
    USER = "User"
    GROUP = "Group"
    COMPUTER = "Computer"
    DOMAIN = "Domain"
    OU = "OU"
    GPO = "GPO"
    CONTAINER = "Container"
    CERT_TEMPLATE = "CertTemplate"
    CA = "CA"


class EdgeType(str, Enum):
    """Directed relationships. Direction is always source --edge--> target."""

    MEMBER_OF = "MemberOf"
    CONTAINS = "Contains"
    ADMIN_TO = "AdminTo"
    HAS_SESSION = "HasSession"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    OWNS = "Owns"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    ADD_MEMBER = "AddMember"
    ALL_EXTENDED_RIGHTS = "AllExtendedRights"
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    ADD_ALLOWED_TO_ACT = "AddAllowedToAct"
    TRUSTS = "Trusts"
    GP_LINK = "GpLink"
    CAN_RDP = "CanRDP"
    DC_SYNC = "DCSync"


# Well-known privileged principal names, matched case-insensitively when a node
# carries no explicit high_value flag.
HIGH_VALUE_NAMES = {
    "domain admins", "enterprise admins", "administrators", "schema admins",
    "domain controllers", "enterprise domain controllers", "account operators",
    "backup operators", "server operators", "print operators",
    "group policy creator owners", "krbtgt", "administrator",
}


@dataclass
class Node:
    """A single AD object. `id` should be stable (objectSid where available)."""

    id: str
    type: NodeType
    name: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Edge:
    source: str
    target: str
    type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.type.value)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


class ADGraph:
    """In-memory attack graph with upsert semantics and JSON persistence."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}
        # adjacency for path search: source_id -> list of (target_id, edge_type)
        self._adj: dict[str, list[tuple[str, str]]] = {}

    # -- mutation ---------------------------------------------------------

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        name: str,
        properties: Optional[dict[str, Any]] = None,
    ) -> Node:
        """Insert or merge a node. Existing properties are updated, not replaced."""
        node_id = node_id.upper() if node_id else name.upper()
        existing = self._nodes.get(node_id)
        if existing is None:
            node = Node(id=node_id, type=node_type, name=name, properties=dict(properties or {}))
            self._nodes[node_id] = node
            self._adj.setdefault(node_id, [])
            return node
        if properties:
            existing.properties.update(properties)
        if name and not existing.name:
            existing.name = name
        return existing

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        properties: Optional[dict[str, Any]] = None,
    ) -> Edge:
        """Insert a directed edge, deduplicated by (source, target, type)."""
        source_id = source_id.upper()
        target_id = target_id.upper()
        edge = Edge(source=source_id, target=target_id, type=edge_type, properties=dict(properties or {}))
        k = edge.key()
        if k not in self._edges:
            self._edges[k] = edge
            self._adj.setdefault(source_id, []).append((target_id, edge_type.value))
        elif properties:
            self._edges[k].properties.update(properties)
        return self._edges[k]

    # -- queries ----------------------------------------------------------

    @property
    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def get(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id.upper())

    def find(self, name: str, node_type: Optional[NodeType] = None) -> list[Node]:
        """Case-insensitive lookup by name (and optionally type)."""
        name_l = name.lower()
        out = []
        for n in self._nodes.values():
            if n.name.lower() == name_l and (node_type is None or n.type == node_type):
                out.append(n)
        return out

    def nodes_of(self, node_type: NodeType) -> list[Node]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def high_value_nodes(self) -> list[Node]:
        """Nodes flagged high_value by a collector, or matching a well-known
        privileged name (Domain Admins, Enterprise Admins, ...)."""
        out = []
        for n in self._nodes.values():
            if n.properties.get("high_value") or n.name.lower() in HIGH_VALUE_NAMES:
                out.append(n)
        return out

    def owned_nodes(self) -> list[Node]:
        """Nodes we control (marked owned by a credential/exploitation module)."""
        return [n for n in self._nodes.values() if n.properties.get("owned")]

    def mark_owned(self, node_id: str) -> Optional[Node]:
        n = self.get(node_id)
        if n is None:
            hits = self.find(node_id)
            n = hits[0] if hits else None
        if n is not None:
            n.properties["owned"] = True
        return n

    def counts(self) -> dict[str, int]:
        """Node counts per type plus total edges — for the run summary."""
        c: dict[str, int] = {}
        for n in self._nodes.values():
            c[n.type.value] = c.get(n.type.value, 0) + 1
        c["Edges"] = len(self._edges)
        return c

    def shortest_path(self, start_id: str, goal_id: str) -> Optional[list[tuple[str, str]]]:
        """BFS shortest attack path start -> goal.

        Returns a list of (node_id, edge_type_taken_to_reach_it); the first entry
        is (start_id, "") . None if unreachable. This is the primitive a full
        attack-path finder builds on.
        """
        start_id, goal_id = start_id.upper(), goal_id.upper()
        if start_id not in self._nodes or goal_id not in self._nodes:
            return None
        if start_id == goal_id:
            return [(start_id, "")]
        prev: dict[str, tuple[str, str]] = {start_id: (start_id, "")}
        q: deque[str] = deque([start_id])
        while q:
            cur = q.popleft()
            for nxt, etype in self._adj.get(cur, []):
                if nxt not in prev:
                    prev[nxt] = (cur, etype)
                    if nxt == goal_id:
                        return self._reconstruct(prev, start_id, goal_id)
                    q.append(nxt)
        return None

    def _reconstruct(
        self, prev: dict[str, tuple[str, str]], start_id: str, goal_id: str
    ) -> list[tuple[str, str]]:
        chain: list[tuple[str, str]] = []
        cur = goal_id
        while cur != start_id:
            parent, etype = prev[cur]
            chain.append((cur, etype))
            cur = parent
        chain.append((start_id, ""))
        chain.reverse()
        return chain

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {"format": "adreaper-graph", "version": 1},
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
        }

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "ADGraph":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        g = cls()
        for nd in data.get("nodes", []):
            g.add_node(nd["id"], NodeType(nd["type"]), nd["name"], nd.get("properties"))
        for ed in data.get("edges", []):
            g.add_edge(ed["source"], ed["target"], EdgeType(ed["type"]), ed.get("properties"))
        return g

    def merge(self, other: "ADGraph") -> None:
        for n in other.nodes:
            self.add_node(n.id, n.type, n.name, n.properties)
        for e in other.edges:
            self.add_edge(e.source, e.target, e.type, e.properties)

    def __len__(self) -> int:
        return len(self._nodes)

    def extend_nodes(self, nodes: Iterable[Node]) -> None:
        for n in nodes:
            self.add_node(n.id, n.type, n.name, n.properties)
