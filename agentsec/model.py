"""Generic AgentSec data model.

Each group represents a phase of the security assessment:

    WHAT EXISTS              Node(Agent|Tool|Identity|Permission|Resource|Data) + Edge
    WHAT SHOULD HAPPEN       Policy (see policy.py)
    WHAT AGENTSEC TRIED      SecurityTest
    WHAT ACTUALLY HAPPENED   Observation
    WHAT IS WRONG            Finding
    WHAT CAN AN ATTACKER REACH  AttackPath
    HOW IMPORTANT IS IT      Risk
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Relationship types
CAN_INVOKE = "CAN_INVOKE"
INVOKED = "INVOKED"
ACCESSES = "ACCESSES"
EXECUTES_AS = "EXECUTES_AS"
HAS_PERMISSION = "HAS_PERMISSION"
REQUIRES = "REQUIRES"
GRANTS_ACCESS_TO = "GRANTS_ACCESS_TO"
CONTAINS = "CONTAINS"


@dataclass
class Node:
    id: str
    type: str  # Agent | Tool | Identity | Permission | Resource | Data | Content
    name: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    rel: str
    dst: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing:
            existing.props.update(node.props)
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, src: str, rel: str, dst: str, **props) -> Edge:
        for e in self.edges:
            if (e.src, e.rel, e.dst) == (src, rel, dst) and rel != INVOKED:
                e.props.update(props)
                return e
        edge = Edge(src, rel, dst, props)
        self.edges.append(edge)
        return edge

    def out(self, src: str, rel: str | None = None) -> list[Edge]:
        return [e for e in self.edges if e.src == src and (rel is None or e.rel == rel)]

    def of_type(self, type_: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.type == type_]

    def to_dict(self) -> dict:
        return {"nodes": [asdict(n) for n in self.nodes.values()], "edges": [asdict(e) for e in self.edges]}


@dataclass
class Capability:
    """Normalized, adapter-independent view of a tool."""
    tool: str
    operation: str  # search | read | write | delete | export | unknown
    bulkAccess: bool
    dataClassification: str  # public | internal | confidential | restricted | unknown
    humanApproval: bool
    destructive: bool
    requiredPermissions: list[str]
    effective: bool  # does the executing identity actually hold requiredPermissions?
    resource: str | None = None


@dataclass
class SecurityTest:
    id: str
    name: str
    category: str
    technique: str
    finding_title: str
    source: str
    message: str
    documents: list[dict]
    oracle: dict
    applicable_to: dict


@dataclass
class Observation:
    test_id: str
    run_id: str
    response: str
    tool_calls: list[dict]
    verdict: str = "PASS"  # PASS | FAIL | ERROR
    reasons: list[str] = field(default_factory=list)


@dataclass
class Risk:
    score: int
    severity: str  # critical | high | medium | low | info
    factors: dict[str, Any]


@dataclass
class AttackPath:
    steps: list[dict]  # [{"node": ..., "type": ..., "via": ...}]

    def render(self) -> str:
        parts = [self.steps[0]["name"]]
        for s in self.steps[1:]:
            parts.append(f"  ↓ {s['via']}")
            parts.append(s["name"])
        return "\n".join(parts)

    def compact(self) -> str:
        return " → ".join(s["name"] for s in self.steps)


@dataclass
class Finding:
    id: str
    title: str
    kind: str  # static | dynamic
    risk: Risk
    policy_results: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    attack_path: AttackPath | None = None
    test_id: str | None = None
    remediation: list[str] = field(default_factory=list)
