"""Discovery + normalization: turns adapter output into the generic graph and capabilities."""
from __future__ import annotations

import re

from .adapters import identity as identity_adapter
from .adapters import mcp as mcp_adapter
from .adapters import openapi as openapi_adapter
from .model import (ACCESSES, CAN_INVOKE, CONTAINS, EXECUTES_AS, GRANTS_ACCESS_TO, HAS_PERMISSION, REQUIRES,
                    Capability, Graph, Node)

VERBS = [
    ("export", r"export|dump|bulk|download_?all|extract"),
    ("delete", r"delete|remove|purge|drop|destroy"),
    ("write", r"update|create|set|write|modify|patch|insert|upsert"),
    ("search", r"search|find|query|list"),
    ("read", r"get|read|fetch|describe|show"),
]
CLASS_RANK = {"public": 0, "internal": 1, "unknown": 1, "confidential": 2, "restricted": 3}


def classify_operation(name: str, description: str = "") -> str:
    text = f"{name} {description}".lower()
    for op, pattern in VERBS:
        if re.search(pattern, name.lower()):
            return op
    for op, pattern in VERBS:
        if re.search(pattern, text):
            return op
    return "unknown"


def discover(cfg: dict, log=print) -> tuple[Graph, list[Capability], dict]:
    g = Graph()
    raw: dict = {"mcp": [], "openapi": {}, "identity": None}
    target = cfg["target"]
    agent_id = f"agent:{target['name']}"
    g.add_node(Node(agent_id, "Agent", target["name"], {"endpoint": cfg["agent"]["endpoint"],
                                                       "environment": target.get("environment")}))

    # Identity adapter
    ident = None
    id_cfg = cfg["security"].get("identity")
    if cfg["security"].get("authentication") == "oauth2" and id_cfg:
        ident = identity_adapter.discover(id_cfg)
        raw["identity"] = ident
        ident_id = f"identity:{ident['subject']}"
        g.add_node(Node(ident_id, "Identity", ident["subject"], {"kind": "workload", "auth": "oauth2"}))
        for scope in ident["scopes"]:
            g.add_node(Node(f"perm:{scope}", "Permission", scope))
            g.add_edge(ident_id, HAS_PERMISSION, f"perm:{scope}")
        log(f"  identity  {ident['subject']}: {', '.join(ident['scopes'])}")

    # MCP adapter (+ OpenAPI adapter for downstream APIs referenced by tools or configured directly)
    specs: dict[str, dict] = {}
    for conn in cfg["connections"]:
        if conn.get("type") == "openapi":
            specs[conn["endpoint"]] = openapi_adapter.load(conn["endpoint"])

    caps: list[Capability] = []
    overrides = cfg["overrides"].get("tools", {})
    for conn in cfg["connections"]:
        if conn.get("type") != "mcp":
            continue
        found = mcp_adapter.discover(conn["endpoint"])
        raw["mcp"].append(found)
        log(f"  mcp       {found['server'].get('name', conn['endpoint'])}: {len(found['tools'])} tools discovered")
        for tool in found["tools"]:
            meta = tool.get("_meta") or {}
            ann = tool.get("annotations") or {}
            down = meta.get("downstream") or {}
            op = None
            if down.get("openapi"):
                if down["openapi"] not in specs:
                    specs[down["openapi"]] = openapi_adapter.load(down["openapi"])
                op = specs[down["openapi"]]["operations"].get(down.get("operationId"))

            operation = classify_operation(tool["name"], tool.get("description", ""))
            data_class = (op or {}).get("dataClassification", "unknown")
            ov = overrides.get(tool["name"], {})
            cap = Capability(
                tool=tool["name"],
                operation=ov.get("operation", operation),
                bulkAccess=ov.get("bulkAccess", bool((op or {}).get("bulk")) or operation == "export"),
                dataClassification=ov.get("dataClassification", data_class),
                humanApproval=ov.get("humanApproval", bool(meta.get("requiresApproval", False))),
                destructive=bool(ann.get("destructiveHint", operation in ("write", "delete"))),
                requiredPermissions=(op or {}).get("scopes", []),
                effective=True,
                resource=specs[down["openapi"]]["title"] if op else None,
            )
            if ident is not None and cap.requiredPermissions:
                cap.effective = set(cap.requiredPermissions) <= set(ident["scopes"])
            caps.append(cap)

            tool_id = f"tool:{tool['name']}"
            g.add_node(Node(tool_id, "Tool", tool["name"], {
                "operation": cap.operation, "bulkAccess": cap.bulkAccess,
                "dataClassification": cap.dataClassification, "humanApproval": cap.humanApproval,
                "destructive": cap.destructive, "effective": cap.effective, "source": "mcp"}))
            g.add_edge(agent_id, CAN_INVOKE, tool_id)
            if ident is not None:
                g.add_edge(tool_id, EXECUTES_AS, f"identity:{ident['subject']}")
            if cap.resource:
                res_id = f"resource:{cap.resource}"
                data_id = f"data:{cap.resource}:{cap.dataClassification}"
                g.add_node(Node(res_id, "Resource", cap.resource, {"type": "api"}))
                g.add_node(Node(data_id, "Data", f"{cap.dataClassification.title()} data ({cap.resource})",
                                {"classification": cap.dataClassification}))
                g.add_edge(tool_id, ACCESSES, res_id, operationId=down.get("operationId"))
                g.add_edge(res_id, CONTAINS, data_id)
                for scope in cap.requiredPermissions:
                    g.add_node(Node(f"perm:{scope}", "Permission", scope))
                    g.add_edge(tool_id, REQUIRES, f"perm:{scope}")
                    g.add_edge(f"perm:{scope}", GRANTS_ACCESS_TO, res_id)

    raw["openapi"] = specs
    return g, caps, raw


def privileged(caps: list[Capability], scopes: list[str] | None) -> tuple[bool, list[str]]:
    """An identity is privileged if it holds write/export/delete-class scopes."""
    if not scopes:
        return False, []
    hits = [s for s in scopes if re.search(r"(write|export|delete|admin|\*)", s)]
    return bool(hits), hits


def excess_permissions(caps: list[Capability], scopes: list[str] | None) -> list[str]:
    """Scopes held by the identity that no discovered tool requires."""
    needed = {p for c in caps for p in c.requiredPermissions}
    return sorted(set(scopes or []) - needed)


def max_classification(*levels: str) -> str:
    return max(levels, key=lambda c: CLASS_RANK.get(c, 1))
