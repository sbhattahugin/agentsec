"""Discovery + normalization: turns adapter output into the generic graph and capabilities."""
from __future__ import annotations

import re

from .adapters import openapi as openapi_adapter
from .model import (ACCESSES, CAN_INVOKE, CONTAINS, EXECUTES_AS, GRANTS_ACCESS_TO, GROUNDED_ON, HAS_PERMISSION,
                    REQUIRES, Capability, Graph, Node)
from .platforms.base import ToolSpec

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


def _resolve_openapi(ts: ToolSpec, specs: dict) -> tuple[dict | None, dict | None]:
    """Find the downstream OpenAPI operation for a tool (spec URL or embedded spec)."""
    if not ts.openapi or not ts.operationId:
        return None, None
    if isinstance(ts.openapi, dict):
        spec = openapi_adapter.parse(ts.openapi, f"embedded:{ts.openapi.get('info', {}).get('title', ts.name)}")
        specs.setdefault(spec["url"], spec)
    else:
        if ts.openapi not in specs:
            specs[ts.openapi] = openapi_adapter.load(ts.openapi)
        spec = specs[ts.openapi]
    return spec, spec["operations"].get(ts.operationId)


def normalize_tool(ts: ToolSpec, specs: dict, overrides: dict, defaults: dict) -> tuple[Capability, dict | None]:
    spec, op = _resolve_openapi(ts, specs)
    ov = overrides.get(ts.name, {})
    operation = ov.get("operation") or ts.operation or classify_operation(ts.name, ts.description)
    op_class = (op or {}).get("dataClassification")
    data_class = (ov.get("dataClassification") or ts.dataClassification
                  or (op_class if op_class and op_class != "unknown" else None)
                  or defaults.get("dataClassification") or "unknown")
    bulk = ts.bulk if ts.bulk is not None else (bool((op or {}).get("bulk")) or operation == "export")
    approval = ts.humanApproval if ts.humanApproval is not None else bool(defaults.get("humanApproval", False))
    cap = Capability(
        tool=ts.name,
        operation=operation,
        bulkAccess=ov.get("bulkAccess", bulk),
        dataClassification=data_class,
        humanApproval=ov.get("humanApproval", approval),
        destructive=ov.get("destructive", ts.destructive if ts.destructive is not None
                           else operation in ("write", "delete")),
        requiredPermissions=list(ov.get("requiredPermissions") or ts.requiredPermissions or (op or {}).get("scopes", [])),
        effective=True,
        resource=ov.get("resource") or ts.resource or (spec["title"] if op else None),
        source=ts.source,
    )
    return cap, op


def discover(cfg: dict, log=print, platform=None) -> tuple[Graph, list[Capability], dict]:
    from . import platforms
    platform = platform or platforms.build(cfg)
    g = Graph()
    raw: dict = {"mcp": [], "openapi": {}, "identity": None, "sources": [], "aliases": {},
                 "platform": platform.describe()}
    target = cfg["target"]
    agent_id = f"agent:{target['name']}"
    inv = platform.invoker.describe() if platform.invoker else {}
    g.add_node(Node(agent_id, "Agent", target["name"], {"endpoint": inv.get("endpoint"), "platform": platform.name,
                                                       "environment": target.get("environment")}))

    found: list = []
    for d in platform.discoverers:
        res = d.discover(log)
        found.append(res)
        raw["openapi"].update(res.raw.get("openapi", {}))
        if "mcp" in res.raw:
            raw["mcp"].append(res.raw["mcp"])

    # Identity: dedicated identity adapter wins; otherwise one reported by a discoverer (e.g. Forge app scopes)
    ident = platform.identity.discover(log) if platform.identity else next((r.identity for r in found if r.identity), None)
    if ident is not None:
        raw["identity"] = ident
        ident_id = f"identity:{ident['subject']}"
        g.add_node(Node(ident_id, "Identity", ident["subject"], {"kind": ident.get("kind", "workload"),
                                                                 "auth": ident.get("auth"),
                                                                 "checkLeastPrivilege": ident.get("checkLeastPrivilege", True)}))
        for scope in ident["scopes"]:
            g.add_node(Node(f"perm:{scope}", "Permission", scope))
            g.add_edge(ident_id, HAS_PERMISSION, f"perm:{scope}")
        if platform.identity:
            log(f"  identity  {ident['subject']}: {', '.join(ident['scopes']) or '(no permissions)'}")

    specs = raw["openapi"]
    caps: list[Capability] = []
    overrides = (cfg.get("overrides") or {}).get("tools", {})
    defaults = cfg.get("defaults") or {}
    for res in found:
        raw["sources"].append({"type": res.source, "label": res.label, "agent": res.agent,
                               "knowledge": res.knowledge,
                               "tools": [{"name": t.name, "description": t.description, "source": t.source,
                                          "attributes": t.attributes, "humanApproval": t.humanApproval,
                                          "destructive": t.destructive} for t in res.tools]})
        for ts in res.tools:
            if any(c.tool == ts.name for c in caps):
                continue
            cap, op = normalize_tool(ts, specs, overrides, defaults)
            if ident is not None and cap.requiredPermissions:
                held = {s.lower() for s in ident["scopes"]}
                cap.effective = {p.lower() for p in cap.requiredPermissions} <= held
            caps.append(cap)
            for alias in ts.aliases:
                raw["aliases"][alias] = ts.name

            tool_id = f"tool:{ts.name}"
            g.add_node(Node(tool_id, "Tool", ts.name, {
                "operation": cap.operation, "bulkAccess": cap.bulkAccess,
                "dataClassification": cap.dataClassification, "humanApproval": cap.humanApproval,
                "destructive": cap.destructive, "effective": cap.effective, "source": ts.source}))
            g.add_edge(agent_id, CAN_INVOKE, tool_id)
            if ident is not None:
                g.add_edge(tool_id, EXECUTES_AS, f"identity:{ident['subject']}")
            if cap.resource:
                res_id = f"resource:{cap.resource}"
                data_id = f"data:{cap.resource}:{cap.dataClassification}"
                g.add_node(Node(res_id, "Resource", cap.resource, {"type": "api"}))
                g.add_node(Node(data_id, "Data", f"{cap.dataClassification.title()} data ({cap.resource})",
                                {"classification": cap.dataClassification}))
                g.add_edge(tool_id, ACCESSES, res_id, operationId=ts.operationId)
                g.add_edge(res_id, CONTAINS, data_id)
                for scope in cap.requiredPermissions:
                    g.add_node(Node(f"perm:{scope}", "Permission", scope))
                    g.add_edge(tool_id, REQUIRES, f"perm:{scope}")
                    g.add_edge(f"perm:{scope}", GRANTS_ACCESS_TO, res_id)

        for k in res.knowledge:
            cls = k.get("dataClassification") or defaults.get("dataClassification") or "internal"
            k["dataClassification"] = cls
            res_id = f"knowledge:{k['name']}"
            data_id = f"data:{k['name']}:{cls}"
            g.add_node(Node(res_id, "Resource", k["name"], {"type": "knowledge", "kind": k.get("kind"),
                                                           "scoped": k.get("scoped"), "detail": k.get("detail")}))
            g.add_node(Node(data_id, "Data", f"{cls.title()} data ({k['name']})", {"classification": cls}))
            g.add_edge(agent_id, GROUNDED_ON, res_id, scoped=k.get("scoped"))
            g.add_edge(res_id, CONTAINS, data_id)

    raw["knowledge"] = [k for r in found for k in r.knowledge]
    return g, caps, raw


def privileged(caps: list[Capability], scopes: list[str] | None) -> tuple[bool, list[str]]:
    """An identity is privileged if it holds write/export/delete-class scopes."""
    if not scopes:
        return False, []
    hits = [s for s in scopes if re.search(r"(write|export|delete|admin|manage|\*)", s, re.I)]
    return bool(hits), hits


def excess_permissions(caps: list[Capability], scopes: list[str] | None) -> list[str]:
    """Scopes held by the identity that no discovered tool requires."""
    needed = {p.lower() for c in caps for p in c.requiredPermissions}
    return sorted(s for s in set(scopes or []) if s.lower() not in needed)


def max_classification(*levels: str) -> str:
    return max(levels, key=lambda c: CLASS_RANK.get(c, 1))
