"""Generic adapters: any HTTP chat endpoint, MCP servers, OpenAPI specs, HTTP telemetry and OAuth2 introspection."""
from __future__ import annotations

import time

from ..adapters import identity as oauth2_identity
from ..adapters import mcp as mcp_adapter
from ..adapters.http import request
from .base import ChatResult, Discovered, ToolSpec, fill


class HttpChatInvoker:
    """POST {message, documents, sessionId} to agent.endpoint and read `response` (the original AgentSec contract)."""
    name = "http-chat"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.endpoint = cfg["endpoint"]
        self.headers = dict(cfg.get("headers") or {})
        self.response_field = cfg.get("responseField", "response")

    def describe(self) -> dict:
        return {"adapter": self.name, "endpoint": self.endpoint}

    def invoke(self, message: str, documents: list[dict], trace_id: str) -> ChatResult:
        status, body = request("POST", self.endpoint,
                               {"message": message, "documents": documents, "sessionId": trace_id},
                               headers={**self.headers, "X-AgentSec-Test-Id": trace_id})
        text = body.get(self.response_field, body) if isinstance(body, dict) else body
        return ChatResult(status, str(text), {"testId": trace_id, "sessionId": trace_id})


class McpDiscoverer:
    """initialize + tools/list. Tool `_meta.downstream` / `_meta.requiresApproval` are honoured when present."""
    name = "mcp"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.endpoint = cfg["endpoint"]
        self.allowed = set(cfg.get("allowedTools") or [])
        self.approval = cfg.get("requireApproval")  # "always" | "never" | {always: [..], never: [..]}

    def _approval(self, name: str, meta: dict) -> bool | None:
        a = self.approval
        if a == "always":
            return True
        if a == "never":
            return False
        if isinstance(a, dict):
            def names(v):
                return (v.get("tool_names") or []) if isinstance(v, dict) else (v or [])
            if name in names(a.get("always")):
                return True
            if name in names(a.get("never")):
                return False
        return bool(meta["requiresApproval"]) if "requiresApproval" in meta else None

    def discover(self, log) -> Discovered:
        found = mcp_adapter.discover(self.endpoint)
        tools = []
        for t in found["tools"]:
            if self.allowed and t["name"] not in self.allowed:
                continue
            meta, ann = t.get("_meta") or {}, t.get("annotations") or {}
            down = meta.get("downstream") or {}
            tools.append(ToolSpec(
                name=t["name"], description=t.get("description", ""), source="mcp",
                humanApproval=self._approval(t["name"], meta),
                destructive=ann.get("destructiveHint"),
                openapi=down.get("openapi"), operationId=down.get("operationId"),
                attributes={"annotations": ann, "meta": meta, "server": self.endpoint},
            ))
        name = found["server"].get("name", self.endpoint)
        log(f"  mcp       {name}: {len(found['tools'])} tools discovered")
        return Discovered("mcp", name, tools, raw={"mcp": found})


class OpenApiDiscoverer:
    """Pre-loads a downstream API spec so tools can be resolved against it (optionally exposes ops as tools)."""
    name = "openapi"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.url = cfg.get("endpoint") or cfg.get("url")
        self.expose = bool(cfg.get("exposeAsTools", False))

    def discover(self, log) -> Discovered:
        from ..adapters import openapi
        spec = openapi.load(self.url)
        tools = [ToolSpec(name=op_id, description=f"{op['method']} {op['path']}", source="openapi",
                          openapi=self.url, operationId=op_id)
                 for op_id, op in spec["operations"].items()] if self.expose else []
        log(f"  openapi   {spec['title']}: {len(spec['operations'])} operations")
        return Discovered("openapi", spec["title"], tools, raw={"openapi": {self.url: spec}})


class HttpEventsTelemetry:
    """GET <url>?<param>=<correlation id> -> {events: [...]} (AgentSec telemetry contract, used by instrumented MCP)."""
    name = "http-events"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.url = cfg.get("url") or cfg.get("telemetry") or cfg.get("endpoint")
        self.param = cfg.get("param", "testId")
        self.match = cfg.get("match", "{testId}")
        self.wait = float(cfg.get("wait", 0.2))
        self.headers = dict(cfg.get("headers") or {})

    def describe(self) -> dict:
        return {"adapter": self.name, "url": self.url, "match": self.match}

    def collect(self, trace_id: str, context: dict) -> list[dict]:
        time.sleep(self.wait)
        value = fill(self.match, {"testId": trace_id, **context})
        url = fill(self.url, {"testId": trace_id, **context})
        if "{" not in self.url:
            url = f"{url}{'&' if '?' in url else '?'}{self.param}={value}"
        status, body = request("GET", url, headers=self.headers)
        events = body.get("events", []) if status == 200 and isinstance(body, dict) else []
        for e in events:
            e.setdefault("testId", trace_id)
        return events


class OAuth2IntrospectionIdentity:
    """client_credentials token + RFC 7662 introspection (the original AgentSec identity adapter)."""
    name = "oauth2-introspection"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.cfg = cfg

    def discover(self, log) -> dict:
        ident = oauth2_identity.discover(self.cfg)
        return {**ident, "kind": "workload", "auth": "oauth2"}


class StaticIdentity:
    """Identity declared in target.yaml (when the platform cannot be queried)."""
    name = "static"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.cfg = cfg

    def discover(self, log) -> dict:
        return {"subject": self.cfg.get("subject", "agent-identity"), "scopes": sorted(self.cfg.get("scopes") or []),
                "kind": self.cfg.get("kind", "workload"), "auth": "declared",
                "checkLeastPrivilege": self.cfg.get("checkLeastPrivilege", True)}
