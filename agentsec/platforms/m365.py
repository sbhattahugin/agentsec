"""Microsoft 365 Copilot declarative agent adapter.

    target: {name: engineering-agent, platform: m365-copilot}
    discovery:
      - type: m365-package
        package: ./appPackage            # folder or .zip containing manifest.json (Teams app manifest)
        agent_id: engineeringAgent       # optional; first declarative agent otherwise
        tenantKnowledgeClassification: confidential   # what un-scoped OneDrive/SharePoint grounding can reach
    agent:                               # optional live testing (experimental, Graph beta, delegated token)
      adapter: m365-copilot-chat
      graph: https://graph.microsoft.com
      auth: {type: bearer, token_env: M365_COPILOT_TOKEN}
    telemetry:                           # Copilot does not return tool calls; observe them downstream
      - type: http-events | app-insights ...

Static analysis works on the package alone:
  manifest.json -> copilotAgents.declarativeAgents[] -> declarativeAgent.json
     capabilities[]  (OneDriveAndSharePoint, GraphConnectors, WebSearch, Email, TeamsMessages, ...)  -> knowledge
     actions[]       -> plugin manifest (schema v2.x): functions[] + runtimes[] (OpenApi | RemoteMCPServer)
  function.capabilities.confirmation.type  AdaptiveCard -> human approval; None -> none.
  If unset, Copilot asks for confirmation on non-GET OpenAPI operations unless x-openai-isConsequential: false.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path, PurePosixPath

from ..adapters import mcp as mcp_adapter
from ..adapters import openapi
from ..adapters.http import request
from .auth import TokenProvider
from .base import AdapterError, ChatResult, Discovered, ToolSpec, compose_message

KNOWLEDGE = {"OneDriveAndSharePoint": ("items_by_url", "items_by_sharepoint_ids"), "GraphConnectors": ("connections",),
             "WebSearch": ("sites",), "Email": ("shared_mailbox", "folders"), "TeamsMessages": ("urls",),
             "People": (), "Meetings": (), "Dataverse": ("knowledge_sources",), "EmbeddedKnowledge": ("files",),
             "CopilotConnectors": ("connections",)}
TENANT_WIDE = {"OneDriveAndSharePoint", "Email", "TeamsMessages", "People", "Meetings", "GraphConnectors"}


class _Package:
    def __init__(self, path: Path):
        self.path = path
        self.zip = zipfile.ZipFile(path) if path.is_file() else None

    def read(self, rel: str) -> str:
        rel = str(PurePosixPath(rel.replace("\\", "/")))
        if self.zip:
            return self.zip.read(rel).decode("utf-8-sig")
        return (self.path / rel).read_text(encoding="utf-8-sig")

    def json(self, rel: str) -> dict:
        return json.loads(self.read(rel))


class M365PackageDiscoverer:
    name = "m365-package"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        base = Path(target.get("_base_dir", "."))
        p = Path(cfg["package"])
        self.path = p if p.is_absolute() else base / p
        if not self.path.exists():
            raise AdapterError(f"M365 app package not found: {self.path}")
        self.cfg = cfg

    def discover(self, log) -> Discovered:
        pkg = _Package(self.path)
        manifest = pkg.json("manifest.json")
        agents = (manifest.get("copilotAgents") or {}).get("declarativeAgents") or []
        if not agents:
            raise AdapterError("manifest.json has no copilotAgents.declarativeAgents")
        ref = next((a for a in agents if a.get("id") == self.cfg.get("agent_id")), agents[0])
        da = pkg.json(ref["file"])
        da_dir = str(PurePosixPath(ref["file"]).parent)

        knowledge = []
        tenant_cls = self.cfg.get("tenantKnowledgeClassification", "confidential")
        for cap in da.get("capabilities", []):
            name = cap.get("name")
            if name not in KNOWLEDGE:
                continue
            scoped = any(cap.get(k) for k in KNOWLEDGE[name]) if KNOWLEDGE[name] else False
            cls = "public" if name == "WebSearch" else (tenant_cls if name in TENANT_WIDE and not scoped else None)
            knowledge.append({"name": name, "kind": name, "scoped": scoped or name not in TENANT_WIDE,
                              "dataClassification": cls,
                              "detail": ", ".join(str(x) for k in KNOWLEDGE[name] for x in (cap.get(k) or []))[:200]
                              or ("entire tenant (everything the signed-in user can access)"
                                  if name in TENANT_WIDE else None)})

        tools = []
        for action in da.get("actions", []):
            plugin_path = str(PurePosixPath(da_dir) / action["file"])
            plugin = pkg.json(plugin_path)
            plugin_dir = str(PurePosixPath(plugin_path).parent)
            funcs = {f["name"]: f for f in plugin.get("functions", [])}
            for rt in plugin.get("runtimes", []):
                targets = rt.get("run_for_functions") or ["*"]
                names = list(funcs) if "*" in targets else [n for n in targets if n in funcs]
                auth = (rt.get("auth") or {}).get("type", "None")
                if rt.get("type") == "OpenApi":
                    url = (rt.get("spec") or {}).get("url", "")
                    spec_doc = self._spec(pkg, plugin_dir, url)
                    ops = openapi.parse(spec_doc, url)["operations"]
                    for n in names:
                        op = ops.get(n, {})
                        tools.append(self._tool(funcs[n], plugin, "m365-openapi", spec_doc, n if op else None,
                                                default_confirm=op.get("method", "GET") != "GET"
                                                and op.get("consequential") is not False,
                                                attrs={"method": op.get("method"), "path": op.get("path"),
                                                       "auth": auth}))
                elif rt.get("type") == "RemoteMCPServer":
                    url = (rt.get("spec") or {}).get("url")
                    live = self._mcp(url, log)
                    for n in names:
                        meta = (live.get(n) or {}).get("_meta") or {}
                        down = meta.get("downstream") or {}
                        t = self._tool(funcs[n], plugin, "m365-mcp", down.get("openapi"), down.get("operationId"),
                                       default_confirm=None, attrs={"server": url, "auth": auth})
                        t.destructive = ((live.get(n) or {}).get("annotations") or {}).get("destructiveHint")
                        tools.append(t)
        log(f"  m365      {da.get('name')}: {len(tools)} actions, {len(knowledge)} knowledge capabilities "
            f"({self.path.name})")
        return Discovered("m365-package", da.get("name", ref["id"]), tools, knowledge,
                          agent={"platform": "Microsoft 365 Copilot", "declarativeAgent": ref["id"],
                                 "instructionsLength": len(da.get("instructions") or ""),
                                 "appId": manifest.get("id")},
                          raw={"declarativeAgent": {k: da.get(k) for k in ("name", "description", "capabilities")}})

    @staticmethod
    def _spec(pkg: _Package, plugin_dir: str, url: str) -> dict:
        if url.startswith(("http://", "https://")):
            status, body = request("GET", url)
            if status != 200:
                raise AdapterError(f"Cannot load OpenAPI spec {url}: {status}")
            return body
        import yaml
        text = pkg.read(str(PurePosixPath(plugin_dir) / url))
        return json.loads(text) if text.lstrip().startswith("{") else yaml.safe_load(io.StringIO(text))

    @staticmethod
    def _mcp(url: str | None, log) -> dict:
        if not url:
            return {}
        try:
            return {t["name"]: t for t in mcp_adapter.discover(url)["tools"]}
        except Exception as e:  # noqa: BLE001 - static analysis still works from the manifest
            log(f"  m365      MCP runtime {url} not reachable from scanner ({e}); using manifest only")
            return {}

    @staticmethod
    def _tool(func: dict, plugin: dict, source: str, spec, op_id, default_confirm, attrs) -> ToolSpec:
        conf = ((func.get("capabilities") or {}).get("confirmation") or {}).get("type")
        approval = True if conf == "AdaptiveCard" else False if conf == "None" else default_confirm
        return ToolSpec(func["name"], func.get("description", ""), source=source, humanApproval=approval,
                        openapi=spec, operationId=op_id,
                        attributes={**attrs, "plugin": plugin.get("name_for_human"), "confirmation": conf or "default"})


class CopilotChatInvoker:
    """EXPERIMENTAL: Microsoft 365 Copilot Chat API (Graph beta, delegated user token, Copilot licence)."""
    name = "m365-copilot-chat"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.base = cfg.get("graph", "https://graph.microsoft.com").rstrip("/") + "/beta/copilot"
        self.auth = TokenProvider(cfg.get("auth") or {"type": "bearer", "token_env": "M365_COPILOT_TOKEN"},
                                  default_scope="https://graph.microsoft.com/.default")
        self.tz = cfg.get("timeZone", "UTC")

    def describe(self) -> dict:
        return {"adapter": self.name, "endpoint": self.base}

    def invoke(self, message: str, documents: list[dict], trace_id: str) -> ChatResult:
        h = self.auth.headers()
        status, conv = request("POST", f"{self.base}/conversations", {}, headers=h)
        if status not in (200, 201):
            return ChatResult(status, f"Copilot conversation failed: {conv}")
        text = compose_message(message, documents)
        status, body = request("POST", f"{self.base}/conversations/{conv['id']}/chat",
                               {"message": {"text": text}, "locationHint": {"timeZone": self.tz}}, headers=h,
                               timeout=120)
        msgs = [m.get("text", "") for m in body.get("messages", []) if m.get("text") and m.get("text") != text]
        return ChatResult(status if status != 201 else 200, msgs[-1] if msgs else str(body),
                          {"conversationId": conv["id"]})
