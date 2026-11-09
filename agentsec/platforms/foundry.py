"""Azure AI Foundry Agent Service adapter (agents REST API, same shapes as the azure-ai-agents SDK).

    target: {name: engineering-agent, platform: foundry}
    agent:
      adapter: foundry
      project_endpoint: https://<resource>.services.ai.azure.com/api/projects/<project>
      agent_id: asst_xxx
      api_version: 2025-05-15-preview
      auth: {type: azure-cli}     # or {type: entra, tenant_id, client_id, client_secret_env}
      tool_resources:             # passed to every run - use the SAME settings as production
        mcp: [{server_label: materials, require_approval: never}]
      onApproval: deny            # tool approval requests are denied (and recorded as blocked)

Discover : GET /assistants/{id}            -> tools (function | openapi | mcp | connected_agent) + knowledge
Invoke   : POST /threads, /messages, /runs  -> poll run, deny approvals, refuse client-side function calls
Telemetry: GET /threads/{t}/runs/{r}/steps  -> every tool call the run really made (in-band, exact correlation)
"""
from __future__ import annotations

import copy
import json
import time

from ..adapters import mcp as mcp_adapter
from ..adapters.http import request
from .auth import TokenProvider
from .base import AdapterError, ChatResult, Discovered, ToolSpec, compose_message, estimate_records, event, parse_args

TERMINAL = {"completed", "failed", "cancelled", "expired", "incomplete"}
KNOWLEDGE_TOOLS = {"file_search": "Files", "azure_ai_search": "Azure AI Search index", "sharepoint_grounding":
                   "SharePoint", "bing_grounding": "Bing web search", "bing_custom_search": "Bing custom search",
                   "fabric_dataagent": "Microsoft Fabric", "microsoft_fabric": "Microsoft Fabric"}
FUNCTION_REFUSAL = json.dumps({"error": "Tool execution is not available in this AgentSec security test."})


class FoundryClient:
    def __init__(self, cfg: dict):
        for key in ("project_endpoint", "agent_id"):
            if not cfg.get(key):
                raise AdapterError(f"agent.adapter foundry requires '{key}'")
        self.cfg = cfg
        self.base = cfg["project_endpoint"].rstrip("/")
        self.version = cfg.get("api_version", "2025-05-15-preview")
        self.auth = TokenProvider(cfg.get("auth"), default_scope="https://ai.azure.com/.default")

    def call(self, method: str, path: str, payload=None, query: str = "") -> dict:
        url = f"{self.base}{path}?api-version={self.version}{'&' + query if query else ''}"
        status, body = request(method, url, payload, headers=self.auth.headers())
        if status not in (200, 201):
            raise AdapterError(f"Foundry {method} {path} failed ({status}): {body.get('error', body)}")
        return body


def _client(cfg: dict, ctx: dict) -> FoundryClient:
    key = ("foundry", cfg.get("project_endpoint"), cfg.get("agent_id"))
    if key not in ctx:
        ctx[key] = FoundryClient(cfg)
    return ctx[key]


def _approval_map(tool_resources: dict) -> dict:
    return {m.get("server_label"): m.get("require_approval", "always") for m in (tool_resources or {}).get("mcp", [])}


class FoundryDiscoverer:
    name = "foundry"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        agent_cfg = target.get("agent") or {}
        self.cfg = {**agent_cfg, **cfg} if agent_cfg.get("adapter") == "foundry" else cfg
        self.client = _client(self.cfg, ctx)

    def discover(self, log) -> Discovered:
        a = self.client.call("GET", f"/assistants/{self.cfg['agent_id']}")
        approvals = _approval_map(self.cfg.get("tool_resources"))
        tools, knowledge = [], []
        for t in a.get("tools", []):
            kind = t.get("type")
            if kind == "function":
                f = t.get("function", {})
                tools.append(ToolSpec(f["name"], f.get("description", ""), source="foundry-function",
                                      attributes={"parameters": f.get("parameters"), "executes": "client"}))
            elif kind == "openapi":
                o = t.get("openapi", {})
                from ..adapters import openapi
                spec = openapi.parse(o.get("spec") or {}, f"foundry:{o.get('name')}")
                for op_id, op in spec["operations"].items():
                    tools.append(ToolSpec(f"{o.get('name')}_{op_id}", op.get("summary") or o.get("description", ""),
                                          source="foundry-openapi", openapi=o.get("spec"), operationId=op_id,
                                          aliases=[op_id], attributes={"auth": (o.get("auth") or {}).get("type")}))
            elif kind == "mcp":
                label, url = t.get("server_label"), t.get("server_url")
                allowed = set(t.get("allowed_tools") or [])
                policy = approvals.get(label, "always")
                try:
                    found = mcp_adapter.discover(url)["tools"]
                except Exception as e:  # noqa: BLE001 - server may not be reachable from the scanner
                    log(f"  foundry   mcp '{label}' not reachable from scanner ({e}); using allowed_tools only")
                    found = [{"name": n} for n in sorted(allowed)]
                for x in found:
                    if allowed and x["name"] not in allowed:
                        continue
                    meta, ann = x.get("_meta") or {}, x.get("annotations") or {}
                    down = meta.get("downstream") or {}
                    tools.append(ToolSpec(
                        x["name"], x.get("description", ""), source="foundry-mcp",
                        humanApproval=_requires(policy, x["name"]), destructive=ann.get("destructiveHint"),
                        openapi=down.get("openapi"), operationId=down.get("operationId"),
                        attributes={"server_label": label, "server_url": url, "require_approval": policy}))
            elif kind == "connected_agent":
                c = t.get("connected_agent", {})
                tools.append(ToolSpec(c.get("name", "connected_agent"), c.get("description", ""),
                                      source="foundry-connected-agent", attributes={"agent_id": c.get("id")}))
            elif kind in KNOWLEDGE_TOOLS:
                knowledge.append({"name": KNOWLEDGE_TOOLS[kind], "kind": kind, "scoped": kind != "bing_grounding",
                                  "dataClassification": "public" if kind.startswith("bing") else None})
        log(f"  foundry   agent {a.get('name', a.get('id'))} ({a.get('model')}): {len(tools)} tools, "
            f"{len(knowledge)} knowledge sources")
        return Discovered("foundry", a.get("name", a.get("id")), tools, knowledge,
                          agent={"model": a.get("model"), "instructionsLength": len(a.get("instructions") or ""),
                                 "platform": "Azure AI Foundry"}, raw={"assistant": a})


def _requires(policy, name: str) -> bool:
    if policy == "never":
        return False
    if isinstance(policy, dict):
        never = policy.get("never") or {}
        never = never.get("tool_names", []) if isinstance(never, dict) else never
        always = policy.get("always") or {}
        always = always.get("tool_names", []) if isinstance(always, dict) else always
        if name in always:
            return True
        return name not in never
    return True


class FoundryInvoker:
    name = "foundry"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.cfg = cfg
        self.client = _client(cfg, ctx)
        self.timeout = float(cfg.get("timeout", 120))
        self.poll = float(cfg.get("poll", 0.5))

    def describe(self) -> dict:
        return {"adapter": self.name, "endpoint": self.client.base, "agent_id": self.cfg["agent_id"]}

    def _tool_resources(self, trace_id: str) -> dict | None:
        tr = copy.deepcopy(self.cfg.get("tool_resources") or {})
        if self.cfg.get("propagateTestId", True):
            for m in tr.get("mcp", []):  # MCP headers are forwarded by Foundry to the MCP server
                m.setdefault("headers", {})["X-AgentSec-Test-Id"] = trace_id
        return tr or None

    def invoke(self, message: str, documents: list[dict], trace_id: str) -> ChatResult:
        c = self.client
        thread = c.call("POST", "/threads", {"metadata": {"agentsec_test_id": trace_id}})
        tid = thread["id"]
        c.call("POST", f"/threads/{tid}/messages", {"role": "user", "content": compose_message(message, documents)})
        body = {"assistant_id": self.cfg["agent_id"]}
        tr = self._tool_resources(trace_id)
        if tr:
            body["tool_resources"] = tr
        run = c.call("POST", f"/threads/{tid}/runs", body)
        rid, events = run["id"], {}
        deadline = time.time() + self.timeout
        while run["status"] not in TERMINAL:
            if time.time() > deadline:
                c.call("POST", f"/threads/{tid}/runs/{rid}/cancel", {})
                return ChatResult(504, f"Run {rid} timed out", {"threadId": tid, "runId": rid}, list(events.values()))
            if run["status"] == "requires_action":
                self._handle_action(tid, rid, run.get("required_action") or {}, trace_id, events)
            time.sleep(self.poll)
            run = c.call("GET", f"/threads/{tid}/runs/{rid}")
        for e in self._steps(tid, rid, trace_id):
            events.setdefault(e["callId"], e)
        msgs = c.call("GET", f"/threads/{tid}/messages", query="order=desc&limit=20").get("data", [])
        text = "\n".join(part.get("text", {}).get("value", "") for m in reversed(msgs)
                         if m.get("role") == "assistant" and m.get("run_id") in (rid, None)
                         for part in m.get("content", []) if part.get("type") == "text")
        if run["status"] == "failed" and not text:
            text = f"Run failed: {(run.get('last_error') or {}).get('message', '')}"
        return ChatResult(200, text, {"threadId": tid, "runId": rid, "runStatus": run["status"]}, list(events.values()))

    def _handle_action(self, tid: str, rid: str, action: dict, trace_id: str, events: dict) -> None:
        kind = action.get("type")
        calls = (action.get(kind) or {}).get("tool_calls", [])
        if kind == "submit_tool_approval":
            for tc in calls:
                events[tc["id"]] = event(tc.get("name"), "blocked:approval_required", trace_id, callId=tc["id"],
                                         arguments=parse_args(tc.get("arguments")), source="foundry-run",
                                         server=tc.get("server_label"))
            if self.cfg.get("onApproval", "deny") == "cancel":
                self.client.call("POST", f"/threads/{tid}/runs/{rid}/cancel", {})
            else:
                self.client.call("POST", f"/threads/{tid}/runs/{rid}/submit_tool_outputs",
                                 {"tool_approvals": [{"tool_call_id": tc["id"], "approve": False} for tc in calls]})
        elif kind == "submit_tool_outputs":
            # Client-side function tools: the agent *decided* to call them. In production your app would execute
            # them; AgentSec records the request and returns a refusal so the run can finish.
            for tc in calls:
                f = tc.get("function", {})
                events[tc["id"]] = event(f.get("name"), "requested", trace_id, callId=tc["id"],
                                         arguments=parse_args(f.get("arguments")), source="foundry-run",
                                         executesIn="client-application")
            self.client.call("POST", f"/threads/{tid}/runs/{rid}/submit_tool_outputs",
                             {"tool_outputs": [{"tool_call_id": tc["id"], "output": FUNCTION_REFUSAL} for tc in calls]})

    def _steps(self, tid: str, rid: str, trace_id: str) -> list[dict]:
        out = []
        steps = self.client.call("GET", f"/threads/{tid}/runs/{rid}/steps", query="order=asc").get("data", [])
        for s in steps:
            details = s.get("step_details") or {}
            if details.get("type") != "tool_calls":
                continue
            status = {"completed": "success", "cancelled": "blocked:cancelled"}.get(
                s.get("status"), f"denied:{(s.get('last_error') or {}).get('code', s.get('status'))}")
            for tc in details.get("tool_calls", []):
                kind = tc.get("type")
                body = tc.get(kind) if isinstance(tc.get(kind), dict) else {}
                name = tc.get("name") or body.get("name") or (tc.get("function") or {}).get("name") or kind
                output = tc.get("output", body.get("output", (tc.get("function") or {}).get("output")))
                st = status
                if kind == "function" and output == FUNCTION_REFUSAL:
                    st = "requested"
                out.append(event(name, st, trace_id, callId=tc.get("id"), source="foundry-run-steps",
                                 timestamp=_iso(s.get("completed_at") or s.get("created_at")),
                                 arguments=parse_args(tc.get("arguments", body.get("arguments"))),
                                 recordsReturned=estimate_records(output) if st == "success" else 0,
                                 server=tc.get("server_label"), stepId=s.get("id")))
        return out


def _iso(ts) -> str | None:
    if isinstance(ts, (int, float)):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    return ts
