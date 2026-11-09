"""Azure Monitor telemetry (Application Insights / Log Analytics) via KQL.

Use when tool calls are already traced to App Insights (Foundry tracing, Copilot Studio App Insights
integration, API Management, your own MCP server). AgentSec runs a KQL query per test and maps rows to
normalized tool-call events.

    telemetry:
      - type: app-insights            # or log-analytics
        app_id: <Application Insights app id>      # log-analytics: workspace_id
        endpoint: https://api.applicationinsights.io   # (log-analytics: https://api.loganalytics.io)
        auth: {type: entra, tenant_id: ..., client_id: ..., client_secret_env: ...}
        query: |
          dependencies
          | where timestamp > ago(30m)
          | where tostring(customDimensions["agentsec.conversationId"]) == "{conversationId}"
          | project timestamp, tool=name, status=iff(success, "success", strcat("denied:", resultCode)),
                    records=toint(customDimensions["records"])
        fields: {tool: tool, timestamp: timestamp, status: status, recordsReturned: records}
        retries: 6        # ingestion is delayed by minutes on real tenants
        delay: 10

Placeholders available in the query: {testId} plus any correlation id the invoker returned
({conversationId}, {threadId}, {runId}, {sessionId}).
"""
from __future__ import annotations

import json
import time

from ..adapters.http import request
from .auth import TokenProvider
from .base import AdapterError, event, fill

DEFAULTS = {
    "app-insights": ("https://api.applicationinsights.io", "apps", "app_id", "https://api.applicationinsights.io/.default"),
    "log-analytics": ("https://api.loganalytics.io", "workspaces", "workspace_id", "https://api.loganalytics.io/.default"),
}


def _lookup(row: dict, path: str):
    cur = row
    for part in path.split("."):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except ValueError:
                return None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


class KqlTelemetry:
    def __init__(self, cfg: dict, target: dict, ctx: dict):
        kind = cfg["type"]
        base, coll, key, scope = DEFAULTS[kind]
        self.name = kind
        if not cfg.get(key):
            raise AdapterError(f"telemetry type {kind} requires '{key}'")
        self.url = f"{cfg.get('endpoint', base).rstrip('/')}/v1/{coll}/{cfg[key]}/query"
        self.query = cfg["query"]
        self.fields = {"tool": "tool", "timestamp": "timestamp", "status": "status",
                       "recordsReturned": "recordsReturned", **(cfg.get("fields") or {})}
        self.retries, self.delay = int(cfg.get("retries", 1)), float(cfg.get("delay", 0.2))
        self.auth = TokenProvider(cfg.get("auth"), default_scope=scope)

    def describe(self) -> dict:
        return {"adapter": self.name, "url": self.url}

    def collect(self, trace_id: str, context: dict) -> list[dict]:
        query = fill(self.query, {"testId": trace_id, **context})
        rows: list[dict] = []
        for _ in range(max(1, self.retries)):
            time.sleep(self.delay)
            status, body = request("POST", self.url, {"query": query}, headers=self.auth.headers())
            if status != 200:
                raise AdapterError(f"KQL query failed ({status}): {body.get('error', body)}")
            for table in body.get("tables", [])[:1]:
                cols = [c["name"] for c in table.get("columns", [])]
                rows = [dict(zip(cols, r)) for r in table.get("rows", [])]
            if rows:
                break
        events = []
        for row in rows:
            get = {k: _lookup(row, v) for k, v in self.fields.items()}
            status = get.get("status")
            if status is True or status in (None, "", "true", "True"):
                status = "success"
            elif status is False:
                status = "denied"
            events.append(event(str(get.get("tool")), str(status), trace_id,
                                timestamp=get.get("timestamp"), recordsReturned=int(get.get("recordsReturned") or 0),
                                humanApproval=bool(_lookup(row, self.fields.get("humanApproval", "humanApproval"))),
                                source=self.name))
        return events
