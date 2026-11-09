"""Microsoft Copilot Studio adapter.

    target: {name: engineering-agent, platform: copilot-studio}
    agent:
      adapter: copilot-studio
      directline:
        endpoint: https://europe.directline.botframework.com/v3/directline
        secret_env: COPILOT_STUDIO_DIRECTLINE_SECRET     # Settings > Security > Web channel security
        # token_endpoint: <Copilot Studio token endpoint>   # alternative for agents without secured access
      timeout: 60
    discovery:
      - type: copilot-studio
        environment_url: https://<org>.crm4.dynamics.com
        bot_schema: cr123_engineeringAgent
        auth: {type: entra, tenant_id: ..., client_id: ..., client_secret_env: ...}  # Dataverse app user
        connectors:                         # custom connector / REST tool -> its OpenAPI definition
          cr123_materialapi: ./specs/material-api.yaml
    telemetry:
      - type: copilot-studio-transcripts    # optional; transcripts are written after the session ends

Discover : Dataverse bots + botcomponents (topic/action YAML: kind TaskDialog, knowledge sources)
Invoke   : Direct Line 3.0 (conversations -> activities -> poll)
Telemetry: generative-orchestration event activities (DynamicPlanStepTriggered/Finished) in the Direct Line
           stream, and/or Dataverse conversationtranscripts.

NOTE: the botcomponent YAML schema and orchestration event names are not formally documented by Microsoft;
parsing here is heuristic and every derived fact can be corrected with `overrides.tools` in target.yaml.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

import yaml

from ..adapters.http import request
from .auth import TokenProvider
from .base import (AdapterError, ChatResult, Discovered, ToolSpec, compose_message, estimate_records, event,
                   odata_url, parse_args)

STEP_START, STEP_END = "DynamicPlanStepTriggered", "DynamicPlanStepFinished"


def events_from_activities(activities: list[dict], trace_id: str, source: str) -> list[dict]:
    """Map Copilot Studio generative-orchestration event activities to normalized tool-call events."""
    steps: dict[str, dict] = {}
    for a in activities:
        if a.get("type") != "event" or a.get("name") not in (STEP_START, STEP_END, "DynamicPlanStepBindUpdate"):
            continue
        v = a.get("value") or {}
        sid = v.get("stepId") or v.get("taskDialogId")
        s = steps.setdefault(sid, {"tool": v.get("taskDialogId"), "timestamp": a.get("timestamp"), "finished": None})
        if a["name"] == "DynamicPlanStepBindUpdate":
            s["arguments"] = v.get("arguments")
        elif a["name"] == STEP_END:
            s["finished"] = v
    out = []
    for sid, s in steps.items():
        fin = s["finished"]
        if fin is None:
            status, records = "incomplete", 0
        else:
            obs = fin.get("observation")
            err = fin.get("error") or (obs.get("error") if isinstance(obs, dict) else None)
            state = str(fin.get("state", "completed")).lower()
            if err or state in ("failed", "faulted", "error"):
                code = (err or {}).get("code", state) if isinstance(err, dict) else (err or state)
                status = f"blocked:{code}" if "approv" in str(code).lower() else f"denied:{code}"
                records = 0
            else:
                status, records = "success", estimate_records(fin.get("observation"))
        out.append(event(s["tool"], status, trace_id, timestamp=s["timestamp"], stepId=sid, source=source,
                         arguments=parse_args(s.get("arguments")), recordsReturned=records))
    return out


class DirectLineInvoker:
    name = "copilot-studio"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        dl = cfg.get("directline") or {}
        self.endpoint = dl.get("endpoint", "https://directline.botframework.com/v3/directline").rstrip("/")
        self.secret_env = dl.get("secret_env")
        self.token_endpoint = dl.get("token_endpoint")
        if not (self.secret_env or self.token_endpoint):
            raise AdapterError("agent.directline needs secret_env or token_endpoint")
        self.timeout = float(cfg.get("timeout", 60))
        self.quiet = float(cfg.get("quiet", 1.5))
        self.poll = float(cfg.get("poll", 0.3))
        self.user = cfg.get("userId", "agentsec-tester")

    def describe(self) -> dict:
        return {"adapter": self.name, "endpoint": self.endpoint}

    def _bearer(self) -> str:
        if self.secret_env:
            secret = os.environ.get(self.secret_env)
            if not secret:
                raise AdapterError(f"environment variable {self.secret_env} is not set")
            return secret
        status, body = request("GET", self.token_endpoint)
        if status != 200 or "token" not in body:
            raise AdapterError(f"Direct Line token endpoint failed ({status})")
        return body["token"]

    def invoke(self, message: str, documents: list[dict], trace_id: str) -> ChatResult:
        status, conv = request("POST", f"{self.endpoint}/conversations", {},
                               headers={"Authorization": f"Bearer {self._bearer()}"})
        if status not in (200, 201):
            return ChatResult(status, f"Direct Line start failed: {conv}")
        cid, headers = conv["conversationId"], {"Authorization": f"Bearer {conv['token']}"}
        status, _ = request("POST", f"{self.endpoint}/conversations/{cid}/activities", {
            "type": "message", "from": {"id": self.user, "name": "AgentSec"}, "locale": "en-US",
            "text": compose_message(message, documents),
            "channelData": {"agentsecTestId": trace_id}}, headers=headers)
        if status not in (200, 201):
            return ChatResult(status, "Direct Line send failed", {"conversationId": cid})
        activities, watermark = [], None
        deadline, last_new = time.time() + self.timeout, time.time()
        while time.time() < deadline:
            time.sleep(self.poll)
            q = f"?watermark={watermark}" if watermark else ""
            status, body = request("GET", f"{self.endpoint}/conversations/{cid}/activities{q}", headers=headers)
            new = [a for a in body.get("activities", []) if (a.get("from") or {}).get("id") != self.user]
            watermark = body.get("watermark", watermark)
            if new:
                activities += new
                last_new = time.time()
            done = any(a.get("type") == "endOfConversation" for a in new)
            replied = any(a.get("type") == "message" for a in activities)
            if done or (replied and time.time() - last_new > self.quiet):
                break
        text = "\n".join(a.get("text", "") for a in activities if a.get("type") == "message" and a.get("text"))
        events = events_from_activities(activities, trace_id, "directline-activities")
        return ChatResult(200, text, {"conversationId": cid, "activities": len(activities)}, events)


class _Dataverse:
    def __init__(self, cfg: dict):
        if not cfg.get("environment_url"):
            raise AdapterError("copilot-studio discovery requires environment_url")
        self.env = cfg["environment_url"].rstrip("/")
        self.auth = TokenProvider(cfg.get("auth"), default_scope=f"{self.env}/.default")

    def get(self, path: str) -> dict:
        status, body = request("GET", odata_url(f"{self.env}/api/data/v9.2/{path}"),
                               headers={**self.auth.headers(), "Accept": "application/json", "OData-Version": "4.0"})
        if status != 200:
            raise AdapterError(f"Dataverse GET {path.split('?')[0]} failed ({status}): {body.get('error', body)}")
        return body

    def bot(self, schema: str) -> dict:
        bots = self.get(f"bots?$select=botid,name,schemaname&$filter=schemaname eq '{schema}'").get("value", [])
        if not bots:
            raise AdapterError(f"Copilot Studio agent with schema name '{schema}' not found")
        return bots[0]


def _component_yaml(c: dict) -> dict:
    try:
        data = yaml.safe_load(c.get("data") or "") or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


class CopilotStudioDiscoverer:
    name = "copilot-studio"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.cfg = cfg
        self.dv = _Dataverse(cfg)
        self.connectors = cfg.get("connectors") or {}

    def discover(self, log) -> Discovered:
        bot = self.dv.bot(self.cfg["bot_schema"])
        comps = self.dv.get(f"botcomponents?$select=name,schemaname,componenttype,description,data"
                            f"&$filter=_parentbotid_value eq {bot['botid']}").get("value", [])
        tools, knowledge = [], []
        for c in comps:
            data = _component_yaml(c)
            kind = data.get("kind")
            if kind == "TaskDialog":
                action = data.get("action") or {}
                ref = action.get("connectionReference") or action.get("connectorId") or ""
                spec = next((v for k, v in self.connectors.items() if k and k in ref), None)
                approval = bool(data.get("confirmation") or action.get("confirmation")
                                or data.get("requireUserConfirmation")) or None
                tools.append(ToolSpec(
                    c.get("name") or c["schemaname"], data.get("modelDescription") or c.get("description") or "",
                    source=f"copilot-studio:{action.get('kind', 'action')}", humanApproval=approval,
                    openapi=spec, operationId=action.get("operationId") if spec else None,
                    aliases=[c["schemaname"]], attributes={"actionKind": action.get("kind"), "connection": ref}))
            elif kind and "Knowledge" in kind:
                src = data.get("source") or {}
                skind = src.get("kind", "unknown")
                knowledge.append({"name": c.get("name") or c["schemaname"], "kind": skind,
                                  "scoped": bool(src.get("site") or src.get("url") or src.get("items")
                                                 or skind != "SharePointSearchSource"),
                                  "dataClassification": "public" if "PublicSite" in skind else None,
                                  "detail": src.get("site") or src.get("url")})
        log(f"  copilot   {bot['name']} ({bot['schemaname']}): {len(comps)} components, {len(tools)} tools, "
            f"{len(knowledge)} knowledge sources")
        return Discovered("copilot-studio", bot["name"], tools, knowledge,
                          agent={"botId": bot["botid"], "platform": "Copilot Studio"},
                          raw={"components": [{k: c.get(k) for k in ("name", "schemaname", "componenttype")}
                                              for c in comps]})


class TranscriptTelemetry:
    """Dataverse conversationtranscripts (written after the conversation ends - configure retries generously)."""
    name = "copilot-studio-transcripts"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        disc = next((d for d in target.get("discovery") or [] if d.get("type") == "copilot-studio"), {})
        merged = {**disc, **cfg}
        self.dv = _Dataverse(merged)
        self.schema = merged.get("bot_schema")
        self.retries, self.delay = int(cfg.get("retries", 3)), float(cfg.get("delay", 1))
        self._bot = None

    def describe(self) -> dict:
        return {"adapter": self.name, "url": self.dv.env}

    def collect(self, trace_id: str, context: dict) -> list[dict]:
        cid = context.get("conversationId")
        if not cid:
            return []
        self._bot = self._bot or self.dv.bot(self.schema)
        since = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for _ in range(max(1, self.retries)):
            time.sleep(self.delay)
            rows = self.dv.get(f"conversationtranscripts?$select=content,conversationstarttime"
                               f"&$filter=_bot_conversationtranscriptid_value eq {self._bot['botid']} "
                               f"and createdon ge {since}").get("value", [])
            for r in rows:
                if cid not in (r.get("content") or ""):
                    continue
                try:
                    acts = json.loads(r["content"]).get("activities", [])
                except ValueError:
                    continue
                return events_from_activities(acts, trace_id, "dataverse-transcript")
        return []
