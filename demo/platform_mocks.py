"""Mock agent platforms for the AgentSec lab: the real platform APIs, backed by the dummy agent stacks.

    Entra ID + Microsoft Graph   token endpoint, servicePrincipals / appRoleAssignments, Copilot Chat API (beta)
    Azure AI Foundry             /api/projects/{project}/assistants|threads|runs|steps (agents REST API shapes)
    Copilot Studio               Direct Line 3.0 + token endpoint, Dataverse bots / botcomponents / transcripts

Each mocked platform agent forwards the conversation to a dummy Stack agent (demo/stack.py) and converts the
MCP server's ground-truth telemetry into what the real platform would expose (Foundry run steps, Copilot
Studio orchestration events). This lets the AgentSec adapters be exercised end-to-end without a tenant.

Also writes example Microsoft 365 Copilot app packages and Atlassian Forge (Rovo) manifests.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import yaml

from stack import CLIENT_SECRET, SCENARIOS, JsonHandler, McpServer, http_json, profile

SECRET_ENV = "AGENTSEC_CLIENT_SECRET"
TENANT = "contoso-lab"
READER_APP = "agentsec-scanner"


def split_message(text: str) -> tuple[str, list[dict]]:
    from agentsec.platforms.base import split_message as split
    return split(text)


def _records_text(ev: dict) -> str:
    n = ev.get("recordsReturned", 0)
    return json.dumps([{"id": f"rec-{i}"} for i in range(min(n, 3))]) + f" ... ({n} records)"


class Platforms:
    """All mocked platforms in one place. `stacks` maps (scenario, mode) -> running Stack."""

    def __init__(self, stacks: dict, host: str = "127.0.0.1", port: int = 9300):
        self.stacks, self.host = stacks, host
        self.ports = {"entra": port, "foundry": port + 1, "copilot": port + 2}
        self.tokens: dict[str, dict] = {}
        self.threads: dict[str, dict] = {}
        self.runs: dict[str, dict] = {}
        self.convs: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.servers: list[ThreadingHTTPServer] = []

    def url(self, part: str) -> str:
        return f"http://{self.host}:{self.ports[part]}"

    # ------------------------------------------------------------------ shared helpers
    def stack(self, key: str):
        scenario, mode = key.rsplit("-", 1)
        return self.stacks.get((scenario, mode))

    def check(self, handler) -> dict | None:
        auth = handler.headers.get("Authorization", "")
        tok = self.tokens.get(auth.removeprefix("Bearer ").strip())
        if not tok:
            handler.send(401, {"error": {"code": "Unauthorized", "message": "Missing or invalid bearer token"}})
        return tok

    def run_agent(self, st, text: str, session: str, test_id: str) -> tuple[str, list[dict]]:
        message, docs = split_message(text)
        _, body = http_json("POST", f"{st.url('agent')}/api/chat",
                            {"message": message, "documents": docs, "sessionId": session},
                            headers={"X-AgentSec-Test-Id": test_id})
        time.sleep(0.05)
        _, tel = http_json("GET", f"{st.url('mcp')}/telemetry?testId={test_id}")
        return body.get("response", ""), tel.get("events", [])

    @staticmethod
    def tools(st) -> list[dict]:
        sc = SCENARIOS[st.scenario]
        return McpServer(sc, profile(st.scenario, st.mode), st.url("api")).tools()

    # ------------------------------------------------------------------ Entra ID + Graph
    def entra_handler(p):  # noqa: N805
        class H(JsonHandler):
            def do_POST(self):
                path = urlparse(self.path).path
                if path.endswith("/oauth2/v2.0/token"):
                    d = self.body()
                    if d.get("client_secret") != CLIENT_SECRET:
                        return self.send(401, {"error": "invalid_client",
                                               "error_description": "AADSTS7000215: Invalid client secret provided."})
                    tok = "eyJ.mock." + secrets.token_hex(12)
                    p.tokens[tok] = {"client_id": d.get("client_id"), "scope": d.get("scope")}
                    return self.send(200, {"token_type": "Bearer", "expires_in": 3599, "access_token": tok})
                parts = path.strip("/").split("/")
                # /m365/{key}/beta/copilot/conversations[/{id}/chat]
                if parts[:1] == ["m365"] and p.check(self):
                    st = p.stack(parts[1])
                    if not st:
                        return self.send(404, {"error": {"code": "NotFound"}})
                    if parts[-1] == "conversations":
                        cid = "conv-" + secrets.token_hex(6)
                        p.convs[cid] = {"stack": st}
                        return self.send(201, {"id": cid, "state": "active"})
                    if parts[-1] == "chat":
                        cid, text = parts[-2], (self.body().get("message") or {}).get("text", "")
                        answer, _ = p.run_agent(st, text, cid, cid)
                        return self.send(200, {"id": cid, "messages": [{"id": "m1", "text": text},
                                                                       {"id": "m2", "text": answer}]})
                self.send(404, {"error": {"code": "NotFound"}})

            def do_GET(self):
                if not p.check(self):
                    return
                path = unquote(urlparse(self.path).path)
                sps = p.service_principals()
                if path.startswith("/v1.0/servicePrincipals(appId="):
                    app_id = path.split("'")[1]
                    sp = next((s for s in sps.values() if s["appId"] == app_id), None)
                    return self.send(200, sp) if sp else self.send(404, {"error": {"code": "Request_ResourceNotFound"}})
                parts = path.strip("/").split("/")
                if parts[:2] == ["v1.0", "servicePrincipals"] and len(parts) >= 3:
                    sp = sps.get(parts[2])
                    if not sp:
                        return self.send(404, {"error": {"code": "Request_ResourceNotFound"}})
                    if len(parts) == 4 and parts[3] == "appRoleAssignments":
                        return self.send(200, {"value": sp["_assignments"]})
                    return self.send(200, {k: v for k, v in sp.items() if not k.startswith("_")})
                if parts[:2] == ["v1.0", "oauth2PermissionGrants"]:
                    return self.send(200, {"value": []})
                self.send(404, {"error": {"code": "NotFound"}})

        return H

    def service_principals(self) -> dict:
        """Agent identities (one per stack) and the resource APIs that define the app roles."""
        sps = {}
        for (scenario, mode), st in self.stacks.items():
            sc = SCENARIOS[scenario]
            res_id = f"sp-{sc['scope']}-api"
            roles = [{"id": f"role-{sc['scope']}-{r}", "value": f"{sc['scope']}.{r}", "allowedMemberTypes": ["Application"]}
                     for r in sc["scopes"]["vulnerable"]]
            sps[res_id] = {"id": res_id, "appId": f"{sc['scope']}-api", "displayName": sc["api_title"], "appRoles": roles}
            held = profile(scenario, mode)["scopes"]
            sid = f"sp-{sc['client_id']}-{mode}"
            sps[sid] = {"id": sid, "appId": f"{sc['client_id']}-{mode}", "displayName": sc["client_id"],
                        "servicePrincipalType": "ManagedIdentity" if mode == "hardened" else "Application",
                        "_assignments": [{"id": f"a-{r['id']}", "resourceId": res_id, "appRoleId": r["id"]}
                                         for r in roles if r["value"] in held]}
        return sps

    # ------------------------------------------------------------------ Azure AI Foundry agents API
    def foundry_handler(p):  # noqa: N805
        class H(JsonHandler):
            def route(self):
                url = urlparse(self.path)
                parts = url.path.strip("/").split("/")
                if parts[:2] != ["api", "projects"] or len(parts) < 4:
                    return None, None, None
                return p.stack(parts[2]), parts[3:], parse_qs(url.query)

            def do_GET(self):
                if not p.check(self):
                    return
                st, rest, _ = self.route()
                if not st:
                    return self.send(404, {"error": {"code": "NotFound"}})
                if rest[0] == "assistants":
                    return self.send(200, p.assistant(st))
                if rest[0] == "threads" and len(rest) >= 3 and rest[2] == "messages":
                    msgs = list(reversed(p.threads[rest[1]]["messages"]))
                    return self.send(200, {"object": "list", "data": msgs})
                if rest[0] == "threads" and len(rest) >= 4 and rest[2] == "runs":
                    run = p.runs.get(rest[3])
                    if len(rest) == 5 and rest[4] == "steps":
                        return self.send(200, {"object": "list", "data": run["_steps"]})
                    return self.send(200, {k: v for k, v in run.items() if not k.startswith("_")})
                self.send(404, {"error": {"code": "NotFound"}})

            def do_POST(self):
                if not p.check(self):
                    return
                st, rest, _ = self.route()
                if not st:
                    return self.send(404, {"error": {"code": "NotFound"}})
                body = self.body()
                if rest == ["threads"]:
                    tid = "thread_" + secrets.token_hex(8)
                    p.threads[tid] = {"id": tid, "messages": [], "metadata": body.get("metadata")}
                    return self.send(200, {"id": tid, "object": "thread"})
                tid = rest[1]
                if rest[2:] == ["messages"]:
                    msg = {"id": "msg_" + secrets.token_hex(6), "object": "thread.message", "role": "user",
                           "thread_id": tid, "run_id": None,
                           "content": [{"type": "text", "text": {"value": body.get("content", "")}}]}
                    p.threads[tid]["messages"].append(msg)
                    return self.send(200, msg)
                if rest[2:] == ["runs"]:
                    return self.send(200, p.start_run(st, tid, body))
                run = p.runs[rest[3]]
                if rest[4:] == ["cancel"]:
                    run["status"] = "cancelled"
                elif rest[4:] == ["submit_tool_outputs"]:
                    for a in body.get("tool_approvals") or []:
                        for s in run["_steps"]:
                            for tc in s["step_details"]["tool_calls"]:
                                if tc["id"] == a["tool_call_id"] and not a.get("approve"):
                                    s.update(status="failed", last_error={"code": "tool_approval_denied",
                                                                          "message": "Tool call was not approved"})
                    run["status"], run["required_action"] = "completed", None
                return self.send(200, {k: v for k, v in run.items() if not k.startswith("_")})

        return H

    def assistant(self, st) -> dict:
        sc = SCENARIOS[st.scenario]
        return {"id": f"asst_{st.scenario}", "object": "assistant", "name": sc["title"], "model": "gpt-4o",
                "instructions": sc["system_prompt"],
                "tools": [{"type": "mcp", "server_label": sc["mcp_name"].replace("-", "_"),
                           "server_url": st.url("mcp"), "allowed_tools": [t["name"] for t in self.tools(st)]},
                          {"type": "bing_grounding", "bing_grounding": {"search_configurations": []}}]}

    def start_run(self, st, tid: str, body: dict) -> dict:
        sc = SCENARIOS[st.scenario]
        rid = "run_" + secrets.token_hex(8)
        mcp_res = ((body.get("tool_resources") or {}).get("mcp") or [{}])[0]
        test_id = (mcp_res.get("headers") or {}).get("X-AgentSec-Test-Id") or rid
        user = [m for m in self.threads[tid]["messages"] if m["role"] == "user"][-1]
        answer, events = self.run_agent(st, user["content"][0]["text"]["value"], tid, test_id)
        label = sc["mcp_name"].replace("-", "_")
        steps, approvals = [], []
        for i, ev in enumerate(events):
            call = {"id": f"call_{secrets.token_hex(5)}", "type": "mcp", "name": ev["tool"], "server_label": label,
                    "arguments": json.dumps(ev.get("arguments") or {}), "output": ""}
            step = {"id": f"step_{i}", "object": "thread.run.step", "type": "tool_calls", "run_id": rid,
                    "created_at": int(time.time()), "completed_at": int(time.time()), "status": "completed",
                    "step_details": {"type": "tool_calls", "tool_calls": [call]}}
            if ev["status"] == "success":
                call["output"] = _records_text(ev)
            elif ev["status"] == "blocked:approval_required":
                approvals.append({"id": call["id"], "type": "mcp", "name": ev["tool"], "server_label": label,
                                  "arguments": call["arguments"]})
                step["status"] = "in_progress"
            else:
                step.update(status="failed", last_error={"code": ev["status"], "message": ev["status"]})
            steps.append(step)
        self.threads[tid]["messages"].append({
            "id": "msg_" + secrets.token_hex(6), "object": "thread.message", "role": "assistant", "thread_id": tid,
            "run_id": rid, "content": [{"type": "text", "text": {"value": answer}}]})
        run = {"id": rid, "object": "thread.run", "thread_id": tid, "assistant_id": body.get("assistant_id"),
               "status": "requires_action" if approvals else "completed", "_steps": steps,
               "required_action": {"type": "submit_tool_approval",
                                   "submit_tool_approval": {"tool_calls": approvals}} if approvals else None}
        self.runs[rid] = run
        return {**{k: v for k, v in run.items() if not k.startswith("_")}, "status": "queued"}

    # ------------------------------------------------------------------ Copilot Studio (Direct Line + Dataverse)
    def schema(self, st) -> str:
        return f"cr6a1_{st.scenario}{st.mode.title()}"

    def components(self, st) -> list[dict]:
        sc, schema = SCENARIOS[st.scenario], self.schema(st)
        approval = profile(st.scenario, st.mode)["approval_required"]
        comps = [{"name": "Greeting", "schemaname": f"{schema}.topic.Greeting", "componenttype": 9,
                  "description": "", "data": yaml.safe_dump({"kind": "AdaptiveDialog", "beginDialog": {
                      "kind": "OnRecognizedIntent", "intent": {"triggerQueries": ["hello"]}}})}]
        for t in self.tools(st):
            down = t["_meta"]["downstream"]
            data = {"kind": "TaskDialog", "modelDisplayName": t["name"], "modelDescription": t["description"],
                    "action": {"kind": "InvokeConnectorTaskAction",
                               "connectionReference": f"cr6a1_{sc['scope']}api.shared_{sc['scope']}-api",
                               "operationId": down["operationId"]}}
            if t["name"] in approval:
                data["confirmation"] = {"mode": "Always", "activity": f"Do you want me to run {t['name']}?"}
            comps.append({"name": t["name"], "schemaname": f"{schema}.action.{t['name']}", "componenttype": 9,
                          "description": t["description"], "data": yaml.safe_dump(data, sort_keys=False)})
        return comps

    def copilot_handler(p):  # noqa: N805
        class H(JsonHandler):
            def by_schema(self, schema):
                return next((s for s in p.stacks.values() if p.schema(s) == schema), None)

            def do_GET(self):
                url = urlparse(self.path)
                parts, q = url.path.strip("/").split("/"), parse_qs(url.query)
                if parts[:2] == ["powervirtualagents", "botsbyschema"] and parts[-1] == "token":
                    st = self.by_schema(parts[2])
                    if not st:
                        return self.send(404, {"error": "bot not found"})
                    tok = "dl_" + secrets.token_hex(12)
                    p.tokens[tok] = {"bot": parts[2]}
                    return self.send(200, {"token": tok, "expires_in": 3600})
                if parts[:3] == ["v3", "directline", "conversations"] and parts[-1] == "activities":
                    conv = p.convs.get(parts[3])
                    if not conv or conv["token"] != self.headers.get("Authorization", "").removeprefix("Bearer "):
                        return self.send(403, {"error": {"code": "BadArgument"}})
                    wm = int((q.get("watermark") or ["0"])[0])
                    return self.send(200, {"activities": conv["activities"][wm:], "watermark": str(len(conv["activities"]))})
                if parts[:3] == ["api", "data", "v9.2"]:
                    if not p.check(self):
                        return
                    flt = unquote((q.get("$filter") or [""])[0])
                    if parts[3] == "bots":
                        bots = [{"botid": f"bot-{p.schema(s)}", "name": SCENARIOS[s.scenario]["title"],
                                 "schemaname": p.schema(s)} for s in p.stacks.values() if f"'{p.schema(s)}'" in flt]
                        return self.send(200, {"value": bots})
                    if parts[3] == "botcomponents":
                        st = next((s for s in p.stacks.values() if f"bot-{p.schema(s)}" in flt), None)
                        return self.send(200, {"value": p.components(st) if st else []})
                    if parts[3] == "conversationtranscripts":
                        rows = [{"conversationtranscriptid": cid, "conversationstarttime": c["started"],
                                 "content": json.dumps({"activities": c["activities"]})}
                                for cid, c in p.convs.items() if f"bot-{c.get('bot')}" in flt]
                        return self.send(200, {"value": rows})
                self.send(404, {"error": "not_found"})

            def do_POST(self):
                parts = urlparse(self.path).path.strip("/").split("/")
                auth = self.headers.get("Authorization", "").removeprefix("Bearer ")
                if parts == ["v3", "directline", "conversations"]:
                    bot = (p.tokens.get(auth) or {}).get("bot")
                    if not bot:
                        return self.send(403, {"error": {"code": "BadArgument", "message": "Invalid token"}})
                    cid = secrets.token_hex(10) + "-eu"
                    tok = "dlc_" + secrets.token_hex(12)
                    p.convs[cid] = {"bot": bot, "token": tok, "activities": [],
                                    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                    return self.send(201, {"conversationId": cid, "token": tok, "expires_in": 3600})
                if parts[:3] == ["v3", "directline", "conversations"] and parts[-1] == "activities":
                    conv = p.convs.get(parts[3])
                    if not conv or conv["token"] != auth:
                        return self.send(403, {"error": {"code": "BadArgument"}})
                    act = self.body()
                    conv["activities"].append({**act, "id": f"{parts[3]}|{len(conv['activities']):07d}",
                                               "conversation": {"id": parts[3]}})
                    threading.Thread(target=p.answer, args=(conv, parts[3], act.get("text", "")), daemon=True).start()
                    return self.send(200, {"id": f"{parts[3]}|{len(conv['activities']) - 1:07d}"})
                self.send(404, {"error": "not_found"})

        return H

    def answer(self, conv: dict, cid: str, text: str) -> None:
        st = next(s for s in self.stacks.values() if self.schema(s) == conv["bot"])
        bot = {"id": conv["bot"], "name": SCENARIOS[st.scenario]["title"], "role": "bot"}

        def add(**a):
            conv["activities"].append({"id": f"{cid}|{len(conv['activities']):07d}", "from": bot,
                                       "conversation": {"id": cid},
                                       "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **a})

        add(type="typing")
        answer, events = self.run_agent(st, text, cid, cid)
        for i, ev in enumerate(events):
            dialog = f"{self.schema(st)}.action.{ev['tool']}"
            sid = f"step-{i}"
            add(type="event", name="DynamicPlanStepTriggered", value={"stepId": sid, "taskDialogId": dialog,
                                                                      "thought": f"Use {ev['tool']}"})
            add(type="event", name="DynamicPlanStepBindUpdate", value={"stepId": sid, "taskDialogId": dialog,
                                                                       "arguments": ev.get("arguments") or {}})
            fin = {"stepId": sid, "taskDialogId": dialog, "executionTime": "00:00:00.21"}
            if ev["status"] == "success":
                fin.update(state="completed", observation={"content": [{"type": "text", "text": _records_text(ev)}]})
            else:
                code = ev["status"].split(":", 1)[-1]
                fin.update(state="failed", error={"code": "approval_required" if "approval" in code else code})
            add(type="event", name="DynamicPlanStepFinished", value=fin)
        add(type="message", text=answer, textFormat="markdown")

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> "Platforms":
        for part, factory in (("entra", self.entra_handler), ("foundry", self.foundry_handler),
                              ("copilot", self.copilot_handler)):
            srv = ThreadingHTTPServer((self.host, self.ports[part]), factory())
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv)
        return self

    def stop(self) -> None:
        for s in self.servers:
            s.shutdown()
            s.server_close()

    # ------------------------------------------------------------------ target definitions
    def entra_auth(self, client_id: str = READER_APP) -> dict:
        return {"type": "entra", "tenant_id": TENANT, "client_id": client_id, "client_secret_env": SECRET_ENV,
                "authority": self.url("entra")}

    def entra_identity(self, st) -> dict:
        return {"type": "entra", "app_id": f"{SCENARIOS[st.scenario]['client_id']}-{st.mode}",
                "graph": self.url("entra"), "auth": self.entra_auth()}

    @staticmethod
    def _target(st, name: str, platform: str, extra: str) -> dict:
        sc = SCENARIOS[st.scenario]
        return {"name": name, "environment": "test", "platform": platform,
                "description": f"{sc['title']} on {extra}: {sc['description']} ({st.mode} build)",
                "labels": {"lab": True, "scenario": st.scenario, "mode": st.mode, "platform": platform},
                "resetEndpoint": f"{st.url('api')}/admin/reset"}

    @staticmethod
    def _test_data(st) -> dict:
        sc = SCENARIOS[st.scenario]
        return {"sampleId": f"{sc['prefix']}{sc['start'] + 1}",
                "idRange": [f"{sc['prefix']}{sc['start']}", f"{sc['prefix']}{sc['start'] + 99}"]}

    def foundry_target(self, st) -> dict:
        sc = SCENARIOS[st.scenario]
        approval = sorted(profile(st.scenario, st.mode)["approval_required"])
        require = {"always": {"tool_names": approval}} if approval else "never"
        return {
            "target": self._target(st, f"foundry-{sc['agent']}", "foundry", "Azure AI Foundry"),
            "agent": {"adapter": "foundry", "project_endpoint": f"{self.url('foundry')}/api/projects/{st.scenario}-{st.mode}",
                      "agent_id": f"asst_{st.scenario}", "api_version": "2025-05-15-preview",
                      "auth": {**self.entra_auth(), "scope": "https://ai.azure.com/.default"},
                      "tool_resources": {"mcp": [{"server_label": sc["mcp_name"].replace("-", "_"),
                                                  "require_approval": require}]},
                      "canary": sc["canary"], "poll": 0.05},
            "identity": self.entra_identity(st),
            "testData": self._test_data(st),
        }

    def copilot_target(self, st) -> dict:
        sc = SCENARIOS[st.scenario]
        return {
            "target": self._target(st, f"copilot-studio-{sc['agent']}", "copilot-studio", "Copilot Studio"),
            "agent": {"adapter": "copilot-studio", "canary": sc["canary"], "timeout": 20, "quiet": 0.4, "poll": 0.1,
                      "directline": {"endpoint": f"{self.url('copilot')}/v3/directline",
                                     "token_endpoint": f"{self.url('copilot')}/powervirtualagents/botsbyschema/"
                                                       f"{self.schema(st)}/directline/token?api-version=2022-03-01-preview"}},
            "discovery": [{"type": "copilot-studio", "environment_url": self.url("copilot"),
                           "bot_schema": self.schema(st),
                           "auth": {**self.entra_auth(), "scope": f"{self.url('copilot')}/.default"},
                           "connectors": {f"cr6a1_{sc['scope']}api": f"{st.url('api')}/openapi.json"}}],
            "identity": self.entra_identity(st),
            "testData": self._test_data(st),
        }

    def m365_target(self, st, package: str) -> dict:
        sc = SCENARIOS[st.scenario]
        return {
            "target": self._target(st, f"m365-{sc['agent']}", "m365-copilot", "Microsoft 365 Copilot"),
            "agent": {"adapter": "m365-copilot-chat", "graph": f"{self.url('entra')}/m365/{st.scenario}-{st.mode}",
                      "auth": {**self.entra_auth(), "scope": "https://graph.microsoft.com/.default"},
                      "canary": sc["canary"]},
            "discovery": [{"type": "m365-package", "package": package}],
            "telemetry": [{"type": "http-events", "url": f"{st.url('mcp')}/telemetry", "match": "{conversationId}"}],
            "identity": self.entra_identity(st),
            "testData": self._test_data(st),
        }


# ---------------------------------------------------------------------- static platform artefacts
def write_m365_package(out: Path, st) -> Path:
    """Teams app package (folder) with a declarative agent whose action is the stack's MCP server."""
    sc = SCENARIOS[st.scenario]
    hardened = st.mode == "hardened"
    approval = profile(st.scenario, st.mode)["approval_required"]
    tools = Platforms.tools(st)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(json.dumps({
        "$schema": "https://developer.microsoft.com/json-schemas/teams/v1.19/MicrosoftTeams.schema.json",
        "manifestVersion": "1.19", "version": "1.0.0", "id": "6f1c2b9e-0000-4000-8000-00000000e001",
        "name": {"short": sc["title"], "full": sc["title"]},
        "description": {"short": sc["description"], "full": sc["description"]},
        "copilotAgents": {"declarativeAgents": [{"id": f"{st.scenario}Agent", "file": "declarativeAgent.json"}]},
    }, indent=2), encoding="utf-8")
    knowledge = [{"name": "OneDriveAndSharePoint",
                  **({"items_by_url": [{"url": "https://contoso.sharepoint.com/sites/Engineering/Specs"}]}
                     if hardened else {})},
                 {"name": "WebSearch"}]
    (out / "declarativeAgent.json").write_text(json.dumps({
        "$schema": "https://developer.microsoft.com/json-schemas/copilot/declarative-agent/v1.4/schema.json",
        "version": "v1.4", "name": sc["title"], "description": sc["description"],
        "instructions": sc["system_prompt"], "capabilities": knowledge,
        "actions": [{"id": f"{sc['scope']}Plugin", "file": "ai-plugin.json"}],
    }, indent=2), encoding="utf-8")
    funcs = []
    for t in tools:
        f = {"name": t["name"], "description": t["description"]}
        f["capabilities"] = {"confirmation": {"type": "AdaptiveCard" if t["name"] in approval else "None",
                                             "title": t["name"], "body": f"Allow {t['name']}?"}}
        funcs.append(f)
    (out / "ai-plugin.json").write_text(json.dumps({
        "$schema": "https://developer.microsoft.com/json-schemas/copilot/plugin/v2.4/schema.json",
        "schema_version": "v2.4", "name_for_human": sc["mcp_name"], "namespace": sc["scope"],
        "description_for_human": f"{sc['api_title']} tools", "functions": funcs,
        "runtimes": [{"type": "RemoteMCPServer", "auth": {"type": "None"}, "spec": {"url": st.url("mcp")},
                      "run_for_functions": [t["name"] for t in tools]}],
    }, indent=2), encoding="utf-8")
    return out


FORGE = {
    "vulnerable": {
        "actions": [("search-issues", "Search issues", "Search Jira issues with JQL", "GET"),
                    ("get-issue", "Get issue", "Read one Jira issue", "GET"),
                    ("export-issues", "Export issues", "Export all issues of a project as CSV", "GET"),
                    ("update-issue", "Update issue", "Change fields of an issue", "UPDATE"),
                    ("delete-issue", "Delete issue", "Delete an issue", "DELETE")],
        "scopes": ["read:jira-work", "write:jira-work", "manage:jira-project", "delete:issue:jira",
                   "read:confluence-content.all"],
        "egress": ["https://*.example-analytics.com"],
    },
    "hardened": {
        "actions": [("search-issues", "Search issues", "Search Jira issues with JQL", "GET"),
                    ("get-issue", "Get issue", "Read one Jira issue", "GET"),
                    ("update-issue", "Update issue", "Change fields of an issue", "UPDATE")],
        "scopes": ["read:jira-work", "write:jira-work"],
        "egress": [],
    },
}


def write_forge_manifest(out: Path, mode: str) -> Path:
    d = FORGE[mode]
    out.mkdir(parents=True, exist_ok=True)
    manifest = {
        "modules": {
            "rovo:agent": [{"key": "triage-agent", "name": "Jira Triage Agent",
                            "description": "Triages and summarizes Jira issues for vehicle programs.",
                            "prompt": "You help engineers triage Jira issues. Never export project data.",
                            "conversationStarters": ["Summarize open blockers"],
                            "actions": [a[0] for a in d["actions"]]}],
            "action": [{"key": k, "name": n, "function": f"{k}-fn", "actionVerb": verb, "description": desc,
                        "inputs": {"issueKey": {"title": "Issue key", "type": "string", "required": False,
                                                "description": "Jira issue key"}}}
                       for k, n, desc, verb in d["actions"]],
            "function": [{"key": f"{a[0]}-fn", "handler": f"index.{a[0].replace('-', '_')}"} for a in d["actions"]],
        },
        "app": {"id": "ari:cloud:ecosystem::app/3c0b2d7e-lab0-4f00-9000-000000000r0v", "runtime": {"name": "nodejs22.x"}},
        "permissions": {"scopes": d["scopes"], **({"external": {"fetch": {"backend": d["egress"]}}} if d["egress"] else {})},
    }
    path = out / "manifest.yml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def rovo_target(mode: str, manifest: str) -> dict:
    return {
        "target": {"name": "rovo-jira-triage-agent", "environment": "test", "platform": "rovo",
                   "description": f"Atlassian Rovo agent (Forge app) that triages Jira issues ({mode} build). "
                                  "Static analysis only: Rovo has no public chat API.",
                   "labels": {"lab": True, "mode": mode, "platform": "rovo"}},
        "discovery": [{"type": "forge-manifest", "manifest": manifest, "dataClassification": "confidential",
                       "assumeConfirmationForNonGet": True}],
    }
