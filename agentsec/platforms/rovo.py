"""Atlassian Rovo agent adapter (Forge app manifest).

    target: {name: jira-triage-agent, platform: rovo}
    discovery:
      - type: forge-manifest
        manifest: ./forge-app/manifest.yml
        agent_key: triage-agent              # optional; first rovo:agent otherwise
        dataClassification: internal         # default for Jira/Confluence content the actions touch
        assumeConfirmationForNonGet: true    # Rovo asks the user before CREATE/UPDATE/DELETE/TRIGGER actions
    agent:                                   # optional: Rovo has no public chat API; use a test harness
      adapter: http-chat
      endpoint: https://your-harness/api/chat

Static analysis maps:
  modules.rovo:agent[].actions -> modules.action[] (actionVerb GET|CREATE|UPDATE|DELETE|TRIGGER) -> tools
  permissions.scopes -> the Forge app identity (all actions run with the app's scopes)
  permissions.external.fetch.backend -> egress destinations (exfiltration surface)
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .base import AdapterError, Discovered, ToolSpec

VERB_OP = {"DELETE": "delete", "CREATE": "write", "UPDATE": "write", "TRIGGER": "write"}


def _operation(verb: str, name: str, description: str) -> str:
    from ..discovery import classify_operation  # lazy: avoids import cycle
    guess = classify_operation(name, description)
    if verb == "GET":
        return guess if guess in ("search", "read", "export") else "read"
    if verb == "TRIGGER" and guess in ("export", "delete"):
        return guess
    return VERB_OP.get(verb, guess)


class ForgeManifestDiscoverer:
    name = "forge-manifest"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        p = Path(cfg["manifest"])
        self.path = p if p.is_absolute() else Path(target.get("_base_dir", ".")) / p
        if not self.path.exists():
            raise AdapterError(f"Forge manifest not found: {self.path}")
        self.cfg = cfg

    def discover(self, log) -> Discovered:
        m = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        modules = m.get("modules") or {}
        agents = modules.get("rovo:agent") or []
        if not agents:
            raise AdapterError(f"{self.path.name}: no modules.rovo:agent defined")
        agent = next((a for a in agents if a.get("key") == self.cfg.get("agent_key")), agents[0])
        actions = {a["key"]: a for a in modules.get("action") or []}
        confirm = self.cfg.get("assumeConfirmationForNonGet", True)
        cls = self.cfg.get("dataClassification", "internal")
        tools = []
        for key in agent.get("actions") or []:
            a = actions.get(key)
            if not a:
                log(f"  rovo      action '{key}' referenced by agent but not defined")
                continue
            verb = str(a.get("actionVerb", "GET")).upper()
            name = a.get("name", key)
            op = _operation(verb, f"{key} {name}", a.get("description", ""))
            tools.append(ToolSpec(
                key, a.get("description", ""), source="rovo-action", operation=op,
                humanApproval=bool(confirm and verb != "GET"), destructive=verb in ("UPDATE", "DELETE"),
                dataClassification=cls, bulk=op == "export", aliases=[name],
                attributes={"actionVerb": verb, "function": a.get("function") or a.get("endpoint"),
                            "inputs": sorted((a.get("inputs") or {}).keys())}))
        perms = m.get("permissions") or {}
        scopes = sorted(perms.get("scopes") or [])
        egress = [x if isinstance(x, str) else x.get("address", str(x))
                  for x in ((perms.get("external") or {}).get("fetch") or {}).get("backend") or []]
        app = m.get("app") or {}
        identity = {"subject": f"forge-app:{app.get('id', 'unknown').split('/')[-1]}", "scopes": scopes,
                    "kind": "forge-app", "auth": "forge", "checkLeastPrivilege": False}
        log(f"  rovo      {agent.get('name', agent['key'])}: {len(tools)} actions, {len(scopes)} app scopes, "
            f"{len(egress)} egress hosts")
        return Discovered("forge-manifest", agent.get("name", agent["key"]), tools, identity=identity,
                          agent={"platform": "Atlassian Rovo", "key": agent["key"],
                                 "promptLength": len(str(agent.get("prompt") or "")), "egress": egress},
                          raw={"agent": {k: agent.get(k) for k in ("key", "name", "description", "actions")}})
