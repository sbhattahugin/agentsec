"""Runs the full assessment pipeline and emits structured progress events.

Both the CLI and the web console use this module; they only differ in how they render events.
"""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Callable

from . import analysis, discovery, engine, platforms, report, risk
from .adapters import http

Emit = Callable[[str, dict], None]

PHASES = [
    {"id": "register", "title": "Register",
     "what": "Load the target definition: only entry points and optional metadata.",
     "how": "Reads target.yaml and picks platform adapters (custom HTTP, Azure AI Foundry, Copilot Studio, "
            "M365 Copilot, Rovo) for invoke / discover / telemetry / identity. Resets the test environment if a "
            "resetEndpoint is configured."},
    {"id": "discover", "title": "Discover",
     "what": "Find out what the agent can actually do, instead of asking developers to model it.",
     "how": "Platform adapters read the agent definition (MCP tools/list, Foundry agent tools, Copilot Studio "
            "components, M365 app package, Forge manifest). OpenAPI specs give scopes, data classification and "
            "bulk semantics. Identity adapters (OAuth2 introspection, Entra ID) list the granted permissions."},
    {"id": "normalize", "title": "Normalize",
     "what": "Translate platform-specific results into the generic model.",
     "how": "Builds Agent -CAN_INVOKE-> Tool -ACCESSES-> Resource -CONTAINS-> Data and "
            "Identity -HAS_PERMISSION-> Permission, and classifies each tool (operation, bulk, "
            "classification, human approval, destructive, effective)."},
    {"id": "static", "title": "Static analysis",
     "what": "Check the configuration against policy before any attack happens.",
     "how": "Every policy's `when` clause is matched against each capability and identity; `require` "
            "is compared with the discovered facts."},
    {"id": "attack", "title": "Attack & observe",
     "what": "Attack the live agent and observe what really happens downstream.",
     "how": "Selects tests whose `applicable_to` matches a discovered capability and sends each payload "
            "through the platform invoker with a unique test id. Tool calls come from the platform itself "
            "(Foundry run steps, Copilot Studio activities) and/or telemetry (MCP events, App Insights). The "
            "verdict is based on real tool invocations, not on how the reply sounds."},
    {"id": "correlate", "title": "Correlate",
     "what": "Turn evidence into attack paths an attacker could follow.",
     "how": "Joins attack source -> agent -> invoked tool -> workload identity -> OAuth permission -> "
            "resource -> data classification."},
    {"id": "policy", "title": "Policy",
     "what": "Compare observed reality with what should happen.",
     "how": "Evaluates policies against runtime facts (e.g. humanApproval observed on the actual call, "
            "records returned per session) and records expected vs observed."},
    {"id": "risk", "title": "Risk",
     "what": "Score each finding deterministically.",
     "how": "Adds fixed weights for each factor (injection succeeded, real execution, classification, bulk, "
            "privileged identity, no approval, ...). No LLM decides severity."},
    {"id": "gate", "title": "Gate",
     "what": "Decide whether this agent may be deployed.",
     "how": "Fails if any finding is at or above the policy gate threshold (failOn). CI uses the exit code."},
]


def _noop(event: str, data: dict) -> None:
    pass


def scan(cfg: dict, pol: dict, emit: Emit = _noop, attacks: str | None = None, static_only: bool = False,
         fail_on: str | None = None) -> dict:
    fail_on = fail_on or pol["gate"].get("failOn", "high")
    started = time.time()

    def phase(pid: str, status: str, **extra) -> None:
        emit("phase", {"id": pid, "status": status, **extra})

    def log(message: str) -> None:
        emit("log", {"message": message})

    token = http.observe(lambda ev: emit("http", ev))
    try:
        t = cfg["target"]
        phase("register", "start")
        plat = platforms.build(cfg)
        desc = plat.describe()
        ident_spec = plat.spec.get("identity") or {}
        emit("target", {
            "name": t["name"], "environment": t.get("environment"), "description": t.get("description"),
            "platform": desc["platform"], "adapters": desc,
            "agent": (desc["invoker"] or {}).get("endpoint"),
            "connections": [{"type": d.get("type"), "endpoint": d.get("endpoint") or d.get("package")
                             or d.get("manifest") or d.get("environment_url") or d.get("url")}
                            for d in plat.spec["discovery"]],
            "authentication": ident_spec.get("type") or cfg["security"].get("authentication"),
            "identity": ident_spec.get("client_id") or ident_spec.get("app_id") or ident_spec.get("subject"),
            "testData": cfg.get("testData"),
        })
        log(f"  platform  {desc['platform']}: invoke={(desc['invoker'] or {}).get('adapter', 'none')}, "
            f"discover={'+'.join(desc['discovery']) or 'none'}, "
            f"telemetry={'+'.join(x['adapter'] for x in desc['telemetry']) or ('in-band' if desc['invoker'] else 'none')}, "
            f"identity={desc['identity'] or 'none'}")
        if t.get("resetEndpoint"):
            status, _ = http.request("POST", t["resetEndpoint"], {})
            log(f"  test environment reset (HTTP {status})")
        phase("register", "done")

        phase("discover", "start")
        graph, caps, raw = discovery.discover(cfg, log=log, platform=plat)
        emit("discovered", {
            "platform": desc["platform"], "sources": raw["sources"], "knowledge": raw.get("knowledge", []),
            "identity": raw.get("identity"),
            "mcp": [{"server": m["server"],
                     "tools": [{"name": x["name"], "description": x.get("description", ""),
                                "annotations": x.get("annotations") or {}, "meta": x.get("_meta") or {}}
                               for x in m["tools"]]} for m in raw.get("mcp", [])],
            "apis": [{"title": s["title"], "url": s["url"], "operations": s["operations"]}
                     for s in raw.get("openapi", {}).values()],
        })
        phase("discover", "done")

        phase("normalize", "start")
        emit("graph", {"stage": "normalized", "graph": graph.to_dict(), "capabilities": [asdict(c) for c in caps]})
        phase("normalize", "done")

        phase("static", "start")
        findings = analysis.static_findings(graph, caps, pol["policies"])
        emit("static_findings", {"findings": [report.finding_dict(f) for f in findings]})
        phase("static", "done")

        tests, skipped, observations = [], [], []
        phase("attack", "start")
        skip_reason = "static-only scan requested" if static_only else None
        if not static_only and plat.invoker is None:
            skip_reason = (f"{desc['platform']} target has no invoke adapter - static analysis only. Add "
                           "agent.adapter (or a test harness agent.endpoint) to run attacks.")
        if skip_reason is None:
            tests, skipped = engine.select(caps, cfg, engine.load_library(attacks) if attacks else None)
            emit("tests_selected", {"tests": [asdict(x) for x in tests], "skipped": skipped})
            observations = engine.run(tests, cfg, caps, graph, emit, platform=plat, aliases=raw.get("aliases"))
            emit("graph", {"stage": "observed", "graph": graph.to_dict(), "capabilities": [asdict(c) for c in caps]})
        else:
            log(f"  attack phase skipped: {skip_reason}")
        phase("attack", "done", skipped=skip_reason is not None, reason=skip_reason)

        phase("correlate", "start")
        findings += analysis.dynamic_findings(graph, caps, tests, observations, pol["policies"])
        emit("attack_paths", {"paths": [
            {"finding": f.id, "title": f.title, "kind": f.kind, "severity": f.risk.severity,
             "steps": f.attack_path.steps}
            for f in report.sort_findings(findings) if f.attack_path and f.risk.severity != "info"]})
        phase("correlate", "done")

        phase("policy", "start")
        emit("policy_results", {"policies": [{"id": p["id"], "title": p.get("title", p["id"])} for p in pol["policies"]],
                                "results": [{**r, "findingId": f.id} for f in report.sort_findings(findings)
                                            for r in f.policy_results]})
        phase("policy", "done")

        phase("risk", "start")
        emit("risk", {"weights": risk.WEIGHTS, "classification": risk.CLASSIFICATION_WEIGHT,
                      "thresholds": risk.THRESHOLDS,
                      "findings": [{"id": f.id, "title": f.title, "kind": f.kind, "score": f.risk.score,
                                    "severity": f.risk.severity, "factors": f.risk.factors}
                                   for f in report.sort_findings(findings)]})
        phase("risk", "done")

        phase("gate", "start")
        summary = report.summarize(tests, skipped, observations, findings, fail_on)
        summary["platform"] = desc["platform"]
        summary["attackSkipped"] = skip_reason
        full = report.to_json(cfg, graph, caps, raw, tests, skipped, observations, findings, summary)
        full["durationSeconds"] = round(time.time() - started, 1)
        emit("summary", {"summary": summary, "findings": [report.finding_dict(f) for f in report.sort_findings(findings)]})
        phase("gate", "done", result=summary["gate"]["result"])
        return {"report": full, "summary": summary, "findings": findings, "graph": graph}
    finally:
        http.unobserve(token)
