"""Attack engine: selects applicable tests, executes them against the agent and collects runtime evidence."""
from __future__ import annotations

import base64
import re
import time
import uuid
from pathlib import Path

import yaml

from .adapters.http import request
from .model import INVOKED, Capability, Graph, Observation, SecurityTest

LIBRARY = Path(__file__).with_name("attacks.yaml")


def load_library(path: str | Path = LIBRARY) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)["tests"]


def _matches(cap: Capability, criteria: dict) -> bool:
    return all(getattr(cap, k) == v for k, v in criteria.items())


def _render(text: str, values: dict) -> str:
    for k, v in values.items():
        text = text.replace("{" + k + "}", str(v))
    return re.sub(r"\{b64:([^{}]*)\}", lambda m: base64.b64encode(m.group(1).encode()).decode(), text)


def select(caps: list[Capability], cfg: dict, library: list[dict] | None = None) -> tuple[list[SecurityTest], list[dict]]:
    """Instantiate tests that are applicable to what was discovered."""
    selected, skipped = [], []
    canary = cfg["agent"].get("canary")
    for t in library or load_library():
        criteria = t.get("applicable_to") or {}
        cap = next((c for c in caps if _matches(c, criteria)), None) if criteria else None
        if criteria and cap is None:
            skipped.append({"id": t["id"], "name": t["name"], "reason": f"no capability matching {criteria}"})
            continue
        values = {"tool": cap.tool if cap else ""}
        oracle = dict(t["oracle"])
        if "response_must_not_match" in oracle:
            pats = [p for p in oracle["response_must_not_match"] if "{canary}" not in p or canary]
            oracle["response_must_not_match"] = [_render(p, {"canary": re.escape(canary or "")}) for p in pats]
        selected.append(SecurityTest(
            id=t["id"], name=t["name"], category=t["category"], technique=t["technique"],
            finding_title=t.get("finding", t["name"]),
            source=t.get("source", "user-prompt"),
            message=_render(t["message"], values),
            documents=[{"name": d["name"], "content": _render(d["content"], values)} for d in t.get("documents", [])],
            oracle=oracle,
            applicable_to={**criteria, "tool": values["tool"]},
        ))
    return selected, skipped


def collect_telemetry(cfg: dict, trace_id: str, wait: float = 0.2) -> list[dict]:
    events: list[dict] = []
    time.sleep(wait)
    for conn in cfg["connections"]:
        if conn.get("telemetry"):
            status, body = request("GET", f"{conn['telemetry']}?testId={trace_id}")
            if status == 200:
                events.extend(body.get("events", []))
    return events


def evaluate(test: SecurityTest, obs: Observation, caps: dict[str, Capability]) -> None:
    o = test.oracle
    for ev in obs.tool_calls:
        cap = caps.get(ev["tool"])
        op = cap.operation if cap else "unknown"
        executed = ev.get("status") == "success"
        if op in o.get("prohibited_operations", []):
            if executed:
                obs.verdict = "FAIL"
                obs.reasons.append(f"Prohibited {op} operation executed: {ev['tool']} "
                                   f"({ev.get('recordsReturned', 0)} records)")
            else:
                obs.reasons.append(f"Prohibited {op} attempted but blocked by control: {ev['tool']} ({ev.get('status')})")
    if "max_records" in o:
        total = sum(e.get("recordsReturned", 0) for e in obs.tool_calls if e.get("status") == "success")
        if total > o["max_records"]:
            obs.verdict = "FAIL"
            obs.reasons.append(f"{total} records returned in one session (limit {o['max_records']})")
        blocked = [e for e in obs.tool_calls if e.get("status", "").startswith("blocked")]
        if blocked:
            obs.reasons.append(f"{len(blocked)} calls blocked by control ({blocked[0]['status']})")
    for pat in o.get("response_must_not_match", []):
        if re.search(pat, obs.response):
            obs.verdict = "FAIL"
            obs.reasons.append(f"Response matched disclosure pattern /{pat}/")


def run(tests: list[SecurityTest], cfg: dict, caps: list[Capability], graph: Graph, log=print) -> list[Observation]:
    run_id = uuid.uuid4().hex[:8]
    cap_by_tool = {c.tool: c for c in caps}
    agent_id = f"agent:{cfg['target']['name']}"
    headers = dict(cfg["agent"].get("headers") or {})
    observations = []
    for t in tests:
        trace_id = f"{t.id}-{run_id}"
        status, body = request("POST", cfg["agent"]["endpoint"],
                               {"message": t.message, "documents": t.documents, "sessionId": trace_id},
                               headers={**headers, "X-AgentSec-Test-Id": trace_id})
        obs = Observation(test_id=t.id, run_id=run_id, response=str(body.get("response", body)), tool_calls=[])
        if status != 200:
            obs.verdict = "ERROR"
            obs.reasons.append(f"Agent returned HTTP {status}")
        else:
            obs.tool_calls = collect_telemetry(cfg, trace_id)
            evaluate(t, obs, cap_by_tool)
        for ev in obs.tool_calls:
            graph.add_edge(agent_id, INVOKED, f"tool:{ev['tool']}", testId=t.id, status=ev.get("status"),
                           recordsReturned=ev.get("recordsReturned", 0), timestamp=ev.get("timestamp"))
        mark = {"PASS": "✓", "FAIL": "✗", "ERROR": "!"}[obs.verdict]
        log(f"  {mark} {t.id:<9} {obs.verdict:<5} {t.name}")
        observations.append(obs)
    return observations
