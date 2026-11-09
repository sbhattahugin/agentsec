"""Correlation: combines discovery, policies, observations and risk into findings and attack paths."""
from __future__ import annotations

from .discovery import excess_permissions, max_classification, privileged
from .model import (ACCESSES, CONTAINS, HAS_PERMISSION, AttackPath, Capability, Finding, Graph, Observation, Risk,
                    SecurityTest)
from .policy import evaluate as evaluate_policies
from .risk import score

PRIVILEGED_SCOPE = ("write", "export", "delete", "admin", "*")
SOURCE_LABEL = {
    "untrusted-content": "Malicious content",
    "obfuscated-prompt": "Encoded attacker prompt",
    "user-prompt": "Attacker prompt",
}


def _action(cap: Capability) -> str:
    return "bulk-export" if cap.operation == "export" and cap.bulkAccess else cap.operation


def _fmt(template: str | None, facts: dict) -> str | None:
    if not template:
        return None
    try:
        return template.format(**facts)
    except (KeyError, IndexError):
        return template


def _identity(graph: Graph):
    ids = graph.of_type("Identity")
    return ids[0] if ids else None


def _tool_privileged(cap: Capability, scopes: list[str]) -> bool:
    return any(p in scopes and any(k in p for k in PRIVILEGED_SCOPE) for p in cap.requiredPermissions)


def build_path(graph: Graph, cap: Capability | None, start: dict | None, scopes: list[str]) -> AttackPath:
    steps = []
    agent = graph.of_type("Agent")[0]
    if start:
        steps.append({"name": start["name"], "type": "Content"})
        steps.append({"name": agent.name, "type": "Agent", "via": start["via"]})
    else:
        steps.append({"name": agent.name, "type": "Agent"})
    if cap is None:
        return AttackPath(steps)
    steps.append({"name": cap.tool, "type": "Tool", "via": "tool execution" if start else "can invoke"})
    ident = _identity(graph)
    if ident:
        steps.append({"name": f"Workload identity ({ident.name})", "type": "Identity", "via": "executes as"})
    res = next((graph.nodes[e.dst] for e in graph.out(f"tool:{cap.tool}", ACCESSES)), None)
    if res:
        held = [p for p in cap.requiredPermissions if p in scopes] or cap.requiredPermissions
        steps.append({"name": res.name, "type": "Resource", "via": f"OAuth permission {', '.join(held)}"})
        data = next((graph.nodes[e.dst] for e in graph.out(res.id, CONTAINS)
                     if graph.nodes[e.dst].props.get("classification") == cap.dataClassification), None)
        if data:
            steps.append({"name": data.name, "type": "Data", "via": cap.operation})
    return AttackPath(steps)


def static_findings(graph: Graph, caps: list[Capability], policies: list[dict]) -> list[Finding]:
    ident = _identity(graph)
    scopes = [graph.nodes[e.dst].name for e in graph.out(ident.id, HAS_PERMISSION)] if ident else []
    findings = []
    for cap in caps:
        facts = {"subject": "capability", "name": cap.tool, "action": _action(cap),
                 "dataClassification": cap.dataClassification, "humanApproval": cap.humanApproval,
                 "destructive": cap.destructive, "bulkAccess": cap.bulkAccess, "effective": cap.effective}
        if not cap.effective:
            continue  # identity cannot exercise it; nothing reachable
        for res in evaluate_policies(policies, facts):
            if res["result"] != "FAIL":
                continue
            risk = score({
                "injection_successful": False, "real_tool_execution": False,
                "data_classification": cap.dataClassification, "bulk_access": cap.bulkAccess,
                "privileged_identity": _tool_privileged(cap, scopes), "no_human_approval": not cap.humanApproval,
                "destructive": cap.destructive,
            })
            findings.append(Finding(
                id=f"{res['policy']}:{cap.tool}", kind="static", risk=risk, policy_results=[res],
                title=_fmt(res["finding"], facts) or res["title"],
                evidence=[{"type": "capability", **facts, "requiredPermissions": cap.requiredPermissions}],
                attack_path=build_path(graph, cap, None, scopes),
                remediation=[_fmt(r, facts) for r in res["remediation"]],
            ))
    if ident:
        excess = excess_permissions(caps, scopes)
        facts = {"subject": "identity", "name": ident.name, "excessPermissions": excess,
                 "excessPermissionsText": ", ".join(excess)}
        for res in evaluate_policies(policies, facts):
            if res["result"] == "FAIL":
                reachable = max_classification(*(c.dataClassification for c in caps)) if caps else "unknown"
                risk = score({"data_classification": reachable, "privileged_identity": privileged(caps, scopes)[0],
                              "excess_permissions": True})
                findings.append(Finding(
                    id=f"{res['policy']}:{ident.name}", kind="static", risk=risk, policy_results=[res],
                    title=_fmt(res["finding"], facts) or res["title"],
                    evidence=[{"type": "identity", "scopes": scopes, "excessPermissions": excess}],
                    remediation=[_fmt(r, facts) for r in res["remediation"]],
                ))
    return findings


def dynamic_findings(graph: Graph, caps: list[Capability], tests: list[SecurityTest],
                     observations: list[Observation], policies: list[dict]) -> list[Finding]:
    ident = _identity(graph)
    scopes = [graph.nodes[e.dst].name for e in graph.out(ident.id, HAS_PERMISSION)] if ident else []
    cap_by_tool = {c.tool: c for c in caps}
    test_by_id = {t.id: t for t in tests}
    findings = []
    for obs in observations:
        test = test_by_id[obs.test_id]
        injection = test.category == "prompt-injection" or test.source in ("untrusted-content", "obfuscated-prompt")
        executed = [e for e in obs.tool_calls if e.get("status") == "success"]
        blocked = [e for e in obs.tool_calls if e.get("status") != "success"]

        policy_results = []
        for ev in obs.tool_calls:
            cap = cap_by_tool.get(ev["tool"])
            if not cap:
                continue
            facts = {"subject": "invocation", "name": cap.tool, "source": test.source,
                     "toolExecution": ev.get("status") == "success"}
            if facts["toolExecution"]:
                facts.update({"action": _action(cap), "dataClassification": cap.dataClassification,
                              "humanApproval": bool(ev.get("humanApproval")), "destructive": cap.destructive})
            policy_results += evaluate_policies(policies, facts)
        if executed:
            cls = max_classification(*(cap_by_tool[e["tool"]].dataClassification for e in executed
                                       if e["tool"] in cap_by_tool))
            policy_results += evaluate_policies(policies, {
                "subject": "session", "name": obs.test_id, "dataClassification": cls,
                "recordsPerSession": sum(e.get("recordsReturned", 0) for e in executed)})
        # de-duplicate identical policy outcomes
        seen, unique = set(), []
        for r in policy_results:
            key = (r["policy"], r["subject"], r["result"])
            if key not in seen:
                seen.add(key)
                unique.append(r)

        evidence = [{"type": "test", "id": test.id, "technique": test.technique, "message": test.message,
                     "documents": test.documents},
                    {"type": "response", "text": obs.response[:500]}]
        evidence += [{"type": "telemetry", **e} for e in obs.tool_calls]

        if obs.verdict != "FAIL":
            if blocked:
                findings.append(Finding(
                    id=test.id, kind="dynamic", test_id=test.id, policy_results=unique, evidence=evidence,
                    title=f"{test.name}: agent attempted {', '.join(sorted({e['tool'] for e in blocked}))} "
                          "but a control blocked it.",
                    risk=Risk(0, "info", {"injection_successful": injection, "real_tool_execution": False,
                                          "blocked_by": sorted({e['status'] for e in blocked})}),
                ))
            continue

        primary = max(executed, key=lambda e: e.get("recordsReturned", 0), default=None)
        cap = cap_by_tool.get(primary["tool"]) if primary else None
        total_records = sum(e.get("recordsReturned", 0) for e in executed)
        bulk_threshold = test.oracle.get("max_records", 50)
        factors = {
            "injection_successful": injection,
            "real_tool_execution": bool(executed),
            "data_classification": cap.dataClassification if cap else "internal",
            "bulk_access": bool(cap and (cap.bulkAccess or total_records > bulk_threshold)),
            "privileged_identity": bool(cap and _tool_privileged(cap, scopes)),
            "no_human_approval": bool(cap and cap.operation not in ("read", "search")
                                      and not any(e.get("humanApproval") for e in executed)),
            "destructive": bool(cap and cap.destructive),
            "disclosure": any("disclosure" in r for r in obs.reasons),
        }
        start = {"name": SOURCE_LABEL.get(test.source, "Attacker input")
                 + (f" ({test.documents[0]['name']})" if test.documents else ""),
                 "via": test.technique + (" prompt injection" if injection else " request")}
        if cap:
            path = build_path(graph, cap, start, scopes)
        else:
            path = build_path(graph, None, start, scopes)
            path.steps.append({"name": "Agent system prompt / configuration", "type": "Data",
                               "via": "response disclosure"})
        remediation = [rem for r in unique if r["result"] == "FAIL" for rem in r["remediation"]]
        findings.append(Finding(
            id=test.id, kind="dynamic", test_id=test.id, title=test.finding_title, risk=score(factors),
            policy_results=unique, evidence=evidence + [{"type": "verdict", "reasons": obs.reasons}],
            attack_path=path, remediation=[_fmt(r, {"name": cap.tool if cap else ""}) for r in remediation],
        ))
    return findings
