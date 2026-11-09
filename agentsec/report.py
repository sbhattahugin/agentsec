"""Console, JSON and Markdown (GitHub step summary) reporting."""
from __future__ import annotations

import json
from dataclasses import asdict

from .model import CAN_INVOKE, INVOKED, Edge, Finding, Graph, Node
from .risk import ORDER

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "info": "🔵"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-ORDER.index(f.risk.severity), -f.risk.score, f.id))


_sorted = sort_findings


def finding_dict(f: Finding) -> dict:
    return {**asdict(f), "attack_path": f.attack_path.steps if f.attack_path else None}


def _as_graph(graph) -> Graph:
    if isinstance(graph, Graph):
        return graph
    g = Graph()
    for n in graph["nodes"]:
        g.add_node(Node(**n))
    for e in graph["edges"]:
        g.edges.append(Edge(**e))
    return g


def summarize(tests, skipped, observations, findings, fail_on: str) -> dict:
    from .risk import at_least
    counts = {sev: sum(1 for f in findings if f.risk.severity == sev) for sev in reversed(ORDER)}
    blocking = [f.id for f in findings if at_least(f.risk.severity, fail_on)]
    return {
        "tests": {"total": len(observations), "passed": sum(o.verdict == "PASS" for o in observations),
                  "failed": sum(o.verdict == "FAIL" for o in observations),
                  "errors": sum(o.verdict == "ERROR" for o in observations), "skipped": len(skipped)},
        "findings": counts,
        "gate": {"failOn": fail_on, "result": "FAIL" if blocking else "PASS", "blocking": blocking},
    }


def to_json(cfg, graph: Graph, caps, raw, tests, skipped, observations, findings, summary) -> dict:
    return {
        "target": cfg["target"],
        "summary": summary,
        "discovery": {"identity": raw.get("identity"), "capabilities": [asdict(c) for c in caps],
                      "mcpServers": [m["server"] for m in raw.get("mcp", [])],
                      "apis": [{"title": s["title"], "url": s["url"]} for s in raw.get("openapi", {}).values()],
                      "platform": raw.get("platform"), "sources": raw.get("sources", []),
                      "knowledge": raw.get("knowledge", [])},
        "graph": graph.to_dict(),
        "tests": [asdict(t) for t in tests],
        "skippedTests": skipped,
        "observations": [asdict(o) for o in observations],
        "findings": [finding_dict(f) for f in _sorted(findings)],
    }


def print_graph(graph, log=print) -> None:
    graph = _as_graph(graph)
    agent = graph.of_type("Agent")[0]
    log(f"  {agent.name}")
    edges = graph.out(agent.id, CAN_INVOKE)
    for i, e in enumerate(edges):
        t = graph.nodes[e.dst]
        flags = [t.props["operation"]]
        if t.props.get("bulkAccess"):
            flags.append("bulk")
        flags.append(t.props.get("dataClassification", "?"))
        flags.append("approval" if t.props.get("humanApproval") else "no-approval")
        if not t.props.get("effective", True):
            flags.append("not-effective: identity lacks scope")
        log(f"  {'└' if i == len(edges) - 1 else '├'}─ CAN_INVOKE → {t.name:<16} [{', '.join(flags)}]")
    for ident in graph.of_type("Identity"):
        perms = [graph.nodes[e.dst].name for e in graph.out(ident.id, "HAS_PERMISSION")]
        log(f"  {ident.name}")
        for i, p in enumerate(perms):
            log(f"  {'└' if i == len(perms) - 1 else '├'}─ HAS_PERMISSION → {p}")


def print_report(summary: dict, findings: list[Finding], graph, log=print) -> None:
    graph = _as_graph(graph)
    invoked = [e for e in graph.edges if e.rel == INVOKED and e.props.get("status") == "success"]
    if invoked:
        log("\n▶ Observed (runtime evidence)")
        agg: dict[tuple, list[int]] = {}
        for e in invoked:
            agg.setdefault((e.props["testId"], graph.nodes[e.dst].name), []).append(e.props["recordsReturned"])
        for (test_id, tool), recs in agg.items():
            log(f"  Agent INVOKED → {tool:<16} test={test_id:<9} calls={len(recs):<4} records={sum(recs)}")
    log("\n▶ Findings")
    if not findings:
        log("  none")
    for f in _sorted(findings):
        log(f"\n  {ICON[f.risk.severity]} {f.risk.severity.upper():<8} [{f.id}] ({f.kind}, score {f.risk.score})")
        log(f"     {f.title}")
        for r in f.policy_results:
            if r["result"] == "FAIL":
                for c in r["checks"]:
                    if not c["ok"]:
                        log(f"     policy {r['policy']}: expected {c['field']}={c['expected']} "
                            f"observed {c['observed']} → FAIL")
        if f.risk.severity in ("critical", "high") and f.attack_path:
            log("     attack path: " + f.attack_path.compact())
    s = summary
    t = s["tests"]
    gate = s["gate"]["result"]
    log("\n" + "═" * 60)
    log("❌ Agent Security Gate: FAILED" if gate == "FAIL" else "✅ Agent Security Gate: PASSED")
    log(f"  Tests {t['total']}   Passed {t['passed']}   Failed {t['failed']}   Skipped {t['skipped']}")
    log("  " + "   ".join(f"{k.title()} {v}" for k, v in s["findings"].items()))
    log(f"  Gate: fail on >= {s['gate']['failOn']}")
    log("═" * 60)


def markdown(cfg, summary: dict, findings: list[Finding]) -> str:
    s, t = summary, summary["tests"]
    gate = s["gate"]["result"]
    lines = [f"## {'❌ Agent Security Gate: FAILED' if gate == 'FAIL' else '✅ Agent Security Gate: PASSED'}",
             "", f"Target: `{cfg['target']['name']}` ({cfg['target'].get('environment', 'n/a')})"
             + (f" - platform: {s['platform']}" if s.get("platform") else ""), "",
             *([f"> ⚠️ Attack phase skipped: {s['attackSkipped']}", ""] if s.get("attackSkipped") else []),
             "| Tests | Passed | Failed | Skipped | " + " | ".join(k.title() for k in s["findings"]) + " |",
             "|---" * (4 + len(s["findings"])) + "|",
             f"| {t['total']} | {t['passed']} | {t['failed']} | {t['skipped']} | "
             + " | ".join(str(v) for v in s["findings"].values()) + " |", "",
             "| Severity | ID | Finding | Score |", "|---|---|---|---|"]
    for f in _sorted(findings):
        lines.append(f"| {ICON[f.risk.severity]} {f.risk.severity} | `{f.id}` | {f.title} | {f.risk.score} |")
    for f in _sorted(findings):
        if f.risk.severity not in ("critical", "high"):
            continue
        lines += ["", f"### {ICON[f.risk.severity]} {f.id}: {f.title}", ""]
        if f.attack_path:
            lines += ["**Attack path**", "```", f.attack_path.render(), "```"]
        lines += ["**Risk factors**", "", "| Factor | Value |", "|---|---|"]
        lines += [f"| {k.replace('_', ' ')} | {v} |" for k, v in f.risk.factors.items()]
        fails = [r for r in f.policy_results if r["result"] == "FAIL"]
        if fails:
            lines += ["", "**Policy violations**", ""]
            for r in fails:
                for c in r["checks"]:
                    if not c["ok"]:
                        lines.append(f"- `{r['policy']}` {r['title']}: expected `{c['field']}={c['expected']}`, "
                                     f"observed `{c['observed']}`")
        tele = [e for e in f.evidence if e.get("type") == "telemetry" and e.get("status") == "success"]
        if tele:
            ev = {k: v for k, v in tele[0].items() if k != "type"}
            lines += ["", "**Runtime evidence**", "```json", json.dumps(ev, indent=2), "```"]
        if f.remediation:
            lines += ["", "**Remediation**", ""] + [f"- {r}" for r in dict.fromkeys(f.remediation)]
    return "\n".join(lines) + "\n"
