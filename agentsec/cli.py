"""agentsec CLI.

    agentsec discover target.yaml
    agentsec scan target.yaml [--policy policies.yaml] [--output report.json] [--markdown summary.md]

Exit codes: 0 = gate passed, 1 = gate failed, 2 = scan error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import __version__, analysis, discovery, engine, policy, report
from .config import load_target


def _discover(cfg):
    print(f"▶ Discovery: {cfg['target']['name']} ({cfg['target'].get('environment', 'n/a')})")
    graph, caps, raw = discovery.discover(cfg)
    print("\n▶ Normalized capability graph")
    report.print_graph(graph)
    return graph, caps, raw


def cmd_discover(args) -> int:
    cfg = load_target(args.target)
    graph, caps, raw = _discover(cfg)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"capabilities": [asdict(c) for c in caps], "graph": graph.to_dict(),
                       "identity": raw.get("identity")}, f, indent=2)
        print(f"\nWrote {args.output}")
    return 0


def cmd_scan(args) -> int:
    cfg = load_target(args.target)
    pol = policy.load(args.policy)
    fail_on = args.fail_on or pol["gate"].get("failOn", "high")

    graph, caps, raw = _discover(cfg)

    print("\n▶ Static analysis (policy vs. discovered configuration)")
    findings = analysis.static_findings(graph, caps, pol["policies"])
    for f in findings:
        print(f"  {report.ICON[f.risk.severity]} {f.title}")
    if not findings:
        print("  no static policy violations")

    tests, skipped, observations = [], [], []
    if not args.static_only:
        tests, skipped = engine.select(caps, cfg, engine.load_library(args.attacks) if args.attacks else None)
        print(f"\n▶ Adversarial tests ({len(tests)} applicable, {len(skipped)} skipped)")
        observations = engine.run(tests, cfg, caps, graph)
        for s in skipped:
            print(f"  - {s['id']:<9} SKIP  {s['name']} ({s['reason']})")
        findings += analysis.dynamic_findings(graph, caps, tests, observations, pol["policies"])

    summary = report.summarize(tests, skipped, observations, findings, fail_on)
    report.print_report(summary, findings, graph)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report.to_json(cfg, graph, caps, raw, tests, skipped, observations, findings, summary),
                      f, indent=2, default=str)
        print(f"Report: {args.output}")
    md = report.markdown(cfg, summary, findings)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    return 1 if summary["gate"]["result"] == "FAIL" else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="agentsec", description="Security testing for AI agents.")
    p.add_argument("--version", action="version", version=f"agentsec {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="Discover and normalize agent capabilities")
    d.add_argument("target")
    d.add_argument("-o", "--output")
    d.set_defaults(func=cmd_discover)

    s = sub.add_parser("scan", help="Discover, analyze, attack and gate")
    s.add_argument("target")
    s.add_argument("--policy", help="Policy YAML (default: built-in agentsec/policies/default.yaml)")
    s.add_argument("--attacks", help="Custom attack library YAML")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Override gate threshold")
    s.add_argument("--static-only", action="store_true", help="Skip adversarial tests")
    s.add_argument("-o", "--output", help="Write full JSON report")
    s.add_argument("--markdown", help="Write Markdown summary")
    s.set_defaults(func=cmd_scan)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:  # noqa: BLE001
        print(f"agentsec: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
