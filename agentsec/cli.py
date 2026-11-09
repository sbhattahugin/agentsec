"""agentsec CLI.

    agentsec discover target.yaml
    agentsec scan target.yaml [--policy policies.yaml] [--output report.json] [--markdown summary.md]
    agentsec ui [--targets DIR] [--port 8080]

Exit codes: 0 = gate passed, 1 = gate failed, 2 = scan error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import __version__, discovery, policy, report, scanner
from .config import load_target


def _utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


class Console:
    """Renders scanner events as the classic console output."""

    def __init__(self, log=print):
        self.log = log

    def __call__(self, event: str, d: dict) -> None:
        log = self.log
        if event == "target":
            log(f"▶ Discovery: {d['name']} ({d.get('environment') or 'n/a'})")
        elif event == "log":
            log(d["message"])
        elif event == "graph" and d["stage"] == "normalized":
            log("\n▶ Normalized capability graph")
            report.print_graph(d["graph"], log)
        elif event == "static_findings":
            log("\n▶ Static analysis (policy vs. discovered configuration)")
            for f in d["findings"]:
                log(f"  {report.ICON[f['risk']['severity']]} {f['title']}")
            if not d["findings"]:
                log("  no static policy violations")
        elif event == "tests_selected":
            self.skipped = d["skipped"]
            log(f"\n▶ Adversarial tests ({len(d['tests'])} applicable, {len(d['skipped'])} skipped)")
        elif event == "test_result":
            mark = {"PASS": "✓", "FAIL": "✗"}.get(d["verdict"], "!")
            log(f"  {mark} {d['id']:<9} {d['verdict']:<5} {d['name']}")
            for r in d["reasons"]:
                log(f"      {r}")
        elif event == "phase" and d["id"] == "attack" and d["status"] == "done":
            for s in getattr(self, "skipped", []):
                log(f"  - {s['id']:<9} SKIP  {s['name']} ({s['reason']})")


def cmd_discover(args) -> int:
    cfg = load_target(args.target)
    print(f"▶ Discovery: {cfg['target']['name']} ({cfg['target'].get('environment', 'n/a')})")
    graph, caps, raw = discovery.discover(cfg)
    print("\n▶ Normalized capability graph")
    report.print_graph(graph)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"capabilities": [asdict(c) for c in caps], "graph": graph.to_dict(),
                       "identity": raw.get("identity")}, f, indent=2)
        print(f"\nWrote {args.output}")
    return 0


def cmd_scan(args) -> int:
    cfg = load_target(args.target)
    pol = policy.load(args.policy)
    result = scanner.scan(cfg, pol, Console(), attacks=args.attacks, static_only=args.static_only,
                          fail_on=args.fail_on)
    summary, findings = result["summary"], result["findings"]
    report.print_report(summary, findings, result["graph"])
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result["report"], f, indent=2, default=str)
        print(f"Report: {args.output}")
    md = report.markdown(cfg, summary, findings)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    return 1 if summary["gate"]["result"] == "FAIL" else 0


def cmd_ui(args) -> int:
    from .ui.server import serve
    serve(args.targets, host=args.host, port=args.port, policy_path=args.policy, open_browser=args.open)
    return 0


def main(argv=None) -> int:
    _utf8_stdout()
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

    u = sub.add_parser("ui", help="Web console: pick a target, watch the scan live")
    u.add_argument("--targets", default="targets", help="Directory with target YAML files (searched recursively)")
    u.add_argument("--policy", help="Policy YAML")
    u.add_argument("--host", default="127.0.0.1")
    u.add_argument("--port", type=int, default=8080)
    u.add_argument("--open", action="store_true", help="Open the browser")
    u.set_defaults(func=cmd_ui)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001
        print(f"agentsec: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
