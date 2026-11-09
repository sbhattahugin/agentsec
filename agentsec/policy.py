"""Policy engine: compares facts (static or observed) against declarative YAML policies."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import load_yaml

DEFAULT_POLICY = Path(__file__).with_name("policies") / "default.yaml"


def load(path: str | Path | None = None) -> dict:
    doc = load_yaml(path or DEFAULT_POLICY)
    doc.setdefault("policies", [])
    doc.setdefault("gate", {"failOn": "high"})
    return doc


def _when(when: dict, facts: dict) -> bool:
    for key, expected in (when or {}).items():
        if key not in facts:
            return False
        actual = facts[key]
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _check(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        if "max" in expected and not (actual is not None and actual <= expected["max"]):
            return False
        if "min" in expected and not (actual is not None and actual >= expected["min"]):
            return False
        if expected.get("empty") is True and actual:
            return False
        return True
    return actual == expected


def evaluate(policies: list[dict], facts: dict) -> list[dict]:
    """Return one result per policy whose `when` matches these facts."""
    results = []
    for p in policies:
        if not _when(p.get("when", {}), facts):
            continue
        checks = []
        for key, expected in p.get("require", {}).items():
            actual = facts.get(key)
            checks.append({"field": key, "expected": expected, "observed": actual, "ok": _check(expected, actual)})
        results.append({
            "policy": p["id"], "title": p.get("title", p["id"]), "subject": facts.get("name"),
            "result": "PASS" if all(c["ok"] for c in checks) else "FAIL", "checks": checks,
            "finding": p.get("finding"), "remediation": p.get("remediation", []),
        })
    return results
