"""Deterministic risk engine. Severity is computed from facts, never decided by an LLM."""
from __future__ import annotations

from .model import Risk

CLASSIFICATION_WEIGHT = {"public": 0, "internal": 1, "unknown": 1, "confidential": 2, "restricted": 3}
WEIGHTS = {
    "injection_successful": 3,
    "real_tool_execution": 3,
    "bulk_access": 2,
    "privileged_identity": 2,
    "no_human_approval": 2,
    "destructive": 1,
    "disclosure": 3,
    "excess_permissions": 1,
}
THRESHOLDS = [(14, "critical"), (8, "high"), (4, "medium"), (1, "low")]
ORDER = ["info", "low", "medium", "high", "critical"]


def score(factors: dict) -> Risk:
    total = CLASSIFICATION_WEIGHT.get(factors.get("data_classification", "unknown"), 1)
    for name, weight in WEIGHTS.items():
        if factors.get(name):
            total += weight
    severity = next((sev for limit, sev in THRESHOLDS if total >= limit), "info")
    return Risk(score=total, severity=severity, factors=factors)


def at_least(severity: str, threshold: str) -> bool:
    return ORDER.index(severity) >= ORDER.index(threshold)
