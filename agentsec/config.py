from __future__ import annotations

from pathlib import Path

import yaml


def load_yaml(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_target(path: str | Path) -> dict:
    cfg = load_yaml(path)
    for key in ("target", "agent"):
        if key not in cfg:
            raise ValueError(f"{path}: missing required section '{key}'")
    if "endpoint" not in cfg["agent"]:
        raise ValueError(f"{path}: agent.endpoint is required")
    cfg.setdefault("connections", [])
    cfg.setdefault("security", {})
    cfg.setdefault("overrides", {})
    return cfg
