from __future__ import annotations

from pathlib import Path

import yaml


def load_yaml(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_target(path: str | Path) -> dict:
    cfg = load_yaml(path)
    if "target" not in cfg or not (cfg["target"] or {}).get("name"):
        raise ValueError(f"{path}: missing required 'target.name'")
    agent = cfg.get("agent") or {}
    if not (agent.get("endpoint") or agent.get("adapter") or cfg.get("discovery") or cfg.get("connections")):
        raise ValueError(f"{path}: define agent.endpoint, agent.adapter or at least one discovery source")
    if agent and not agent.get("adapter") and "endpoint" not in agent:
        raise ValueError(f"{path}: agent.endpoint is required (or set agent.adapter)")
    return prepare(cfg, Path(path).resolve().parent)


def prepare(cfg: dict, base_dir: Path | str = ".") -> dict:
    cfg.setdefault("agent", {})
    cfg.setdefault("connections", [])
    cfg.setdefault("security", {})
    cfg.setdefault("overrides", {})
    cfg.setdefault("defaults", {})
    cfg.setdefault("_base_dir", str(base_dir))
    return cfg
