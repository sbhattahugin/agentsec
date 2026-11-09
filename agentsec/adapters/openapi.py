"""OpenAPI adapter: maps operationIds to required scopes, data classification and bulk semantics."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .http import request

METHODS = {"get", "put", "post", "patch", "delete"}


def load(url: str) -> dict:
    if url.startswith(("http://", "https://")):
        status, spec = request("GET", url)
        if status != 200:
            raise RuntimeError(f"Could not load OpenAPI spec {url}: {status}")
    else:
        text = Path(url.removeprefix("file://")).read_text(encoding="utf-8")
        spec = json.loads(text) if text.lstrip().startswith("{") else yaml.safe_load(text)
    return parse(spec, url)


def parse(spec: dict, url: str = "(embedded)") -> dict:
    title = spec.get("info", {}).get("title", url)
    ops = {}
    for path, item in spec.get("paths", {}).items():
        for method, op in item.items():
            if method not in METHODS or "operationId" not in op:
                continue
            scopes = sorted({s for req in op.get("security", spec.get("security", [])) for v in req.values() for s in v})
            ops[op["operationId"]] = {
                "method": method.upper(),
                "path": path,
                "summary": op.get("summary") or op.get("description", ""),
                "scopes": scopes,
                "dataClassification": op.get("x-data-classification", "unknown"),
                "bulk": bool(op.get("x-bulk", False)),
                "consequential": op.get("x-openai-isConsequential"),
            }
    return {"title": title, "url": url, "operations": ops}
