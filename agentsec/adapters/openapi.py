"""OpenAPI adapter: maps operationIds to required scopes, data classification and bulk semantics."""
from __future__ import annotations

from .http import request

METHODS = {"get", "put", "post", "patch", "delete"}


def load(url: str) -> dict:
    status, spec = request("GET", url)
    if status != 200:
        raise RuntimeError(f"Could not load OpenAPI spec {url}: {status}")
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
                "scopes": scopes,
                "dataClassification": op.get("x-data-classification", "unknown"),
                "bulk": bool(op.get("x-bulk", False)),
            }
    return {"title": title, "url": url, "operations": ops}
