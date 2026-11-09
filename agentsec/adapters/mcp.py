"""MCP adapter: JSON-RPC 2.0 over HTTP (initialize + tools/list)."""
from __future__ import annotations

from .http import request


class McpError(RuntimeError):
    pass


def _rpc(endpoint: str, method: str, params: dict | None = None, rid: int = 1) -> dict:
    status, body = request("POST", endpoint, {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                           headers={"Accept": "application/json"})
    if status != 200 or "error" in body:
        raise McpError(f"{method} failed ({status}): {body.get('error')}")
    return body["result"]


def discover(endpoint: str) -> dict:
    info = _rpc(endpoint, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "agentsec", "version": "0.1.0"}})
    tools, cursor = [], None
    while True:
        result = _rpc(endpoint, "tools/list", {"cursor": cursor} if cursor else {}, rid=2)
        tools.extend(result.get("tools", []))
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return {"server": info.get("serverInfo", {}), "tools": tools}
