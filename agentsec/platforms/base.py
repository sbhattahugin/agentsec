"""Common contracts for platform adapters.

Every agent platform is reduced to four roles:

    Discoverer  -> what tools / knowledge / identity does the agent have?   (ToolSpec, knowledge, identity)
    Invoker     -> send one attack conversation to the agent                (ChatResult)
    Telemetry   -> which tools did that conversation really execute?        (normalized events)
    Identity    -> which permissions does the executing identity hold?      ({subject, scopes})

The core engine (normalization, policy, attack, correlation, risk, gate) only sees these normalized shapes.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ToolSpec:
    """A tool as reported by a platform, before normalization into a Capability."""
    name: str
    description: str = ""
    source: str = "mcp"                    # mcp | openapi | function | connector | m365-function | rovo-action ...
    operation: str | None = None           # explicit operation if the platform states it (e.g. Rovo actionVerb)
    bulk: bool | None = None
    dataClassification: str | None = None
    humanApproval: bool | None = None
    destructive: bool | None = None
    requiredPermissions: list[str] = field(default_factory=list)
    resource: str | None = None
    openapi: str | dict | None = None      # spec URL or embedded spec used to resolve `operationId`
    operationId: str | None = None
    aliases: list[str] = field(default_factory=list)  # other names the platform uses for this tool in telemetry
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Discovered:
    source: str                            # adapter type, e.g. "foundry"
    label: str                             # human-readable name of what was inspected
    tools: list[ToolSpec] = field(default_factory=list)
    knowledge: list[dict] = field(default_factory=list)  # {name, kind, scoped, dataClassification, detail}
    identity: dict | None = None
    agent: dict = field(default_factory=dict)            # platform facts about the agent itself
    raw: dict = field(default_factory=dict)


@dataclass
class ChatResult:
    status: int                            # HTTP-like status: 200 ok, anything else is an error
    text: str
    context: dict = field(default_factory=dict)  # correlation ids: conversationId, threadId, runId ...
    events: list[dict] | None = None       # tool-call events the platform returned in-band (run steps, activities)


class AdapterError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compose_message(message: str, documents: list[dict]) -> str:
    """Platforms without a 'documents' field get supplied content inlined, the way a user would paste it."""
    parts = [message]
    for d in documents or []:
        parts.append(f"\n\nAttached document: {d.get('name', 'document')}\n-----\n{d.get('content', '')}\n-----")
    return "".join(parts)


DOC_RE = re.compile(r"\n\nAttached document: (.+?)\n-----\n(.*?)\n-----", re.S)


def split_message(text: str) -> tuple[str, list[dict]]:
    """Inverse of compose_message (used by the mock platforms)."""
    docs = [{"name": m.group(1), "content": m.group(2)} for m in DOC_RE.finditer(text)]
    return DOC_RE.sub("", text), docs


RECORDS_RE = re.compile(r"\((\d+) records?\)|\b(\d+) records? (?:returned|exported|found)", re.I)


def estimate_records(output: Any) -> int:
    """Best-effort record count from a tool output (JSON array, {value|items|results|records:[...]}, or text)."""
    if output is None:
        return 0
    if isinstance(output, str):
        m = RECORDS_RE.search(output)
        if m:
            return int(m.group(1) or m.group(2))
        try:
            output = json.loads(output)
        except (ValueError, TypeError):
            return 0
    if isinstance(output, list):
        return len(output)
    if isinstance(output, dict):
        for key in ("recordsReturned", "count", "@odata.count", "total"):
            if isinstance(output.get(key), int):
                return output[key]
        for key in ("value", "items", "results", "records", "data"):
            if isinstance(output.get(key), list):
                return len(output[key])
        if isinstance(output.get("content"), list):  # MCP CallToolResult
            return sum(estimate_records(c.get("text")) for c in output["content"] if isinstance(c, dict))
    return 0


def event(tool: str, status: str, test_id: str, **extra) -> dict:
    """Normalized telemetry event."""
    return {"timestamp": extra.pop("timestamp", None) or now(), "tool": tool, "status": status,
            "testId": test_id, "recordsReturned": extra.pop("recordsReturned", 0),
            "humanApproval": extra.pop("humanApproval", False), **extra}


def parse_args(arguments: Any) -> Any:
    if isinstance(arguments, str):
        try:
            return json.loads(arguments)
        except ValueError:
            return arguments
    return arguments


def odata_url(url: str) -> str:
    """Percent-encode spaces/quotes in OData query strings ($filter=name eq 'x') while keeping the syntax."""
    from urllib.parse import quote
    return quote(url, safe=":/?&=$,()@;+*!'%")


def fill(template: str, values: dict) -> str:
    """Replace {placeholders} with correlation values; unknown placeholders are left untouched."""
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), m.group(0))), template)
