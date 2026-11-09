"""Platform adapter registry.

A target is assembled from four kinds of adapters (see base.py). New-style target.yaml:

    target:   {name, environment, platform}
    agent:    {adapter: http-chat | foundry | copilot-studio | m365-copilot-chat, ...}   # optional: static-only
    discovery: [{type: mcp | openapi | foundry | copilot-studio | m365-package | forge-manifest, ...}]
    telemetry: [{type: http-events | app-insights | log-analytics | copilot-studio-transcripts, ...}]
    identity:  {type: oauth2-introspection | entra | static, ...}

The original format (agent.endpoint + connections[] + security.identity) is translated automatically.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import copilot_studio, entra, foundry, generic, kql, m365, rovo
from .base import AdapterError, ChatResult, Discovered, ToolSpec  # noqa: F401 - re-export

INVOKERS = {
    "http-chat": generic.HttpChatInvoker,
    "foundry": foundry.FoundryInvoker,
    "copilot-studio": copilot_studio.DirectLineInvoker,
    "m365-copilot-chat": m365.CopilotChatInvoker,
}
DISCOVERERS = {
    "mcp": generic.McpDiscoverer,
    "openapi": generic.OpenApiDiscoverer,
    "foundry": foundry.FoundryDiscoverer,
    "copilot-studio": copilot_studio.CopilotStudioDiscoverer,
    "m365-package": m365.M365PackageDiscoverer,
    "forge-manifest": rovo.ForgeManifestDiscoverer,
}
TELEMETRY = {
    "http-events": generic.HttpEventsTelemetry,
    "app-insights": kql.KqlTelemetry,
    "log-analytics": kql.KqlTelemetry,
    "copilot-studio-transcripts": copilot_studio.TranscriptTelemetry,
}
IDENTITY = {
    "oauth2-introspection": generic.OAuth2IntrospectionIdentity,
    "entra": entra.EntraIdentity,
    "static": generic.StaticIdentity,
}
# Platforms whose invoker can also discover the agent definition from the same API.
SELF_DESCRIBING = {"foundry": "foundry"}
PLATFORM_NAMES = {"foundry": "Azure AI Foundry", "copilot-studio": "Copilot Studio", "m365-copilot": "Microsoft 365 Copilot",
                  "m365-package": "Microsoft 365 Copilot", "rovo": "Atlassian Rovo", "forge-manifest": "Atlassian Rovo",
                  "http-chat": "Custom (HTTP)", "custom": "Custom (HTTP)"}


def _new(registry: dict, kind: str, role: str, cfg: dict, target: dict, ctx: dict):
    if kind not in registry:
        raise AdapterError(f"Unknown {role} adapter '{kind}'. Available: {', '.join(sorted(registry))}")
    return registry[kind](cfg, target, ctx)


def normalize(cfg: dict) -> dict:
    """Return {invoker, discovery[], telemetry[], identity} specs for both new and legacy target formats."""
    agent = cfg.get("agent") or {}
    adapter = agent.get("adapter") or ("http-chat" if agent.get("endpoint") else None)
    discovery = [dict(d) for d in cfg.get("discovery") or []]
    telemetry = [dict(t) for t in cfg.get("telemetry") or []]
    for conn in cfg.get("connections") or []:
        kind = conn.get("type")
        if kind in ("mcp", "openapi"):
            discovery.append({**conn, "type": kind})
        if conn.get("telemetry"):
            telemetry.append({"type": "http-events", "url": conn["telemetry"]})
    if adapter in SELF_DESCRIBING and not any(d.get("type") == SELF_DESCRIBING[adapter] for d in discovery):
        discovery.insert(0, {"type": SELF_DESCRIBING[adapter]})
    identity = cfg.get("identity")
    sec = cfg.get("security") or {}
    if not identity and sec.get("identity") and sec.get("authentication", "oauth2") == "oauth2":
        identity = {"type": "oauth2-introspection", **sec["identity"]}
    return {"invoker": adapter, "agent": agent, "discovery": discovery, "telemetry": telemetry, "identity": identity}


@dataclass
class Platform:
    name: str
    invoker: object | None
    discoverers: list = field(default_factory=list)
    telemetry: list = field(default_factory=list)
    identity: object | None = None
    spec: dict = field(default_factory=dict)

    def describe(self) -> dict:
        return {
            "platform": self.name,
            "invoker": self.invoker.describe() if self.invoker else None,
            "discovery": [d.name for d in self.discoverers],
            "telemetry": [t.describe() for t in self.telemetry],
            "identity": self.identity.name if self.identity else None,
        }


def build(cfg: dict) -> Platform:
    spec = normalize(cfg)
    ctx: dict = {}
    invoker = _new(INVOKERS, spec["invoker"], "agent", spec["agent"], cfg, ctx) if spec["invoker"] else None
    discoverers = [_new(DISCOVERERS, d.get("type"), "discovery", d, cfg, ctx) for d in spec["discovery"]]
    telemetry = [_new(TELEMETRY, t.get("type"), "telemetry", t, cfg, ctx) for t in spec["telemetry"]]
    identity = _new(IDENTITY, spec["identity"].get("type"), "identity", spec["identity"], cfg, ctx) \
        if spec["identity"] else None
    name = (cfg.get("target") or {}).get("platform") or next(
        (d.get("type") for d in spec["discovery"] if d.get("type") in PLATFORM_NAMES), spec["invoker"] or "custom")
    return Platform(PLATFORM_NAMES.get(name, name), invoker, discoverers, telemetry, identity, spec)
