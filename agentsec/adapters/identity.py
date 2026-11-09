"""Identity adapter for OAuth2 client-credentials workloads (RFC 6749 + RFC 7662 introspection)."""
from __future__ import annotations

import os

from .http import request


def discover(cfg: dict) -> dict:
    client_id = cfg["client_id"]
    secret = os.environ.get(cfg.get("client_secret_env", "AGENTSEC_CLIENT_SECRET"), "")
    status, tok = request("POST", cfg["token_endpoint"], {"grant_type": "client_credentials", "client_id": client_id,
                                                          "client_secret": secret}, form=True)
    if status != 200:
        raise RuntimeError(f"Token request failed for {client_id}: {status} {tok}")
    status, info = request("POST", cfg["introspection_endpoint"], {"token": tok["access_token"]}, form=True)
    if status != 200 or not info.get("active"):
        raise RuntimeError(f"Token introspection failed for {client_id}: {status} {info}")
    return {"subject": info.get("sub", client_id), "scopes": sorted(info.get("scope", "").split())}
