"""Credential helpers shared by platform adapters. Secrets are only ever read from environment variables.

    auth:
      type: entra             # client credentials against Microsoft Entra ID
      tenant_id: <tenant>
      client_id: <app id>
      client_secret_env: AGENTSEC_ENTRA_SECRET
      scope: https://ai.azure.com/.default        # adapter supplies a sensible default
      authority: https://login.microsoftonline.com # override for sovereign clouds / mocks

    auth: {type: azure-cli}                 # uses `az account get-access-token` (developer laptop)
    auth: {type: bearer, token_env: VAR}    # pre-acquired token (e.g. delegated M365 token)
    auth: {type: none}
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

from ..adapters.http import request
from .base import AdapterError

DEFAULT_AUTHORITY = "https://login.microsoftonline.com"


class TokenProvider:
    def __init__(self, cfg: dict | None, default_scope: str | None = None):
        self.cfg = dict(cfg or {"type": "none"})
        self.scope = self.cfg.get("scope") or default_scope
        self._token: str | None = None
        self._expires = 0.0

    def token(self) -> str | None:
        kind = self.cfg.get("type", "none")
        if kind == "none":
            return None
        if self._token and time.time() < self._expires - 60:
            return self._token
        if kind == "bearer":
            var = self.cfg.get("token_env", "AGENTSEC_BEARER_TOKEN")
            tok = os.environ.get(var)
            if not tok:
                raise AdapterError(f"auth.type bearer: environment variable {var} is not set")
            self._token, self._expires = tok, time.time() + 3600
        elif kind == "entra":
            self._token, self._expires = self._entra()
        elif kind == "azure-cli":
            self._token, self._expires = self._azure_cli()
        else:
            raise AdapterError(f"Unknown auth type '{kind}'")
        return self._token

    def headers(self) -> dict:
        tok = self.token()
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def _entra(self) -> tuple[str, float]:
        c = self.cfg
        for key in ("tenant_id", "client_id"):
            if not c.get(key):
                raise AdapterError(f"auth.type entra requires '{key}'")
        secret_var = c.get("client_secret_env", "AGENTSEC_ENTRA_SECRET")
        secret = os.environ.get(secret_var)
        if not secret:
            raise AdapterError(f"auth.type entra: environment variable {secret_var} is not set")
        url = f"{c.get('authority', DEFAULT_AUTHORITY).rstrip('/')}/{c['tenant_id']}/oauth2/v2.0/token"
        status, body = request("POST", url, {"grant_type": "client_credentials", "client_id": c["client_id"],
                                             "client_secret": secret, "scope": self.scope}, form=True)
        if status != 200 or "access_token" not in body:
            raise AdapterError(f"Entra token request failed ({status}): {body.get('error_description') or body}")
        return body["access_token"], time.time() + int(body.get("expires_in", 3600))

    def _azure_cli(self) -> tuple[str, float]:
        az = shutil.which("az") or shutil.which("az.cmd")
        if not az:
            raise AdapterError("auth.type azure-cli: Azure CLI 'az' not found on PATH")
        args = [az, "account", "get-access-token", "--output", "json"]
        if self.scope:
            args += ["--scope", self.scope]
        if self.cfg.get("tenant_id"):
            args += ["--tenant", self.cfg["tenant_id"]]
        out = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise AdapterError(f"az account get-access-token failed: {out.stderr.strip()}")
        data = json.loads(out.stdout)
        return data["accessToken"], time.time() + 3000
