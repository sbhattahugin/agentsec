"""Microsoft Entra ID identity adapter: which application permissions does the agent's identity really hold?

    identity:
      type: entra
      app_id: <client id of the agent's service principal / managed identity>   # or object_id
      graph: https://graph.microsoft.com          # optional, override for mocks / national clouds
      includeDelegated: true                      # also read oauth2PermissionGrants (delegated scopes)
      auth: {type: entra, tenant_id: ..., client_id: ..., client_secret_env: ...}   # reader app, needs
                                                  # Application.Read.All (Graph)

Graph calls: servicePrincipals(appId='..') -> /appRoleAssignments -> resource SP appRoles (role values)
             [-> oauth2PermissionGrants?$filter=clientId eq '<sp id>' (delegated scopes)]
"""
from __future__ import annotations

from urllib.parse import quote

from ..adapters.http import request
from .auth import TokenProvider
from .base import AdapterError, odata_url


class EntraIdentity:
    name = "entra"

    def __init__(self, cfg: dict, target: dict, ctx: dict):
        self.cfg = cfg
        self.graph = cfg.get("graph", "https://graph.microsoft.com").rstrip("/") + "/v1.0"
        self.auth = TokenProvider(cfg.get("auth"), default_scope="https://graph.microsoft.com/.default")

    def _get(self, path: str) -> dict:
        status, body = request("GET", odata_url(f"{self.graph}{path}"), headers=self.auth.headers())
        if status != 200:
            raise AdapterError(f"Graph GET {path} failed ({status}): {body.get('error', body)}")
        return body

    def discover(self, log) -> dict:
        if self.cfg.get("object_id"):
            sp = self._get(f"/servicePrincipals/{self.cfg['object_id']}")
        elif self.cfg.get("app_id"):
            sp = self._get(f"/servicePrincipals(appId='{quote(self.cfg['app_id'])}')")
        else:
            raise AdapterError("identity.type entra requires app_id or object_id")
        scopes, resources = [], {}
        for a in self._get(f"/servicePrincipals/{sp['id']}/appRoleAssignments").get("value", []):
            res = resources.get(a["resourceId"])
            if res is None:
                res = resources[a["resourceId"]] = self._get(f"/servicePrincipals/{a['resourceId']}")
            role = next((r for r in res.get("appRoles", []) if r.get("id") == a.get("appRoleId")), None)
            scopes.append(role["value"] if role and role.get("value") else f"{res.get('displayName')}:default")
        if self.cfg.get("includeDelegated"):
            grants = self._get(f"/oauth2PermissionGrants?$filter=clientId eq '{sp['id']}'").get("value", [])
            scopes += [s for g in grants for s in (g.get("scope") or "").split()]
        log(f"  entra     {sp.get('displayName', sp['id'])}: {len(scopes)} permissions")
        return {"subject": sp.get("displayName") or sp.get("appId"), "scopes": sorted(set(scopes)),
                "kind": sp.get("servicePrincipalType", "Application").lower(), "auth": "entra",
                "appId": sp.get("appId"), "objectId": sp["id"],
                "checkLeastPrivilege": self.cfg.get("checkLeastPrivilege", True)}
