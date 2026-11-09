"""Minimal JSON-over-HTTP client with an optional observer (used to show the live 'wire log')."""
from __future__ import annotations

import contextvars
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

SECRET_KEYS = {"client_secret", "access_token", "refresh_token", "token", "password", "authorization"}
_observer: contextvars.ContextVar[Callable[[dict], None] | None] = contextvars.ContextVar("agentsec_http_observer",
                                                                                        default=None)


def observe(callback: Callable[[dict], None]):
    """Report every request made in the current context to `callback`. Returns a token for `unobserve`."""
    return _observer.set(callback)


def unobserve(token) -> None:
    _observer.reset(token)


def redact(obj):
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in SECRET_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _preview(obj, limit: int = 600) -> str:
    text = json.dumps(redact(obj), default=str, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + f"… ({len(text)} chars)"


def request(method: str, url: str, payload=None, headers=None, form: bool = False, timeout: float = 30):
    headers = dict(headers or {})
    data = None
    if payload is not None:
        if form:
            data = urllib.parse.urlencode(payload).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.monotonic()
    status, body, error = 0, {}, None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, body = resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            status, body = e.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            status, body = e.code, {"error": raw.decode(errors="replace")}
    except (urllib.error.URLError, OSError) as e:
        error = e
        body = {"error": str(getattr(e, "reason", e))}
    finally:
        observer = _observer.get()
        if observer:
            observer({
                "method": method, "url": url, "status": status,
                "ms": round((time.monotonic() - started) * 1000),
                "trace": next((v for k, v in headers.items() if k.lower() == "x-agentsec-test-id"), None),
                "request": _preview(payload) if payload is not None else None,
                "response": _preview(body),
            })
    if error:
        raise ConnectionError(f"{method} {url}: {body['error']}") from error
    return status, body
