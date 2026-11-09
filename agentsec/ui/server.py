"""AgentSec web console: pick a registered target, run a scan and watch every phase live.

Standard library only. Scan progress is streamed to the browser as Server-Sent Events.
"""
from __future__ import annotations

import json
import mimetypes
import threading
import time
import traceback
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .. import engine, policy, scanner
from ..config import load_target
from ..platforms import PLATFORM_NAMES, normalize
from ..report import markdown

STATIC = Path(__file__).with_name("static")
TYPES = {".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}

# Presenter pacing (seconds, multiplied by the selected pace) so humans can follow the scan.
PACING = {"phase": 0.6, "test_start": 0.5, "test_response": 0.5, "test_telemetry": 0.6, "test_result": 0.7,
          "discovered": 0.4, "graph": 0.4, "static_findings": 0.5, "attack_paths": 0.6, "policy_results": 0.5,
          "risk": 0.5, "http": 0.03}


def platform_name(cfg: dict) -> str:
    spec = normalize(cfg)
    key = cfg["target"].get("platform") or next((d.get("type") for d in spec["discovery"] if d.get("type") in PLATFORM_NAMES),
                                                spec["invoker"] or "custom")
    return PLATFORM_NAMES.get(key, key)


class Console:
    def __init__(self, targets_dir: str | Path, policy_path: str | None = None):
        self.targets_dir = Path(targets_dir).resolve()
        self.policy_path = policy_path
        self.runs: dict[str, dict] = {}
        self.lock = threading.Lock()

    def targets(self) -> list[dict]:
        out = []
        for path in sorted(self.targets_dir.rglob("*.y*ml")):
            if any(part.startswith(("_", ".")) for part in path.relative_to(self.targets_dir).parts[:-1]):
                continue  # assets (app packages, manifests) referenced by targets
            try:
                cfg = load_target(path)
            except Exception as e:  # noqa: BLE001
                out.append({"file": self.rel(path), "error": str(e)})
                continue
            t = cfg["target"]
            spec = normalize(cfg)
            out.append({
                "file": self.rel(path), "name": t["name"], "environment": t.get("environment"),
                "description": t.get("description", ""), "labels": t.get("labels") or {},
                "platform": platform_name(cfg), "agent": spec["agent"].get("endpoint") or spec["agent"].get("project_endpoint")
                or (spec["agent"].get("directline") or {}).get("endpoint") or spec["agent"].get("graph"),
                "adapter": spec["invoker"], "connections": [d.get("type") for d in spec["discovery"]],
                "telemetry": [x.get("type") for x in spec["telemetry"]],
                "yaml": path.read_text(encoding="utf-8"),
            })
        order = {"vulnerable": 0, "hardened": 1}
        return sorted(out, key=lambda t: (t.get("name", ""), order.get((t.get("labels") or {}).get("mode"), 2), t["file"]))

    def rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.targets_dir).as_posix()

    def resolve(self, name: str) -> Path:
        path = (self.targets_dir / name).resolve()
        if self.targets_dir not in path.parents or not path.is_file():
            raise FileNotFoundError(name)
        return path


def make_handler(console: Console):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def send_json(self, status: int, payload, ctype="application/json") -> None:
            data = payload.encode() if isinstance(payload, str) else json.dumps(payload, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                if url.path in ("/", "/index.html"):
                    return self.static("index.html")
                if url.path.startswith("/static/"):
                    return self.static(unquote(url.path[len("/static/"):]))
                if url.path == "/api/targets":
                    return self.send_json(200, {"targetsDir": str(console.targets_dir), "targets": console.targets()})
                if url.path == "/api/policy":
                    path = console.policy_path or policy.DEFAULT_POLICY
                    return self.send_json(200, {"path": str(path), "yaml": Path(path).read_text(encoding="utf-8"),
                                                "policy": policy.load(console.policy_path)})
                if url.path == "/api/attacks":
                    return self.send_json(200, {"path": str(engine.LIBRARY),
                                                "yaml": engine.LIBRARY.read_text(encoding="utf-8"),
                                                "tests": engine.load_library()})
                if url.path == "/api/phases":
                    return self.send_json(200, scanner.PHASES)
                if url.path.startswith("/api/report/"):
                    run_id, _, fmt = url.path[len("/api/report/"):].partition(".")
                    run = console.runs.get(run_id)
                    if not run or "report" not in run:
                        return self.send_json(404, {"error": "unknown run"})
                    if fmt == "md":
                        return self.send_json(200, run["markdown"], "text/markdown; charset=utf-8")
                    return self.send_json(200, run["report"])
                if url.path == "/api/scan":
                    return self.scan(q.get("target", ""), float(q.get("pace", "1") or 1))
                self.send_json(404, {"error": "not found"})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except FileNotFoundError as e:
                self.send_json(404, {"error": f"not found: {e}"})

        def static(self, name: str) -> None:
            path = (STATIC / name).resolve()
            if STATIC.resolve() not in path.parents or not path.is_file():
                return self.send_json(404, {"error": "not found"})
            # explicit types: Windows registry mappings can be wrong for .js
            ctype = TYPES.get(path.suffix) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self.send_json(200, path.read_text(encoding="utf-8"), ctype)

        def scan(self, target: str, pace: float) -> None:
            pace = max(0.0, min(pace, 3.0))
            path = console.resolve(target)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            run_id = uuid.uuid4().hex[:8]
            seq = 0

            def emit(event: str, data: dict) -> None:
                nonlocal seq
                seq += 1
                msg = f"id: {seq}\nevent: {event}\ndata: {json.dumps(data, default=str)}\n\n"
                self.wfile.write(msg.encode())
                self.wfile.flush()
                if pace:
                    time.sleep(PACING.get(event, 0.05) * pace)

            try:
                emit("run", {"runId": run_id, "target": target, "phases": scanner.PHASES,
                             "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S")})
                cfg = load_target(path)
                pol = policy.load(console.policy_path)
                result = scanner.scan(cfg, pol, emit)
                with console.lock:
                    console.runs[run_id] = {"report": result["report"],
                                            "markdown": markdown(cfg, result["summary"], result["findings"])}
                emit("done", {"runId": run_id, "result": result["summary"]["gate"]["result"],
                              "report": f"/api/report/{run_id}", "markdown": f"/api/report/{run_id}.md"})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                try:
                    emit("error", {"message": str(e)})
                except OSError:
                    pass

    return H


def serve(targets_dir: str | Path = "targets", host: str = "127.0.0.1", port: int = 8080,
          policy_path: str | None = None, open_browser: bool = False) -> None:
    console = Console(targets_dir, policy_path)
    server = ThreadingHTTPServer((host, port), make_handler(console))
    server.daemon_threads = True
    url = f"http://{host}:{port}"
    print(f"\nAgentSec console: {url}   (targets: {console.targets_dir}, Ctrl+C to stop)", flush=True)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

