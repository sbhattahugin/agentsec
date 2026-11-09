"""End-to-end: start the mock stack in each mode and run the full scan."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from agentsec.cli import main

ROOT = Path(__file__).resolve().parent.parent


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def stack(request, tmp_path, monkeypatch):
    agent, mcp, api = _port(), _port(), _port()
    proc = subprocess.Popen([sys.executable, str(ROOT / "demo" / "stack.py"), "--mode", request.param,
                             "--agent-port", str(agent), "--mcp-port", str(mcp), "--api-port", str(api)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", agent), timeout=0.1).close()
            break
        except OSError:
            time.sleep(0.1)
    cfg = yaml.safe_load((ROOT / "examples" / "target.yaml").read_text())
    cfg["agent"]["endpoint"] = f"http://127.0.0.1:{agent}/api/chat"
    cfg["target"]["resetEndpoint"] = f"http://127.0.0.1:{api}/admin/reset"
    cfg["connections"][0].update(endpoint=f"http://127.0.0.1:{mcp}", telemetry=f"http://127.0.0.1:{mcp}/telemetry")
    cfg["security"]["identity"].update(token_endpoint=f"http://127.0.0.1:{api}/oauth/token",
                                       introspection_endpoint=f"http://127.0.0.1:{api}/oauth/introspect")
    target = tmp_path / "target.yaml"
    target.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv("AGENTSEC_CLIENT_SECRET", "demo-secret")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    yield target
    proc.terminate()
    proc.wait()


@pytest.mark.parametrize("stack", ["vulnerable"], indirect=True)
def test_vulnerable_agent_fails_gate(stack, tmp_path):
    out = tmp_path / "report.json"
    assert main(["scan", str(stack), "-o", str(out)]) == 1
    report = json.loads(out.read_text())
    findings = {f["id"]: f for f in report["findings"]}
    assert findings["PI-002"]["risk"]["severity"] == "critical"
    assert findings["DATA-004:ExportMaterials"]["risk"]["severity"] == "high"
    assert "PI-001" not in findings  # direct injection was refused
    invoked = [e for e in report["graph"]["edges"] if e["rel"] == "INVOKED" and e["props"]["testId"] == "PI-002"]
    assert invoked and invoked[0]["props"]["recordsReturned"] == 3821
    assert [s["type"] for s in findings["PI-002"]["attack_path"]] == \
        ["Content", "Agent", "Tool", "Identity", "Resource", "Data"]


@pytest.mark.parametrize("stack", ["hardened"], indirect=True)
def test_hardened_agent_passes_gate(stack, tmp_path):
    out = tmp_path / "report.json"
    assert main(["scan", str(stack), "-o", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["summary"]["tests"]["failed"] == 0
    assert all(f["risk"]["severity"] == "info" for f in report["findings"])
