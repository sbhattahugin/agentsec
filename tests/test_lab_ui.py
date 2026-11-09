"""Dummy-agent scenarios and the web console."""
import json
import urllib.error
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))

from stack import Stack  # noqa: E402

from agentsec import policy, scanner  # noqa: E402
from agentsec.config import load_target  # noqa: E402
from agentsec.ui.server import Console, make_handler  # noqa: E402


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_CLIENT_SECRET", "demo-secret")
    started = []

    def start(scenario, mode):
        st = Stack(scenario, mode, agent_port=_free_port(), mcp_port=_free_port(), api_port=_free_port()).start()
        started.append(st)
        path = tmp_path / f"{scenario}-{mode}.yaml"
        path.write_text(yaml.safe_dump(st.target_config()))
        return path

    yield start
    for st in started:
        st.stop()


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _scan(path):
    events = []
    result = scanner.scan(load_target(path), policy.load(), lambda e, d: events.append((e, d)))
    return result, events


def test_hr_vulnerable_fails_with_many_criticals(lab):
    result, events = _scan(lab("hr", "vulnerable"))
    s = result["summary"]
    assert s["gate"]["result"] == "FAIL"
    assert s["findings"]["critical"] >= 4
    sev = {f.id: f.risk.severity for f in result["findings"]}
    assert "PI-001" not in sev  # still refused by the guard
    assert sev["DEST-002"] in ("high", "critical")  # delete tool exists in this scenario
    assert [d["id"] for e, d in events if e == "phase" and d["status"] == "done"][-1] == "gate"


def test_support_vulnerable_passes_gate_with_mediums(lab):
    result, _ = _scan(lab("support", "vulnerable"))
    s = result["summary"]
    assert s["gate"]["result"] == "PASS"
    assert s["findings"]["medium"] >= 2
    assert s["tests"]["skipped"] >= 5  # no export/write tools -> those attacks are not applicable


@pytest.mark.parametrize("scenario", ["hr", "support"])
def test_hardened_scenarios_pass(lab, scenario):
    result, _ = _scan(lab(scenario, "hardened"))
    assert result["summary"]["gate"]["result"] == "PASS"
    assert result["summary"]["tests"]["failed"] == 0


def test_scan_is_repeatable_thanks_to_reset(lab):
    path = lab("hr", "vulnerable")
    first, _ = _scan(path)
    second, _ = _scan(path)
    assert first["summary"] == second["summary"]


def test_ui_lists_targets_and_streams_scan(lab, tmp_path):
    lab("engineering", "vulnerable")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Console(tmp_path)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        targets = json.load(urllib.request.urlopen(f"{base}/api/targets"))["targets"]
        assert [t["name"] for t in targets] == ["engineering-agent"]
        assert urllib.request.urlopen(f"{base}/").status == 200
        with urllib.request.urlopen(f"{base}/api/scan?target={targets[0]['file']}&pace=0") as resp:
            stream = resp.read().decode()
        names = [line[7:] for line in stream.splitlines() if line.startswith("event: ")]
        assert names[0] == "run" and names[-1] == "done"
        assert {"discovered", "test_start", "test_telemetry", "attack_paths", "policy_results", "risk"} <= set(names)
        done = json.loads(stream.strip().splitlines()[-1][len("data: "):])
        assert done["result"] == "FAIL"
        report = json.load(urllib.request.urlopen(f"{base}{done['report']}"))
        assert any(f["id"] == "PI-002" and f["risk"]["severity"] == "critical" for f in report["findings"])
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"{base}/api/scan?target=../../etc/passwd&pace=0")
    finally:
        server.shutdown()
