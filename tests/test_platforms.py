"""Platform adapters (Foundry, Copilot Studio, M365 Copilot, Rovo) against the local mock platforms."""
import socket
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))

import platform_mocks as pm  # noqa: E402
from stack import Stack  # noqa: E402

from agentsec import policy, scanner  # noqa: E402
from agentsec.config import load_target  # noqa: E402
from agentsec.platforms.base import estimate_records, split_message  # noqa: E402
from agentsec.platforms.copilot_studio import events_from_activities  # noqa: E402


def _port(n: int = 1) -> int:
    """First of n consecutive free ports."""
    for _ in range(50):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            base = s.getsockname()[1]
        if base + n < 65000 and all(_free(base + i) for i in range(n)):
            return base
    raise RuntimeError("no free ports")


def _free(p: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", p))
            return True
        except OSError:
            return False


@pytest.fixture
def platforms(tmp_path, monkeypatch):
    monkeypatch.setenv(pm.SECRET_ENV, "demo-secret")
    stacks, started = {}, []

    def get(scenario, mode):
        if (scenario, mode) not in stacks:
            st = Stack(scenario, mode, agent_port=_port(), mcp_port=_port(), api_port=_port()).start()
            stacks[(scenario, mode)] = st
        return stacks[(scenario, mode)]

    class Lab:
        def __init__(self):
            self.plat = None

        def target(self, kind, scenario, mode):
            st = get(scenario, mode)
            if self.plat is None:
                self.plat = pm.Platforms(stacks, "127.0.0.1", _port(3)).start()
                started.append(self.plat)
            if kind == "foundry":
                cfg = self.plat.foundry_target(st)
            elif kind == "copilot":
                cfg = self.plat.copilot_target(st)
            else:
                pkg = pm.write_m365_package(tmp_path / f"m365-{mode}", st)
                cfg = self.plat.m365_target(st, pkg.relative_to(tmp_path).as_posix())
            path = tmp_path / f"{kind}-{scenario}-{mode}.yaml"
            path.write_text(yaml.safe_dump(cfg, sort_keys=False))
            return path

    lab = Lab()
    yield lab
    for p in started:
        p.stop()
    for st in stacks.values():
        st.stop()


def _scan(path):
    r = scanner.scan(load_target(path), policy.load(), lambda *_: None)
    return r["summary"], {f.id: f for f in r["findings"]}


@pytest.mark.parametrize("kind,scenario", [("foundry", "engineering"), ("copilot", "hr"), ("m365", "engineering")])
def test_platform_vulnerable_fails_hardened_passes(platforms, kind, scenario):
    summary, findings = _scan(platforms.target(kind, scenario, "vulnerable"))
    assert summary["gate"]["result"] == "FAIL"
    assert findings["PI-002"].risk.severity == "critical"
    assert "DATA-004" in " ".join(findings)
    summary, findings = _scan(platforms.target(kind, scenario, "hardened"))
    assert summary["gate"]["result"] == "PASS", [f.id for f in findings.values() if f.risk.severity != "info"]
    assert summary["tests"]["failed"] == 0


def test_m365_flags_unscoped_knowledge(platforms):
    _, findings = _scan(platforms.target("m365", "engineering", "vulnerable"))
    assert any(k.startswith("KNW-001") for k in findings)


@pytest.mark.parametrize("mode,result", [("vulnerable", "FAIL"), ("hardened", "PASS")])
def test_rovo_static_only(tmp_path, mode, result):
    manifest = pm.write_forge_manifest(tmp_path / "rovo", mode)
    path = tmp_path / "rovo.yaml"
    path.write_text(yaml.safe_dump(pm.rovo_target(mode, manifest.relative_to(tmp_path).as_posix())))
    summary, findings = _scan(path)
    assert summary["gate"]["result"] == result
    assert summary["attackSkipped"]
    if mode == "vulnerable":
        assert "DATA-004:export-issues" in findings


def test_estimate_records():
    assert estimate_records("Exported (3821 records)") == 3821
    assert estimate_records('{"value": [1, 2, 3]}') == 3
    assert estimate_records("nothing") == 0


def test_split_message_roundtrip():
    msg = "Summarize\n\nAttached document: a.txt\n-----\nhello\n-----"
    text, docs = split_message(msg)
    assert text.strip() == "Summarize" and docs == [{"name": "a.txt", "content": "hello"}]


def test_copilot_studio_plan_events():
    acts = [
        {"type": "event", "name": "DynamicPlanStepTriggered",
         "value": {"taskDialogId": "cr6a1_x.action.ExportEmployees", "stepId": "s1"}},
        {"type": "event", "name": "DynamicPlanStepBindUpdate", "value": {"stepId": "s1", "arguments": {"all": True}}},
        {"type": "event", "name": "DynamicPlanStepFinished",
         "value": {"stepId": "s1", "taskDialogId": "cr6a1_x.action.ExportEmployees", "observation": "(12 records)"}},
    ]
    ev = events_from_activities(acts, "t1", "copilot-studio")
    assert len(ev) == 1 and ev[0]["status"] == "success" and ev[0]["recordsReturned"] == 12
    assert ev[0]["tool"].endswith("ExportEmployees")
