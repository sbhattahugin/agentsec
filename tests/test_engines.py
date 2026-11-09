from agentsec.discovery import classify_operation
from agentsec.policy import evaluate
from agentsec.risk import score

DATA_004 = {"id": "DATA-004", "when": {"action": "bulk-export", "dataClassification": ["confidential", "restricted"]},
            "require": {"humanApproval": True}}


def test_classify_operation():
    assert classify_operation("ExportMaterials") == "export"
    assert classify_operation("UpdateMaterial") == "write"
    assert classify_operation("GetMaterial") == "read"
    assert classify_operation("SearchMaterial") == "search"
    assert classify_operation("delete_customer") == "delete"


def test_policy_fail_and_pass():
    facts = {"action": "bulk-export", "dataClassification": "confidential", "humanApproval": False}
    assert evaluate([DATA_004], facts)[0]["result"] == "FAIL"
    assert evaluate([DATA_004], {**facts, "humanApproval": True})[0]["result"] == "PASS"
    assert evaluate([DATA_004], {**facts, "dataClassification": "public"}) == []


def test_policy_comparisons():
    p = {"id": "X", "when": {}, "require": {"n": {"max": 50}, "extra": {"empty": True}}}
    assert evaluate([p], {"n": 10, "extra": []})[0]["result"] == "PASS"
    assert evaluate([p], {"n": 51, "extra": []})[0]["result"] == "FAIL"
    assert evaluate([p], {"n": 1, "extra": ["a"]})[0]["result"] == "FAIL"


def test_risk_is_deterministic():
    critical = {"injection_successful": True, "real_tool_execution": True, "data_classification": "confidential",
                "bulk_access": True, "privileged_identity": True, "no_human_approval": True}
    assert score(critical).severity == "critical"
    assert score(critical).score == score(dict(critical)).score
    static = {**critical, "injection_successful": False, "real_tool_execution": False}
    assert score(static).severity == "high"
    assert score({"data_classification": "public"}).severity == "info"
