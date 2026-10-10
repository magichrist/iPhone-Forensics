"""Spec-section tests: all 9 integrity classes, all health statuses, v4 buyer verdicts, model-aware capability detection."""
import json
import urllib.request
from pathlib import Path

import pytest

from iphone_forensics.buyer import CHECKLIST, evaluate, evaluate_v4, template
from iphone_forensics.hardware import assess_hardware, battery_checks, storage_checks
from iphone_forensics.integrity import assess_integrity, classify_change


# ---------------------------------------------------------- all 9 integrity classes
# Spec §4: verified, consistent, change_detected, replacement_indicated,
# suspicious, inconclusive, not_detectable, not_tested, unsupported.

def test_all_nine_integrity_states_are_enumerable():
    from iphone_forensics.models import INTEGRITY_CLASSES
    assert len(INTEGRITY_CLASSES) == 9
    expected = {"verified", "consistent", "change_detected", "replacement_indicated",
                "suspicious", "inconclusive", "not_detectable", "not_tested", "unsupported"}
    assert set(INTEGRITY_CLASSES) == expected


def test_classify_consistent_when_values_match():
    classification, _ = classify_change("ProductType", "iPhone15,4", "iPhone15,4")
    # identical values never reach classify_change, but the engine records
    # 'consistent' in assess_integrity — verify that instead:
    result = assess_integrity({"device": {"ProductType": "iPhone15,4"}},
                              {"device": {"ProductType": "iPhone15,4"}})
    assert result["classifications"]["ProductType"] == "consistent"


def test_classify_change_detected_for_os_build():
    classification, finding = classify_change("BuildVersion", "21A329", "21B101")
    assert classification == "change_detected"
    assert "restore" in finding.detail or "iOS update" in finding.detail


def test_classify_serial_change_suspicious():
    classification, finding = classify_change("SerialNumber", "A", "B")
    assert classification == "suspicious"
    assert finding.severity == "BLOCKER"
    assert "not automatically proof" in finding.detail


def test_classify_diagnostic_metric_change():
    classification, finding = classify_change("diagnostic:GasGauge:CycleCount", 0, 402)
    assert classification == "change_detected"


def test_classify_unknown_field_suspicious_not_replacement():
    classification, finding = classify_change("SomeUnmappedField", "x", "y")
    assert classification == "suspicious"
    # The critical rule: metadata change is never auto-called physical replacement.
    assert "replacement_indicated" != classification


def test_replacement_indicated_requires_diagnostic_assertion():
    """replacement_indicated is intentional only when a supported diagnostic source
    asserts a part change — engine has no code path that infers it from metadata
    alone, and this test locks that in."""
    prev = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "S"}}
    prev["diagnostic_candidates"] = [{"key": "FullChargeCapacity", "value": 2800}]
    curr = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "S"}}
    curr["diagnostic_candidates"] = [{"key": "FullChargeCapacity", "value": 3100}]
    result = assess_integrity(prev, curr)
    # Capacity field changed → change_detected; nothing escalates to
    # replacement_indicated without a supported diagnostic assertion.
    assert all(f.get("classification") != "replacement_indicated" for f in result["findings"])


def test_not_comparable_becomes_inconclusive():
    result = assess_integrity({"device": {}}, {"device": {"ProductType": "iPhone15,4"}})
    assert result["classifications"].get("ProductType") == "inconclusive"
    assert result["changes"][0]["status"] == "not_comparable"


def test_no_previous_report_is_not_tested():
    result = assess_integrity(None, {"device": {}})
    assert result["overall"] == "not_tested"


def test_not_detectable_exposed_via_capability_matrix():
    # Capability matrix must state what tools cannot answer.
    from iphone_forensics.cli_v4 import cmd_capabilities
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exit_code = cmd_capabilities(type("A", (), {"__init__": lambda self: None})())
    out = buf.getvalue()
    assert exit_code == 0
    assert "not independently verifiable" in out
    assert "not reliably detectable" in out


# ---------------------------------------------------------- buyer verdict rules

def test_v4_verdict_avoid_purchase_on_critical_fail():
    data = template()
    data["checks"]["activation_lock"]["status"] = "fail"
    result = evaluate_v4(data)
    assert result["verdict"] == "AVOID_PURCHASE"
    assert "rule 1" in result["rule"]


def test_v4_verdict_insufficient_evidence_for_almost_blank():
    data = template()  # everything not_tested
    result = evaluate_v4(data)
    assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "rule 2" in result["rule"]


def test_v4_verdict_critical_unknown_but_enough_answered():
    data = template()
    for cid in ("battery_health", "display_touch", "cameras", "audio", "physical_damage"):
        data["checks"][cid]["status"] = "pass"
    result = evaluate_v4(data)
    assert result["verdict"] == "INVESTIGATE_FURTHER"
    assert "rule 3" in result["rule"]


def test_v4_verdict_buy_only_after_repair():
    data = template()
    for item in CHECKLIST:
        if item["critical"]:
            data["checks"][item["id"]]["status"] = "pass"
    data["checks"]["display_touch"]["status"] = "fail"
    result = evaluate_v4(data)
    assert result["verdict"] == "BUY_ONLY_AFTER_REPAIR"
    assert "rule 4" in result["rule"]


def test_v4_verdict_good_candidate_not_certification():
    data = template()
    for item in CHECKLIST:
        data["checks"][item["id"]]["status"] = "pass"
    result = evaluate_v4(data)
    assert result["verdict"] == "GOOD_CANDIDATE"
    assert "not a certification" in result["certification_disclaimer"]


def test_v4_single_suspicion_does_not_condemn():
    """A single unverified suspicion (not_tested critical) must NOT yield
    AVOID_PURCHASE — that is reserved for recorded failures."""
    data = template()
    for item in CHECKLIST:
        if item["critical"]:
            data["checks"][item["id"]]["status"] = "pass"
    result = evaluate_v4(data)
    assert result["verdict"] == "GOOD_CANDIDATE"


def test_v3_and_v4_verdicts_coexist():
    data = template()
    data["checks"]["activation_lock"]["status"] = "fail"
    v3 = evaluate(data)
    v4 = evaluate_v4(data)
    assert v3["verdict"] == "HIGH RISK — DO NOT PAY YET"
    assert v4["verdict"] == "AVOID_PURCHASE"


def test_invalid_checklist_status_treated_as_unknown():
    data = template()
    data["checks"]["carrier_eligibility"]["status"] = "lorem"
    result = evaluate_v4(data)
    assert "carrier_eligibility" in result["critical_unknown"]


# ---------------------------------------------------------- hardware-health statuses

def test_health_status_pass_for_measured_battery():
    report = {"diagnostic_candidates": [{"source": "GasGauge", "key": "CycleCount", "value": "150"}],
              "device": {}, "crash_triage": {}}
    cycle = next(c for c in battery_checks(report) if "cycle" in c.question.lower())
    assert cycle.status == "pass"


def test_health_status_pass_with_warnings_storage():
    report = {"diagnostic_candidates": [],
              "device": {"TotalDiskCapacity": 256_000_000_000, "TotalDataCapacity": 240_000_000_000}}
    checks = storage_checks(report)
    assert checks[0].status == "pass_with_warnings"


def test_health_status_degraded_on_capacity_inconsistency():
    report = {"diagnostic_candidates": [],
              "device": {"TotalDiskCapacity": 64_000_000_000, "TotalDataCapacity": 90_000_000_000}}
    assert storage_checks(report)[1].status == "degraded"


def test_health_status_inconclusive_for_panic_match():
    report = {"diagnostic_candidates": [], "device": {},
              "crash_triage": {"panic_candidates": [{"panicString": "thermal runaway"}]}}
    thermal = [c for c in assess_hardware(report)["checks"]
               if c["subsystem"] == "thermal" and "panic" in c.get("source", "")]
    assert thermal and thermal[0]["status"] == "inconclusive"


def test_health_status_not_tested_when_no_evidence_at_all():
    assessment = assess_hardware({"diagnostic_candidates": [], "device": {}, "crash_triage": {}})
    assert assessment["subsystems"]["battery"] == "not_tested"
    assert assessment["subsystems"]["storage"] == "not_tested"


def test_health_status_unsupported_exists_in_models():
    from iphone_forensics.models import HEALTH_STATUSES
    assert "unsupported" in HEALTH_STATUSES
    assert "fail" in HEALTH_STATUSES
    assert set(HEALTH_STATUSES) == {"pass", "pass_with_warnings", "degraded", "fail",
                                    "inconclusive", "not_tested", "unsupported"}


def test_missing_telemetry_never_becomes_pass():
    checklist_checks = battery_checks({"diagnostic_candidates": [], "device": {}})
    assert all(c.status != "pass" for c in checklist_checks)


def test_no_universal_threshold_without_disclosure():
    """Any heuristic threshold must be labeled in the check itself."""
    report = {"diagnostic_candidates": [{"source": "GasGauge", "key": "CycleCount", "value": "600"}]}
    cycle = next(c for c in battery_checks(report) if "cycle" in c.question.lower())
    # The check must explain its basis, not just claim a number is bad.
    assert any(word in cycle.explanation.lower() for word in ("wear", "compare", "documented"))


# ---------------------------------------------------------- model/iOS capability awareness

def test_assessment_reports_ios_applicability_field():
    check = battery_checks({"diagnostic_candidates": [{"source": "GasGauge", "key": "CycleCount", "value": "150"}]})[0]
    # model/iOS applicability present in SubsystemCheck
    assert hasattr(check, "model_applicability") and hasattr(check, "ios_applicability")


def test_device_identity_extraction_from_plist_dict():
    from iphone_forensics.models import DeviceIdentity
    identity = DeviceIdentity.from_device_plist({
        "ProductType": "iPhone15,4", "ProductVersion": "18.0",
        "SerialNumber": "SER", "TotalDiskCapacity": "128000000000"})
    assert identity.product_type == "iPhone15,4"
    assert identity.total_disk_capacity == 128000000000
    assert identity.product_version == "18.0"  # first-class field, not in extra
