from pathlib import Path

from iphone_forensics.hardware import assess_hardware, battery_checks, storage_checks, manual_subsystem_checks
from iphone_forensics.integrity import assess_integrity, classify_change


def _report_with(candidates, device=None, panic=None):
    return {
        "diagnostic_candidates": candidates,
        "device": device or {},
        "crash_triage": {"panic_candidates": panic or []},
    }


def test_battery_cycle_count_detected():
    report = _report_with([{"source": "GasGauge", "key": "CycleCount", "value": "203"}])
    checks = battery_checks(report)
    cycle = next(c for c in checks if "cycle" in c.question.lower())
    assert cycle.measurement == 203.0
    assert cycle.status == "pass"


def test_battery_high_cycle_gets_warning():
    report = _report_with([{"source": "GasGauge", "key": "CycleCount", "value": "900"}])
    cycle = next(c for c in battery_checks(report) if "cycle" in c.question.lower())
    assert cycle.status == "pass_with_warnings"
    assert cycle.severity == "REVIEW"


def test_battery_missing_is_not_tested_never_pass():
    report = _report_with([])
    cycle = next(c for c in battery_checks(report) if "cycle" in c.question.lower())
    assert cycle.status == "not_tested"
    assert cycle.measurement is None
    assert cycle.requires_hands_on is True


def test_storage_normalization():
    report = _report_with([], device={"TotalDiskCapacity": 128_000_000_000,
                                      "TotalDataCapacity": 119_000_000_000})
    check = storage_checks(report)[0]
    assert check.measurement == 128.0
    assert check.status == "pass_with_warnings"
    consistency = storage_checks(report)[1]
    assert consistency.status == "pass_with_warnings"


def test_storage_inconsistency_flags_review():
    report = _report_with([], device={"TotalDiskCapacity": 100_000_000_000,
                                      "TotalDataCapacity": 120_000_000_000})
    consistency = storage_checks(report)[1]
    assert consistency.status == "degraded"
    assert consistency.severity == "WARNING"


def test_manual_checks_exist_and_require_hands_on():
    manual = manual_subsystem_checks()
    assert len(manual) >= 8
    assert all(c.requires_hands_on for c in manual)
    assert all(c.status == "not_tested" for c in manual)


def test_full_assessment_structure():
    report = _report_with([{"source": "GasGauge", "key": "CycleCount", "value": "203"}],
                          device={"TotalDiskCapacity": 128_000_000_000,
                                  "TotalDataCapacity": 119_000_000_000})
    assessment = assess_hardware(report)
    assert "battery" in assessment["subsystems"]
    assert "storage" in assessment["subsystems"]
    assert assessment["subsystems"]["battery"] == "pass"
    assert len(assessment["checks"]) > 8
    assert "unknown, not a pass" in assessment["disclaimer"]


def test_thermal_panic_becomes_inconclusive_not_fail():
    report = _report_with([], panic=[{"panicString": "thermal pressure event on cpu0"}])
    assessment = assess_hardware(report)
    thermal = [c for c in assessment["checks"]
               if c["subsystem"] == "thermal" and "panic" in c["source"]]
    assert thermal, "thermal panic should produce a thermal check"
    assert thermal[0]["status"] == "inconclusive"


# ------------------------------------------------------------------ integrity

def test_classify_serial_change_is_suspicious_blocker():
    classification, finding = classify_change("SerialNumber", "A", "B")
    assert classification == "suspicious"
    assert finding.severity == "BLOCKER"


def test_classify_ios_version_change_is_benign():
    classification, finding = classify_change("ProductVersion", "17.4", "18.0")
    assert classification == "change_detected"
    assert "iOS update" in finding.detail or "restore" in finding.detail


def test_classify_capacity_increase_flagged():
    classification, finding = classify_change("diagnostic:GasGauge:FullChargeCapacity", 2800, 3100)
    assert classification == "change_detected"
    assert "increased" in finding.detail or "re-verify" in finding.next_test


def test_assess_integrity_no_previous():
    result = assess_integrity(None, {"device": {"ProductType": "iPhone15,4"}})
    assert result["overall"] == "not_tested"


def test_assess_integrity_consistent():
    prev = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "X"}}
    curr = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "X"}}
    result = assess_integrity(prev, curr)
    assert result["overall"] == "consistent"
    assert result["classifications"]["SerialNumber"] == "consistent"


def test_assess_integrity_model_mismatch_with_buyer():
    prev = None
    curr = {"device": {"ProductType": "iPhone13,2"}}
    buyer = {"buyer": {"advertised_model": "iPhone 15"}, "observations": {}}
    result = assess_integrity(prev, curr, buyer_data=buyer)
    suspicious = [f for f in result["findings"] if "advertised model" in f["title"].lower()]
    assert suspicious
    assert result["classifications"].get("advertised_model") == "suspicious"
