"""Claim-matrix enforcement in code (docs/v5/06-authenticity-honesty.md).

The claim matrix in `capabilities.py` is a *policy*. These tests pin the *gates*
that enforce it at the points where claims are produced. A test that only checks
the data tables would pass even if the gates were deleted — so each test here
drives the real production function and asserts the violation is caught.

Offline only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from iphone_forensics import capabilities, hardware, integrity, reporting

# ============================================ 1. the audit finds real violations

def _report(**overrides) -> dict:
    report = {
        "version": "5.0.0",
        "device": {"ProductType": "iPhone15,4", "ProductVersion": "18.1",
                   "BuildVersion": "22B83", "ModelNumber": "MU2Y3"},
        "collection": [],
        "findings": [],
    }
    report.update(overrides)
    return report


def test_audit_catches_a_bare_battery_number():
    """A battery value with no unit is an unlabelled number, refused by the matrix."""
    report = _report(hardware_assessment={
        "subsystems": {"battery": "pass"},
        "checks": [{"subsystem": "battery", "question": "Cycle count", "status": "pass",
                    "measurement": 812, "measurement_unit": "", "confidence": "high"}],
        "warnings": [], "disclaimer": ""})
    violations = hardware.audit_battery_claims(report)
    assert violations, "a battery value with no unit must be flagged"


def test_audit_accepts_a_unit_verified_battery_value():
    report = _report(hardware_assessment={
        "subsystems": {"battery": "pass"},
        "checks": [{"subsystem": "battery", "question": "Cycle count", "status": "pass",
                    "measurement": 812, "measurement_unit": "cycles", "confidence": "high"}],
        "warnings": [], "disclaimer": ""})
    assert hardware.audit_battery_claims(report) == []


def test_audit_accepts_an_uncollected_battery_metric():
    """An absent metric is a gap to report, not a claim to refuse."""
    report = _report(hardware_assessment={
        "subsystems": {"battery": "not_tested"},
        "checks": [{"subsystem": "battery", "question": "Cycle count", "status": "not_tested",
                    "measurement": None, "measurement_unit": "", "confidence": "none"}],
        "warnings": [], "disclaimer": ""})
    assert hardware.audit_battery_claims(report) == []


def test_audit_catches_a_replacement_claim_without_a_supported_source():
    report = _report(integrity_assessment={
        "overall": "replacement_indicated",
        "classifications": {"battery": "replacement_indicated"},
        "changes": [{"field": "battery", "previous": "", "current": "",
                     "source": "ideviceinfo metadata difference"}],
        "continuity": "not_detectable", "disclaimer": ""})
    violations = integrity.audit_integrity_claims(report)
    assert any("component_replaced" in v for v in violations)


def test_audit_accepts_a_replacement_claim_with_a_supported_source():
    report = _report(
        device={"ProductType": "iPhone15,4", "SerialNumber": "SER12345678"},
        integrity_assessment={
            "overall": "replacement_indicated",
            "classifications": {"battery": "replacement_indicated"},
            "changes": [{"field": "battery", "previous": "", "current": "",
                         "source": "parts_and_service_history"}],
            "continuity": "established", "disclaimer": ""})
    assert integrity.audit_integrity_claims(report) == []


def test_audit_catches_continuity_asserted_without_a_hardware_bound_identifier():
    """Two snapshots repeating a value do not prove same-device."""
    report = _report(integrity_assessment={
        "overall": "consistent", "classifications": {},
        "changes": [], "continuity": "established", "disclaimer": ""})
    violations = integrity.audit_integrity_claims(report)
    assert any("never_tampered" in v for v in violations)


def test_audit_accepts_continuity_with_a_serial_number():
    report = _report(device={"ProductType": "iPhone15,4", "SerialNumber": "SER12345678"},
                    integrity_assessment={
                        "overall": "consistent", "classifications": {}, "changes": [],
                        "continuity": "established", "disclaimer": ""})
    assert integrity.audit_integrity_claims(report) == []


# ============================================ 2. forbidden assertions are caught

@pytest.mark.parametrize("phrase", [
    "This device is malware-free",
    "No malware was found on this device",
    "This device was never tampered with",
])
def test_text_level_audit_catches_forbidden_verdicts(phrase):
    report = _report(findings=[{"severity": "INFO", "title": phrase,
                                "detail": "", "evidence": []}])
    violations = capabilities.audit_report(report)
    assert violations, f"{phrase!r} must be refused by the claim audit"


def test_text_level_audit_ignores_ordinary_report_language():
    """Honest wording must not trip the gate — it exists to catch violations."""
    report = _report(findings=[{"severity": "REVIEW",
                                "title": "Exact product identifier not parsed",
                                "detail": "No ProductType was parsed. This is an evidence gap.",
                                "evidence": []}])
    assert capabilities.audit_report(report) == []


# ============================================ 3. the gate fires inside a real run

def test_finalize_records_the_claim_audit(tmp_path: Path):
    """A finished report carries its own claim audit."""
    import argparse

    from iphone_forensics.cli_v4 import _finish_run, _new_report

    run = tmp_path / "run"
    run.mkdir()
    paths = _paths(run)
    args = argparse.Namespace(redact=False, compare_json=None)
    report = _new_report(argparse.Namespace(redact=False, compare_json=None,
                                             sensitive_consent=False, sensitive_explicit=[]))
    _finish_run(paths["run_dir"], report, {"checks": {}}, args)

    persisted = __import__("json").loads(
        (paths["run_dir"] / "report.json").read_text(encoding="utf-8"))
    assert persisted["claim_audit"]["checked"] is True
    assert persisted["claim_audit"]["violations"] == []


def test_a_violation_becomes_a_blocker_finding(tmp_path: Path):
    """An unsupported claim must never slip through unremarked."""
    report = _report(hardware_assessment={
        "subsystems": {"battery": "pass"},
        "checks": [{"subsystem": "battery", "question": "Cycle count", "status": "pass",
                    "measurement": 500, "measurement_unit": "", "confidence": "high"}],
        "warnings": [], "disclaimer": ""})
    audit = reporting._audit_claim_matrix(report)
    assert audit["violation_count"] == 1
    assert any(f["title"].startswith("An unsupported claim") for f in report["findings"])


def test_audit_cannot_be_bypassed_by_finalize():
    """The audit runs on every finalize() call, whatever the caller supplied."""
    report = _report()
    report["claim_audit"] = {"checked": False, "violations": [], "violation_count": 0}
    audit = reporting._audit_claim_matrix(report)
    assert audit["checked"] is True, "a pre-seeded clean audit must not be trusted"


def _paths(run: Path):
    from iphone_forensics.evidence import run_dir_paths

    return run_dir_paths(run, "20260101-120000")


# ============================================ 4. missing battery data stays a gap

def test_missing_battery_metric_is_reported_as_unknown_not_as_a_replacement(tmp_path: Path):
    """The single most important honesty property in the whole tool."""
    report = _report(hardware_assessment={
        "subsystems": {"battery": "not_tested"},
        "checks": [{"subsystem": "battery", "question": "Cycle count",
                    "status": "not_tested", "measurement": None,
                    "measurement_unit": "", "confidence": "none",
                    "explanation": "The device did not expose a cycle count."}],
        "warnings": [], "disclaimer": ""})
    html = _html(tmp_path, report)
    assert "not_tested" in html
    assert "evidence gap" in html.lower() or "not collected" in html.lower()


def _html(tmp_path: Path, report: dict) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    reporting.build_html(tmp_path, report)
    return (tmp_path / "report.html").read_text(encoding="utf-8")