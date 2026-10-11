"""CLI integration, panic recurrence, and v4-schema migration tests (spec §9/§12/§14)."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from iphone_forensics.analysis import analyze_crash_artifacts


def _run_cli(*argv: str) -> subprocess.CompletedProcess:
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-m", "iphone_forensics.cli_v4", *argv],
        capture_output=True, text=True, env=env, timeout=60)


# ------------------------------------------------------- CLI integration (new commands)

def test_cli_buyer_verdict_insufficient(tmp_path: Path):
    result = _run_cli("buyer")
    assert result.returncode == 1
    assert "INSUFFICIENT_EVIDENCE" in result.stdout


def test_cli_buyer_with_checklist(tmp_path: Path):
    # All critical checks pass and one non-critical fails → rule 4 applies.
    # (With critical unknowns present, rule 3 outranks rule 4 by design —
    # see test_cli_buyer_critical_unknowns_outrank below.)
    checks = {"battery_health": {"status": "pass"}, "cameras": {"status": "pass"},
              "physical_damage": {"status": "fail"}}
    from iphone_forensics.buyer import CHECKLIST
    for item in CHECKLIST:
        if item["critical"]:
            checks[item["id"]] = {"status": "pass"}
    checklist = tmp_path / "c.json"
    checklist.write_text(json.dumps({"checks": checks}))
    result = _run_cli("buyer", "--checklist-json", str(checklist))
    assert "BUY_ONLY_AFTER_REPAIR" in result.stdout


def test_cli_buyer_critical_unknowns_outrank_noncritical_failures(tmp_path: Path):
    checklist = tmp_path / "c.json"
    checklist.write_text(json.dumps({"checks": {
        "battery_health": {"status": "pass"}, "cameras": {"status": "pass"},
        "physical_damage": {"status": "fail"}}}))
    result = _run_cli("buyer", "--checklist-json", str(checklist))
    assert "INVESTIGATE_FURTHER" in result.stdout
    assert "rule 3" in result.stdout


def test_cli_hardware_on_existing_report(tmp_path: Path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"diagnostic_candidates": [], "device": {}, "crash_triage": {}}))
    result = _run_cli("hardware", str(report))
    assert result.returncode == 0
    assert "not_tested" in result.stdout


def test_cli_diagnose_lists_actions(tmp_path: Path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({
        "findings": [{"severity": "BLOCKER", "title": "No toolkit", "detail": "install", "evidence": []}],
        "hardware_assessment": {"warnings": []},
        "buyer_data": {"checks": {"battery_health": {"status": "not_tested"}}},
        "crash_triage": {}}))
    result = _run_cli("diagnose", str(report))
    assert "CRITICAL" in result.stdout and "MANUAL" in result.stdout


def test_cli_diagnose_clean_report(tmp_path: Path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"findings": [], "hardware_assessment": {"warnings": []},
                                  "buyer_data": {"checks": {}}, "crash_triage": {}}))
    result = _run_cli("diagnose", str(report))
    assert "No outstanding" in result.stdout


def test_cli_compare_two_reports(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"device": {"ProductType": "iPhone15,4"}}))
    b.write_text(json.dumps({"device": {"ProductType": "iPhone15,4"}}))
    result = _run_cli("compare", "--previous", str(a), "--current", str(b))
    assert result.returncode == 0
    assert "consistent" in result.stdout


def test_cli_config_write_and_validate(tmp_path: Path):
    cfg = tmp_path / "cfg.json"
    result = _run_cli("config", "--out", str(cfg))
    assert result.returncode == 0 and cfg.exists()
    ok = _run_cli("config", "--check", str(cfg))
    assert ok.returncode == 0
    (tmp_path / "bad.json").write_text('{"subprocess_timeout_seconds_default": "oops"}')
    bad = _run_cli("config", "--check", str(tmp_path / "bad.json"))
    assert bad.returncode == 2


def test_cli_integrity_exit_code_for_suspicious(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"device": {"SerialNumber": "S-one"}}))
    b.write_text(json.dumps({"device": {"SerialNumber": "S-two"}}))
    result = _run_cli("integrity", "--previous", str(a), "--current", str(b))
    assert result.returncode == 1  # EXIT_FINDINGS
    assert "suspicious" in result.stdout


# ------------------------------------------------------- panic recurrence (spec §9)

def _make_run_with_panics(tmp_path: Path, count: int = 3) -> Path:
    run = tmp_path / "run"
    ev = run / "raw" / "offline-evidence"
    ev.mkdir(parents=True)
    for i in range(count):
        (ev / f"panic-full-{i}.ips").write_text(json.dumps({
            "bug_type": "210", "procName": "kernel",
            "timestamp": f"2026-01-0{i + 1}T10:00:00Z",
            "panicString": "WDT timeout"}))
    return run


def test_repeated_panics_detected_as_pattern(tmp_path: Path):
    triage = analyze_crash_artifacts(_make_run_with_panics(tmp_path))
    patterns = triage["recurrence"]["repeated_patterns"]
    assert patterns, "3 identical bug_type+procName artifacts must group"
    assert patterns[0]["occurrences"] == 3
    assert patterns[0]["classification"] == "weak_heuristic_pattern"


def test_recurrence_span_and_timestamps(tmp_path: Path):
    triage = analyze_crash_artifacts(_make_run_with_panics(tmp_path))
    pattern = triage["recurrence"]["repeated_patterns"][0]
    assert len(pattern["timestamps"]) == 3
    assert "2026-01-01" in pattern["span"]


def test_recurrence_with_unknown_timestamp_format(tmp_path: Path):
    run = tmp_path / "run"
    ev = run / "raw" / "offline-evidence"
    ev.mkdir(parents=True)
    for i in range(2):
        (ev / f"watchdog-{i}.ips").write_text(json.dumps(
            {"bug_type": "283", "procName": "wfd", "timestamp": "garbage-time-format"}))
    triage = analyze_crash_artifacts(run)
    pattern = triage["recurrence"]["repeated_patterns"][0]
    assert pattern["timestamps_unknown"] == 2
    assert pattern["span"] == "insufficient timestamp data"


def test_single_artifact_is_not_a_pattern(tmp_path: Path):
    run = tmp_path / "run"
    ev = run / "raw" / "offline-evidence"
    ev.mkdir(parents=True)
    (ev / "panic-full-0.ips").write_text(json.dumps(
        {"bug_type": "210", "procName": "kernel", "timestamp": "2026-01-01T10:00:00Z"}))
    triage = analyze_crash_artifacts(run)
    assert triage["recurrence"]["pattern_count"] == 0


def test_recurrence_never_classified_as_diagnosis():
    from iphone_forensics.analysis import _recurrence_analysis
    items = [{"bug_type": "210", "procName": "kernel", "timestamp": "2026-01-01T10:00:00Z"}
             for _ in range(5)]
    result = _recurrence_analysis(items, [])
    assert all(p["classification"] == "weak_heuristic_pattern" for p in result["repeated_patterns"])


# ------------------------------------------------------- v4 schema + v3 migration (spec §12)

def test_report_json_records_schema_version(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    from iphone_forensics.cli_v4 import _new_report, _finish_run
    import argparse
    args = argparse.Namespace(redact=False, compare_json=None)
    report = _new_report(args)
    assert report["schema_version"] == "5.0.0"
    _finish_run(run, report, {"checks": {}}, args)
    persisted = json.loads((run / "report.json").read_text())
    assert persisted["schema_version"] == "5.0.0"
    # v5 writes the run README; a finished run must never ship without it.
    assert (run / "README.txt").is_file()


def test_integrity_engine_reads_v3_report_without_schema_version(tmp_path: Path):
    """A v3 report (no schema_version key) must be usable as previous/current."""
    v3 = {"version": "3.0.0", "device": {"ProductType": "iPhone15,4"},
          "diagnostic_candidates": [], "collection": []}
    from iphone_forensics.integrity import assess_integrity
    result = assess_integrity(v3, {"schema_version": "4.0.0",
                                   "device": {"ProductType": "iPhone15,4"}})
    assert result["overall"] == "consistent"


def test_partial_collection_report_states_incompleteness(tmp_path: Path):
    """A report whose collection failed must NOT look like a healthy one."""
    report = {
        "diagnostic_candidates": [], "device": {},
        "crash_triage": {},
        "collection": [{"name": "device-info", "status": "failed_or_partial"}],
    }
    from iphone_forensics.hardware import assess_hardware
    from iphone_forensics.analysis import automated_assessment
    hardware = assess_hardware(report)
    assessment = automated_assessment(report, None)
    assert hardware["subsystems"]["battery"] == "not_tested"
    assert assessment["collection_failed_or_partial"] == 1
    assert assessment["status"] == "incomplete"


def test_entry_points_declared():
    text = Path("pyproject.toml").read_text()
    assert 'iphone-surgery = "iphone_forensics.cli_v4:main"' in text
    assert 'iphone-forensics = "iphone_forensics.cli:main"' in text


def test_hardware_integration_markers_skip_no_device():
    """Live-device tests: skip cleanly when no libimobiledevice devices exist."""
    import shutil
    if not shutil.which("idevice_id"):
        pytest.skip("libimobiledevice not installed")
    from iphone_forensics.collectors import discover_devices
    from pathlib import Path
    probe = Path("/tmp/ipt-probe")
    probe.mkdir(mode=0o700, exist_ok=True)
    devices = discover_devices(probe, [])
    # If a real phone happens to be attached we still only assert shape, never health.
    assert isinstance(devices, list)
