import json
import subprocess
import sys
from pathlib import Path

from iphone_forensics.repair import load_or_create, new_case, qa_summary, record_work


def test_new_case_defaults():
    case = new_case("CASE-1")
    assert case["status"] == "open"
    assert len(case["qa_checks"]) >= 10
    assert all(v == "not_tested" for v in case["qa_checks"].values())


def test_record_work_appends():
    case = new_case("CASE-1")
    record_work(case, "battery", part_source="OEM", notes="donor pull")
    assert case["work_performed"][0]["part"] == "battery"
    assert case["work_performed"][0]["part_source"] == "OEM"


def test_qa_summary_ready_requires_all_pass():
    case = new_case("CASE-1")
    assert qa_summary(case)["ready_for_customer"] is False
    for check in case["qa_checks"]:
        case["qa_checks"][check] = "pass"
    assert qa_summary(case)["ready_for_customer"] is True


def test_compare_pre_post_requires_both_reports(tmp_path: Path):
    case = new_case("CASE-1")
    result = qa = None
    from iphone_forensics.repair import compare_pre_post
    result = compare_pre_post(case)
    assert result["status"] == "incomplete"
    pre = tmp_path / "pre.json"
    post = tmp_path / "post.json"
    pre.write_text(json.dumps({"device": {"ProductType": "iPhone15,4", "SerialNumber": "S1"}}))
    post.write_text(json.dumps({"device": {"ProductType": "iPhone15,4", "SerialNumber": "S2"}}))
    case["pre_repair_baseline"] = str(pre)
    case["post_repair_report"] = str(post)
    result = compare_pre_post(case)
    assert result["overall"] == "suspicious"   # serial mismatch between pre and post


def _run_cli(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "iphone_forensics.cli_v4", *argv],
        capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"})


def test_cli_doctor_offline_ok():
    result = _run_cli("doctor")
    assert result.returncode == 0
    assert "Operational mode" in result.stdout


def test_cli_case_roundtrip(tmp_path: Path):
    case_file = tmp_path / "case.json"
    result = _run_cli("case", str(case_file), "--case-id", "T-1", "--symptoms", "no Face ID")
    assert result.returncode == 0, result.stderr
    case = json.loads(case_file.read_text())
    assert case["case_id"] == "T-1"
    assert case["customer_reported_symptoms"] == "no Face ID"


def test_cli_integrity_inconclusive_for_identical(tmp_path: Path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"device": {"ProductType": "iPhone15,4"}}))
    result = _run_cli("integrity", "--previous", str(report), "--current", str(report))
    assert "Overall integrity status" in result.stdout


def test_cli_evidence_verify_missing_path():
    result = _run_cli("evidence-verify", "/nonexistent/path/xyz")
    assert result.returncode == 2


def test_cli_manual_tests_lists_items():
    result = _run_cli("manual-tests")
    assert "Face ID" in result.stdout
    assert "cameras" in result.stdout
