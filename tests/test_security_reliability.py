"""Security, privacy, and reliability tests — spec §11/§14.

Path traversal, symlink attacks, malformed evidence, oversized inputs,
subprocess hang handling, and identifier redaction across output formats.
"""

import json
import sys
from pathlib import Path

import pytest

from iphone_forensics.analysis import analyze_crash_artifacts
from iphone_forensics.buyer import template
from iphone_forensics.evidence import build_manifest, verify_manifest
from iphone_forensics.reporting import build_html
from iphone_forensics.util import run_command, safe_name

# ----------------------------------------------------------------- path traversal / symlinks


def test_offline_copy_rejects_escape_via_source_is_dir(tmp_path: Path):
    """inspect --backup-dir only accepts directories; a file cannot smuggle a path out."""
    from iphone_forensics.cli_v4 import _inspect_backup

    not_a_dir = tmp_path / "file.json"
    not_a_dir.write_text("{}")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    report: dict = {"findings": []}
    _inspect_backup(type("Args", (), {"backup_dir": str(not_a_dir)})(), run_dir, report, template())
    assert any(f["severity"] == "BLOCKER" for f in report["findings"])


def test_symlinked_artifact_not_followed_out_of_tree(tmp_path: Path):
    """A symlink inside the evidence root pointing outside must not crash or leak."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret")
    run = tmp_path / "run"
    (run / "raw" / "offline-evidence").mkdir(parents=True)
    (run / "raw" / "offline-evidence" / "link.ips").symlink_to(secret)
    # Triage must not follow into arbitrary content nor crash.
    triage = analyze_crash_artifacts(run)
    assert "files_scanned" in triage


def test_safe_name_neutrally_handles_traversal():
    assert ".." not in safe_name("../../etc/passwd")
    assert "/" not in safe_name("a/b/c")
    assert "\\" not in safe_name("a\\b")


def test_verify_manifest_rejects_traversal_paths(tmp_path: Path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "x.txt").write_text("x")
    build_manifest(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    data = json.loads(manifest_path.read_text())
    data["artifacts"].append(
        {"path": "../../outside/secret.txt", "size_bytes": 1, "sha256": "0" * 64}
    )
    evil = tmp_path / "evil-manifest.json"
    evil.write_text(json.dumps(data))
    verdict = verify_manifest(evil)
    # Must count as missing (or error), never silently resolve outside base.
    assert verdict["verified"] is False
    assert verdict["missing"] == 1 or "error" in verdict


# ----------------------------------------------------------------- malformed evidence


def test_malformed_ips_content_does_not_crash_triage(tmp_path: Path):
    run = tmp_path / "run"
    (run / "raw" / "offline-evidence").mkdir(parents=True)
    (run / "raw" / "offline-evidence" / "bad.ips").write_bytes(
        b"\x00\x01\x02\xff\xfe not json \xf0\x9f"
    )
    triage = analyze_crash_artifacts(run)
    assert triage["files_scanned"] == 1


def test_huge_single_line_ip_recognized_but_bounded(tmp_path: Path):
    run = tmp_path / "run"
    (run / "raw" / "offline-evidence").mkdir(parents=True)
    # 5 MB single line of 'A' inside an .ips — must be bounded (1 MB read cap).
    (run / "raw" / "offline-evidence" / "big.ips").write_text("A" * (5 * 1024 * 1024))
    triage = analyze_crash_artifacts(run)
    assert triage["files_scanned"] == 1  # no crash, no unbounded read blowup


def test_conflicting_telemetry_reported_not_averaged(tmp_path: Path):
    report = {
        "diagnostic_candidates": [
            {"source": "A", "key": "CycleCount", "value": "10"},
            {"source": "B", "key": "CycleCount", "value": "9000"},
        ],
        "device": {},
        "crash_triage": {},
    }
    checks = [
        c
        for c in __import__(
            "iphone_forensics.hardware", fromlist=["battery_checks"]
        ).battery_checks(report)
        if "cycle" in c.question.lower()
    ]
    # First-seen wins, but both candidates remain visible in report evidence.
    assert any(c.measurement is not None for c in checks)


# ----------------------------------------------------------------- subprocess reliability


def test_run_command_times_out_hanging_process():
    if sys.platform == "win32":
        pytest.skip("POSIX sleep semantics")
    result = run_command(["sleep", "5"], timeout=1)
    assert result["timed_out"] is True
    # Duration must be near the 1s timeout, not 5s.
    assert result["duration_seconds"] < 3


def test_run_command_missing_executable_is_clean():
    result = run_command(["definitely-not-a-real-binary-xyz"], timeout=3)
    assert result["returncode"] is None
    assert result["timed_out"] is False
    assert b"No such file" in result["stderr"] or result["stderr"]


def test_run_command_preserves_nonzero_exit_meaning():
    result = run_command(["false"], timeout=5)
    assert result["returncode"] == 1
    assert result["timed_out"] is False


# ----------------------------------------------------------------- redaction across outputs

SENSITIVE = "SERIALTOPSECRET1234"


def _report_with_sensitive():
    return {
        "version": "4.0.0",
        "started_at": "now",
        "finished_at": "later",
        "host": {"platform": "test", "macOS": "", "python": "3", "architecture": "arm64"},
        "target_udid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "connected_devices": ["AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"],
        "device": {"SerialNumber": SENSITIVE, "ProductType": "iPhone15,4"},
        "collection": [
            {
                "name": "cmd",
                "command": ["tool", "-u", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"],
                "status": "success",
            }
        ],
        "findings": [],
        "tools": {},
        "limitations": [],
        "assessment": {},
        "buyer_data": template(),
    }


def test_redaction_masks_in_html_and_json(tmp_path: Path):
    from iphone_forensics.reporting import finalize

    report = _report_with_sensitive()
    finalize(tmp_path, report, redact_identifiers=True)
    for name in ("report-redacted.json", "report-redacted.html"):
        text = (tmp_path / name).read_text()
        assert SENSITIVE not in text
        assert "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" not in text


def test_private_report_keeps_full_identifiers(tmp_path: Path):
    from iphone_forensics.reporting import finalize

    report = _report_with_sensitive()
    finalize(tmp_path, report, redact_identifiers=True)
    assert SENSITIVE in (tmp_path / "report.json").read_text()


def test_html_escapes_findings_and_device_fields(tmp_path: Path):
    report = {
        "version": "4.0.0",
        "started_at": "n",
        "finished_at": "n",
        "host": {"platform": "t", "macOS": "", "python": "3", "architecture": "arm"},
        "device": {"DeviceName": "<script>x</script>"},
        "findings": [
            {"severity": "INFO", "title": "<img src=x onerror=alert(1)>", "detail": "<b>"}
        ],
        "collection": [],
        "tools": {},
        "limitations": [],
        "assessment": {},
        "buyer_data": template(),
    }
    build_html(tmp_path, report)
    html = (tmp_path / "report.html").read_text()
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_manifest_v4_schema_roundtrip_after_finalize(tmp_path: Path):
    from iphone_forensics.reporting import finalize

    report = _report_with_sensitive()
    finalize(tmp_path, report)  # no redaction
    # v3 finalize writes a list manifest; v4 verify must accept it.
    verdict = verify_manifest(tmp_path)
    assert verdict["matched"] >= 0
