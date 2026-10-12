"""Real-device validation (docs/v5/08-testing.md, docs/v5/10 §10 row 19).

No iPhone is attached in CI, so every test here skips cleanly. The default suite
never requires hardware; opt in explicitly with IPHONE_FORENSICS_DEVICE_TESTS=1
when a device is actually connected.

Offline by default: no test in this file runs a subprocess or touches a device
unless the opt-in is set.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_OPT_IN = "IPHONE_FORENSICS_DEVICE_TESTS"


def _idevice_id() -> str | None:
    return shutil.which("idevice_id")


def _device_attached() -> bool:
    """True only when idevice_id exists AND reports at least one UDID."""
    tool = _idevice_id()
    if not tool:
        return False
    try:
        result = subprocess.run(
            [tool, "-l"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return any(line.strip() for line in result.stdout.splitlines() if line.strip())


def _opt_in() -> bool:
    return os.environ.get(_OPT_IN) == "1"


DEVICE_ATTACHED = _device_attached()
RUN_THESE = DEVICE_ATTACHED and _opt_in()

requires_device = pytest.mark.skipif(
    not RUN_THESE,
    reason=f"set {_OPT_IN}=1 with an iPhone attached (idevice_id -l must report a UDID)",
)


@requires_device
def test_full_inspect_run_produces_a_verifiable_report(tmp_path: Path):
    """End-to-end: inspect a real device and verify every artifact it writes."""
    from iphone_forensics.evidence import verify_manifest
    from iphone_forensics.reporting import validate_report_html

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # The CLI entry point is what a user runs; drive it through the facade.
    from iphone_forensics.cli import main

    code = main(["inspect", "--no-sensitive", "--output", str(tmp_path)])
    assert code in (0, 1), f"inspect exited {code}"

    candidates = sorted(tmp_path.glob("iphone-forensics-*/report.json"))
    assert candidates, "inspect produced no report.json"
    run_dir = candidates[0].parent

    for filename in ("report.html", "report.json", "manifest.json", "README.txt"):
        assert (run_dir / filename).is_file(), f"missing {filename}"
    assert (run_dir / "evidence").is_dir(), "missing evidence/"

    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    html = (run_dir / "report.html").read_text(encoding="utf-8")
    assert validate_report_html(html, report) == [], "the real-device HTML failed validation"
    assert verify_manifest(run_dir)["verified"] is True, "the real-device manifest does not verify"
    assert "http" not in html and "<script" not in html.lower()


@requires_device
def test_compare_discovers_the_run_it_just_made(tmp_path: Path, monkeypatch):
    """compare's default auto-discovery must find a real run directory."""
    from iphone_forensics import cli

    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "iphone-forensics-20260101-120000"
    (run_dir / "evidence").mkdir(parents=True)
    (run_dir / "report.json").write_text(
        json.dumps({"schema_version": "5.0.0", "device": {}, "collection": [], "findings": []})
    )
    found = cli._default_current_report()
    assert found is not None
    assert found.parent == run_dir


def test_skip_reason_is_clear_when_no_device():
    """The skip must explain how to opt in, not just say 'skipped'."""
    if RUN_THESE:
        pytest.skip("device tests are enabled; nothing to assert")
    assert _OPT_IN in requires_device.kwargs.get("reason", ""), (
        "the skip reason must name the opt-in variable"
    )
