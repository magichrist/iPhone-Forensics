"""The compact HTML report: one fact per line, no repeated or device-independent data.

report.json remains the complete evidence record. These tests pin the presentation
contract so the verbose panels, duplicate tables and boilerplate stay out.
"""

from __future__ import annotations

import re
from pathlib import Path

from iphone_forensics.reporting import build_html, finalize, validate_report_html


def _report() -> dict:
    return {
        "version": "5.1.0",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:05:00+00:00",
        "device": {
            "ProductType": "iPhone15,4",
            "ProductVersion": "18.1",
            "BuildVersion": "22B83",
            "SerialNumber": "SERIAL123456",
            "TotalDiskCapacity": 128000000000,
        },
        "collection": [
            {"name": "device-info", "status": "collected"},
            {"name": "crash-reports", "status": "skipped_by_user"},
        ],
        "findings": [
            {
                "severity": "WARNING",
                "title": "Battery cycle count is high",
                "detail": "Above the expected range.",
                "evidence": ["raw/diagnostics.plist"],
            },
            {"severity": "INFO", "title": "Model reported by iOS", "detail": "", "evidence": []},
        ],
        "assessment": {
            "status": "review",
            "verdict": "REVIEW — CHECK MANUALLY",
            "collection_total": 2,
            "collection_successful": 1,
            "collection_failed_or_partial": 1,
        },
        "hardware_assessment": {
            "checks": [
                {
                    "subsystem": "battery",
                    "question": "Battery cycle count",
                    "status": "degraded",
                    "measurement": 612,
                    "measurement_unit": "cycles",
                },
                {
                    "subsystem": "storage",
                    "question": "Total physical storage capacity",
                    "status": "pass",
                    "measurement": 128.0,
                    "measurement_unit": "decimal GB",
                },
            ]
        },
        "integrity_assessment": {
            "overall": "consistent",
            "classifications": {"SerialNumber": "consistent", "SomePart": "not_detectable"},
            "changes": [],
        },
    }


def _render(tmp_path: Path, report: dict) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    build_html(tmp_path, report)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


def _body(html: str) -> str:
    """Rendered content only — the stylesheet legitimately repeats words like 'table'."""
    return re.sub(r"<style.*?</style>", "", html, flags=re.DOTALL)


def test_report_is_short_even_with_a_full_fixture(tmp_path: Path):
    html = _render(tmp_path, _report())
    # The whole self-contained document, CSS included, fits in a small page.
    assert len(html.encode("utf-8")) < 9000
    assert validate_report_html(html, _report()) == []


def test_no_repeated_panels_or_device_independent_boilerplate(tmp_path: Path):
    body = _body(_render(tmp_path, _report()))
    for gone in (
        "Outcome and completeness",
        "No changes between snapshots",
        "No classifications",
        "No changes detected",
        "comparison: not collected",
        "Exit code",
        "Seconds",
        "Coverage by category",
        "How to read this report",
        "Labels: Verified",
        "Battery/storage:",
    ):
        assert gone not in body, f"verbose boilerplate is back: {gone!r}"


def test_each_measurement_is_rendered_once(tmp_path: Path):
    body = _body(_render(tmp_path, _report()))
    assert body.count("612 cycles") == 1
    # A passing measurement stays in report.json; it is not drawn in the HTML.
    assert "128 decimal GB" not in body
    # Raw bytes and their derived GB are not printed side by side.
    assert "128000000000" not in body
    assert "128.00 GB" in body


def test_integrity_only_lists_classifications_needing_attention(tmp_path: Path):
    body = _body(_render(tmp_path, _report()))
    assert "integrity: consistent" in body
    assert "SomePart: not_detectable" in body
    # A passing classification is not printed twice (overall + per-field table).
    assert "SerialNumber: consistent" not in body


def test_gaps_table_has_only_the_columns_a_reader_needs(tmp_path: Path):
    body = _body(_render(tmp_path, _report()))
    section = body.split("5. Collection gaps", 1)[1]
    headers = re.findall(r"<th scope='col'>(.*?)</th>", section)
    assert headers == ["Collector", "Status", "Outcome"]
    assert "skipped_by_user" in section and "Not consented" in section
    assert "returncode" not in section


def test_comparison_panel_appears_only_with_actual_changes(tmp_path: Path):
    report = _report()
    assert "Change since the previous inspection" not in _render(tmp_path / "none", report)
    report["comparison"] = {
        "changes": [
            {"field": "ProductVersion", "previous": "17.0", "current": "18.1", "status": "changed"}
        ]
    }
    body = _body(_render(tmp_path / "diff", report))
    assert "Change since the previous inspection" in body
    assert "17.0" in body and "18.1" in body
    assert "No changes detected" not in body


def test_malformed_report_shapes_do_not_break_rendering(tmp_path: Path):
    """A corrupt list field is an evidence gap, never a reason to lose the report."""
    report = _report()
    report["hardware_assessment"]["checks"] = 7
    report["integrity_assessment"]["changes"] = "not-a-list"
    report["comparison"] = {"changes": {"field": "x"}}
    report["findings"][0]["evidence"] = "raw/one.plist"
    report["device"]["TotalDiskCapacity"] = float("inf")
    html = _render(tmp_path, report)
    assert "<h2>1. Summary</h2>" in html
    assert validate_report_html(html, report) == []


def test_redacted_export_stays_compact_and_honest(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    finalize(tmp_path, _report(), redact_identifiers=True)
    html = (tmp_path / "report-redacted.html").read_text(encoding="utf-8")
    assert len(html.encode("utf-8")) < 9000
    assert "SERIAL123456" not in html
    assert "Identifiers masked in this HTML export" in html
    assert "report-validation: clean" in html
