"""Phase 5 reporting tests — spec §12, phase-5 tasks 2 & 3.

Covers:
  1. Partial-collection honesty banner (a partial run must never read as healthy).
  2. The "Unknown / unavailable / unsupported / skipped tests" panel, rendered
     from `capabilities.get_matrix()` with counts matching `coverage_counts()`.
  3. The 15-section HTML outline mapped against spec §12.
  4. Missing != 0/false — absent telemetry is never coerced into a value.
  5. Redaction and XSS escaping still hold for the new sections.

Offline only: no device, no network, no toolchain.
"""
import re
from pathlib import Path

from iphone_forensics.buyer import CHECKLIST, template
from iphone_forensics.capabilities import COVERAGE_LEVELS, coverage_counts, get_matrix
from iphone_forensics.reporting import MISSING, SECTION_TITLES, build_html, esc, finalize

SERIAL = "SERIALTOPSECRET1234"
IMEI = "351234567890123"
UDID = "00008030-AAAAAAAA-BBBB-CCCC-DDDDEEEEEEEE"


def _report(**overrides) -> dict:
    """Minimal report shaped like a real v4 run (collections may be overridden)."""
    report = {
        "project": "iPhone Forensics",
        "schema_version": "4.0.0",
        "version": "4.0.0",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:05:00+00:00",
        "host": {"platform": "test", "macOS": "", "python": "3.14", "architecture": "arm64"},
        "tools": {"ideviceinfo": "/usr/bin/ideviceinfo"},
        "target_udid": UDID,
        "connected_devices": [UDID],
        "device": {"ProductType": "iPhone15,4", "SerialNumber": SERIAL,
                   "InternationalMobileEquipmentIdentity": IMEI},
        "collection": [{"name": "device-info-xml", "status": "success", "returncode": 0,
                        "duration_seconds": 1.5, "stdout_bytes": 4096, "stderr_bytes": 0,
                        "timed_out": False}],
        "findings": [],
        "limitations": ["Read-only inspection."],
        "assessment": {"status": "no_recorded_failures", "verdict": "NO RECORDED FAILURES",
                       "description": "Decision support only.", "collection_total": 1,
                       "collection_successful": 1, "collection_failed_or_partial": 0,
                       "identity_fields_present": 4, "identity_fields_expected": 4},
        "buyer_data": template(),
    }
    report.update(overrides)
    return report


def _html(tmp_path: Path, report: dict, **kwargs) -> str:
    build_html(tmp_path, report, **kwargs)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


# --------------------------------------------------------------- 15-section outline

def test_report_renders_all_fifteen_spec_sections_in_order(tmp_path: Path):
    """Spec §12 order: executive summary ... limitations/next steps."""
    report = _report()
    report["hardware_assessment"] = {"subsystems": {"battery": "pass"}, "checks": [],
                                    "warnings": [], "blockers": [], "disclaimer": "Heuristic."}
    report["integrity_assessment"] = {"overall": "verified", "classifications": {"SerialNumber": "verified"},
                                      "changes": [], "findings": [], "disclaimer": "Not proof."}
    html = _html(tmp_path, report)
    positions = []
    for number, title in enumerate(SECTION_TITLES, start=1):
        heading = f"{number}. {title}"
        assert heading in html, f"missing spec §12 section: {heading}"
        positions.append(html.index(heading))
    assert positions == sorted(positions), "spec §12 sections must appear in order"


def test_section_titles_cover_executive_summary_through_next_steps():
    assert SECTION_TITLES[0] == "Executive summary"
    assert SECTION_TITLES[-1].endswith("next steps")
    assert len(SECTION_TITLES) == 15


# --------------------------------------------------------- partial-collection banner

def test_banner_absent_on_clean_report(tmp_path: Path):
    html = _html(tmp_path, _report())
    # The CSS rule is always present; assert the banner *element* is not rendered.
    assert "<section class='panel banner-incomplete'" not in html
    assert "INCOMPLETE COLLECTION" not in html


def test_banner_shown_when_a_collector_failed(tmp_path: Path):
    report = _report(collection=[
        {"name": "device-info-xml", "status": "success", "returncode": 0, "duration_seconds": 1.0,
         "stdout_bytes": 10, "stderr_bytes": 0, "timed_out": False},
        {"name": "diagnostics-battery", "status": "failed_or_partial", "returncode": 1,
         "duration_seconds": 60.0, "timed_out": False, "stdout_bytes": 0, "stderr_bytes": 120},
    ])
    html = _html(tmp_path, report)
    assert "<section class='panel banner-incomplete'" in html, "a failed collector must raise the banner"
    assert "INCOMPLETE COLLECTION" in html
    # The banner must name the sections that cannot be evaluated, not just count failures.
    assert "Diagnostic metric candidates" in html
    assert "diagnostics-battery" in html


def test_banner_shown_when_assessment_status_is_incomplete(tmp_path: Path):
    """incomplete status with all-success collectors (e.g. missing identity fields)."""
    report = _report(assessment={"status": "incomplete", "verdict": "INCOMPLETE — HOLD PAYMENT",
                                 "description": "", "collection_total": 1, "collection_successful": 1,
                                 "collection_failed_or_partial": 0, "identity_fields_present": 1,
                                 "identity_fields_expected": 4})
    html = _html(tmp_path, report)
    assert "<section class='panel banner-incomplete'" in html
    assert "Device identity (reported by iOS)" in html


def test_banner_does_not_look_like_a_healthy_verdict(tmp_path: Path):
    """status is 'no_recorded_failures' but a collector failed: must not render green/neutral."""
    report = _report(collection=[
        {"name": "full-backup-libimobiledevice", "status": "failed_or_partial", "returncode": None,
         "duration_seconds": 3600.0, "timed_out": True, "stdout_bytes": 0, "stderr_bytes": 900},
    ])
    report["assessment"] = {"status": "no_recorded_failures", "verdict": "NO RECORDED FAILURES",
                            "description": "", "collection_total": 1, "collection_successful": 0,
                            "collection_failed_or_partial": 1, "identity_fields_present": 4,
                            "identity_fields_expected": 4}
    html = _html(tmp_path, report)
    assert "<section class='panel banner-incomplete'" in html
    assert "verdict neutral" not in html, "a partial run must not be styled as a clean pass"


def test_banner_escapes_untrusted_collector_names(tmp_path: Path):
    report = _report(collection=[
        {"name": "<script>alert('x')</script>", "status": "failed_or_partial", "returncode": 1,
         "duration_seconds": 1.0, "timed_out": False, "stdout_bytes": 0, "stderr_bytes": 0},
    ])
    html = _html(tmp_path, report)
    assert "<script>alert('x')</script>" not in html
    assert "&lt;script&gt;" in html


# ------------------------------------------ unknown / unavailable / unsupported panel

def test_unknown_panel_renders_counts_matching_coverage_counts(tmp_path: Path):
    html = _html(tmp_path, _report())
    assert "Unknown / unavailable / unsupported / skipped tests" in html
    counts = coverage_counts()
    for level in COVERAGE_LEVELS:
        # Counts are rendered as "<b>level</b>: N" inside a list item.
        assert f"<b>{level}</b>: {counts[level]}</li>" in html, f"missing count for {level}"


def test_unknown_panel_lists_unsupported_and_manual_items(tmp_path: Path):
    html = _html(tmp_path, _report())
    assert "Can never be established in software" in html
    assert "Requires a guided manual test" in html
    for row in get_matrix():
        if row["coverage"] in {"manual", "unsupported"}:
            # Matrix text is escaped like any other untrusted field.
            assert esc(row["item"]) in html, f"matrix item absent from panel: {row['item']}"


def test_unknown_panel_names_unsupported_honest_limits(tmp_path: Path):
    html = _html(tmp_path, _report())
    # The two capabilities the matrix declares as impossible must be called out as such.
    assert "Water resistance / opened-before" in html
    assert "Component originality / parts pairing state" in html


def test_unknown_panel_lists_failed_collectors_as_skipped(tmp_path: Path):
    report = _report(collection=[
        {"name": "crash-report-copy", "status": "failed_or_partial", "returncode": 127,
         "timed_out": False, "duration_seconds": 2.0, "stdout_bytes": 0, "stderr_bytes": 30},
    ])
    html = _html(tmp_path, report)
    assert "Skipped / unavailable in this specific run" in html
    assert "crash-report-copy" in html


def test_unknown_panel_empty_state_when_all_collectors_succeeded(tmp_path: Path):
    html = _html(tmp_path, _report())
    assert "Every collector completed or ended as an expected stream boundary" in html


# ------------------------------------------------------ missing != 0 / missing != false

def test_absent_assessment_counts_are_not_rendered_as_zero(tmp_path: Path):
    """An assessment with no counts must read 'not provided', not 0 — 0 is a claim."""
    report = _report(assessment={"status": "incomplete", "verdict": "INCOMPLETE",
                                 "description": "", "buyer_checklist": {"counts": {}}})
    html = _html(tmp_path, report)
    stats = html[html.index('<div class="stats">'):html.index('<p class="callout">')]
    tiles = dict(re.findall(r'<span class="muted">(.*?)</span><b>(.*?)</b>', stats, re.DOTALL))
    assert tiles["Collectors completed"] == f"{MISSING}/{MISSING}"
    assert tiles["Failed / partial"] == MISSING
    assert tiles["Identity fields"] == f"{MISSING}/{MISSING}"
    assert tiles["Checklist passed"] == f"{MISSING}/{len(CHECKLIST)}"
    # Regression guard: the old serializer emitted hardcoded 0 / 4 / 21 baselines here.
    for label, value in tiles.items():
        assert not re.search(r"(^|/)(0|4)$", value), f"'{label}' still defaults to a number: {value}"


def test_missing_collection_telemetry_renders_not_provided(tmp_path: Path):
    """A collector with no recorded exit code/bytes is unknown, not 0."""
    report = _report(collection=[{"name": "mystery-collector", "status": "failed_or_partial"}])
    html = _html(tmp_path, report)
    # Anchor inside the "13. Collection coverage" table, not the banner (which also
    # names the failed collector).
    coverage_start = html.index("13. Collection coverage")
    row_start = html.index("mystery-collector", coverage_start)
    row = html[row_start:html.index("</tr>", row_start)]
    assert MISSING in row
    assert "<td>0</td>" not in row


def test_missing_crash_triage_counts_are_not_rendered_as_zero(tmp_path: Path):
    report = _report(crash_triage={"interpretation": "Triage ran."})
    html = _html(tmp_path, report)
    triage_start = html.index("10. Crash and panic triage")
    line = html[triage_start:html.index("</p>", html.index("Files scanned", triage_start))]
    assert "Files scanned: not provided" in line


def test_missing_buyer_observations_are_not_zero(tmp_path: Path):
    """template() ships None observations — they must render as 'not provided', never 0."""
    report = _report(buyer_data=template())
    assert report["buyer_data"]["observations"]["battery_cycle_count"] is None
    html = _html(tmp_path, report)
    assert f"Battery maximum capacity (%)</td><td>{MISSING}</td>" in html
    assert f"Battery cycle count</td><td>{MISSING}</td>" in html
    assert f"Repair estimate</td><td>{MISSING}</td>" in html


def test_explicit_zero_measurement_is_still_shown(tmp_path: Path):
    """Guard against over-correcting: a real recorded 0 must survive."""
    report = _report(buyer_data=template())
    report["buyer_data"]["observations"]["battery_cycle_count"] = 0
    html = _html(tmp_path, report)
    assert "Battery cycle count</td><td>0</td>" in html


# ------------------------------------------------------------------------ security

def test_no_external_requests_in_generated_html(tmp_path: Path):
    """Standalone offline file: no remote stylesheets, scripts, fonts, or images."""
    html = _html(tmp_path, _report())
    for marker in ("http://", "https://", "//cdn", "<script src", "<link rel=\"stylesheet\""):
        assert marker not in html, f"external reference found: {marker}"


def test_no_script_injection_via_device_findings_or_collection(tmp_path: Path):
    report = _report(
        device={"ProductType": "<script>alert(1)</script>",
                "SerialNumber": "<img src=x onerror=alert(2)>"},
        findings=[{"severity": "INFO", "title": "<script>bad()</script>",
                   "detail": "<b>bold</b>", "evidence": ["<iframe src=x>"]}],
        collection=[{"name": "<script>evil()</script>", "status": "failed_or_partial",
                     "returncode": 1, "timed_out": False, "duration_seconds": 1.0,
                     "stdout_bytes": 0, "stderr_bytes": 0}],
        diagnostic_candidates=[{"source": "<script>s()</script>", "key": "<b>k</b>",
                                "value": "<script>v()</script>", "interpretation": "<i>i</i>"}],
        limitations=["<script>limit()</script>"],
    )
    html = _html(tmp_path, report)
    for payload in ("<script>alert(1)</script>", "<script>bad()</script>", "<script>evil()</script>",
                    "<script>s()</script>", "<script>v()</script>", "<script>limit()</script>",
                    "<iframe src=x>", "<img src=x onerror=alert(2)>"):
        assert payload not in html, f"unescaped payload: {payload}"
    assert "&lt;script&gt;" in html


def test_redacted_exports_still_mask_identifiers(tmp_path: Path):
    """Reuse pattern from test_security_reliability — redaction must survive the new sections."""
    report = _report()
    finalize(tmp_path, report, redact_identifiers=True)
    for name in ("report-redacted.json", "report-redacted.html"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert SERIAL not in text, f"{name} leaked SerialNumber"
        assert IMEI not in text, f"{name} leaked IMEI"
        assert UDID not in text, f"{name} leaked UDID"
    # The unknown panel must still render in the redacted HTML export.
    redacted_html = (tmp_path / "report-redacted.html").read_text(encoding="utf-8")
    assert "Unknown / unavailable / unsupported / skipped tests" in redacted_html
    assert "Can never be established in software" in redacted_html


def test_private_report_keeps_full_identifiers(tmp_path: Path):
    report = _report()
    finalize(tmp_path, report, redact_identifiers=True)
    assert SERIAL in (tmp_path / "report.json").read_text(encoding="utf-8")


def test_redacted_html_does_not_contain_banner_for_identifiers(tmp_path: Path):
    """The failure banner must not become a redaction leak channel."""
    report = _report(collection=[
        {"name": "device-info-xml", "command": ["ideviceinfo", "-u", UDID],
         "status": "failed_or_partial", "returncode": 1, "timed_out": False,
         "duration_seconds": 1.0, "stdout_bytes": 0, "stderr_bytes": 0},
    ])
    finalize(tmp_path, report, redact_identifiers=True)
    assert UDID not in (tmp_path / "report-redacted.html").read_text(encoding="utf-8")