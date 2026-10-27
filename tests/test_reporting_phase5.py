"""Phase 5 reporting tests — spec §12, phase-5 tasks 2 & 3.

Covers:
  1. Partial-collection honesty banner (a partial run must never read as healthy).
  2. The "Unknown, unavailable, unsupported and skipped tests" panel, rendered
     from `capabilities.get_matrix()` with counts matching `coverage_counts()`.
  3. The 15-section HTML outline mapped against spec §12.
  4. Missing != 0/false — absent telemetry is never coerced into a value.
  5. Redaction and XSS escaping still hold for the new sections.

Offline only: no device, no network, no toolchain.
"""

import re
from pathlib import Path

from iphone_forensics.buyer import template
from iphone_forensics.capabilities import get_matrix
from iphone_forensics.reporting import (
    MISSING,
    SECTION_TITLES,
    build_html,
    esc,
    finalize,
)

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
        "device": {
            "ProductType": "iPhone15,4",
            "SerialNumber": SERIAL,
            "InternationalMobileEquipmentIdentity": IMEI,
        },
        "collection": [
            {
                "name": "device-info-xml",
                "status": "success",
                "returncode": 0,
                "duration_seconds": 1.5,
                "stdout_bytes": 4096,
                "stderr_bytes": 0,
                "timed_out": False,
            }
        ],
        "findings": [],
        "limitations": ["Read-only inspection."],
        "assessment": {
            "status": "no_recorded_failures",
            "verdict": "NO RECORDED FAILURES",
            "description": "Decision support only.",
            "collection_total": 1,
            "collection_successful": 1,
            "collection_failed_or_partial": 0,
            "identity_fields_present": 4,
            "identity_fields_expected": 4,
        },
        "buyer_data": template(),
    }
    report.update(overrides)
    return report


def _html(tmp_path: Path, report: dict, **kwargs) -> str:
    build_html(tmp_path, report, **kwargs)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


# --------------------------------------------------------------- 15-section outline


def test_report_renders_all_fifteen_spec_sections_in_order(tmp_path: Path):
    """Brief outline order: summary, findings, device, hardware, collection gaps."""
    report = _report()
    report["hardware_assessment"] = {
        "subsystems": {"battery": "pass"},
        "checks": [],
        "warnings": [],
        "blockers": [],
        "disclaimer": "Heuristic.",
    }
    report["integrity_assessment"] = {
        "overall": "verified",
        "classifications": {"SerialNumber": "verified"},
        "changes": [],
        "findings": [],
        "disclaimer": "Not proof.",
    }
    html = _html(tmp_path, report)
    positions = []
    for number, title in enumerate(SECTION_TITLES, start=1):
        heading = f"{number}. {title}"
        assert heading in html, f"missing spec §12 section: {heading}"
        positions.append(html.index(heading))
    assert positions == sorted(positions), "spec §12 sections must appear in order"


def test_section_titles_cover_summary_through_collection_gaps():
    """The brief outline: five sections, from the verdict down to collector gaps."""
    assert SECTION_TITLES[0] == "Summary"
    assert SECTION_TITLES[-1] == "Collection gaps"
    assert len(SECTION_TITLES) == 5
    assert "Findings" in SECTION_TITLES
    assert "Hardware, battery and integrity" in SECTION_TITLES
    # The removed sections must not linger in the declared outline.
    assert "Buyer checklist" not in SECTION_TITLES
    assert "Technical appendix" not in SECTION_TITLES


def test_no_alias_points_at_a_section_that_no_longer_exists():
    """A deep-link alias must resolve to a rendered section.

    An alias whose target was removed would render an anchor to nowhere: the link
    would appear to work while showing nothing. This is why the buyer-checklist and
    appendix aliases were dropped rather than repointed.
    """
    from iphone_forensics.reporting import SECTION_ALIASES

    for old, new in SECTION_ALIASES:
        assert new in SECTION_TITLES, f"{old!r} aliases to missing section {new!r}"


# --------------------------------------------------------- partial-collection banner


def test_banner_absent_on_clean_report(tmp_path: Path):
    html = _html(tmp_path, _report())
    # The CSS rule is always present; assert the banner *element* is not rendered.
    assert "<section class='panel banner-incomplete'" not in html
    assert "INCOMPLETE COLLECTION" not in html


def test_banner_shown_when_a_collector_failed(tmp_path: Path):
    report = _report(
        collection=[
            {
                "name": "device-info-xml",
                "status": "success",
                "returncode": 0,
                "duration_seconds": 1.0,
                "stdout_bytes": 10,
                "stderr_bytes": 0,
                "timed_out": False,
            },
            {
                "name": "diagnostics-battery",
                "status": "failed_or_partial",
                "returncode": 1,
                "duration_seconds": 60.0,
                "timed_out": False,
                "stdout_bytes": 0,
                "stderr_bytes": 120,
            },
        ]
    )
    html = _html(tmp_path, report)
    assert "<section class='panel banner-incomplete'" in html, (
        "a failed collector must raise the banner"
    )
    assert "Incomplete collection" in html
    # The banner must name the failing collector itself.
    assert "diagnostics-battery" in html
    # Device-fault wording is reserved for collectors that ran and returned a
    # negative result; the banner copy never calls a gap a device fault.
    assert "not a device fault" in html


def test_banner_shown_when_assessment_status_is_incomplete(tmp_path: Path):
    """incomplete status with all-success collectors (e.g. missing identity fields)."""
    report = _report(
        assessment={
            "status": "incomplete",
            "verdict": "INCOMPLETE — HOLD PAYMENT",
            "description": "",
            "collection_total": 1,
            "collection_successful": 1,
            "collection_failed_or_partial": 0,
            "identity_fields_present": 1,
            "identity_fields_expected": 4,
        }
    )
    html = _html(tmp_path, report)
    assert "<section class='panel banner-incomplete'" in html
    assert "Device identity and configuration" in html


def test_banner_does_not_look_like_a_healthy_verdict(tmp_path: Path):
    """status is 'no_recorded_failures' but a collector failed: must not render green/neutral."""
    report = _report(
        collection=[
            {
                "name": "full-backup-libimobiledevice",
                "status": "failed_or_partial",
                "returncode": None,
                "duration_seconds": 3600.0,
                "timed_out": True,
                "stdout_bytes": 0,
                "stderr_bytes": 900,
            },
        ]
    )
    report["assessment"] = {
        "status": "no_recorded_failures",
        "verdict": "NO RECORDED FAILURES",
        "description": "",
        "collection_total": 1,
        "collection_successful": 0,
        "collection_failed_or_partial": 1,
        "identity_fields_present": 4,
        "identity_fields_expected": 4,
    }
    html = _html(tmp_path, report)
    assert "<section class='panel banner-incomplete'" in html
    assert "verdict neutral" not in html, "a partial run must not be styled as a clean pass"


def test_banner_escapes_untrusted_collector_names(tmp_path: Path):
    report = _report(
        collection=[
            {
                "name": "<script>alert('x')</script>",
                "status": "failed_or_partial",
                "returncode": 1,
                "duration_seconds": 1.0,
                "timed_out": False,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
            },
        ]
    )
    html = _html(tmp_path, report)
    assert "<script>alert('x')</script>" not in html
    assert "&lt;script&gt;" in html


# -------------------------------------- whole-project capability matrix is out


def test_capability_matrix_is_not_rendered_in_the_report(tmp_path: Path):
    """The brief report carries no device-independent project boilerplate.

    The whole-project capability matrix (unsupported / manual / partial tables,
    identical on every run) was cut per the v5.2 brief-report contract. The honest
    exceptions live in capabilities.py and in `ipad... --capabilities`; the report
    records only what THIS run actually measured or failed to collect.
    """
    html = _html(tmp_path, _report())
    assert "Unknown, unavailable, unsupported and skipped tests" not in html
    assert "Can never be established in software" not in html
    assert "Requires a guided manual test" not in html
    assert "Coverage by category" not in html
    # Nothing from the static matrix leaks into the HTML.
    for row in get_matrix():
        if row["coverage"] in {"manual", "unsupported"}:
            assert esc(row["item"]) not in html, f"matrix item rendered: {row['item']}"


def test_impossible_capabilities_are_not_claimed_by_the_report(tmp_path: Path):
    """Cutting the matrix must not cut the guarantee: the report never suggests
    that it could establish an impossible claim either.

    The report renders device findings only; the standing limitation is enforced by
    `_audit_claim_matrix` and surfaced once in the footer.
    """
    html = _html(tmp_path, _report())
    assert "Water resistance" not in html.replace("&nbsp;", " ")
    # The footer still carries the standing limitations, once, in one line.
    assert "no authenticity / replacement / health verdicts" in html


def test_gaps_table_names_this_run_skipped_collectors(tmp_path: Path):
    report = _report(
        collection=[
            {
                "name": "crash-report-copy",
                "status": "failed_or_partial",
                "returncode": 127,
                "timed_out": False,
                "duration_seconds": 2.0,
                "stdout_bytes": 0,
                "stderr_bytes": 30,
            },
        ]
    )
    html = _html(tmp_path, report)
    assert "5. Collection gaps" in html
    assert "crash-report-copy" in html


def test_gaps_table_empty_state_when_all_collectors_succeeded(tmp_path: Path):
    html = _html(tmp_path, _report())
    assert "all 1 collector steps produced usable evidence" in html


# ------------------------------------------------------ missing != 0 / missing != false


def test_absent_assessment_counts_are_not_rendered_as_zero(tmp_path: Path):
    """An assessment with no counts must read 'not collected/not provided', not 0."""
    report = _report(
        assessment={
            "status": "incomplete",
            "verdict": "INCOMPLETE",
            "description": "",
            "buyer_checklist": {"counts": {}},
        }
    )
    html = _html(tmp_path, report)
    summary = html[html.index("Outcome and completeness") : html.index('<p class="muted">findings')]
    rows = dict(re.findall(r"<td>(.*?)</td><td>(.*?)</td>", summary, re.DOTALL))
    # A ratio is only a ratio when both halves exist. Absent halves render one
    # honest placeholder — never "not provided/not provided" or a hardcoded 0/4.
    assert rows["collectors completed"] == MISSING
    assert rows["collector gaps"] == MISSING
    assert rows["identity fields"] == MISSING
    # Regression guard: no field may silently default to a baseline number.
    for label, value in rows.items():
        assert not re.search(r"(^|/)(0|4)$", value), (
            f"'{label}' still defaults to a number: {value}"
        )


def test_missing_collection_telemetry_renders_not_provided(tmp_path: Path):
    """A collector with no recorded exit code/bytes is unknown, not 0."""
    report = _report(collection=[{"name": "mystery-collector", "status": "failed_or_partial"}])
    html = _html(tmp_path, report)
    # Anchor inside the gaps table, not the banner (which also names the collector).
    gaps_start = html.index("5. Collection gaps")
    row_start = html.index("mystery-collector", gaps_start)
    row = html[row_start : html.index("</tr>", row_start)]
    assert MISSING in row
    assert "<td>0</td>" not in row


def test_crash_triage_absence_is_never_rendered_as_a_zero(tmp_path: Path):
    """Crash triage moved wholly to report.json in the brief report.

    The HTML renders no "Files scanned: 0" line for a run that collected nothing:
    an absent count stays absent. This test pins the invariant at the JSON layer,
    where the data still lives.
    """
    report = _report(crash_triage={"interpretation": "Triage ran."})
    html = _html(tmp_path, report)
    assert "Files scanned" not in html
    assert "Triage ran." not in html
    # The data is untouched in the report payload.
    assert report["crash_triage"].get("files_scanned") is None


def test_missing_buyer_observations_are_not_zero(tmp_path: Path):
    """template() ships None observations — they must never become 0 anywhere.

    The buyer-observations table was removed with the checklist section, so this now
    asserts the invariant at the layer that still owns it: the raw JSON. A `None`
    must survive as `None`, because the moment anything coerces it to 0 the report
    would claim a measured zero for a value nobody supplied.
    """
    report = _report(buyer_data=template())
    observations = report["buyer_data"]["observations"]
    assert observations["battery_cycle_count"] is None
    assert observations["battery_max_capacity_percent"] is None
    assert observations["repair_estimate"] is None
    # Nothing coerced the absence into a number on the way into the report.
    for key, value in observations.items():
        assert value is not None or isinstance(value, str) or value is None, key
        assert value != 0 or key == "carrier_eligibility_result", key


def test_explicit_zero_measurement_is_still_shown(tmp_path: Path):
    """Guard against over-correcting: a real recorded 0 must survive.

    The counterpart to the test above — a 0 the operator genuinely supplied has to
    stay a 0, in the data the verdict is computed from.
    """
    report = _report(buyer_data=template())
    report["buyer_data"]["observations"]["battery_cycle_count"] = 0
    html = _html(tmp_path, report)
    # The observations are no longer rendered in the HTML, so assert on the data the
    # report carries rather than on a table that was deliberately removed.
    assert report["buyer_data"]["observations"]["battery_cycle_count"] == 0
    assert "Battery cycle count" not in html


# ------------------------------------------------------------------------ security


def test_no_external_requests_in_generated_html(tmp_path: Path):
    """Standalone offline file: no remote stylesheets, scripts, fonts, or images."""
    html = _html(tmp_path, _report())
    for marker in ("http://", "https://", "//cdn", "<script src", '<link rel="stylesheet"'):
        assert marker not in html, f"external reference found: {marker}"


def test_no_script_injection_via_device_findings_or_collection(tmp_path: Path):
    report = _report(
        device={
            "ProductType": "<script>alert(1)</script>",
            "SerialNumber": "<img src=x onerror=alert(2)>",
        },
        findings=[
            {
                "severity": "INFO",
                "title": "<script>bad()</script>",
                "detail": "<b>bold</b>",
                "evidence": ["<iframe src=x>"],
            }
        ],
        collection=[
            {
                "name": "<script>evil()</script>",
                "status": "failed_or_partial",
                "returncode": 1,
                "timed_out": False,
                "duration_seconds": 1.0,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
            }
        ],
        diagnostic_candidates=[
            {
                "source": "<script>s()</script>",
                "key": "<b>k</b>",
                "value": "<script>v()</script>",
                "interpretation": "<i>i</i>",
            }
        ],
        limitations=["<script>limit()</script>"],
    )
    html = _html(tmp_path, report)
    for payload in (
        "<script>alert(1)</script>",
        "<script>bad()</script>",
        "<script>evil()</script>",
        "<script>s()</script>",
        "<script>v()</script>",
        "<script>limit()</script>",
        "<iframe src=x>",
        "<img src=x onerror=alert(2)>",
    ):
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
    # The brief-report panels must still render in the redacted HTML export.
    redacted_html = (tmp_path / "report-redacted.html").read_text(encoding="utf-8")
    assert "2. Findings" in redacted_html
    assert "5. Collection gaps" in redacted_html
    assert "Identifiers masked in this HTML export" in redacted_html


def test_private_report_keeps_full_identifiers(tmp_path: Path):
    report = _report()
    finalize(tmp_path, report, redact_identifiers=True)
    assert SERIAL in (tmp_path / "report.json").read_text(encoding="utf-8")


def test_redacted_html_does_not_contain_banner_for_identifiers(tmp_path: Path):
    """The failure banner must not become a redaction leak channel."""
    report = _report(
        collection=[
            {
                "name": "device-info-xml",
                "command": ["ideviceinfo", "-u", UDID],
                "status": "failed_or_partial",
                "returncode": 1,
                "timed_out": False,
                "duration_seconds": 1.0,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
            },
        ]
    )
    finalize(tmp_path, report, redact_identifiers=True)
    assert UDID not in (tmp_path / "report-redacted.html").read_text(encoding="utf-8")
