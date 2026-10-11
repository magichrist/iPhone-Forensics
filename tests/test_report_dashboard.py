"""v5 dashboard, inline-SVG charts, and HTML validator (docs/v5/04-html-report.md).

Covers:
  1. Dashboard counts equal a fresh recomputation from report.json.
  2. No data -> no chart, and honest "not collected" copy instead.
  3. Malicious device/finding strings are escaped in the dashboard and charts.
  4. The rendered report contains no external (http/CDN) references.
  5. The validator is clean on a full fixture and flags a broken evidence link.

Offline only: no device, no network, no toolchain.
"""
from __future__ import annotations

import re
from pathlib import Path

from iphone_forensics.buyer import template
from iphone_forensics.reporting import (
    NOT_COLLECTED,
    OUTCOME_BUCKETS,
    build_html,
    dashboard_counts,
    finalize,
    validate_report_html,
)

# --------------------------------------------------------------------- fixtures

FULL_REPORT: dict = {
    "version": "5.0.0",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:05:00+00:00",
    "host": {"platform": "test", "python": "3.14", "architecture": "arm64"},
    "tools": {"ideviceinfo": "/usr/bin/ideviceinfo"},
    "device": {"ProductType": "iPhone15,4", "ProductVersion": "18.1", "BuildVersion": "22B83",
               "ModelNumber": "MU2Y3", "SerialNumber": "SERIALTOPSECRET1234"},
    "collection": [
        {"name": "device-info-xml", "status": "collected", "returncode": 0, "duration_seconds": 1.5,
         "stdout_bytes": 4096, "stderr_bytes": 0, "timed_out": False},
        {"name": "diagnostics-battery", "status": "passed", "returncode": 0, "duration_seconds": 2.0,
         "stdout_bytes": 900, "stderr_bytes": 0, "timed_out": False},
        {"name": "crash-reports", "status": "permission_denied", "returncode": None,
         "duration_seconds": 0.2, "stdout_bytes": 0, "stderr_bytes": 12, "timed_out": False},
    ],
    "findings": [
        {"severity": "BLOCKER", "title": "Activation Lock is active", "detail": "Seller must erase.",
         "evidence": ["raw/device-info.xml"]},
        {"severity": "WARNING", "title": "Battery cycle count is high", "detail": "612 cycles.",
         "evidence": []},
        {"severity": "REVIEW", "title": "Storage capacity not independently confirmed", "detail": "",
         "evidence": []},
        {"severity": "INFO", "title": "Model matches advertised tier", "detail": "", "evidence": []},
    ],
    "limitations": ["Read-only inspection."],
    "assessment": {"status": "incomplete", "verdict": "INCOMPLETE — HOLD PAYMENT",
                   "description": "Evidence gaps remain.", "collection_total": 3,
                   "collection_successful": 2, "collection_failed_or_partial": 1,
                   "identity_fields_present": 5, "identity_fields_expected": 6},
    "buyer_data": template(),
    "hardware_assessment": {
        "subsystems": {"battery": "pass_with_warnings", "storage": "pass"},
        "checks": [
            {"subsystem": "battery", "question": "Battery cycle count", "status": "pass_with_warnings",
             "measurement": 612, "measurement_unit": "cycles", "severity": "REVIEW"},
            {"subsystem": "battery", "question": "Battery maximum capacity", "status": "inconclusive",
             "measurement": None, "severity": "INFO"},
            {"subsystem": "storage", "question": "Total physical storage capacity",
             "status": "pass", "measurement": 128.0, "measurement_unit": "decimal GB",
             "severity": "INFO"},
            {"subsystem": "storage", "question": "Usable data capacity", "status": "not_tested",
             "measurement": None, "severity": "INFO"},
        ],
        "warnings": [], "blockers": [], "disclaimer": "Heuristic, not proof.",
    },
    "integrity_assessment": {"overall": "consistent", "classifications": {"SerialNumber": "consistent"},
                             "changes": [], "disclaimer": "Not proof of authenticity."},
}

EMPTY_REPORT: dict = {
    "version": "5.0.0",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:05:00+00:00",
    "host": {},
    "device": {},
    "collection": [],
    "findings": [],
    "tools": {},
    "limitations": [],
    "assessment": {},
    "buyer_data": template(),
}


def _render(tmp_path: Path, report: dict, **kwargs) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    build_html(tmp_path, report, **kwargs)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


def _copy(report: dict) -> dict:
    """Shallow-copied fixture so a test can mutate it without cross-test leakage."""
    return {**report, "device": dict(report.get("device", {}))}


# ---------------------------------------------------- dashboard counts recompute

def test_dashboard_counts_match_recomputation(tmp_path: Path):
    """Rendered dashboard numbers must equal a fresh recomputation from the report."""
    report = _copy(FULL_REPORT)
    expected = dashboard_counts(report)

    # The fixture is internally consistent: every check and collector is bucketed once.
    assert sum(expected[bucket] for bucket in OUTCOME_BUCKETS) == expected["checks_performed"]
    # 4 hardware checks (pass_with_warnings, inconclusive, pass, not_tested) plus
    # 3 collectors (collected, passed, permission_denied).
    assert expected == {"passed": 3, "warning": 1, "failed": 0, "inconclusive": 1,
                        "unsupported": 0, "skipped": 2, "checks_performed": 7}

    html = _render(tmp_path, report)
    for bucket in OUTCOME_BUCKETS:
        match = re.search(rf"data-dash-key='{bucket}' data-dash-count='(\d+)'", html)
        assert match, f"dashboard did not render a count for {bucket}"
        assert int(match.group(1)) == expected[bucket], (
            f"{bucket}: HTML {match.group(1)} != recomputed {expected[bucket]}")
    performed = re.search(r"data-dash-key='checks_performed' data-dash-count='(\d+)'", html)
    assert performed and int(performed.group(1)) == expected["checks_performed"]


def test_dashboard_counts_property_across_report_shapes(tmp_path: Path):
    """Counts track the report for varied shapes, including empty and junk input."""
    cases = [
        _copy(FULL_REPORT),
        _copy(EMPTY_REPORT),
        _copy({**EMPTY_REPORT, "collection": [{"name": "x", "status": "totally_unknown"}]}),
        _copy({**EMPTY_REPORT, "collection": [{"name": "x", "status": None}, "junk"]}),
        _copy({**EMPTY_REPORT, "hardware_assessment": {"checks": [{"status": "weird"}, {}]}}),
    ]
    for index, report in enumerate(cases):
        html = _render(tmp_path / f"case{index}", report)
        expected = dashboard_counts(report)
        for bucket in OUTCOME_BUCKETS:
            match = re.search(rf"data-dash-key='{bucket}' data-dash-count='(\d+)'", html)
            assert match, f"case {index}: missing count for {bucket}"
            assert int(match.group(1)) == expected[bucket], f"case {index}: {bucket} drifted"


def test_unknown_status_never_counts_as_passed(tmp_path: Path):
    """An unrecognized or missing status must never inflate the passed bucket."""
    report = _copy({**EMPTY_REPORT,
                    "collection": [{"name": "a", "status": "mystery"},
                                   {"name": "b", "status": ""},
                                   {"name": "c", "status": None}]})
    counts = dashboard_counts(report)
    assert counts["passed"] == 0
    assert counts["checks_performed"] == 3
    assert counts["inconclusive"] == 3


def test_dashboard_shows_measured_metrics_only_when_present(tmp_path: Path):
    """Battery/storage numbers appear when measured and vanish when they are not."""
    report = _copy(FULL_REPORT)
    html = _render(tmp_path, report)
    assert "612" in html and "cycles" in html, "a genuinely measured metric must be shown"
    assert "128" in html and "decimal GB" in html

    stripped = _copy({**EMPTY_REPORT,
                      "hardware_assessment": {"subsystems": {}, "checks": [
                          {"subsystem": "battery", "question": "Cycle count",
                           "status": "not_tested", "measurement": None}]}})
    html2 = _render(tmp_path / "stripped", stripped)
    assert f"Battery / storage metrics: {NOT_COLLECTED}" in html2
    assert "Absent metrics are unknown, not normal" in html2


def test_top_issues_prefer_blocker_and_warning(tmp_path: Path):
    report = _copy(FULL_REPORT)
    html = _render(tmp_path, report)
    block = html.index("Activation Lock is active")
    warning = html.index("Battery cycle count is high")
    review = html.index("Storage capacity not independently confirmed")
    assert block < warning < review, "top issues must be ordered by severity"

    # Scope to the top-issues block itself: INFO findings belong in §11, not here.
    issues_block = html.split("Top issues to resolve before purchase")[1].split("</table>")[0]
    assert "Model matches advertised tier" not in issues_block, \
        "INFO findings are not issues"


# ------------------------------------------------------------- no data, no chart

def test_empty_report_renders_no_charts(tmp_path: Path):
    """An empty report must not draw charts or imply a clean result."""
    html = _render(tmp_path, _copy(EMPTY_REPORT))
    assert "<svg" not in html, "no data must mean no chart"
    assert "not collected" in html
    assert "No checks were performed and no collectors were recorded" in html
    assert "absence of data, not a pass" in html
    # A zero-run must not read as a device with no problems.
    assert "Top issues: none recorded" in html
    assert "not a clean bill of health" in html


def test_empty_report_shows_not_collected_for_every_bucket(tmp_path: Path):
    report = _copy(EMPTY_REPORT)
    html = _render(tmp_path, report)
    assert dashboard_counts(report)["checks_performed"] == 0
    for bucket in OUTCOME_BUCKETS:
        pattern = rf"data-dash-key='{bucket}' data-dash-count='0'>{NOT_COLLECTED}<"
        assert re.search(pattern, html), f"{bucket} must display '{NOT_COLLECTED}', not 0"


def test_no_invented_percentages_or_health_scores(tmp_path: Path):
    """Coverage must never be dressed up as a health or genuineness percentage."""
    html = _render(tmp_path, _copy(FULL_REPORT))
    assert "Coverage is not health" in html
    for marker in ("health%", "genuine%", "authenticity score", "trust score"):
        assert marker not in html.lower(), f"invented score rendered: {marker}"
    # Check rendered copy only: the stylesheet legitimately contains CSS widths.
    body = re.sub(r"<style.*?</style>", "", html, flags=re.DOTALL)
    assert re.search(r"\d+\s*%", body) is None, "no percentage may be rendered at all"


# ------------------------------------------------------------------- escaping

def test_malicious_strings_escaped_in_dashboard_and_charts(tmp_path: Path):
    report = _copy({
        **EMPTY_REPORT,
        "device": {"ProductType": "<script>alert('model')</script>",
                   "ProductVersion": "<img src=x onerror=alert('ios')>",
                   "BuildVersion": "\"><svg onload=alert('build')>"},
        "findings": [{"severity": "BLOCKER", "title": "<script>alert('title')</script>",
                      "detail": "<b>d</b>", "evidence": ["<iframe src=x>"]},
                     {"severity": "WARNING", "title": "<script>alert('warn')</script>",
                      "detail": "", "evidence": []}],
        "collection": [{"name": "<script>alert('collector')</script>", "status": "collected",
                        "returncode": 0, "duration_seconds": 1.0, "stdout_bytes": 1,
                        "stderr_bytes": 0}],
        "limitations": ["<script>alert('limit')</script>"],
    })
    html = _render(tmp_path, report)

    for payload in ("<script>alert('model')</script>", "<script>alert('ios')</script>",
                    "<script>alert('build')</script>", "<script>alert('title')</script>",
                    "<script>alert('warn')</script>", "<script>alert('collector')</script>",
                    "<script>alert('limit')</script>", "<iframe src=x>",
                    "<img src=x onerror=alert('ios')>", "<svg onload=alert('build')>"):
        assert payload not in html, f"unescaped payload leaked: {payload}"
    assert "&lt;script&gt;" in html

    # The payload-bearing text must still be present, escaped, inside the dashboard.
    dashboard = html.split("Executive dashboard")[1]
    assert "&lt;script&gt;alert(&#x27;title&#x27;)&lt;/script&gt;" in dashboard or \
           "&lt;script&gt;alert('title')&lt;/script&gt;" in dashboard


def test_malicious_strings_in_chart_labels_are_escaped(tmp_path: Path):
    """Chart labels come from report data and must be escaped like any other text."""
    report = _copy({**EMPTY_REPORT,
                    "findings": [{"severity": "WARNING",
                                  "title": "</text><script>alert(1)</script>",
                                  "detail": "", "evidence": []}]})
    html = _render(tmp_path, report)
    assert "</text><script>" not in html
    assert "<script>alert(1)</script>" not in html


# ----------------------------------------------------------------- offline-safe

def test_output_contains_no_external_references(tmp_path: Path):
    """Standalone file: no remote CSS, scripts, fonts, images, or CDN references."""
    for label, report in (("full", _copy(FULL_REPORT)), ("empty", _copy(EMPTY_REPORT))):
        html = _render(tmp_path / label, report)
        for marker in ("http://", "https://", "//cdn", "<script src", "<script>",
                       "<link rel=\"stylesheet\"", "@import", "srcset="):
            assert marker not in html, f"[{label}] external reference: {marker}"


def test_charts_carry_no_scripting(tmp_path: Path):
    html = _render(tmp_path, _copy(FULL_REPORT))
    assert "<svg" in html, "the full fixture should render charts"
    svg_blocks = re.findall(r"<svg.*?</svg>", html, flags=re.DOTALL)
    assert svg_blocks, "expected at least one inline SVG chart"
    for block in svg_blocks:
        lowered = block.lower()
        assert "javascript" not in lowered
        assert "href" not in lowered
        assert "<script" not in lowered
        # Numbers belong in attributes only; labels are escaped text.
        assert "onload=" not in lowered and "onclick=" not in lowered


def test_every_chart_has_a_text_table_equivalent(tmp_path: Path):
    """Print and screen-reader users need the numbers without the graphic."""
    html = _render(tmp_path, _copy(FULL_REPORT))
    for heading in ("Check outcomes", "Findings by severity", "Collector success"):
        panel = html.split(f"<h3>{heading}</h3>")[1].split("</section>")[0]
        assert "<table>" in panel, f"chart panel '{heading}' needs a text table equivalent"


# -------------------------------------------------------------------- validator

def test_validator_clean_on_full_fixture(tmp_path: Path):
    report = _copy(FULL_REPORT)
    assert validate_report_html(_render(tmp_path, report), report) == []


def test_validator_clean_on_empty_fixture(tmp_path: Path):
    report = _copy(EMPTY_REPORT)
    assert validate_report_html(_render(tmp_path, report), report) == []


def test_validator_flags_unclosed_tag():
    broken = "<html><body><div><p>text</p></body></html>"
    errors = validate_report_html(broken, _copy(EMPTY_REPORT))
    assert any("unclosed tag <div>" in error for error in errors), errors


def test_validator_flags_stray_closing_tag():
    broken = "<html><body></div></body></html>"
    errors = validate_report_html(broken, _copy(EMPTY_REPORT))
    assert any("stray closing tag </div>" in error for error in errors), errors


def test_validator_flags_broken_evidence_link():
    """A link to an artifact the report never recorded is a validation failure."""
    report = _copy(FULL_REPORT)
    html = ("<html><body>"
            "<a href='raw/device-info.xml'>real</a>"
            "<a href='raw/ghost-artifact.bin'>invented</a>"
            "</body></html>")
    errors = validate_report_html(html, report)
    assert any("evidence link not found in report: raw/ghost-artifact.bin" in e for e in errors), errors
    assert not any("raw/device-info.xml" in e for e in errors), "a real link must not be flagged"


def test_validator_flags_count_mismatch(tmp_path: Path):
    """Counts in the HTML that disagree with report.json must be reported."""
    report = _copy(FULL_REPORT)
    html = _render(tmp_path, report)
    expected = dashboard_counts(report)
    tampered = html.replace(f"data-dash-key='passed' data-dash-count='{expected['passed']}'",
                            f"data-dash-key='passed' data-dash-count='{expected['passed'] + 5}'")
    assert tampered != html, "tamper did not apply"
    errors = validate_report_html(tampered, report)
    assert any("dashboard count mismatch for passed" in e for e in errors), errors


def test_validator_never_raises_on_junk_input():
    """Validation must not break report generation, whatever it is handed."""
    for junk in ("", "<", "<html", "<<<>>>", "\x00\x01", "<a href=>"):
        assert isinstance(validate_report_html(junk, {}), list)
        assert isinstance(validate_report_html(junk, {"findings": None, "collection": 5}), list)


def test_build_html_embeds_validation_comment(tmp_path: Path):
    report = _copy(FULL_REPORT)
    html = _render(tmp_path, report)
    assert "<!-- report-validation: clean -->" in html

    broken = _copy({**EMPTY_REPORT, "device": {}, "findings": [], "collection": [],
                    "hardware_assessment": {"checks": [{"status": "pass", "subsystem": "battery"}]}})
    # Force a mismatch by validating a hand-mutated document.
    rendered = _render(tmp_path / "mismatch", broken)
    assert "report-validation:" in rendered


# ------------------------------------------------------------------ redaction

def test_redacted_export_still_contains_no_identifiers(tmp_path: Path):
    report = _copy(FULL_REPORT)
    finalize(tmp_path, report, redact_identifiers=True)
    redacted_html = (tmp_path / "report-redacted.html").read_text(encoding="utf-8")
    assert "SERIALTOPSECRET1234" not in redacted_html
    assert "Executive dashboard" in redacted_html, "the dashboard must survive redaction"
    assert "report-validation:" in redacted_html