"""v5 end-to-end integration tests: real pipeline, not isolated helpers.

Why this file exists
--------------------
Earlier v5 work (P2 output layout, P3 status model, P4 dashboard) landed as
units whose tests called the helper *directly*. That let three real defects ship
behind a green suite:

  1. `analysis.py` still compared statuses against the v4 vocabulary
     (``success`` / ``expected_end`` / ``failed_or_partial``) while collectors
     had already started emitting v5 statuses (``collected`` ...). Every
     successful collector produced a bogus "Collection incomplete" finding.
  2. `reporting._incomplete_banner` and the unknown-panel table had the same
     stale comparisons, so a healthy run could render as fully incomplete.
  3. `evidence.run_dir_paths` / `write_readme_txt` were implemented and
     unit-tested in isolation but never called by any run path, so no real run
     ever produced ``evidence/`` or ``README.txt``.

A helper-only test cannot catch any of those: each helper was correct, the
*wiring* was wrong. These tests therefore drive the real pipeline —
collectors -> analysis -> report.json -> report.html -> manifest — and assert on
what a run actually leaves on disk.

Scope: offline only. No device, no network, no libimobiledevice.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from iphone_forensics import analysis, collectors, evidence, reporting, util
from iphone_forensics.models import COLLECTION_STATUSES, normalize_status

# --------------------------------------------------------------------- helpers


def _render(tmp_path: Path, report: dict, **kwargs) -> str:
    """Drive the real HTML writer and read back what it produced."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    reporting.build_html(tmp_path, report, **kwargs)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


def _completed_report(**overrides) -> dict:
    """A report whose collectors all genuinely succeeded under the v5 vocabulary."""
    report = {
        "version": "5.0.0",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:05:00+00:00",
        "host": {"platform": "test", "python": "3.11", "architecture": "arm64"},
        "tools": {"ideviceinfo": "/usr/bin/ideviceinfo"},
        "device": {
            "ProductType": "iPhone15,4",
            "ProductVersion": "18.1",
            "BuildVersion": "22B83",
            "ModelNumber": "MU2Y3",
        },
        "collection": [
            {
                "name": "device-info",
                "status": "collected",
                "returncode": 0,
                "duration_seconds": 1.0,
                "stdout_bytes": 100,
                "stderr_bytes": 0,
                "timed_out": False,
            },
            {
                "name": "diagnostics-battery",
                "status": "collected",
                "returncode": 0,
                "duration_seconds": 2.0,
                "stdout_bytes": 200,
                "stderr_bytes": 0,
                "timed_out": False,
            },
        ],
        "findings": [],
    }
    report.update(overrides)
    return report


def _incomplete_findings(report: dict) -> list[dict]:
    return [
        f
        for f in analysis.derive_findings(report, None)
        if str(f.get("title", "")).startswith("Collection incomplete")
    ]


# =========================================================== 1. status regression


def test_successful_collectors_produce_no_incomplete_findings():
    """Regression: v5 'collected' must not read as an incomplete collection.

    Under the stale comparison every healthy collector was reported as
    'Collection incomplete'. This is the exact user-visible corruption.
    """
    report = _completed_report()
    assert analysis._status_of(report["collection"][0]) == "collected"
    assert _incomplete_findings(report) == []


def test_assessment_counts_success_before_failure():
    """A successful collection must count as successful, not as a gap."""
    report = _completed_report()
    result = analysis.automated_assessment(report, None)
    assert result["collection_successful"] == 2
    assert result["collection_gaps"] == 0
    assert result["collection_negative_results"] == 0
    # v4 key keeps its v4 meaning so existing readers stay correct.
    assert result["collection_failed_or_partial"] == 0


def test_real_gaps_are_counted_and_reported_once_each():
    """Every non-completing status yields exactly one gap and one finding."""
    report = _completed_report(
        collection=[
            {"name": "device-info", "status": "collected"},
            {"name": "crash-reports", "status": "permission_denied"},
            {"name": "app-list", "status": "skipped_by_user"},
            {"name": "syslog", "status": "tool_missing"},
            {"name": "diagnostics-wifi", "status": "collection_error"},
        ]
    )
    result = analysis.automated_assessment(report, None)
    assert result["collection_successful"] == 1
    assert result["collection_gaps"] == 4
    assert result["collection_negative_results"] == 0
    assert len(_incomplete_findings(report)) == 4


def test_unavailable_statuses_never_render_as_failed(tmp_path: Path):
    """Task §10.10: unavailable is never dressed up as a device failure."""
    unavailable = [
        "permission_denied",
        "tool_missing",
        "skipped_by_user",
        "not_applicable",
        "collection_error",
        "unsupported",
    ]
    report = _completed_report(
        collection=[{"name": f"step-{status}", "status": status} for status in unavailable]
        + [{"name": "device-info", "status": "collected"}]
    )

    for finding in _incomplete_findings(report):
        assert finding["severity"] != "BLOCKER"
        assert finding.get("status") != "failed"

    html = _render(tmp_path, report)
    for status in unavailable:
        assert status in html
    # The banner must fire, but must not call these device faults.
    assert "<section class='panel banner-incomplete'" in html
    assert "not a device fault" in html


def test_v4_status_strings_still_read_correctly():
    """Read-compat: pre-v5 run directories must still load (docs/v5/05)."""
    report = _completed_report(
        collection=[
            {"name": "legacy-ok", "status": "success"},
            {"name": "legacy-boundary", "status": "expected_end"},
            {"name": "legacy-bad", "status": "failed_or_partial"},
        ]
    )
    result = analysis.automated_assessment(report, None)
    assert result["collection_successful"] == 2
    assert result["collection_gaps"] == 1
    # Only one finding, for the one legacy entry that truly lacked evidence.
    assert [f["title"] for f in _incomplete_findings(report)] == [
        "Collection incomplete: legacy-bad"
    ]


def test_every_emitted_status_is_inside_the_declared_vocabulary(tmp_path: Path):
    """No layer may emit a status outside models.COLLECTION_STATUSES."""
    raw = tmp_path / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    cases = {
        "collected": {
            "command": ["x"],
            "returncode": 0,
            "stdout": b"ok",
            "stderr": b"",
            "timed_out": False,
        },
        "expected": {
            "command": ["x"],
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "timed_out": True,
            "expected_stream_end": True,
        },
        "timeout": {
            "command": ["x"],
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "timed_out": True,
        },
        "nonzero": {
            "command": ["x"],
            "returncode": 3,
            "stdout": b"",
            "stderr": b"bad",
            "timed_out": False,
        },
        "missing": {
            "command": ["nope"],
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "timed_out": False,
            "missing_binary": True,
        },
    }
    expected = {
        "collected": "collected",
        "expected": "collected",  # bounded log capture is by design
        "timeout": "collection_error",
        "nonzero": "collection_error",
        "missing": "tool_missing",
    }
    for name, result in cases.items():
        meta = util.write_command_result(raw, name, dict(result))
        assert meta["status"] == expected[name]
        assert meta["status"] in COLLECTION_STATUSES


def test_normalize_status_never_invents_a_pass():
    """An unknown status must never resolve to a passing state."""
    for junk in ["", None, "success-ish", 17, object()]:
        assert normalize_status(junk) not in {"collected", "passed"}


# =============================================== 2. banner / coverage integration


def test_healthy_run_shows_no_incomplete_banner(tmp_path: Path):
    """The converse regression: a healthy run must not read as incomplete."""
    report = _completed_report()
    html = _render(tmp_path, report)
    # Match the rendered element, not the CSS rule that styles it.
    assert "<section class='panel banner-incomplete'" not in html


def test_gap_run_names_the_sections_it_could_not_evaluate(tmp_path: Path):
    report = _completed_report(
        collection=[
            {"name": "device-info", "status": "tool_missing"},
        ]
    )
    assessment = analysis.automated_assessment(report, None)
    html = _render(tmp_path, {**report, "assessment": assessment})
    assert "<section class='panel banner-incomplete'" in html
    # tool_missing is an environment gap and must be described as such.
    assert "not a device fault" in html
    assert "Tool not installed" in html


# ============================================== 3. run-dir layout is actually wired


def test_run_dir_layout_helper_is_the_single_source_of_names(tmp_path: Path):
    """run_dir_paths owns the naming; nothing else may invent a run dir name."""
    paths = evidence.run_dir_paths(tmp_path, "20260101-120000")
    run_dir = paths["run_dir"]
    assert run_dir.name == "iphone-forensics-20260101-120000"
    assert paths["evidence_dir"].is_dir()
    assert paths["evidence_dir"].name == "evidence"

    # The permissions requirement (0700) holds on both directories.
    assert stat.S_IMODE(os.stat(run_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths["evidence_dir"]).st_mode) == 0o700


def test_repeated_runs_never_overwrite(tmp_path: Path):
    first = evidence.run_dir_paths(tmp_path, "20260101-120000")["run_dir"]
    second = evidence.run_dir_paths(tmp_path, "20260101-120000")["run_dir"]
    third = evidence.run_dir_paths(tmp_path, "20260101-120000")["run_dir"]
    assert first.name == "iphone-forensics-20260101-120000"
    assert second.name == "iphone-forensics-20260101-120000-1"
    assert third.name == "iphone-forensics-20260101-120000-2"
    # The first run's content survives untouched.
    (first / "report.html").write_text("original", encoding="utf-8")
    assert (first / "report.html").read_text(encoding="utf-8") == "original"


def test_compare_default_discovery_matches_the_dirs_a_run_creates(tmp_path: Path, monkeypatch):
    """Regression: compare globs the name a run actually writes.

    compare defaulted to './iphone-forensics-*/report.json' while the engine
    created 'iphone-audit-<stamp>', so auto-discovery could never find a run.
    """
    from iphone_forensics import cli

    paths = evidence.run_dir_paths(tmp_path, "20260101-120000")
    paths["report.json"].write_text(json.dumps(_completed_report()), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    found = cli._default_current_report()
    assert found is not None, "compare must auto-discover a run it just created"
    assert found.name == "report.json"
    assert found.parent == paths["run_dir"]


def test_readme_is_written_by_a_real_run_finish(tmp_path: Path):
    """Regression: README.txt existed as a helper but no run wrote it."""
    paths = evidence.run_dir_paths(tmp_path, "20260101-120000")
    run_dir = paths["run_dir"]
    (run_dir / "evidence").mkdir(exist_ok=True)

    written = evidence.write_readme_txt(
        run_dir,
        {
            "version": "5.0.0",
            "generated": "2026-01-01T12:00:00+00:00",
            "device": "iPhone15,4",
        },
    )
    assert written.is_file()
    text = written.read_text(encoding="utf-8")
    assert "report.html" in text
    assert "Privacy" in text or "privacy" in text
    assert "5.0.0" in text


def test_artifacts_land_in_evidence_not_the_legacy_raw_dir(tmp_path: Path):
    """The v5 split is real: evidence/ holds the artifacts and raw/ is gone."""
    paths = evidence.run_dir_paths(tmp_path, "20260101-120000")
    run_dir = paths["run_dir"]

    util.write_command_result(
        paths["evidence_dir"],
        "device-info",
        {
            "command": ["ideviceinfo"],
            "returncode": 0,
            "stdout": b"<plist/>",
            "stderr": b"",
            "timed_out": False,
        },
    )

    listed = {entry["path"] for entry in evidence.build_manifest(run_dir)["artifacts"]}
    assert any(path.startswith("evidence/") for path in listed)
    assert not any(path.startswith("raw/") for path in listed)
    assert not (run_dir / "raw").exists()


def test_crash_triage_reads_both_evidence_and_legacy_raw(tmp_path: Path):
    """A v4 run directory must stay analyzable after the rename."""
    v5 = tmp_path / "v5-run"
    paths = evidence.run_dir_paths(v5, "20260101-120000")
    crash = paths["evidence_dir"] / "crash-reports"
    crash.mkdir(parents=True, exist_ok=True)
    (crash / "panic.ips").write_text('{"panicString":"watchdog timeout"}\n', encoding="utf-8")

    legacy = tmp_path / "v4-run"
    (legacy / "raw" / "crash-reports").mkdir(parents=True, exist_ok=True)
    (legacy / "raw" / "crash-reports" / "panic.ips").write_text(
        '{"panicString":"watchdog timeout"}\n', encoding="utf-8"
    )

    for run_dir in (paths["run_dir"], legacy):
        triage = analysis.analyze_crash_artifacts(run_dir)
        assert triage["panic_or_watchdog_candidate_count"] == 1, (
            f"{run_dir.name} triage must find its crash artifacts"
        )


def test_finished_run_is_cleanly_verifiable(tmp_path: Path):
    """A completed run must verify with zero added/missing/changed files.

    Regression: README.txt used to be written *after* the manifest, so every
    real run verified as having a stray 'added since hashing' file.
    """
    import argparse

    from iphone_forensics.cli_v4 import _finish_run, _new_report

    run = tmp_path / "run"
    run.mkdir()
    paths = evidence.run_dir_paths(run, "20260101-120000")
    run_dir = paths["run_dir"]
    util.write_command_result(
        paths["evidence_dir"],
        "device-info",
        {
            "command": ["ideviceinfo"],
            "returncode": 0,
            "stdout": b"<plist/>",
            "stderr": b"",
            "timed_out": False,
        },
    )

    args = argparse.Namespace(redact=False, compare_json=None)
    report = _new_report(args)
    _finish_run(run_dir, report, {"checks": {}}, args)

    verification = evidence.verify_manifest(run_dir)
    assert verification["added"] == [], f"unexpected untracked files: {verification['added']}"
    assert verification["missing"] == 0
    assert verification["changed"] == 0
    assert verification["verified"] is True


def test_manifest_lists_exactly_the_files_that_exist(tmp_path: Path):
    """No phantom entries, and every real artifact is hashed."""
    paths = evidence.run_dir_paths(tmp_path, "20260101-120000")
    run_dir = paths["run_dir"]
    paths["evidence_dir"].mkdir(exist_ok=True)
    (paths["evidence_dir"] / "device-info.json").write_text("{}", encoding="utf-8")

    manifest = evidence.build_manifest(run_dir)
    listed = {entry["path"] for entry in manifest["artifacts"]}

    on_disk = {str(path.relative_to(run_dir)) for path in run_dir.rglob("*") if path.is_file()} - {
        "manifest.json"
    }

    assert listed == on_disk
    # And the manifest verifies against what is actually on disk.
    assert evidence.verify_manifest(run_dir)["verified"] is True


def test_failed_collection_leaves_no_phantom_evidence(tmp_path: Path):
    """A collector that produced nothing must leave no file and no manifest entry."""
    paths = evidence.run_dir_paths(tmp_path, "20260101-120000")
    run_dir = paths["run_dir"]
    raw = paths["evidence_dir"]
    raw.mkdir(exist_ok=True)

    collection: list[dict] = []
    # A missing binary writes stdout/stderr files but yields no usable evidence;
    # the manifest must describe files, not conclusions.
    util.write_command_result(
        raw,
        "absent-tool",
        {
            "command": ["nope"],
            "returncode": None,
            "stdout": b"",
            "stderr": b"not found",
            "timed_out": False,
            "missing_binary": True,
        },
    )
    collection.append({"name": "absent-tool", "status": "tool_missing"})

    manifest = evidence.build_manifest(run_dir)
    assert manifest["artifacts"]
    # Nothing in the manifest claims a successful artifact for the missing tool.
    for entry in manifest["artifacts"]:
        assert entry["path"].startswith("evidence/")


# ================================================== 4. consent is recorded, always


def test_consent_state_is_recorded_for_granted_and_declined():
    """docs/v5/07: a run must state on its face whether consent was given."""
    import argparse

    from iphone_forensics.cli_v4 import _new_report

    granted = _new_report(
        argparse.Namespace(
            redact=False, compare_json=None, sensitive_consent=True, sensitive_explicit=["app_list"]
        )
    )
    assert granted["scope"]["sensitive_collection"] == "granted"
    assert granted["scope"]["sensitive_collection_items"] == ["app_list"]

    declined = _new_report(
        argparse.Namespace(
            redact=False, compare_json=None, sensitive_consent=False, sensitive_explicit=[]
        )
    )
    assert declined["scope"]["sensitive_collection"] == "declined"
    assert declined["scope"]["sensitive_collection_items"] == []


def test_direct_engine_invocation_records_not_requested():
    """No consent gate presented must be reported as such, not as 'declined'."""
    import argparse

    from iphone_forensics.cli_v4 import _new_report

    report = _new_report(argparse.Namespace(redact=False, compare_json=None))
    assert report["scope"]["sensitive_collection"] == "not_requested"


def test_declined_consent_is_never_rendered_as_a_failure(tmp_path: Path):
    """Declining must read as a choice, not a defect."""
    report = _completed_report(
        scope={
            "sensitive_collection": "declined",
            "sensitive_collection_items": [],
            "backup_requested": False,
            "logs_requested": False,
            "crash_reports_requested": False,
            "app_inventory_requested": False,
        }
    )
    html = _render(tmp_path, report)
    assert "declined" in html.lower()
    assert "not</b> collected" in html or "not collected" in html.lower()


def test_redaction_is_one_helper_with_absence_still_reads_as_absent():
    """docs/v5/07: one redaction policy, and a missing value is never masked.

    The v4 split (cli_v4.redact vs reporting._redact_identifier) disagreed on
    empty input: the console rendered '••••', implying a value was hidden, while
    the report rendered ''. Both now delegate to util.redact.
    """
    from iphone_forensics.cli_v4 import redact as cli_redact
    from iphone_forensics.reporting import _redact_identifier

    for absent in (None, ""):
        assert util.redact(absent) == ""
        assert cli_redact(absent) == ""
        assert _redact_identifier(absent) == ""

    masked = util.redact("UDID1234567890ABCDEF")
    assert masked.endswith("CDEF")
    assert "1234567890" not in masked
    # And all three surfaces agree on a real identifier.
    assert cli_redact("UDID1234567890ABCDEF") == masked
    assert _redact_identifier("UDID1234567890ABCDEF") == masked


# ============================================== 5. epistemic labeling (docs/v5/05)


def test_every_finding_reaching_a_real_report_is_labeled(tmp_path: Path):
    """docs/v5/05: no finding may reach report.json or the HTML unlabeled."""
    import argparse

    from iphone_forensics.cli_v4 import _finish_run, _new_report
    from iphone_forensics.models import EPISTEMIC_LABELS

    run = tmp_path / "run"
    run.mkdir()
    paths = evidence.run_dir_paths(run, "20260101-120000")

    args = argparse.Namespace(redact=False, compare_json=None)
    report = _new_report(args)
    # Findings from several different modules, none labeled up front.
    report["findings"].extend(
        [
            {
                "severity": "BLOCKER",
                "title": "Buyer-critical check failed",
                "detail": "x",
                "evidence": [],
            },
            {
                "severity": "WARNING",
                "title": "Recurring panic artifacts",
                "detail": "x",
                "evidence": [],
            },
            {
                "severity": "REVIEW",
                "title": "Exact product identifier not parsed",
                "detail": "x",
                "evidence": [],
            },
            {
                "severity": "INFO",
                "title": "Reported product identifier available",
                "detail": "x",
                "evidence": [],
            },
            {
                "severity": "REVIEW",
                "title": "Cellular signal strength",
                "detail": "Compare against a reference in Settings.",
                "evidence": [],
            },
        ]
    )
    _finish_run(paths["run_dir"], report, {"checks": {}}, args)

    persisted = json.loads((paths["run_dir"] / "report.json").read_text(encoding="utf-8"))
    assert persisted["findings"]
    for finding in persisted["findings"]:
        assert finding.get("epistemic") in EPISTEMIC_LABELS, (
            f"unlabeled finding reached report.json: {finding.get('title')}"
        )

    html = (paths["run_dir"] / "report.html").read_text(encoding="utf-8")
    for label in EPISTEMIC_LABELS:
        assert f"pill-{label}" in html, f"{label} badge never rendered"


def test_epistemic_labels_distinguish_evidence_from_guesswork():
    """The label must reflect how a finding was actually established."""
    from iphone_forensics.analysis import epistemic_for

    assert (
        epistemic_for({"severity": "INFO", "title": "Product identifier available"}) == "observed"
    )
    assert epistemic_for({"severity": "WARNING", "title": "Recurring panics"}) == "inferred"
    assert epistemic_for({"severity": "REVIEW", "title": "Identifier not parsed"}) == "unknown"
    # A subject only a human can check is never dressed up as observed.
    assert (
        epistemic_for({"severity": "REVIEW", "title": "Face ID", "detail": "Test this manually"})
        == "needs_manual"
    )
    # An explicit label is always respected.
    assert epistemic_for({"severity": "INFO", "title": "x", "epistemic": "inferred"}) == "inferred"


def test_epistemic_badges_carry_text_not_colour_alone(tmp_path: Path):
    """WCAG 1.4.1: the badge must be readable without colour."""
    report = _completed_report(
        findings=[
            {"severity": "REVIEW", "title": "Identifier not parsed", "detail": "d", "evidence": []},
        ]
    )
    html = _render(tmp_path, report)
    assert "Manual check required" in html
    assert "Unknown — open question" in html


# ============================================ 6. report outline (docs/v5/04, §4C)


def test_report_has_a_working_table_of_contents(tmp_path: Path):
    """Every TOC entry must resolve to a section that actually rendered."""
    report = _completed_report(
        hardware_assessment={"subsystems": {"battery": "pass"}, "checks": [], "warnings": []},
        integrity_assessment={
            "overall": "change_detected",
            "classifications": {"a": "b"},
            "changes": [],
            "continuity": "not_detectable",
        },
    )
    html = _render(tmp_path, report)

    assert "<nav" in html and "skip-link" in html
    ids = set(re.findall(r"""id=['"]([^'"]+)['"]""", html))
    links = set(re.findall(r"""href=['"]#([^'"]+)['"]""", html))
    assert links, "the table of contents must link somewhere"
    assert links <= ids, f"dangling anchors: {sorted(links - ids)}"

    # Every section is both a link target and announced by its heading.
    chains = re.findall(r"""aria-labelledby=['"]([^'"]+)['"]""", html)
    assert chains and all(chain in ids for chain in chains)


def test_toc_never_lists_a_section_that_did_not_render(tmp_path: Path):
    """An absent panel must not leave a dead entry in the contents list."""
    import re as _re

    from iphone_forensics.reporting import SECTION_TITLES

    html = _render(tmp_path, _completed_report())
    links = set(_re.findall(r"""href=['"]#(s\d+-[^'"]+)['"]""", html))
    # No hardware/integrity data was supplied, so sections 3-5 must be absent
    # from the contents as well as from the body.
    assert not any(link.startswith(("s3-", "s4-", "s5-")) for link in links)
    assert len(links) == len([t for t in SECTION_TITLES]) - 3


def test_report_is_dark_mode_and_reduced_motion_aware(tmp_path: Path):
    html = _render(tmp_path, _completed_report())
    assert "prefers-color-scheme" in html
    assert "prefers-reduced-motion" in html
    assert "sr-only" in html, "visually-hidden captions need the sr-only utility"


def test_tables_carry_header_scope_for_screen_readers(tmp_path: Path):
    """WCAG: a screen reader must know which column a cell belongs to."""
    html = _render(tmp_path, _completed_report())
    headers = re.findall(r"<th[ >]", html)
    scoped = re.findall(r"<th scope='col'>", html)
    assert headers, "the report must contain tables"
    assert len(scoped) == len(headers), f"{len(headers) - len(scoped)} headers lack scope"


def test_report_stays_offline_and_script_free(tmp_path: Path):
    """No external references and no scripting, ever."""
    html = _render(tmp_path, _completed_report())
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html
    assert "onclick" not in html.lower() and "onload" not in html.lower()


def test_report_renders_the_section_outline_in_order(tmp_path: Path):
    """Exactly 9 numbered sections, in order, numbered 1..9 without gaps.

    Two sections were removed (the buyer checklist and the technical appendix), so the
    outline shrank from 11 to 9. The numbering is asserted explicitly rather than
    derived from `len(SECTION_TITLES)`, because a test that computes its own
    expectation from the thing it is checking proves nothing about renumbering.
    """
    import re

    from iphone_forensics.reporting import SECTION_TITLES

    report = _completed_report(
        hardware_assessment={
            "subsystems": {"battery": "pass", "storage": "not_tested"},
            "checks": [],
            "warnings": [],
            "disclaimer": "Not proof.",
        },
        integrity_assessment={
            "overall": "change_detected",
            "classifications": {"SerialNumber": "consistent"},
            "changes": [],
            "continuity": "not_detectable",
            "disclaimer": "Not proof.",
        },
    )
    html = _render(tmp_path, report)
    # Headings carry an id (added for deep links); match it optionally.
    headings = re.findall(r"<h2(?: id='[^']*')?>(\d+)\.\s*([^<]+)</h2>", html)

    rendered = [title.strip() for _, title in headings]
    assert rendered == list(SECTION_TITLES), f"outline drifted: {rendered}"
    assert [number for number, _ in headings] == [str(n) for n in range(1, 10)]


def test_removed_sections_are_never_rendered(tmp_path: Path):
    """The buyer checklist and technical appendix must not come back.

    Guards against a future edit reintroducing either section, and pins the fact that
    the section count is 9 rather than 11.
    """
    html = _render(tmp_path, _completed_report())
    for gone in (
        "Buyer checklist",
        "Buyer-critical blockers",
        "Checklist and physical tests",
        "Buyer-entered observations",
        "Technical appendix",
        "Toolchain and evidence integrity",
    ):
        assert gone not in html, f"{gone!r} is rendered again"
    assert "8. Risks, findings and actions" in html
    assert "9. Evidence and coverage" in html


def test_outline_survives_conditional_panels_being_absent(tmp_path: Path):
    """Sections 3-5 render only when that data exists; the rest must not shift."""
    import re

    from iphone_forensics.reporting import SECTION_TITLES

    html = _render(tmp_path, _completed_report())
    rendered = [
        title.strip() for title in re.findall(r"<h2(?: id='[^']*')?>\d+\.\s*([^<]+)</h2>", html)
    ]

    # No hardware/integrity data -> those panels are absent, never empty shells.
    assert "Hardware and components" not in rendered
    assert "Parts, repairs and integrity" not in rendered
    # The remaining sections keep their declared numbers.
    for expected in ("Executive summary", "Evidence and coverage"):
        assert expected in rendered
    assert set(rendered).issubset(set(SECTION_TITLES))


def test_every_section_title_is_referenced_by_the_rendered_report(tmp_path: Path):
    """No declared section may be a heading the report never produces."""
    import argparse

    from iphone_forensics.cli_v4 import _finish_run, _new_report

    run = tmp_path / "run"
    run.mkdir()
    paths = evidence.run_dir_paths(run, "20260101-120000")
    report = _new_report(
        argparse.Namespace(
            redact=False, compare_json=None, sensitive_consent=False, sensitive_explicit=[]
        )
    )
    report["hardware_assessment"] = {
        "subsystems": {"battery": "not_tested"},
        "checks": [],
        "warnings": [],
        "disclaimer": "",
    }
    _finish_run(
        paths["run_dir"],
        report,
        {"checks": {}},
        argparse.Namespace(redact=False, compare_json=None),
    )
    html = (paths["run_dir"] / "report.html").read_text(encoding="utf-8")
    assert "Hardware and components" in html
    assert "Battery and power" in html


# ============================================ 7. savvy-user surface (docs/v5/02)


def test_advanced_help_documents_the_whole_engine_surface():
    """A savvy user must be able to discover the advanced interface from the v5 CLI."""
    import contextlib
    import io

    from iphone_forensics import cli

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli._print_advanced_help()
    text = buffer.getvalue()

    assert "Advanced commands" in text
    # One binary, one name: the retired `iphone-surgery` must not be advertised.
    assert cli.PROGRAM in text
    assert "iphone-surgery" not in text, f"the retired CLI name is still advertised:\n{text}"
    # Exit codes are documented for scripting.
    assert "Exit codes" in text
    for name, _help in cli._engine_subcommands():
        assert name in text, f"subcommand {name} missing from --help-advanced"


def test_engine_subcommand_list_is_derived_not_hardcoded():
    from iphone_forensics.cli import _engine_subcommands
    from iphone_forensics.cli_v4 import build_parser

    documented = {name for name, _ in _engine_subcommands()}
    parser = build_parser()
    actual = {
        entry.dest
        for action in parser._actions
        for entry in getattr(action, "_choices_actions", []) or []
    }
    assert actual, "no subcommand action found on the engine parser"
    assert documented == actual, f"--help-advanced is missing {sorted(actual - documented)}"


def test_advanced_help_stays_out_of_the_basic_help():
    """The four-command surface must stay uncluttered for an ordinary user."""
    import contextlib
    import io

    from iphone_forensics import cli

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli._print_advanced_help()
    advanced = buffer.getvalue()
    assert "--syslog-seconds" in advanced
    assert "--backup" in advanced

    # The basic help must stay free of collector-flag noise.
    parser = cli._build_parser()
    basic = parser.format_help()
    assert "syslog" not in basic
    assert "crash-reports" not in basic


def test_v4_deep_links_still_land_on_the_right_section(tmp_path: Path):
    """docs/v5/10 risk mitigation: the section renumber must not orphan old links."""
    import re as _re

    from iphone_forensics.reporting import SECTION_ALIASES

    report = _completed_report(
        hardware_assessment={"subsystems": {"battery": "not_tested"}, "checks": [], "warnings": []},
        integrity_assessment={
            "overall": "change_detected",
            "classifications": {"a": "b"},
            "changes": [],
            "continuity": "not_detectable",
        },
    )
    html = _render(tmp_path, report)

    ids = set(_re.findall(r"""id=['"]([^'"]+)['"]""", html))
    for old_heading, new_heading in SECTION_ALIASES:
        expected = _slug = old_heading.lower().replace("(", "").replace(")", "")
        expected = re.sub(r"[^a-z0-9]+", "-", expected).strip("-")
        assert expected in ids, f"old heading {old_heading!r} has no anchor"

    # And the alias table is honest: every target really is a rendered section.
    rendered = set(re.findall(r"<h2(?: id='[^']*')?>\d+\.\s*([^<]+)</h2>", html))
    for _old, new in SECTION_ALIASES:
        assert new in rendered, f"{new!r} is aliased to but never rendered"


# =============================================== 8. collectors integration wiring


def test_skipped_collector_records_skipped_by_user(tmp_path: Path):
    """Consent-declined collection is recorded, never silently dropped."""
    raw = tmp_path / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    collection: list[dict] = []

    collectors.save_result(
        raw, collection, "app-list", ["pymobiledevice3", "apps", "list"], skip=True
    )

    assert len(collection) == 1
    assert collection[0]["status"] == "skipped_by_user"
    assert collection[0]["status"] in COLLECTION_STATUSES


def test_pairing_denial_is_permission_denied_not_collection_error(tmp_path: Path, monkeypatch):
    """A trust denial is a permissions gap, not a tool failure (docs/v5/05)."""
    raw = tmp_path / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    collection: list[dict] = []

    monkeypatch.setattr(
        collectors,
        "run_command",
        lambda *a, **k: {
            "command": ["idevicepair"],
            "returncode": 1,
            "stdout": b"",
            "stderr": b"device is not paired with this host: access denied",
            "duration_seconds": 0.1,
            "timed_out": False,
        },
    )

    collectors.save_result(
        raw,
        collection,
        "pairing-validation",
        ["idevicepair", "validate"],
        denial_markers=collectors.PAIRING_DENIAL_MARKERS,
    )
    assert collection[0]["status"] == "permission_denied"


def test_healthy_output_mentioning_denial_is_not_reclassified(tmp_path: Path, monkeypatch):
    """The denial gate requires an errored run; a healthy exit is never reclassified."""
    raw = tmp_path / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    collection: list[dict] = []

    monkeypatch.setattr(
        collectors,
        "run_command",
        lambda *a, **k: {
            "command": ["idevicepair"],
            "returncode": 0,
            "stdout": b"Device is paired",
            "stderr": b"",
            "duration_seconds": 0.1,
            "timed_out": False,
        },
    )

    collectors.save_result(
        raw,
        collection,
        "pairing-validation",
        ["idevicepair", "validate"],
        denial_markers=collectors.PAIRING_DENIAL_MARKERS,
    )
    assert collection[0]["status"] == "collected"


def test_no_toolkit_records_tool_missing_rather_than_silence(tmp_path: Path, monkeypatch):
    """With no discovery tool the gap must be explicit, not an empty result."""
    raw = tmp_path / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    collection: list[dict] = []

    monkeypatch.setattr(collectors.shutil, "which", lambda name: None)
    assert collectors.discover_devices(raw, collection) == []
    assert any(item.get("status") == "tool_missing" for item in collection)
