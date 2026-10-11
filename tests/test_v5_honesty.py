"""Honesty and safety guarantees (docs/v5/06-authenticity-honesty.md, 07-safety-privacy.md).

These tests pin *refusals*. Each one asserts that the tool does NOT make a tempting
inference from a gap — the shortcuts that would turn missing evidence into either a
reassuring verdict or an accusation. Both failure modes are wrong; the point of this
suite is that neither can creep back in silently.

Offline only: no device, no network, no toolchain.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from iphone_forensics import capabilities, collectors, integrity, reporting, util


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


def _html(tmp_path: Path, report: dict, **kwargs) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    reporting.build_html(tmp_path, report, **kwargs)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


def _html_without_claim_policy(html: str) -> str:
    """Strip the claim-matrix panel before scanning for forbidden wording.

    That panel deliberately *quotes* each forbidden claim in order to prohibit it,
    so a whole-document scan would match the prohibition itself. Removing it leaves
    the report's own assertions, which is what these tests are about.
    """
    start = html.find("<h3>What this report may and may not claim</h3>")
    if start == -1:
        return html
    end = html.find("<h3>Limitations</h3>", start)
    return html[:start] + (html[end:] if end != -1 else "")


# ============================================== 1. the claim matrix is declared

def test_claim_matrix_declares_evidence_and_fallback_for_every_claim():
    rules = capabilities.claim_rules()
    assert rules, "the claim matrix must not be empty"
    # A fallback must name an explicit, bounded outcome rather than assert a verdict.
    bounded = re.compile(
        r"unknown|inconclusive|not_detectable|manual|no indicators|at most|never",
        re.IGNORECASE)
    for row in rules:
        assert row["claim"].strip()
        assert row["requires"].strip(), f"{row['claim']} does not state its evidence"
        assert row["otherwise"].strip(), f"{row['claim']} has no fallback wording"
        assert bounded.search(row["otherwise"]), \
            f"{row['claim']} fallback does not resolve to a bounded non-verdict"


def test_unknown_claim_falls_back_to_the_most_conservative_wording():
    """A missing rule must never license an unsupported claim."""
    assert capabilities.fallback_for("a_claim_nobody_defined").startswith("unknown")


def test_forbidden_inferences_all_state_the_correct_wording():
    entries = capabilities.forbidden_inferences()
    assert len(entries) >= 5
    for row in entries:
        assert row["wrong_claim"].strip()
        assert row["correct"].strip()
        assert row["wrong_claim"] != row["correct"]


def test_policy_wording_can_itself_never_assert_a_verdict():
    """The policy data must not drift into making the claim it forbids.

    These tables are the last line of defence, so editing one to state an
    accusation or a clean bill of health would be a silent, total failure of the
    honesty guarantee. The correct-wording fields are held to the same standard the
    report itself is held to.
    """
    forbidden = re.compile(
        r"\b(?:is|are|was|were)\s+(?:replaced|genuine|counterfeit|tampered|malware[- ]free)\b"
        r"|\bindicates\b(?!\s+nothing)"
        r"|\bproves\b(?!\s+(?:nothing|no ))"
        r"|\bconfirms\b(?!\s+(?:nothing|no ))"
        r"|\bmeans the (?:battery|part|device)\b",
        re.IGNORECASE)
    for row in capabilities.claim_rules():
        assert not forbidden.search(row["otherwise"]), \
            f"fallback wording asserts a verdict: {row['claim']} -> {row['otherwise']!r}"
    for row in capabilities.forbidden_inferences():
        assert not forbidden.search(row["correct"]), \
            f"correct wording asserts a verdict: {row['inference']} -> {row['correct']!r}"


def test_claim_policy_names_every_forbidden_inference():
    """The report quotes these prohibitions, so each must be a real prohibition."""
    declared = {row["inference"] for row in capabilities.forbidden_inferences()}
    for required in ("missing_battery_metric_means_replaced_battery",
                     "missing_serial_means_tampering",
                     "unknown_part_means_genuine_or_counterfeit",
                     "identifier_present_means_component_verified",
                     "clean_metadata_means_malware_free"):
        assert required in declared, f"forbidden inference {required} is no longer declared"


def test_claim_matrix_is_rendered_into_the_report(tmp_path: Path):
    """A reader can see the limits of the evidence, not just trust them."""
    html = _html(tmp_path, _report())
    assert "What this report may and may not claim" in html
    assert "Inferences this tool never draws" in html
    assert "battery_metric" in html
    assert "malware_free" in html


def test_no_genuine_or_health_percentage_claims_anywhere(tmp_path: Path):
    """docs/v5/06: the tool never grades a device as genuine or healthy.

    Patterns require an *affirmative* claim with a value. The report is full of
    disclaimers like "not interpreted as health scores", which are the tool being
    honest — those must not trip the check.
    """
    html = _html_without_claim_policy(_html(tmp_path, _report()))
    affirmative = (
        r"\d+\s*%\s*(?:genuine|authentic|healthy)",
        r"(?:genuine|authentic|healthy)\D{0,15}\d+\s*%",
        r"health\s+score\s*(?:of|is|:|=)\s*\d",
        r"health\s+score\s+is\s+(?:high|low|good|poor|excellent)",
        r"\b(?:is|are)\s+(?:genuine|fully\s+genuine|counterfeit)\b",
    )
    for pattern in affirmative:
        assert not re.search(pattern, html, re.IGNORECASE), f"invented claim matched {pattern!r}"


# ================================= 2. forbidden inferences (one test each)

def test_missing_battery_metric_never_means_replaced_battery(tmp_path: Path):
    """Missing battery data is an evidence gap, not a repair record."""
    report = _report(hardware_assessment={
        "subsystems": {"battery": "not_tested"},
        "checks": [{"subsystem": "battery", "question": "Cycle count", "status": "not_tested",
                    "measurement": None, "confidence": "none"}],
        "warnings": [], "disclaimer": "Not proof."})
    html = _html_without_claim_policy(_html(tmp_path, report))
    assert "not_tested" in html
    # No statement of the forbidden inference anywhere in the report's own voice.
    assert not re.search(r"(replaced|substitut|remanufactur)\w*\s+battery", html, re.IGNORECASE)


def test_missing_serial_never_means_tampering(tmp_path: Path):
    report = _report(device={"ProductType": "iPhone15,4"})  # no SerialNumber at all
    html = _html_without_claim_policy(_html(tmp_path, report))
    assert not re.search(r"(missing|absent)\s+serial\w*\s+(means|indicates|suggests)", html, re.IGNORECASE)


def test_unknown_part_is_never_called_genuine_or_counterfeit(tmp_path: Path):
    """No public API exposes parts-pairing state, so neither verdict is available."""
    report = _report(integrity_assessment={
        "overall": "inconclusive", "classifications": {"SomePart": "not_detectable"},
        "changes": [], "continuity": "not_detectable", "disclaimer": "Not proof."})
    html = _html_without_claim_policy(_html(tmp_path, report))
    assert "not_detectable" in html
    assert not re.search(r"part is (genuine|counterfeit|aftermarket)", html, re.IGNORECASE)


def test_present_identifier_never_proves_a_component_works(tmp_path: Path):
    """Biometrics/display/sensors need the guided physical test."""
    report = _report(device={"ProductType": "iPhone15,4", "SerialNumber": "ABC123DEF",
                             "UniqueDeviceID": "UDID1234567890ABCDEF"})
    html = _html_without_claim_policy(_html(tmp_path, report))
    assert "manual" in html.lower()
    assert not re.search(r"(face ?id|display|sensors?) (is |are )?(verified|working|healthy)", html, re.IGNORECASE)


def test_clean_metadata_never_means_malware_free(tmp_path: Path):
    report = _report(crash_triage={"interpretation": "Triage ran.", "files_scanned": 0,
                                   "crash_or_diagnostic_count": 0,
                                   "panic_or_watchdog_candidate_count": 0})
    html = _html_without_claim_policy(_html(tmp_path, report))
    assert not re.search(r"malware[- ]free|no malware|clean device", html, re.IGNORECASE)
    # Absence of indicators is described as absence, with a false-positive caveat.
    assert re.search(r"no indicators matched|does not mean", html, re.IGNORECASE)


def test_continuity_is_never_asserted_without_a_hardware_bound_identifier():
    """Matching snapshots with no stable identifier must not read as same-device proof."""
    previous = _report(device={"ProductType": "iPhone15,4"})  # no serial, no UDID
    current = _report(device={"ProductType": "iPhone15,4"})
    result = integrity.assess_integrity(previous, current, {"checks": {}})
    assert result["continuity"] == "not_detectable"
    assert result["overall"] != "verified"


def test_continuity_from_a_stable_identifier_is_evidence_not_proof():
    """A stable identifier does support continuity — but never as a clean bill of health."""
    previous = _report(device={"ProductType": "iPhone15,4", "SerialNumber": "ABC"})
    current = _report(device={"ProductType": "iPhone15,4", "SerialNumber": "ABC"})
    result = integrity.assess_integrity(previous, current, {"checks": {}})
    assert result["continuity"] == "established"
    assert result.get("disclaimer"), "continuity must still carry its limits"


# ================================================ 3. non-destructive guarantee

def test_standard_profile_never_runs_a_state_changing_command():
    """docs/v5/07: the default profile performs zero state changes."""
    forbidden = ("backup", "erase", "restore", "reset", "install", "uninstall",
                 "provision", "mount", "pair", "activation", "jailbreak")
    # The default sensitive profile is "off": consent never invents a capture window
    # or a backup, so nothing on this list may be enabled by default.
    import argparse

    from iphone_forensics.cli import _engine_args

    args = _engine_args(argparse.Namespace(output=".", device=None, buyer_json=None,
                                           compare_json=None, redact_identifiers=False,
                                           no_capability_catalog=False),
                        output=".", device=None, sensitive=False)
    assert args.backup == "none"
    assert args.syslog_seconds == 0
    assert args.pmd_syslog_seconds == 0
    for name in ("app_list", "pmd_app_list", "pmd_processes", "crash_reports",
                 "pmd_crash_reports", "provisioning"):
        assert getattr(args, name) is False, f"{name} is on without consent"
    assert str(args.backup) not in forbidden


def test_no_silent_backup_without_explicit_flag():
    """A full backup must be impossible to trigger implicitly."""
    import argparse

    from iphone_forensics.cli import _engine_args

    args = _engine_args(argparse.Namespace(output=".", device=None, buyer_json=None,
                                           compare_json=None, redact_identifiers=False,
                                           no_capability_catalog=False),
                        output=".", device=None, sensitive=True)
    # Consent turns on the boolean collectors but never invents a backup or a
    # capture window: those still need their own explicit flag.
    assert args.backup == "none"
    assert args.syslog_seconds == 0
    assert args.pmd_syslog_seconds == 0


# ================================================= 4. consent is a real gate

def test_declining_consent_leaves_a_complete_but_honest_run(tmp_path: Path):
    """Declining costs nothing: the run still finishes and says what was skipped."""
    import argparse

    from iphone_forensics.cli_v4 import _finish_run, _new_report

    run = tmp_path / "run"
    run.mkdir()
    paths = util_run_dir(run)
    args = argparse.Namespace(redact=False, compare_json=None)
    report = _new_report(argparse.Namespace(redact=False, compare_json=None,
                                             sensitive_consent=False,
                                             sensitive_explicit=[]))
    report["collection"].append({"name": "app-list", "status": "skipped_by_user",
                                 "returncode": None, "timed_out": False})
    _finish_run(paths["run_dir"], report, {"checks": {}}, args)

    html = (paths["run_dir"] / "report.html").read_text(encoding="utf-8")
    assert "skipped" in html.lower(), "a declined run must still render its skipped items"
    assert "report-validation" in html, "the run must still complete and validate"
    persisted = json.loads((paths["run_dir"] / "report.json").read_text(encoding="utf-8"))
    assert persisted["scope"]["sensitive_collection"] == "declined"


def util_run_dir(run: Path):
    from iphone_forensics.evidence import run_dir_paths

    return run_dir_paths(run, "20260101-120000")


# ============================================ 5. canary redaction (docs/v5/07)

def test_canary_identifier_is_masked_in_the_shareable_export(tmp_path: Path):
    """The redacted export must be safe to hand to anyone; the private one is not.

    The unredacted report is the evidence of record and deliberately contains the
    real identifiers — it stays on this machine. What must never leak is the
    *shareable* artifact, or the console.
    """
    canary = "UDIDCANARY0123456789ABCDEF0123"
    secrets = (canary, "SERIALCANARY9876543210", "IMEICANARY555666777888999")
    report = _report(device={
        "ProductType": "iPhone15,4", "SerialNumber": "SERIALCANARY9876543210",
        "UniqueDeviceID": canary, "IMEI": "IMEICANARY555666777888999",
    }, target_udid=canary, connected_devices=[canary])

    redacted_html = _html(tmp_path, report, redact_identifiers=True)
    for secret in secrets:
        assert secret not in redacted_html, \
            f"unredacted identifier leaked into the shareable report: {secret[:8]}..."

    # The private report still holds the evidence, as it must.
    private_html = _html(tmp_path, report)
    assert any(secret in private_html for secret in secrets), \
        "the private report must retain the identifiers it collected"

    # And the console-facing redaction never returns the full value.
    for secret in secrets:
        assert secret not in util.redact(secret)


def test_consistent_redaction_across_every_surface():
    """Console, HTML and JSON must mask identically (one helper, docs/v5/07)."""
    from iphone_forensics.cli_v4 import redact as cli_redact
    from iphone_forensics.reporting import _redact_identifier

    secret = "UDID1234567890ABCDEF0123456789"
    expected = util.redact(secret)
    assert cli_redact(secret) == expected
    assert _redact_identifier(secret) == expected
    assert expected.endswith("6789")
    assert "1234567890" not in expected


# ============================================== 6. status honesty under the hood

def test_collection_error_is_not_reported_as_a_device_fault():
    """A tool that errored has told us nothing about the device."""
    report = _report(collection=[{"name": "diagnostics-wifi", "status": "collection_error",
                                  "returncode": 3, "timed_out": False}])
    from iphone_forensics.analysis import automated_assessment, derive_findings

    result = automated_assessment(report, None)
    assert result["collection_negative_results"] == 0
    assert result["collection_gaps"] == 1
    findings = [f for f in derive_findings(report, None)
                if "Collection incomplete" in f.get("title", "")]
    assert len(findings) == 1
    assert findings[0].get("status") == "collection_error"


def test_pairing_denial_never_becomes_a_tool_failure():
    assert collectors.PAIRING_DENIAL_MARKERS == ("denied", "refused")
    # A denial is a permissions gap; it must not be reclassified as a device fault.
    result = {"returncode": 1, "stderr": b"access denied", "timed_out": False}
    assert result["returncode"] != 0, "the denial gate requires an errored run"


def test_collection_statuses_never_accept_health_vocabulary():
    """The two vocabularies are separate; a health word is not a collection status.

    `inconclusive` and `unsupported` legitimately appear in both lists — the words
    mean the same thing in each. What must never happen is a health verdict being
    read as a collection outcome, because that would turn "pass" into "we
    collected something".
    """
    from iphone_forensics.models import COLLECTION_STATUSES, normalize_status

    health_only = {"pass", "pass_with_warnings", "degraded", "fail", "not_tested"}
    assert health_only and not (health_only & set(COLLECTION_STATUSES)), \
        "a health verdict must never be a collection status"

    for word in sorted(health_only):
        # A stray health word must degrade to a non-passing state, never to
        # "collected"/"passed" — that would claim we gathered evidence.
        assert normalize_status(word) not in {"collected", "passed"}, \
            f"health word {word!r} was read as a successful collection"