"""Regression tests for the defects found in the v5 audit.

Each test here pins a bug that shipped with a green test suite: the original
tests all passed while these behaviours were broken. They are grouped by the
guarantee they protect, not by the module under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iphone_forensics import evidence, integrity, reporting

UDID = "00008030-001234567890ABCD"
SERIAL = "SN0ABCDEFGHIJ"
IMEI = "356938035643809"


def _report(**overrides):
    base = {
        "schema_version": "5.0.0",
        "version": "5.0.0",
        "device": {"ProductType": "iPhone15,2", "SerialNumber": SERIAL, "UniqueDeviceID": UDID},
        "collection": [
            {
                "name": "device-info-xml",
                "status": "collected",
                "command": ["ideviceinfo", "-u", UDID],
            }
        ],
        "findings": [],
        "scope": {},
        "target_udid": UDID,
        "connected_devices": [UDID],
    }
    base.update(overrides)
    return base


# ----------------------------------------------------------------- HTML shell


def test_report_has_exactly_one_style_block(tmp_path: Path):
    """A duplicated `<style>` made the CSS parser drop the whole :root block.

    Two opens and one close meant every `var(--x)` downstream resolved to
    nothing, so the report rendered unstyled while the validator still said
    "clean" — it never checked for balanced style tags.
    """
    reporting.build_html(tmp_path, _report())
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert html.count("<style>") == html.count("</style>") == 1


def test_css_custom_properties_survive_rendering(tmp_path: Path):
    """The theme block must actually reach the document."""
    reporting.build_html(tmp_path, _report())
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert ":root{" in html
    for token in ("--bg:", "--ink:", "--accent:", "--good:"):
        assert token in html, f"theme token {token} missing"


# ------------------------------------------------------------------- manifest


def test_manifest_is_written_after_every_artifact(tmp_path: Path):
    """The manifest hashed the directory before the reports landed in it."""
    reporting.finalize(tmp_path, _report(), redact_identifiers=True)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == evidence.SCHEMA_VERSION
    for name in ("report.html", "report.json", "report-redacted.html", "report-redacted.json"):
        assert (tmp_path / name).is_file()


def test_manifest_verifies_against_the_run_that_wrote_it(tmp_path: Path):
    """The artifact whose job is tamper-evidence must survive its own check."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "device-info.stdout.txt").write_text("payload", encoding="utf-8")

    reporting.finalize(tmp_path, _report(), redact_identifiers=True)

    result = evidence.verify_manifest(tmp_path)
    assert result["verified"] is True, result["problems"]
    assert result["changed"] == 0 and result["missing"] == 0
    # The evidence file must be covered, not silently absent.
    assert any(
        a["path"].endswith("device-info.stdout.txt")
        for a in json.loads((tmp_path / "manifest.json").read_text())["artifacts"]
    )


def test_manifest_writer_is_single(tmp_path: Path):
    """Both manifest writers must emit the same schema.

    `reporting.create_manifest` used to write a bare v3 list while
    `evidence.build_manifest` wrote the 5.0.0 object, so the same file had two
    incompatible shapes depending on the call path.
    """
    manifest = reporting.create_manifest(tmp_path)
    assert isinstance(manifest, dict)
    assert manifest["schema_version"] == evidence.SCHEMA_VERSION
    assert "artifacts" in manifest


# ------------------------------------------------------------------- redaction


def test_redacted_artifacts_contain_no_identifier_anywhere(tmp_path: Path):
    """Redaction must not leak a device identifier.

    The scrub was positional (device / target_udid / connected_devices /
    collection[].command) so an identifier inside a finding's free-text `detail`
    reached report-redacted.json in the clear — and so did the HTML rendered from
    it.
    """
    report = _report(
        findings=[
            {
                "severity": "INFO",
                "title": "Collector output referenced the device",
                "detail": f"command targeted udid {UDID} on a device reporting IMEI {IMEI}",
                "epistemic": "observed",
                "evidence": [],
            }
        ]
    )
    report["device"]["InternationalMobileEquipmentIdentity"] = IMEI

    reporting.finalize(tmp_path, report, redact_identifiers=True)

    for name in ("report-redacted.json", "report-redacted.html"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert UDID not in text, f"{name} leaked the UDID"
        assert IMEI not in text, f"{name} leaked the IMEI"
        assert SERIAL not in text, f"{name} leaked the serial"


def test_redaction_does_not_mutate_the_private_report(tmp_path: Path):
    """The private report must keep real identifiers.

    `redacted = dict(report)` was a shallow copy, so scrubbing the shared
    `collection` list masked the command in `report.json` too — the two
    "companion" artifacts silently disagreed.
    """
    report = _report()
    reporting.finalize(tmp_path, report, redact_identifiers=True)

    on_disk = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert on_disk["target_udid"] == UDID
    assert UDID in on_disk["collection"][0]["command"]
    assert on_disk["device"]["SerialNumber"] == SERIAL
    # And the caller's own dict must be untouched.
    assert report["target_udid"] == UDID
    assert UDID in report["collection"][0]["command"]


def test_scrub_identifiers_masks_by_key_not_just_by_value():
    """Key-based masking catches identifiers in sections we have not seen yet."""
    payload = {"some_future_section": {"SerialNumber": SERIAL}, "plain": "no identifier here"}
    scrubbed = reporting._scrub_identifiers(payload, ())
    assert SERIAL not in json.dumps(scrubbed)
    assert scrubbed["plain"] == "no identifier here"


# --------------------------------------------------------------- tamper signal


@pytest.mark.parametrize(
    "field",
    [
        "SerialNumber",
        "UniqueDeviceID",
        "InternationalMobileEquipmentIdentity",
        "IMEI",
        "UDID",
    ],
)
def test_every_hardware_identifier_change_is_a_blocker(field: str):
    """IMEI/UDID changes must reach BLOCKER.

    The old check tested for the substrings "imei"/"udid", which never occur in
    "InternationalMobileEquipmentIdentity" or "UniqueDeviceID" — the field names
    iOS actually reports. An IMEI swap degraded from BLOCKER to REVIEW while the
    module docstring still promised the rule.
    """
    _, finding = integrity.classify_change(field, "old", "new")
    assert finding.severity == "BLOCKER", f"{field} -> {finding.severity}"
    assert finding.classification == "suspicious"


@pytest.mark.parametrize("field", ["ProductType", "ProductVersion", "ModelNumber"])
def test_non_identifier_changes_are_not_promoted_to_blocker(field: str):
    """The fix must not turn every change into a BLOCKER."""
    _, finding = integrity.classify_change(field, "old", "new")
    assert finding.severity != "BLOCKER", f"{field} wrongly promoted to BLOCKER"


def test_hardware_identifier_matching_is_separator_insensitive():
    for variant in ("udid", "UDID", "DeviceUDID", "unique_device_id", "uniqueDeviceId"):
        assert integrity._is_hardware_identifier(variant), variant
    for other in ("ProductType", "ProductVersion", "BuildVersion"):
        assert not integrity._is_hardware_identifier(other), other
