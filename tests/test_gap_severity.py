"""Severity must describe the *kind* of gap, not just that a gap exists.

Every status below `_COMPLETED_STATUSES` is an evidence gap, but grading them all
REVIEW contradicted their own detail text — "this is not a device fault",
"nothing is wrong with the device" — and made a healthy phone on a machine missing
an optional tool exit nonzero with a list of things to investigate.

These tests pin the distinction the README promises: only a check that ran and
returned something negative is a finding about the device.
"""
from __future__ import annotations

from iphone_forensics.analysis import _GAP_SEVERITY, derive_findings
from iphone_forensics.buyer import template


def _findings(collection=None, buyer_data=None):
    report = {
        "device": {"ProductType": "iPhone14,5"},
        "findings": [],
        "collection": collection if collection is not None else [],
    }
    return derive_findings(report, buyer_data or template())


def _by_title(findings, needle):
    return [f for f in findings if needle in f["title"]]


# --------------------------------------------- environment gaps are not faults

def test_missing_tool_is_info_not_review():
    """A missing optional tool is an environment gap about this machine."""
    findings = _findings([{"name": "provisioning-profiles", "status": "tool_missing"}])
    gap = _by_title(findings, "Collection incomplete")[0]
    assert gap["severity"] == "INFO"
    assert "not a device fault" in gap["detail"]


def test_collection_error_is_info_not_review():
    """The pymobiledevice3 bug produced these; they are not device problems."""
    findings = _findings([{"name": "installed-apps-pymobiledevice3", "status": "collection_error"}])
    gap = _by_title(findings, "Collection incomplete")[0]
    assert gap["severity"] == "INFO"
    assert "not automatically a device fault" in gap["detail"]


def test_permission_denied_is_info_not_review():
    findings = _findings([{"name": "pairing-validation", "status": "permission_denied"}])
    assert _by_title(findings, "Collection incomplete")[0]["severity"] == "INFO"


def test_skipped_by_user_is_info_not_review():
    """Declining consent is the operator's choice, not a defect."""
    findings = _findings([{"name": "crash-report-copy", "status": "skipped_by_user"}])
    gap = _by_title(findings, "Collection incomplete")[0]
    assert gap["severity"] == "INFO"
    assert "nothing is wrong with the device" in gap["detail"]


def test_unsupported_and_not_applicable_are_info():
    for status in ("unsupported", "not_applicable"):
        findings = _findings([{"name": "x", "status": status}])
        assert _by_title(findings, "Collection incomplete")[0]["severity"] == "INFO"


# ------------------------------------- a real negative result still gets REVIEW

def test_failed_status_stays_review():
    """The check ran and returned a negative: that IS a finding about the device."""
    findings = _findings([{"name": "diagnostics-GasGauge", "status": "failed"}])
    assert _by_title(findings, "Collection incomplete")[0]["severity"] == "REVIEW"


def test_inconclusive_status_stays_review():
    findings = _findings([{"name": "ioreg-IOPower", "status": "inconclusive"}])
    assert _by_title(findings, "Collection incomplete")[0]["severity"] == "REVIEW"


def test_every_gap_status_has_a_severity():
    from iphone_forensics.analysis import _GAP_DETAIL
    for status in _GAP_DETAIL:
        assert status in _GAP_SEVERITY, f"{status} has wording but no severity"


# ------------------------------------------------ manual checks are not defects

def test_unverified_buyer_checks_are_info_not_review():
    """Activation Lock etc. need a human; the tool never claimed to check them."""
    findings = _findings()
    manual = _by_title(findings, "Buyer-critical check not verified")
    assert manual, "expected the unverified-checklist findings"
    assert all(f["severity"] == "INFO" for f in manual)
    assert all(f["epistemic"] == "needs_manual" for f in manual)


def test_buyer_critical_failure_stays_blocker():
    """A check that ran and FAILED must never be downgraded to INFO."""
    data = template()
    data["checks"]["activation_lock"]["status"] = "fail"
    findings = _findings(buyer_data=data)
    blocked = _by_title(findings, "Buyer-critical check failed")
    assert blocked and blocked[0]["severity"] == "BLOCKER"


# ------------------------------------------------------------- clean run shape

def test_a_clean_run_produces_no_review_or_blocker_findings():
    """A fully collected device with nothing wrong must not fail the exit code.

    This is the regression that mattered: a normal run on a healthy phone exited
    1 with seven REVIEW findings, all of them gaps about the host or checks the
    tool never performs.
    """
    findings = _findings([
        {"name": "device-info-xml", "status": "collected"},
        {"name": "diagnostics-GasGauge", "status": "collected"},
        {"name": "installed-apps-pymobiledevice3", "status": "collection_error"},
    ])
    manual = _by_title(findings, "not verified")
    assert manual and all(f["severity"] == "INFO" for f in manual), \
        "manual checks are informational, not defects"
    severities = {f["severity"] for f in findings}
    assert "REVIEW" not in severities, severities
    assert "BLOCKER" not in severities, severities