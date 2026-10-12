"""Spec tests for the v5 collection status / epistemic label model (models.py).

Covers docs/v5/05-evidence-analysis-model.md:
  * all 11 collection statuses are declared and enumerable
  * legacy v4 outcome strings normalize without raising
  * every status maps to an existing HEALTH_STATUSES value (summary roll-up)
  * the 4 epistemic labels are declared
Purely additive: no existing v4 symbol may change.
"""

from iphone_forensics.models import (
    COLLECTION_STATUSES,
    EPISTEMIC_LABELS,
    HEALTH_STATUSES,
    STATUS_TO_HEALTH,
    normalize_status,
)

EXPECTED_COLLECTION_STATUSES = {
    "collected",
    "passed",
    "warning",
    "failed",
    "inconclusive",
    "unsupported",
    "permission_denied",
    "tool_missing",
    "collection_error",
    "skipped_by_user",
    "not_applicable",
}


# ---------------------------------------------------- all 11 statuses reachable


def test_all_eleven_collection_statuses_are_reachable():
    assert len(COLLECTION_STATUSES) == 11
    assert set(COLLECTION_STATUSES) == EXPECTED_COLLECTION_STATUSES
    # each one normalizes to itself (pass-through, no aliasing)
    for status in COLLECTION_STATUSES:
        assert normalize_status(status) == status


# ------------------------------------------------------- legacy string compat


def test_legacy_outcome_strings_normalize_without_raising():
    assert normalize_status("success") == "collected"
    assert normalize_status("expected_end") == "collected"
    assert normalize_status("failed_or_partial") == "collection_error"


def test_normalize_status_is_case_and_whitespace_tolerant():
    assert normalize_status("  SUCCESS ") == "collected"
    assert normalize_status("Failed_Or_Partial") == "collection_error"


def test_normalize_status_unknown_and_odd_values_never_raise():
    assert normalize_status("totally_made_up") == "inconclusive"
    assert normalize_status("") == "inconclusive"
    assert normalize_status(None) == "inconclusive"  # type: ignore[arg-type]
    assert normalize_status(123) == "inconclusive"  # type: ignore[arg-type]


# ----------------------------------------------------- status -> health roll-up


def test_status_to_health_covers_every_collection_status():
    assert set(STATUS_TO_HEALTH) == set(COLLECTION_STATUSES)


def test_status_to_health_values_are_valid_health_statuses():
    for status, health in STATUS_TO_HEALTH.items():
        assert health in HEALTH_STATUSES, f"{status} -> {health!r} not in HEALTH_STATUSES"


def test_status_to_health_rollup_expectations():
    assert STATUS_TO_HEALTH["failed"] == "fail"
    assert STATUS_TO_HEALTH["warning"] == "pass_with_warnings"
    assert STATUS_TO_HEALTH["inconclusive"] == "inconclusive"
    assert STATUS_TO_HEALTH["unsupported"] == "unsupported"
    for status in (
        "skipped_by_user",
        "permission_denied",
        "tool_missing",
        "collection_error",
        "not_applicable",
    ):
        assert STATUS_TO_HEALTH[status] == "not_tested", status
    assert STATUS_TO_HEALTH["collected"] == "pass"
    assert STATUS_TO_HEALTH["passed"] == "pass"


# -------------------------------------------------------------- epistemic labels


def test_epistemic_labels_are_the_four_declared_values():
    assert len(EPISTEMIC_LABELS) == 4
    assert set(EPISTEMIC_LABELS) == {"observed", "inferred", "unknown", "needs_manual"}


# ----------------------------------------------------------- additive-only guard


def test_existing_v4_symbols_still_present():
    from iphone_forensics import models

    for name in (
        "SEVERITIES",
        "CONFIDENCE_LEVELS",
        "HEALTH_STATUSES",
        "INTEGRITY_CLASSES",
        "SubsystemCheck",
        "Finding",
        "DeviceIdentity",
        "EvidenceRecord",
    ):
        assert hasattr(models, name), f"v4 symbol {name} was removed"
