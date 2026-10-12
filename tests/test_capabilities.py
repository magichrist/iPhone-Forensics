"""Tests for the capability matrix data module (docs/v4/capability-matrix.md).

Pure data — no device or tool chain required.
"""

from iphone_forensics.capabilities import (
    CAPABILITIES,
    COVERAGE_LEVELS,
    by_category,
    coverage_counts,
    get_matrix,
)


def test_import_public_surface():
    matrix = get_matrix()
    assert matrix
    assert all(isinstance(row, dict) for row in matrix)


def test_all_coverage_values_in_allowed_set():
    for row in CAPABILITIES:
        assert row["coverage"] in COVERAGE_LEVELS, row["item"]


def test_every_spec_category_present():
    # §3 categories required by docs/v4/phase-2-hardware.md
    for category in (
        "identity",
        "battery",
        "storage",
        "display",
        "cameras",
        "biometrics",
        "connectivity",
        "thermal",
        "physical",
    ):
        assert by_category(category), f"missing §3 category: {category}"


def test_every_entry_has_source_requirements_limits():
    for row in CAPABILITIES:
        for key in (
            "category",
            "item",
            "coverage",
            "source",
            "requirements",
            "limits",
            "model_applicability",
            "ios_applicability",
        ):
            assert key in row, f"{row.get('item')}: missing key {key!r}"


def test_unsupported_rows_declare_no_software_method():
    unsupported = [r for r in CAPABILITIES if r["coverage"] == "unsupported"]
    items = " ".join(r["item"].lower() for r in unsupported)
    assert "water resistance" in items and "opened-before" in items
    # Unsupported rows must honestly state there is no method — never "—"-free claims.
    for row in unsupported:
        assert row["limits"], row["item"]


def test_by_category_is_case_insensitive_and_returns_copies():
    assert by_category("Battery") == by_category("battery")
    assert by_category("no-such-category") == []
    entry = by_category("storage")[0]
    entry["coverage"] = "tampered"
    assert by_category("storage")[0]["coverage"] != "tampered"


def test_get_matrix_returns_isolated_copies():
    matrix = get_matrix()
    assert len(matrix) == len(CAPABILITIES)
    matrix[0]["coverage"] = "tampered"
    assert CAPABILITIES[0]["coverage"] != "tampered"


def test_coverage_counts_cover_every_level_and_sum_to_matrix_size():
    counts = coverage_counts()
    assert set(counts) == set(COVERAGE_LEVELS)
    assert sum(counts.values()) == len(CAPABILITIES)
    # The matrix must not claim everything is automated — honesty check.
    assert counts["unsupported"] >= 1
    assert counts["manual"] >= 1
