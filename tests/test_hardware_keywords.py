"""Regression tests for hardware panic/thermal keyword hygiene.

The keyword tuples drive substring matching against lowercased panic strings.
A keyword with surrounding whitespace silently narrows its match window
(e.g. " backlight" never matches a string starting with "backlight"), so the
tuples must stay lowercase, duplicate-free, and whitespace-free.
"""
from iphone_forensics.hardware import (
    BATTERY_SERVICE_HINTS,
    PANIC_HINTS,
    PANIC_KEYWORD_MAP,
    STORAGE_SERVICE_HINTS,
    THERMAL_PATTERN_HINTS,
    assess_hardware,
)

_PAIR_HINT_TUPLES = (
    BATTERY_SERVICE_HINTS,
    STORAGE_SERVICE_HINTS,
)


def _report(panic=None):
    return {
        "diagnostic_candidates": [],
        "device": {},
        "crash_triage": {"panic_candidates": panic or []},
    }


# ------------------------------------------------------------------ backlight

def test_backlight_typo_regression_routes_to_display_bucket():
    """' backlight' (leading space) missed strings starting with 'backlight'."""
    report = _report([{"panicString": "backlight driver fault on gpu"}])
    assessment = assess_hardware(report)
    assert "display" in assessment["panic_by_subsystem"]
    matched = assessment["panic_by_subsystem"]["display"]
    assert any("backlight" in p["panicString"] for p in matched)


def test_backlight_substring_in_sentence_still_matches():
    report = _report([{"panicString": "AMOLED backlight failure"}])
    assessment = assess_hardware(report)
    # display is a manual subsystem, so the triage lands in
    # panic_by_subsystem without appending a duplicate check.
    assert "display" in assessment["panic_by_subsystem"]
    display_checks = [c for c in assessment["checks"] if c["subsystem"] == "display"]
    assert len(display_checks) == 1  # only the manual-guided check remains


# ------------------------------------------------------------ case handling

def test_keyword_matching_is_case_insensitive():
    report = _report([{"panicString": "CAMERA ISP Fault While Streaming"}])
    assessment = assess_hardware(report)
    assert "cameras" in assessment["panic_by_subsystem"]


def test_thermal_hint_matching_is_case_insensitive():
    report = _report([{"panicString": "THERMALmonitord overheat shutdown"}])
    assessment = assess_hardware(report)
    thermal = [c for c in assessment["checks"]
               if c["subsystem"] == "thermal" and "panic" in c["source"]]
    assert thermal, "thermal keyword should produce a thermal triage check"
    assert thermal[0]["status"] == "inconclusive"


# ------------------------------------------------------------ tuple hygiene

def test_no_hint_keyword_has_surrounding_whitespace():
    for hints in _PAIR_HINT_TUPLES:
        for keyword, _message in hints:
            assert keyword == keyword.strip(), f"untrimmed keyword: {keyword!r}"
    for keyword in THERMAL_PATTERN_HINTS:
        assert keyword == keyword.strip(), f"untrimmed keyword: {keyword!r}"
    for keyword in PANIC_HINTS:
        assert keyword == keyword.strip(), f"untrimmed keyword: {keyword!r}"


def test_no_panic_keyword_has_surrounding_whitespace():
    for subsystem, keywords in PANIC_KEYWORD_MAP.items():
        for keyword in keywords:
            assert keyword == keyword.strip(), (
                f"untrimmed keyword in {subsystem}: {keyword!r}")


def test_all_keywords_are_lowercase():
    for hints in _PAIR_HINT_TUPLES:
        for keyword, _message in hints:
            assert keyword == keyword.lower(), f"non-lowercase keyword: {keyword!r}"
    for keyword in THERMAL_PATTERN_HINTS:
        assert keyword == keyword.lower(), f"non-lowercase keyword: {keyword!r}"
    for keyword in PANIC_HINTS:
        assert keyword == keyword.lower(), f"non-lowercase keyword: {keyword!r}"
    for subsystem, keywords in PANIC_KEYWORD_MAP.items():
        for keyword in keywords:
            assert keyword == keyword.lower(), (
                f"non-lowercase keyword in {subsystem}: {keyword!r}")


def test_no_duplicate_keywords_within_a_bucket():
    for hints in _PAIR_HINT_TUPLES:
        keywords = [keyword for keyword, _message in hints]
        assert len(keywords) == len(set(keywords))
    assert len(THERMAL_PATTERN_HINTS) == len(set(THERMAL_PATTERN_HINTS))
    assert len(PANIC_HINTS) == len(set(PANIC_HINTS))
    for subsystem, keywords in PANIC_KEYWORD_MAP.items():
        assert len(keywords) == len(set(keywords)), f"duplicate keyword in {subsystem}"


# -------------------------------------------------------------- status guard

def test_thermal_hint_stays_inconclusive_never_fail():
    report = _report([{"panicString": "thermal pressure event on cpu0"}])
    assessment = assess_hardware(report)
    assert assessment["subsystems"].get("thermal") in {"inconclusive", "not_tested"}
    thermal = [c for c in assessment["checks"]
               if c["subsystem"] == "thermal" and "panic" in c["source"]]
    assert thermal and thermal[0]["status"] == "inconclusive"
