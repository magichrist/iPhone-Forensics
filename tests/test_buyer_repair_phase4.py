"""Phase 4 — buyer verdicts and repair case exports.

Two guarantees are pinned here.

**Buyer rule order.** `evaluate_v4` is a first-match-wins ladder, so the tests
below drive one verdict at a time and assert the rule that fired — a refactor
that reorders the ladder, or swaps `not_tested` for `fail`, fails loudly.

**Manual-only ownership.** The four ownership checks are never software-verified
here, so a *suspicion* about them must never read as a *failure*: an unresolved
critical item routes to INVESTIGATE_FURTHER ("go check this"), while only a
recorded `fail` condemns to AVOID_PURCHASE.
"""
import pytest

from iphone_forensics.buyer import (
    BUYER_VERDICTS,
    CHECKLIST,
    CHECKLIST_VERSION,
    OWNERSHIP_MANUAL,
    evaluate_v4,
    evaluate_v4_json,
    template,
)
from iphone_forensics.repair import case_to_json, new_case, qa_summary, record_work

CRITICAL_IDS = [item["id"] for item in CHECKLIST if item["critical"]]
NONCRITICAL_IDS = [item["id"] for item in CHECKLIST if not item["critical"]]


def _answered(status: str = "pass", critical: bool = True) -> dict:
    """A checklist whose relevant items are answered, everything else untouched."""
    data = template()
    for check_id in (CRITICAL_IDS if critical else NONCRITICAL_IDS):
        data["checks"][check_id]["status"] = status
    return data


def _with(**overrides: str) -> dict:
    """`_answered()` with specific item ids set to a status."""
    data = _answered()
    for check_id, status in overrides.items():
        data["checks"][check_id]["status"] = status
    return data


def _clean() -> dict:
    """Every item answered `pass` — the only input reaching rule 5."""
    return _answered() | {"checks": {i: {"status": "pass"} for i in
                                     CRITICAL_IDS + NONCRITICAL_IDS}}


# ------------------------------------------------------------ rule order / verdict

def test_rule1_critical_fail_verdict_is_avoid_purchase():
    data = _answered()
    data["checks"]["activation_lock"]["status"] = "fail"
    result = evaluate_v4(data)
    assert result["verdict"] == "AVOID_PURCHASE"
    assert "rule 1" in result["rule"]
    assert result["critical_failures"] == ["activation_lock"]


def test_rule2_fewer_than_three_answered_verdict_is_insufficient_evidence():
    # Two non-critical items answered is still too little to say anything —
    # rule 2 fires before the critical unknowns of rule 3.
    data = template()
    data["checks"]["battery_health"]["status"] = "pass"
    data["checks"]["cameras"]["status"] = "pass"
    result = evaluate_v4(data)
    assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "rule 2" in result["rule"]


def test_rule3_critical_unknown_verdict_is_investigate_further():
    # Enough items answered to comment, but one critical check stays unknown.
    data = _answered()
    data["checks"]["battery_health"]["status"] = "pass"
    data["checks"]["cameras"]["status"] = "pass"
    data["checks"]["audio"]["status"] = "pass"
    data["checks"]["carrier_eligibility"]["status"] = "not_tested"
    result = evaluate_v4(data)
    assert result["verdict"] == "INVESTIGATE_FURTHER"
    assert "rule 3" in result["rule"]
    assert result["critical_unknown"] == ["carrier_eligibility"]


def test_rule4_noncritical_fail_verdict_is_buy_only_after_repair():
    data = _answered()
    data["checks"]["display_touch"]["status"] = "fail"
    result = evaluate_v4(data)
    assert result["verdict"] == "BUY_ONLY_AFTER_REPAIR"
    assert "rule 4" in result["rule"]
    assert result["noncritical_failures"] == ["display_touch"]


def test_rule5_clean_checklist_verdict_is_good_candidate():
    data = _answered()
    for check_id in NONCRITICAL_IDS:
        data["checks"][check_id]["status"] = "pass"
    result = evaluate_v4(data)
    assert result["verdict"] == "GOOD_CANDIDATE"
    assert "rule 5" in result["rule"]


def test_every_verdict_in_enum_is_reachable():
    """The enum advertises exactly five outcomes; each is produced by a case."""
    reached = {
        evaluate_v4(_with(activation_lock="fail"))["verdict"],                    # rule 1
        evaluate_v4(template())["verdict"],                                      # rule 2
        evaluate_v4(_answered() | {"checks": {**_answered()["checks"],           # rule 3
            "battery_health": {"status": "pass"},
            "cameras": {"status": "pass"},
            "audio": {"status": "pass"},
            "carrier_eligibility": {"status": "not_tested"}}})["verdict"],
        evaluate_v4(_with(display_touch="fail"))["verdict"],                     # rule 4
        evaluate_v4(_clean())["verdict"],                                        # rule 5
    }
    assert reached == set(BUYER_VERDICTS)


# ------------------------------------------------------------------ status handling

def test_invalid_status_is_coerced_to_not_tested_not_pass_and_not_fail():
    data = _answered()
    data["checks"]["activation_lock"]["status"] = "probably fine"
    result = evaluate_v4(data)
    assert "activation_lock" not in result["critical_failures"]
    assert "activation_lock" in result["critical_unknown"]


@pytest.mark.parametrize("bad", [None, 1, True, "", "probably fine", "PASS", "not-applicable"])
def test_invalid_status_degrades_to_unknown_not_pass_or_fail(bad):
    data = _answered()
    data["checks"]["icloud_signout"]["status"] = bad
    result = evaluate_v4(data)
    assert result["critical_failures"] == []
    assert result["critical_unknown"] == ["icloud_signout"]


@pytest.mark.parametrize("bad", [{"status": "pass"}, ["pass"], None])
def test_unhashable_status_degrades_to_unknown(bad):
    """A non-string status must degrade to not_tested, never raise.

    Hand-edited JSON can put a dict/list/None where a status string belongs;
    `set` membership on those raises TypeError, so coercion happens first.
    """
    result = evaluate_v4(_with(icloud_signout=bad))
    assert result["critical_failures"] == []
    assert result["verdict"] in {"INVESTIGATE_FURTHER", "INSUFFICIENT_EVIDENCE"}
    assert "icloud_signout" in result["critical_unknown"]


def test_single_suspicion_does_not_condemn_device():
    """An unverified critical item routes to INVESTIGATE_FURTHER, never AVOID."""
    data = _answered()
    for check_id in NONCRITICAL_IDS[:3]:
        data["checks"][check_id]["status"] = "pass"
    data["checks"]["remote_management"]["status"] = "not_tested"
    result = evaluate_v4(data)
    assert result["verdict"] == "INVESTIGATE_FURTHER"
    assert result["critical_failures"] == []
    assert "remote_management" in result["unresolved_checks_that_could_change_verdict"]


def test_good_candidate_carries_non_certification_disclaimer():
    data = _answered()
    for check_id in NONCRITICAL_IDS:
        data["checks"][check_id]["status"] = "pass"
    assert "not a certification" in evaluate_v4(data)["certification_disclaimer"].lower()


# ------------------------------------------------------------------ ownership honesty

def test_ownership_manual_covers_the_four_critical_ownership_checks():
    assert set(OWNERSHIP_MANUAL) == {"activation_lock", "remote_management",
                                     "carrier_eligibility", "icloud_signout"}
    assert set(OWNERSHIP_MANUAL) == set(CRITICAL_IDS)


def test_ownership_manual_note_disclaims_software_verification():
    for note in OWNERSHIP_MANUAL.values():
        assert "manual-only" in note
        assert "reactivation" in note
        assert "carrier" in note
        assert "not conclusive" in note


def test_ownership_ids_are_all_marked_critical_in_checklist():
    by_id = {item["id"]: item for item in CHECKLIST}
    assert all(by_id[check_id]["critical"] for check_id in OWNERSHIP_MANUAL)


# ------------------------------------------------------------------ json export

def test_evaluate_v4_json_is_evaluate_v4_plus_checklist_version():
    data = _answered()
    data["checks"]["display_touch"]["status"] = "fail"
    payload = evaluate_v4_json(data)
    expected = evaluate_v4(data)
    assert payload["checklist_version"] == CHECKLIST_VERSION
    assert set(payload) == set(expected) | {"checklist_version"}
    assert all(payload[key] == expected[key] for key in expected)


def test_evaluate_v4_json_does_not_mutate_or_alias_the_engine_result():
    payload = evaluate_v4_json(_answered())
    payload["critical_unknown"].append("injected")
    assert "injected" not in evaluate_v4(_answered())["critical_unknown"]


# ------------------------------------------------------------------ repair case export

def test_case_to_json_shape():
    case = new_case("CASE-4", device_hint="iPhone 12", customer_symptoms="no charge",
                    authorized_scope="repair-and-return")
    record_work(case, "charging port flex", part_source="OEM", notes="replaced")
    payload = case_to_json(case)
    assert set(payload) == {"case_id", "status", "device_hint", "symptoms",
                            "authorized_scope", "work_performed", "qa"}
    assert payload["case_id"] == "CASE-4"
    assert payload["status"] == "open"
    assert payload["device_hint"] == "iPhone 12"
    assert payload["symptoms"] == "no charge"
    assert payload["authorized_scope"] == "repair-and-return"
    assert payload["work_performed"][0]["part"] == "charging port flex"
    assert payload["qa"]["total"] == 14


def test_case_to_json_omits_comparison_until_one_exists():
    assert "comparison_overall" not in case_to_json(new_case("CASE-4"))
    case = new_case("CASE-4")
    case["comparison"] = {"status": "incomplete", "note": "both reports required"}
    assert "comparison_overall" not in case_to_json(case)
    case["comparison"] = {"overall": "consistent", "classifications": {}}
    assert case_to_json(case)["comparison_overall"] == "consistent"


def test_case_to_json_does_not_mutate_the_case():
    case = new_case("CASE-4")
    payload = case_to_json(case)
    payload["work_performed"].append({"part": "injected"})
    assert case["work_performed"] == []


def test_case_to_json_carries_no_raw_report_paths_or_notes():
    case = new_case("CASE-4")
    case["pre_repair_baseline"] = "/private/tmp/pre.json"
    case["post_repair_report"] = "/private/tmp/post.json"
    case["technician_notes"] = "customer suspected water damage"
    assert not any("/private/tmp" in str(v) for v in case_to_json(case).values())


# ------------------------------------------------------------------ QA roll-up

def test_qa_ready_for_customer_requires_all_fourteen_checks_pass():
    case = new_case("CASE-4")
    summary = qa_summary(case)
    assert summary["total"] == 14
    assert summary["ready_for_customer"] is False
    for check in case["qa_checks"]:
        case["qa_checks"][check] = "pass"
    assert qa_summary(case)["ready_for_customer"] is True


@pytest.mark.parametrize("broken", ["not_tested", "fail"])
def test_qa_single_unfinished_check_withholds_ready_for_customer(broken):
    case = new_case("CASE-4")
    for check in case["qa_checks"]:
        case["qa_checks"][check] = "pass"
    case["qa_checks"]["Customer-reported symptoms individually re-tested "
                          "and resolved or documented"] = broken
    summary = qa_summary(case)
    assert summary["ready_for_customer"] is False
    assert summary[broken if broken == "not_tested" else "fail"] == 1
    assert case_to_json(case)["qa"] == summary