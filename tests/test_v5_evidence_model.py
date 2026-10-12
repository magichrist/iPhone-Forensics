"""Evidence trail + rule-engine prerequisites (docs/v5/05-evidence-analysis-model.md).

Two guarantees under test:

1. **Evidence trail** — every observation is bound to its collector, its timestamp,
   its unit, its interpretation, its thresholds (labelled heuristic vs documented),
   its limitations and its reasoning. Raw evidence stays separate from
   interpretation, and a missing value stays missing.

2. **Rule prerequisites** — a rule whose prerequisites are unmet does not fire, and
   that is recorded as `not_evaluated: missing <field>` rather than skipped
   silently.

Offline only.
"""

from __future__ import annotations

from pathlib import Path

from iphone_forensics import buyer, hardware, models

# ============================================================ 1. evidence trail


def _assess(**overrides) -> dict:
    report = {"diagnostic_candidates": [], "device": {}, "collection": [], "findings": []}
    report.update(overrides)
    return report


def test_battery_check_carries_a_full_evidence_trail():
    """A measured battery value must carry its unit, reasoning and limits."""
    result = hardware.assess_hardware(
        _assess(
            diagnostic_candidates=[
                {
                    "source": "idevicediagnostics GasGauge",
                    "key": "CycleCount",
                    "value": "812",
                    "caveat": "unit unverified",
                }
            ]
        )
    )
    check = next(
        c for c in result["checks"] if c["subsystem"] == "battery" and "ycle" in c["question"]
    )

    assert check["check_id"] == "battery.cycle_count", "a stable id is required"
    assert check["collector"], "the producing collector must be named"
    assert check["collected_at"], "collection time must be recorded"
    assert check["measurement"] == 812.0
    assert check["measurement_unit"] == "cycles"
    assert check["normalized_value"] is not None
    assert check["interpretation"], "a value needs an interpretation"
    # Thresholds must be labelled as heuristic or documented, never implied universal.
    assert "heuristic" in check["thresholds"].lower() or "documented" in check["thresholds"].lower()
    assert check["limitations"], "every observation states what it cannot establish"
    assert check["reasoning"], "the path to the interpretation must be shown"


def test_a_high_cycle_count_threshold_is_labelled_a_heuristic():
    """The 500-cycle threshold must never read as a documented Apple limit."""
    result = hardware.assess_hardware(
        _assess(
            diagnostic_candidates=[
                {"source": "GasGauge", "key": "CycleCount", "value": "900", "caveat": ""}
            ]
        )
    )
    check = next(c for c in result["checks"] if "ycle" in c["question"])
    assert "heuristic" in check["thresholds"].lower()
    assert "not documented" in check["thresholds"].lower()


def test_missing_battery_metric_has_no_measurement_but_keeps_its_trail():
    """A gap must stay a gap: no invented value, but the trail is still recorded."""
    result = hardware.assess_hardware(_assess())
    check = next(c for c in result["checks"] if "ycle" in c["question"])
    assert check["measurement"] is None
    assert check["status"] == "not_tested"
    assert check["check_id"] == "battery.cycle_count"
    assert check["interpretation"], "an absent value still needs an interpretation"
    assert "not evidence of a replacement" in check["limitations"]


def test_storage_checks_carry_stable_ids_and_collector():
    result = hardware.assess_hardware(
        _assess(device={"TotalDiskCapacity": 128_000_000_000, "TotalDataCapacity": 64_000_000_000})
    )
    ids = {check["check_id"] for check in result["checks"]}
    assert "storage.total_capacity" in ids
    assert "storage.data_vs_disk" in ids
    assert all(
        check["collector"] for check in result["checks"] if check["check_id"].startswith("storage.")
    )


def test_collected_at_is_a_real_utc_timestamp():
    from datetime import datetime

    result = hardware.assess_hardware(_assess(device={"TotalDiskCapacity": 128_000_000_000}))
    stamps = [c["collected_at"] for c in result["checks"] if c["collected_at"]]
    assert stamps, "collected checks must be timestamped"
    for stamp in stamps:
        datetime.fromisoformat(stamp)  # raises on a malformed timestamp


def test_trail_survives_a_dict_round_trip():
    """Old reports and JSON sidecars must still load with the new fields."""
    result = hardware.assess_hardware(
        _assess(
            diagnostic_candidates=[
                {"source": "GasGauge", "key": "CycleCount", "value": "120", "caveat": ""}
            ]
        )
    )
    check = result["checks"][0]
    restored = models.SubsystemCheck.from_dict(check)
    assert restored.check_id == check["check_id"]
    assert restored.collected_at == check["collected_at"]
    assert restored.interpretation == check["interpretation"]
    assert restored.previous_value == check["previous_value"]


def test_previous_value_is_only_populated_for_comparisons():
    """`previous_value` is a compare-run field; a normal run must not invent one."""
    result = hardware.assess_hardware(_assess())
    assert all(c["previous_value"] is None for c in result["checks"])


# =========================================================== 2. rule prerequisites


def _evaluate(checks: dict) -> dict:
    return buyer.evaluate_v4({"checks": checks})


def test_a_recorded_critical_failure_fires_rule_one():
    result = _evaluate({"activation_lock": {"status": "fail"}})
    assert result["verdict"] == "AVOID_PURCHASE"
    assert result["rule_engine"]["fired"] == "buyer.critical_failure"
    assert result["rule_engine"]["fired"] in result["rule"]


def test_fewer_than_three_answers_fires_the_insufficiency_rule():
    result = _evaluate({"battery_health": {"status": "pass"}})
    assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert result["rule_engine"]["fired"] == "buyer.insufficient_evidence"


def test_critical_unknowns_fire_the_investigation_rule():
    result = _evaluate(
        {
            "battery_health": {"status": "pass"},
            "cameras": {"status": "pass"},
            "physical_damage": {"status": "fail"},
        }
    )
    assert result["verdict"] == "INVESTIGATE_FURTHER"
    assert result["rule_engine"]["fired"] == "buyer.critical_unknowns"


def test_non_critical_failures_fire_the_repair_rule():
    """Every critical item must be answered, or rule 3 fires first — correctly."""
    result = _evaluate(
        {
            "activation_lock": {"status": "pass"},
            "remote_management": {"status": "pass"},
            "carrier_eligibility": {"status": "pass"},
            "icloud_signout": {"status": "pass"},
            "charging_usb": {"status": "fail"},
        }
    )
    assert result["verdict"] == "BUY_ONLY_AFTER_REPAIR"
    assert result["rule_engine"]["fired"] == "buyer.noncritical_failures"


def test_a_clean_checklist_fires_the_candidate_rule():
    checks = {item["id"]: {"status": "pass"} for item in buyer.CHECKLIST}
    result = _evaluate(checks)
    assert result["verdict"] == "GOOD_CANDIDATE"
    assert result["rule_engine"]["fired"] == "buyer.no_recorded_failures"


def test_an_empty_checklist_falls_back_to_insufficient_evidence():
    """Rule 5 must not fire without evidence — it has a prerequisite."""
    result = _evaluate({})
    assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert result["rule_engine"]["fired"] == "buyer.insufficient_evidence"


def test_the_candidate_rule_records_why_it_did_not_fire_without_evidence():
    """An unmet prerequisite must be visible, not silently skipped."""
    result = _evaluate({})
    trace = result["rule_engine"]["trace"]
    candidate = next(entry for entry in trace if entry["rule_id"] == "buyer.no_recorded_failures")
    assert candidate["status"] == "not_evaluated"
    assert candidate["missing"], "the missing prerequisite must be named"


def test_every_rule_trace_entry_cites_a_version():
    """docs/v5/05: each verdict cites rule id + rule version."""
    for checks in (
        {},
        {"battery_health": {"status": "fail"}},
        {item["id"]: {"status": "pass"} for item in buyer.CHECKLIST},
    ):
        for entry in _evaluate(checks)["rule_engine"]["trace"]:
            assert entry["rule_id"].startswith("buyer.")
            assert entry["rule_version"] == "1"
            assert entry["status"]


def test_rule_order_is_the_documented_contract():
    """First-match order is a contract; reordering would change verdicts."""
    assert [rule["id"] for rule in buyer.BUYER_RULES] == [
        "buyer.critical_failure",
        "buyer.insufficient_evidence",
        "buyer.critical_unknowns",
        "buyer.noncritical_failures",
        "buyer.no_recorded_failures",
    ]


def test_a_critical_failure_outranks_non_critical_failures():
    """Rule 1 beats rule 4 even when both conditions hold."""
    result = _evaluate({"activation_lock": {"status": "fail"}, "charging_port": {"status": "fail"}})
    assert result["verdict"] == "AVOID_PURCHASE"
    assert result["rule_engine"]["fired"] == "buyer.critical_failure"


# ============================================================ 3. wiring


def test_trail_reaches_the_written_report(tmp_path: Path):
    """The trail must survive to report.json, not die in memory."""
    import argparse
    import json

    from iphone_forensics.cli_v4 import _finish_run, _new_report

    run = tmp_path / "run"
    run.mkdir()
    from iphone_forensics.evidence import run_dir_paths

    paths = run_dir_paths(run, "20261011-090721")
    report = _new_report(
        argparse.Namespace(
            redact=False, compare_json=None, sensitive_consent=False, sensitive_explicit=[]
        )
    )
    report["diagnostic_candidates"] = [
        {"source": "GasGauge", "key": "CycleCount", "value": "300", "caveat": ""}
    ]
    report["device"] = {"TotalDiskCapacity": 128_000_000_000}
    args = argparse.Namespace(redact=False, compare_json=None)
    _finish_run(paths["run_dir"], report, {"checks": {}}, args)

    persisted = json.loads((paths["run_dir"] / "report.json").read_text(encoding="utf-8"))
    checks = persisted["hardware_assessment"]["checks"]
    assert checks, "hardware checks must be persisted"
    assert all("check_id" in check for check in checks)
    assert any(check["interpretation"] for check in checks)
