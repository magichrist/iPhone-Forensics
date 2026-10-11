from iphone_forensics.buyer import CHECKLIST, evaluate, template


def test_template_has_all_checklist_items():
    data = template()
    assert set(data["checks"]) == {item["id"] for item in CHECKLIST}
    assert all(entry["status"] == "not_tested" for entry in data["checks"].values())


def test_unknown_critical_checks_hold_payment():
    """v4 rule engine: enough items answered, critical ones still unknown → hold."""
    data = template()
    for item in CHECKLIST:
        if item["id"] in {"battery_health", "cameras", "display_touch"}:
            data["checks"][item["id"]]["status"] = "pass"
    result = evaluate(data)
    assert result["verdict"] == "INCOMPLETE — HOLD PAYMENT"
    assert result["critical_unknowns"]
    assert result["rule_engine"]["fired"] == "buyer.critical_unknowns"


def test_fewer_than_three_answered_is_insufficient_evidence():
    """v4: rule 2 takes precedence over critical unknowns when barely answered."""
    data = template()
    data["checks"]["battery_health"]["status"] = "pass"
    result = evaluate(data)
    assert result["verdict"] == "INCOMPLETE — EVIDENCE GAPS REMAIN"
    assert result["rule_engine"]["fired"] == "buyer.insufficient_evidence"


def test_critical_failure_is_high_risk():
    data = template()
    data["checks"]["activation_lock"]["status"] = "fail"
    result = evaluate(data)
    assert result["verdict"] == "HIGH RISK — DO NOT PAY YET"
    assert result["critical_failures"]


def test_all_critical_pass_noncritical_fail_review():
    data = template()
    for item in CHECKLIST:
        if item["critical"]:
            data["checks"][item["id"]]["status"] = "pass"
    data["checks"]["display_touch"]["status"] = "fail"
    result = evaluate(data)
    assert result["verdict"] == "REVIEW — NEGOTIATE OR INVESTIGATE"


def test_invalid_status_treated_as_unknown():
    data = template()
    data["checks"]["activation_lock"]["status"] = "probably"
    result = evaluate(data)
    assert "activation_lock" not in result["critical_failures"]
    assert result["critical_unknowns"]


def test_partial_json_is_merged_with_default_checklist():
    defaults = template()
    partial = {"activation_lock": {"status": "pass", "notes": "checked"}}
    defaults["checks"].update(partial)
    assert defaults["checks"]["activation_lock"]["status"] == "pass"
    assert defaults["checks"]["remote_management"]["status"] == "not_tested"
