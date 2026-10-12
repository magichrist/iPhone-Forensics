"""Buyer-side inspection checklist and v4 verdict engine.

This module answers exactly one question: *given what a buyer actually recorded,
should they pay for this device right now?* It never infers a result — it
reasons over statuses the buyer (or a shop acting for them) entered by hand.

Statuses
--------
Four statuses are valid for every one of the 20 items in ``CHECKLIST``:

  ``pass``             the check was carried out and the outcome was acceptable
  ``fail``             the check was carried out and the outcome was not
  ``not_tested``       nobody has checked this yet (the template default)
  ``not_applicable``   the check does not apply to this device/seller context

Anything else — ``"probably"``, ``None``, a number, a nested object — is an
*invalid* status and is coerced to ``not_tested``. An unverifiable claim is
therefore never silently promoted to a pass and never silently becomes a fail:
it stays unknown, which is exactly what the verdict engine expects.

Verdicts (five, no more)
-----------------------
``AVOID_PURCHASE``        a buyer-critical ownership/eligibility check was
                          recorded ``fail`` — an affirmative barrier.
``INSUFFICIENT_EVIDENCE`` fewer than three items were answered at all, so there
                          is too little here to say anything.
``INVESTIGATE_FURTHER``   some critical items remain unknown (not tested/not
                          applicable) after enough was answered to comment.
``BUY_ONLY_AFTER_REPAIR`  nothing critical is broken, but non-critical items
                          failed; repair cost and return terms decide.
``GOOD_CANDIDATE``        nothing failed. Explicitly **not** a certification.

Rule order (first match wins — see ``evaluate_v4``)
--------------------------------------------------
  1. critical ``fail``                      → AVOID_PURCHASE
  2. fewer than 3 items answered            → INSUFFICIENT_EVIDENCE
  3. any remaining critical unknown         → INVESTIGATE_FURTHER
  4. any remaining non-critical failure     → BUY_ONLY_AFTER_REPAIR
  5. otherwise                              → GOOD_CANDIDATE

Because rule 1 fires on a *recorded* failure only, a single unverified
suspicion never condemns a device: it lands in ``critical_unknown`` and routes
to rule 3, which is the honest "go check this" answer.

Ownership honesty
-----------------
Activation Lock, Remote Management, carrier eligibility, and Apple Account
sign-out cannot be verified by this tool or by a paired Mac. They stay
manual-only (see ``OWNERSHIP_MANUAL``): the seller-erase plus reactivation
cycle and a carrier query are the only conclusive sources, and no CLI text in
this project may imply otherwise.

Notes and photos attached to a checklist are the buyer's own files under the
run directory. They are never collected, uploaded, or read automatically.
"""

from __future__ import annotations

from typing import Any

# Version stamped onto machine-readable verdict exports by evaluate_v4_json().
CHECKLIST_VERSION = "4.0.0"

# v4 buyer verdict enum. v3's human-readable verdict strings are preserved
# alongside for compatibility (see verdict_v3).
BUYER_VERDICTS = (
    "GOOD_CANDIDATE",  # critical+standard checks pass (nothing recorded failed)
    "BUY_ONLY_AFTER_REPAIR",  # non-critical failures; repair cost/return terms decide
    "INVESTIGATE_FURTHER",  # unresolved checks or unexplained discrepancies
    "AVOID_PURCHASE",  # a buyer-critical ownership/eligibility barrier failed
    "INSUFFICIENT_EVIDENCE",  # too little was actually tested to say anything
)

CHECKLIST: list[dict[str, Any]] = [
    {
        "id": "activation_lock",
        "category": "Ownership & activation",
        "label": "Seller erased device; buyer can proceed through online activation without previous-owner credentials",
        "critical": True,
    },
    {
        "id": "remote_management",
        "category": "Ownership & activation",
        "label": "No unexpected Remote Management / organization enrollment screen",
        "critical": True,
    },
    {
        "id": "management_profiles",
        "category": "Security & management",
        "label": "VPN & Device Management / configuration profiles reviewed and understood",
        "critical": False,
    },
    {
        "id": "carrier_eligibility",
        "category": "Network & ownership",
        "label": "Carrier confirms IMEI eligibility and intended carrier compatibility",
        "critical": True,
    },
    {
        "id": "carrier_lock",
        "category": "Network & ownership",
        "label": "Carrier Lock status checked in Settings → General → About",
        "critical": False,
    },
    {
        "id": "parts_history",
        "category": "Repairs & identity",
        "label": "Parts & Service History reviewed and discussed with seller",
        "critical": False,
    },
    {
        "id": "battery_health",
        "category": "Battery",
        "label": "Battery Health maximum capacity and service messages reviewed",
        "critical": False,
    },
    {
        "id": "display_touch",
        "category": "Physical & functional tests",
        "label": "Display, brightness, dead pixels, and touch grid tested",
        "critical": False,
    },
    {
        "id": "face_id",
        "category": "Physical & functional tests",
        "label": "Face ID setup/unlock tested successfully",
        "critical": False,
    },
    {
        "id": "cameras",
        "category": "Physical & functional tests",
        "label": "Front camera and each rear camera, autofocus, flash, and video tested",
        "critical": False,
    },
    {
        "id": "audio",
        "category": "Physical & functional tests",
        "label": "Microphones, earpiece, loudspeaker, and recorded playback tested",
        "critical": False,
    },
    {
        "id": "buttons_haptics",
        "category": "Physical & functional tests",
        "label": "Buttons, Action button, vibration/haptics, and mute behavior tested",
        "critical": False,
    },
    {
        "id": "charging_usb",
        "category": "Physical & functional tests",
        "label": "USB-C charging/data connection and cable fit tested",
        "critical": False,
    },
    {
        "id": "wireless",
        "category": "Connectivity",
        "label": "Wi-Fi and Bluetooth connected to known-good accessories/networks",
        "critical": False,
    },
    {
        "id": "cellular",
        "category": "Connectivity",
        "label": "Calls, mobile data, and SIM/eSIM behavior tested with compatible service",
        "critical": False,
    },
    {
        "id": "gps_nfc",
        "category": "Connectivity",
        "label": "Location services and NFC use-case tested where practical",
        "critical": False,
    },
    {
        "id": "physical_damage",
        "category": "Physical condition",
        "label": "Frame, glass, camera lenses, port, seams, corrosion, and repair signs inspected",
        "critical": False,
    },
    {
        "id": "liquid_exposure",
        "category": "Physical condition",
        "label": "Visible liquid indicators inspected if accessible; seller disclosure recorded",
        "critical": False,
    },
    {
        "id": "storage_claim",
        "category": "Identity & storage",
        "label": "Storage tier matches listing and Settings → General → About",
        "critical": False,
    },
    {
        "id": "icloud_signout",
        "category": "Ownership & activation",
        "label": "Seller signed out of their Apple Account / Find My before erase",
        "critical": True,
    },
    {
        "id": "price_receipt",
        "category": "Transaction",
        "label": "Price, receipt/proof of sale, return terms, and seller identity recorded appropriately",
        "critical": False,
    },
]

# The four buyer-critical ownership/eligibility items, and the reason they can
# never be automated. These ids are a subset of CHECKLIST (each has
# critical=True); the constant is documentation, not a second source of truth —
# nothing in the verdict engine reads it.
OWNERSHIP_MANUAL: dict[str, str] = {
    check_id: ("manual-only: seller-erase + reactivation + carrier check; Mac query not conclusive")
    for check_id in (
        "activation_lock",
        "remote_management",
        "carrier_eligibility",
        "icloud_signout",
    )
}


def template() -> dict[str, Any]:
    return {
        "buyer": {
            "asking_price": None,
            "currency": "USD",
            "country_or_region": "",
            "advertised_model": "",
            "advertised_storage": "",
            "seller_notes": "",
        },
        "checks": {item["id"]: {"status": "not_tested", "notes": ""} for item in CHECKLIST},
        "observations": {
            "battery_max_capacity_percent": None,
            "battery_cycle_count": None,
            "reported_storage_gb": None,
            "repair_estimate": None,
            "carrier_eligibility_result": "not_checked",
        },
    }


# ------------------------------------------------------------------ rule engine
# docs/v5/05-evidence-analysis-model.md: every rule carries an id, a version, the
# prerequisites it needs, when it fires, why, and the tests that pin it.
#
# A rule whose prerequisites are unmet does NOT fire. That is recorded as
# `not_evaluated: missing <field>` in the trace rather than silently skipping,
# so a reader can see exactly which piece of evidence would have let a different
# verdict through. The first matching rule wins; the order below is the contract.
# `prerequisites` maps a fact name to the minimum it must reach before the rule may
# fire: an integer means "at least this many" (list length or count), `True` means the
# boolean fact must hold. A rule whose prerequisites are unmet does not fire, and the
# trace records which field was missing — so the evidence that would change a verdict
# is visible rather than silently skipped.
BUYER_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "buyer.critical_failure",
        "version": "1",
        "prerequisites": {"critical_failures": 1},
        "fires_when": "critical_failures is non-empty",
        "rationale": (
            "A recorded failure on a buyer-critical item is the only condition that "
            "condemns the deal on its own. An unverified suspicion does NOT: only an "
            "explicit recorded `fail` triggers this rule."
        ),
        "outcome": "AVOID_PURCHASE",
    },
    {
        "id": "buyer.insufficient_evidence",
        "version": "1",
        "prerequisites": {"checklist_present": True},
        "fires_when": "fewer than 3 checklist items were answered at all",
        "rationale": (
            "With fewer than three answered items there is not enough signal to "
            "distinguish a bad phone from an unchecked one. Reporting a verdict here "
            "would be invented confidence."
        ),
        "outcome": "INSUFFICIENT_EVIDENCE",
    },
    {
        "id": "buyer.critical_unknowns",
        "version": "1",
        "prerequisites": {"no_critical_failure": True},
        "fires_when": "buyer-critical checks remain unverified",
        "rationale": (
            "Unverified critical items are the honest 'go and look' answer. They are "
            "not failures, so they must not condemn, and they are not passes, so they "
            "must not reassure."
        ),
        "outcome": "INVESTIGATE_FURTHER",
    },
    {
        "id": "buyer.noncritical_failures",
        "version": "1",
        "prerequisites": {"no_critical_unknown": True},
        "fires_when": "non-critical checks failed",
        "rationale": (
            "Non-critical failures make the phone worth negotiating on, not avoiding. "
            "The verdict points at price and repair terms rather than a verdict on the "
            "device itself."
        ),
        "outcome": "BUY_ONLY_AFTER_REPAIR",
    },
    {
        "id": "buyer.no_recorded_failures",
        "version": "1",
        "prerequisites": {"recorded_count": 3},
        "fires_when": "no failures were recorded in the supplied checklist",
        "rationale": (
            "Only a checklist with enough answered evidence may say 'no failures'. The "
            "result is a candidate, explicitly never a certification."
        ),
        "outcome": "GOOD_CANDIDATE",
    },
)


def _prerequisite_met(facts: dict[str, Any], field: str, requirement: Any) -> bool:
    """True when the fact *field* reaches *requirement*.

    An integer requirement means "at least this many" — the length of a list, or the
    value of a count. `True` means the boolean fact must hold. This is what makes a
    prerequisite a real gate rather than a presence check: a rule that needs three
    answered items does not fire on an empty checklist, and says so.
    """
    value = facts.get(field)
    if requirement is True:
        return value is True
    if isinstance(requirement, int) and not isinstance(requirement, bool):
        if isinstance(value, (list, tuple, set)):
            return len(value) >= requirement
        try:
            return int(value) >= requirement
        except (TypeError, ValueError):
            return False
    return bool(value)


def _prerequisites_met(facts: dict[str, Any]) -> dict[str, bool]:
    """Evaluate every rule's prerequisites up front, once.

    A rule is evaluable only when *all* of its prerequisites are met. The result is
    cached so the per-rule trace can report exactly which field was missing rather
    than implying a rule was considered and rejected.
    """
    met: dict[str, bool] = {}
    for rule in BUYER_RULES:
        met[rule["id"]] = all(
            _prerequisite_met(facts, field, requirement)
            for field, requirement in rule["prerequisites"].items()
        )
    return met


def _rule_fires(rule: dict[str, Any], facts: dict[str, Any]) -> bool:
    """The rule's own firing condition, evaluated against computed facts."""
    identifier = rule["id"]
    if identifier == "buyer.critical_failure":
        return bool(facts["critical_failures"])
    if identifier == "buyer.insufficient_evidence":
        return facts["recorded_count"] < 3
    if identifier == "buyer.critical_unknowns":
        return bool(facts["critical_unknown"])
    if identifier == "buyer.noncritical_failures":
        return bool(facts["noncritical_failures"])
    if identifier == "buyer.no_recorded_failures":
        return (not facts["failed_any"]) and facts["recorded_count"] >= 3
    return False


def evaluate_v4(checklist_data: dict[str, Any] | None) -> dict[str, Any]:
    """Buyer verdict from the rule engine: first matching rule wins.

    Each rule is evaluated against explicit prerequisites. A rule whose prerequisites
    are unmet is recorded as `not_evaluated: missing <field>` rather than skipped
    silently, so the trace shows exactly what evidence would have changed the verdict.
    The five outcomes and their order are unchanged from v4.
    """
    data = checklist_data or template()
    checks = data.get("checks", {}) if isinstance(data, dict) else {}
    resolved: list[str] = []
    failed_any: list[str] = []
    critical_failures: list[str] = []
    critical_unknown: list[str] = []
    noncritical_failures: list[str] = []
    for item in CHECKLIST:
        entry = checks.get(item["id"], {}) if isinstance(checks, dict) else {}
        status = entry.get("status", "not_tested") if isinstance(entry, dict) else "not_tested"
        if not isinstance(status, str):  # hand-edited JSON can hold a dict/list/None
            status = "not_tested"
        if status not in {"pass", "fail", "not_tested", "not_applicable"}:
            status = "not_tested"
        if status in {"pass", "not_applicable"}:
            resolved.append(item["id"])
        if status == "fail":
            failed_any.append(item["id"])
            if item["critical"]:
                critical_failures.append(item["id"])
            else:
                noncritical_failures.append(item["id"])
        if item["critical"] and status == "not_tested":
            critical_unknown.append(item["id"])

    # The facts every rule's prerequisites are evaluated against.
    facts: dict[str, Any] = {
        "critical_failures": critical_failures,
        "critical_unknown": critical_unknown,
        "noncritical_failures": noncritical_failures,
        "resolved": resolved,
        "failed_any": failed_any,
        "recorded_count": len(resolved) + len(failed_any),
        "no_critical_failure": not critical_failures,
        "no_critical_unknown": not critical_unknown,
        "checklist_present": isinstance(data, dict),
    }

    met = _prerequisites_met(facts)
    trace: list[dict[str, Any]] = []
    fired: dict[str, Any] | None = None
    for rule in BUYER_RULES:
        if not met.get(rule["id"], False):
            missing = sorted(
                field
                for field, requirement in rule["prerequisites"].items()
                if not _prerequisite_met(facts, field, requirement)
            )
            trace.append(
                {
                    "rule_id": rule["id"],
                    "rule_version": rule["version"],
                    "status": "not_evaluated",
                    "missing": missing or ["prerequisite not met"],
                    "reason": rule["rationale"],
                }
            )
            continue
        # The rule's prerequisites hold; its own firing condition decides.
        if _rule_fires(rule, facts):
            fired = fired or rule
            trace.append(
                {
                    "rule_id": rule["id"],
                    "rule_version": rule["version"],
                    "status": "fired",
                    "missing": [],
                    "reason": rule["rationale"],
                }
            )
            continue
        trace.append(
            {
                "rule_id": rule["id"],
                "rule_version": rule["version"],
                "status": "prerequisites_met_but_not_fired",
                "missing": [],
                "reason": rule["rationale"],
            }
        )

    verdict = fired["outcome"] if fired else "INSUFFICIENT_EVIDENCE"
    rule = (
        f"{fired['id']} v{fired['version']}: {fired['fires_when']}"
        if fired
        else "no rule fired; defaulting to INSUFFICIENT_EVIDENCE"
    )

    could_change = sorted(set(critical_unknown + noncritical_failures))
    return {
        "verdict": verdict,
        "rule": rule,
        "rule_engine": {"version": "1", "fired": fired["id"] if fired else None, "trace": trace},
        "critical_failures": critical_failures,
        "critical_unknown": critical_unknown,
        "noncritical_failures": noncritical_failures,
        # v3-compatible aliases, so callers written against the older shape keep
        # working while the rule engine carries the full trace.
        "critical_unknowns": critical_unknown,
        "failures": sorted(set(failed_any)),
        "unresolved_checks_that_could_change_verdict": could_change,
        "certification_disclaimer": (
            "GOOD_CANDIDATE means no failures are recorded in the supplied checklist. "
            "It is not a certification of authenticity, hardware health, or the absence "
            "of hidden defects."
        ),
    }


def evaluate_v4_json(checklist_data: dict[str, Any] | None) -> dict[str, Any]:
    """Machine-readable verdict export: the `evaluate_v4` payload plus a version.

    Purely additive — the verdict, rule, and every trace list come straight from
    `evaluate_v4` unchanged, so console and JSON output can never disagree. The
    only new field is `checklist_version`, so a stored verdict can be matched to
    the rules that produced it if the rule order ever changes.
    """
    result = dict(evaluate_v4(checklist_data))
    result["checklist_version"] = CHECKLIST_VERSION
    return result


# v4 enum verdict -> the v3 wording callers were written against. Kept as data so
# the two surfaces cannot drift apart silently.
_V3_VERDICT_WORDING = {
    "AVOID_PURCHASE": "HIGH RISK — DO NOT PAY YET",
    "INSUFFICIENT_EVIDENCE": "INCOMPLETE — EVIDENCE GAPS REMAIN",
    "INVESTIGATE_FURTHER": "INCOMPLETE — HOLD PAYMENT",
    "BUY_ONLY_AFTER_REPAIR": "REVIEW — NEGOTIATE OR INVESTIGATE",
    "GOOD_CANDIDATE": "NO RECORDED FAILURES — NOT A CERTIFICATION",
}

_V3_EXPLANATIONS = {
    "AVOID_PURCHASE": "At least one buyer-critical ownership or eligibility check failed. Resolve it with the seller/provider before paying.",
    "INSUFFICIENT_EVIDENCE": "Fewer than three checklist items were answered; there is not enough evidence to judge.",
    "INVESTIGATE_FURTHER": "One or more buyer-critical checks remain unverified. Complete them before paying.",
    "BUY_ONLY_AFTER_REPAIR": "At least one non-critical inspection item failed. Assess repair cost and return terms before deciding.",
    "GOOD_CANDIDATE": "No failures are recorded in the supplied checklist. This does not certify hardware health, authenticity, or absence of hidden issues.",
}


def evaluate(checklist_data: dict[str, Any] | None) -> dict[str, Any]:
    """v3-shaped verdict, now carrying the rule engine trace from `evaluate_v4`.

    The v4 verdict is translated back to the v3 wording so callers written against
    the older contract keep working unchanged, while the rule trace is preserved.
    """
    v4 = evaluate_v4(checklist_data)
    verdict = v4["verdict"]
    return {
        "verdict": _V3_VERDICT_WORDING.get(verdict, verdict),
        "explanation": _V3_EXPLANATIONS.get(verdict, ""),
        "counts": _count_statuses(checklist_data),
        "critical_failures": v4["critical_failures"],
        "critical_unknowns": v4["critical_unknowns"],
        "failures": v4["failures"],
        "checks": CHECKLIST,
        "rule": v4["rule"],
        "rule_engine": v4["rule_engine"],
    }


def _count_statuses(checklist_data: dict[str, Any] | None) -> dict[str, int]:
    data = checklist_data or template()
    checks = data.get("checks", {}) if isinstance(data, dict) else {}
    counts = {"pass": 0, "fail": 0, "not_tested": 0, "not_applicable": 0}
    for item in CHECKLIST:
        entry = checks.get(item["id"], {}) if isinstance(checks, dict) else {}
        status = entry.get("status", "not_tested") if isinstance(entry, dict) else "not_tested"
        if not isinstance(status, str):
            status = "not_tested"
        if status not in counts:
            status = "not_tested"
        counts[status] += 1
    return counts
