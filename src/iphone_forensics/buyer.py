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
    "GOOD_CANDIDATE",          # critical+standard checks pass (nothing recorded failed)
    "BUY_ONLY_AFTER_REPAIR",   # non-critical failures; repair cost/return terms decide
    "INVESTIGATE_FURTHER",     # unresolved checks or unexplained discrepancies
    "AVOID_PURCHASE",          # a buyer-critical ownership/eligibility barrier failed
    "INSUFFICIENT_EVIDENCE",   # too little was actually tested to say anything
)

CHECKLIST: list[dict[str, Any]] = [
    {"id":"activation_lock","category":"Ownership & activation","label":"Seller erased device; buyer can proceed through online activation without previous-owner credentials","critical":True},
    {"id":"remote_management","category":"Ownership & activation","label":"No unexpected Remote Management / organization enrollment screen","critical":True},
    {"id":"management_profiles","category":"Security & management","label":"VPN & Device Management / configuration profiles reviewed and understood","critical":False},
    {"id":"carrier_eligibility","category":"Network & ownership","label":"Carrier confirms IMEI eligibility and intended carrier compatibility","critical":True},
    {"id":"carrier_lock","category":"Network & ownership","label":"Carrier Lock status checked in Settings → General → About","critical":False},
    {"id":"parts_history","category":"Repairs & identity","label":"Parts & Service History reviewed and discussed with seller","critical":False},
    {"id":"battery_health","category":"Battery","label":"Battery Health maximum capacity and service messages reviewed","critical":False},
    {"id":"display_touch","category":"Physical & functional tests","label":"Display, brightness, dead pixels, and touch grid tested","critical":False},
    {"id":"face_id","category":"Physical & functional tests","label":"Face ID setup/unlock tested successfully","critical":False},
    {"id":"cameras","category":"Physical & functional tests","label":"Front camera and each rear camera, autofocus, flash, and video tested","critical":False},
    {"id":"audio","category":"Physical & functional tests","label":"Microphones, earpiece, loudspeaker, and recorded playback tested","critical":False},
    {"id":"buttons_haptics","category":"Physical & functional tests","label":"Buttons, Action button, vibration/haptics, and mute behavior tested","critical":False},
    {"id":"charging_usb","category":"Physical & functional tests","label":"USB-C charging/data connection and cable fit tested","critical":False},
    {"id":"wireless","category":"Connectivity","label":"Wi-Fi and Bluetooth connected to known-good accessories/networks","critical":False},
    {"id":"cellular","category":"Connectivity","label":"Calls, mobile data, and SIM/eSIM behavior tested with compatible service","critical":False},
    {"id":"gps_nfc","category":"Connectivity","label":"Location services and NFC use-case tested where practical","critical":False},
    {"id":"physical_damage","category":"Physical condition","label":"Frame, glass, camera lenses, port, seams, corrosion, and repair signs inspected","critical":False},
    {"id":"liquid_exposure","category":"Physical condition","label":"Visible liquid indicators inspected if accessible; seller disclosure recorded","critical":False},
    {"id":"storage_claim","category":"Identity & storage","label":"Storage tier matches listing and Settings → General → About","critical":False},
    {"id":"icloud_signout","category":"Ownership & activation","label":"Seller signed out of their Apple Account / Find My before erase","critical":True},
    {"id":"price_receipt","category":"Transaction","label":"Price, receipt/proof of sale, return terms, and seller identity recorded appropriately","critical":False},
]

# The four buyer-critical ownership/eligibility items, and the reason they can
# never be automated. These ids are a subset of CHECKLIST (each has
# critical=True); the constant is documentation, not a second source of truth —
# nothing in the verdict engine reads it.
OWNERSHIP_MANUAL: dict[str, str] = {
    check_id: (
        "manual-only: seller-erase + reactivation + carrier check; "
        "Mac query not conclusive"
    )
    for check_id in ("activation_lock", "remote_management",
                     "carrier_eligibility", "icloud_signout")
}


def template() -> dict[str, Any]:
    return {
        "buyer": {"asking_price": None, "currency": "USD", "country_or_region": "", "advertised_model": "",
                  "advertised_storage": "", "seller_notes": ""},
        "checks": {item["id"]: {"status": "not_tested", "notes": ""} for item in CHECKLIST},
        "observations": {"battery_max_capacity_percent": None, "battery_cycle_count": None,
                         "reported_storage_gb": None, "repair_estimate": None,
                         "carrier_eligibility_result": "not_checked"},
    }


def evaluate_v4(checklist_data: dict[str, Any] | None) -> dict[str, Any]:
    """v4 buyer verdict with enum + transparent rule trace.

    Rules (transparent, in order):
      1. ADFirmed buyer-critical failure → AVOID_PURCHASE.
         A single unverified suspicion does NOT condemn: only recorded `fail`
         statuses on critical items trigger this.
      2. Any critical item still not answered (not_tested/not_applicable) and
         fewer than 3 checks recorded at all → INSUFFICIENT_EVIDENCE.
      3. Remaining critical unknowns → INVESTIGATE_FURTHER.
      4. Non-critical failures only → BUY_ONLY_AFTER_REPAIR.
      5. No failures recorded → GOOD_CANDIDATE, explicitly NOT a certification.
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
        if not isinstance(status, str):   # hand-edited JSON can hold a dict/list/None
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

    if critical_failures:
        verdict = "AVOID_PURCHASE"
        rule = "rule 1: buyer-critical check recorded as FAIL"
    elif len(resolved) + len(failed_any) < 3:
        verdict = "INSUFFICIENT_EVIDENCE"
        rule = "rule 2: fewer than 3 checklist items were actually answered"
    elif critical_unknown:
        verdict = "INVESTIGATE_FURTHER"
        rule = "rule 3: buyer-critical checks remain unverified"
    elif noncritical_failures:
        verdict = "BUY_ONLY_AFTER_REPAIR"
        rule = "rule 4: non-critical checks failed; weigh repair cost and return terms"
    else:
        verdict = "GOOD_CANDIDATE"
        rule = "rule 5: no failures recorded in the supplied checklist"

    could_change = sorted(set(critical_unknown + noncritical_failures))
    return {
        "verdict": verdict,
        "rule": rule,
        "critical_failures": critical_failures,
        "critical_unknown": critical_unknown,
        "noncritical_failures": noncritical_failures,
        "unresolved_checks_that_could_change_verdict": could_change,
        "certification_disclaimer": (
            "GOOD_CANDIDATE means no failures are recorded in the supplied checklist. "
            "It is not a certification of authenticity, hardware health, or the absence "
            "of hidden defects."),
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


def evaluate(checklist_data: dict[str, Any] | None) -> dict[str, Any]:
    data = checklist_data or template()
    checks = data.get("checks", {}) if isinstance(data, dict) else {}
    counts = {"pass": 0, "fail": 0, "not_tested": 0, "not_applicable": 0}
    critical_failures = []
    failures = []
    critical_unknowns = []
    for item in CHECKLIST:
        entry = checks.get(item["id"], {}) if isinstance(checks, dict) else {}
        status = entry.get("status", "not_tested") if isinstance(entry, dict) else "not_tested"
        if not isinstance(status, str):   # hand-edited JSON can hold a dict/list/None
            status = "not_tested"
        if status not in {"pass", "fail", "not_tested", "not_applicable"}:
            status = "not_tested"
        counts[status] += 1
        if status == "fail":
            failures.append(item["label"])
            if item["critical"]:
                critical_failures.append(item["label"])
        if item["critical"] and status in {"not_tested", "not_applicable"}:
            critical_unknowns.append(item["label"])
    if critical_failures:
        verdict = "HIGH RISK — DO NOT PAY YET"
        explanation = "At least one buyer-critical ownership or eligibility check failed. Resolve it with the seller/provider before paying."
    elif critical_unknowns:
        verdict = "INCOMPLETE — HOLD PAYMENT"
        explanation = "One or more buyer-critical checks remain unverified. Complete them before paying."
    elif failures:
        verdict = "REVIEW — NEGOTIATE OR INVESTIGATE"
        explanation = "At least one non-critical inspection item failed. Assess repair cost and return terms before deciding."
    else:
        verdict = "NO RECORDED FAILURES — NOT A CERTIFICATION"
        explanation = "No failures are recorded in the supplied checklist. This does not certify hardware health, authenticity, or absence of hidden issues."
    return {"verdict": verdict, "explanation": explanation, "counts": counts,
            "critical_failures": critical_failures, "critical_unknowns": critical_unknowns,
            "failures": failures, "checks": CHECKLIST}
