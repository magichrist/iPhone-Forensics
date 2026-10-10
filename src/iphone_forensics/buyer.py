from __future__ import annotations

from typing import Any

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


def template() -> dict[str, Any]:
    return {
        "buyer": {"asking_price": None, "currency": "USD", "country_or_region": "", "advertised_model": "",
                  "advertised_storage": "", "seller_notes": ""},
        "checks": {item["id"]: {"status": "not_tested", "notes": ""} for item in CHECKLIST},
        "observations": {"battery_max_capacity_percent": None, "battery_cycle_count": None,
                         "reported_storage_gb": None, "repair_estimate": None,
                         "carrier_eligibility_result": "not_checked"},
    }


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
