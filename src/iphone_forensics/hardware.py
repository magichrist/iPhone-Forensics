"""Hardware evidence normalization and subsystem health assessment.

Normalizes only what genuinely exists in collected evidence (ideviceinfo plist
keys, GasGauge/NAND diagnostics, IORegistry dumps). Missing information becomes
an explicit `not_tested`/`unsupported`/`inconclusive` status — never a pass and
never an invented measurement.
"""
from __future__ import annotations

from typing import Any

from .models import SubsystemCheck

BYTES_PER_GB_DECIMAL = 1_000_000_000

# Documented in Apple's OWN support pages and device About screens; these are
# real thresholds a human can also check, not invented ML-style limits.
# Where a threshold is heuristic, that is labeled in `expected`.
BATTERY_SERVICE_HINTS = (
    ("maximum capacity", "Battery Health maximum capacity is at or below the service threshold (Apple shows a service notice)."),
    ("service", "Battery Health shows a service message."),
)

STORAGE_SERVICE_HINTS = (
    ("disk", "Storage-related diagnostic entry."),
    ("nand", "NAND-related diagnostic entry."),
)

THERMAL_PATTERN_HINTS = (
    "thermal", "temperature", "overheat", "thermaldie",
)

PANIC_HINTS = ("panic", "resetcounter", "watchdog")

# Panic-string keyword buckets per subsystem. Every keyword is lowercase and
# whitespace-free (matching lowercases the panicString; substrings must not
# carry their own padding). Tests in tests/test_hardware_keywords.py enforce
# this hygiene.
PANIC_KEYWORD_MAP: dict[str, tuple[str, ...]] = {
    "battery": ("battery", "power", "charge", "smc"),
    "storage": ("nand", "storage", "disk", "apfs"),
    "display": ("display", "backlight", "lcd", "oled"),
    "cameras": ("camera", "isp"),
    "biometrics": ("faceid", "touchid", "biometric", "secureenclave"),
    "connectivity_manual": ("wlan", "bluetooth", "baseband", "cellular"),
}


# --------------------------------------------------------------------- helpers

def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_bytes_to_gb(value: Any) -> float | None:
    number = _num(value)
    return round(number / BYTES_PER_GB_DECIMAL, 2) if number is not None else None


def find_candidate(candidates: list[dict[str, Any]], pattern: str) -> list[dict[str, Any]]:
    pat = pattern.lower()
    return [c for c in candidates if pat in str(c.get("key", "")).lower()]


# ------------------------------------------------------------------- battery

def battery_checks(report: dict[str, Any]) -> list[SubsystemCheck]:
    checks: list[SubsystemCheck] = []

    # 1. Cycle count from GasGauge diagnostics if the device exposed it.
    cycle = find_candidate(report.get("diagnostic_candidates", []), "yclecount") or \
            find_candidate(report.get("diagnostic_candidates", []), "ycle count")
    value = _num(cycle[0].get("value")) if cycle else None
    check = SubsystemCheck(
        subsystem="battery",
        question="Battery cycle count as exposed by the device diagnostics relay",
        test="idevicediagnostics diagnostics GasGauge (when supported)",
        source="GasGauge diagnostic candidate" if cycle else "",
        measurement=value,
        measurement_unit="cycles" if value is not None else "",
        expected="Apple does not publish a universal cycle limit; iOS surfaces a service notice when warranted.",
        observed=f"CycleCount={int(value)}" if value is not None else "",
        status="pass_with_warnings" if (value is not None and value >= 500) else
               ("pass" if value is not None else "not_tested"),
        confidence="medium" if value is not None else "none",
        explanation="Cycle count is a wear indicator. Compare with the buyer-reported age of the phone.",
    )
    if value is None:
        check.explanation = ("The connected device/tool combination did not expose a cycle count through "
                             "supported diagnostics. Verify manually in Settings → Battery → Battery Health & Charging.")
        check.requires_hands_on = True
    if value is not None and value >= 500:
        check.severity = "REVIEW"
        check.next_test = "Confirm Battery Health percentage in Settings and record it in the buyer checklist."
        check.alternatives = ["Long ownership is legitimate; high cycle count alone is not a fault."]
    checks.append(check)

    # 2. Max capacity if exposed.
    cap = find_candidate(report.get("diagnostic_candidates", []), "maximumfacapacity") or \
          find_candidate(report.get("diagnostic_candidates", []), "fullchargecapacity") or \
          find_candidate(report.get("diagnostic_candidates", []), "designcapacity")
    capacity = _num(cap[0].get("value")) if cap else None
    cap_check = SubsystemCheck(
        subsystem="battery",
        question="Battery maximum (full-charge) capacity when the device exposes it",
        test="GasGauge / All diagnostics via idevicediagnostics (when supported)",
        source=cap[0].get("source", "") if cap else "",
        measurement=capacity,
        measurement_unit="%" if capacity is not None and capacity <= 150 else "mAh (raw)" if capacity is not None else "",
        expected="Interpret only against this device's model-specific documentation; units vary by field and firmware.",
        observed=f"MaxCapacity={capacity}" if capacity is not None else "",
        status="inconclusive" if capacity is not None else "not_tested",
        confidence="low" if capacity is not None else "none",
        explanation=("Raw capacity fields need unit verification against the tool version; do not treat an "
                     "unlabeled number as a percentage of design capacity."),
    )
    if capacity is None:
        cap_check.explanation = ("Device did not expose a capacity figure through supported diagnostics. "
                                 "Ask the seller to show Settings → Battery → Battery Health & Charging and record it manually.")
        cap_check.requires_hands_on = True
    checks.append(cap_check)
    return checks


# ------------------------------------------------------------------- storage

def storage_checks(report: dict[str, Any]) -> list[SubsystemCheck]:
    device = report.get("device", {}) if isinstance(report.get("device"), dict) else {}
    total = device.get("TotalDiskCapacity")
    data = device.get("TotalDataCapacity")
    total_gb = normalize_bytes_to_gb(total)
    data_gb = normalize_bytes_to_gb(data)
    checks: list[SubsystemCheck] = [SubsystemCheck(
        subsystem="storage",
        question="Total physical storage capacity as reported by iOS",
        test="ideviceinfo (TotalDiskCapacity)",
        source="device-info plist",
        measurement=total_gb,
        measurement_unit="decimal GB (normalized from bytes)",
        expected="Matches the advertised tier (16/32/64/128/256/512 GB / 1 TB families).",
        observed=f"{total_gb} GB" if total_gb is not None else "",
        status="pass_with_warnings" if total_gb is not None else "not_tested",
        confidence="medium" if total_gb is not None else "none",
        explanation=("This is the iOS-reported value. Capture a photo of Settings → General → iPhone Storage and "
                     "About for cross-confirmation; a mismatch with the listing suggests an incorrect advertisement "
                     "or, rarely, firmware/identifier tampering — investigate, don't accuse."),
        alternatives=["Advertised tier may have been listed incorrectly by the seller."],
        requires_hands_on=total_gb is None,
    ), SubsystemCheck(
        subsystem="storage",
        question="Usable data capacity vs physical capacity (heuristic NAND-consistency hint)",
        test="Derived comparison of TotalDiskCapacity vs TotalDataCapacity",
        source="device-info plist",
        measurement=data_gb,
        measurement_unit="decimal GB",
        expected="Data capacity should be somewhat below disk capacity on every real device.",
        observed=f"disk={total_gb} GB, data={data_gb} GB" if total_gb is not None or data_gb is not None else "",
        status="pass_with_warnings" if (total_gb and data_gb and data_gb < total_gb) else
               ("degraded" if (total_gb and data_gb and data_gb >= total_gb) else "not_tested"),
        confidence="low",
        severity="WARNING" if (total_gb and data_gb and data_gb >= total_gb) else "INFO",
        explanation=("iOS reports these fields from different subsystems. A data value >= disk value is unexpected "
                     "and warrants manual verification in Settings, but is not by itself proof of a counterfeit device."),
        alternatives=["iOS-version-specific reporting differences."],
    )]
    # NAND diagnostic hints, if the device exposed any.
    nand = find_candidate(report.get("diagnostic_candidates", []), "nand") + \
           find_candidate(report.get("diagnostic_candidates", []), "disk.?capacity")
    if nand:
        checks.append(SubsystemCheck(
            subsystem="storage",
            question="NAND/storage diagnostic entries exposed by the device",
            test="diagnostics All / NAND via idevicediagnostics (when supported)",
            source="diagnostics candidates",
            measurement=nand[:5],
            status="inconclusive",
            confidence="low",
            explanation="Entries matched keyword heuristics only; their meaning depends on firmware and tool version.",
            severity="REVIEW",
        ))
    return checks


# ------------------------------------------------------------------- display / cameras / biometrics

MANUAL_SUBSYSTEMS = {
    "display": ("Display, touch, brightness, dead pixels, burn-in, discoloration, True Tone responsiveness",
                "Structured physical test: full-white/full-black/screen grids; touch every corner and midpoints; "
                "compare brightness at low/high settings; check for uneven tint and image retention."),
    "cameras": ("Front/rear cameras, ultra-wide/telephoto where present, autofocus, OIS, flash, lens switching",
                "Open Camera, take photos with each lens, tap-to-focus near/far, record a short video while panning, "
                "toggle flash, switch between 0.5×/1×/2×+ and check for dust, blur, color casts."),
    "biometrics": ("Face ID or Touch ID enrollment and unlock reliability",
                   "Enroll a fresh Face ID/Touch ID record and unlock several times in different lighting/angles. "
                   "Never store or extract biometric templates; this check is functional only."),
    "audio": ("Microphones (bottom, front, rear), earpiece, loudspeaker, call audio routing",
              "Record a voice memo and play it back; test speakerphone; test each mic path (voice memo uses bottom "
              "mic, video uses front/rear mics); play tones at full and low volume."),
    "connectivity_manual": ("Wi-Fi, Bluetooth, cellular, GPS, NFC where the model has it",
                            "Join a known-good Wi-Fi; pair a Bluetooth accessory; check cellular signal and a test "
                            "call; confirm Maps shows a GPS fix; test Apple Pay tap where practical."),
    "buttons_haptics": ("Side button, volume buttons, Action/mute switch where present, vibration, haptics",
                        "Press each button and confirm the expected on-screen behavior; toggle silent mode and feel "
                        "the haptic; enable keyboard haptics."),
    "charging_manual": ("Wired charging, data transfer, wireless charging (MagSafe/Qi) where supported",
                        "Connect a data-capable cable and confirm charging starts and a file/photo transfer works "
                        "or the device appears in Finder; place on a Qi/MagSafe pad and confirm charge begins. "
                        "Wiggle the cable to detect intermittent contacts."),
    "thermal": ("Sustained-load thermal behavior",
                "Record video for 10+ minutes at max brightness with the phone plugged in; note any abrupt "
                "shutdown, persistent surface heat, or sustained 'temperature' warning."),
    "sensors": ("Proximity, ambient light, accelerometer/gyroscope, compass, LiDAR where present",
                "Cover the top of the screen during a call to verify proximity; auto-brightness should adapt; "
                "open Compass/Measure app and check orientation tracking."),
}


def manual_subsystem_checks() -> list[SubsystemCheck]:
    """Real physical inspection items — the tool cannot fake these results."""
    return [SubsystemCheck(
        subsystem=name,
        question=f"Manual guided test: {title}",
        status="not_tested",
        test=procedure,
        source="human observation",
        confidence="none",   # confidence is assigned only after the human records the result
        requires_hands_on=True,
        explanation="Software cannot substitute for a physical test here. Record the result in the buyer checklist.",
    ) for name, (title, procedure) in MANUAL_SUBSYSTEMS.items()]


# --------------------------------------------------------------------- main assessment

def assess_hardware(report: dict[str, Any]) -> dict[str, Any]:
    """Build the full hardware-health assessment from collected evidence."""
    checks = battery_checks(report) + storage_checks(report) + manual_subsystem_checks()

    # Crash/panic evidence feeds battery, storage, thermal, and general subsystem status.
    triage = report.get("crash_triage", {})
    panic_candidates = triage.get("panic_candidates", [])
    thermal_panics = [p for p in panic_candidates
                      if any(h in str(p.get("panicString", "")).lower()
                             for h in THERMAL_PATTERN_HINTS)]
    if thermal_panics:
        checks.append(SubsystemCheck(
            subsystem="thermal",
            question="Thermal/overheat events in collected panic artifacts",
            status="inconclusive", confidence="low", severity="REVIEW",
            measurement=thermal_panics[:5],
            test="panic-content keyword triage",
            source="crash/panic artifacts",
            explanation=("Panic strings matching thermal keywords suggest thermal events but are heuristics; "
                         "firmware versions and transient load can trigger them on healthy devices."),
            alternatives=["Sustained heavy load", "hot environment", "known firmware quirks"],
            next_test="Repeat a sustained-load test and watch for a recurrence.",
        ))
    panic_by_subsystem: dict[str, list[dict[str, Any]]] = {}
    for subsystem, keywords in PANIC_KEYWORD_MAP.items():
        matches = [p for p in panic_candidates
                   if any(k in str(p.get("panicString", "")).lower() for k in keywords)]
        if matches:
            panic_by_subsystem[subsystem] = matches[:10]

    existing = [c.subsystem for c in checks]
    for subsystem, matches in panic_by_subsystem.items():
        if subsystem in existing:
            continue
        checks.append(SubsystemCheck(
            subsystem=subsystem,
            question=f"Panic/crash artifacts referencing {subsystem} subsystem",
            status="inconclusive", confidence="low", severity="REVIEW",
            measurement=matches,
            test="panic-content keyword triage",
            source="crash/panic artifacts",
            explanation=("A keyword match in a panic string is a weak heuristic. Correlate for recurrence "
                         "and look for matching manual-test failures before drawing any hardware conclusion."),
            alternatives=["App bugs", "firmware issues", "storage pressure", "coincidental wording"],
        ))

    # Aggregate per-subsystem summary. Never collapse to a single numeric score.
    subsystems: dict[str, dict[str, Any]] = {}
    for check in checks:
        entry = subsystems.setdefault(check.subsystem, {"statuses": [], "checks": 0})
        entry["statuses"].append(check.status)
        entry["checks"] += 1
    summary: dict[str, str] = {}
    for subsystem, entry in subsystems.items():
        statuses = entry["statuses"]
        evaluated = [s for s in statuses if s not in {"not_tested", "unsupported"}]
        if not evaluated:
            summary[subsystem] = "not_tested"
        elif "fail" in evaluated or "suspicious" in evaluated:
            summary[subsystem] = "fail"
        elif "degraded" in evaluated:
            summary[subsystem] = "degraded"
        elif "pass_with_warnings" in evaluated:
            summary[subsystem] = "pass_with_warnings"
        elif all(s == "pass" for s in evaluated):
            summary[subsystem] = "pass"
        else:
            summary[subsystem] = "inconclusive"

    warnings = [check.to_dict() for check in checks if check.severity in {"WARNING", "REVIEW"}]
    blockers = [check.to_dict() for check in checks if check.severity == "BLOCKER"]
    return {
        "subsystems": summary,
        "checks": [c.to_dict() for c in checks],
        "warnings": warnings,
        "blockers": blockers,
        "panic_by_subsystem": panic_by_subsystem,
        "disclaimer": ("Missing data is unknown, not a pass. A Battery Health figure shown by iOS is an Apple-reported "
                       "figure, not an independent measurement. No checklist here certifies authenticity, health, or "
                       "water resistance."),
    }
