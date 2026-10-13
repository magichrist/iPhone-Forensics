"""Capability matrix as data (spec §3, §15; docs/v4/capability-matrix.md).

One entry per capability row: what this toolchain can answer, what it can only
hint at, what needs a guided human test, and what can never be established in
software. Pure data + tiny query helpers — no I/O, no dependencies. `cmd_capabilities`
and the report's "Unknown/unsupported" section consume this instead of a
hardcoded table.
"""

from __future__ import annotations

import re
from typing import Any

# Coverage levels (see docs/v4/capability-matrix.md):
#   automated    — tool answers directly
#   partial      — tool hints, human confirms
#   manual       — guided physical test; software cannot decide
#   unsupported  — cannot be established; never claim
COVERAGE_LEVELS = ("automated", "partial", "manual", "unsupported")

# Keep category names aligned with SubsystemCheck.subsystem values used by
# hardware.py where an equivalent exists (battery, storage, display, cameras,
# biometrics, connectivity, thermal, physical).
CAPABILITIES: list[dict[str, str]] = [
    # ---------------------------------------------------------------- identity
    {
        "category": "identity",
        "item": "ProductType / model / iOS version / build",
        "coverage": "automated",
        "source": "ideviceinfo plist",
        "requirements": "libimobiledevice installed; host trusted by the device",
        "limits": "Reported values are not proof of authenticity; a listing mismatch warrants investigation, not accusation.",
        "model_applicability": "All iPhone models supported by libimobiledevice.",
        "ios_applicability": "All iOS versions the installed tool version supports; very new iOS builds may lag tool support.",
    },
    {
        "category": "identity",
        "item": "Serial / IMEI / UDID / ECID",
        "coverage": "automated",
        "source": "ideviceinfo (when exposed)",
        "requirements": "Host trust; iOS may withhold individual identifiers",
        "limits": "Sensitive data — handle under data-minimization rules; a serial/IMEI never authenticates hardware.",
        "model_applicability": "IMEI only on cellular models; Wi-Fi-only models have no IMEI.",
        "ios_applicability": "Some iOS versions withhold ECID or parts of the serial from unauthenticated queries.",
    },
    {
        "category": "identity",
        "item": "Board / configuration variant",
        "coverage": "partial",
        "source": "device plist + diagnostics",
        "requirements": "Model-dependent field availability",
        "limits": "Fields vary by iOS and tool version; absence is not evidence of tampering.",
        "model_applicability": "HardwareModel/regional variant keys differ per model family.",
        "ios_applicability": "Key set changes between iOS builds; treat missing keys as not_tested.",
    },
    {
        "category": "identity",
        "item": "Provisioning / supervision state",
        "coverage": "partial",
        "source": "ideviceprovision / installed profiles",
        "requirements": "Provisioning tool present on the host",
        "limits": "MDM enrollment must be re-checked on-device after erase; host view can be stale.",
        "model_applicability": "All models.",
        "ios_applicability": "Profile visibility depends on iOS version and trust state.",
    },
    # ----------------------------------------------------------------- battery
    {
        "category": "battery",
        "item": "Cycle count",
        "coverage": "partial",
        "source": "GasGauge via idevicediagnostics",
        "requirements": "Device and tool combination must expose GasGauge",
        "limits": "Units vary; the 500-cycle review flag is a labeled heuristic, not an Apple-published limit.",
        "model_applicability": "Exposure of GasGauge fields is model- and firmware-dependent.",
        "ios_applicability": "Newer iOS versions increasingly restrict diagnostics relays; missing = not_tested, never pass.",
    },
    {
        "category": "battery",
        "item": "Max / full-charge / design capacity",
        "coverage": "partial",
        "source": "GasGauge capacity candidates",
        "requirements": "Same as cycle count (device + tool support)",
        "limits": "Raw numbers need unit verification; the iOS Battery Health percentage is an Apple-reported figure, not an independent measurement.",
        "model_applicability": "Capacity keys and units differ by model and firmware.",
        "ios_applicability": "Availability varies with iOS version; verify against Settings → Battery Health & Charging.",
    },
    {
        "category": "battery",
        "item": "Voltage / current / temperature / state",
        "coverage": "partial",
        "source": "Battery diagnostic candidates",
        "requirements": "Diagnostics relay supported on this device/tool pair",
        "limits": "Transient readings — a single sample is never conclusive in either direction.",
        "model_applicability": "Field availability varies per model.",
        "ios_applicability": "Often withheld on recent iOS builds.",
    },
    {
        "category": "battery",
        "item": "Drain / thermal history",
        "coverage": "partial",
        "source": "Panic/crash triage + recurrence analysis",
        "requirements": "Panic or crash artifacts present on the collected data",
        "limits": "A pattern suggests, never diagnoses; correlate recurrence before drawing conclusions.",
        "model_applicability": "All models, when artifacts exist.",
        "ios_applicability": "Artifact retention and format vary by iOS version.",
    },
    {
        "category": "battery",
        "item": "Wired / wireless charging function",
        "coverage": "manual",
        "source": "Guided test: cable fit, charge start, Qi/MagSafe pad, wiggle test",
        "requirements": "Human + known-good cable and charging pad",
        "limits": "Host USB pairing proves connectivity, not port or charging-circuit health.",
        "model_applicability": "Wireless charging requires a Qi/MagSafe-capable model.",
        "ios_applicability": "Charge-on-connect behavior can differ with iOS version and accessory certification.",
    },
    # ----------------------------------------------------------------- storage
    {
        "category": "storage",
        "item": "Total / data capacity",
        "coverage": "automated",
        "source": "TotalDiskCapacity / TotalDataCapacity → normalized decimal GB",
        "requirements": "ideviceinfo access (trust established)",
        "limits": "Marketed vs usable vs free capacity are distinguished; the query says nothing about NAND health.",
        "model_applicability": "All models exposing the plist keys; marketed tiers differ by model and year.",
        "ios_applicability": "Keys present across supported iOS versions; normalization assumes decimal GB.",
    },
    {
        "category": "storage",
        "item": "NAND telemetry / errors",
        "coverage": "partial",
        "source": "NAND diagnostics + crash triage",
        "requirements": "Device exposes storage diagnostics; artifacts collected",
        "limits": "Keyword heuristic only; entries depend on firmware wording and tool version.",
        "model_applicability": "Diagnostic key availability is model-dependent.",
        "ios_applicability": "Newer iOS versions expose fewer raw diagnostics.",
    },
    # ----------------------------------------------------------------- display
    {
        "category": "display",
        "item": "Component / calibration IDs",
        "coverage": "partial",
        "source": "Diagnostics / service keys if exposed",
        "requirements": "Model-dependent diagnostic exposure",
        "limits": "Often absent; absence is not evidence either way.",
        "model_applicability": "Service keys differ per display type (OLED/LCD) and model.",
        "ios_applicability": "Frequently withheld on recent iOS versions.",
    },
    {
        "category": "display",
        "item": "Dead pixels / touch / burn-in / brightness",
        "coverage": "manual",
        "source": "Full-white/black grids, touch every corner and midpoint, brightness sweep",
        "requirements": "Human eyes and hands; controlled lighting helps",
        "limits": "Software cannot judge pixels, touch response, tint, or image retention.",
        "model_applicability": "Procedures adapt to screen size and ProMotion capability.",
        "ios_applicability": "Test apps run on any supported iOS; no software shortcut exists.",
    },
    # ----------------------------------------------------------------- cameras
    {
        "category": "cameras",
        "item": "Init / errors / logs",
        "coverage": "partial",
        "source": "Crash triage (camera/isp keywords) + diagnostic candidates",
        "requirements": "Crash/panic artifacts present",
        "limits": "Weak heuristic; a keyword hit is not a camera fault and no hit is not a clean bill.",
        "model_applicability": "Lens count and ISP naming vary by model.",
        "ios_applicability": "Crash artifact wording varies by iOS version.",
    },
    {
        "category": "cameras",
        "item": "Focus / OIS / flash / lens quality",
        "coverage": "manual",
        "source": "Photo per lens, tap-focus near/far, video pan, flash toggle",
        "requirements": "Human judgment of image quality",
        "limits": "Software cannot judge sharpness, color cast, dust, or OIS behavior.",
        "model_applicability": "Test each lens the model actually has (ultra-wide/telephoto/LiDAR where present).",
        "ios_applicability": "Camera app behavior differs slightly per iOS version; procedure is unchanged.",
    },
    # -------------------------------------------------------------- biometrics
    {
        "category": "biometrics",
        "item": "Service errors",
        "coverage": "partial",
        "source": "Panic triage (faceid/touchid/secureenclave keywords)",
        "requirements": "Panic/crash artifacts present",
        "limits": "Cannot verify component pairing or origin; biometric templates are never extracted or stored.",
        "model_applicability": "Face ID vs Touch ID depends on model generation.",
        "ios_applicability": "Panic wording varies by iOS version.",
    },
    {
        "category": "biometrics",
        "item": "Enroll / unlock function",
        "coverage": "manual",
        "source": "Fresh enroll + repeated unlock in varied light and angles",
        "requirements": "Human; enrolled person present",
        "limits": "Functional test only — it says nothing about part originality or pairing state.",
        "model_applicability": "Face ID procedure on Face ID models; Touch ID on button models.",
        "ios_applicability": "Enrollment UI flow differs per iOS version.",
    },
    # ------------------------------------------------------------- connectivity
    {
        "category": "connectivity",
        "item": "USB pairing / data transfer",
        "coverage": "automated",
        "source": "idevicepair validate + photo/file transfer test",
        "requirements": "Data-capable cable; trust accepted on device",
        "limits": "Pairing success proves data lines, not mechanical port health or charging-circuit health.",
        "model_applicability": "Lightning vs USB-C port depends on model generation.",
        "ios_applicability": "Pairing dialog and trust cache behavior vary by iOS version.",
    },
    {
        "category": "connectivity",
        "item": "Wi-Fi / Bluetooth / cellular / GPS / NFC",
        "coverage": "manual",
        "source": "Join known-good Wi-Fi, pair BT accessory, test call, Maps GPS fix, Apple Pay tap",
        "requirements": "Human + network/SIM/BT accessory",
        "limits": "On-device only; no host-side substitute exists.",
        "model_applicability": "NFC/UWB/GPS capability varies by model; skip tests the model lacks.",
        "ios_applicability": "Settings paths shift between iOS versions.",
    },
    {
        "category": "connectivity",
        "item": "SIM / eSIM configuration",
        "coverage": "partial",
        "source": "Provisioning / carrier fields if exposed",
        "requirements": "Tool exposes carrier/SIM plist fields",
        "limits": "Carrier eligibility, blacklist, and lock status are separate manual checks.",
        "model_applicability": "eSIM support and dual-SIM behavior vary by model and region.",
        "ios_applicability": "Carrier field availability varies by iOS build.",
    },
    # ---------------------------------------------------------- audio / sensors
    {
        "category": "audio_sensors",
        "item": "Mics / speakers / buttons / haptics / proximity / light / compass",
        "coverage": "manual",
        "source": "Voice memo, tone playback, button press, cover test, Compass/Measure app",
        "requirements": "Human senses",
        "limits": "Panic triage may hint at a fault but never decides; software cannot hear or feel.",
        "model_applicability": "Action button / mute switch / LiDAR presence depends on model.",
        "ios_applicability": "Compass/Measure and haptics settings differ per iOS version.",
    },
    # ----------------------------------------------------------------- thermal
    {
        "category": "thermal",
        "item": "Overheat events",
        "coverage": "partial",
        "source": "Thermal diagnostic candidates + panic triage",
        "requirements": "Artifacts present; recurrence checked",
        "limits": "Context-dependent keyword matching; never fail on a single event; recurrence matters.",
        "model_applicability": "Thermal behavior and throttle thresholds are model-specific.",
        "ios_applicability": "Thermal warning UI and panic wording vary by iOS version.",
    },
    # ---------------------------------------------------------------- physical
    {
        "category": "physical",
        "item": "Damage / bend / gaps / lens / corrosion / port / swelling / screws / seals",
        "coverage": "manual",
        "source": "Visual inspection workflow",
        "requirements": "Human observation; good lighting",
        "limits": "Human-observed label only — the tool records what the human reports, never infers it.",
        "model_applicability": "All models; frame and screw patterns differ by generation.",
        "ios_applicability": "Not applicable — physical condition is independent of iOS.",
    },
    {
        "category": "physical",
        "item": "Water resistance / opened-before",
        "coverage": "unsupported",
        "source": "—",
        "requirements": "—",
        "limits": "No software method exists; never claim ingress protection or prior-opening status from tool output.",
        "model_applicability": "Applies to all models; ingress ratings differ per model but are unverifiable in software.",
        "ios_applicability": "Not applicable.",
    },
    # ------------------------------------------------------------ parts history
    {
        "category": "identity",
        "item": "Device clock vs host clock",
        "coverage": "partial",
        "source": "idevicedate (bare invocation only) compared with host UTC",
        "requirements": "libimobiledevice installed; host trust established",
        "limits": (
            "A skew of minutes is normal. A skew of days suggests the clock was set "
            "by hand, which is a legitimate thing to have done and only a hint about "
            "setup history — never proof of tampering. The mutating forms of this tool "
            "(-s, -c) are refused by the read-only guard."
        ),
        "model_applicability": "All models exposing the value.",
        "ios_applicability": "Always available to a trusted host.",
    },
    {
        "category": "parts_history",
        "item": "DeveloperDiskImage mount / developer mode state",
        "coverage": "partial",
        "source": "ideviceimagemounter list + devmodestatus",
        "requirements": "libimobiledevice installed; iOS 16+ for developer mode status",
        "limits": (
            "A mounted image or enabled developer mode hints at prior development or "
            "jailbreak activity. Developer use is legitimate and this is not a parts "
            "or repair record. Mount and unmount are refused by the read-only guard."
        ),
        "model_applicability": "All models; developer mode status requires iOS 16+.",
        "ios_applicability": "Both subcommands are query-only and available to a trusted host.",
    },
    {
        "category": "parts_history",
        "item": "Paired companion devices (Watch / AirPods)",
        "coverage": "partial",
        "source": "pymobiledevice3 companion list",
        "requirements": "pymobiledevice3 installed",
        "limits": (
            "Accessory pairing history the seller may not mention. Useful background "
            "for setup and for unpairing later; not evidence of tampering."
        ),
        "model_applicability": "All models.",
        "ios_applicability": "Requires a device that supports companion pairing.",
    },
    {
        "category": "parts_history",
        "item": "Apple Parts & Service History",
        "coverage": "manual",
        "source": "Settings → General → About (on-device)",
        "requirements": "Human with on-device access; seller cooperation",
        "limits": "Apple exposes this only on the device itself; no public pairing-state API exists for the host.",
        "model_applicability": "History section appears on models/iOS versions that support it.",
        "ios_applicability": "Introduced and renamed across iOS versions; absence on old iOS means unknown, not genuine.",
    },
    {
        "category": "parts_history",
        "item": "Component originality / parts pairing state",
        "coverage": "unsupported",
        "source": "—",
        "requirements": "—",
        "limits": "No public API exposes pairing state; the tool cannot independently verify originality of parts.",
        "model_applicability": "Part-pairing enforcement varies by model generation.",
        "ios_applicability": "Parts & Service History messaging varies by iOS version but stays on-device only.",
    },
    # ---------------------------------------------------------------- ownership
    {
        "category": "ownership",
        "item": "Activation Lock / Find My",
        "coverage": "partial",
        "source": "pymobiledevice3 activation state + seller erase / buyer reactivation",
        "requirements": (
            "pymobiledevice3 for the state query; seller cooperation + network access "
            "during reactivation for the decisive check"
        ),
        "limits": (
            "The host-side query reports the device's current activation state and is "
            "evidence, not a verdict. It does not exercise the full Setup Assistant "
            "flow, the device can report differently before and after an erase, and "
            "only the seller's erase followed by your own reactivation decides."
        ),
        "model_applicability": "All models.",
        "ios_applicability": "Activation screens and sign-out flow differ per iOS version.",
    },
    {
        "category": "ownership",
        "item": "Remote management / supervision",
        "coverage": "manual",
        "source": "Setup screens + Settings → VPN & Device Management",
        "requirements": "Human on-device check after erase",
        "limits": "Must be verified after erase — a previously hidden MDM profile can reappear during setup.",
        "model_applicability": "All models.",
        "ios_applicability": "Settings path and setup-assistant wording vary per iOS version.",
    },
    {
        "category": "ownership",
        "item": "Carrier lock / blacklist / financing",
        "coverage": "manual",
        "source": "Carrier check or authoritative IMEI blacklist lookup",
        "requirements": "Carrier access or a trusted IMEI check service",
        "limits": "Lock status, blacklist status, and financing status are distinct checks — never conflate them.",
        "model_applicability": "Carrier-lock policy differs by model and region.",
        "ios_applicability": "Not applicable — carrier state is independent of iOS version.",
    },
    # ------------------------------------------------------------------ malware
    {
        "category": "malware",
        "item": "Known indicators in backup",
        "coverage": "partial",
        "source": "mvt-ios check-backup (if installed), user-supplied indicators",
        "requirements": "Authorized backup + user-supplied indicator set; mvt-ios optional and never auto-downloaded",
        "limits": "No hit ≠ clean; a hit ≠ conviction; no indicator file is fetched or uploaded automatically.",
        "model_applicability": "All models with a computer-backup capability.",
        "ios_applicability": "Backup format and accessible data change per iOS version.",
    },
]


# ----------------------------------------------------------------- claim matrix
# docs/v5/06-authenticity-honesty.md. Deep investigation, modest claims.
#
# Each entry states what evidence a claim requires, and — just as importantly —
# what must be said instead when that evidence is absent. Anything not listed as
# permitted is not claimed: absence of evidence is reported as unknown, never
# upgraded into a healthy verdict or an accusation.
CLAIM_MATRIX: list[dict[str, str]] = [
    {
        "claim": "identifier_reported",
        "requires": "The field is present in output from a named collector.",
        "otherwise": "unknown: state that the field was not collected; make no claim.",
    },
    {
        "claim": "battery_metric",
        "requires": "A unit-verified candidate with its source cited.",
        "otherwise": (
            "inconclusive: say the value is unlabelled and must be confirmed in "
            "Settings > Battery > Battery Health."
        ),
    },
    {
        "claim": "component_replaced",
        "requires": (
            "integrity.classify_assertion() returning replacement_indicated, with a "
            "supported source and an artifact behind it."
        ),
        "otherwise": (
            "at most change_detected or suspicious from a metadata difference; a "
            "diff is not a repair record."
        ),
    },
    {
        "claim": "part_genuine_or_counterfeit",
        "requires": "Never obtainable with this toolchain.",
        "otherwise": (
            "not_detectable, with a pointer to an authorised service provider; "
            "Apple exposes no public parts-pairing API."
        ),
    },
    {
        "claim": "faceid_display_sensor_healthy",
        "requires": "A human recorded the guided manual test as passing.",
        "otherwise": "manual-check-required: the presence of an identifier proves nothing about health.",
    },
    {
        "claim": "malware_free",
        "requires": "Never claimed by this tool.",
        "otherwise": (
            "report only what triage found; a clean scan means 'no indicators "
            "matched', with an explicit false-positive warning."
        ),
    },
    {
        "claim": "never_tampered",
        "requires": "Never claimed by this tool.",
        "otherwise": "unknown: absence of contradicting metadata is not evidence of integrity.",
    },
]

# Inferences this tool must never draw (docs/v5/06). Each is a tempting shortcut
# that would turn missing data into either a reassuring or an accusatory claim.
# `regression-tests` names the test that pins the correct behaviour.
FORBIDDEN_INFERENCES: list[dict[str, str]] = [
    {
        "inference": "missing_battery_metric_means_replaced_battery",
        "wrong_claim": "A missing battery metric indicates a replaced battery.",
        "correct": "inconclusive — the metric was not collected; verify in Settings.",
    },
    {
        "inference": "missing_serial_means_tampering",
        "wrong_claim": "A missing serial number indicates tampering.",
        "correct": "unknown — the field may simply not be exposed by this tool or iOS version.",
    },
    {
        "inference": "unknown_part_means_genuine_or_counterfeit",
        "wrong_claim": "An unidentified part is genuine (or counterfeit).",
        "correct": "not_detectable — refer to an authorised service provider.",
    },
    {
        "inference": "identifier_present_means_component_verified",
        "wrong_claim": "A present identifier proves biometrics, display or sensors work.",
        "correct": "manual-check-required — run the guided physical test.",
    },
    {
        "inference": "clean_metadata_means_malware_free",
        "wrong_claim": "Clean metadata means the device is malware-free.",
        "correct": "no indicators matched — never a guarantee.",
    },
    {
        "inference": "no_changes_means_device_continuity",
        "wrong_claim": "Two identical reports prove these are the same physical device.",
        "correct": "continuity is not_detectable without a hardware-bound identifier.",
    },
]


# --------------------------------------------------------------------- helpers

# Which capability category each collector actually feeds.
#
# This mapping replaces a substring test that asked whether a category name was
# contained in a collector's name ("battery" in "device-info-xml"). No real
# collector name contains any category, so the coverage table rendered a
# permanent zero for every category — the chart could never show that the
# standard profile really did collect GasGauge battery telemetry.
#
# Keys are matched exactly against the collector's `name`. Keys ending in "-*"
# are prefixes, which is how the parameterised collectors are covered.
COLLECTOR_CATEGORY: dict[str, str] = {
    "pairing-validation": "identity",
    "device-info-xml": "identity",
    "device-info-key-values": "identity",
    "capability_catalog": "identity",
    # The diagnostics subsets carry real subsystem telemetry: GasGauge is battery,
    # NAND is storage, WiFi is connectivity. These are the collectors that make
    # the battery/storage rows in the coverage table non-zero.
    "diagnostics-GasGauge": "battery",
    "diagnostics-NAND": "storage",
    "diagnostics-WiFi": "connectivity",
    "diagnostics-All": "identity",
    "ioreg-IOPower": "battery",
    "ioreg-IODeviceTree": "identity",
    "ioreg-IOService": "identity",
    "installed-apps-*": "ownership",
    "provisioning-profiles": "ownership",
    "processes": "ownership",
    "live-syslog": "malware",
    "live-syslog-pymobiledevice3": "malware",
    "full-backup-*": "malware",
    "libimobiledevice-full-backup": "malware",
    "crash-report-copy": "physical",
    "pmd-crash-reports": "physical",
}


def category_for_collector(name: str) -> str | None:
    """Capability category a collector contributes to, or None if it feeds none.

    Exact match first, then longest matching ``prefix-*`` key, so a specific
    entry always beats a wildcard.
    """
    if not name:
        return None
    exact = COLLECTOR_CATEGORY.get(name)
    if exact:
        return exact
    best: tuple[int, str] | None = None
    for key, category in COLLECTOR_CATEGORY.items():
        if not key.endswith("-*"):
            continue
        prefix = key[:-1]
        if name.startswith(prefix) and (best is None or len(prefix) > best[0]):
            best = (len(prefix), category)
    return best[1] if best else None


def get_matrix() -> list[dict[str, str]]:
    """Full matrix as a fresh list of shallow copies — callers cannot mutate module data."""
    return [dict(row) for row in CAPABILITIES]


def by_category(name: str) -> list[dict[str, str]]:
    """Rows for one category (case-insensitive). Empty list when unknown."""
    wanted = name.strip().lower()
    return [dict(row) for row in CAPABILITIES if row["category"].lower() == wanted]


def coverage_counts() -> dict[str, int]:
    """How many rows fall in each coverage level; every level always present."""
    counts: dict[str, int] = {level: 0 for level in COVERAGE_LEVELS}
    for row in CAPABILITIES:
        counts[row["coverage"]] = counts.get(row["coverage"], 0) + 1
    return counts


def claim_rules() -> list[dict[str, str]]:
    """The claim matrix as fresh copies (claim -> required evidence -> fallback wording)."""
    return [dict(row) for row in CLAIM_MATRIX]


def forbidden_inferences() -> list[dict[str, str]]:
    """The inferences this tool must never draw, with the correct wording."""
    return [dict(row) for row in FORBIDDEN_INFERENCES]


def fallback_for(claim: str) -> str:
    """The wording to use when *claim* cannot be supported.

    Unknown claims fall back to the most conservative statement the tool can make,
    so a missing rule can never silently license an unsupported claim.
    """
    for row in CLAIM_MATRIX:
        if row["claim"] == claim:
            return row["otherwise"]
    return "unknown: not claimable with this toolchain."


# ----------------------------------------------------------------- claim gates
# The matrix above is a policy; this function is the enforcement. It inspects the
# *structured data* of a finished report and returns a violation for every claim
# the tool made without the evidence the matrix requires.
#
# Deliberately narrow: it checks the handful of claims that a caller could get
# wrong from inside this codebase, rather than pattern-matching English prose.
# The rendered HTML is never scanned, because the report's own Technical appendix
# legitimately quotes each forbidden claim in order to prohibit it.

# (regex, claim) — an affirmative assertion of something the matrix forbids.
_FORBIDDEN_ASSERTIONS: tuple[tuple[str, str], ...] = (
    (r"\bmalware[- ]free\b", "malware_free"),
    (r"\bno malware\b", "malware_free"),
    (r"\bnever tampered\b", "never_tampered"),
    (r"\bface ?id (?:is|are) (?:verified|working|healthy)\b", "faceid_display_sensor_healthy"),
    (
        r"\b(?:display|sensors?) (?:is|are) (?:verified|working|healthy)\b",
        "faceid_display_sensor_healthy",
    ),
)


def _texts(value: Any) -> list[str]:
    """Every string inside a nested report structure, flattened."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_texts(item))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_texts(item))
        return out
    return []


def audit_report(report: dict[str, Any]) -> list[str]:
    """Enforce the claim matrix against a finished report's *text*.

    Checks the affirmative assertions the matrix forbids — the claims a caller
    could make from inside this codebase. Domain-specific gates (battery units,
    replacement sources, continuity) live next to the code that produces them:
    `hardware.audit_battery_claims` and `integrity.audit_integrity_claims`.

    Returns one human-readable violation per unsupported claim, empty when the report
    only states things it has evidence for. Run before the report is written, so an
    unsupported claim cannot reach the file on disk.

    Deliberately narrow, and never applied to rendered HTML: the report's Technical
    appendix legitimately quotes each forbidden claim in order to prohibit it.
    """
    violations: list[str] = []
    for pattern, claim in _FORBIDDEN_ASSERTIONS:
        for text in _texts(report):
            if re.search(pattern, text, re.IGNORECASE):
                violations.append(
                    f"{claim}: forbidden assertion {pattern!r} found in report data "
                    f"-> {fallback_for(claim)}"
                )
                break  # one violation per claim is enough to act on
    return violations


def _texts(value: Any) -> list[str]:
    """Every string inside a nested report structure, flattened."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_texts(item))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_texts(item))
        return out
    return []
