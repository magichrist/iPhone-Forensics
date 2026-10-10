"""Capability matrix as data (spec §3, §15; docs/v4/capability-matrix.md).

One entry per capability row: what this toolchain can answer, what it can only
hint at, what needs a guided human test, and what can never be established in
software. Pure data + tiny query helpers — no I/O, no dependencies. `cmd_capabilities`
and the report's "Unknown/unsupported" section consume this instead of a
hardcoded table.
"""
from __future__ import annotations

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
        "coverage": "manual",
        "source": "Seller erases and signs out; buyer performs reactivation test",
        "requirements": "Seller cooperation + network access during reactivation",
        "limits": "A Mac-side activation query is not conclusive; only the full erase-and-reactivate cycle decides.",
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


# --------------------------------------------------------------------- helpers

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
