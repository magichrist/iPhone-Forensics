"""Hardware integrity and change assessment.

Compares two snapshots (previous report vs current report, or buyer-stated
expectations vs observed evidence) and classifies every difference with one of
the nine INTEGRITY_CLASSES, plus an independent confidence label.

Hard rule enforced below: a change in software-reported metadata is exactly that
— a metadata change. It is physical replacement only when a supported diagnostic
source says so.

Phase-3 hardening implemented here:

* :func:`normalize_device` — schema normalization applied to *both* snapshots
  before any comparison: legacy v3 ``Product Type`` (space) keys resolve to v4
  ``ProductType`` (any space-separated spelling of an identity field does),
  capacities are canonicalized to integer bytes with GB tiers understood
  (``128`` → ``128000000000``), and a report with no ``schema_version`` is
  treated as v3 rather than assumed to be v4. This keeps schema drift from
  showing up as a fake "change".
* Continuity guard — when the two snapshots share no hard identifier
  (UDID/serial/IMEI), the result carries ``continuity="not_detectable"`` and an
  INFO finding titled "Device continuity cannot be established". The overall
  verdict is then capped at ``inconclusive`` *when at least one of those
  identifiers was recorded somewhere* — i.e. the data needed to link the
  snapshots existed and does not link them. Snapshots that never recorded any
  identifier (a legacy v3 report with only ``ProductType``) keep their
  field-level verdict: nothing was contradicted, the gap is reported by the
  ``continuity`` key and the finding instead of by a silent downgrade.
  Suspicious verdicts (the serial/IMEI/UDID BLOCKER rule and buyer cross-check
  discrepancies) are never downgraded by the cap.
* :func:`classify_assertion` — the single constructor for the classes the
  engine never *infers* from metadata (``verified``, ``replacement_indicated``,
  ``unsupported``, …). It refuses ``replacement_indicated`` unless the source is
  a supported diagnostic assertion (Apple Parts & Service History, a supported
  diagnostic service, technician-verified evidence), so no metadata diff can
  ever produce a part-swap claim.
"""

from __future__ import annotations

import re
from typing import Any

from .models import INTEGRITY_CLASSES, Finding

# Stable-ish identity fields; changes here deserve human follow-up but can also
# legitimately change with firmware re-flash, restore, or iOS-version reporting.
IDENTITY_FIELDS = [
    "ProductType",
    "ProductVersion",
    "BuildVersion",
    "ModelNumber",
    "HardwareModel",
    "SerialNumber",
    "InternationalMobileEquipmentIdentity",
    "UniqueDeviceID",
    "TotalDiskCapacity",
    "TotalDataCapacity",
    "ActivationState",
    "CarrierBundleVersion",
]

# The hard-identity triplet used to decide whether two snapshots can be linked
# to the same physical device. Product type / iOS version are *not* enough:
# they are shared by every phone of the same model and build.
CONTINUITY_FIELDS = ("UniqueDeviceID", "SerialNumber", "InternationalMobileEquipmentIdentity")

# A change to any of these is the tool's strongest tamper signal, so each must
# reach BLOCKER. The previous check was a substring test for "serial"/"imei"/
# "udid", which never matched the field names iOS actually reports: "imei" is
# not a substring of "InternationalMobileEquipmentIdentity", nor "udid" of
# "UniqueDeviceID". An IMEI swap silently degraded from BLOCKER to REVIEW while
# the module docstring still promised the BLOCKER rule. Match on names, and fall
# back to a substring sweep only for keys no collector produces today.
HARDWARE_IDENTIFIER_FIELDS = frozenset(CONTINUITY_FIELDS) | {
    "IMEI",
    "IMSI",
    "MEID",
    "ICCID",
    "UDID",
    "WiFiAddress",
    "BluetoothAddress",
    "PhoneNumber",
}


def _is_hardware_identifier(field: str) -> bool:
    """True when *field* names a hard hardware identifier.

    Case- and separator-insensitive, so `udid`, `UDID`, `DeviceUDID` and
    `UniqueDeviceID` are all recognised.
    """
    normalized = re.sub(r"[^a-z0-9]", "", str(field).lower())
    if normalized in {_re_key(known) for known in HARDWARE_IDENTIFIER_FIELDS}:
        return True
    # Substring sweep for forward compatibility with keys not yet seen.
    return any(token in normalized for token in ("serial", "imei", "udid", "meid", "iccid"))


def _re_key(name: str) -> str:
    """Normalize a field name the same way :func:`_is_hardware_identifier` does."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


# Compared in integer bytes; a value too small to be bytes is read as a GB tier.
CAPACITY_FIELDS = ("TotalDiskCapacity", "TotalDataCapacity")

BYTES_PER_GB = 1_000_000_000
# Largest plausible storage tier in GB (4 TB). Anything at or below this that
# appears in a capacity field is a tier, not a byte count.
MAX_GB_TIER = 4096

# Smallest capacity an iPhone has shipped with (8 GB). A bare number below this
# is not a plausible GB tier, so it is read as a raw byte count instead of being
# multiplied. Without this floor the tier heuristic was discontinuous at its own
# boundary: 4096 scaled to 4.096e12 bytes but 4097 did not.
MIN_GB_TIER = 8

# Fields where a change is *most plausibly* benign (iOS reporting, pairing state).
BENIGN_PATTERNS = ("ProductVersion", "BuildVersion", "ActivationState", "CarrierBundleVersion")

# Hardware-telemetry candidates that, when they change between snapshots, most
# plausibly indicate component wear (not replacement).
WEAR_CANDIDATES = (
    "yclecount",
    "fullchargecapacity",
    "maximumfacapacity",
    "designcapacity",
    "cyccount",
)

# The only sources that may ever produce `replacement_indicated`
# (docs/v4/tampering-indicators.md). Anything else — including a metadata diff
# between two snapshots — is refused by classify_assertion.
SUPPORTED_REPLACEMENT_SOURCES = (
    "parts_and_service_history",
    "diagnostic_service",
    "technician_verified",
)

# Compact (lowercase, no spaces) identity-field name → canonical v4 spelling.
# Feeds normalize_device: "Product Type" / "producttype" / "Serial Number" all
# resolve to the same canonical key, with the exact canonical spelling winning.
_CANONICAL_BY_COMPACT = {name.lower().replace(" ", ""): name for name in IDENTITY_FIELDS}
# Shorthand keys that appear in some legacy/merged reports.
_CANONICAL_BY_COMPACT.update(
    {"udid": "UniqueDeviceID", "imei": "InternationalMobileEquipmentIdentity"}
)

# Severity per class for asserted (never inferred) classifications.
_ASSERTION_SEVERITY = {
    "verified": "INFO",
    "consistent": "INFO",
    "change_detected": "REVIEW",
    "replacement_indicated": "WARNING",
    "suspicious": "REVIEW",
    "inconclusive": "INFO",
    "not_detectable": "INFO",
    "not_tested": "INFO",
    "unsupported": "INFO",
}


def _norm(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def _present(value: Any) -> bool:
    """An identifier counts as recorded only when it has a non-empty value."""
    return _norm(value) != ""


def _canonical_field(key: Any) -> str | None:
    """Canonical v4 name for a device-dict key, or None when it is not an identity field."""
    return _CANONICAL_BY_COMPACT.get(str(key).strip().lower().replace(" ", ""))


def _canonical_capacity(value: Any) -> Any:
    """Canonicalize a capacity to integer bytes; GB tiers are scaled up.

    ``128``/``"128"``/``"128 GB"`` (a tier) becomes ``128000000000`` bytes so it
    compares equal to the byte count iOS reports, and int-vs-string forms compare
    equal via `_norm`. Values that are not parseable numbers pass through
    unchanged so a bogus value stays visible instead of being silently dropped.
    """
    if value is None or isinstance(value, bool):
        return value
    text = str(value).strip().replace(",", "")
    if not text:
        return value
    # An explicit unit suffix is authoritative: "128 GB" is a tier even though the
    # bare number is small. Record that the string carried a unit so the bare
    # number below is not second-guessed.
    had_unit_suffix = False
    for suffix in ("gib", "gb"):
        if text.lower().endswith(suffix):
            text = text[: -len(suffix)].strip()
            had_unit_suffix = True
            break
    try:
        number = float(text)
    except ValueError:
        return value
    if had_unit_suffix:
        # "128 GB" is unambiguous: always bytes, regardless of magnitude.
        return round(number * BYTES_PER_GB)
    if number >= MIN_GB_TIER * BYTES_PER_GB:
        # Already a plausible byte count (>= the smallest shipping capacity), so
        # leave it alone. This single threshold replaces a "<= 4096 GB tier" rule
        # that was discontinuous at its own boundary — 4096 became 4.096e12 bytes
        # while 4097 stayed 4097 — and it also stops a bare `1` being read as 1e9.
        return round(number)
    if MIN_GB_TIER <= number <= MAX_GB_TIER:
        # Inside the tier range and below any plausible byte count, so it is a GB
        # tier. Values under MIN_GB_TIER (a bare `1`) are not a capacity any iPhone
        # has shipped with and are left untouched rather than inflated.
        return round(number * BYTES_PER_GB)
    return round(number)


def normalize_device(report: dict[str, Any] | None) -> dict[str, Any]:
    """Return a normalized device dict from a v3 or v4 report (or a bare device dict).

    Accepts a full report (``{"schema_version": …, "device": {...}}``) or a bare
    device record (``{"Product Type": ...}``). A missing ``schema_version`` is
    treated as v3: legacy space-separated keys and string capacities are expected
    and resolved rather than assumed absent. Passing a dict that is neither a
    report nor a device record (no recognized device keys) yields ``{}`` —
    report-level keys are never mistaken for device data.

    Normalization applied (input is never mutated; a new dict is returned):

    1. v3/legacy key spellings resolve to their canonical v4 name
       (``Product Type`` → ``ProductType``, ``UDID`` → ``UniqueDeviceID``, …);
       an exactly-canonical key always wins over an alias for the same field.
    2. ``TotalDiskCapacity``/``TotalDataCapacity`` become integer bytes, with
       GB tiers and optional "GB" suffixes understood.

    Normalized values are what the comparison and any change rows show, so both
    snapshots are always compared in the same units and spelling.
    """
    if not isinstance(report, dict):
        return {}
    if "device" in report:
        source = report.get("device")
        if not isinstance(source, dict):
            return {}
    elif any(_canonical_field(key) for key in report):
        source = report  # bare device record, no report wrapper
    else:
        return {}  # report without device data: keep it empty

    resolved: dict[str, Any] = {}
    for key, value in source.items():
        target = _canonical_field(key) or key
        if target in resolved:
            if key == target:  # exact canonical spelling beats a legacy alias
                resolved[target] = value
            continue
        resolved[target] = value
    for field in CAPACITY_FIELDS:
        if field in resolved:
            resolved[field] = _canonical_capacity(resolved[field])
    return resolved


def classify_change(
    field_name: str, previous: Any, current: Any, source: str = ""
) -> tuple[str, Finding]:
    """Return (classification, Finding) for one differing field."""
    severity = "REVIEW"
    confidence = "low"
    explanation = ""
    next_test = ""
    evidence = ["report.json (previous)", "report.json (current)"]

    field_lower = field_name.lower()

    if any(p.lower() in field_lower for p in BENIGN_PATTERNS):
        classification = "change_detected"
        explanation = (
            f"{field_name} changed between snapshots. Most plausible causes: iOS update, restore, or "
            f"reporting differences between tool versions. Verify the device is the same physical hardware "
            f"(serial, IMEI, UDID) before treating this as evidence about the device itself."
        )
        next_test = "Re-verify with the seller that the device has not been swapped."
    elif any(w in field_lower for w in WEAR_CANDIDATES):
        classification = "change_detected"
        severity = "INFO"
        explanation = (
            "Battery telemetry changed between snapshots. Wear accumulation is normal; a sudden large "
            "jump in *capacity* between snapshots is more suspicious than a cycle-count increase, "
            "because capacity drop is monotonic on real hardware."
        )
        next_test = (
            "If the capacity figure *increased* between two inspections of the same claimed device, "
            "physically re-verify identity (serial/IMEI shown in Settings vs report) before continuing."
        )
        evidence.append("diagnostics GasGauge")
    elif field_lower.startswith("diagnostic:"):
        classification = "change_detected"
        severity = "INFO"
        explanation = "A diagnostic candidate metric changed. Interpret only with source-tool provenance and units in hand."
    elif _is_hardware_identifier(field_name):
        classification = "suspicious"
        severity = "BLOCKER"
        confidence = "medium"
        explanation = (
            "A hardware identifier reported as changed between snapshots is a serious discrepancy. "
            "This is *not automatically proof* of a swapped logic board — iOS restore/repair tooling can "
            "legitimately rewrite some reporting — but the phone must not be paid for until identity is "
            "independently confirmed in Settings → General → About and against the seller's documentation."
        )
        next_test = (
            "Physically read the serial/IMEI from Settings or the SIM tray and compare against both "
            "snapshots; escalate to an authorized service provider for parts-and-service history."
        )
    else:
        classification = "suspicious"
        explanation = (
            "An unexplained difference between snapshots. Could be a re-flash, a repaired/reprogrammed "
            "component, or simply different tool versions or pairing states. Investigate before concluding."
        )

    finding = Finding(
        severity=severity,
        title=f"Snapshot change: {field_name}",
        detail=f"Previous: {previous!r} → Current: {current!r}. {explanation}",
        confidence=confidence,
        evidence=evidence,
        classification=classification,
        next_test=next_test,
    )
    assert classification in INTEGRITY_CLASSES
    return classification, finding


def classify_assertion(
    classification: str,
    claim: str,
    *,
    evidence: list[str] | None = None,
    source: str = "",
    confidence: str = "medium",
    next_test: str = "",
) -> tuple[str, Finding]:
    """The single constructor for classifications the engine never *infers*.

    `classify_change()`/`assess_integrity()` only ever infer `consistent`,
    `change_detected`, `suspicious`, `inconclusive` (plus `not_tested` as an
    overall verdict) from a metadata diff. The remaining INTEGRITY_CLASSES are
    asserted from an identified claim, and this function is where that happens:

    * ``verified`` — a *narrow* claim backed by reliable, identified evidence
      (for example: "both snapshots report the same serial, read from Settings →
      General → About"). An empty claim or missing evidence raises ValueError,
      so a vague agreement can never be upgraded to ``verified`` — the caller
      must name both the claim and its evidence.
    * ``replacement_indicated`` — only from a supported diagnostic assertion
      (``source`` must be one of SUPPORTED_REPLACEMENT_SOURCES: Apple Parts &
      Service History, a supported diagnostic service, technician-verified
      evidence) *with* the artifact as evidence. Any other source — including a
      metadata difference between two snapshots — raises ValueError. This is the
      hard rule from docs/v4/tampering-indicators.md, enforced at the API edge.
    * ``unsupported`` / ``not_detectable`` / ``inconclusive`` / ``not_tested`` —
      require a stated reason so unknowns stay visible.

    Returns ``(classification, Finding)`` like `classify_change`.
    """
    assert classification in INTEGRITY_CLASSES
    claim_text = str(claim).strip()
    evidence_paths = list(evidence or [])
    if not claim_text:
        raise ValueError(f"{classification} requires a stated claim/reason.")
    if classification == "replacement_indicated":
        if _norm(source) not in SUPPORTED_REPLACEMENT_SOURCES:
            raise ValueError(
                "replacement_indicated requires a supported diagnostic source "
                f"{SUPPORTED_REPLACEMENT_SOURCES}; a change in software-reported metadata is never a "
                f"part-swap claim (got source={source!r})."
            )
        if not evidence_paths:
            raise ValueError("replacement_indicated requires the diagnostic artifact as evidence.")
    elif classification == "verified" and not evidence_paths:
        raise ValueError("verified requires a narrow claim plus identified evidence.")

    title = {
        "replacement_indicated": "Diagnostic assertion indicates a component replacement",
        "verified": f"Verified: {claim_text}" if len(claim_text) <= 70 else "Verified claim",
    }.get(classification, f"Integrity classification: {classification}")
    finding = Finding(
        severity=_ASSERTION_SEVERITY[classification],
        title=title,
        detail=f"{claim_text} (source: {source or 'not stated'}).",
        confidence=confidence,
        evidence=evidence_paths,
        classification=classification,
        next_test=next_test,
    )
    return classification, finding


def assess_integrity(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
    buyer_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Cross-snapshot integrity classification.

    `previous` is the previous report dict (v3 or v4 schema — missing
    `schema_version` is treated as v3). `current` is the current report dict.
    Optionally cross-checks buyer-stated storage/model.

    Both snapshots pass through `normalize_device()` first, so legacy key
    spellings and int-vs-string/GB-vs-bytes capacities are compared in one
    canonical form; `changes[]` rows therefore show normalized values (legacy
    alias resolved, capacities as integer bytes).

    Output shape (unchanged from earlier phases, plus `continuity`):
    ``{overall, continuity, classifications, changes, findings, disclaimer}``.

    Continuity guard: when neither snapshot shares a recorded UDID, serial or
    IMEI with the other, `continuity` is ``"not_detectable"`` and an INFO finding
    ("Device continuity cannot be established") is appended. If at least one of
    those identifiers *was* recorded on either side, the overall verdict is then
    capped at ``inconclusive`` — the data needed to link the snapshots existed
    and does not link them. Snapshots that recorded no identifier at all keep
    their field-level verdict (a v3 report with only ProductType still compares
    `consistent`); the continuity key and finding carry that gap instead.
    A ``suspicious`` verdict (serial/IMEI/UDID BLOCKER, buyer cross-check) is
    never downgraded by the cap. With no previous snapshot, `continuity` is
    ``"not_tested"``.
    """
    findings: list[Finding] = []
    changes: list[dict[str, Any]] = []
    classifications: dict[str, str] = {}

    prev_device = normalize_device(previous)
    curr_device = normalize_device(current)

    # Continuity state (finding is appended after the field-by-field pass).
    identity_recorded = any(
        _present(prev_device.get(field)) or _present(curr_device.get(field))
        for field in CONTINUITY_FIELDS
    )
    shared_identity = [
        field
        for field in CONTINUITY_FIELDS
        if _present(prev_device.get(field))
        and _norm(prev_device.get(field)) == _norm(curr_device.get(field))
    ]
    if not previous:
        continuity = "not_tested"
    elif shared_identity:
        continuity = "established"
    else:
        continuity = "not_detectable"

    for field_name in IDENTITY_FIELDS:
        prev_value, curr_value = prev_device.get(field_name), curr_device.get(field_name)
        if prev_value is None and curr_value is None:
            continue
        if prev_value is None or curr_value is None:
            changes.append(
                {
                    "field": field_name,
                    "previous": prev_value,
                    "current": curr_value,
                    "status": "not_comparable",
                    "confidence": "none",
                    "note": "One snapshot lacks this field; comparison cannot be made.",
                }
            )
            findings.append(
                Finding(
                    severity="INFO",
                    title=f"Field not comparable: {field_name}",
                    detail="One snapshot lacks this field, so no change claim can be made.",
                    confidence="high",
                    classification="inconclusive",
                )
            )
            classifications[field_name] = "inconclusive"
            continue
        if _norm(prev_value) == _norm(curr_value):
            classifications[field_name] = "consistent"
            continue
        classification, finding = classify_change(field_name, prev_value, curr_value)
        changes.append(
            {
                "field": field_name,
                "previous": prev_value,
                "current": curr_value,
                "status": "changed",
                "classification": classification,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "next_test": finding.next_test,
            }
        )
        findings.append(finding)
        classifications[field_name] = classification

    if continuity == "not_detectable":
        findings.append(
            Finding(
                severity="INFO",
                title="Device continuity cannot be established",
                detail=(
                    "The two snapshots share no recorded hardware identifier (UDID, serial, IMEI): at least one "
                    "side has none recorded, or the recorded values do not match. Nothing here confirms the two "
                    "reports describe the same physical device, so treat every agreement below as agreement about "
                    "reported metadata only — not evidence that the device is unchanged or genuine."
                ),
                confidence="high",
                evidence=["report.json (previous)", "report.json (current)"],
                classification="not_detectable",
                next_test=(
                    "Read the serial and IMEI from Settings → General → About (or the SIM tray) and compare them "
                    "against both snapshots and the seller's documentation."
                ),
            )
        )

    # Buyer-stated vs observed cross-check.
    if isinstance(buyer_data, dict):
        buyer = buyer_data.get("buyer", {})
        observations = buyer_data.get("observations", {})
        advertised_model = str(buyer.get("advertised_model", "") or "")
        advertised_storage_gb = _norm(observations.get("reported_storage_gb"))
        observed_disk_gb = None
        try:
            observed_disk_gb = round(
                int(curr_device.get("TotalDiskCapacity", 0)) / 1_000_000_000, 1
            )
        except (TypeError, ValueError):
            pass
        if advertised_model and curr_device:
            model_matches = advertised_model.lower() in _norm(
                curr_device.get("ProductType")
            ) or advertised_model.lower() in _norm(
                curr_device.get("MarketingName", curr_device.get("DeviceName", ""))
            )
            if not model_matches:
                findings.append(
                    Finding(
                        severity="REVIEW",
                        title="Advertised model does not match device-reported identity",
                        detail=(
                            f"Seller advertised “{advertised_model}”; device reports ProductType="
                            f"{curr_device.get('ProductType', 'unknown')}. Marketing names also differ from the advertised "
                            f"model string. This may be a listing typo or a misrepresentation — verify before paying."
                        ),
                        confidence="medium",
                        classification="suspicious",
                        next_test="Compare the model shown in Settings → General → About against the listing.",
                        evidence=["buyer-checklist.json", "device-info plist"],
                    )
                )
                classifications["advertised_model"] = "suspicious"
        if advertised_storage_gb and observed_disk_gb and advertised_storage_gb:
            try:
                advertised_value = float(observations.get("reported_storage_gb"))
                if abs(advertised_value - observed_disk_gb) > max(2.0, advertised_value * 0.1):
                    findings.append(
                        Finding(
                            severity="REVIEW",
                            title="Advertised storage differs from iOS-reported capacity beyond rounding",
                            detail=(
                                f"Seller/observations claim ~{advertised_value:g} GB; iOS reports {observed_disk_gb} GB "
                                f"(decimal). Marketing/OS rounding can differ by a GB or two; bigger gaps warrant "
                                f"verification."
                            ),
                            confidence="medium",
                            classification="suspicious",
                            next_test="Compare Settings → General → iPhone Storage against the listing.",
                            evidence=["buyer-checklist.json", "device-info plist"],
                        )
                    )
                    classifications["advertised_storage"] = "suspicious"
            except (TypeError, ValueError):
                pass

    # A field only counts as evidence for `consistent` if it was actually
    # *comparable* on both sides. The old test was "did we record any
    # classification at all", and an all-inconclusive dict is truthy — so two
    # reports sharing no comparable field were scored `consistent`, the
    # strongest available verdict, from no evidence whatsoever.
    comparable = [c for c in classifications.values() if c != "inconclusive"]

    if not previous:
        overall = "not_tested"
    elif any(c == "suspicious" for c in classifications.values()):
        overall = "suspicious"
    elif any(c == "change_detected" for c in classifications.values()):
        overall = "change_detected"
    elif comparable:
        overall = "consistent"
    else:
        overall = "inconclusive"

    # Continuity cap: identity was recorded somewhere but links nothing, so an
    # affirmative verdict overstates what the evidence supports. `suspicious`
    # (serial/IMEI/UDID BLOCKER, buyer cross-check) is never downgraded here.
    if (
        continuity == "not_detectable"
        and identity_recorded
        and overall in ("consistent", "change_detected")
    ):
        overall = "inconclusive"

    return {
        "overall": overall,
        "continuity": continuity,
        "classifications": classifications,
        "changes": changes,
        "findings": [f.to_dict() for f in findings],
        "disclaimer": (
            "A change in software-reported metadata alone is never proof of a physical component "
            "replacement. Only concrete diagnostic assertions (e.g. Apple's Parts & Service History, "
            "a supported diagnostic service, or technician-verified evidence) can indicate a replacement."
        ),
    }


def audit_integrity_claims(report: dict[str, Any]) -> list[str]:
    """Enforce the `component_replaced` and `never_tampered` claim rules.

    * A replacement claim must trace to a supported diagnostic source. A metadata
      difference is a *change*, never a repair record.
    * Continuity is a property of a physical device. Two snapshots that merely
      repeat a value do not establish it, so it is never asserted as proof of
      integrity.
    """
    from .capabilities import fallback_for

    violations: list[str] = []
    integrity = report.get("integrity_assessment")
    if not isinstance(integrity, dict):
        return violations

    # Every replacement claim must name a supported source somewhere in the record.
    for field_name, classification in (integrity.get("classifications") or {}).items():
        if str(classification).strip().lower() != "replacement_indicated":
            continue
        sources = [
            str(change.get("source", ""))
            for change in integrity.get("changes", [])
            if isinstance(change, dict)
        ]
        if not any(_norm(source) in SUPPORTED_REPLACEMENT_SOURCES for source in sources):
            violations.append(
                f"component_replaced: {field_name} claims replacement without a supported "
                f"diagnostic source -> {fallback_for('component_replaced')}"
            )

    # Continuity may be reported, but never as a clean bill of health.
    continuity = str(integrity.get("continuity") or "").strip().lower()
    if continuity == "established" and not _has_hardware_bound_identifier(report):
        violations.append(
            f"never_tampered: continuity asserted without a hardware-bound identifier "
            f"-> {fallback_for('never_tampered')}"
        )

    return violations


def _has_hardware_bound_identifier(report: dict[str, Any]) -> bool:
    """True when the report carries an identifier that cannot be changed in software.

    A serial number read from the device is hardware-bound; a snapshot that merely
    repeats a value is not.
    """
    device = report.get("device") if isinstance(report.get("device"), dict) else {}
    serial = str(device.get("SerialNumber") or "").strip()
    return bool(serial) and len(serial) >= 6
