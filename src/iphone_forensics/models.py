"""Domain models for v4 hardware-first inspection.

Everything here is deliberately plain dataclasses with `to_dict`/`from_dict`
helpers so the report JSON layer can round-trip without a schema library.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- candidates

SEVERITIES = ("INFO", "REVIEW", "WARNING", "BLOCKER")

CONFIDENCE_LEVELS = ("high", "medium", "low", "none")

HEALTH_STATUSES = (
    "pass",          # evidence supports that the checked property holds
    "pass_with_warnings",
    "degraded",
    "fail",
    "inconclusive",  # evidence exists but is insufficient or contradictory
    "not_tested",    # the test was optional and was not run
    "unsupported",   # the hardware/service/tool chain genuinely cannot answer
)

INTEGRITY_CLASSES = (
    "verified",              # narrowly defined claim, reliable identified evidence
    "consistent",            # all available evidence agrees; not proof of authenticity
    "change_detected",       # comparable snapshots/records establish a change
    "replacement_indicated", # a supported diagnostic source indicates a replacement
    "suspicious",            # unexplained discrepancy; investigate, not proof
    "inconclusive",
    "not_detectable",        # tools cannot answer
    "not_tested",
    "unsupported",
)

# Health-integrity mappings when collapsing a subsystem for summary views.
_INTEGRITY_TO_HEALTH = {
    "verified": "pass",
    "consistent": "pass_with_warnings",
    "change_detected": "degraded",
    "replacement_indicated": "degraded",
    "suspicious": "degraded",
    "inconclusive": "inconclusive",
    "not_detectable": "unsupported",
    "not_tested": "not_tested",
    "unsupported": "unsupported",
}


@dataclass
class SubsystemCheck:
    """One evaluated hardware property. Never fabricates a measurement."""
    subsystem: str            # battery, storage, display, cameras, biometrics, ...
    question: str             # precise property being evaluated
    status: str = "not_tested"
    test: str = ""            # what was actually performed (or would be)
    source: str = ""          # where the evidence comes from
    measurement: Any = None   # raw or normalized measurement, may be None
    measurement_unit: str = ""
    expected: str = ""        # expected range/condition, and its basis
    observed: str = ""
    severity: str = "INFO"
    confidence: str = "low"
    model_applicability: str = "known model-specific limits apply where documented"
    ios_applicability: str = ""
    explanation: str = ""
    alternatives: list[str] = field(default_factory=list)   # other plausible causes
    next_test: str = ""
    requires_hands_on: bool = False
    evidence_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubsystemCheck:
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Finding:
    """A statement about the device traceable to evidence."""
    severity: str = "INFO"
    title: str = ""
    detail: str = ""
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)
    classification: str = ""          # INTEGRITY_CLASSES value when integrity-related
    next_test: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class DeviceIdentity:
    """Identifiers as *observed* — never treated as proof of authenticity."""
    product_type: str = ""
    product_version: str = ""      # iOS version
    build_version: str = ""
    model_number: str = ""
    hardware_model: str = ""
    device_name: str = ""
    serial_number: str | None = None
    imei: str | None = None
    udid: str | None = None
    total_disk_capacity: int | None = None    # bytes as reported
    total_data_capacity: int | None = None
    activation_state: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_device_plist(cls, device: dict[str, Any]) -> DeviceIdentity:
        def s(key: str) -> str:
            return str(device.get(key) or "")

        def ident(key: str) -> str | None:
            value = device.get(key)
            return str(value) if value else None

        return cls(
            product_type=s("ProductType"), product_version=s("ProductVersion"),
            build_version=s("BuildVersion"), model_number=s("ModelNumber"),
            hardware_model=s("HardwareModel"), device_name=s("DeviceName"),
            serial_number=ident("SerialNumber"),
            imei=ident("InternationalMobileEquipmentIdentity"),
            udid=ident("UniqueDeviceID"),
            total_disk_capacity=_safe_int(device.get("TotalDiskCapacity")),
            total_data_capacity=_safe_int(device.get("TotalDataCapacity")),
            activation_state=s("ActivationState"),
            extra={k: v for k, v in device.items()
                   if k not in {"ProductType", "ProductVersion", "BuildVersion", "ModelNumber",
                                "HardwareModel", "DeviceName", "SerialNumber",
                                "InternationalMobileEquipmentIdentity", "UniqueDeviceID",
                                "TotalDiskCapacity", "TotalDataCapacity", "ActivationState"}},
        )


@dataclass
class EvidenceRecord:
    """One collected artifact with provenance and hash."""
    artifact: str            # relative path inside the run directory
    collector: str           # e.g. "libimobiledevice", "pymobiledevice3", "manual"
    method: str              # command or human action, subject to redaction
    artifact_type: str = ""  # "stdout", "plist", "log", "panic", "photo", ...
    size_bytes: int | None = None
    sha256: str = ""
    outcome: str = "success"
    error: str = ""
    redactions_applied: list[str] = field(default_factory=list)
    originated_at: str = ""  # explicit timezone-aware collection time

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
