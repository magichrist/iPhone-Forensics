"""Repair-shop / technician workflow.

A case records device intake, a pre-repair baseline, work performed, and a
post-repair inspection. Nothing here "performs" a repair — it structures
evidence, comparisons, and a final QA checklist for humans.

Who gets which file
------------------
There is exactly one report exporter, and it is not this module's job to build
another one:

  customer-facing     ``report-redacted.{html,json}`` — the redacted export.
                      Hand this to the customer. Identifiers are masked and no
                      raw evidence paths are embedded.
  technician-private  the raw ``report.json`` and the ``raw/`` evidence
                      directory under the run directory. Full identifiers and
                      unredacted artifacts stay with the technician/shop.

``case_to_json()`` returns the case's own bookkeeping (intake, scope, work,
QA roll-up). It is shop-internal working state — it is *not* a redaction step,
so a case export must not be treated as customer-safe on its own. Redaction
lives in ``reporting.finalize(..., redact_identifiers=True)``.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from .integrity import assess_integrity
from .util import write_json

QA_CHECKS = [
    "Device powers on and completes boot reliably",
    "Battery charges from 0% to at least 50% without interruption",
    "No unexpected shutdown under sustained load",
    "Display shows no new artifacts (dead pixels, touch dead zones, discoloration)",
    "All cameras focus and capture correctly",
    "Face ID / Touch ID works (if device was opened, re-verified after reassembly)",
    "All microphones and speakers tested",
    "All buttons and switches respond",
    "Wi-Fi, Bluetooth, cellular connect and hold",
    "Charging port holds cable firmly; no intermittent disconnects",
    "Wireless charging works (if supported)",
    "No sensors misbehaving (proximity, ambient light, compass)",
    "Enclosure sealed correctly; no gaps, missing screws, or damaged seals",
    "Customer-reported symptoms individually re-tested and resolved or documented",
]


def new_case(
    case_id: str,
    device_hint: str = "",
    customer_symptoms: str = "",
    authorized_scope: str = "diagnostics-only",
) -> dict[str, Any]:
    return {
        "schema_version": "4.0.0",
        "case_id": case_id,
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "device_hint": device_hint,
        "customer_reported_symptoms": customer_symptoms,
        "authorized_scope": authorized_scope,
        "pre_repair_baseline": None,  # path to a report.json
        "work_performed": [],  # [{part, part_source, replaced_at, notes}]
        "technician_notes": "",
        "post_repair_report": None,  # path to a report.json
        "qa_checks": {check: "not_tested" for check in QA_CHECKS},
        "comparison": None,
        "status": "open",
    }


def load_or_create(case_path: Path, case_id: str = "", **kwargs: Any) -> dict[str, Any]:
    if case_path.exists():
        try:
            import json

            data = json.loads(case_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("schema_version"):
                return data
        except (OSError, ValueError):
            pass
    return new_case(case_id or case_path.stem, **kwargs)


def record_work(case: dict[str, Any], part: str, part_source: str = "", notes: str = "") -> None:
    case["work_performed"].append(
        {
            "part": part,
            "part_source": part_source,
            "recorded_at": dt.datetime.now(dt.UTC).isoformat(),
            "notes": notes,
        }
    )


def compare_pre_post(case: dict[str, Any]) -> dict[str, Any]:
    """Integrity comparison between the pre-repair baseline and post-repair report."""
    pre_path, post_path = case.get("pre_repair_baseline"), case.get("post_repair_report")
    if not pre_path or not post_path:
        return {
            "status": "incomplete",
            "note": "Both a pre-repair baseline and a post-repair report are required.",
        }
    try:
        import json

        pre = json.loads(Path(pre_path).expanduser().read_text(encoding="utf-8"))
        post = json.loads(Path(post_path).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"status": "error", "note": f"Could not load reports: {exc}"}
    result = assess_integrity(pre, post)
    case["comparison"] = result
    return result


def qa_summary(case: dict[str, Any]) -> dict[str, Any]:
    values = list(case.get("qa_checks", {}).values())
    return {
        "total": len(values),
        "pass": sum(1 for v in values if v == "pass"),
        "fail": sum(1 for v in values if v == "fail"),
        "not_tested": sum(1 for v in values if v == "not_tested"),
        "ready_for_customer": all(v == "pass" for v in values),
    }


def case_to_json(case: dict[str, Any]) -> dict[str, Any]:
    """Condense a case into the machine-readable roll-up `--json` consumers read.

    Deliberately excludes raw report paths and technician notes so the shape
    stays stable for downstream tooling, and carries the pre/post comparison's
    `overall` classification only when a comparison has actually been run —
    an absent comparison is omitted rather than reported as a verdict.
    """
    payload: dict[str, Any] = {
        "case_id": case.get("case_id", ""),
        "status": case.get("status", "open"),
        "device_hint": case.get("device_hint", ""),
        "symptoms": case.get("customer_reported_symptoms", ""),
        "authorized_scope": case.get("authorized_scope", ""),
        "work_performed": list(case.get("work_performed", [])),
        "qa": qa_summary(case),
    }
    comparison = case.get("comparison")
    if isinstance(comparison, dict) and comparison.get("overall"):
        payload["comparison_overall"] = comparison["overall"]
    return payload


def save_case(case: dict[str, Any], path: Path) -> None:
    write_json(path, case)
