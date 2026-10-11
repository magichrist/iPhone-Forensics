from __future__ import annotations

from typing import Any

from .buyer import evaluate
from .evidence import EVIDENCE_DIR_NAME, LEGACY_EVIDENCE_DIR_NAME
from .models import EPISTEMIC_LABELS, normalize_status

# Collection statuses that mean "we got usable evidence out of this step".
# Everything else (failed, inconclusive, unsupported, permission_denied,
# tool_missing, collection_error, skipped_by_user, not_applicable) is an
# *evidence gap*, not a device fault — see _GAP_DETAIL for the wording.
_COMPLETED_STATUSES = frozenset({"collected", "passed", "warning"})

# Why a step produced no usable evidence, by status. A missing tool or a
# declined consent must never read as a device problem (docs/v5/05, §10.10/10.11).
_GAP_DETAIL: dict[str, str] = {
    "failed": "The check ran and returned a negative result. Inspect the recorded stderr and evidence.",
    "inconclusive": "Evidence was collected but is insufficient or contradictory to decide the question.",
    "unsupported": "This device, iOS version, or toolchain cannot answer this question at all.",
    "permission_denied": "Blocked by pairing, trust, or permissions. Re-trust the computer and retry; nothing was learned about the device.",
    "tool_missing": "The required tool is not installed. This is an environment gap, not a device fault.",
    "collection_error": "The command failed, timed out, or returned nonzero. Inspect its stderr and prerequisites; this is not automatically a device fault.",
    "skipped_by_user": "Not collected because sensitive collection was not consented to. Nothing is known about this item; nothing is wrong with the device.",
    "not_applicable": "This question does not apply to this device.",
}


def _status_of(item: dict[str, Any]) -> str:
    """Normalize one collection entry's status (accepts v3/v4 strings on read)."""
    return normalize_status(item.get("status", ""))


def _is_evidence_gap(status: str) -> bool:
    """True when *status* means we learned nothing usable from that step."""
    return status not in _COMPLETED_STATUSES


# Severity -> epistemic label, for findings that carry no explicit one.
# docs/v5/05 requires every finding to say *how* we know: read straight from an
# artifact, reasoned from evidence, genuinely unknown, or needing human hands.
_SEVERITY_EPISTEMIC: dict[str, str] = {
    "BLOCKER": "observed",     # a recorded negative result from a check that ran
    "WARNING": "inferred",     # a pattern reasoned from collected evidence
    "REVIEW": "unknown",       # an open question / gap, explicitly not a conclusion
    "INFO": "observed",        # a fact read directly from device-reported data
}

# Manual subsystems are the honest home of `needs_manual`: this tool cannot
# observe them, and a finding about one must say so rather than imply a result.
MANUAL_HINTS = ("manual", "physically", "hands-on", "settings app",
                "parts & service", "parts and service")


def epistemic_for(finding: dict[str, Any]) -> str:
    """Resolve the epistemic label for one finding, never returning empty.

    Order of preference: an explicit ``epistemic`` on the finding, then a manual
    subject (which is by definition not observable here), then the severity
    default. The result is always one of models.EPISTEMIC_LABELS.
    """
    explicit = str(finding.get("epistemic", "") or "").strip().lower()
    if explicit in EPISTEMIC_LABELS:
        return explicit
    haystack = f"{finding.get('title', '')} {finding.get('detail', '')}".lower()
    if any(hint in haystack for hint in MANUAL_HINTS):
        return "needs_manual"
    return _SEVERITY_EPISTEMIC.get(str(finding.get("severity", "")).upper(), "unknown")


def label_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stamp every finding with its epistemic label (docs/v5/05).

    An unlabelled finding is not allowed to reach the report: a reader could not
    tell a recorded fact from a guess, which is precisely the confusion this
    tool exists to avoid.
    """
    for finding in findings:
        if isinstance(finding, dict):
            finding["epistemic"] = epistemic_for(finding)
    return findings


def derive_findings(report: dict[str, Any], buyer_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    findings = list(report.get("findings", []))
    device = report.get("device", {})
    if not isinstance(device, dict):
        device = {}
    product_type = str(device.get("ProductType", device.get("Product Type", "")))
    if product_type:
        findings.append({"severity":"INFO", "title":"Reported product identifier available",
            "detail":f"Device reports ProductType={product_type}. This is a consistency clue, not proof of authenticity.",
            "evidence":[f"{EVIDENCE_DIR_NAME}/device-info.plist"]})
    if not product_type:
        findings.append({"severity":"REVIEW", "title":"Exact product identifier not parsed",
            "detail":"No ProductType was parsed from metadata. Inspect Settings → General → About and raw metadata; this is an evidence gap, not proof of a counterfeit device.",
            "evidence":[f"{EVIDENCE_DIR_NAME}/device-info-xml.stdout.txt",
                        f"{EVIDENCE_DIR_NAME}/device-info-key-values.stdout.txt"]})
    for item in report.get("collection", []):
        status = _status_of(item)
        if _is_evidence_gap(status):
            findings.append({"severity":"REVIEW", "title":f"Collection incomplete: {item.get('name')}",
                "detail":_GAP_DETAIL.get(status, "No usable evidence was collected for this step."),
                "status":status,
                "evidence":[f"{EVIDENCE_DIR_NAME}/{item.get('stdout_file','')}",
                            f"{EVIDENCE_DIR_NAME}/{item.get('stderr_file','')}"]})
    evaluation = evaluate(buyer_data)
    for title in evaluation["critical_failures"]:
        findings.append({"severity":"BLOCKER", "title":"Buyer-critical check failed", "detail":title,
                         "evidence":["buyer-checklist.json"]})
    for title in evaluation["critical_unknowns"]:
        findings.append({"severity":"REVIEW", "title":"Buyer-critical check not verified", "detail":title,
                         "epistemic":"needs_manual",   # a human must verify this one
                         "evidence":["buyer-checklist.json"]})
    return label_findings(findings)


def automated_assessment(report: dict[str, Any], buyer_data: dict[str, Any] | None) -> dict[str, Any]:
    """Transparent coverage assessment, not a hardware-quality prediction."""
    collection = report.get("collection", [])
    statuses = [_status_of(c) for c in collection]
    completed = sum(1 for s in statuses if s in _COMPLETED_STATUSES)
    # A negative result (the check ran and said no) is a real finding. Every other
    # gap is an absence of evidence, and must not be counted as a device failure.
    failed = sum(1 for s in statuses if s == "failed")
    gaps = len(statuses) - completed
    # v4 meaning of `collection_failed_or_partial` was "steps that did not
    # succeed", which is exactly `gaps`. Keep that meaning so existing readers
    # stay correct, and expose the strict negative-result count separately.
    negative_results = failed
    device = report.get("device", {})
    identity_fields = ["ProductType", "ProductVersion", "BuildVersion", "ModelNumber"]
    identity_present = sum(1 for key in identity_fields if isinstance(device, dict) and device.get(key))
    buyer_eval = evaluate(buyer_data)
    if buyer_eval["critical_failures"]:
        verdict = "HIGH RISK — DO NOT PAY YET"
        status = "high_risk"
    elif buyer_eval["critical_unknowns"]:
        verdict = "INCOMPLETE — HOLD PAYMENT"
        status = "incomplete"
    elif buyer_eval["failures"]:
        verdict = "REVIEW — NEGOTIATE OR INVESTIGATE"
        status = "review"
    elif not device or identity_present < 2 or gaps:
        verdict = "INCOMPLETE — EVIDENCE GAPS REMAIN"
        status = "incomplete"
    else:
        verdict = "NO RECORDED BUYER-CHECKLIST FAILURES — NOT A CERTIFICATION"
        status = "no_recorded_failures"
    return {"status": status, "verdict": verdict,
            "description":"This is a decision-support summary, not a forensic certification or prediction of hardware life.",
            "collection_total":len(collection), "collection_successful":completed,
            # `collection_failed_or_partial` is the v4 key name and keeps its v4
            # meaning (steps that produced no usable evidence) so existing readers
            # stay correct. `collection_negative_results` is the strict count of
            # checks that ran and said "no" — the only bucket that is a finding
            # about the device rather than an absence of evidence.
            "collection_failed_or_partial":gaps,
            "collection_negative_results":negative_results,
            "collection_gaps":gaps,
            "collection_status_counts":{s: statuses.count(s) for s in sorted(set(statuses))},
            "identity_fields_present":identity_present,
            "identity_fields_expected":len(identity_fields), "buyer_checklist":buyer_eval}


def compare_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare stable device fields and explicitly named diagnostic candidates."""
    fields = ["ProductType", "ProductVersion", "BuildVersion", "ModelNumber", "HardwareModel",
              "TotalDiskCapacity", "TotalDataCapacity", "ActivationState", "CarrierBundleVersion"]
    old_device = previous.get("device", {}) if isinstance(previous.get("device"), dict) else {}
    new_device = current.get("device", {}) if isinstance(current.get("device"), dict) else {}
    changes = []
    for field in fields:
        old, new = old_device.get(field), new_device.get(field)
        if old is None and new is None:
            continue
        status = "not_comparable" if old is None or new is None else "unchanged" if str(old) == str(new) else "changed"
        changes.append({"field":field, "previous":old if old is not None else "not available",
                        "current":new if new is not None else "not available", "status":status})
    old_metrics = {(m.get("source"), m.get("key")):m.get("value") for m in previous.get("diagnostic_candidates", [])}
    new_metrics = {(m.get("source"), m.get("key")):m.get("value") for m in current.get("diagnostic_candidates", [])}
    for key in sorted(set(old_metrics) | set(new_metrics), key=str):
        old, new = old_metrics.get(key), new_metrics.get(key)
        status = "new" if key not in old_metrics else "not available" if key not in new_metrics else "unchanged" if str(old) == str(new) else "changed"
        changes.append({"field":f"diagnostic:{key[0]}:{key[1]}", "previous":old if old is not None else "not available",
                        "current":new if new is not None else "not available", "status":status})
    return {"previous_version":previous.get("version"), "previous_finished_at":previous.get("finished_at"),
            "changes":changes, "note":"Differences may reflect OS/tool versions, permissions, collection conditions, or normal state changes; investigate before diagnosing a fault."}


def analyze_crash_artifacts(run_dir) -> dict[str, Any]:
    """Conservative filename/content triage for crash and panic artifacts already collected."""
    import json
    import re
    from pathlib import Path

    base = Path(run_dir)
    # v5 writes artifacts under evidence/; v4 run directories still use raw/, so
    # both are read and an older run stays analyzable.
    roots = [base / EVIDENCE_DIR_NAME / "crash-reports",
             base / EVIDENCE_DIR_NAME / "pymobiledevice3-crash-reports",
             base / EVIDENCE_DIR_NAME / "offline-evidence",
             base / LEGACY_EVIDENCE_DIR_NAME / "crash-reports",
             base / LEGACY_EVIDENCE_DIR_NAME / "pymobiledevice3-crash-reports",
             base / LEGACY_EVIDENCE_DIR_NAME / "offline-evidence"]
    files = [path for root in roots if root.exists() for path in root.rglob("*") if path.is_file()]
    panic_items = []
    crash_items = []
    for path in files:
        lower = path.name.lower()
        if any(term in lower for term in ("panic", "resetcounter", "watchdog")) or path.suffix.lower() == ".panic":
            category = "panic_or_watchdog_candidate"
        elif path.suffix.lower() in {".ips", ".crash", ".diag", ".hang"}:
            category = "crash_or_diagnostic"
        else:
            continue
        item = {"path":str(path.relative_to(run_dir)), "category":category, "size_bytes":path.stat().st_size}
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:1_000_000]
            # Modern .ips files may start with a metadata JSON line and a payload JSON line.
            for line in content.splitlines()[:30]:
                stripped = line.strip()
                if not stripped.startswith("{"):
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    for key in ("timestamp", "captureTime", "bug_type", "incident", "procName", "name", "panicString", "exception"):
                        if key in payload and isinstance(payload[key], (str, int, float)):
                            item[key] = str(payload[key])[:500]
                    break
            if "panicString" not in item:
                match = re.search(r"(?im)^panicString\s*:\s*(.+)$|^panic\s*:\s*(.+)$", content)
                if match:
                    item["panicString"] = (match.group(1) or match.group(2) or "").strip()[:500]
        except OSError as exc:
            item["read_error"] = str(exc)
        (panic_items if category == "panic_or_watchdog_candidate" else crash_items).append(item)
    return {"files_scanned":len(files), "crash_or_diagnostic_count":len(crash_items),
            "panic_or_watchdog_candidate_count":len(panic_items), "panic_candidates":panic_items[:100],
            "crash_candidates":crash_items[:200],
            "recurrence": _recurrence_analysis(panic_items, crash_items),
            "interpretation":"Filename/content triage only. A panic artifact is not by itself proof of a hardware fault; correlate repeated incidents and seek professional diagnostics."}


def _recurrence_analysis(panic_items: list[dict[str, Any]],
                         crash_items: list[dict[str, Any]]) -> dict[str, Any]:
    """Group panic/crash artifacts by bug_type and process; detect repeats.

    A repeated identical bug_type+procName combination is a *pattern*, not a
    diagnosis. Timestamps are parsed leniently; unknown formats degrade to
    'unknown' rather than fabricating a date.
    """
    import datetime as _dt
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in list(panic_items) + list(crash_items):
        key = (str(item.get("bug_type", "unknown")), str(item.get("procName", item.get("name", "unknown"))))
        groups.setdefault(key, []).append(item)

    patterns: list[dict[str, Any]] = []
    for (bug_type, proc), items in groups.items():
        if len(items) < 2:
            continue
        timestamps = []
        for it in items:
            raw = str(it.get("timestamp") or it.get("captureTime") or "")
            parsed = None
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                try:
                    parsed = _dt.datetime.strptime(raw.replace("+0000", "Z").rstrip("Z")
                                                   if not raw.endswith("Z") else raw, fmt)
                    break
                except ValueError:
                    continue
            timestamps.append(parsed.isoformat() + "Z" if parsed else None)
        known = [t for t in timestamps if t]
        patterns.append({
            "bug_type": bug_type, "procName": proc, "occurrences": len(items),
            "timestamps": known[:20],
            "timestamps_unknown": len(timestamps) - len(known),
            "span": (f"{min(known)} → {max(known)}" if len(known) >= 2 else "insufficient timestamp data"),
            "classification": "weak_heuristic_pattern",
            "note": "Repeated artifacts suggest recurrence; a pattern is not a hardware diagnosis.",
            "paths": [str(i.get("path")) for i in items[:10]],
        })
    patterns.sort(key=lambda p: (-p["occurrences"], p["bug_type"]))
    return {
        "repeated_patterns": patterns[:50],
        "pattern_count": len(patterns),
        "note": ("Recurrence analysis groups artifacts by (bug_type, procName). "
                 "Two+ occurrences warrant investigation; they never constitute a "
                 "hardware diagnosis by themselves."),
    }
