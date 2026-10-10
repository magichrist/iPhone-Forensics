from __future__ import annotations

from typing import Any

from .buyer import evaluate


def derive_findings(report: dict[str, Any], buyer_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    findings = list(report.get("findings", []))
    device = report.get("device", {})
    if not isinstance(device, dict):
        device = {}
    product_type = str(device.get("ProductType", device.get("Product Type", "")))
    if product_type:
        findings.append({"severity":"INFO", "title":"Reported product identifier available",
            "detail":f"Device reports ProductType={product_type}. This is a consistency clue, not proof of authenticity.",
            "evidence":["raw/device-info.plist"]})
    if not product_type:
        findings.append({"severity":"REVIEW", "title":"Exact product identifier not parsed",
            "detail":"No ProductType was parsed from metadata. Inspect Settings → General → About and raw metadata; this is an evidence gap, not proof of a counterfeit device.",
            "evidence":["raw/device-info-xml.stdout.txt", "raw/device-info-key-values.stdout.txt"]})
    for item in report.get("collection", []):
        if item.get("status") not in {"success", "expected_end"}:
            findings.append({"severity":"REVIEW", "title":f"Collection incomplete: {item.get('name')}",
                "detail":"The command failed, timed out, or returned nonzero. Inspect its stderr and prerequisites; this is not automatically a device fault.",
                "evidence":[f"raw/{item.get('stdout_file','')}", f"raw/{item.get('stderr_file','')}"]})
    evaluation = evaluate(buyer_data)
    for title in evaluation["critical_failures"]:
        findings.append({"severity":"BLOCKER", "title":"Buyer-critical check failed", "detail":title,
                         "evidence":["buyer-checklist.json"]})
    for title in evaluation["critical_unknowns"]:
        findings.append({"severity":"REVIEW", "title":"Buyer-critical check not verified", "detail":title,
                         "evidence":["buyer-checklist.json"]})
    return findings


def automated_assessment(report: dict[str, Any], buyer_data: dict[str, Any] | None) -> dict[str, Any]:
    """Transparent coverage assessment, not a hardware-quality prediction."""
    collection = report.get("collection", [])
    completed = sum(1 for c in collection if c.get("status") in {"success", "expected_end"})
    failed = sum(1 for c in collection if c.get("status") == "failed_or_partial")
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
    elif not device or identity_present < 2 or failed:
        verdict = "INCOMPLETE — EVIDENCE GAPS REMAIN"
        status = "incomplete"
    else:
        verdict = "NO RECORDED BUYER-CHECKLIST FAILURES — NOT A CERTIFICATION"
        status = "no_recorded_failures"
    return {"status": status, "verdict": verdict,
            "description":"This is a decision-support summary, not a forensic certification or prediction of hardware life.",
            "collection_total":len(collection), "collection_successful":completed,
            "collection_failed_or_partial":failed, "identity_fields_present":identity_present,
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

    roots = [Path(run_dir) / "raw" / "crash-reports",
             Path(run_dir) / "raw" / "pymobiledevice3-crash-reports",
             Path(run_dir) / "raw" / "offline-evidence"]
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
