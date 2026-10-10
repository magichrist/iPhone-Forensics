from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .buyer import CHECKLIST, evaluate
from .capabilities import COVERAGE_LEVELS, coverage_counts, get_matrix
from .util import sha256_file, write_json

# Missing telemetry must stay visibly missing. Never coerce absent data to 0/False/"" —
# "unknown" and "zero" mean opposite things in a forensic report (spec §12 / report-schema.md).
MISSING = "not provided"

# Spec §12 report order. The HTML must render exactly these 15 sections, in this
# order, so a reader (and the section audit) can rely on a stable outline.
SECTION_TITLES: tuple[str, ...] = (
    "Executive summary",
    "Buyer-critical blockers",
    "Device identity (reported by iOS)",
    "Comparison with previous inspection",
    "Buyer checklist and physical tests",
    "Buyer-entered observations",
    "Diagnostic metric candidates",
    "Hardware health assessment (v4)",
    "Hardware integrity assessment (v4)",
    "Crash and panic triage",
    "Automated findings",
    "Unknown / unavailable / unsupported / skipped tests",
    "Collection coverage",
    "Toolchain, evidence integrity, and raw files",
    "Scope, limitations, and next steps",
)

# Which report sections a failed collector leaves unevaluable. Keyword match on the
# collector name; anything unmatched falls back to the evidence-level default.
# Sections are named by title, not number: the v4 hardware/integrity panels are only
# rendered when that data exists, so a hard number could point at an absent heading.
_COLLECTOR_SECTION_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("device-info", ("Device identity (reported by iOS)", "Diagnostic metric candidates",
                     "Hardware health assessment (v4)")),
    ("connected-devices", ("Device identity (reported by iOS)",
                           "Comparison with previous inspection")),
    ("pairing", ("Device identity (reported by iOS)",)),
    ("diagnostics", ("Diagnostic metric candidates", "Hardware health assessment (v4)",
                     "Crash and panic triage")),
    ("ioreg", ("Diagnostic metric candidates", "Hardware health assessment (v4)")),
    ("crash", ("Crash and panic triage",)),
    ("syslog", ("Diagnostic metric candidates", "Crash and panic triage")),
    ("provisioning", ("Device identity (reported by iOS)",)),
    ("installed-apps", ("Application and process inventory (raw evidence only)",)),
    ("processes", ("Application and process inventory (raw evidence only)",)),
    ("backup", ("Offline evidence copy and backup indicator triage",)),
    ("mvt", ("Backup malware-indicator triage (MVT)",)),
)

_DEFAULT_UNEVALUABLE = ("Automated findings", "Collection coverage")


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _val(value: Any, missing: str = MISSING) -> Any:
    """Render absent telemetry as `missing`, never as 0 / False / empty string."""
    if value is None:
        return missing
    if isinstance(value, str) and not value.strip():
        return missing
    return value


def create_manifest(run_dir: Path) -> list[dict[str, Any]]:
    manifest = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name not in {"manifest.json", "report.json", "report.html"}:
            manifest.append({"path":str(path.relative_to(run_dir)), "size_bytes":path.stat().st_size,
                             "sha256":sha256_file(path)})
    write_json(run_dir / "manifest.json", manifest)
    return manifest


def _table(headers: list[str], rows: list[list[Any]], empty: str) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    if not body:
        body = f'<tr><td colspan="{len(headers)}">{esc(empty)}</td></tr>'
    return f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _v4_sections(report: dict[str, Any]) -> str:
    """v4-only HTML: hardware health and integrity panels (empty when absent)."""
    parts: list[str] = []

    hardware = report.get("hardware_assessment") or {}
    subsystems = hardware.get("subsystems", {})
    if subsystems:
        status_rows = [[name, status] for name, status in subsystems.items()]
        check_rows = [[c.get("subsystem", ""), c.get("question", ""), c.get("status", ""),
                       c.get("measurement", ""), c.get("confidence", "")] for c in hardware.get("checks", [])]
        parts.append(
            f"<section class='panel'><h2>8. Hardware health assessment (v4)</h2>"
            f"{_table(['Subsystem', 'Overall status'], status_rows, 'No hardware assessment')}")
        parts.append(_table(["Subsystem", "Question", "Status", "Measurement", "Confidence"],
                            check_rows, "No individual hardware checks recorded"))
        if hardware.get("warnings"):
            warn_rows = [[c.get("subsystem", ""), c.get("question", ""), c.get("explanation", "")] for c in hardware["warnings"]]
            parts.append(_table(["Subsystem", "Warning / review item", "Explanation"], warn_rows, ""))
        parts.append(f"<p class='muted'>{esc(hardware.get('disclaimer', ''))}</p></section>")

    integrity = report.get("integrity_assessment") or {}
    # `continuity` is v4-only: a v3 report has no such key and must render exactly as
    # before. It is also the one field that must be shown even when classifications and
    # changes are both empty — "no differences found" between two snapshots that may not
    # describe the same physical device is not a pass, and hiding the key would let an
    # empty panel imply one.
    continuity = integrity.get("continuity")
    if integrity.get("classifications") or integrity.get("changes") or continuity:
        overall = integrity.get("overall", "inconclusive")
        if overall == "suspicious":
            integrity_verdict_class = "high"
        elif overall == "change_detected":
            integrity_verdict_class = "warn"
        else:
            integrity_verdict_class = "neutral"
        continuity_line = (f"<p class='muted'>Device continuity: {esc(continuity)}</p>"
                           if continuity else "")
        parts.append(
            f"<section class='panel'><h2>9. Hardware integrity assessment (v4)</h2>"
            f"<div class='verdict {integrity_verdict_class}'>"
            f"Integrity status: {esc(overall)}</div>"
            f"{continuity_line}")
        class_rows = [[field_name, status] for field_name, status in integrity.get("classifications", {}).items()]
        parts.append(_table(["Field / item", "Classification"], class_rows, "No classifications"))
        change_rows = [[ch.get("field", ""), ch.get("previous", ""), ch.get("current", ""),
                        ch.get("classification", ch.get("status", "")), ch.get("confidence", "")] for ch in integrity.get("changes", [])]
        parts.append(_table(["Changed field", "Previous", "Current", "Classification", "Confidence"],
                            change_rows, "No changes between snapshots"))
        parts.append(f"<p class='muted'>{esc(integrity.get('disclaimer', ''))}</p></section>")

    return "".join(parts)


def _redact_identifier(value: Any) -> str:
    text = str(value if value is not None else "")
    if len(text) <= 4:
        return "••••" if text else ""
    return "•" * max(4, len(text) - 4) + text[-4:]


def _partial_collection_banner(report: dict[str, Any], assessment: dict[str, Any]) -> str:
    """Visible warning when collection was incomplete (spec §12 / phase-5 task 2).

    A partial run must never read like a healthy one, so the banner names the exact
    report sections that could not be evaluated instead of only counting failures.
    """
    collection = [c for c in report.get("collection", []) if isinstance(c, dict)]
    failed = [c for c in collection if c.get("status") == "failed_or_partial"]
    incomplete_status = assessment.get("status") == "incomplete"
    if not failed and not incomplete_status:
        return ""

    sections: list[str] = []
    for item in failed:
        name = str(item.get("name", "") or "").lower()
        matched = False
        for keyword, mapped in _COLLECTOR_SECTION_HINTS:
            if keyword in name:
                for section in mapped:
                    if section not in sections:
                        sections.append(section)
                matched = True
        if not matched:
            for section in _DEFAULT_UNEVALUABLE:
                if section not in sections:
                    sections.append(section)
    if incomplete_status and not sections:
        # Status is incomplete even when every collector reported success — typically
        # missing identity fields. Identity-dependent sections are what cannot stand.
        for section in ("Device identity (reported by iOS)", "Comparison with previous inspection"):
            if section not in sections:
                sections.append(section)

    failed_names = [str(c.get("name") or "unnamed collector") for c in failed]
    reasons: list[str] = []
    if failed_names:
        reasons.append(f"{len(failed_names)} of {len(collection)} collector(s) failed, timed out, "
                       f"or returned partial output: {', '.join(failed_names)}.")
    if incomplete_status:
        reasons.append("The automated assessment status is 'incomplete' — evidence gaps remain.")
    if not collection:
        reasons.append("No collection commands were recorded for this report.")

    section_items = "".join(f"<li>{esc(section)}</li>" for section in sections)
    reason_items = "".join(f"<li>{esc(reason)}</li>" for reason in reasons)
    return (
        "<section class='panel banner-incomplete' role='alert'>"
        "<h2>⚠ INCOMPLETE COLLECTION — THIS REPORT IS NOT A COMPLETE ASSESSMENT</h2>"
        f"<p><b>Read this first.</b> Collection did not finish cleanly. The sections below could "
        f"not be fully evaluated and must be treated as <b>inconclusive</b>, not as passes and not "
        f"as failures. Do not rely on absent data as a negative result.</p>"
        f"<ul>{reason_items}</ul>"
        + (f"<p><b>Sections that cannot be evaluated from this run:</b></p><ul>{section_items}</ul>"
           if section_items else "")
        + "<p class='muted'>Resolve the failed collectors (toolchain, trust pairing, permissions, "
          "timeouts) and rerun before drawing conclusions. See "
          "'Unknown / unavailable / unsupported / skipped tests' for the full gap list.</p></section>"
    )


def _unknown_panel(report: dict[str, Any]) -> str:
    """Explicit unknown/unavailable/unsupported/skipped panel (spec §12, phase-5 task 3).

    Sourced from the capability matrix so the report cannot drift from what the
    toolchain can and cannot establish. Counts come from the same data as the panel
    rows; nothing here is a pass/fail judgement.
    """
    matrix = get_matrix()
    counts = coverage_counts()
    manual = [row for row in matrix if row.get("coverage") == "manual"]
    unsupported = [row for row in matrix if row.get("coverage") == "unsupported"]
    partial = [row for row in matrix if row.get("coverage") == "partial"]

    def rows_for(rows: list[dict[str, str]]) -> list[list[Any]]:
        return [[row.get("category", ""), row.get("item", ""), row.get("coverage", ""),
                 row.get("requirements", ""), row.get("limits", "")] for row in rows]

    counts_items = "".join(
        f"<li><b>{esc(level)}</b>: {esc(counts.get(level, 0))}</li>" for level in COVERAGE_LEVELS)
    total = len(matrix)
    return (
        "<section class='panel'><h2>12. Unknown / unavailable / unsupported / skipped tests</h2>"
        f"<p>This section exists so that a reader never mistakes <i>not measured</i> for "
        f"<i>measured and fine</i>. It is generated from the project's capability matrix "
        f"({esc(total)} declared capabilities) and lists what software cannot decide, plus what "
        f"this specific run did not collect. Absence of evidence is never a pass.</p>"
        f"<p><b>Capability coverage across the whole project:</b></p><ul>{counts_items}</ul>"
        f"<h3>Can never be established in software ({esc(len(unsupported))})</h3>"
        "<p class='muted'>The tool will never claim these. They require an authorized service "
        "provider, on-device inspection, or are physically impossible to determine.</p>"
        + _table(["Category", "Item", "Coverage", "Why it is not automatic / requirements", "Limits"],
                 rows_for(unsupported), "No unsupported capabilities declared.") +
        f"<h3>Requires a guided manual test ({esc(len(manual))})</h3>"
        "<p class='muted'>A human must run these. Software output can never decide them; a "
        "successful automated run leaves them unverified.</p>"
        + _table(["Category", "Item", "Coverage", "How it is tested / requirements", "Limits"],
                 rows_for(manual), "No manual capabilities declared.") +
        f"<h3>Partial coverage — tool hints only ({esc(len(partial))})</h3>"
        "<p class='muted'>These produce hints, not verdicts. A missing value here means "
        "<i>not tested</i> (newer iOS versions frequently withhold diagnostics), never "
        "<i>healthy</i>.</p>"
        + _table(["Category", "Item", "Coverage", "Source", "Limits"],
                 rows_for(partial), "No partial capabilities declared.") +
        "<h3>Skipped / unavailable in this specific run</h3>"
        "<p class='muted'>Collectors that failed, timed out, were not requested, or whose tool is "
        "not installed. Each line is an evidence gap for the sections named above.</p>"
        + _table(["Collector", "Status", "Exit code", "Timed out", "Timed out seconds"],
                 [[c.get("name", ""), c.get("status", ""), _val(c.get("returncode")),
                   _val(c.get("timed_out")), _val(c.get("duration_seconds"))]
                  for c in report.get("collection", []) if isinstance(c, dict)
                  and c.get("status") not in {"success", "expected_end"}],
                 "Every collector completed or ended as an expected stream boundary. "
                 "Manual and unsupported capabilities above still require a human.") +
        "</section>"
    )


def build_html(run_dir: Path, report: dict[str, Any], redact_identifiers: bool = False) -> None:
    device = report.get("device", {}) if isinstance(report.get("device"), dict) else {}
    important = ["DeviceName", "ProductType", "ProductVersion", "BuildVersion", "ModelNumber",
                 "HardwareModel", "SerialNumber", "InternationalMobileEquipmentIdentity",
                 "ActivationState", "CarrierBundleVersion", "TotalDiskCapacity", "TotalDataCapacity"]
    sensitive_keys = {"SerialNumber", "InternationalMobileEquipmentIdentity", "UniqueDeviceID", "UDID", "WiFiAddress", "BluetoothAddress"}
    identity_rows = [[key, _redact_identifier(device.get(key)) if redact_identifiers and key in sensitive_keys else device.get(key)]
                     for key in important if device.get(key) is not None]
    for capacity_key in ("TotalDiskCapacity", "TotalDataCapacity"):
        value = device.get(capacity_key)
        try:
            capacity_bytes = int(value)
            identity_rows.append([f"{capacity_key} (decimal GB, derived)", f"{capacity_bytes / 1_000_000_000:.2f} GB"])
        except (TypeError, ValueError):
            pass
    findings = report.get("findings", [])
    finding_rows = [[f.get("severity", "INFO"), f.get("title", ""), f.get("detail", ""), ", ".join(f.get("evidence", []))] for f in findings]
    # Missing collection telemetry stays "not provided" — a collector that never ran is not a
    # collector that returned zero bytes / exit code 0.
    collection_rows = [[c.get("name"), c.get("status"), _val(c.get("returncode")),
                        _val(c.get("duration_seconds")), _val(c.get("stdout_bytes")),
                        _val(c.get("stderr_bytes"))]
                       for c in report.get("collection", []) if isinstance(c, dict)]
    tool_rows = [[name, path or "not installed"] for name, path in report.get("tools", {}).items()]
    diagnostic_rows = [[m.get("source"), m.get("key"), _val(m.get("value")), m.get("interpretation")]
                       for m in report.get("diagnostic_candidates", [])]
    limits = report.get("limitations", [])
    crash_triage = report.get("crash_triage", {})
    crash_rows = [[item.get("path"), item.get("category"), _val(item.get("timestamp")),
                   _val(item.get("procName", item.get("name"))), _val(item.get("panicString"))]
                  for item in crash_triage.get("panic_candidates", []) + crash_triage.get("crash_candidates", [])]
    assessment = report.get("assessment", {}) if isinstance(report.get("assessment"), dict) else {}
    checklist_eval = assessment.get("buyer_checklist", evaluate(report.get("buyer_data")))
    checklist_data = report.get("buyer_data") or {}
    checks = checklist_data.get("checks", {}) if isinstance(checklist_data, dict) else {}
    buyer_rows = []
    for item in CHECKLIST:
        entry = checks.get(item["id"], {}) if isinstance(checks, dict) else {}
        buyer_rows.append([item["category"], item["label"], (entry.get("status", "not_tested") if isinstance(entry, dict) else "not_tested"),
                           (entry.get("notes", "") if isinstance(entry, dict) else ""), "Critical" if item["critical"] else "Standard"])
    buyer = checklist_data.get("buyer", {}) if isinstance(checklist_data, dict) else {}
    observations = checklist_data.get("observations", {}) if isinstance(checklist_data, dict) else {}
    currency = buyer.get("currency") or "USD"  # documented default; template() always sets it
    # Buyer-supplied observations are free text: an omitted field is "not provided", never 0.
    buyer_summary = [["Asking price", _val(buyer.get("asking_price"))], ["Currency", currency],
                     ["Country/region", _val(buyer.get("country_or_region"))],
                     ["Advertised model", _val(buyer.get("advertised_model"))],
                     ["Advertised storage", _val(buyer.get("advertised_storage"))],
                     ["Battery maximum capacity (%)", _val(observations.get("battery_max_capacity_percent"))],
                     ["Battery cycle count", _val(observations.get("battery_cycle_count"))],
                     ["Reported storage (GB)", _val(observations.get("reported_storage_gb"))],
                     ["Repair estimate", _val(observations.get("repair_estimate"))],
                     ["Carrier eligibility", _val(observations.get("carrier_eligibility_result"), "not_checked")]]
    buyer_summary_rows = [[k, v] for k, v in buyer_summary]
    asking = buyer.get("asking_price")
    repair = observations.get("repair_estimate")
    projected_cost = None
    try:
        if asking is not None and repair is not None:
            projected_cost = float(asking) + float(repair)
    except (TypeError, ValueError):
        projected_cost = None
    if projected_cost is not None:
        buyer_summary_rows.append(["Asking price + buyer-entered repair estimate",
                                   f"{projected_cost:g} {currency} (not a market valuation)"])
    if report.get("comparison"):
        comparison_rows = [[item.get("field"), item.get("previous"), item.get("current"), item.get("status")] for item in report["comparison"].get("changes", [])]
    else:
        comparison_rows = []
    severity_class = "high" if assessment.get("status") == "high_risk" else "warn" if assessment.get("status") in {"incomplete", "review"} else "neutral"
    # A partial run must never be styled or worded like a healthy one.
    incomplete_banner = _partial_collection_banner(report, assessment)
    if incomplete_banner and severity_class == "neutral":
        severity_class = "warn"
    unknown_panel = _unknown_panel(report)
    v4_sections = _v4_sections(report)
    html_doc = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>iPhone Forensics v{esc(report.get("version"))} — Buyer Inspection Report</title>
<style>
:root{{--bg:#f4f6f9;--panel:#fff;--ink:#17202b;--muted:#5e6a78;--line:#dce2e8;--accent:#2459a9;--high:#9c2525;--warn:#8b5a00;--good:#176b43}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:26px 18px 60px}}h1{{font-size:clamp(1.7rem,4vw,2.6rem);margin:0}}h2{{font-size:1.28rem;margin:0 0 12px}}h3{{font-size:1rem;margin:0 0 8px}}p{{margin:8px 0}}.muted{{color:var(--muted)}}.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin:16px 0;box-shadow:0 2px 8px #152b4308}}
.hero{{border-top:5px solid var(--accent)}}.banner-incomplete{{border:2px solid var(--high);background:#fdeaea}}.banner-incomplete h2{{color:var(--high);margin-bottom:10px}}.banner-incomplete ul{{margin:8px 0;padding-left:22px}}.banner-incomplete li{{margin:4px 0}}.verdict{{padding:14px;border-radius:10px;font-weight:750;font-size:1.1rem}}.verdict.high{{background:#fce8e8;color:var(--high)}}.verdict.warn{{background:#fff3d9;color:var(--warn)}}.verdict.neutral{{background:#e8f5ee;color:var(--good)}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:10px;margin-top:14px}}.stat{{border:1px solid var(--line);border-radius:10px;padding:12px}}.stat b{{display:block;font-size:1.3rem}}.table-wrap{{width:100%;overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:560px}}th,td{{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}th{{background:#f0f3f7;font-size:.84rem}}td{{font-size:.92rem}}.pill{{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:.78rem;font-weight:700}}.callout{{border-left:4px solid var(--accent);padding:10px 12px;background:#edf3fb}}code{{overflow-wrap:anywhere}}details summary{{cursor:pointer;font-weight:650}}footer{{margin-top:26px;color:var(--muted);font-size:.85rem}}@media(max-width:600px){{main{{padding:16px 10px 40px}}.panel{{padding:13px}}}}@media print{{body{{background:#fff}}main{{max-width:none;padding:0}}.panel{{box-shadow:none;break-inside:avoid}}}}
</style></head><body><main>
<header><p class="muted">LOCAL DEVICE INSPECTION · V{esc(report.get("version"))}</p><h1>Used iPhone Inspection Report</h1><p class="muted">Started {esc(report.get("started_at"))} · Finished {esc(report.get("finished_at"))}</p></header>
<section class="panel hero"><h2>1. Executive summary</h2><div class="verdict {severity_class}">{esc(assessment.get("verdict", "INCOMPLETE — NO ASSESSMENT"))}</div><p>{esc(assessment.get("description", ""))}</p>
<div class="stats"><div class="stat"><span class="muted">Collectors completed</span><b>{esc(_val(assessment.get("collection_successful")))}/{esc(_val(assessment.get("collection_total")))}</b></div><div class="stat"><span class="muted">Failed / partial</span><b>{esc(_val(assessment.get("collection_failed_or_partial")))}</b></div><div class="stat"><span class="muted">Identity fields</span><b>{esc(_val(assessment.get("identity_fields_present")))}/{esc(_val(assessment.get("identity_fields_expected")))}</b></div><div class="stat"><span class="muted">Checklist passed</span><b>{esc(_val(checklist_eval.get("counts", {}).get("pass")))}/{len(CHECKLIST)}</b></div></div>
<p class="callout"><b>Interpretation:</b> missing or inaccessible data is unknown, not a pass or a device defect. This tool cannot certify authenticity, hardware health, water resistance, Activation Lock status, or blacklist eligibility.</p></section>
{incomplete_banner}
<section class="panel"><h2>2. Buyer-critical blockers</h2>
{_table(["Status","Item"], [["FAILED", x] for x in checklist_eval.get("critical_failures", [])] + [["NOT VERIFIED", x] for x in checklist_eval.get("critical_unknowns", [])], "No critical checklist gaps are recorded. Independently verify activation and carrier eligibility before payment.")}</section>
<section class="panel"><h2>3. Device identity (reported by iOS)</h2>{_table(["Field","Reported value"], identity_rows, "No parsed identity fields. Check raw metadata and Settings → General → About.")}
<p class="muted">Identifiers such as serial number, IMEI and UDID are sensitive. Reported values are not cryptographic proof of authenticity.{" This HTML export masks identifiers; the private JSON/raw evidence remains unredacted." if redact_identifiers else ""}</p></section>
<section class="panel"><h2>4. Comparison with previous inspection</h2>{_table(["Field","Previous","Current","Assessment"], comparison_rows, "No previous report was supplied for comparison.")}</section>
<section class="panel"><h2>5. Buyer checklist and physical tests</h2><p>Update <code>buyer-checklist.json</code> with statuses <code>pass</code>, <code>fail</code>, <code>not_tested</code>, or <code>not_applicable</code>, then rerun with <code>--buyer-json</code>.</p>
{_table(["Category","Check","Status","Notes","Priority"], buyer_rows, "No checks")}</section>
<section class="panel"><h2>6. Buyer-entered observations</h2>{_table(["Field","Value"], buyer_summary_rows, "No observations")}</section>
<section class="panel"><h2>7. Diagnostic metric candidates</h2><p>These are source fields whose names look relevant to battery, capacity, thermal, voltage, or storage. They are not normalized or interpreted as health scores; verify units and semantics against the source/tool version.</p>{_table(["Source","Field","Raw value","Caveat"], diagnostic_rows, "No candidate metrics were exposed by the collected diagnostics. This is inconclusive.")}</section>
{v4_sections}
<section class="panel"><h2>10. Crash and panic triage</h2><p>{esc(crash_triage.get("interpretation", "No crash artifact triage was performed."))}</p><p>Files scanned: {esc(_val(crash_triage.get("files_scanned")))} · Crash/diagnostic candidates: {esc(_val(crash_triage.get("crash_or_diagnostic_count")))} · Panic/watchdog candidates: {esc(_val(crash_triage.get("panic_or_watchdog_candidate_count")))}</p>{_table(["Artifact","Category","Timestamp","Process","Panic signature (if present)"], crash_rows, "No collected crash-report files to triage. This does not mean the phone has no crash history.")}</section>
<section class="panel"><h2>11. Automated findings</h2>{_table(["Severity","Finding","Interpretation","Evidence files"], finding_rows, "No automated findings. This is not a health certification.")}</section>
{unknown_panel}
<section class="panel"><h2>13. Collection coverage</h2>{_table(["Collector","Status","Exit code","Seconds","Output bytes","Error bytes"], collection_rows, "No collection commands were run.")}
<p class="muted">An expected end of a bounded live log stream is normal. Nonzero exits and timeouts should be reviewed in raw output before interpretation. A missing entry here means the collector never reported — it is not a zero-length success.</p></section>
<section class="panel"><h2>14. Toolchain, evidence integrity, and raw files</h2>{_table(["Tool","Detected path"], tool_rows, "No tool inventory")}
<p class="muted">Capability catalogs contain tool help output only. The presence of a command does not mean the project has safely executed every capability it advertises.</p>
<p>SHA-256 digests and sizes are stored in <code>manifest.json</code>. They help detect changes after collection; they do not prove that device-originated data is authentic.</p><p>Machine-readable companion: <code>report.json</code>. Raw command output and capability help are in <code>raw/</code>. Keep this directory private.</p></section>
<section class="panel"><h2>15. Scope, limitations, and next steps</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in limits)}</ul>
<h3>Recommended pre-payment sequence</h3><ol><li>Seller signs out of Apple Account / Find My and erases the phone.</li><li>Connect to the internet and confirm setup does not request the previous owner's credentials or show unexpected Remote Management.</li><li>Confirm carrier eligibility using the intended carrier or a trusted authoritative provider.</li><li>Complete physical tests and inspect Parts & Service History and Battery Health in Settings.</li><li>Agree on price, return terms, and proof of sale only after unresolved critical checks are settled.</li></ol></section>
<footer>iPhone Forensics v{esc(report.get("version"))} · Generated locally · HTML is the primary human-readable report; JSON and manifest are companion evidence files.</footer>
</main></body></html>'''
    (run_dir / "report.html").write_text(html_doc, encoding="utf-8")


def finalize(run_dir: Path, report: dict[str, Any], redact_identifiers: bool = False) -> None:
    report["finished_at"] = report.get("finished_at") or __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    create_manifest(run_dir)
    write_json(run_dir / "report.json", report)
    build_html(run_dir, report, redact_identifiers=redact_identifiers)
    if redact_identifiers:
        redacted = dict(report)
        redacted_device = dict(report.get("device", {})) if isinstance(report.get("device"), dict) else {}
        for key in ("SerialNumber", "InternationalMobileEquipmentIdentity", "UniqueDeviceID", "UDID", "WiFiAddress", "BluetoothAddress"):
            if key in redacted_device:
                redacted_device[key] = _redact_identifier(redacted_device[key])
        redacted["device"] = redacted_device
        original_udid = str(report.get("target_udid", "") or "")
        redacted["target_udid"] = _redact_identifier(original_udid)
        redacted["connected_devices"] = [_redact_identifier(value) for value in report.get("connected_devices", [])]
        redacted["tools_pymobiledevice3"] = report.get("tools_pymobiledevice3")
        for collection_item in redacted.get("collection", []):
            command = collection_item.get("command", []) if isinstance(collection_item, dict) else []
            if original_udid:
                collection_item["command"] = [str(part).replace(original_udid, _redact_identifier(original_udid)) for part in command]
        write_json(run_dir / "report-redacted.json", redacted)
        # report-redacted.html is generated from the redacted copy; never include raw evidence links.
        build_html(run_dir, redacted, redact_identifiers=True)
        generated = (run_dir / "report.html").read_text(encoding="utf-8")
        (run_dir / "report-redacted.html").write_text(generated, encoding="utf-8")
        build_html(run_dir, report, redact_identifiers=False)
