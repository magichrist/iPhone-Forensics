from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .buyer import CHECKLIST, evaluate
from .util import sha256_file, write_json


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


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


def _redact_identifier(value: Any) -> str:
    text = str(value if value is not None else "")
    if len(text) <= 4:
        return "••••" if text else ""
    return "•" * max(4, len(text) - 4) + text[-4:]


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
    collection_rows = [[c.get("name"), c.get("status"), c.get("returncode"), c.get("duration_seconds"),
                        c.get("stdout_bytes"), c.get("stderr_bytes")] for c in report.get("collection", [])]
    tool_rows = [[name, path or "not installed"] for name, path in report.get("tools", {}).items()]
    diagnostic_rows = [[m.get("source"), m.get("key"), m.get("value"), m.get("interpretation")]
                       for m in report.get("diagnostic_candidates", [])]
    limits = report.get("limitations", [])
    crash_triage = report.get("crash_triage", {})
    crash_rows = [[item.get("path"), item.get("category"), item.get("timestamp", ""), item.get("procName", item.get("name", "")), item.get("panicString", "")]
                  for item in crash_triage.get("panic_candidates", []) + crash_triage.get("crash_candidates", [])]
    assessment = report.get("assessment", {})
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
    buyer_summary = [["Asking price", buyer.get("asking_price", "not provided")], ["Currency", buyer.get("currency", "USD")],
                     ["Country/region", buyer.get("country_or_region", "not provided")],
                     ["Advertised model", buyer.get("advertised_model", "not provided")],
                     ["Advertised storage", buyer.get("advertised_storage", "not provided")],
                     ["Battery maximum capacity (%)", observations.get("battery_max_capacity_percent", "not provided")],
                     ["Battery cycle count", observations.get("battery_cycle_count", "not provided")],
                     ["Repair estimate", observations.get("repair_estimate", "not provided")],
                     ["Carrier eligibility", observations.get("carrier_eligibility_result", "not_checked")]]
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
        buyer_summary_rows.append(["Asking price + buyer-entered repair estimate", f"{projected_cost:g} {buyer.get('currency', 'USD')} (not a market valuation)"])
    if report.get("comparison"):
        comparison_rows = [[item.get("field"), item.get("previous"), item.get("current"), item.get("status")] for item in report["comparison"].get("changes", [])]
    else:
        comparison_rows = []
    severity_class = "high" if assessment.get("status") == "high_risk" else "warn" if assessment.get("status") in {"incomplete", "review"} else "neutral"
    html_doc = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>iPhone Forensics v{esc(report.get("version"))} — Buyer Inspection Report</title>
<style>
:root{{--bg:#f4f6f9;--panel:#fff;--ink:#17202b;--muted:#5e6a78;--line:#dce2e8;--accent:#2459a9;--high:#9c2525;--warn:#8b5a00;--good:#176b43}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:26px 18px 60px}}h1{{font-size:clamp(1.7rem,4vw,2.6rem);margin:0}}h2{{font-size:1.28rem;margin:0 0 12px}}h3{{font-size:1rem;margin:0 0 8px}}p{{margin:8px 0}}.muted{{color:var(--muted)}}.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin:16px 0;box-shadow:0 2px 8px #152b4308}}
.hero{{border-top:5px solid var(--accent)}}.verdict{{padding:14px;border-radius:10px;font-weight:750;font-size:1.1rem}}.verdict.high{{background:#fce8e8;color:var(--high)}}.verdict.warn{{background:#fff3d9;color:var(--warn)}}.verdict.neutral{{background:#e8f5ee;color:var(--good)}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:10px;margin-top:14px}}.stat{{border:1px solid var(--line);border-radius:10px;padding:12px}}.stat b{{display:block;font-size:1.3rem}}.table-wrap{{width:100%;overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:560px}}th,td{{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}th{{background:#f0f3f7;font-size:.84rem}}td{{font-size:.92rem}}.pill{{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:.78rem;font-weight:700}}.callout{{border-left:4px solid var(--accent);padding:10px 12px;background:#edf3fb}}code{{overflow-wrap:anywhere}}details summary{{cursor:pointer;font-weight:650}}footer{{margin-top:26px;color:var(--muted);font-size:.85rem}}@media(max-width:600px){{main{{padding:16px 10px 40px}}.panel{{padding:13px}}}}@media print{{body{{background:#fff}}main{{max-width:none;padding:0}}.panel{{box-shadow:none;break-inside:avoid}}}}
</style></head><body><main>
<header><p class="muted">LOCAL DEVICE INSPECTION · V{esc(report.get("version"))}</p><h1>Used iPhone Inspection Report</h1><p class="muted">Started {esc(report.get("started_at"))} · Finished {esc(report.get("finished_at"))}</p></header>
<section class="panel hero"><h2>Buyer summary</h2><div class="verdict {severity_class}">{esc(assessment.get("verdict", "INCOMPLETE — NO ASSESSMENT"))}</div><p>{esc(assessment.get("description", ""))}</p>
<div class="stats"><div class="stat"><span class="muted">Collectors completed</span><b>{esc(assessment.get("collection_successful", 0))}/{esc(assessment.get("collection_total", 0))}</b></div><div class="stat"><span class="muted">Failed / partial</span><b>{esc(assessment.get("collection_failed_or_partial", 0))}</b></div><div class="stat"><span class="muted">Identity fields</span><b>{esc(assessment.get("identity_fields_present", 0))}/{esc(assessment.get("identity_fields_expected", 4))}</b></div><div class="stat"><span class="muted">Checklist passed</span><b>{esc(checklist_eval.get("counts", {}).get("pass", 0))}/{len(CHECKLIST)}</b></div></div>
<p class="callout"><b>Interpretation:</b> missing or inaccessible data is unknown, not a pass or a device defect. This tool cannot certify authenticity, hardware health, water resistance, Activation Lock status, or blacklist eligibility.</p></section>
<section class="panel"><h2>1. Buyer-critical blockers</h2>
{_table(["Status","Item"], [["FAILED", x] for x in checklist_eval.get("critical_failures", [])] + [["NOT VERIFIED", x] for x in checklist_eval.get("critical_unknowns", [])], "No critical checklist gaps are recorded. Independently verify activation and carrier eligibility before payment.")}</section>
<section class="panel"><h2>2. Device identity (reported by iOS)</h2>{_table(["Field","Reported value"], identity_rows, "No parsed identity fields. Check raw metadata and Settings → General → About.")}
<p class="muted">Identifiers such as serial number, IMEI and UDID are sensitive. Reported values are not cryptographic proof of authenticity.{" This HTML export masks identifiers; the private JSON/raw evidence remains unredacted." if redact_identifiers else ""}</p></section>
<section class="panel"><h2>3. Comparison with previous inspection</h2>{_table(["Field","Previous","Current","Assessment"], comparison_rows, "No previous report was supplied for comparison.")}</section>
<section class="panel"><h2>4. Buyer checklist and physical tests</h2><p>Update <code>buyer-checklist.json</code> with statuses <code>pass</code>, <code>fail</code>, <code>not_tested</code>, or <code>not_applicable</code>, then rerun with <code>--buyer-json</code>.</p>
{_table(["Category","Check","Status","Notes","Priority"], buyer_rows, "No checks")}</section>
<section class="panel"><h2>5. Buyer-entered observations</h2>{_table(["Field","Value"], buyer_summary_rows, "No observations")}</section>
<section class="panel"><h2>6. Diagnostic metric candidates</h2><p>These are source fields whose names look relevant to battery, capacity, thermal, voltage, or storage. They are not normalized or interpreted as health scores; verify units and semantics against the source/tool version.</p>{_table(["Source","Field","Raw value","Caveat"], diagnostic_rows, "No candidate metrics were exposed by the collected diagnostics. This is inconclusive.")}</section>
<section class="panel"><h2>7. Crash and panic triage</h2><p>{esc(crash_triage.get("interpretation", "No crash artifact triage was performed."))}</p><p>Files scanned: {esc(crash_triage.get("files_scanned", 0))} · Crash/diagnostic candidates: {esc(crash_triage.get("crash_or_diagnostic_count", 0))} · Panic/watchdog candidates: {esc(crash_triage.get("panic_or_watchdog_candidate_count", 0))}</p>{_table(["Artifact","Category","Timestamp","Process","Panic signature (if present)"], crash_rows, "No collected crash-report files to triage. This does not mean the phone has no crash history.")}</section>
<section class="panel"><h2>8. Automated findings</h2>{_table(["Severity","Finding","Interpretation","Evidence files"], finding_rows, "No automated findings. This is not a health certification.")}</section>
<section class="panel"><h2>9. Collection coverage</h2>{_table(["Collector","Status","Exit code","Seconds","Output bytes","Error bytes"], collection_rows, "No collection commands were run.")}
<p class="muted">An expected end of a bounded live log stream is normal. Nonzero exits and timeouts should be reviewed in raw output before interpretation.</p></section>
<section class="panel"><h2>10. Toolchain</h2>{_table(["Tool","Detected path"], tool_rows, "No tool inventory")}
<p>Capability catalogs contain tool help output only. The presence of a command does not mean the project has safely executed every capability it advertises.</p></section>
<section class="panel"><h2>11. Evidence integrity and raw files</h2><p>SHA-256 digests and sizes are stored in <code>manifest.json</code>. They help detect changes after collection; they do not prove that device-originated data is authentic.</p><p>Machine-readable companion: <code>report.json</code>. Raw command output and capability help are in <code>raw/</code>. Keep this directory private.</p></section>
<section class="panel"><h2>12. Scope and limitations</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in limits)}</ul></section>
<section class="panel"><h2>13. Recommended pre-payment sequence</h2><ol><li>Seller signs out of Apple Account / Find My and erases the phone.</li><li>Connect to the internet and confirm setup does not request the previous owner's credentials or show unexpected Remote Management.</li><li>Confirm carrier eligibility using the intended carrier or a trusted authoritative provider.</li><li>Complete physical tests and inspect Parts & Service History and Battery Health in Settings.</li><li>Agree on price, return terms, and proof of sale only after unresolved critical checks are settled.</li></ol></section>
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
