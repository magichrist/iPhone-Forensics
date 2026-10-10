from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import analyze_crash_artifacts, automated_assessment, compare_reports, derive_findings
from .buyer import template
from .collectors import LIB_TOOLS, collect_capabilities, collect_device, discover_devices
from .reporting import finalize
from .util import secure_mkdir, write_json

LIMITATIONS = [
    "This is a buyer-oriented inspection aid, not a forensic certification or substitute for Apple/authorized service diagnostics.",
    "iOS and pairing permissions restrict access; this project cannot acquire every protected file or diagnostic.",
    "Missing, denied, empty, unsupported, or failed measurements are unknown, not proof of a defect or proof of health.",
    "Software cannot prove authenticity, absence of hidden repairs, liquid exposure, water resistance, or latent hardware faults.",
    "Activation Lock, organization enrollment after reset, carrier blacklist, financing, and carrier eligibility need independent checks.",
    "Battery and hardware metrics are included only when actually exposed by the device/tool version; unsupported values are not fabricated.",
    "App inventory, process lists, logs, crash reports, provisioning data, and backups may expose private data.",
    "SHA-256 hashes show whether collected files changed after hashing; they do not prove device-originated data is authentic.",
    "Capability catalogs collect help text only. Discovered state-changing commands are not automatically executed.",
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="iphone-forensics",
        description="Local-first, non-destructive iPhone inspection with an HTML buyer report.")
    parser.add_argument("--udid", help="Target device UDID. If omitted, exactly one connected device is required.")
    parser.add_argument("--output", default=str(Path.home() / "Desktop" / "iphone-forensics"),
                        help="Output root directory (default: ~/Desktop/iphone-forensics)")
    parser.add_argument("--buyer-json", help="Read buyer checklist/price/observations from a JSON file.")
    parser.add_argument("--compare-json", help="Compare this run with a previous report.json.")
    parser.add_argument("--redact-identifiers", action="store_true", help="Also emit report-redacted.html and report-redacted.json with identifiers masked.")
    parser.add_argument("--mvt-backup", help="Optionally run installed mvt-ios check-backup against an existing authorized backup directory.")
    parser.add_argument("--init-buyer-checklist", metavar="PATH", help="Write an editable buyer-checklist JSON template and exit.")
    parser.add_argument("--no-capability-catalog", action="store_true", help="Skip tool help catalog for a faster run.")
    parser.add_argument("--crash-reports", action="store_true", help="Copy/pull crash reports where supported; may collect private data.")
    parser.add_argument("--app-list", action="store_true", help="Collect installed-app inventory (privacy-sensitive).")
    parser.add_argument("--provisioning", action="store_true", help="Collect provisioning-profile inventory where supported.")
    parser.add_argument("--syslog-seconds", type=int, default=0, help="Bounded libimobiledevice live log capture (0–120 seconds).")
    parser.add_argument("--pmd-syslog-seconds", type=int, default=0, help="Bounded pymobiledevice3 live log capture (0–120 seconds).")
    parser.add_argument("--pmd-crash-reports", action="store_true", help="Collect crash reports using pymobiledevice3.")
    parser.add_argument("--pmd-processes", action="store_true", help="Collect process inventory using pymobiledevice3 (privacy-sensitive).")
    parser.add_argument("--pmd-app-list", action="store_true", help="Collect installed-app inventory using pymobiledevice3.")
    parser.add_argument("--backup", choices=("none", "libimobiledevice", "pymobiledevice3"), default="none",
                        help="Create a potentially sensitive full backup; default is none.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    for name in ("syslog_seconds", "pmd_syslog_seconds"):
        if not 0 <= getattr(args, name) <= 120:
            print(f"error: --{name.replace('_', '-')} must be between 0 and 120", file=sys.stderr)
            return 2
    if args.init_buyer_checklist:
        target = Path(args.init_buyer_checklist).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        write_json(target, template())
        print(f"Buyer checklist template written: {target}")
        return 0

    buyer_data: dict[str, Any] = template()
    if args.buyer_json:
        source = Path(args.buyer_json).expanduser()
        try:
            loaded = json.loads(source.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("top-level JSON must be an object")
            # Deep-merge user fields into the complete default checklist so omitted
            # check entries remain explicitly unknown instead of disappearing.
            defaults = template()
            for section in ("buyer", "observations"):
                if isinstance(loaded.get(section), dict):
                    defaults[section].update(loaded[section])
            if isinstance(loaded.get("checks"), dict):
                for check_id, entry in loaded["checks"].items():
                    if check_id in defaults["checks"] and isinstance(entry, dict):
                        defaults["checks"][check_id].update(entry)
            buyer_data = defaults
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"error: cannot read --buyer-json: {exc}", file=sys.stderr)
            return 2

    output_root = Path(args.output).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = output_root / f"iphone-audit-{stamp}"
    suffix = 1
    while run_dir.exists():
        run_dir = output_root / f"iphone-audit-{stamp}-{suffix}"
        suffix += 1
    secure_mkdir(run_dir)
    raw = run_dir / "raw"
    raw.mkdir(mode=0o700)
    report: dict[str, Any] = {
        "project":"iPhone Forensics", "version":__version__,
        "started_at":dt.datetime.now(dt.timezone.utc).isoformat(), "finished_at":None,
        "host":{"platform":platform.platform(), "macOS":platform.mac_ver()[0],
                "python":sys.version.split()[0], "architecture":platform.machine()},
        "tools":{name:shutil.which(name) for name in LIB_TOOLS},
        "tools_pymobiledevice3":shutil.which("pymobiledevice3"),
        "target_udid":None, "connected_devices":[], "device":{}, "collection":[],
        "findings":[], "limitations":LIMITATIONS, "buyer_data":buyer_data,
        "scope":{"default_read_only":True, "backup_requested":args.backup != "none",
                 "logs_requested":bool(args.syslog_seconds or args.pmd_syslog_seconds),
                 "crash_reports_requested":bool(args.crash_reports or args.pmd_crash_reports),
                 "app_inventory_requested":bool(args.app_list or args.pmd_app_list)},
    }
    report["tools"]["pymobiledevice3"] = report["tools_pymobiledevice3"]
    report["tools"]["mvt-ios"] = shutil.which("mvt-ios")
    write_json(run_dir / "buyer-checklist.json", buyer_data)

    device_tool_available = any(path for name, path in report["tools"].items() if name != "mvt-ios")
    if args.mvt_backup and not device_tool_available:
        _run_mvt_backup(args.mvt_backup, run_dir, raw, report)
        _finish(run_dir, report, buyer_data, args.compare_json, args.redact_identifiers)
        success = any(item.get("name") == "mvt-check-backup" and item.get("status") == "success" for item in report["collection"])
        print(f"Offline backup triage complete. HTML report: {run_dir / 'report.html'}")
        return 0 if success else 2

    if not device_tool_available:
        report["findings"].append({"severity":"BLOCKER", "title":"No supported toolkit detected",
            "detail":"Install libimobiledevice and/or pymobiledevice3, then reconnect the phone.", "evidence":[]})
        _finish(run_dir, report, buyer_data, args.compare_json, args.redact_identifiers)
        print(f"No supported toolkit detected. HTML report: {run_dir / 'report.html'}")
        return 2

    if not args.no_capability_catalog:
        collect_capabilities(raw, report)
    devices = discover_devices(raw, report["collection"])
    report["connected_devices"] = devices
    if args.udid:
        udid = args.udid
        if devices and udid not in devices:
            report["findings"].append({"severity":"WARNING", "title":"Requested device not found in discovery output",
                "detail":"The selected UDID was not listed by discovery. It may be disconnected, unpaired, or visible through a transport this tool does not enumerate.",
                "evidence":["raw/connected-devices.txt"]})
    elif len(devices) == 1:
        udid = devices[0]
    elif not devices:
        report["findings"].append({"severity":"BLOCKER", "title":"No connected device detected",
            "detail":"Unlock the iPhone, connect a data-capable cable, approve Trust This Computer, and retry.",
            "evidence":["raw/connected-devices.txt"]})
        _finish(run_dir, report, buyer_data, args.compare_json, args.redact_identifiers)
        print(f"No device detected. HTML report: {run_dir / 'report.html'}")
        return 3
    else:
        report["findings"].append({"severity":"BLOCKER", "title":"Multiple devices detected",
            "detail":"Disconnect other devices or rerun with --udid for the intended phone.", "evidence":["raw/connected-devices.txt"]})
        _finish(run_dir, report, buyer_data, args.compare_json, args.redact_identifiers)
        print(f"Multiple devices detected. HTML report: {run_dir / 'report.html'}")
        return 4

    report["target_udid"] = udid
    collect_device(args, run_dir, raw, report, udid)
    if args.mvt_backup:
        _run_mvt_backup(args.mvt_backup, run_dir, raw, report)
    _finish(run_dir, report, buyer_data, args.compare_json, args.redact_identifiers)
    print("\nInspection finished.")
    print(f"HTML buyer report: {run_dir / 'report.html'}")
    print(f"JSON data:         {run_dir / 'report.json'}")
    print(f"Evidence manifest: {run_dir / 'manifest.json'}")
    print(f"Buyer checklist:   {run_dir / 'buyer-checklist.json'}")
    print("Review unknowns and buyer-critical checks before paying; do not treat missing data as a pass.")
    return 0


def _run_mvt_backup(backup_path: str, run_dir: Path, raw: Path, report: dict[str, Any]) -> None:
    import shutil
    from .util import run_command, write_command_result
    executable = shutil.which("mvt-ios")
    source = Path(backup_path).expanduser().resolve()
    if not source.exists() or not source.is_dir():
        report.setdefault("findings", []).append({"severity":"WARNING", "title":"MVT backup path unavailable",
            "detail":"The supplied path does not exist or is not a directory; no MVT scan was run.", "evidence":[]})
        return
    if not executable:
        report.setdefault("findings", []).append({"severity":"INFO", "title":"MVT not installed",
            "detail":"Install Mobile Verification Toolkit (mvt-ios) separately to scan an existing authorized backup.", "evidence":[]})
        return
    output_dir = raw / "mvt-results"
    output_dir.mkdir(mode=0o700)
    command = [executable, "check-backup", "--output", str(output_dir), str(source)]
    result = run_command(command, timeout=3600)
    report.setdefault("collection", []).append(write_command_result(raw, "mvt-check-backup", result))
    report["mvt"] = {"input_backup":str(source), "output_directory":"raw/mvt-results",
                      "note":"MVT output is triage evidence, not proof that a device is clean or compromised."}


def _finish(run_dir: Path, report: dict[str, Any], buyer_data: dict[str, Any],
            compare_json: str | None = None, redact_identifiers: bool = False) -> None:
    if compare_json:
        try:
            previous = json.loads(Path(compare_json).expanduser().read_text(encoding="utf-8"))
            if isinstance(previous, dict):
                report["comparison"] = compare_reports(previous, report)
            else:
                report["findings"].append({"severity":"WARNING", "title":"Comparison input is not a JSON object",
                    "detail":"The previous report could not be compared.", "evidence":[]})
        except (OSError, json.JSONDecodeError) as exc:
            report["findings"].append({"severity":"WARNING", "title":"Previous report could not be loaded",
                "detail":str(exc), "evidence":[]})
    report["crash_triage"] = analyze_crash_artifacts(run_dir)
    if report["crash_triage"]["panic_or_watchdog_candidate_count"]:
        report.setdefault("findings", []).append({"severity":"REVIEW", "title":"Panic/watchdog candidate artifacts collected",
            "detail":f"Found {report['crash_triage']['panic_or_watchdog_candidate_count']} filename/content candidates. This is triage only, not a hardware diagnosis; investigate repeated events and source context.",
            "evidence":[item["path"] for item in report["crash_triage"]["panic_candidates"][:10]]})
    report["assessment"] = automated_assessment(report, buyer_data)
    report["findings"] = derive_findings(report, buyer_data)
    finalize(run_dir, report, redact_identifiers=redact_identifiers)


if __name__ == "__main__":
    raise SystemExit(main())
