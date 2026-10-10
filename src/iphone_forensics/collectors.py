from __future__ import annotations

import plistlib
import re
import shutil
from pathlib import Path
from typing import Any

from .util import run_command, safe_name, write_command_result

LIB_TOOLS = ["idevice_id", "ideviceinfo", "idevicepair", "idevicediagnostics",
             "idevicecrashreport", "idevicesyslog", "idevicebackup2", "ideviceinstaller",
             "ideviceprovision", "idevicedate", "idevicename", "ideviceimagemounter"]


def decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def parse_plist(value: bytes) -> Any:
    try:
        return plistlib.loads(value)
    except Exception:
        return None


def parse_key_values(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            if key.strip() and len(key) < 160:
                result[key.strip()] = value.strip()
    return result


def diagnostic_candidates(payload: bytes, source: str) -> list[dict[str, Any]]:
    """Extract only plausible battery/storage/thermal values; never infer missing metrics."""
    parsed = parse_plist(payload)
    if parsed is None:
        parsed = parse_key_values(decode(payload))
    patterns = re.compile(r"battery|gas.?gauge|cycle.?count|full.?charge|design.?capacity|maximum.?capacity|temperature|thermal|voltage|health|nand|disk.?capacity", re.IGNORECASE)
    candidates: list[dict[str, Any]] = []

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(child, (dict, list)):
                    walk(child, path)
                elif patterns.search(path):
                    candidates.append({"source":source, "key":path, "value":child,
                                       "interpretation":"Raw diagnostic candidate; units and meaning depend on the source field."})
        elif isinstance(value, list):
            for index, child in enumerate(value[:500]):
                walk(child, f"{prefix}[{index}]")
        elif isinstance(value, str):
            for line in value.splitlines():
                if ": " in line:
                    key, child = line.split(": ", 1)
                    if patterns.search(key):
                        candidates.append({"source":source, "key":key.strip(), "value":child.strip(),
                                           "interpretation":"Raw diagnostic candidate; units and meaning depend on the source field."})
    walk(parsed)
    return candidates[:300]


def save_result(raw: Path, collection: list[dict[str, Any]], name: str,
                command: list[str], timeout: int = 45) -> dict[str, Any]:
    result = run_command(command, timeout=timeout)
    meta = write_command_result(raw, name, result)
    collection.append(meta)
    return result


def discover_devices(raw: Path, collection: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    idevice_id = shutil.which("idevice_id")
    if idevice_id:
        res = save_result(raw, collection, "connected-devices-libimobiledevice", [idevice_id, "-l"], 15)
        found.extend(line.strip() for line in decode(res["stdout"]).splitlines() if line.strip())
    pmd = shutil.which("pymobiledevice3")
    if pmd:
        res = save_result(raw, collection, "connected-devices-pymobiledevice3", [pmd, "usbmux", "list"], 20)
        text = decode(res["stdout"]) + "\n" + decode(res["stderr"])
        found.extend(re.findall(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", text))
    unique = list(dict.fromkeys(found))
    (raw / "connected-devices.txt").write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")
    return unique


def collect_capabilities(raw: Path, report: dict[str, Any]) -> None:
    """Capture help text only; never run every discovered command."""
    root = raw / "capabilities"
    root.mkdir(mode=0o700, exist_ok=True)
    catalog: dict[str, Any] = {"libimobiledevice": {}, "pymobiledevice3": {},
                               "policy": "Help-only discovery; discovered commands are not automatically executed."}
    for tool in LIB_TOOLS:
        path = shutil.which(tool)
        if not path:
            catalog["libimobiledevice"][tool] = {"available": False}
            continue
        res = run_command([path, "--help"], timeout=12)
        meta = write_command_result(root, f"{tool}-help", res)
        catalog["libimobiledevice"][tool] = {"available": True, **meta}
    pmd = shutil.which("pymobiledevice3")
    if pmd:
        res = run_command([pmd, "--help"], timeout=20)
        meta = write_command_result(root, "pymobiledevice3-root-help", res)
        help_text = decode(res["stdout"]) + "\n" + decode(res["stderr"])
        groups: list[str] = []
        in_commands = False
        for line in help_text.splitlines():
            if line.strip().lower() == "commands:":
                in_commands = True
                continue
            if in_commands:
                match = re.match(r"^\s{2,}([a-zA-Z][a-zA-Z0-9_-]*)\s{2,}.*$", line)
                if match:
                    candidate = match.group(1)
                    if candidate not in groups and candidate not in {"options", "commands"}:
                        groups.append(candidate)
                elif line.strip() and not line.startswith(" "):
                    in_commands = False
        catalog["pymobiledevice3"]["root"] = meta
        catalog["pymobiledevice3"]["command_groups"] = groups
        for group in groups[:120]:
            group_res = run_command([pmd, group, "--help"], timeout=15)
            catalog["pymobiledevice3"][group] = write_command_result(root, f"pymobiledevice3-{safe_name(group)}-help", group_res)
    else:
        catalog["pymobiledevice3"]["available"] = False
    report["capability_catalog"] = catalog
    (root / "catalog.json").write_text(__import__("json").dumps(catalog, indent=2), encoding="utf-8")


def collect_device(args: Any, run_dir: Path, raw: Path, report: dict[str, Any], udid: str) -> None:
    collection = report["collection"]
    if shutil.which("idevicepair"):
        save_result(raw, collection, "pairing-validation", [shutil.which("idevicepair") or "idevicepair", "-u", udid, "validate"], 20)

    device: dict[str, Any] = {}
    ideviceinfo = shutil.which("ideviceinfo")
    if ideviceinfo:
        result = save_result(raw, collection, "device-info-xml", [ideviceinfo, "-u", udid, "-x"], 45)
        parsed = parse_plist(result["stdout"])
        if isinstance(parsed, dict):
            device = parsed
            with (raw / "device-info.plist").open("wb") as stream:
                plistlib.dump(parsed, stream, fmt=plistlib.FMT_XML, sort_keys=True)
        else:
            fallback = save_result(raw, collection, "device-info-key-values", [ideviceinfo, "-u", udid], 45)
            device = parse_key_values(decode(fallback["stdout"]))
    else:
        report["findings"].append({"severity":"INFO", "title":"ideviceinfo unavailable",
            "detail":"Native device metadata was not collected. Install libimobiledevice for wider metadata coverage.", "evidence":[]})
    report["device"] = device

    diagnostics = shutil.which("idevicediagnostics")
    report.setdefault("diagnostic_candidates", [])
    if diagnostics:
        for kind in ("All", "GasGauge", "WiFi", "NAND"):
            result = save_result(raw, collection, f"diagnostics-{kind}", [diagnostics, "-u", udid, "diagnostics", kind], 60)
            report["diagnostic_candidates"].extend(diagnostic_candidates(result["stdout"], f"diagnostics-{kind}"))
        for plane in ("IOPower", "IODeviceTree", "IOService"):
            save_result(raw, collection, f"ioreg-{plane}", [diagnostics, "-u", udid, "ioreg", plane], 60)
    else:
        report["findings"].append({"severity":"INFO", "title":"idevicediagnostics unavailable",
            "detail":"Hardware-related diagnostic requests were skipped; this does not imply a device fault.", "evidence":[]})

    if args.crash_reports:
        tool = shutil.which("idevicecrashreport")
        if tool:
            folder = raw / "crash-reports"
            folder.mkdir(mode=0o700)
            save_result(raw, collection, "crash-report-copy", [tool, "-u", udid, "-k", str(folder)], 180)
        else:
            report["findings"].append({"severity":"INFO", "title":"Crash report tool unavailable", "detail":"Install libimobiledevice to attempt crash report collection.", "evidence":[]})
    if args.app_list:
        tool = shutil.which("ideviceinstaller")
        if tool:
            save_result(raw, collection, "installed-apps-libimobiledevice", [tool, "-u", udid, "-l"], 90)
    if args.provisioning:
        tool = shutil.which("ideviceprovision")
        if tool:
            save_result(raw, collection, "provisioning-profiles", [tool, "-u", udid, "list"], 60)
    if args.syslog_seconds:
        tool = shutil.which("idevicesyslog")
        if tool:
            from .util import capture_stream, write_command_result
            result = capture_stream([tool, "-u", udid], args.syslog_seconds, raw / "live-syslog.txt")
            collection.append(write_command_result(raw, "live-syslog", result))
        else:
            report["findings"].append({"severity":"INFO", "title":"idevicesyslog unavailable", "detail":"Requested live log capture could not run.", "evidence":[]})

    if args.backup == "libimobiledevice":
        tool = shutil.which("idevicebackup2")
        if tool:
            folder = raw / "libimobiledevice-full-backup"
            folder.mkdir(mode=0o700)
            save_result(raw, collection, "full-backup-libimobiledevice", [tool, "-u", udid, "backup", str(folder)], 3600)
        else:
            report["findings"].append({"severity":"WARNING", "title":"Backup tool unavailable", "detail":"idevicebackup2 is not installed; requested backup skipped.", "evidence":[]})

    pmd = shutil.which("pymobiledevice3")
    if not pmd:
        report["findings"].append({"severity":"INFO", "title":"pymobiledevice3 unavailable",
            "detail":"Install the optional pymobiledevice3 dependency for additional iOS service coverage.", "evidence":[]})
        return
    prefix = [pmd, "--udid", udid]
    save_result(raw, collection, "pymobiledevice3-version", [pmd, "version"], 20)
    if args.pmd_app_list:
        save_result(raw, collection, "installed-apps-pymobiledevice3", [*prefix, "apps", "list"], 90)
    if args.pmd_processes:
        save_result(raw, collection, "processes-pymobiledevice3", [*prefix, "processes", "ps"], 60)
    if args.pmd_crash_reports:
        folder = raw / "pymobiledevice3-crash-reports"
        folder.mkdir(mode=0o700)
        save_result(raw, collection, "crash-pull-pymobiledevice3", [*prefix, "crash", "pull", str(folder)], 180)
    if args.pmd_syslog_seconds:
        from .util import capture_stream, write_command_result
        result = capture_stream([*prefix, "syslog", "live"], args.pmd_syslog_seconds, raw / "pymobiledevice3-live-syslog.txt")
        collection.append(write_command_result(raw, "pymobiledevice3-live-syslog", result))
    if args.backup == "pymobiledevice3":
        folder = raw / "pymobiledevice3-full-backup"
        folder.mkdir(mode=0o700)
        save_result(raw, collection, "full-backup-pymobiledevice3", [*prefix, "backup2", "backup", "--full", str(folder)], 3600)
