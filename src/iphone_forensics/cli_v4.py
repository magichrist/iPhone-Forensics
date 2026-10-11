"""v4 CLI: `iphone-surgery`, organized into subcommands.

Zero new runtime dependencies. Each command has a real, documented purpose and
works without a connected device where that is meaningful.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import (
    analyze_crash_artifacts,
    automated_assessment,
    compare_reports,
    derive_findings,
)
from .buyer import template as buyer_template
from .collectors import LIB_TOOLS, collect_capabilities, collect_device, discover_devices
from .evidence import (
    EVIDENCE_DIR_NAME,
    SCHEMA_VERSION,
    build_manifest,
    run_dir_paths,
    verify_manifest,
    write_readme_txt,
)
from .hardware import assess_hardware, manual_subsystem_checks
from .integrity import assess_integrity
from .reporting import finalize
from .util import redact as util_redact
from .util import run_command, write_json

PROGRAM = "iphone-surgery"
CONFIG_FILENAME = "iphone-surgery.json"
# Empty string = the current working directory: Path("") resolves to the CWD,
# so the default needs no special case in any consumer.
DEFAULT_OUTPUT_ROOT = ""
# Written into config templates by `config --out` and resolved to the real CWD
# when a config is applied, so a template copied between machines still means
# "wherever you run the tool". Documented in `config --help`.
CWD_OUTPUT_MARKER = "<current-working-directory>"

# Stable exit codes so automation can branch on them reliably.
EXIT_OK = 0
EXIT_FINDINGS = 1       # completed, but review-worthy findings exist
EXIT_CONFIG = 2         # user/tool configuration problem
EXIT_NO_DEVICE = 3
EXIT_AMBIGUOUS_DEVICE = 4
EXIT_PARTIAL = 5        # ran but with collection gaps
EXIT_TOOL_FAILURE = 6

# Decision table (docs/v4/phase-1-cli-reliability.md, task 4). Audited per `return`:
#   0  run finished and nothing review-worthy; also every completed run under
#      --no-fail-on-findings
#   1  run finished with BLOCKER / WARNING / REVIEW findings (`_exit_for`)
#   2  a user-supplied input was wrong or unreadable: --backup-dir that is not a
#      directory, --buyer-json, --compare-json misuse, missing/unreadable report
#      paths, unknown QA check, invalid or existing-without---force output file,
#      invalid config file, a log-capture request above syslog_max_seconds
#   3  discovery completed and no device was attached
#   4  discovery completed and more than one device is attached
#   5  collection ran with gaps (reserved: emitted by report contents, not yet by
#      a dedicated code path)
#   6  a discovered tool failed (reserved; not emitted yet)
# Runs that never reach collection (no toolkit, no device, ambiguous device) never
# return 0 even under --no-fail-on-findings: nothing was inspected, so success
# would be a lie to automation.

SENSITIVE_KEYS = {"SerialNumber", "InternationalMobileEquipmentIdentity", "UniqueDeviceID",
                  "UDID", "WiFiAddress", "BluetoothAddress", "IMEI", "IntegratedCircuitCardIdentity"}
REDACTED = "••••"


def redact(value: Any) -> str:
    """Mask an identifier. Delegates to the single util helper (docs/v5/07)."""
    return util_redact(value)


def _tool_path(name: str) -> str | None:
    if name == "pymobiledevice3":
        return shutil.which("pymobiledevice3")
    if name == "mvt-ios":
        return shutil.which("mvt-ios")
    return shutil.which(name) if name in LIB_TOOLS else shutil.which(name)


# ------------------------------------------------------------ configuration

class ConfigError(Exception):
    """Missing or invalid configuration file — surfaced as EXIT_CONFIG."""


def default_config() -> dict[str, Any]:
    """Documented configuration defaults; identical to what `config --out` writes."""
    return {
        "schema_version": "4.0.0",
        "output_root": CWD_OUTPUT_MARKER,
        "safe_name_max_length": 100,
        "subprocess_timeout_seconds_default": 45,
        "syslog_max_seconds": 120,
        "offline_evidence_max_file_mb": 64,
        "offline_evidence_max_files": 2000,
        "redact_identifiers_in_console": True,
    }


def validate_config(data: Any, defaults: dict[str, Any] | None = None) -> None:
    """Validate a parsed config object; shared by `config --check` and auto-load.

    Raises ValueError with a human-readable reason on the first problem.
    """
    if not isinstance(data, dict):
        raise ValueError("must be a JSON object")
    defaults = defaults if defaults is not None else default_config()
    int_keys = {key for key, value in defaults.items() if isinstance(value, int)}
    for key, value in data.items():
        if key in int_keys and not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
    if "output_root" in data and not isinstance(data["output_root"], str):
        raise ValueError("output_root must be a string path")
    redact_key = "redact_identifiers_in_console"
    if redact_key in data and not isinstance(data[redact_key], bool):
        raise ValueError(f"{redact_key} must be true or false")


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        validate_config(data)
    except ValueError as exc:
        raise ConfigError(f"invalid config {path}: {exc}") from exc
    return data


def load_config(explicit_path: str | None = None) -> tuple[dict[str, Any], list[Path]]:
    """Build the effective config: defaults <- ./iphone-surgery.json <- --config PATH.

    Missing files are tolerated for the CWD file (auto-discovery is optional by
    design); a missing explicit --config path is an error. Later sources override
    earlier ones, so the documented precedence holds:

        CLI flag > --config PATH > ./iphone-surgery.json > built-in defaults

    Returns (effective config, sources actually loaded) — application only
    happens for sources actually loaded, so behavior without a config file is
    byte-for-byte what it was before auto-load existed.
    """
    config = default_config()
    sources: list[Path] = []
    cwd_config = Path.cwd() / CONFIG_FILENAME
    if cwd_config.is_file():
        sources.append(cwd_config)
    if explicit_path:
        explicit = Path(explicit_path).expanduser()
        if not explicit.is_file():
            raise ConfigError(f"config not found: {explicit}")
        if not sources or explicit.resolve() != sources[0].resolve():
            sources.append(explicit)
    for source in sources:
        config.update(_read_config_file(source))
    return config, sources


def _apply_config(args: argparse.Namespace, config: dict[str, Any],
                  sources: list[Path]) -> None:
    """Apply the effective config to the parsed args; explicit CLI flags still win."""
    args.config_data = config
    # --output parses with argparse.SUPPRESS, so the attribute exists only when
    # the flag was actually passed: the config fills the gap, a CLI flag wins.
    if not hasattr(args, "output"):
        configured = str(Path(config["output_root"]).expanduser())
        # The template marker (and an empty value, which Path renders as ".")
        # mean "the directory this run starts in"; resolve it here so every
        # downstream consumer sees a real path.
        args.output = str(Path.cwd()) if configured in (".", CWD_OUTPUT_MARKER) else configured
    # Console identifiers are always redacted regardless of config. The config
    # flag additionally enables the report-redacted.{html,json} exports, exactly
    # as if --redact had been passed (only when a config file was loaded, so
    # the no-config default behavior is unchanged).
    if sources and config.get("redact_identifiers_in_console"):
        args.redact = True
    if sources:
        # subprocess_timeout_seconds_default: util.run_command() and
        # collectors.save_result() honour an explicit per-call timeout first
        # (crash pulls, backups); the configured value replaces their *defaults*
        # for any call that relies on them.
        from . import collectors, util
        timeout = int(config["subprocess_timeout_seconds_default"])
        if len(util.run_command.__defaults__ or ()) == 1:
            util.run_command.__defaults__ = (timeout,)
        if len(collectors.save_result.__defaults__ or ()) == 1:
            collectors.save_result.__defaults__ = (timeout,)


# ---------------------------------------------------------------- welcome

def _device_count_summary(tools_available: bool) -> str:
    """Best-effort, redacted device count for the welcome screen. Never raises."""
    if not tools_available:
        return "unknown — no discovery toolkit installed"
    try:
        # Probe into a temp dir: the welcome screen must leave no files behind.
        with tempfile.TemporaryDirectory(prefix="iphone-surgery-") as tmp:
            devices = discover_devices(Path(tmp), [])
    except Exception as exc:  # noqa: BLE001 — welcome must never crash (same policy as doctor)
        return f"unknown — discovery failed ({str(exc)[:80]})"
    if not devices:
        return "none detected"
    return f"{len(devices)} detected (UDIDs redacted here; report files keep full values)"


def cmd_welcome(args: argparse.Namespace) -> int:
    """No-subcommand welcome: version, toolchain, devices, prerequisites, next step.

    Non-interactive by default and automation-safe: no prompt is shown unless
    --interactive is passed AND stdin is a TTY. Always exits 0.
    """
    print(f"iphone-surgery v{__version__} — hardware-first iPhone diagnostics, "
          "integrity assessment, buyer & repair workflows")
    print()
    lbd_count = sum(1 for name in LIB_TOOLS if shutil.which(name))
    pmd = shutil.which("pymobiledevice3")
    mvt = shutil.which("mvt-ios")
    pmd_state = "installed" if pmd else "not installed (optional)"
    mvt_state = "installed" if mvt else "not installed (optional)"
    print(f"Toolchain:     libimobiledevice {lbd_count}/{len(LIB_TOOLS)} tools found")
    print(f"                 pymobiledevice3: {pmd_state}; mvt-ios: {mvt_state}")
    mode = ("full device support" if lbd_count else
            "pymobiledevice3 only" if pmd else "offline analysis only")
    print(f"Operational mode: {mode}")
    print(f"Devices:          {_device_count_summary(bool(lbd_count or pmd))}")
    print("Prerequisites:    iPhone unlocked · Trust This Computer approved · data-capable cable.")
    print()
    print("Next actions:")
    print("  iphone-surgery doctor                       toolchain, pairing, reachability check")
    print("  iphone-surgery inspect --backup-dir <dir>   offline analysis of a backup (no device)")
    print("  iphone-surgery capabilities                 what software can and cannot verify")
    print("  iphone-surgery --help                       all 16 subcommands")
    # Only prompt when explicitly requested on a real terminal; scripts (stdin
    # closed or piped) always fall through to EXIT_OK without reading stdin.
    if getattr(args, "interactive", False) and sys.stdin.isatty():
        try:
            answer = input("\nRun `iphone-surgery doctor` now? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer in {"y", "yes", "d", "doctor"}:
            return cmd_doctor(args)
    return EXIT_OK


# ---------------------------------------------------------------- commands

def _probe_version(path: str) -> str:
    """Best-effort version string from a tool's --help first line. Never raises."""
    try:
        res = run_command([path, "--help"], timeout=10)
        text = (res.get("stdout", b"") + b"\n" + res.get("stderr", b"")).decode("utf-8", "replace")
        first_line = text.strip().splitlines()[0].strip() if text.strip() else ""
        return first_line or "unknown version"
    except Exception:  # noqa: BLE001 - a doctor probe must never raise, whatever the tool does
        return "unknown version"


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check toolchain, pairing, and device reachability; report feature availability."""
    print(f"iphone-surgery v{__version__} — doctor\n")

    python_ok = sys.version_info >= (3, 11)
    print(f"Python {sys.version.split()[0]} (needs >= 3.11): {'OK' if python_ok else 'TOO OLD'}")

    tools = {name: shutil.which(name) for name in LIB_TOOLS}
    lbd = any(tools.values())
    pmd = shutil.which("pymobiledevice3")
    mvt = shutil.which("mvt-ios")

    print(f"libimobiledevice tools: {'available' if lbd else 'NOT FOUND (brew install libimobiledevice)'}")
    for name, path in tools.items():
        print(f"  {name:<22} {'✓ ' + path if path else '—'}")
    print(f"pymobiledevice3:        {'✓ ' + pmd if pmd else '— not installed (optional)'}")
    print(f"mvt-ios:                {'✓ ' + mvt if mvt else '— not installed (optional, for backup triage)'}")

    # Output writability + free space on the resolved output root (default CWD).
    output_root = Path(getattr(args, "output", None) or Path.cwd()).expanduser().resolve()
    try:
        free_bytes = shutil.disk_usage(output_root).free
        free_mb = free_bytes / (1024 * 1024)
        if os.access(output_root, os.W_OK):
            print(f"Output writable:         ✓ {output_root} ({free_mb:.0f} MB free)")
        else:
            print(f"Output writable:         ⚠ NOT WRITABLE: {output_root} ({free_mb:.0f} MB free)")
    except OSError as exc:
        print(f"Output writable:         ⚠ could not check {output_root}: {exc}")

    # Tool versions via --help probe (never execute device commands).
    ideviceinfo = shutil.which("ideviceinfo")
    print(f"ideviceinfo version:     {_probe_version(ideviceinfo) if ideviceinfo else 'unknown version'}")
    print(f"pymobiledevice3 version: {_probe_version(pmd) if pmd else 'unknown version'}")

    devices: list[str] = []
    if lbd or pmd:
        try:
            collection_probe: list[dict[str, Any]] = []
            raw_probe = (Path(getattr(args, "output", None)
                          or Path.cwd()).expanduser()
                         / "doctor-probe")
            raw_probe.mkdir(parents=True, exist_ok=True, mode=0o700)
            devices = discover_devices(raw_probe, collection_probe)
        except Exception as exc:  # doctor must never crash on odd tool behavior
            print(f"device discovery probe failed: {exc}")
    print(f"\nDevice discovery: {'none detected' if not devices else f'{len(devices)} device(s)'}")
    for i, udid in enumerate(devices, 1):
        print(f"  {i}. {redact(udid)}   (full value kept private in report files)")

    mode = "full" if lbd else ("partial (pymobiledevice3 only)" if pmd else "offline analysis only")
    print(f"\nOperational mode: {mode}")
    if not lbd:
        print("Offline workflows still work: `iphone-surgery inspect --backup-dir <dir>`,")
        print("`iphone-surgery report <dir>`, `iphone-surgery compare <prev> <curr>`,")
        print("`iphone-surgery evidence verify <dir-or-manifest>`.")
    return EXIT_OK


def cmd_devices(args: argparse.Namespace) -> int:
    collection: list[dict[str, Any]] = []
    out_root = Path(args.output).expanduser() / "devices-probe"
    out_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    devices = discover_devices(out_root, collection)
    if not devices:
        print("No connected device detected.")
        print("Check: cable carries data (not charge-only), phone unlocked, Trust This Computer approved,")
        print("`idevice_id -l` and `pymobiledevice3 usbmux list` for native confirmation.")
        return EXIT_NO_DEVICE
    for i, udid in enumerate(devices, 1):
        print(f"{i}. {redact(udid)}")
    if len(devices) == 1:
        print("\nRerun any command with no --device flag to use this phone.")
    else:
        print("\nMultiple devices detected. Use --device <value> with the full UDID for the intended phone;")
        print("it is printed unredacted inside the run's report.json.")
    return EXIT_OK


def _collect_full(args: argparse.Namespace, run_dir: Path, report: dict[str, Any]) -> None:
    class _BackingArgs:
        """Adapt v4 flags to the v3 collect_device interface without touching v3 code."""
        crash_reports = args.crash_reports
        app_list = args.app_list
        provisioning = args.provisioning
        syslog_seconds = args.syslog_seconds
        pmd_syslog_seconds = args.pmd_syslog_seconds
        pmd_crash_reports = args.pmd_crash_reports
        pmd_processes = args.pmd_processes
        pmd_app_list = args.pmd_app_list
        backup = args.backup

    raw = run_dir / EVIDENCE_DIR_NAME
    udid = report["target_udid"]
    if not args.no_capability_catalog:
        collect_capabilities(raw, report)
    collect_device(_BackingArgs, run_dir, raw, report, udid)


def cmd_inspect(args: argparse.Namespace) -> int:
    config = getattr(args, "config_data", None) or {}
    syslog_max = int(config.get("syslog_max_seconds", 120))
    for dest, flag in (("syslog_seconds", "--syslog-seconds"),
                       ("pmd_syslog_seconds", "--pmd-syslog-seconds")):
        requested = int(getattr(args, dest, 0) or 0)
        if requested > syslog_max:
            print(f"error: {flag} {requested}s exceeds syslog_max_seconds ({syslog_max}s); "
                  "raise the limit in the config file", file=sys.stderr)
            return EXIT_CONFIG

    buyer_data = buyer_template()
    if args.buyer_json:
        try:
            loaded = json.loads(Path(args.buyer_json).expanduser().read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("top-level JSON must be an object")
            defaults = buyer_template()
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
            return EXIT_CONFIG

    if args.backup_dir:
        # Config gate: an unusable source path is the same class of mistake as an
        # unreadable --buyer-json, so it is rejected before a run directory is
        # created rather than reported as a finding after a wasted run.
        source = Path(args.backup_dir).expanduser()
        if not source.is_dir():
            print(f"error: --backup-dir is not a directory: {source}", file=sys.stderr)
            return EXIT_CONFIG

    console = _Console(args)
    run_dir = _new_run_dir(args)
    # run_dir_paths() already created the evidence/ directory (mode 0700).
    raw = run_dir / EVIDENCE_DIR_NAME
    report = _new_report(args)

    if args.backup_dir:
        # Offline: stages 1-2 live in _inspect_backup, stages 3-5 in _finish_run.
        _inspect_backup(args, run_dir, report, buyer_data, console)
        _finish_run(run_dir, report, buyer_data, args, console)
        _print_summary(run_dir, report, console)
        return _exit_for(report, args)

    # ---- stage 1: discovery (toolchain check + device selection)
    console.stage(1)
    tools_confirmed = any(_tool_path(n) for n in list(LIB_TOOLS) + ["pymobiledevice3"])
    if not tools_confirmed:
        report["findings"].append({
            "severity": "BLOCKER", "title": "No supported toolkit detected",
            "detail": ("Install libimobiledevice (`brew install libimobiledevice`) and/or pymobiledevice3, or run "
                       "offline analysis with `iphone-surgery inspect --backup-dir <dir>`."),
            "evidence": []})
        # first_stage=2: nothing was collected, so this is not a completed run and
        # --no-fail-on-findings must not report it as a success.
        _finish_run(run_dir, report, buyer_data, args, console, first_stage=2)
        print("No supported toolkit detected. Run `iphone-surgery doctor` for options.")
        _print_summary(run_dir, report, console)
        return _exit_for(report, args, completed=False)

    devices = discover_devices(raw, report["collection"])
    report["connected_devices"] = devices
    if args.device:
        udid = args.device
        if devices and udid not in devices:
            report["findings"].append({"severity": "WARNING",
                "title": "Requested device not in discovery output",
                "detail": "May be disconnected, unpaired, or on a transport this probe does not enumerate.",
                "evidence": [f"{EVIDENCE_DIR_NAME}/connected-devices.txt"]})
    elif len(devices) == 1:
        udid = devices[0]
    elif not devices:
        report["findings"].append({"severity": "BLOCKER", "title": "No connected device detected",
            "detail": "Unlock the iPhone, use a data-capable cable, approve Trust This Computer, retry.",
            "evidence": [f"{EVIDENCE_DIR_NAME}/connected-devices.txt"]})
        _finish_run(run_dir, report, buyer_data, args, console, first_stage=2)
        print("No device detected. Run `iphone-surgery doctor` to debug.")
        _print_summary(run_dir, report, console)
        return EXIT_NO_DEVICE
    else:
        report["findings"].append({"severity": "BLOCKER", "title": "Multiple devices detected",
            "detail": "Rerun with --device <udid> for the intended phone.",
            "evidence": [f"{EVIDENCE_DIR_NAME}/connected-devices.txt"]})
        _finish_run(run_dir, report, buyer_data, args, console, first_stage=2)
        print(f"{len(devices)} devices detected — rerun with --device <udid>. "
              "Full values are kept in this run's report.json.")
        _print_summary(run_dir, report, console)
        return EXIT_AMBIGUOUS_DEVICE
    console.stage_done(1)

    # ---- stage 2: collection
    console.stage(2)
    report["target_udid"] = udid
    _collect_full(args, run_dir, report)
    console.stage_done(2)
    console.collectors(report["collection"])

    # ---- stages 3-5: triage, assessment, report
    _finish_run(run_dir, report, buyer_data, args, console)
    _print_summary(run_dir, report, console)
    return _exit_for(report, args)


def _inspect_backup(args: argparse.Namespace, run_dir: Path, report: dict[str, Any],
                    buyer_data: dict[str, Any], console: _Console | None = None) -> None:
    """Offline stages 1-2: analyze an existing authorized backup or panic-file dump directory.

    Triage (stage 3) deliberately does not happen here: it belongs to
    `_finish_run` so the offline and device paths each announce stage 3 once.
    """
    console = console or _SILENT_CONSOLE
    source = Path(args.backup_dir).expanduser().resolve()
    console.stage(1)
    if not source.exists() or not source.is_dir():
        report["findings"].append({"severity": "BLOCKER", "title": "Backup path unavailable",
            "detail": f"{source} does not exist or is not a directory.", "evidence": []})
        return
    report["offline_analysis"] = {"source": str(source), "mode": "existing-backup"}
    console.stage_done(1)

    # Copy suppled diagnostic/crash artifacts into run evidence so the manifest
    # and SW-256 chain-of-custody cover them. Keep under a bounded per-file cap
    # to avoid runaway copies from huge backup trees (protective, not forensics-lite).
    import shutil as _shutil
    console.stage(2)
    copied = 0
    skipped = 0
    started = time.monotonic()
    cfg = getattr(args, "config_data", None) or {}
    MAX_FILE_BYTES = int(cfg.get("offline_evidence_max_file_mb", 64)) * 1024 * 1024
    MAX_FILES = int(cfg.get("offline_evidence_max_files", 2000))
    for path in sorted(source.rglob("*")):
        if copied >= MAX_FILES:
            report["findings"].append({"severity": "WARNING",
                "title": "Offline artifact copy truncated",
                "detail": f"More than {MAX_FILES} candidate artifacts in source; copy stopped early.",
                "evidence": []})
            break
        if not path.is_file():
            continue
        name_lower = path.name.lower()
        is_candidate = (path.suffix.lower() in {".ips", ".crash", ".panic", ".diag", ".hang", ".synced"}
                        or any(term in name_lower for term in ("panic", "resetcounter", "watchdog", "jetsam")))
        if not is_candidate:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                report["findings"].append({"severity": "INFO",
                    "title": f"Skipped oversized artifact: {path.name}",
                    "detail": "Over the 64 MB per-file evidence-copy cap; content remains at the original path.",
                    "evidence": []})
                skipped += 1
                continue
            rel_parent = path.relative_to(source).parent
            dest_dir = run_dir / EVIDENCE_DIR_NAME / "offline-evidence" / rel_parent
            dest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            _shutil.copy2(path, dest_dir / path.name)
            copied += 1
        except OSError as exc:
            report["findings"].append({"severity": "INFO",
                "title": f"Could not copy artifact: {path.name}",
                "detail": str(exc), "evidence": []})
            skipped += 1
    # Record the offline copy as a collection step, so report.json and --verbose
    # list the work that actually happened. Per-file skips stay INFO findings:
    # the step itself ran to completion, so it is not a failed collector.
    report.setdefault("collection", []).append({
        "name": "offline-artifact-copy", "command": [], "returncode": 0,
        "duration_seconds": round(time.monotonic() - started, 3), "timed_out": False,
        "expected_stream_end": False, "stdout_file": "", "stderr_file": "",
        "stdout_bytes": 0, "stderr_bytes": 0, "status": "collected",
        "detail": f"{copied} artifact(s) copied from {source}, {skipped} skipped",
    })

    mvt = shutil.which("mvt-ios")
    if mvt:
        from .cli import _run_mvt_backup  # reuse the v3 implementation
        _run_mvt_backup(str(source), run_dir, run_dir / EVIDENCE_DIR_NAME, report)
    else:
        report["findings"].append({"severity": "INFO", "title": "MVT not installed",
            "detail": "Install mvt-ios separately for malicious-indicator scanning of the backup.",
            "evidence": []})
    console.stage_done(2)
    console.collectors(report.get("collection", []))


def cmd_integrity(args: argparse.Namespace) -> int:
    previous_path = Path(args.previous).expanduser()
    current_path = Path(args.current).expanduser()
    for label, path in (("previous", previous_path), ("current", current_path)):
        if not path.exists():
            print(f"error: {label} report not found: {path}", file=sys.stderr)
            return EXIT_CONFIG
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        current = json.loads(current_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read reports: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    if not isinstance(previous, dict) or not isinstance(current, dict):
        print("error: both reports must be JSON objects", file=sys.stderr)
        return EXIT_CONFIG

    result = assess_integrity(previous, current)
    print(f"Overall integrity status: {result['overall']}\n")
    # Continuity is a separate axis from the overall class: it says whether the
    # two snapshots could even be tied to the same device (established |
    # not_detectable | not_tested). Human output only — `--out` JSON is untouched.
    if result.get("continuity"):
        print(f"Device continuity: {result['continuity']}\n")
    if result["changes"]:
        print(f"{'Field':<30} {'Previous':<25} {'Current':<25} Classification")
        for change in result["changes"]:
            print(f"{change['field']:<30} {str(change['previous'])[:25]:<25} "
                  f"{str(change['current'])[:25]:<25} {change.get('classification', change.get('status', ''))}")
    else:
        print("No comparable changes between the two reports.")
    print(f"\n{result['disclaimer']}")
    if args.out:
        write_json(Path(args.out).expanduser(), result)
        print(f"\nFull assessment written: {args.out}")
    return EXIT_OK if result["overall"] in {"not_tested", "consistent"} else EXIT_FINDINGS


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return EXIT_CONFIG
    result = verify_manifest(target)
    if "error" in result and result.get("matched", 0) == 0 and result.get("changed", 0) == 0 \
            and result.get("missing", 0) == 0:
        print(f"error: {result['error']}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"Verified OK:   {result['matched']}")
    print(f"Changed:       {result['changed']}")
    print(f"Missing:       {result['missing']}")
    if result["added"]:
        print(f"Added since hashing ({len(result['added'])}):")
        for path in result["added"][:20]:
            print(f"  + {path}")
    for problem in result.get("problems", [])[:20]:
        print(f"  ! {problem['path']}: {problem['problem']}")
    print(f"\n{result['note']}")
    return EXIT_OK if result["verified"] else EXIT_FINDINGS


def cmd_report(args: argparse.Namespace) -> int:
    """Re-generate HTML from an existing report.json without touching evidence."""
    source = Path(args.report).expanduser()
    if not source.exists():
        print(f"error: report not found: {source}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    if not isinstance(report, dict):
        print("error: report must be a JSON object", file=sys.stderr)
        return EXIT_CONFIG
    run_dir = source.parent
    build_manifest(run_dir)
    finalize(run_dir, report, redact_identifiers=args.redact)
    print(f"HTML regenerated: {run_dir / 'report.html'}")
    return EXIT_OK


def cmd_tools(args: argparse.Namespace) -> int:
    for name in list(LIB_TOOLS) + ["pymobiledevice3", "mvt-ios"]:
        path = shutil.which(name)
        print(f"{name:<24} {'✓ ' + path if path else 'not installed'}")
    return EXIT_OK


def cmd_checklist(args: argparse.Namespace) -> int:
    target = Path(args.out).expanduser() if args.out else Path.cwd() / "buyer-checklist.json"
    if target.exists() and not args.force:
        print(f"error: {target} exists; use --force to overwrite", file=sys.stderr)
        return EXIT_CONFIG
    target.parent.mkdir(parents=True, exist_ok=True)
    write_json(target, buyer_template())
    print(f"Buyer checklist template written: {target}")
    print("Edit statuses to pass/fail/not_tested/not_applicable, then run:")
    print(f"  iphone-surgery inspect --buyer-json {target}")
    return EXIT_OK


def cmd_case(args: argparse.Namespace) -> int:
    """Create, update, compare, or close a repair case.

    With ``--json`` the machine-readable roll-up (``repair.case_to_json``) is the
    only thing printed to stdout, so ``json.loads(stdout)`` works; the human
    progress lines move to stderr for that run. Without ``--json`` the output is
    byte-for-byte what it was before.
    """
    from . import repair
    json_only = bool(getattr(args, "json", False))

    def say(message: str = "") -> None:
        print(message, file=sys.stderr if json_only else sys.stdout)

    case_path = Path(args.case_file).expanduser()
    case = repair.load_or_create(case_path, case_id=args.case_id or "")

    if args.add_work:
        part_source = args.part_source or ""
        repair.record_work(case, part=args.add_work, part_source=part_source, notes=args.work_notes or "")
        say(f"Recorded work: {args.add_work}")
    if args.symptoms:
        case["customer_reported_symptoms"] = args.symptoms
    if args.baseline:
        case["pre_repair_baseline"] = str(Path(args.baseline).expanduser().resolve())
        say(f"Pre-repair baseline set: {case['pre_repair_baseline']}")
    if args.post:
        case["post_repair_report"] = str(Path(args.post).expanduser().resolve())
        say(f"Post-repair report set: {case['post_repair_report']}")
    if args.notes:
        case["technician_notes"] = args.notes
    if args.qa:
        for qa_expr in ([args.qa] if isinstance(args.qa, str) else args.qa):
            check, status = (qa_expr.split("=", 1) + [""])[:2] if "=" in qa_expr else (qa_expr, "pass")
            if check in case["qa_checks"]:
                case["qa_checks"][check] = status
                say(f"QA: {check} = {status}")
                continue
            matches = [c for c in case["qa_checks"] if check.lower() in c.lower()]
            if len(matches) == 1:
                case["qa_checks"][matches[0]] = status
                say(f"QA: {matches[0]} = {status}")
            else:
                print(f"error: ambiguous or unknown QA check '{check}'; options:", file=sys.stderr)
                for name in case["qa_checks"]:
                    print(f"  - {name}", file=sys.stderr)
                return EXIT_CONFIG
    if args.compare:
        result = repair.compare_pre_post(case)
        say(f"Pre/post comparison status: {result.get('status', 'n/a')}")
        if result.get("classifications"):
            for field_name, classification in result["classifications"].items():
                say(f"  {field_name}: {classification}")
        say(result.get("note", result.get("disclaimer", "")))
    if args.close:
        case["status"] = "closed"
        summary = repair.qa_summary(case)
        say(f"Case closed. QA: {summary['pass']}/{summary['total']} pass, "
            f"{summary['fail']} fail, {summary['not_tested']} untested. "
            f"Ready-for-customer: {summary['ready_for_customer']}")

    repair.save_case(case, case_path)
    say(f"Case saved: {case_path}")
    if json_only:
        payload = repair.case_to_json(case)  # work_performed + qa_summary + comparison_overall
        if isinstance(case.get("comparison"), dict):
            payload["comparison"] = case["comparison"]
        print(json.dumps(payload, indent=2, default=str))
    return EXIT_OK


def cmd_buyer(args: argparse.Namespace) -> int:
    """Evaluate a buyer checklist offline and print the v4 verdict + rule."""
    from .buyer import evaluate_v4, template
    data = template()
    if args.checklist_json:
        try:
            loaded = json.loads(Path(args.checklist_json).expanduser().read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("top-level JSON must be an object")
            # Deep-merge user fields into the full default checklist so omitted
            # entries stay explicitly unknown (same semantics as v3 --buyer-json).
            for section in ("buyer", "observations"):
                if isinstance(loaded.get(section), dict):
                    data[section].update(loaded[section])
            if isinstance(loaded.get("checks"), dict):
                for check_id, entry in loaded["checks"].items():
                    if check_id in data["checks"] and isinstance(entry, dict):
                        data["checks"][check_id].update(entry)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read checklist: {exc}", file=sys.stderr)
            return EXIT_CONFIG
    result = evaluate_v4(data)
    print(f"Buyer verdict: {result['verdict']}")
    print(f"Rule applied:  {result['rule']}")
    if result["critical_failures"]:
        print("Critical checks that FAILED: " + ", ".join(result["critical_failures"]))
    if result["critical_unknown"]:
        print("Critical checks UNVERIFIED: " + ", ".join(result["critical_unknown"]))
    if result["unresolved_checks_that_could_change_verdict"]:
        print("Resolve these to change the verdict: "
              + ", ".join(result["unresolved_checks_that_could_change_verdict"]))
    print(result["certification_disclaimer"])
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    if args.out:
        write_json(Path(args.out).expanduser(), result)
        print(f"Written: {args.out}")
    return EXIT_OK if result["verdict"] in {"GOOD_CANDIDATE", "BUY_ONLY_AFTER_REPAIR"} else EXIT_FINDINGS


def cmd_hardware(args: argparse.Namespace) -> int:
    """Re-run the hardware-health assessment over an existing report.json."""
    source = Path(args.report).expanduser()
    if not source.exists():
        print(f"error: report not found: {source}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    if not isinstance(report, dict):
        print("error: report must be a JSON object", file=sys.stderr)
        return EXIT_CONFIG
    assessment = assess_hardware(report)
    if args.json:
        print(json.dumps(assessment, indent=2, default=str))
    else:
        print("Hardware subsystem statuses:")
        for name, status in assessment["subsystems"].items():
            print(f"  {name:<22} {status}")
        print(f"\n{assessment['disclaimer']}")
    if args.out:
        write_json(Path(args.out).expanduser(), assessment)
        print(f"Written: {args.out}")
    return EXIT_OK


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Decision-tree next steps from findings in an existing report.json."""
    source = Path(args.report).expanduser()
    if not source.exists():
        print(f"error: report not found: {source}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    steps: list[tuple[str, str]] = []
    for finding in report.get("findings", []):
        sev = finding.get("severity", "")
        title = finding.get("title", "")
        if sev == "BLOCKER":
            steps.append(("1. CRITICAL", f"Resolve first: {title}. {finding.get('detail', '')[:200]}"))
    hardware = report.get("hardware_assessment") or {}
    for check in hardware.get("warnings", []):
        steps.append(("2. REVIEW", f"{check.get('subsystem')}: {check.get('question')} — {check.get('next_test') or check.get('explanation', '')[:160]}"))
    buyer = (report.get("buyer_data") or {}).get("checks", {})
    unverified = [cid for cid, entry in buyer.items()
                  if isinstance(entry, dict) and entry.get("status") == "not_tested"]
    if unverified:
        steps.append(("3. MANUAL", "Unverified checklist items remain: " + ", ".join(unverified[:8])
                      + (" …" if len(unverified) > 8 else "")))
    triage = report.get("crash_triage") or {}
    if triage.get("panic_or_watchdog_candidate_count"):
        steps.append(("4. EVIDENCE", f"{triage['panic_or_watchdog_candidate_count']} panic/watchdog artifacts on disk; "
                      "correlate recurrence and consider professional diagnostics."))
    if not steps:
        print("No outstanding recommended actions in this report.")
        return EXIT_OK
    print("Recommended next steps (in priority order):")
    for tag, text in steps[:12]:
        print(f"  {tag}: {text}")
    return EXIT_OK


# Human wording the legacy `capabilities` table used for rows software can never
# answer. Kept as an annotation on those rows so the console keeps the exact
# spec phrasing (locked by `test_not_detectable_exposed_via_capability_matrix`)
# while the Coverage column itself comes from capabilities.get_matrix().
_UNSUPPORTED_PHRASES = (
    ("water resistance", "not reliably detectable"),
    ("component originality", "not independently verifiable"),
)

# Rendered only when capabilities.py cannot be imported, so `capabilities` (and
# anything else touching this table) never crashes on a broken/partial install.
# Same (item, coverage, source, limits) shape as the matrix rows used below.
_LEGACY_CAPABILITY_ROWS: list[tuple[str, str, str, str]] = [
    ("Device identity metadata", "automated", "ideviceinfo (+ pmd3 when installed)",
     "reported values are not proof of authenticity"),
    ("Battery cycle count / capacity fields", "partial", "idevicediagnostics GasGauge (device+tool dependent)",
     "units vary; verify against Settings → Battery Health"),
    ("Total/data storage capacity", "automated", "ideviceinfo plist fields", "normalized decimal GB"),
    ("Display / touch quality", "manual", "guided physical test", "software cannot judge pixels or touch"),
    ("Cameras (all lenses, focus, flash)", "manual", "guided physical test", "software cannot judge image quality"),
    ("Face ID / Touch ID function", "manual", "guided re-enroll & unlock test", "never extracts biometric data"),
    ("Audio (mics, speakers, routing)", "manual", "guided voice-memo/playback test", ""),
    ("Buttons/haptics/proximity/sensors", "manual", "guided physical test", ""),
    ("Wired/wireless charging", "manual + host USB observation", "guided test", "host pairing ≠ charging health"),
    ("Wi-Fi/BT/cellular/GPS/NFC", "manual", "guided tests on-device", ""),
    ("Thermal events", "partial", "panic-artifact keyword triage", "inconclusive by design; recurrence matters"),
    ("Crash/panic history", "partial", "crash-report collection + triage", "triage only, not diagnosis"),
    ("Parts & Service History", "manual", "Settings → General → About", "Apple exposes this only on the device itself"),
    ("Activation Lock / MDM", "manual", "seller-erase + reactivation test", "not conclusively queryable from a paired Mac"),
    ("Carrier lock/blacklist", "manual", "carrier or authoritative IMEI check", "distinct from eligibility"),
    ("Spyware indicators (backup)", "partial", "mvt-ios if installed, user-supplied indicators",
     "no hit ≠ clean; hit ≠ conviction"),
    ("Water resistance / opened-before", "not reliably detectable", "—", "no software method supports a claim"),
    ("Component originality", "not independently verifiable", "—", "no public API exposes pairing state"),
]


def cmd_capabilities(args: argparse.Namespace) -> int:
    """Print what this tool can/partially-cannot establish, per evidence source.

    Rows come from the canonical matrix in `capabilities.py`; the legacy table
    above is only a crash-proof fallback (any import/rendering problem degrades
    to it instead of failing the command).
    """
    rows: list[tuple[str, str, str, str]] | None = None
    try:
        from .capabilities import get_matrix
        rows = [(str(row.get("item", "")), str(row.get("coverage", "")),
                 str(row.get("source", "")), str(row.get("limits", "")))
                for row in get_matrix()]
    except Exception:  # noqa: BLE001 — a broken matrix must not kill the command
        rows = None
    if not rows:
        rows = list(_LEGACY_CAPABILITY_ROWS)

    print(f"{'Capability':<52} {'Coverage':<13} Source / limits")
    print("-" * 118)
    for item, coverage, source, limit in rows:
        line = f"{item:<52} {coverage:<13} {source}"
        notes = [phrase for key, phrase in _UNSUPPORTED_PHRASES
                 if key in item.lower() and phrase not in coverage]
        if limit and limit != "—":
            notes.append(limit)
        if notes:
            line += "  (" + "; ".join(notes) + ")"
        print(line)
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    """Field- and metric-level comparison of two report.json snapshots."""
    previous = Path(args.previous).expanduser()
    current = Path(args.current).expanduser()
    for label, path in (("previous", previous), ("current", current)):
        if not path.exists():
            print(f"error: {label} report not found: {path}", file=sys.stderr)
            return EXIT_CONFIG
    try:
        prev = json.loads(previous.read_text(encoding="utf-8"))
        curr = json.loads(current.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read reports: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    comparison = compare_reports(prev, curr)
    integrity = assess_integrity(prev, curr)
    if not comparison["changes"]:
        print("No comparable fields between the two reports.")
    else:
        print(f"{'Field':<45} {'Previous':<22} {'Current':<22} Status")
        for change in comparison["changes"]:
            print(f"{str(change['field'])[:45]:<45} {str(change['previous'])[:22]:<22} "
                  f"{str(change['current'])[:22]:<22} {change['status']}")
    print(f"\nIntegrity classification: {integrity['overall']}")
    if integrity.get("continuity"):
        print(f"Device continuity: {integrity['continuity']}")
    print(comparison.get("note", ""))
    if args.out:
        write_json(Path(args.out).expanduser(), {"field_comparison": comparison, "integrity": integrity})
        print(f"Written: {args.out}")
    return EXIT_OK


def cmd_config(args: argparse.Namespace) -> int:
    """Write/validate a JSON config file with documented defaults."""
    defaults = default_config()
    if args.check:
        source = Path(args.check).expanduser()
        if not source.exists():
            print(f"error: config not found: {source}", file=sys.stderr)
            return EXIT_CONFIG
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            validate_config(data, defaults)
            print(f"Config OK: {source}")
            return EXIT_OK
        except (OSError, ValueError) as exc:
            print(f"error: invalid config: {exc}", file=sys.stderr)
            return EXIT_CONFIG
    target = Path(args.out).expanduser() if args.out else Path.cwd() / "iphone-surgery.json"
    if target.exists() and not args.force:
        print(f"error: {target} exists; use --force", file=sys.stderr)
        return EXIT_CONFIG
    target.parent.mkdir(parents=True, exist_ok=True)
    write_json(target, defaults)
    print(f"Config template written: {target}")
    return EXIT_OK


def cmd_manual_tests(args: argparse.Namespace) -> int:
    print("Guided manual hardware tests (record results in the buyer checklist):\n")
    for i, check in enumerate(manual_subsystem_checks(), 1):
        print(f"{i}. {check.question}")
        print(f"   {check.test}\n")
    return EXIT_OK


# ------------------------------------------------------------ shared helpers

# The five stages a run moves through, in order. Each one is announced exactly
# once by `inspect`, so progress output can never drift from the work performed.
STAGE_LABELS = ("discovery", "collection", "triage", "assessment", "report")


def _seconds(value: Any) -> str:
    """Format a duration for console output; never raises on odd report values."""
    try:
        return f"{float(value):.2f}s"
    except (TypeError, ValueError):
        return "—"


class _Console:
    """Verbosity-aware console for `inspect`.

    * default — exactly one progress line per stage.
    * ``--quiet`` — no progress lines; only the compact summary and error text.
    * ``--verbose`` — the stage lines plus per-stage seconds, and a
      name/status/seconds line per collector once collection has finished.

    Flags are read with ``getattr`` so partial namespaces (library callers, the
    test suite) behave like a default run. ``--quiet`` beats ``--verbose``: it is
    the stronger promise.
    """

    def __init__(self, args: argparse.Namespace | None = None) -> None:
        self.quiet = bool(getattr(args, "quiet", False))
        self.verbose = bool(getattr(args, "verbose", False)) and not self.quiet
        self._since = time.monotonic()

    def stage(self, index: int) -> None:
        """Announce stage `index` (1-based). This is the only per-stage line."""
        if not self.quiet:
            print(f"[{index}/{len(STAGE_LABELS)}] {STAGE_LABELS[index - 1]}")

    def stage_done(self, index: int) -> None:
        """--verbose only: how long the stage just announced took."""
        if self.verbose:
            print(f"      ↳ {STAGE_LABELS[index - 1]} took {time.monotonic() - self._since:.2f}s")
        self._since = time.monotonic()

    def collectors(self, collection: list[dict[str, Any]]) -> None:
        """--verbose only: one line per collected command."""
        if not self.verbose:
            return
        if not collection:
            print("      ↳ collectors: none ran in this mode")
            return
        for entry in collection:
            print(f"      ↳ {str(entry.get('name', '?')):<36} "
                  f"{str(entry.get('status', '?')):<18} {_seconds(entry.get('duration_seconds'))}")


# Used whenever no console is supplied: progress and timing are suppressed.
_SILENT_CONSOLE = _Console(argparse.Namespace(quiet=True))


def _new_run_dir(args: argparse.Namespace) -> Path:
    """Create this run's directory via the single layout helper.

    `evidence.run_dir_paths` is the only place that knows the run-dir naming
    and the `evidence/` split (docs/v5/03-output-layout.md). Naming the directory
    here as well is what previously let `compare`'s auto-discovery miss every
    run it had just produced.
    """
    output_root = Path(args.output).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # UTC, so a run directory is unambiguous no matter where it was produced.
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    paths = run_dir_paths(output_root, stamp)
    return paths["run_dir"]


def _new_report(args: argparse.Namespace) -> dict[str, Any]:
    from .cli import LIMITATIONS  # reuse the canonical v3 limitations list
    return {
        "project": "iPhone Forensics", "schema_version": SCHEMA_VERSION, "version": __version__,
        "started_at": dt.datetime.now(dt.UTC).isoformat(),
        "finished_at": None,
        "host": {"platform": platform.platform(), "macOS": platform.mac_ver()[0],
                 "python": sys.version.split()[0], "architecture": platform.machine()},
        "tools": {name: shutil.which(name) for name in list(LIB_TOOLS) + ["pymobiledevice3", "mvt-ios"]},
        "target_udid": None, "connected_devices": [], "device": {}, "collection": [],
        "findings": [], "limitations": LIMITATIONS, "buyer_data": buyer_template(),
        "hardware_assessment": None, "integrity_assessment": None,
        "scope": {
            "read_only": True,
            # Whether sensitive collection was allowed for THIS run, and why.
            # `granted` means an operator consented or named the collectors;
            # `declined` means consent was asked for and refused (or the session
            # was non-interactive); `not_requested` means no consent gate was
            # presented, i.e. a direct engine/advanced invocation.
            # Items named explicitly on the command line are listed so a run
            # never leaves it ambiguous what was collected with what authority.
            "sensitive_collection": _sensitive_consent_state(args),
            "sensitive_collection_items": list(getattr(args, "sensitive_explicit", []) or []),
            "backup_requested": getattr(args, "backup", "none") != "none",
            "logs_requested": bool(getattr(args, "syslog_seconds", 0) or getattr(args, "pmd_syslog_seconds", 0)),
            "crash_reports_requested": bool(getattr(args, "crash_reports", False) or getattr(args, "pmd_crash_reports", False)),
            "app_inventory_requested": bool(getattr(args, "app_list", False) or getattr(args, "pmd_app_list", False)),
        },
    }


def _sensitive_consent_state(args: argparse.Namespace) -> str:
    """Describe the consent outcome for sensitive collection in this run.

    Three honest states, never a guess:
      granted       - an operator consented, or named the collectors explicitly
      declined      - consent was declined, refused, or unavailable non-interactively
      not_requested - the engine was invoked directly (no consent gate presented)

    Declining is never a failure: it simply means those items stay
    `skipped_by_user` in the collection log.
    """
    if not hasattr(args, "sensitive_consent"):
        return "not_requested"
    return "granted" if args.sensitive_consent else "declined"


def _triage_crash_artifacts(run_dir: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Panic/artifact triage over the run (stage 3), offline runs included.

    When an offline run copied nothing usable (per-file caps, unreadable source),
    the supplied directory is scanned too so the report still carries
    context-only counts instead of implying the source was empty.
    """
    triage = analyze_crash_artifacts(run_dir)
    source = (report.get("offline_analysis") or {}).get("source")
    if triage["panic_or_watchdog_candidate_count"] == 0 and source:
        triage = analyze_crash_artifacts(Path(source))
    # Offline-only: a device run reports pulled crash artifacts through its
    # collection entries and the hardware engine, not through this finding.
    if report.get("offline_analysis") and triage["panic_or_watchdog_candidate_count"]:
        report.setdefault("findings", []).append({
            "severity": "REVIEW",
            "title": "Panic/watchdog candidate artifacts in supplied backup directory",
            "detail": (f"{triage['panic_or_watchdog_candidate_count']} candidates. Triage only, not a hardware "
                       f"diagnosis; correlate recurrence and consult professional diagnostics."),
            "evidence": [i["path"] for i in triage["panic_candidates"][:10]]})
    return triage


def _finish_run(run_dir: Path, report: dict[str, Any], buyer_data: dict[str, Any],
                args: argparse.Namespace, console: _Console | None = None,
                first_stage: int = 3) -> None:
    """Triage → assessment → report: the closing stages of a run.

    `console` is optional — omitted (library and test callers) the stages are
    silent. `first_stage=2` is for runs that stopped before collection (no
    toolkit, no device, ambiguous device): it announces the skipped collection
    stage so the printed stage numbers stay contiguous with the caller's
    stage 1.
    """
    console = console or _SILENT_CONSOLE
    report["buyer_data"] = buyer_data
    if args.compare_json:
        try:
            previous = json.loads(Path(args.compare_json).expanduser().read_text(encoding="utf-8"))
            if isinstance(previous, dict):
                report["comparison"] = compare_reports(previous, report)
                integrity = assess_integrity(previous, report, buyer_data)
                report["integrity_assessment"] = integrity
                report["findings"].extend(integrity["findings"])
            else:
                report["findings"].append({"severity": "WARNING",
                    "title": "Comparison input is not a JSON object", "detail": "", "evidence": []})
        except (OSError, json.JSONDecodeError) as exc:
            report["findings"].append({"severity": "WARNING",
                "title": "Previous report could not be loaded", "detail": str(exc), "evidence": []})

    if first_stage < 3:
        console.stage(2)
        console.stage_done(2)

    console.stage(3)
    if not report.get("crash_triage"):
        report["crash_triage"] = _triage_crash_artifacts(run_dir, report)
    console.stage_done(3)

    console.stage(4)
    report["hardware_assessment"] = assess_hardware(report)
    report["assessment"] = automated_assessment(report, buyer_data)
    report["findings"] = derive_findings(report, buyer_data)
    if report.get("integrity_assessment"):
        report["findings"].extend(
            f for f in report["integrity_assessment"]["findings"]
            if f.get("classification") in {"suspicious", "change_detected", "replacement_indicated"})
    console.stage_done(4)

    console.stage(5)
    finalize(run_dir, report, redact_identifiers=args.redact)
    # README before the manifest: the manifest must describe exactly what the run
    # left on disk, and a README written afterwards would verify as "added since
    # hashing" — the run dir would never reach a clean verification.
    argv = list(getattr(sys, "argv", []) or [])
    write_readme_txt(run_dir, {
        "version": __version__,
        "generated": report.get("started_at"),
        "finished": report.get("finished_at"),
        "device": report.get("device") if isinstance(report.get("device"), dict) else None,
        "command": " ".join(["iphone-surgery", *argv[1:]]) if len(argv) > 1 else None,
    })
    build_manifest(run_dir)
    console.stage_done(5)


def _exit_for(report: dict[str, Any], args: argparse.Namespace, *, completed: bool = True) -> int:
    """Exit code for a finished run.

    `completed=False` marks a run that stopped before any collection happened
    (no supported toolkit). `--no-fail-on-findings` documents itself as "always
    exit 0 on completed runs", so it must not report success for a run where
    nothing was inspected.
    """
    if completed and getattr(args, "fail_on_findings", True) is False:
        return EXIT_OK
    blockers = [f for f in report.get("findings", []) if f.get("severity") == "BLOCKER"]
    if blockers:
        return EXIT_FINDINGS
    warnings = [f for f in report.get("findings", []) if f.get("severity") in {"WARNING", "REVIEW"}]
    return EXIT_FINDINGS if warnings else EXIT_OK


def _findings_breakdown(findings: list[dict[str, Any]]) -> str:
    """`3 (1 BLOCKER, 1 REVIEW, 1 INFO)` — counts by severity, commonest first."""
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    order = sorted(counts, key=lambda severity: (-counts[severity], severity))
    return ", ".join(f"{counts[severity]} {severity}" for severity in order)


def _print_summary(run_dir: Path, report: dict[str, Any], console: _Console | None = None) -> None:
    """Where the run landed and what it found.

    `--quiet` keeps a three-line summary (run, report, findings) so a scripted
    caller still learns the output paths without the progress chatter.
    """
    findings = report.get("findings", [])
    if console is not None and console.quiet:
        print(f"Run:      {run_dir}")
        print(f"Report:   {run_dir / 'report.html'}")
        print(f"Findings: {len(findings)} ({_findings_breakdown(findings)})"
              if findings else "Findings: 0")
        return

    hardware = report.get("hardware_assessment", {})
    print("\nInspection finished.")
    print(f"HTML report:  {run_dir / 'report.html'}")
    print(f"JSON data:    {run_dir / 'report.json'}")
    print(f"Manifest:     {run_dir / 'manifest.json'}")
    print(f"Findings:     {len(findings)} ({_findings_breakdown(findings)})"
          if findings else "Findings:     0")
    subs = hardware.get("subsystems", {})
    if subs:
        print("\nHardware subsystem statuses:")
        for name, status in subs.items():
            print(f"  {name:<20} {status}")
    warnings = len(hardware.get("warnings", []))
    if warnings:
        print(f"Review-worthy hardware warnings: {warnings}")
    print("\nUnknown ≠ pass. Do not treat missing evidence as a healthy result.")


# ------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=("Hardware-first iPhone inspection, integrity assessment, and buyer/repair workflows. "
                     "Safe, read-only by default; works offline against existing backups/evidence."),
        epilog=("Examples:\n"
                "  iphone-surgery doctor\n"
                "  iphone-surgery devices\n"
                "  iphone-surgery inspect --buyer-json ~/checklist.json\n"
                "  iphone-surgery inspect --backup-dir ~/backup-2026-01-01 --redact\n"
                "  iphone-surgery integrity --previous old.json --current new.json\n"
                "  iphone-surgery evidence-verify ./iphone-audit-20260101-120000\n"
                "\n"
                f"Config: ./{CONFIG_FILENAME} is auto-loaded when present; --config PATH overrides it.\n"
                "Precedence: CLI flag > --config PATH > "
                f"./{CONFIG_FILENAME} > built-in defaults.\n"))
    parser.add_argument("--version", action="version", version=f"iphone-surgery {__version__}")
    parser.add_argument("--config", metavar="PATH",
                        help=f"Load configuration JSON from PATH (default: ./{CONFIG_FILENAME} when present)")
    parser.add_argument("--interactive", action="store_true",
                        help="Prompt for the next action on the welcome screen (only when stdin is a TTY)")
    parser.add_argument("--output", default=argparse.SUPPRESS,
                        help="Output root directory (default: the current working directory; "
                             "config: output_root)")
    parser.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="Suppress progress chatter; print only the summary and errors.")
    parser.add_argument("--verbose", action="store_true", default=argparse.SUPPRESS,
                        help="Extra detail: per-collector name/status/seconds and stage timing.")
    sub = parser.add_subparsers(dest="command")

    def _common(p):
        """Flags every subcommand accepts, so they work after the subcommand name too."""
        # SUPPRESS defaults: a subparser default would otherwise clobber a value
        # parsed before the subcommand name (argparse namespace reuse).
        p.add_argument("--output", default=argparse.SUPPRESS,
                       help="Output root directory (default: the current working directory; "
                            "config: output_root)")
        p.add_argument("--config", metavar="PATH", default=argparse.SUPPRESS,
                       help=f"Load configuration JSON from PATH (default: ./{CONFIG_FILENAME} when present)")
        p.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                       help="Suppress progress chatter; print only the summary and errors.")
        p.add_argument("--verbose", action="store_true", default=argparse.SUPPRESS,
                       help="Extra detail: per-collector name/status/seconds and stage timing.")

    p = sub.add_parser("doctor", help="Check toolchain, pairing, and device reachability")
    _common(p)
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("devices", help="List connected devices (redacted in console)")
    _common(p)
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("inspect", help="Full device inspection (device connected or --backup-dir offline)")
    _common(p)
    p.add_argument("--device", help="Target UDID when multiple devices are connected")
    p.add_argument("--buyer-json", help="Load buyer checklist from JSON")
    p.add_argument("--compare-json", help="Compare against previous report.json")
    p.add_argument("--redact", action="store_true", help="Also write report-redacted.{html,json}")
    p.add_argument("--backup-dir", help="Offline: analyze an existing authorized backup/evidence directory")
    p.add_argument("--no-capability-catalog", action="store_true", help="Skip tool help discovery")
    p.add_argument("--crash-reports", action="store_true", help="Copy/pull crash reports (privacy-sensitive)")
    p.add_argument("--app-list", action="store_true", help="Collect app inventory (privacy-sensitive)")
    p.add_argument("--provisioning", action="store_true", help="Collect provisioning profiles")
    p.add_argument("--syslog-seconds", type=int, default=0, help="Bounded live log capture (0-120)")
    p.add_argument("--pmd-syslog-seconds", type=int, default=0, help="Bounded pmd3 live log capture (0-120)")
    p.add_argument("--pmd-crash-reports", action="store_true", help="Pull crash reports via pymobiledevice3")
    p.add_argument("--pmd-processes", action="store_true", help="Process inventory via pymobiledevice3")
    p.add_argument("--pmd-app-list", action="store_true", help="App list via pymobiledevice3")
    p.add_argument("--backup", choices=("none", "libimobiledevice", "pymobiledevice3"), default="none",
                   help="Explicit full backup (potentially sensitive)")
    p.add_argument("--fail-on-findings", dest="fail_on_findings", action="store_true", default=True,
                   help="Exit nonzero when REVIEW/WARNING/BLOCKER findings exist (default)")
    p.add_argument("--no-fail-on-findings", dest="fail_on_findings", action="store_false",
                   help="Always exit 0 on completed runs regardless of findings")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("integrity", help="Classify changes between two report snapshots")
    p.add_argument("--previous", required=True, help="Previous report.json")
    p.add_argument("--current", required=True, help="Current report.json")
    p.add_argument("--out", help="Write full assessment JSON here")
    p.set_defaults(func=cmd_integrity)

    p = sub.add_parser("evidence-verify", help="Verify artifacts against a manifest")
    p.add_argument("target", help="Run directory or manifest.json path")
    p.set_defaults(func=cmd_evidence_verify)

    p = sub.add_parser("report", help="Regenerate HTML from an existing report.json")
    p.add_argument("report", help="Path to report.json")
    p.add_argument("--redact", action="store_true", help="Also emit redacted copies")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("tools", help="Show detected toolchain")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("checklist", help="Write a buyer checklist template")
    p.add_argument("--out", help="Target path (default ./buyer-checklist.json)")
    p.add_argument("--force", action="store_true", help="Overwrite existing file")
    p.set_defaults(func=cmd_checklist)

    p = sub.add_parser("case", help="Repair-case workflow: intake, work log, pre/post compare, QA, close")
    p.add_argument("case_file", help="JSON file storing the case (created if missing)")
    p.add_argument("--case-id", help="Case identifier when creating")
    p.add_argument("--symptoms", help="Customer-reported symptoms text")
    p.add_argument("--baseline", help="Path to pre-repair report.json")
    p.add_argument("--post", help="Path to post-repair report.json")
    p.add_argument("--add-work", metavar="PART", help="Record a part replacement or work item")
    p.add_argument("--part-source", help="Where the part came from (OEM, aftermarket, customer-supplied)")
    p.add_argument("--work-notes", help="Notes for the recorded work item")
    p.add_argument("--qa", metavar="CHECK[=STATUS]", action="append",
                   help="Set a QA check (repeatable, substring match allowed); STATUS: pass/fail/not_tested")
    p.add_argument("--compare", action="store_true", help="Run pre/post-repair comparison")
    p.add_argument("--notes", help="Free-form technician notes")
    p.add_argument("--close", action="store_true", help="Mark case closed and print QA summary")
    p.add_argument("--json", action="store_true",
                   help="Print the machine-readable case roll-up as JSON on stdout "
                        "(human progress lines move to stderr for this run)")
    p.set_defaults(func=cmd_case)

    p = sub.add_parser("manual-tests", help="Print the guided manual hardware tests")
    p.set_defaults(func=cmd_manual_tests)

    p = sub.add_parser("buyer", help="Evaluate a buyer checklist and print the v4 verdict")
    p.add_argument("--checklist-json", help="Path to a filled/edited buyer-checklist JSON")
    p.add_argument("--json", action="store_true", help="Also print the machine-readable result")
    p.add_argument("--out", help="Write the verdict JSON here")
    p.set_defaults(func=cmd_buyer)

    p = sub.add_parser("hardware", help="Re-run hardware-health assessment on an existing report.json")
    p.add_argument("report", help="Path to report.json")
    p.add_argument("--json", action="store_true", help="Print the machine-readable assessment")
    p.add_argument("--out", help="Write assessment JSON here")
    p.set_defaults(func=cmd_hardware)

    p = sub.add_parser("diagnose", help="Decision-tree next steps from an existing report")
    p.add_argument("report", help="Path to report.json")
    p.set_defaults(func=cmd_diagnose)

    p = sub.add_parser("capabilities", help="Print the capability matrix: automated/partial/manual/not-verifiable")
    p.set_defaults(func=cmd_capabilities)

    p = sub.add_parser("compare", help="Field- and integrity-level comparison of two reports")
    p.add_argument("--previous", required=True, help="Previous report.json")
    p.add_argument("--current", required=True, help="Current report.json")
    p.add_argument("--out", help="Write combined comparison JSON here")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("config", help="Write or validate the tool configuration "
                                   "(default output_root: <current-working-directory>)")
    p.add_argument("--check", help="Validate an existing config file")
    p.add_argument("--out", help="Where to write the template (default ./iphone-surgery.json)")
    p.add_argument("--force", action="store_true", help="Overwrite")
    p.set_defaults(func=cmd_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Config auto-load. Precedence once loaded:
    #   CLI flag > --config PATH > ./iphone-surgery.json > built-in defaults.
    # The `config` subcommand manages files directly and never auto-loads, so a
    # broken ./iphone-surgery.json stays repairable via `config --out --force`.
    try:
        if getattr(args, "command", None) == "config":
            config, sources = default_config(), []
        else:
            config, sources = load_config(getattr(args, "config", None))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Fix or remove the file, or point --config at a valid one "
              "(validate with `iphone-surgery config --check <path>`).", file=sys.stderr)
        return EXIT_CONFIG
    _apply_config(args, config, sources)
    if sources and not getattr(args, "quiet", False):
        print("config: using " + ", ".join(str(path) for path in sources), file=sys.stderr)

    if not getattr(args, "command", None):
        # No subcommand: welcome screen (version, toolchain, devices, next step).
        return cmd_welcome(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
