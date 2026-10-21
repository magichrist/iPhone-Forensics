from __future__ import annotations

import datetime as dt
import plistlib
import re
import shutil
from pathlib import Path
from typing import Any

from .readonly import enforce_read_only
from .util import run_command, safe_name, write_command_result

LIB_TOOLS = [
    "idevice_id",
    "ideviceinfo",
    "idevicepair",
    "idevicediagnostics",
    "idevicecrashreport",
    "idevicesyslog",
    "idevicebackup2",
    "ideviceinstaller",
    "ideviceprovision",
    "idevicedate",
    "idevicename",
    "ideviceimagemounter",
]

# Conservative pairing/trust denial vocabulary: only these exact words in tool
# output (combined with an errored exit) reclassify a run as permission_denied.
PAIRING_DENIAL_MARKERS = ("denied", "refused")

# When `idevicediagnostics diagnostics All` is refused, the device simply does
# not expose a catch-all relay domain; the per-domain queries (GasGauge, WiFi,
# NAND) still work. Recording that as a collection_error made a healthy device
# look broken, so it is reclassified as `unsupported` — the question does not
# apply — rather than a failure.
DIAGNOSTICS_UNSUPPORTED_MARKERS = (
    "could not connect to diagnostics_relay",
    "not supported",
    "no such domain",
)


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
    patterns = re.compile(
        r"battery|gas.?gauge|cycle.?count|full.?charge|design.?capacity|maximum.?capacity|temperature|thermal|voltage|health|nand|disk.?capacity",
        re.IGNORECASE,
    )
    candidates: list[dict[str, Any]] = []

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(child, (dict, list)):
                    walk(child, path)
                elif patterns.search(path):
                    candidates.append(
                        {
                            "source": source,
                            "key": path,
                            "value": child,
                            "interpretation": "Raw diagnostic candidate; units and meaning depend on the source field.",
                        }
                    )
        elif isinstance(value, list):
            for index, child in enumerate(value[:500]):
                walk(child, f"{prefix}[{index}]")
        elif isinstance(value, str):
            for line in value.splitlines():
                if ": " in line:
                    key, child = line.split(": ", 1)
                    if patterns.search(key):
                        candidates.append(
                            {
                                "source": source,
                                "key": key.strip(),
                                "value": child.strip(),
                                "interpretation": "Raw diagnostic candidate; units and meaning depend on the source field.",
                            }
                        )

    walk(parsed)
    return candidates[:300]


def save_result(
    raw: Path,
    collection: list[dict[str, Any]],
    name: str,
    command: list[str],
    timeout: int = 45,
    *,
    skip: bool = False,
    denial_markers: tuple[str, ...] | None = None,
    unsupported_markers: tuple[str, ...] | None = None,
    enforce_read_only_check: bool = True,
) -> dict[str, Any]:
    """Run one bounded command, record its outcome, and return the raw result.

    Every command spawned here is a device command and is checked against the
    read-only allowlist before it runs. `collect_device` is the only caller, and all
    of its commands are queries, so a refusal here means a mutating form has been
    introduced — which is exactly the accident worth stopping.

    skip=True records a skipped_by_user entry and never spawns a subprocess.
    denial_markers enables a conservative permission_denied reclassification: the
    marker must appear in the tool output *and* the command must have errored
    (nonzero exit / timeout), so healthy runs that merely mention the word are
    left alone.
    """
    if skip:
        meta = write_command_result(
            raw,
            name,
            {
                "command": command,
                "returncode": None,
                "stdout": b"",
                "stderr": b"skipped by operator request",
                "duration_seconds": 0.0,
                "timed_out": False,
            },
            status_override="skipped_by_user",
            status_detail_override="skipped by operator request",
        )
        collection.append(meta)
        return {
            "command": command,
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "duration_seconds": 0.0,
            "timed_out": False,
        }
    # The read-only check lives in `util.run_command`, not here, so it cannot be
    # skipped by a caller that stubs `run_command` to probe behaviour. `save_result`
    # is the one place that must never be able to spawn a mutating command, so it
    # also checks directly; the duplicate call is cheap and the guarantee is not.
    #
    # `enforce_read_only_check=False` exists for exactly one purpose: tests that use a
    # host binary such as `python -c 'pass'` as a stand-in for a device tool, to
    # exercise exit-code handling. `collect_device` never passes it, and
    # test_readonly_guard.py::test_save_result_cannot_be_told_to_skip_the_guard
    # pins that.
    if enforce_read_only_check:
        enforce_read_only(command)
    result = run_command(
        command,
        timeout=timeout,
        device_command=enforce_read_only_check,
        enforce=enforce_read_only_check,
    )
    meta = write_command_result(raw, name, result)
    if denial_markers and meta["status"] == "collection_error":
        text = (
            (result.get("stdout", b"") + result.get("stderr", b""))
            .decode("utf-8", "replace")
            .lower()
        )
        if any(marker in text for marker in denial_markers):
            meta["status"] = "permission_denied"
            meta["status_detail"] = "tool reported pairing/trust denial"
    # A tool that reports the operation is not applicable did not fail, and the
    # device is not at fault: reclassify rather than count it as an error.
    if unsupported_markers and meta["status"] == "collection_error":
        text = (
            (result.get("stdout", b"") + result.get("stderr", b""))
            .decode("utf-8", "replace")
            .lower()
        )
        if any(marker in text for marker in unsupported_markers):
            meta["status"] = "unsupported"
            meta["status_detail"] = "device or iOS version does not expose this interface"
    collection.append(meta)
    return result


def _pmd_supports_udid_flag(pmd: str) -> bool:
    """True when this pymobiledevice3 build still accepts the global `--udid`.

    The option was removed in pymobiledevice3 11.x, where device selection moved
    to `--tunnel`/`--rsd` and a single attached device is auto-selected. Passing
    `--udid` to a build that dropped it does not degrade gracefully: the CLI
    exits 2 with "No such option: --udid" before doing any work, so every
    pymobiledevice3 collector failed with a `collection_error` that looked like a
    device problem rather than a version mismatch.

    Probed once per run and cached, because it costs a `--help` invocation.
    """
    cached = _PMD_UDID_FLAG_CACHE.get(pmd)
    if cached is not None:
        return cached
    try:
        result = run_command([pmd, "--help"], timeout=20)
        text = (result.get("stdout", b"") + result.get("stderr", b"")).decode("utf-8", "replace")
        supported = "--udid" in text
    except Exception:  # noqa: BLE001 - an unprobeable tool must not abort collection
        supported = False
    _PMD_UDID_FLAG_CACHE[pmd] = supported
    return supported


_PMD_UDID_FLAG_CACHE: dict[str, bool] = {}


def _pmd_prefix(pmd: str, udid: str, report: dict[str, Any]) -> list[str]:
    """Command prefix selecting *udid*, using only options this build supports.

    On builds that dropped `--udid` the device is selected implicitly (a single
    attached device) or via `--tunnel UDID`. Passing the option unconditionally
    made every pymobiledevice3 collector fail, so the gap is recorded as an
    evidence note rather than left to look like a device fault.
    """
    if _pmd_supports_udid_flag(pmd):
        return [pmd, "--udid", udid]
    report.setdefault("findings", []).append(
        {
            "severity": "INFO",
            "title": "pymobiledevice3 does not accept --udid on this version",
            "detail": (
                "This build selects the attached device implicitly. "
                "Connect exactly one iPhone, or use a tunnel, so the tool "
                "cannot be told which device to use."
            ),
            "evidence": [],
        }
    )
    return [pmd]


def discover_devices(raw: Path, collection: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    idevice_id = shutil.which("idevice_id")
    if idevice_id:
        # Guarded separately from save_result: this runs before any run directory
        # exists, so a refusal must fail the probe rather than be recorded as a gap.
        res = run_command([idevice_id, "-l"], timeout=15, device_command=True)
        found.extend(line.strip() for line in decode(res["stdout"]).splitlines() if line.strip())
    pmd = shutil.which("pymobiledevice3")
    if pmd:
        res = run_command([pmd, "usbmux", "list"], timeout=20, device_command=True)
        text = decode(res["stdout"]) + "\n" + decode(res["stderr"])
        found.extend(
            re.findall(
                r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", text
            )
        )
    if not idevice_id and not pmd:
        # No discovery tool at all: record the gap explicitly as tool_missing
        # instead of silently collecting nothing.
        collection.append(
            write_command_result(
                raw,
                "connected-devices-discovery",
                {
                    "command": [],
                    "returncode": None,
                    "stdout": b"",
                    "stderr": b"neither idevice_id nor pymobiledevice3 is installed",
                    "duration_seconds": 0.0,
                    "timed_out": False,
                    "missing_binary": True,
                },
            )
        )
    unique = list(dict.fromkeys(found))
    (raw / "connected-devices.txt").write_text(
        "\n".join(unique) + ("\n" if unique else ""), encoding="utf-8"
    )
    return unique


def collect_capabilities(raw: Path, report: dict[str, Any]) -> None:
    """Capture help text only; never run every discovered command."""
    root = raw / "capabilities"
    root.mkdir(mode=0o700, exist_ok=True)
    catalog: dict[str, Any] = {
        "libimobiledevice": {},
        "pymobiledevice3": {},
        "policy": "Help-only discovery; discovered commands are not automatically executed.",
    }
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
            catalog["pymobiledevice3"][group] = write_command_result(
                root, f"pymobiledevice3-{safe_name(group)}-help", group_res
            )
    else:
        catalog["pymobiledevice3"]["available"] = False
    report["capability_catalog"] = catalog
    (root / "catalog.json").write_text(
        __import__("json").dumps(catalog, indent=2), encoding="utf-8"
    )


def collect_provenance(
    raw: Path,
    collection: list[dict[str, Any]],
    report: dict[str, Any],
    udid: str,
    pmd: str,
    prefix: list[str],
) -> None:
    """Query the read-only signals a buyer cares about most, and skip the rest.

    Every command here is a *query*. None of them mounts, writes, pairs, activates,
    or changes a setting, and each is checked against the read-only allowlist by
    `save_result` before it runs. The three signals worth the effort:

      * **Activation state** — whether the device is still tied to an Apple ID. This
        is the single most consequential thing a buyer needs to know and the one the
        capability matrix previously could only answer with "ask a human". It stays
        a *partial* answer: a clean state on a Mac is evidence, but only the full
        erase-and-reactivate cycle on the device decides, and the report says so.
      * **Developer Disk Image / developer mode** — a mounted DDI or an enabled
        developer mode is a strong hint that this phone was previously used for
        development or jailbreak work. Hints, not verdicts.
      * **Companion devices** — paired Watches and AirPods are accessory history the
        seller may not have thought to mention.
    """
    report.setdefault("provenance", {})
    provenance = report["provenance"]

    activation = save_result(
        raw, collection, "activation-state", [*prefix, "activation", "state"], 30
    )
    text = decode(activation["stdout"])
    state = ""
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            if key.strip().lower() in {"activationstate", "activation state"}:
                state = value.strip()
    provenance["activation_state"] = {
        "value": state or None,
        "raw": text.strip()[:2000],
        "collected": bool(state),
        "interpretation": (
            "Activation state as reported by the device over lockdown. A non-empty "
            "value is evidence about the device's account state; it is not proof of "
            "ownership, and only the seller's erase plus your own reactivation "
            "decides the question."
        ),
        "limits": (
            "Never claim Activation Lock is clear from this alone. A Mac-side query "
            "does not exercise the full Setup Assistant flow that a real reactivation "
            "would, and the device can report differently before and after an erase."
        ),
    }

    for tool, arg, key in (
        ("ideviceimagemounter", "list", "mounted_images"),
        ("ideviceimagemounter", "devmodestatus", "developer_mode"),
    ):
        path = shutil.which(tool)
        if not path:
            continue
        result = save_result(raw, collection, f"imagemounter-{arg}", [path, "-u", udid, arg], 30)
        body = decode(result["stdout"]).strip()
        provenance[key] = {
            "value": body or None,
            "raw": body[:2000],
            "interpretation": (
                "DeveloperDiskImage state reported by the device. A mounted image or "
                "an enabled developer mode hints at prior development or jailbreak "
                "activity."
                if key == "mounted_images"
                else "Developer Mode status reported by the device."
            ),
            "limits": (
                "A hint, not a verdict. Developer use is legitimate and a mounted image "
                "does not establish a jailbreak, a repair, or a parts change."
            ),
        }

    if pmd:
        companions = save_result(
            raw, collection, "companion-devices", [*prefix, "companion", "list"], 30
        )
        body = decode(companions["stdout"]).strip()
        provenance["companion_devices"] = {
            "value": body or None,
            "raw": body[:2000],
            "interpretation": (
                "Accessories the device reports as paired. Useful background, and a "
                "reminder to unpair them before setup if they belong to the seller."
            ),
            "limits": "Not evidence of tampering; pairing state alone proves nothing.",
        }


def collect_device(args: Any, run_dir: Path, raw: Path, report: dict[str, Any], udid: str) -> None:
    collection = report["collection"]
    if shutil.which("idevicepair"):
        save_result(
            raw,
            collection,
            "pairing-validation",
            [shutil.which("idevicepair") or "idevicepair", "-u", udid, "validate"],
            20,
            denial_markers=PAIRING_DENIAL_MARKERS,
        )

    device: dict[str, Any] = {}
    ideviceinfo = shutil.which("ideviceinfo")
    if ideviceinfo:
        result = save_result(
            raw, collection, "device-info-xml", [ideviceinfo, "-u", udid, "-x"], 45
        )
        parsed = parse_plist(result["stdout"])
        if isinstance(parsed, dict):
            device = parsed
            with (raw / "device-info.plist").open("wb") as stream:
                plistlib.dump(parsed, stream, fmt=plistlib.FMT_XML, sort_keys=True)
        else:
            fallback = save_result(
                raw, collection, "device-info-key-values", [ideviceinfo, "-u", udid], 45
            )
            device = parse_key_values(decode(fallback["stdout"]))
    else:
        report["findings"].append(
            {
                "severity": "INFO",
                "title": "ideviceinfo unavailable",
                "detail": "Native device metadata was not collected. Install libimobiledevice for wider metadata coverage.",
                "evidence": [],
            }
        )

    # Storage capacity lives in its own preferences domain. `ideviceinfo -x`
    # dumps only the *default* domain, and on current iOS that domain has no
    # TotalDiskCapacity/TotalDataCapacity — so storage capacity silently read as
    # "not collected" on every modern device while being available one flag away.
    # Merged into `device` so the storage checks find the keys they look for.
    if ideviceinfo:
        disk = save_result(
            raw,
            collection,
            "device-info-disk-usage",
            [ideviceinfo, "-u", udid, "-q", "com.apple.disk_usage"],
            45,
        )
        parsed_disk = parse_plist(disk["stdout"])
        if not isinstance(parsed_disk, dict):
            parsed_disk = parse_key_values(decode(disk["stdout"]))
        if isinstance(parsed_disk, dict) and parsed_disk:
            device = {**device, **parsed_disk}

    # Two declared-but-never-invoked tools. Both print with no flags; the mutating
    # forms (`idevicedate -c`, `idevicename <name>`) are deliberately not used and
    # are refused by the read-only allowlist if anyone reaches for them.
    for tool, key in (("idevicedate", "DeviceTime"), ("idevicename", "DeviceName")):
        path = shutil.which(tool)
        if not path:
            continue
        result = save_result(raw, collection, f"device-{tool}", [path, "-u", udid], 20)
        value = decode(result["stdout"]).strip()
        if value:
            device = {**device, key: value}

    report["device"] = device

    # Device clock vs host clock. A large skew is a weak hint that the clock was set
    # manually — which is a legitimate thing to have done, and never proof of
    # tampering on its own.
    device_time = device.get("DeviceTime")
    if isinstance(device_time, str) and device_time.strip():
        report["clock_skew"] = {
            "device_time": device_time.strip(),
            "host_time": dt.datetime.now(dt.UTC).isoformat(),
            "note": (
                "Compare the device clock with the host clock. A skew of minutes is "
                "normal; a skew of days suggests the clock was set by hand, which is "
                "a hint about setup history and not a finding."
            ),
        }

    diagnostics = shutil.which("idevicediagnostics")
    report.setdefault("diagnostic_candidates", [])
    if diagnostics:
        for kind in ("All", "GasGauge", "WiFi", "NAND"):
            result = save_result(
                raw,
                collection,
                f"diagnostics-{kind}",
                [diagnostics, "-u", udid, "diagnostics", kind],
                60,
                denial_markers=DIAGNOSTICS_UNSUPPORTED_MARKERS,
            )
            report["diagnostic_candidates"].extend(
                diagnostic_candidates(result["stdout"], f"diagnostics-{kind}")
            )
        for plane in ("IOPower", "IODeviceTree", "IOService"):
            save_result(
                raw, collection, f"ioreg-{plane}", [diagnostics, "-u", udid, "ioreg", plane], 60
            )
    else:
        report["findings"].append(
            {
                "severity": "INFO",
                "title": "idevicediagnostics unavailable",
                "detail": "Hardware-related diagnostic requests were skipped; this does not imply a device fault.",
                "evidence": [],
            }
        )

    if args.crash_reports:
        tool = shutil.which("idevicecrashreport")
        if tool:
            folder = raw / "crash-reports"
            folder.mkdir(mode=0o700)
            save_result(
                raw, collection, "crash-report-copy", [tool, "-u", udid, "-k", str(folder)], 180
            )
        else:
            report["findings"].append(
                {
                    "severity": "INFO",
                    "title": "Crash report tool unavailable",
                    "detail": "Install libimobiledevice to attempt crash report collection.",
                    "evidence": [],
                }
            )
    if args.app_list:
        tool = shutil.which("ideviceinstaller")
        if tool:
            save_result(
                raw, collection, "installed-apps-libimobiledevice", [tool, "-u", udid, "-l"], 90
            )
    if args.provisioning:
        tool = shutil.which("ideviceprovision")
        if tool:
            save_result(raw, collection, "provisioning-profiles", [tool, "-u", udid, "list"], 60)
    if args.syslog_seconds:
        tool = shutil.which("idevicesyslog")
        if tool:
            from .util import capture_stream, write_command_result

            result = capture_stream(
                [tool, "-u", udid],
                args.syslog_seconds,
                raw / "live-syslog.txt",
                device_command=True,
            )
            collection.append(write_command_result(raw, "live-syslog", result))
        else:
            report["findings"].append(
                {
                    "severity": "INFO",
                    "title": "idevicesyslog unavailable",
                    "detail": "Requested live log capture could not run.",
                    "evidence": [],
                }
            )

    if args.backup == "libimobiledevice":
        tool = shutil.which("idevicebackup2")
        if tool:
            folder = raw / "libimobiledevice-full-backup"
            folder.mkdir(mode=0o700)
            save_result(
                raw,
                collection,
                "full-backup-libimobiledevice",
                [tool, "-u", udid, "backup", str(folder)],
                3600,
            )
        else:
            report["findings"].append(
                {
                    "severity": "WARNING",
                    "title": "Backup tool unavailable",
                    "detail": "idevicebackup2 is not installed; requested backup skipped.",
                    "evidence": [],
                }
            )

    pmd = shutil.which("pymobiledevice3")
    if not pmd:
        report["findings"].append(
            {
                "severity": "INFO",
                "title": "pymobiledevice3 unavailable",
                "detail": "Install the optional pymobiledevice3 dependency for additional iOS service coverage.",
                "evidence": [],
            }
        )
        return
    prefix = _pmd_prefix(pmd, udid, report)
    save_result(raw, collection, "pymobiledevice3-version", [pmd, "version"], 20)
    collect_provenance(raw, collection, report, udid, pmd, prefix)
    if args.pmd_app_list:
        save_result(
            raw, collection, "installed-apps-pymobiledevice3", [*prefix, "apps", "list"], 90
        )
    if args.pmd_processes:
        save_result(raw, collection, "processes-pymobiledevice3", [*prefix, "processes", "ps"], 60)
    if args.pmd_crash_reports:
        folder = raw / "pymobiledevice3-crash-reports"
        folder.mkdir(mode=0o700)
        save_result(
            raw,
            collection,
            "crash-pull-pymobiledevice3",
            [*prefix, "crash", "pull", str(folder)],
            180,
        )
    if args.pmd_syslog_seconds:
        from .util import capture_stream, write_command_result

        result = capture_stream(
            [*prefix, "syslog", "live"],
            args.pmd_syslog_seconds,
            raw / "pymobiledevice3-live-syslog.txt",
            device_command=True,
        )
        collection.append(write_command_result(raw, "pymobiledevice3-live-syslog", result))
    if args.backup == "pymobiledevice3":
        folder = raw / "pymobiledevice3-full-backup"
        folder.mkdir(mode=0o700)
        save_result(
            raw,
            collection,
            "full-backup-pymobiledevice3",
            [*prefix, "backup2", "backup", "--full", str(folder)],
            3600,
        )
