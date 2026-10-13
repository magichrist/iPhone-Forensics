"""v5 public CLI: `iphone-forensics` — four commands over the v4 engine.

    iphone-forensics devices    list connected phones + the next step
    iphone-forensics inspect    one-command read-only inspection → report.html
    iphone-forensics doctor     toolchain / pairing / reachability diagnostics
    iphone-forensics compare    gap-aware diff of two report.json snapshots

This module is a **dispatcher only**. Every command delegates to the v4 engine
in `cli_v4.py` (`cmd_devices`, `cmd_doctor`, `cmd_inspect`, `cmd_compare`,
`cmd_checklist`) and reuses `collectors.discover_devices` for device selection,
so no collection, triage, or assessment logic is forked here. Every advanced
engine command (`integrity`, `case`, `buyer`, `evidence-verify`, …) is mounted on
this same binary via `cli_v4.add_subcommands`, so the project ships one name for
one tool.

Collection profiles
-------------------
`inspect` runs the *standard profile*: every non-destructive collector is on
(device info, All/GasGauge/WiFi/NAND diagnostics, IORegistry planes, the
help-only capability catalog, and triage of artifacts already present on disk).
The privacy-sensitive set (app inventory, process inventory, live syslog,
crash-report pull, provisioning profiles, full backups, MVT backup triage) is
**off unless consented to**: `--yes-sensitive`, `--no-sensitive`, or — on a real
terminal only — a single y/N prompt that enumerates the scope. A non-interactive
session never prompts and records the skip as `skipped_by_user` on the console.

Compatibility
-------------
Every legacy collector flag still works. They live in a hidden compatibility
group (`--help` for the four commands stays clean; `iphone-forensics
--help-advanced` documents the lot) and are mapped onto `inspect` options:

    --udid                    -> --device
    --redact-identifiers      -> the engine's --redact
    --mvt-backup PATH         -> the offline --backup-dir analysis path
    --init-buyer-checklist P  -> `iphone-forensics checklist --out P` (overwrites)
    --output / --buyer-json / --compare-json / --no-capability-catalog
                              -> passed through unchanged

Invoking `iphone-forensics <legacy flags>` with no command still performs the
same inspection it always did, so existing automation and `iphone_audit.py`
(which calls `cli.main`) keep working.

Exit codes (shared with the engine; see `cli_v4`'s decision table):
    0 OK · 1 completed with review-worthy findings · 2 usage/config problem
    3 discovery completed, no device attached · 4 more than one device attached
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .cli_v4 import (
    DEFAULT_OUTPUT_ROOT,
    EXIT_AMBIGUOUS_DEVICE,
    EXIT_CONFIG,
    EXIT_OK,
    _tool_path,
    add_subcommands,
    cmd_checklist,
    cmd_compare,
    cmd_devices,
    cmd_doctor,
    cmd_inspect,
    redact,
)
from .collectors import LIB_TOOLS, discover_devices
from .evidence import EVIDENCE_DIR_NAME

# Kept here because `cli_v4._new_report` imports this list as the canonical one.
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

COMMANDS = ("devices", "inspect", "doctor", "compare")
PROGRAM = "iphone-forensics"

# Bounded log capture ceiling; also enforced by the engine (`syslog_max_seconds`).
MAX_SYSLOG_SECONDS = 120

# --------------------------------------------------------------- flag tables
# One table drives the hidden compatibility group *and* `--help-advanced`, so the
# parser and the documentation cannot drift apart. Layout:
#     (flag, is_sensitive, argparse kwargs)
_COMPAT_FLAGS: tuple[tuple[str, bool, dict[str, Any]], ...] = (
    ("--udid", False, {"dest": "device", "help": "Legacy alias for --device (full UDID)."}),
    (
        "--output",
        False,
        {
            "metavar": "DIR",
            "help": "Output root directory (default: the current working directory).",
        },
    ),
    (
        "--buyer-json",
        False,
        {"metavar": "PATH", "help": "Load a buyer checklist/observations JSON file."},
    ),
    (
        "--compare-json",
        False,
        {
            "metavar": "PATH",
            "help": "Also embed an integrity comparison against a previous report.json in this run's report.",
        },
    ),
    (
        "--redact-identifiers",
        False,
        {
            "action": "store_true",
            "help": "Also emit report-redacted.html and report-redacted.json with identifiers masked.",
        },
    ),
    (
        "--no-capability-catalog",
        False,
        {
            "action": "store_true",
            "help": "Skip the help-only tool capability catalog for a faster run.",
        },
    ),
    (
        "--init-buyer-checklist",
        False,
        {
            "metavar": "PATH",
            "help": "Write an editable buyer-checklist JSON template to PATH and exit (overwrites).",
        },
    ),
    ("--app-list", True, {"action": "store_true", "help": "Collect installed-app inventory."}),
    (
        "--pmd-app-list",
        True,
        {"action": "store_true", "help": "Collect installed-app inventory with pymobiledevice3."},
    ),
    (
        "--pmd-processes",
        True,
        {
            "action": "store_true",
            "help": "Collect the running-process inventory with pymobiledevice3.",
        },
    ),
    (
        "--crash-reports",
        True,
        {"action": "store_true", "help": "Copy crash reports off the device."},
    ),
    (
        "--pmd-crash-reports",
        True,
        {"action": "store_true", "help": "Pull crash reports with pymobiledevice3."},
    ),
    (
        "--provisioning",
        True,
        {"action": "store_true", "help": "Collect provisioning-profile inventory."},
    ),
    (
        "--syslog-seconds",
        True,
        {"type": int, "help": "Bounded libimobiledevice live log capture (0-120 seconds)."},
    ),
    (
        "--pmd-syslog-seconds",
        True,
        {"type": int, "help": "Bounded pymobiledevice3 live log capture (0-120 seconds)."},
    ),
    (
        "--backup",
        True,
        {
            "choices": ("none", "libimobiledevice", "pymobiledevice3"),
            "help": "Create a full backup (potentially sensitive); default is none.",
        },
    ),
    (
        "--mvt-backup",
        True,
        {
            "metavar": "PATH",
            "help": "Triage an existing authorized backup directory: offline analysis + mvt-ios check-backup.",
        },
    ),
)

_CONSENT_FLAGS: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "--yes-sensitive",
        {
            "action": "store_true",
            "help": "Include the sensitive collectors that take no extra argument (app, "
            "process, crash-report, and provisioning inventory). Bounded log capture "
            "and full backups still require their own dedicated flag; see "
            f"`{PROGRAM} --help-advanced`.",
        },
    ),
    (
        "--no-sensitive",
        {
            "action": "store_true",
            "help": "Never prompt and keep every sensitive collector off (automation-safe default).",
        },
    ),
)


def _dest_of(flag: str, spec: dict[str, Any]) -> str:
    return str(spec.get("dest") or flag.lstrip("-").replace("-", "_"))


# Destinations whose presence means the caller asked for a privacy-sensitive
# collector. Derived from the table so the two can never disagree.
SENSITIVE_DESTS = frozenset(_dest_of(f, s) for f, sens, s in _COMPAT_FLAGS if sens)
# Any legacy flag at all means "run an inspection", which is how the pre-v5
# no-subcommand invocation keeps working.
COMPAT_DESTS = frozenset(_dest_of(f, s) for f, _sens, s in _COMPAT_FLAGS)

# Human-readable consent scope, in the order the selector lists it.
# Each entry is (label, flags, argparse dests it enables) so the checkbox menu,
# the `--yes-sensitive` blanket switch, and the explicit-flag path can never
# disagree about what a given line actually collects.
SENSITIVE_SCOPE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Installed-app inventory", "--app-list, --pmd-app-list", ("app_list", "pmd_app_list")),
    ("Running-process inventory", "--pmd-processes", ("pmd_processes",)),
    (
        "Live system-log capture",
        "--syslog-seconds, --pmd-syslog-seconds",
        ("syslog_seconds", "pmd_syslog_seconds"),
    ),
    (
        "Crash-report copy / pull",
        "--crash-reports, --pmd-crash-reports",
        ("crash_reports", "pmd_crash_reports"),
    ),
    ("Provisioning-profile inventory", "--provisioning", ("provisioning",)),
    ("Full device backup", "--backup", ("backup",)),
    ("MVT backup triage", "--mvt-backup", ("mvt_backup",)),
)

# Labels that need a value (a duration, a target path) rather than a bare switch.
# Consent selects them, but the operator still has to supply the argument — the
# tool never invents a capture window or picks a backup destination.
SENSITIVE_NEEDS_VALUE: frozenset[str] = frozenset(
    {
        "Live system-log capture",
        "Full device backup",
        "MVT backup triage",
    }
)


# --------------------------------------------------------------- small helpers


def _given(namespace: argparse.Namespace, dest: str) -> Any:
    """Value of `dest`, or None when the flag was not passed at all.

    Every compatibility flag is registered with ``default=argparse.SUPPRESS``,
    so "absent" is distinguishable from "explicitly set to a falsy value".
    """
    return getattr(namespace, dest, None)


def _flag_value(namespace: argparse.Namespace, dest: str, fallback: Any = None) -> Any:
    value = getattr(namespace, dest, None)
    return fallback if value is None else value


def _is_tty(stream: Any = None) -> bool:
    """True only for a real terminal. Scripts and CI must never be prompted."""
    handle = sys.stdin if stream is None else stream
    try:
        return bool(handle is not None and handle.isatty())
    except (AttributeError, ValueError):
        return False


def _toolkit_present() -> bool:
    """Same discovery precondition the engine checks before stage 1 (no probes)."""
    return any(_tool_path(name) for name in list(LIB_TOOLS) + ["pymobiledevice3"])


# ------------------------------------------------------------ device selection


def _probe_devices() -> list[str] | None:
    """Discover attached UDIDs into a throwaway directory.

    Returns None when discovery itself failed, so the caller can defer to the
    engine (which reports the real error) instead of pretending "no device".
    """
    try:
        with tempfile.TemporaryDirectory(prefix="iphone-forensics-select-") as probe:
            return discover_devices(Path(probe), [])
    except Exception as exc:  # noqa: BLE001 — a probe failure must not abort the run
        print(f"Device probe failed ({exc}); deferring to the inspection engine.")
        return None


def _ask_device_and_consent(
    devices: list[str], consent: bool | None
) -> tuple[str | None, bool | None]:
    """Deprecated combined prompt, kept only so imports do not break.

    Device selection and sensitive collection are now two separate interactive
    widgets — `interactive.choose_device` and `interactive.choose_sensitive` —
    because a checkbox list cannot share one prompt line with a numbered list.
    """
    from .interactive import choose_device, choose_sensitive

    chosen = choose_device(devices)
    if chosen is None:
        return None, None
    labels = choose_sensitive(tuple((label, flags) for label, flags, _ in SENSITIVE_SCOPE))
    return chosen, bool(labels)


# ------------------------------------------------------------------- consent


def _explicitly_requested(namespace: argparse.Namespace, dest: str) -> bool:
    """Was this sensitive collector actually asked for?

    `--backup none` is the flag's own default, so passing it is not a request.
    """
    value = _given(namespace, dest)
    if dest == "backup":
        return bool(value) and value != "none"
    return bool(value)


def _prompt_consent(stream: Any = None) -> bool | None:
    """One y/N prompt enumerating the sensitive scope.

    None means "no prompt was possible" (non-interactive), so the caller can
    record the skip as `skipped_by_user` instead of inventing consent.
    """
    handle = sys.stdin if stream is None else stream
    if not _is_tty(handle):
        return None
    print("\nStandard profile is read-only. Consent would additionally collect:")
    for item, flags in SENSITIVE_SCOPE:
        print(f"  - {item:<32} ({flags})")
    try:
        answer = input("Include sensitive collection in this run? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in {"y", "yes"}


def _selected_dests(labels: set[str]) -> frozenset[str]:
    """Argparse dests enabled by the consent labels the operator ticked."""
    dests: set[str] = set()
    for label, _flags, targets in SENSITIVE_SCOPE:
        if label in labels:
            dests.update(targets)
    return frozenset(dests)


def _resolve_sensitive(
    namespace: argparse.Namespace, stream: Any = None
) -> tuple[bool, frozenset[str]]:
    """Decide the sensitive profile: (consent_for_the_rest, explicitly_requested).

    * An explicit collector flag is itself consent **for that collector only**,
      and it also suppresses the prompt, so legacy automation that already names
      a sensitive collector is never interrupted.
    * ``--yes-sensitive`` turns on every boolean collector; ``--no-sensitive`` and
      an empty selection leave them off; a non-interactive session always leaves
      them off and is recorded as ``skipped_by_user``.
    * On a TTY the operator gets a **checkbox list** — space toggles, Enter
      confirms — so they can take exactly the app inventory without also handing
      over log capture and a backup. An all-or-nothing y/N could not express that.
    * Dests that need a value (``--syslog-seconds``, ``--backup``, ``--mvt-backup``)
      are selected but not enabled: consent never invents a capture window or a
      backup destination, so the operator must still pass the argument.
    """
    explicit = frozenset(dest for dest in SENSITIVE_DESTS if _explicitly_requested(namespace, dest))
    if _flag_value(namespace, "yes_sensitive", False):
        print(
            "Sensitive collection enabled (--yes-sensitive): app, process, crash-report, and "
            "provisioning inventory."
        )
        return True, explicit
    if explicit:
        print(
            "Sensitive collectors explicitly requested: "
            + ", ".join(sorted(f"--{dest.replace('_', '-')}" for dest in explicit))
            + " — every other sensitive collector stays off."
        )
        return False, explicit
    if _flag_value(namespace, "no_sensitive", False):
        print("Sensitive collection disabled (--no-sensitive).")
        return False, explicit

    from .interactive import choose_sensitive

    labels = choose_sensitive(tuple((label, flags) for label, flags, _ in SENSITIVE_SCOPE))
    if not labels:
        if not _is_tty(stream):
            print(
                "Non-interactive session: sensitive collection skipped "
                "(status: skipped_by_user). Re-run with --yes-sensitive to include it."
            )
        else:
            print("Sensitive collection not selected; standard read-only profile only.")
        return False, explicit

    chosen = _selected_dests(labels)
    needs_value = sorted(label for label in labels if label in SENSITIVE_NEEDS_VALUE)
    if needs_value:
        print(
            "Selected but still needs its argument (nothing was invented for you): "
            + ", ".join(needs_value)
        )
        print("  e.g. --syslog-seconds 30 for log capture, --backup libimobiledevice for a backup.")
    return True, frozenset(explicit | chosen)


# ------------------------------------------------------------ engine delegation


def _engine_args(
    namespace: argparse.Namespace,
    *,
    output: str,
    device: str | None,
    sensitive: bool,
    explicit: frozenset[str] = frozenset(),
) -> argparse.Namespace:
    """Build the namespace `cli_v4.cmd_inspect` expects.

    Only the flags the engine reads are forwarded, so nothing from the v5
    surface leaks into the run. `sensitive` is consent for the collectors that
    take no argument; an explicitly passed flag always wins for its own
    collector, and the collectors that need a duration or a target
    (`--syslog-seconds`, `--backup`, `--mvt-backup`) stay off unless explicitly
    requested, so consent never invents a capture window or a backup.
    """

    def boolean(dest: str) -> bool:
        """True when this collector was named on the command line or consented to.

        `sensitive` is the *blanket* consent from `--yes-sensitive`; a partial
        checkbox selection arrives in `explicit` instead, so this no longer ORs
        everything into every collector when a single item was ticked.
        """
        return bool(_given(namespace, dest)) or sensitive or dest in explicit

    # Two offline paths reach the engine's `backup_dir`: the engine's own
    # `--backup-dir`, and the facade's legacy `--mvt-backup`. Only the latter was
    # ever read here, so `inspect --backup-dir` parsed cleanly and then ran a
    # *device* collection against no device — the run produced an empty report
    # instead of triaging the supplied directory.
    backup_dir = _given(namespace, "backup_dir")
    mvt_backup = _given(namespace, "mvt_backup")
    if backup_dir and mvt_backup:
        print(
            "error: --backup-dir and --mvt-backup both select the offline path; pass only one.",
            file=sys.stderr,
        )
        backup_dir = mvt_backup = None
    offline_dir = backup_dir or mvt_backup
    if mvt_backup:
        print(
            f"--mvt-backup {mvt_backup}: running the offline backup path (artifact triage + mvt-ios "
            "check-backup). No device collection runs for this path."
        )
    elif backup_dir:
        print(
            f"--backup-dir {backup_dir}: running the offline evidence path. "
            "No device collection runs for this path."
        )
    return argparse.Namespace(
        output=output,
        device=device,
        backup_dir=offline_dir or None,
        buyer_json=_flag_value(namespace, "buyer_json"),
        compare_json=_flag_value(namespace, "compare_json"),
        redact=bool(_flag_value(namespace, "redact_identifiers", False)),
        no_capability_catalog=bool(_flag_value(namespace, "no_capability_catalog", False)),
        fail_on_findings=bool(_flag_value(namespace, "fail_on_findings", True)),
        app_list=boolean("app_list"),
        pmd_app_list=boolean("pmd_app_list"),
        pmd_processes=boolean("pmd_processes"),
        crash_reports=boolean("crash_reports"),
        pmd_crash_reports=boolean("pmd_crash_reports"),
        provisioning=boolean("provisioning"),
        syslog_seconds=int(_flag_value(namespace, "syslog_seconds", 0) or 0),
        pmd_syslog_seconds=int(_flag_value(namespace, "pmd_syslog_seconds", 0) or 0),
        backup=str(_flag_value(namespace, "backup", "none") or "none"),
        # Recorded in report.scope so a run states, on its face, whether sensitive
        # collection was granted, declined, or never applicable (docs/v5/07).
        sensitive_consent=sensitive,
        sensitive_explicit=sorted(explicit),
    )


def _validate_capture_bounds(namespace: argparse.Namespace) -> int | None:
    """Reject an out-of-range log window before any run directory is created."""
    for dest in ("syslog_seconds", "pmd_syslog_seconds"):
        value = _flag_value(namespace, dest, 0)
        if value in (None, 0):
            continue
        try:
            seconds = int(value)
        except (TypeError, ValueError):
            print(
                f"error: --{dest.replace('_', '-')} must be a whole number of seconds",
                file=sys.stderr,
            )
            return EXIT_CONFIG
        if not 0 <= seconds <= MAX_SYSLOG_SECONDS:
            print(
                f"error: --{dest.replace('_', '-')} must be between 0 and {MAX_SYSLOG_SECONDS}",
                file=sys.stderr,
            )
            return EXIT_CONFIG
    return None


# ----------------------------------------------------------------- commands


def _run_inspect(namespace: argparse.Namespace, output: str) -> int:
    """`inspect`: select a device, resolve consent, delegate to the engine."""
    invalid = _validate_capture_bounds(namespace)
    if invalid is not None:
        return invalid

    # Validate --device before anything is created, so a bad value costs nothing
    # and cannot produce a run directory full of collection errors.
    invalid_device = _resolve_device_argument(namespace)
    if invalid_device is not None:
        return invalid_device

    device = _flag_value(namespace, "device")
    # Offline paths (`--backup-dir` / `--mvt-backup`) analyse supplied artifacts
    # and never touch a device, so neither device discovery nor the consent
    # prompt belongs in that flow.
    offline = bool(_given(namespace, "backup_dir") or _given(namespace, "mvt_backup"))
    if offline:
        sensitive, explicit = False, frozenset()
        return cmd_inspect(
            _engine_args(namespace, output=output, device=None, sensitive=False, explicit=explicit)
        )
    if not device:
        devices = _probe_devices()
        if devices is None:
            pass  # probe failed: let the engine discover (and report) itself
        elif not devices:
            if _toolkit_present():
                print("No connected device detected.")
                print(
                    "Next: `iphone-forensics doctor` — checks the cable, pairing, and Trust prompt."
                )
            else:
                print("No supported iOS toolkit detected.")
                print(
                    "Next: `iphone-forensics doctor` — prints install instructions for "
                    "libimobiledevice and/or pymobiledevice3."
                )
            # Handled by the engine so the run still leaves a BLOCKER report and
            # returns EXIT_NO_DEVICE, exactly like the pre-v5 flow.
        elif _is_tty():
            # An interactive selector even for a single device: it shows the full
            # UDID (so it can be reused) and lets the operator confirm rather than
            # silently inspecting whatever happens to be plugged in.
            from .interactive import choose_device

            chosen = choose_device(devices)
            if chosen is None:
                print("No device selected; nothing was inspected.")
                return EXIT_AMBIGUOUS_DEVICE
            device = chosen
        else:
            print(f"{len(devices)} device(s) connected and this session is not interactive.")
            for index, udid in enumerate(devices, 1):
                print(f"  {index}. {udid}")
            print("Using the first. Pass --device <udid> to choose another.")

    sensitive, explicit = _resolve_sensitive(namespace)
    return _dispatch_inspect(namespace, output, device, sensitive, explicit)


def _looks_like_udid(value: str) -> bool:
    """True when *value* has the shape of a device UDID.

    Observed forms, with and without the dash:

    * ``00008030-001234567890ABCD`` — 8 hex + dash + 16 hex, what
      ``idevice_id -l`` and libimobiledevice report (25 chars, 24 hex digits).
    * ``udid-00008030001234567890ABCD…`` — the prefixed form some tools emit.
    * 16- and 40-hex forms appear in older and vendor tooling.

    Anything else — a menu number like ``1``, a path, a name — is not a UDID and
    must never be handed to the collectors as one. The earlier version of this
    check only accepted 40 hex digits and so rejected the common 24-digit form,
    turning every real UDID into a usage error.
    """
    compact = str(value).strip().lower()
    compact = compact.removeprefix("udid-")
    compact = compact.replace("-", "")
    if len(compact) < 8 or not all(char in "0123456789abcdef" for char in compact):
        return False
    # Lengths actually seen: 24 (idevice_id), 16, 32, 40. A bare 8-hex value is
    # also the device's ECID tail and is accepted by the collectors.
    return len(compact) in (8, 16, 24, 32, 40)


def _resolve_device_argument(namespace: argparse.Namespace) -> int | None:
    """Reject a `--device` value that cannot be a UDID, before any run starts.

    `--device 1` was taken literally as a UDID, so every collector ran against a
    device that does not exist and the run produced a wall of collection errors
    with an empty device record. A selection number is a reasonable thing to type,
    so it is resolved to a real UDID when there is exactly one choice, and
    rejected with the actual UDIDs listed when the input is not a device at all.
    """
    raw = _flag_value(namespace, "device")
    if raw is None:
        return None
    if str(raw).strip() == "":
        # `--device` with no value means "let me pick". nargs="?" on the flag
        # makes this an explicit request for the selector rather than a typo.
        from .interactive import choose_device

        devices = _probe_devices() or []
        if not devices:
            print("error: --device was given but no device is attached.", file=sys.stderr)
            print("Next: `iphone-forensics doctor`.", file=sys.stderr)
            return EXIT_NO_DEVICE
        chosen = choose_device(devices)
        if chosen is None:
            return EXIT_AMBIGUOUS_DEVICE
        _set_device(namespace, chosen)
        return None
    device = str(raw).strip()
    if _looks_like_udid(device):
        return None

    # Not a UDID. If it is a menu number, resolve it against what is attached.
    if device.isdigit():
        devices = _probe_devices() or []
        index = int(device)
        if devices and 1 <= index <= len(devices):
            print(
                f"--device {device} resolved to device {index} of {len(devices)}: "
                f"{redact(devices[index - 1])}"
            )
            _set_device(namespace, devices[index - 1])
            return None
        listing = (
            "\n".join(f"  {n}. {redact(u)}" for n, u in enumerate(devices, 1))
            or "  (no devices detected — run `iphone-forensics doctor`)"
        )
        print(
            f"error: --device {device!r} is not a device number in range and not a UDID.",
            file=sys.stderr,
        )
        print(f"Connected devices:\n{listing}", file=sys.stderr)
        print(
            "Pass a UDID (Settings → General → About → Serial Number), or omit "
            "--device to select interactively.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    print(f"error: --device {device!r} is not a UDID.", file=sys.stderr)
    print(
        "A UDID is the device's Serial Number as shown in "
        "Settings → General → About, or the last 8 characters of it.",
        file=sys.stderr,
    )
    return EXIT_CONFIG


def _set_device(namespace: argparse.Namespace, udid: str) -> None:
    """Record the resolved UDID on the namespace under every name it is read by."""
    namespace.device = udid
    namespace.udid = udid


def _dispatch_inspect(
    namespace: argparse.Namespace,
    output: str,
    device: str | None,
    sensitive: bool,
    explicit: frozenset[str],
    *,
    announce: bool = False,
) -> int:
    """Hand the resolved device and consent decision to the engine.

    `announce` is False for the `_resolve_sensitive` path, which has already
    explained the decision it reached. Printing it a second time here made a
    consented run say "Sensitive collection enabled" twice, which reads like the
    scope was granted twice. The single-prompt path passes True because it has not
    printed anything yet.
    """
    if announce:
        if sensitive:
            print("Sensitive collection enabled for this run by consent.")
        elif granted_explicitly := explicit:
            print(
                "Sensitive collectors explicitly requested: "
                + ", ".join(sorted(f"--{dest.replace('_', '-')}" for dest in granted_explicitly))
                + " — every other sensitive collector stays off."
            )
        elif not _is_tty():
            print(
                "Non-interactive session: sensitive collection skipped "
                "(status: skipped_by_user). Re-run with --yes-sensitive to include it."
            )
        else:
            print("Sensitive collection declined; standard read-only profile only.")
    return cmd_inspect(
        _engine_args(
            namespace, output=output, device=device, sensitive=sensitive, explicit=explicit
        )
    )


def _default_current_report() -> Path | None:
    """Newest `./iphone-forensics-*/report.json` in the working directory."""
    candidates = [
        path for path in Path.cwd().glob("iphone-forensics-*/report.json") if path.is_file()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _run_compare(namespace: argparse.Namespace) -> int:
    # The flag wins if both forms are given, since it is the explicit one.
    previous = str(
        _flag_value(namespace, "previous_flag", "")
        or _flag_value(namespace, "previous_report", "")
        or ""
    )
    if not previous:
        print(
            "error: compare needs a previous report.json, given either "
            "positionally or with --previous",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    current = _flag_value(namespace, "current")
    if not current:
        current = _default_current_report()
        if current is None:
            print(
                "error: --current was not given and no ./iphone-forensics-*/report.json was found "
                "in the current directory",
                file=sys.stderr,
            )
            print("Pass --current <report.json> explicitly.", file=sys.stderr)
            return EXIT_CONFIG
        print(f"Comparing against the newest run in this directory: {current}")
    return cmd_compare(
        argparse.Namespace(
            previous=previous, current=str(current), out=_flag_value(namespace, "out")
        )
    )


def _write_checklist_template(path: str) -> int:
    """`--init-buyer-checklist PATH`: the engine's checklist writer, overwriting."""
    return cmd_checklist(argparse.Namespace(out=path, force=True))


# ------------------------------------------------------------------ welcome


def _welcome() -> int:
    """No command and no legacy flags: say what this is and what to run next."""
    tools = [name for name in LIB_TOOLS if shutil.which(name)]
    pmd = shutil.which("pymobiledevice3")
    print(f"iphone-forensics v{__version__} — local-first, non-destructive iPhone inspection")
    print()
    if tools or pmd:
        print(
            f"Toolchain: {len(tools)}/{len(LIB_TOOLS)} libimobiledevice tools"
            + ("; pymobiledevice3 available" if pmd else "; pymobiledevice3 not installed")
        )
    else:
        print(
            "Toolchain: no iOS toolkit detected — install libimobiledevice and/or pymobiledevice3."
        )
    print("Prerequisites: iPhone unlocked · Trust This Computer approved · data-capable cable.")
    print()
    print("Next:")
    print("  iphone-forensics devices    list connected phones and the next step")
    print("  iphone-forensics inspect    full read-only inspection → report.html")
    print("  iphone-forensics doctor     diagnose the toolchain, pairing, and reachability")
    print("  iphone-forensics compare <previous-report.json>   diff two runs")
    print()
    print("Advanced/compatibility flags: iphone-forensics --help-advanced")
    return EXIT_OK


# ------------------------------------------------------------------- parser


def _existing_flags(parser: argparse.ArgumentParser) -> set[str]:
    """Option strings and dests already declared on *parser*."""
    seen: set[str] = set()
    for action in parser._actions:
        seen.update(action.option_strings)
        if action.dest and action.dest != "help":
            seen.add(action.dest)
    return seen


def _add_compat_flags(parser: argparse.ArgumentParser, *, all_flags: bool) -> None:
    """Attach the hidden compatibility group.

    `help=argparse.SUPPRESS` keeps them out of `--help`; `default=SUPPRESS` keeps
    a subparser from clobbering a value given before the subcommand name and lets
    the dispatcher tell "not passed" from "passed as falsy".

    A flag the parser already declares is skipped rather than re-added. Now that
    the facade augments the engine's own `inspect`/`devices`/`doctor` parsers,
    several legacy names (`--output`, `--device`, `--buyer-json`, …) are already
    present with equivalent meaning, and argparse rejects a duplicate option.
    """
    present = _existing_flags(parser)
    for flag, _sensitive, spec in _COMPAT_FLAGS:
        if not all_flags and flag == "--output":
            continue
        dest = _dest_of(flag, spec)
        if flag in present or dest in present:
            continue
        kwargs = {key: value for key, value in spec.items() if key != "help"}
        parser.add_argument(flag, default=argparse.SUPPRESS, help=argparse.SUPPRESS, **kwargs)


def _add_consent_flags(container: Any, *, hidden: bool) -> None:
    """Attach --yes-sensitive / --no-sensitive as a mutually exclusive pair.

    `hidden=True` suppresses both the help column and the default so the flags
    work with no command at all (pre-v5 invocation) without cluttering `--help`.
    """
    group = container.add_mutually_exclusive_group()
    for flag, spec in _CONSENT_FLAGS:
        kwargs = {key: value for key, value in spec.items() if key != "help"}
        if hidden:
            kwargs["help"] = argparse.SUPPRESS
        # SUPPRESS always, not only when hidden. The subparser's store_true
        # default (False) otherwise overwrote a `--yes-sensitive` given *before*
        # the subcommand, so `--yes-sensitive inspect` silently ran with
        # sensitive collection off while `inspect --yes-sensitive` honoured it.
        # Matching the compat flags' `default=SUPPRESS` also keeps "not passed"
        # distinguishable from "passed as False" for `_resolve_sensitive`.
        kwargs["default"] = argparse.SUPPRESS
        group.add_argument(flag, **kwargs)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Local-first, non-destructive iPhone inspection with an HTML buyer report. "
            "Four commands; a standard inspection needs no flags."
        ),
        epilog=(
            "Examples:\n"
            "  iphone-forensics devices\n"
            "  iphone-forensics inspect\n"
            "  iphone-forensics doctor\n"
            "  iphone-forensics compare ./iphone-forensics-20260101-120000/report.json\n"
            "\n"
            "A standard `inspect` run collects everything read-only and leaves sensitive\n"
            "collection off unless you consent. Advanced/compatibility flags:\n"
            f"  {PROGRAM} --help-advanced\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    parser.add_argument(
        "--help-advanced",
        dest="help_advanced",
        action="store_true",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    _add_compat_flags(parser, all_flags=True)
    # Consent flags are hidden here but must work wherever the legacy flags do,
    # so the no-subcommand (pre-v5) invocation stays controllable from a script.
    _add_consent_flags(parser, hidden=True)

    sub = parser.add_subparsers(dest="command", metavar="command")

    # The engine defines every subcommand except `compare`. Defining `inspect`
    # twice — once here with a hand-copied flag list and once in the engine — is
    # what let the facade drift: `inspect --backup-dir` and
    # `--no-fail-on-findings` worked under `iphone-surgery` and silently vanished
    # from `iphone-forensics`. So the facade *augments* the engine's parser
    # (attaching consent and legacy flags and swapping in its own dispatch)
    # instead of re-declaring one.
    add_subcommands(sub, skip=frozenset({"compare"}))

    _augment_facade_commands(sub)

    # `compare` is the one command the facade redefines outright: it takes the
    # previous report positionally and defaults `--current` to the newest run in
    # the working directory, which the engine's `--previous/--current` pair does
    # not.
    compare = sub.add_parser(
        "compare",
        help="Gap-aware comparison of two report.json snapshots",
        description=(
            "Classify every field as changed, unchanged, only-in-one-side, or not "
            "comparable, and report the integrity/continuity verdict. A missing field "
            "on one side is never treated as a device change.\n\n"
            "The previous report may be given positionally or with --previous; both "
            "forms are accepted because the engine previously required the flag."
        ),
    )
    # Distinct dests on purpose. Sharing one dest looks tidier but silently loses the
    # flag: an unsatisfied `nargs="?"` positional is applied *after* the option,
    # overwriting it with None. So `compare --previous a.json` parsed to None.
    compare.add_argument(
        "previous_report", metavar="PREVIOUS_REPORT", nargs="?", help="Earlier run's report.json"
    )
    compare.add_argument(
        "--previous",
        metavar="REPORT",
        dest="previous_flag",
        help="Earlier run's report.json (alternative to the positional form)",
    )
    compare.add_argument(
        "--current",
        metavar="REPORT",
        help="Later run's report.json (default: newest ./iphone-forensics-*/report.json)",
    )
    compare.add_argument("--out", metavar="PATH", help="Write the combined comparison JSON here")
    compare.set_defaults(func=_run_compare)

    return parser


def _augment_facade_commands(sub: Any) -> None:
    """Layer the facade's behaviour onto the engine's subcommand parsers.

    For `devices`, `doctor` and `inspect` this attaches the facade's own flags and
    replaces `func` with the facade's dispatch, so a run behaves the documented
    way (consent prompt, device selection, legacy-flag mapping) while keeping
    every flag the engine already declared.
    """
    for name, facade_func, all_flags, description in _FACADE_AUGMENTED:
        command = sub.choices[name]
        if description:
            command.description = description
        if name == "inspect":
            _add_consent_flags(command, hidden=False)
            # Auto-open is on for a human at a terminal, so it needs a documented
            # way out for scripts and for anyone who just wants the files.
            command.add_argument(
                "--no-open",
                dest="no_open",
                action="store_true",
                help="Do not open report.html in a browser when the run finishes.",
            )
        _add_compat_flags(command, all_flags=all_flags)
        command.set_defaults(func=facade_func)


def _run_devices(namespace: argparse.Namespace) -> int:
    return cmd_devices(
        argparse.Namespace(output=_flag_value(namespace, "output", DEFAULT_OUTPUT_ROOT))
    )


def _run_doctor(namespace: argparse.Namespace) -> int:
    return cmd_doctor(
        argparse.Namespace(output=_flag_value(namespace, "output", DEFAULT_OUTPUT_ROOT))
    )


def _run_inspect_command(namespace: argparse.Namespace, output: str | None = None) -> int:
    """`inspect` entry point (also used by the no-subcommand compatibility path)."""
    if _flag_value(namespace, "init_buyer_checklist"):
        return _write_checklist_template(str(_flag_value(namespace, "init_buyer_checklist")))
    root = output or _flag_value(namespace, "output", DEFAULT_OUTPUT_ROOT)
    return _run_inspect(namespace, str(root))


# Commands the facade customises on top of the engine's parser:
#   (name, dispatch, attach_all_compat_flags, description override)
# `compare` is absent: the facade redefines that parser outright, because its
# positional-argument form is incompatible with the engine's flag pair.
# Declared after the dispatch functions, which it references.
_FACADE_AUGMENTED: tuple[tuple[str, Any, bool, str], ...] = (
    ("devices", _run_devices, False, ""),
    ("doctor", _run_doctor, False, ""),
    (
        "inspect",
        _run_inspect_command,
        True,
        "Run the standard profile: every non-destructive collector is on and "
        "sensitive collection is off unless you consent.\n\n"
        "No flag is needed for a normal inspection. Device selection, output "
        "location, buyer checklists, redaction, and every legacy collector flag "
        f"are documented by `{PROGRAM} --help-advanced`.",
    ),
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse `argv`. Kept as the module's parsing entry point (v3 compatibility)."""
    return _build_parser().parse_args(argv)


def _engine_subcommands() -> list[tuple[str, str]]:
    """The advanced engine's subcommands, read from its own parser.

    Derived rather than hardcoded so this help text can never drift from the
    interface it documents.
    """
    try:
        from .cli_v4 import build_parser

        parser = build_parser()
        for action in parser._actions:
            # _SubParsersAction records each subcommand's one-line help here.
            entries = getattr(action, "_choices_actions", None)
            if entries:
                return sorted((str(entry.dest), str(entry.help or "")) for entry in entries)
        return []
    except Exception:  # noqa: BLE001 - --help must never fail, whatever the engine parser does
        return []


def _print_advanced_help() -> int:
    print(f"{PROGRAM} {__version__} — advanced and compatibility flags\n")
    print("These are hidden from `--help` because a standard inspection needs none of them.")
    print("They work on `inspect` and, for back-compatibility, with no command at all.\n")
    print("Consent (standard profile keeps sensitive collection OFF):")
    for flag, spec in _CONSENT_FLAGS:
        print(f"  {flag:<26} {spec['help']}")
    print("\nSensitive collectors (off unless consented, or explicitly requested):")
    for flag, sensitive, spec in _COMPAT_FLAGS:
        if sensitive:
            print(f"  {flag:<26} {spec['help']}")
    print("\nOther flags:")
    for flag, sensitive, spec in _COMPAT_FLAGS:
        if not sensitive:
            print(f"  {flag:<26} {spec['help']}")

    subcommands = _engine_subcommands()
    if subcommands:
        print("\nAdvanced commands (same binary, listed in --help):")
        print("  Everything above, plus per-stage control, repair cases, and")
        print("  machine-readable output — the surface to reach for when scripting")
        print("  or post-processing a run.")
        width = max(len(name) for name, _ in subcommands) + 2
        for name, help_text in subcommands:
            print(f"  {name:<{width}} {help_text}")
        print(f"\n  Run `{PROGRAM} <command> --help` for the flags of one stage.")

    print("\nExamples:")
    print(f"  {PROGRAM} inspect --app-list --provisioning")
    print(f"  {PROGRAM} inspect --syslog-seconds 30 --no-sensitive")
    print(f"  {PROGRAM} inspect --device 00008030-001234567890ABCD")
    print(f"  {PROGRAM} --init-buyer-checklist ./checklist.json")
    print(f"  {PROGRAM} case --new --udid <udid> && {PROGRAM} case --json")
    print("\nExit codes:")
    print("  0 ok · 1 findings · 2 usage/config · 3 no device · 4 ambiguous device")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Parse `argv` and dispatch. The only entry point (`iphone_audit.py` too)."""
    args = _build_parser().parse_args(argv)

    if _flag_value(args, "help_advanced", False):
        return _print_advanced_help()

    command = _flag_value(args, "command")

    # Whether the operator actually typed a legacy flag must be decided *before*
    # the config layer runs: `_apply_config` writes defaults such as `output` onto
    # the namespace, and reading the namespace afterwards made a bare `iphone-forensics`
    # look like a legacy invocation, so it ran a full inspection instead of the
    # welcome screen.
    legacy_flags_given = any(_given(args, dest) is not None for dest in COMPAT_DESTS)

    # The config layer runs for every command on this binary, not just the
    # engine's. `./iphone-surgery.json` and `--config` are documented as global,
    # and after the two CLIs were merged a facade command (`inspect`) would
    # otherwise be the one place `output_root` was silently ignored.
    config_error = _apply_effective_config(args)
    if config_error is not None:
        return config_error

    if command is not None:
        # Either a facade command or an advanced one mounted from the engine
        # (integrity, case, buyer, evidence-verify, …); both carry their own `func`.
        return args.func(args)
    if not legacy_flags_given:
        return _welcome()
    # No command, but legacy flags were passed: perform the same inspection the
    # pre-v5 CLI always performed (this is also the `iphone_audit.py` path).
    return _run_inspect_command(args)


def _apply_effective_config(args: argparse.Namespace) -> int | None:
    """Load and apply configuration. Returns an exit code on failure, else None.

    Wraps the engine's loader, which used to be called only by `cli_v4.main`.
    The `config` subcommand manages files directly and must never auto-load —
    that is what keeps a broken config file repairable via `config --out --force`.
    """
    from .cli_v4 import EXIT_CONFIG, ConfigError, _apply_config, default_config, load_config

    try:
        if _flag_value(args, "command") == "config":
            config, sources = default_config(), []
        else:
            config, sources = load_config(getattr(args, "config", None))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            f"Fix or remove the file, or point --config at a valid one "
            f"(validate with `{PROGRAM} config --check <path>`).",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    _apply_config(args, config, sources)
    if sources and not getattr(args, "quiet", False):
        print("config: using " + ", ".join(str(path) for path in sources), file=sys.stderr)
    return None


def _run_mvt_backup(backup_path: str, run_dir: Path, raw: Path, report: dict[str, Any]) -> None:
    """Run mvt-ios check-backup against an existing authorized backup.

    Kept in this module because the v4 offline path (`cli_v4._inspect_backup`)
    imports it; the v5 dispatcher does not call it directly.
    """
    import shutil

    from .util import run_command, write_command_result

    executable = shutil.which("mvt-ios")
    source = Path(backup_path).expanduser().resolve()
    if not source.exists() or not source.is_dir():
        report.setdefault("findings", []).append(
            {
                "severity": "WARNING",
                "title": "MVT backup path unavailable",
                "detail": "The supplied path does not exist or is not a directory; no MVT scan was run.",
                "evidence": [],
            }
        )
        return
    if not executable:
        report.setdefault("findings", []).append(
            {
                "severity": "INFO",
                "title": "MVT not installed",
                "detail": "Install Mobile Verification Toolkit (mvt-ios) separately to scan an existing authorized backup.",
                "evidence": [],
            }
        )
        return
    output_dir = raw / "mvt-results"
    output_dir.mkdir(mode=0o700)
    command = [executable, "check-backup", "--output", str(output_dir), str(source)]
    result = run_command(command, timeout=3600)
    report.setdefault("collection", []).append(
        write_command_result(raw, "mvt-check-backup", result)
    )
    report["mvt"] = {
        "input_backup": str(source),
        "output_directory": f"{EVIDENCE_DIR_NAME}/mvt-results",
        "note": "MVT output is triage evidence, not proof that a device is clean or compromised.",
    }


if __name__ == "__main__":
    raise SystemExit(main())
