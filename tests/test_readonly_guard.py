"""The read-only guarantee, enforced rather than promised.

The product claim is "inspecting an iPhone changes nothing". A test suite is the
only thing that keeps that claim true as the code evolves, so these tests attack the
guard from the direction a future bug would come from: a mutating form that looks
read-only, or a read-only form that gets blocked and quietly disappears from a run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from iphone_forensics.readonly import (
    READ_ONLY_COMMANDS,
    ReadOnlyViolation,
    enforce_read_only,
    is_read_only,
)

UDID = "00008030-000123456789ABCD"
UDID_40 = "d1234567890abcdef1234567890abcdef12345678"
BIN = "/opt/homebrew/bin"

# Every shape the collectors actually issue. If collection changes shape, this fails
# loudly rather than the run silently losing a collector.
READ_ONLY_SHAPES = [
    [f"{BIN}/idevice_id", "-l"],
    [f"{BIN}/ideviceinfo", "-u", UDID, "-x"],
    [f"{BIN}/ideviceinfo", "-u", UDID, "-q", "com.apple.disk_usage"],
    [f"{BIN}/idevicepair", "-u", UDID, "validate"],
    [f"{BIN}/idevicediagnostics", "-u", UDID, "diagnostics", "All"],
    [f"{BIN}/idevicediagnostics", "-u", UDID, "diagnostics", "GasGauge"],
    [f"{BIN}/idevicediagnostics", "-u", UDID, "diagnostics", "WiFi"],
    [f"{BIN}/idevicediagnostics", "-u", UDID, "diagnostics", "NAND"],
    [f"{BIN}/idevicediagnostics", "-u", UDID, "ioreg", "IOPower"],
    [f"{BIN}/idevicecrashreport", "-u", UDID, "-k", "/tmp/run/evidence/crash-reports"],
    [f"{BIN}/idevicesyslog", "-u", UDID],
    [f"{BIN}/ideviceprovision", "-u", UDID, "list"],
    [f"{BIN}/ideviceinstaller", "-u", UDID, "-l"],
    [f"{BIN}/idevicename", "-u", UDID],
    [f"{BIN}/idevicedate", "-u", UDID],
    [f"{BIN}/ideviceimagemounter", "-u", UDID, "list"],
    [f"{BIN}/ideviceimagemounter", "-u", UDID, "devmodestatus"],
    ["pymobiledevice3", "usbmux", "list"],
    ["pymobiledevice3", "version"],
    ["pymobiledevice3", "--udid", UDID, "activation", "state"],
    ["pymobiledevice3", "--udid", UDID, "apps", "list"],
    ["pymobiledevice3", "--udid", UDID, "processes", "ps"],
    ["pymobiledevice3", "--udid", UDID, "crash", "pull", "/tmp/run/pmd-crash"],
    ["pymobiledevice3", "--udid", UDID, "syslog", "live"],
    ["pymobiledevice3", "--udid", UDID, "provision", "list"],
    ["pymobiledevice3", "--udid", UDID, "profile", "list"],
    ["pymobiledevice3", "--udid", UDID, "mounter", "list"],
    ["pymobiledevice3", "--udid", UDID, "amfi", "developer-mode-status"],
    ["pymobiledevice3", "--udid", UDID, "companion", "list"],
    ["pymobiledevice3", "--udid", UDID, "lockdown", "info"],
]

# Shapes that would change device state. Each must be refused.
MUTATING_SHAPES = [
    # idevicedate writes the clock with -s/-c/--set/--sync.
    [f"{BIN}/idevicedate", "-u", UDID, "-c"],
    [f"{BIN}/idevicedate", "-u", UDID, "--sync"],
    [f"{BIN}/idevicedate", "-u", UDID, "-s", "2020-01-01T00:00:00Z"],
    [f"{BIN}/idevicedate", "-u", UDID, "--set", "2020-01-01T00:00:00Z"],
    # idevicename rewrites the device name when handed a positional argument.
    [f"{BIN}/idevicename", "-u", UDID, "My iPhone"],
    # Mounting and unmounting a DeveloperDiskImage changes device state.
    [f"{BIN}/ideviceimagemounter", "-u", UDID, "mount", "/tmp/Developer.dmg"],
    [f"{BIN}/ideviceimagemounter", "-u", UDID, "unmount", "/tmp/Developer.dmg"],
    # Activation.
    ["pymobiledevice3", "--udid", UDID, "activation", "activate"],
    ["pymobiledevice3", "--udid", UDID, "activation", "deactivate"],
    ["pymobiledevice3", "--udid", UDID, "activation", "itunes"],
    # Image mounting.
    ["pymobiledevice3", "--udid", UDID, "mounter", "mount-developer"],
    ["pymobiledevice3", "--udid", UDID, "mounter", "mount-personalized"],
    ["pymobiledevice3", "--udid", UDID, "mounter", "umount-developer"],
    ["pymobiledevice3", "--udid", UDID, "mounter", "auto-mount"],
    # Developer mode.
    ["pymobiledevice3", "--udid", UDID, "amfi", "enable-developer-mode"],
    ["pymobiledevice3", "--udid", UDID, "amfi", "reveal-developer-mode"],
    # App install / uninstall / container writes.
    ["pymobiledevice3", "--udid", UDID, "apps", "install", "/tmp/app.ipa"],
    ["pymobiledevice3", "--udid", UDID, "apps", "uninstall", "com.example.app"],
    ["pymobiledevice3", "--udid", UDID, "apps", "push", "a.txt", "/tmp/dst"],
    ["pymobiledevice3", "--udid", UDID, "apps", "rm", "a.txt", "/tmp/dst"],
    # Pairing state.
    ["pymobiledevice3", "--udid", UDID, "lockdown", "pair"],
    ["pymobiledevice3", "--udid", UDID, "lockdown", "unpair"],
    # Backup / restore.
    ["pymobiledevice3", "--udid", UDID, "backup2", "backup"],
    ["pymobiledevice3", "--udid", UDID, "restore"],
    # Backups via libimobiledevice.
    [f"{BIN}/idevicebackup2", "-u", UDID, "backup", "/tmp/run/backup"],
    # Installers.
    [f"{BIN}/ideviceinstaller", "-u", UDID, "install", "/tmp/app.ipa"],
    [f"{BIN}/ideviceinstaller", "-u", UDID, "uninstall", "com.example.app"],
]


@pytest.mark.parametrize("command", READ_ONLY_SHAPES, ids=lambda c: " ".join(c[1:]) or c[0])
def test_every_collector_shape_is_allowed(command: list[str]) -> None:
    """A read-only collector must never be silently refused."""
    assert enforce_read_only(command) == command


@pytest.mark.parametrize("command", MUTATING_SHAPES, ids=lambda c: " ".join(c[1:]))
def test_every_mutating_shape_is_refused(command: list[str]) -> None:
    """The core guarantee: this program cannot write to a device."""
    with pytest.raises(ReadOnlyViolation):
        enforce_read_only(command)


def test_unknown_shapes_are_refused_by_default() -> None:
    """The allowlist fails closed. An unrecognised flag is not trusted."""
    for command in (
        [f"{BIN}/ideviceinfo", "-u", UDID, "--something-new"],
        [f"{BIN}/ideviceinfo", "-u", UDID, "-x", "-q", "com.apple.disk_usage"],
        ["some-binary-we-have-never-heard-of", "--udid", UDID, "read"],
        [f"{BIN}/idevicedate", "-u", UDID, "-c", "--quiet"],
    ):
        assert not is_read_only(command), command


def test_udid_does_not_change_the_shape() -> None:
    """One allowlist entry covers every device: the UDID is not behaviour."""
    # The guard returns the command untouched; what matters is that all three forms
    # pass. Comparing the returned commands would be comparing UDIDs, which
    # obviously differ — the property under test is "accepted", not "identical".
    for command in (
        [f"{BIN}/ideviceinfo", "-u", UDID, "-x"],
        [f"{BIN}/ideviceinfo", "-u", UDID_40, "-x"],
        [f"{BIN}/ideviceinfo", f"-u{UDID}", "-x"],
    ):
        assert enforce_read_only(command) == command


def test_a_mutating_argument_hiding_in_a_path_shape_is_not_normalized_away() -> None:
    """Path normalization must not erase a mutating subcommand.

    The `_PATH_RE` normalizes paths to `<path>` so output directories need not be
    hardcoded. If that pattern were loose enough to swallow `mount`, then
    `imagemounter mount <path>` could normalize to a shape that had only ever seen a
    placeholder — and the guard would pass a command that writes.
    """
    # This is a path-like token only because of its extension, and it is NOT a
    # subcommand position, so it must not be silently dropped.
    assert not is_read_only([f"{BIN}/ideviceimagemounter", "-u", UDID, "mount", "/tmp/x.dmg"])
    # A slash-bearing token in a mutating position is still refused.
    assert not is_read_only(["pymobiledevice3", "--udid", UDID, "mounter", "mount-developer"])


def test_empty_command_is_refused() -> None:
    with pytest.raises(ReadOnlyViolation):
        enforce_read_only([])


def test_activation_state_never_claims_activation_lock_is_clear() -> None:
    """The new activation signal must not overstate what it proves.

    Adding `pymobiledevice3 activation state` is the first time the tool can say
    anything about activation from the host side. The temptation is to render a
    clean state as reassurance; that is exactly the claim matrix's forbidden move,
    because only the erase-and-reactivate cycle decides.
    """
    import sys as _sys

    if "iphone_forensics" not in _sys.modules:
        return
    from iphone_forensics.capabilities import CAPABILITIES

    rows = [r for r in CAPABILITIES if "Activation Lock" in r["item"]]
    assert rows, "activation capability must remain declared"
    entry = rows[0]
    # Not `automated`: the host query is evidence, not the decisive check.
    assert entry["coverage"] == "partial"
    assert re.search(r"not.*verdict|only the", entry["limits"], re.IGNORECASE)
    assert "erase" in entry["limits"].lower()


def test_allowlist_never_contains_a_mutating_subcommand() -> None:
    """Structural check on the allowlist itself.

    If someone adds a mutating shape to `READ_ONLY_COMMANDS` to "make a test pass",
    this fails. The allowlist is the whole security boundary, so it gets audited
    rather than trusted.
    """
    forbidden = re.compile(
        r"^(?:mount|unmount|umount|auto-mount|activate|deactivate|itunes|install|"
        r"uninstall|push|rm|pair|unpair|restore|backup|upgrade|set|sync|"
        r"enable-developer-mode|reveal-developer-mode)$",
        re.IGNORECASE,
    )
    for binary, shape in READ_ONLY_COMMANDS:
        for arg in shape:
            assert not forbidden.match(arg), f"{binary} {shape} contains a mutating arg {arg!r}"


def test_guard_raises_before_spawning(tmp_path: Path) -> None:
    """`run_command` refuses rather than spawning, and does not need the binary.

    A missing binary would otherwise surface as an ENOENT recorded as a tool gap,
    which is how a refused command could hide inside a normal-looking run.
    """
    from iphone_forensics.util import run_command

    with pytest.raises(ReadOnlyViolation):
        run_command(
            [f"{BIN}/idevicedate", "-u", UDID, "-c"], timeout=5, device_command=True
        )


def test_capture_stream_is_guarded_too() -> None:
    """The syslog collectors spawn through capture_stream, not run_command.

    A mutating shape must be refused here too, and no output file may be created —
    the refusal has to happen before the child process is started.
    """
    from iphone_forensics.util import capture_stream

    target = Path("/tmp/should-not-exist/syslog.txt")
    with pytest.raises(ReadOnlyViolation):
        capture_stream(
            ["pymobiledevice3", "--udid", UDID, "mounter", "auto-mount"],
            1,
            target,
            device_command=True,
        )
    assert not target.exists()


def test_syslog_stream_is_allowed_because_it_only_reads() -> None:
    """The genuine read-only stream still works, so the guard costs nothing."""
    from iphone_forensics.util import capture_stream

    target = Path("/tmp/iphone-forensics-readonly-check.log")
    try:
        capture_stream(["pymobiledevice3", "syslog", "live"], 1, target, device_command=True)
    except ReadOnlyViolation as exc:  # pragma: no cover - would be a guard regression
        pytest.fail(f"a read-only syslog capture was refused: {exc}")
    finally:
        target.unlink(missing_ok=True)


def test_save_result_cannot_be_told_to_skip_the_guard_by_accident() -> None:
    """The bypass used by host-command tests is keyword-only and defaults to on.

    `save_result` takes `enforce_read_only_check=False` so tests that drive it with
    a host binary (`python -c 'pass'`) can still exercise exit-code handling. This
    pins that it is off by default, so no caller can opt out by omitting an argument.
    """
    import inspect

    from iphone_forensics import collectors

    default = inspect.signature(collectors.save_result).parameters["enforce_read_only_check"].default
    assert default is True


def test_collect_device_never_passes_the_bypass() -> None:
    """No production collector may opt out of the guard.

    A source-level check rather than a behavioural one: `collect_device` is long and
    its commands differ per flag, so this asserts the property directly instead of
    trusting that every future command inside it was written correctly.
    """
    import inspect

    from iphone_forensics import collectors

    for func in (collectors.collect_device, collectors.collect_provenance,
                 collectors.discover_devices):
        source = inspect.getsource(func)
        assert "enforce_read_only_check=False" not in source, func.__name__
        assert "enforce=False" not in source, func.__name__


def test_host_only_commands_are_not_gated_by_default() -> None:
    """`--help` and `version` stay callable without declaring anything.

    The capability catalog runs `<group> --help` for up to 120 pymobiledevice3
    groups. Those are host-only and must not need an allowlist entry each.
    """
    from iphone_forensics.util import run_command

    result = run_command(["/bin/echo", "--help"], timeout=5)
    assert result["returncode"] == 0
    assert b"--help" in result["stdout"]