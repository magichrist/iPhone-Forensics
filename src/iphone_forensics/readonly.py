"""A mechanical guard that a command cannot write to a connected device.

This project makes a hard promise: inspecting an iPhone changes nothing. That
promise is only worth something if it is checked, so every command that talks to a
device passes through `enforce_read_only` before it is spawned.

The problem with promising this in prose is that the tools themselves are not
read-only. `idevicedate` with no arguments prints the date and with `-c` sets it.
`idevicename` prints the name and rewrites it when handed a positional argument.
`pymobiledevice3 activation` offers `state` next to `activate` and `deactivate`.
The read-only form and the mutating form of the same binary differ only by a flag,
which is precisely the kind of thing a future edit gets wrong by accident — someone
adding `--network`, or "helpfully" passing a UDID, or switching to `-q` for terser
output can silently cross a line that no type checker or test would flag.

So the rule is enforced structurally: name the exact argument vectors that are known
safe, and refuse everything else. A command that is not on the list does not run.
That inverts the usual failure mode — a new collector that forgets to declare itself
is refused, rather than a new flag that slips a mutating form past a human reader.

Refusal is loud on purpose. A collector that cannot prove it is read-only must fail
loudly in development rather than quietly do nothing in the field.
"""

from __future__ import annotations

import re

# Subcommands that mutate device state, named here so a refusal can say *why*
# rather than only *that*. Grouped by the binary they belong to, because the same
# word means different things to different tools.
_MUTATING: dict[str, tuple[str, ...]] = {
    "ideviceimagemounter": ("mount", "unmount"),
    "idevicebackup2": ("backup", "restore", "upgrade"),
    "ideviceinstaller": ("install", "uninstall"),
    "idevicedate": ("--set", "-s", "--sync", "-c"),
    "pymobiledevice3": (
        "activate",
        "deactivate",
        "itunes",
        "mount-developer",
        "mount-personalized",
        "auto-mount",
        "umount-developer",
        "umount-personalized",
        "install",
        "uninstall",
        "push",
        "rm",
        "pair",
        "unpair",
        "restore",
        "enable-developer-mode",
        "reveal-developer-mode",
    ),
}


class ReadOnlyViolation(RuntimeError):
    """Raised when a command is not on the read-only allowlist."""


_UDID_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")

# A filesystem path is normalized to <path> so the allowlist can be written as a
# shape instead of pinned to one hardcoded output directory.
#
# This is deliberately *not* a bare "contains a slash" test. Over-matching here would
# be a security hole in the wrong direction: a mutating argument that happens to
# contain a slash would be erased from the signature and could then match a shape
# that only ever saw a placeholder. So a token is a path only if it is an absolute
# or home-relative path, or it carries a known file extension.
_PATH_RE = re.compile(r"^/|^\.\./|^\./|^~/|\.(?:dmg|plist|ipa|app|ipcc|mobileprovision)$")


def _basename(command: list[str]) -> str:
    return command[0].rsplit("/", 1)[-1] if command else ""


def _normalize(args: list[str]) -> tuple[str, ...]:
    """Reduce an argument vector to a device-independent shape.

    A UDID and an output directory both vary per run and per machine while leaving
    the command's *effect* on the device unchanged. Collapsing them to placeholders
    is what lets the allowlist match every device and every run directory instead of
    only the one that happened to exist when it was written.
    """
    out: list[str] = []
    skip_value = False
    for token in args:
        if skip_value:
            skip_value = False
            continue
        if token in ("-u", "--udid"):
            # The UDID that follows is device-specific, not behaviour-specific:
            # drop both so one shape covers every device.
            skip_value = True
            continue
        if token.startswith("-u") and len(token) > 2:
            continue  # attached -uUDID form
        if _UDID_RE.match(token):
            continue  # a bare UDID passed without its flag
        if _PATH_RE.search(token):
            out.append("<path>")
            continue
        out.append(token)
    return tuple(out)


def _explain(binary: str, normalized: tuple[str, ...]) -> str:
    mutating = _MUTATING.get(binary, ())
    for arg in normalized:
        if arg.lower() in mutating:
            return f"the subcommand or flag {arg!r} writes to the device"
    return "this exact argument vector is not on the read-only allowlist"


def enforce_read_only(command: list[str]) -> list[str]:
    """Return `command` unchanged, or raise if it is not provably read-only.

    The allowlist is exact argument *shapes*, not patterns. That is stricter than a
    heuristic and deliberately so: a heuristic would have to reason about what an
    unknown flag might do, and the entire point is that unknown flags are not
    trusted. `idevicedate -u <udid>` is allowed because the bare shape is listed;
    `idevicedate -u <udid> -c` is a different shape and is refused.
    """
    if not command:
        raise ReadOnlyViolation("refusing to run an empty command")

    binary = _basename(command)
    normalized = _normalize(command[1:])

    if (binary, normalized) in READ_ONLY_COMMANDS:
        return command

    raise ReadOnlyViolation(
        f"refusing to run {' '.join(command)!r}: {_explain(binary, normalized)}. "
        f"Only shapes on the read-only allowlist may touch a device. If this shape is "
        f"genuinely read-only, add it to readonly.READ_ONLY_COMMANDS deliberately and "
        f"say in the commit why it cannot write. Never add a mutating form."
    )


# The allowlist. Every entry was checked against that tool's own help output, and
# each is the *query* form — never the mutating sibling that sits beside it.
READ_ONLY_COMMANDS: frozenset[tuple[str, tuple[str, ...]]] = frozenset(
    {
        # -- libimobiledevice -------------------------------------------------
        ("idevice_id", ("-l",)),
        ("ideviceinfo", ("-x",)),
        ("ideviceinfo", ("-q", "com.apple.disk_usage")),
        ("ideviceinfo", ("-q", "com.apple.mobile.iTunes")),
        ("ideviceinfo", ("-q", "com.apple.mobile.battery")),
        ("idevicepair", ("validate",)),
        ("idevicediagnostics", ("diagnostics", "All")),
        ("idevicediagnostics", ("diagnostics", "GasGauge")),
        ("idevicediagnostics", ("diagnostics", "WiFi")),
        ("idevicediagnostics", ("diagnostics", "NAND")),
        ("idevicediagnostics", ("ioreg", "IOPower")),
        ("idevicediagnostics", ("ioreg", "IODeviceTree")),
        ("idevicediagnostics", ("ioreg", "IOService")),
        # -k writes crash reports to a host directory; the device is only read.
        ("idevicecrashreport", ("-k", "<path>")),
        ("idevicesyslog", ()),
        ("ideviceprovision", ("list",)),
        ("ideviceinstaller", ("-l",)),
        # Bare = print. A NAME positional rewrites idevicename; -s/-c sets the clock.
        ("idevicename", ()),
        ("idevicedate", ()),
        ("ideviceimagemounter", ("list",)),
        ("ideviceimagemounter", ("devmodestatus",)),
        # -- pymobiledevice3 ---------------------------------------------------
        ("pymobiledevice3", ("usbmux", "list")),
        ("pymobiledevice3", ("version",)),
        ("pymobiledevice3", ("activation", "state")),
        ("pymobiledevice3", ("apps", "list")),
        ("pymobiledevice3", ("processes", "ps")),
        ("pymobiledevice3", ("crash", "pull", "<path>")),
        ("pymobiledevice3", ("syslog", "live")),
        ("pymobiledevice3", ("provision", "list")),
        ("pymobiledevice3", ("profile", "list")),
        ("pymobiledevice3", ("mounter", "list")),
        ("pymobiledevice3", ("amfi", "developer-mode-status")),
        ("pymobiledevice3", ("companion", "list")),
        ("pymobiledevice3", ("lockdown", "info")),
    }
)


def is_read_only(command: list[str]) -> bool:
    """Boolean form, for tests and for reporting which shapes are permitted."""
    try:
        enforce_read_only(command)
    except ReadOnlyViolation:
        return False
    return True
