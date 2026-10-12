"""Interactive terminal selection for the CLI.

Two widgets, both operating on a real TTY and both degrading to a non-interactive
fallback so scripts and CI never block:

* :func:`choose_device` — pick exactly one attached device.
* :func:`choose_sensitive` — a checkbox list over the privacy-sensitive
  collectors, toggled with Space and confirmed with Enter.

Kept separate from :mod:`iphone_forensics.cli` so the terminal handling is
testable on its own and so the rest of the CLI never imports termios/tty.
"""

from __future__ import annotations

import contextlib
import sys
from typing import Any

# Key codes we care about. Arrow keys arrive as the three-byte escape sequence
# ESC [ A / ESC [ B, which a raw read gives us one byte at a time.
KEY_UP = "\x1b[A"
KEY_DOWN = "\x1b[B"
KEY_SPACE = " "
KEY_ENTER = "\r"


@contextlib.contextmanager
def _raw_mode(stream: Any):
    """Put *stream* in cbreak mode so keys arrive unbuffered, without Enter.

    Restores the terminal on the way out, including on an exception, so a
    crashed selection can never leave the user's shell unusable.
    """
    import termios
    import tty

    fd = stream.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _read_key(stream: Any) -> str:
    """Read one keypress, collapsing an arrow-key escape sequence.

    A lone ESC (user pressed Escape) must not be mistaken for the start of an
    arrow sequence, so anything that is not followed by `[` in the same read is
    returned as a bare ESC.
    """
    char = stream.read(1)
    if char != "\x1b":
        return char
    nxt = stream.read(1)
    if nxt != "[":
        return "\x1b"
    final = stream.read(1)
    return "\x1b[" + final


def _is_tty(stream: Any = None) -> bool:
    handle = sys.stdin if stream is None else stream
    try:
        return bool(handle is not None and handle.isatty())
    except (AttributeError, ValueError):
        return False


# ----------------------------------------------------------------- device pick


def choose_device(devices: list[str]) -> str | None:
    """Pick exactly one of *devices*. None = cancelled.

    Arrow keys (or j/k) move, Enter selects. The full UDID is shown because the
    operator is choosing their own attached hardware and needs the identifier to
    paste into `--device` on a later run; it is still masked in non-interactive
    output, logs, and every written artifact that is meant to be shared.
    """
    if not devices:
        return None
    if len(devices) == 1 and not _is_tty():
        return devices[0]

    if not _is_tty():
        print(f"{len(devices)} devices detected.")
        for index, udid in enumerate(devices, 1):
            print(f"  {index}. {udid}")
        print(
            "This session is not interactive; using the first device. "
            "Pass --device <udid> to choose another.",
            file=sys.stderr,
        )
        return devices[0]

    current = 0
    while True:
        try:
            _clear_screen()
            print(
                f"\n{len(devices)} device(s) connected — choose one "
                f"(↑/↓ to move, Enter to select):\n"
            )
            for index, udid in enumerate(devices):
                marker = "❯" if index == current else " "
                print(f" {marker} {index + 1}. {udid}")
            print("\n  ↑/↓ move · Enter select · q quit")
            with _raw_mode(sys.stdin):
                sys.stdout.flush()
                key = _read_key(sys.stdin)

            if key in (KEY_DOWN, "j"):
                current = (current + 1) % len(devices)
            elif key in (KEY_UP, "k"):
                current = (current - 1) % len(devices)
            elif key in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
                digit = int(key) - 1
                if 0 <= digit < len(devices):
                    current = digit
            elif key in (KEY_ENTER, "\n"):
                _clear_screen()
                return devices[current]
            elif key in ("q", "Q", "\x1b", "\x03"):
                _clear_screen()
                print("\nNo device selected.")
                return None
        except KeyboardInterrupt:
            _clear_screen()
            print("\nCancelled.")
            return None


# ------------------------------------------------------------- checkbox select


def choose_sensitive(scope: tuple[tuple[str, str], ...]) -> set[str]:
    """Checkbox selection over the privacy-sensitive collectors.

    Returns the set of flag-group ids chosen. Space toggles, ↑/↓ moves, `a`
    selects all, `n` clears, Enter confirms. Starts empty: sensitive collection
    stays off unless the operator deliberately opts in, which is the whole point
    of asking.

    Falls back to "nothing selected" when there is no TTY, so automation keeps
    the existing safe default.
    """
    if not scope:
        return set()
    if not _is_tty():
        return set()

    chosen: set[int] = set()
    current = 0
    while True:
        try:
            _clear_screen()
            print("\nPrivacy-sensitive collection — space to toggle, Enter to confirm\n")
            for index, (item, flags) in enumerate(scope):
                box = "[x]" if index in chosen else "[ ]"
                marker = "❯" if index == current else " "
                print(f" {marker} {box} {item}")
                print(f"       {flags}")
            selected = len(chosen)
            print(
                f"\n  ↑/↓ move · space toggle · a all · n none · "
                f"Enter confirm ({selected} selected)"
            )
            with _raw_mode(sys.stdin):
                sys.stdout.flush()
                key = _read_key(sys.stdin)

            if key in (KEY_DOWN, "j"):
                current = (current + 1) % len(scope)
            elif key in (KEY_UP, "k"):
                current = (current - 1) % len(scope)
            elif key in (KEY_SPACE, "x", "\t"):
                chosen.symmetric_difference_update({current})
            elif key in ("a", "A"):
                chosen = set(range(len(scope)))
            elif key in ("n", "N"):
                chosen = set()
            elif key in ("\r", "\n"):
                _clear_screen()
                names = {scope[i][0] for i in sorted(chosen)}
                if names:
                    print("Sensitive collection enabled for:")
                    for name in sorted(names):
                        print(f"  - {name}")
                else:
                    print("Sensitive collection off for this run.")
                return names
            elif key in ("q", "Q", "\x1b", "\x03"):
                _clear_screen()
                print("\nCancelled — sensitive collection off for this run.")
                return set()
        except KeyboardInterrupt:
            _clear_screen()
            print("\nCancelled — sensitive collection off for this run.")
            return set()


def _clear_screen() -> None:
    """Repaint from the top. Falls back to a newline when the terminal can't."""
    if _is_tty():
        sys.stdout.write("\x1b[H\x1b[2J")
    else:
        sys.stdout.write("\n")
