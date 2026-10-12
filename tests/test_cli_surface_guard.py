"""CLI-surface guard: pins the unified CLI surface (docs/v5/01 + 02).

Current shape:
  - ``iphone-forensics`` is the only entry point. It exposes the 4-command
    facade (``devices``/``inspect``/``doctor``/``compare``) plus every advanced
    subcommand the engine offers.
  - ``iphone_forensics.cli_v4`` no longer ships a console script; it remains
    importable as the engine and ``cli_v4.main`` forwards to the unified CLI.
  - ``iphone_audit.py`` is a thin wrapper that calls ``cli.main``.

These tests run the CLIs as subprocesses (offline, no iPhone) and assert on
``--help`` output only, so they are hermetic and device-free.
"""

import argparse
import os
import py_compile
import subprocess
import sys
from pathlib import Path

from iphone_forensics import cli

REPO_ROOT = Path(__file__).resolve().parents[1]

# P0 guard: update me when the 4-command facade lands (docs/v5/02-cli-redesign.md)
LEGACY_COLLECTOR_FLAGS = [
    "--app-list",
    "--crash-reports",
    "--syslog-seconds",
    "--backup",
    "--provisioning",
    "--udid",
    "--output",
]

# P0 guard: update me when the 4-command facade lands (docs/v5/02-cli-redesign.md)
V4_SUBCOMMANDS = [
    "doctor",
    "devices",
    "inspect",
    "integrity",
    "evidence-verify",
    "report",
    "tools",
    "checklist",
    "case",
    "manual-tests",
    "buyer",
    "hardware",
    "diagnose",
    "capabilities",
    "compare",
    "config",
]


def _hermetic_env(home: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    # Tool-free PATH: help output must not depend on libimobiledevice/pymobiledevice3.
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    env["HOME"] = str(home)
    return env


def _run_module(module: str, home: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", module, *argv],
        capture_output=True,
        text=True,
        env=_hermetic_env(home),
        cwd=str(REPO_ROOT),
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


# v5: the 4-command facade remains the documented path (docs/v5/02), and the
# advanced surface is now mounted on the same binary rather than a second entry
# point, so these four must still lead.
V5_COMMANDS = ["devices", "inspect", "doctor", "compare"]


def test_cli_help_lists_facade_commands_and_hides_legacy_collector_flags(tmp_path: Path):
    result = _run_module("iphone_forensics.cli", tmp_path, "--help")
    assert result.returncode == 0, result.stderr
    for command in V5_COMMANDS:
        assert command in result.stdout, f"command {command!r} missing from cli --help"
    # Every legacy collector flag must be documented by --help-advanced, and must
    # be kept out of the printed top-level help. They are still accepted as
    # top-level options on purpose — that is how the pre-v5 no-subcommand
    # invocation works — so the check is against rendered help text, not against
    # the parser's option set.
    top_level_options = {
        opt for action in cli._build_parser()._actions for opt in action.option_strings
    }
    for flag in LEGACY_COLLECTOR_FLAGS:
        # A legacy flag may be accepted at the top level (that is what the
        # pre-v5 no-subcommand invocation relies on), but it must be declared with
        # help=SUPPRESS so `--help` never lists it. A subcommand's one-line help
        # may still *mention* a flag by name — e.g. `inspect`'s "... or
        # --backup-dir offline" — which is documentation, not a leaked option.
        for action in cli._build_parser()._actions:
            if flag in action.option_strings:
                assert action.help is argparse.SUPPRESS, (
                    f"legacy flag {flag!r} must stay hidden from --help"
                )
    advanced = _run_module("iphone_forensics.cli", tmp_path, "--help-advanced")
    assert advanced.returncode == 0, advanced.stderr
    for flag in LEGACY_COLLECTOR_FLAGS:
        assert flag in advanced.stdout, f"legacy flag {flag!r} missing from cli --help-advanced"


# P0 guard: update me when the 4-command facade lands (docs/v5/02-cli-redesign.md)
def test_v4_help_lists_all_16_subcommands(tmp_path: Path):
    result = _run_module("iphone_forensics.cli_v4", tmp_path, "--help")
    assert result.returncode == 0, result.stderr
    for subcommand in V4_SUBCOMMANDS:
        assert subcommand in result.stdout, f"subcommand {subcommand!r} missing from cli_v4 --help"


# P0 guard: update me when the 4-command facade lands (docs/v5/02-cli-redesign.md)
def test_iphone_audit_compiles(tmp_path: Path):
    target = REPO_ROOT / "iphone_audit.py"
    assert target.exists(), "iphone_audit.py must keep existing at repo root"
    py_compile.compile(str(target), doraise=True)


# P0 guard: update me when the 4-command facade lands (docs/v5/02-cli-redesign.md)
def test_iphone_audit_help_exits_zero(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "iphone_audit.py"), "--help"],
        capture_output=True,
        text=True,
        env=_hermetic_env(tmp_path),
        cwd=str(REPO_ROOT),
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
