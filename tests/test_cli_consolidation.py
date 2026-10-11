"""Tests for the unified CLI: one binary, one name, one prompt.

The project shipped two console scripts (`iphone-forensics` and
`iphone-surgery`) for one tool, and their surfaces had already drifted: flags
worked under one name and not the other. These tests pin the merged surface.
"""
from __future__ import annotations

import argparse
import builtins
import io
import sys
from pathlib import Path

import pytest

from iphone_forensics import cli, cli_v4

REPO_ROOT = Path(__file__).resolve().parents[1]


def _subcommands(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and choices:
            return set(choices)
    return set()


# ------------------------------------------------------------- one CLI surface

def test_only_one_console_script_is_installed():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = text.split("[project.scripts]", 1)[1].split("[", 1)[0]
    scripts = [line.split("=", 1)[0].strip() for line in block.splitlines()
               if "=" in line and not line.strip().startswith("#")]
    assert scripts == ["iphone-forensics"], scripts


def test_unified_cli_exposes_every_engine_command():
    """Nothing the engine offered may be lost by the merge."""
    engine = _subcommands(cli_v4.build_parser())
    unified = _subcommands(cli._build_parser())
    assert engine <= unified, f"lost in the merge: {sorted(engine - unified)}"


def test_facade_commands_are_still_present():
    assert {"devices", "inspect", "doctor", "compare"} <= _subcommands(cli._build_parser())


def test_inspect_keeps_engine_flags_the_facade_never_declared():
    """The facade must not shadow the engine's parser and lose flags.

    `inspect --backup-dir` and `--no-fail-on-findings` used to work only under
    `iphone-surgery`; re-declaring `inspect` in the facade silently dropped them.
    """
    unified = cli._build_parser()
    inspect = next(a.choices for a in unified._actions
                   if isinstance(getattr(a, "choices", None), dict) and a.choices)["inspect"]
    options = {opt for action in inspect._actions for opt in action.option_strings}
    for flag in ("--backup-dir", "--no-fail-on-findings", "--fail-on-findings",
                 "--config", "--quiet", "--verbose"):
        assert flag in options, f"inspect lost {flag}"


def test_inspect_still_offers_the_facade_flags():
    inspect = next(a.choices for a in cli._build_parser()._actions
                   if isinstance(getattr(a, "choices", None), dict) and a.choices)["inspect"]
    options = {opt for action in inspect._actions for opt in action.option_strings}
    for flag in ("--yes-sensitive", "--no-sensitive", "--redact-identifiers",
                 "--init-buyer-checklist"):
        assert flag in options, f"inspect lost {flag}"


def test_legacy_entry_point_forwards_and_warns(capsys):
    """`cli_v4.main` must not become a second, divergent CLI."""
    calls: list[list[str]] = []
    original = cli.main
    cli.main = lambda argv: calls.append(list(argv)) or 0
    try:
        assert cli_v4.main(["tools"]) == 0
    finally:
        cli.main = original
    assert calls == [["tools"]], "the legacy entry point must forward its argv"
    assert "deprecated" in capsys.readouterr().err.lower()


def test_compare_accepts_both_positional_and_flag_form():
    """Scripts using the old `--previous` form must keep working."""
    parser = cli._build_parser()
    positional = parser.parse_args(["compare", "a.json", "--current", "b.json"])
    assert positional.previous_report == "a.json"
    # Regression: the positional's nargs="?" default was applied after the option,
    # overwriting it, so `--previous` parsed to None.
    flagged = parser.parse_args(["compare", "--previous", "a.json", "--current", "b.json"])
    assert flagged.previous_flag == "a.json"


def test_bare_invocation_shows_the_welcome_screen(monkeypatch, capsys):
    """No command and no legacy flag must not start an inspection.

    Regression: the config layer writes `output` onto the namespace, and the
    dispatch read the namespace *after* applying config to decide whether legacy
    flags were passed. A bare `iphone-forensics` therefore looked like a legacy
    invocation and ran a full inspection against no device.
    """
    monkeypatch.setattr(cli, "cmd_inspect",
                        lambda args: (_ for _ in ()).throw(
                            AssertionError("bare invocation must not inspect")))
    monkeypatch.setattr(cli, "_run_inspect_command",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("bare invocation must not inspect")))
    assert cli.main([]) == 0
    assert "iphone-forensics" in capsys.readouterr().out


def test_config_defaults_do_not_count_as_legacy_flags(monkeypatch):
    """The 'were legacy flags passed?' decision must precede config loading."""
    seen: list[bool] = []
    monkeypatch.setattr(cli, "_apply_effective_config",
                        lambda args: seen.append(
                            any(cli._given(args, d) is not None for d in cli.COMPAT_DESTS)) or None)
    monkeypatch.setattr(cli, "_welcome", lambda: 0)
    cli.main([])
    assert seen == [False], "config-supplied defaults were mistaken for user flags"


def test_both_compare_forms_reach_the_engine(tmp_path, monkeypatch):
    """End-to-end through dispatch, not just parsing."""
    previous = tmp_path / "a.json"
    current = tmp_path / "b.json"
    for path in (previous, current):
        path.write_text('{"device": {"ProductType": "iPhone15,4"}}', encoding="utf-8")

    seen: list[tuple] = []
    monkeypatch.setattr(cli, "cmd_compare",
                        lambda ns: seen.append((ns.previous, ns.current)) or 0)
    assert cli.main(["compare", str(previous), "--current", str(current)]) == 0
    assert cli.main(["compare", "--previous", str(previous),
                     "--current", str(current)]) == 0
    assert len(seen) == 2, "one of the two compare forms did not dispatch"
    for got_previous, got_current in seen:
        assert got_previous == str(previous)
        assert got_current == str(current)


def test_offline_paths_do_not_require_a_device():
    """`--backup-dir` must reach the engine, not be dropped by the facade."""
    parser = cli._build_parser()
    namespace = parser.parse_args(["inspect", "--backup-dir", "/tmp/backup"])
    engine = cli._engine_args(namespace, output=".", device=None, sensitive=False)
    assert engine.backup_dir == "/tmp/backup", "--backup-dir was silently discarded"


def test_backup_dir_and_mvt_backup_are_mutually_exclusive(capsys):
    namespace = cli._build_parser().parse_args(
        ["inspect", "--backup-dir", "/tmp/a", "--mvt-backup", "/tmp/b"])
    result = cli._engine_args(namespace, output=".", device=None, sensitive=False)
    assert result.backup_dir is None
    assert "both select the offline path" in capsys.readouterr().err


# ------------------------------------------------------------- consent plumbing

def test_consent_flag_works_before_or_after_the_subcommand():
    """`--yes-sensitive inspect` used to be silently ignored."""
    parser = cli._build_parser()
    before = parser.parse_args(["--yes-sensitive", "inspect"])
    after = parser.parse_args(["inspect", "--yes-sensitive"])
    assert before.yes_sensitive is True
    assert after.yes_sensitive is True
    assert parser.parse_args(["--no-sensitive", "inspect"]).no_sensitive is True


# --------------------------------------------------------------- single prompt

@pytest.fixture
def interactive(monkeypatch):
    """A TTY session that records how many times input() was called."""

    def run(reply: str, devices: list[str] | None = None):
        calls: list[str] = []
        stdin = io.StringIO()
        stdin.isatty = lambda: True  # type: ignore[method-assign]
        monkeypatch.setattr(sys, "stdin", stdin)
        monkeypatch.setattr(builtins, "input", lambda prompt="": (calls.append(prompt), reply)[1])
        monkeypatch.setattr(cli, "_probe_devices", lambda: devices or ["UDID-A", "UDID-B"])

        captured: dict[str, object] = {}
        monkeypatch.setattr(cli, "cmd_inspect",
                            lambda args: captured.update(vars(args)) or 0)
        code = cli.main(["inspect"])
        return code, len(calls), captured

    return run


def test_device_selection_and_consent_are_a_single_prompt(interactive):
    """Two blocking prompts in a row interrupted the operator twice."""
    _, prompts, captured = interactive("2 y")
    assert prompts == 1, "expected exactly one interactive prompt"
    assert captured["device"] == "UDID-B"
    assert captured["sensitive_consent"] is True


def test_bare_enter_defaults_to_first_device_and_declines(interactive):
    _, prompts, captured = interactive("")
    assert prompts == 1
    assert captured["device"] == "UDID-A"
    assert captured["sensitive_consent"] is False


def test_answering_only_consent_still_defaults_the_device(interactive):
    _, prompts, captured = interactive("y")
    assert prompts == 1
    assert captured["device"] == "UDID-A"
    assert captured["sensitive_consent"] is True


def test_answering_only_a_device_declines_consent(interactive):
    _, prompts, captured = interactive("2")
    assert prompts == 1
    assert captured["device"] == "UDID-B"
    assert captured["sensitive_consent"] is False


def test_sensitive_scope_is_printed_exactly_once(interactive, capsys):
    interactive("2 y")
    assert capsys.readouterr().out.count("Standard profile is read-only") == 1


def test_offline_inspect_never_prompts(monkeypatch, capsys):
    """An offline run touches no device and must not prompt at all."""
    def explode(prompt=""):
        raise AssertionError("the offline path must not prompt")

    monkeypatch.setattr(builtins, "input", explode)
    monkeypatch.setattr(cli, "_probe_devices",
                        lambda: (_ for _ in ()).throw(AssertionError("must not probe")))
    monkeypatch.setattr(cli, "cmd_inspect", lambda args: 0)
    assert cli.main(["inspect", "--backup-dir", "/tmp/backup"]) == 0