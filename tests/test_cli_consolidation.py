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
    scripts = [
        line.split("=", 1)[0].strip()
        for line in block.splitlines()
        if "=" in line and not line.strip().startswith("#")
    ]
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
    inspect = next(
        a.choices
        for a in unified._actions
        if isinstance(getattr(a, "choices", None), dict) and a.choices
    )["inspect"]
    options = {opt for action in inspect._actions for opt in action.option_strings}
    for flag in (
        "--backup-dir",
        "--no-fail-on-findings",
        "--fail-on-findings",
        "--config",
        "--quiet",
        "--verbose",
    ):
        assert flag in options, f"inspect lost {flag}"


def test_inspect_still_offers_the_facade_flags():
    inspect = next(
        a.choices
        for a in cli._build_parser()._actions
        if isinstance(getattr(a, "choices", None), dict) and a.choices
    )["inspect"]
    options = {opt for action in inspect._actions for opt in action.option_strings}
    for flag in (
        "--yes-sensitive",
        "--no-sensitive",
        "--redact-identifiers",
        "--init-buyer-checklist",
    ):
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
    monkeypatch.setattr(
        cli,
        "cmd_inspect",
        lambda args: (_ for _ in ()).throw(AssertionError("bare invocation must not inspect")),
    )
    monkeypatch.setattr(
        cli,
        "_run_inspect_command",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("bare invocation must not inspect")),
    )
    assert cli.main([]) == 0
    assert "iphone-forensics" in capsys.readouterr().out


def test_config_defaults_do_not_count_as_legacy_flags(monkeypatch):
    """The 'were legacy flags passed?' decision must precede config loading."""
    seen: list[bool] = []
    monkeypatch.setattr(
        cli,
        "_apply_effective_config",
        lambda args: (
            seen.append(any(cli._given(args, d) is not None for d in cli.COMPAT_DESTS)) or None
        ),
    )
    monkeypatch.setattr(cli, "_welcome", lambda: 0)
    cli.main([])
    assert seen == [False], "config-supplied defaults were mistaken for user flags"


# ------------------------------------------------------- --device validation


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", False),
        ("0", False),
        ("9", False),
        ("abc", False),
        ("banana", False),
        ("/tmp/x", False),
        ("", False),
        ("00008030-001234567890ABCD", True),  # what idevice_id reports
        ("00008030001234567890ABCD", True),
        ("udid-00008030001234567890ABCD", True),
        ("F96E1B0F-1A2B3C4D5E6F7081", True),
    ],
)
def test_udid_shape_detection(value: str, expected: bool):
    assert cli._looks_like_udid(value) is expected, value


def test_real_udid_formats_are_accepted(monkeypatch):
    """A first draft only allowed 40 hex digits and rejected the common
    24-digit form, turning every genuine UDID into a usage error."""
    cli._probe_devices = lambda: ["00008030-001234567890ABCD"]
    namespace = cli._build_parser().parse_args(["inspect", "--device", "00008030-001234567890ABCD"])
    assert cli._resolve_device_argument(namespace) is None


def test_device_number_resolves_to_the_attached_device(monkeypatch):
    """`--device 1` must not be passed to the collectors as a literal UDID."""
    monkeypatch.setattr(cli, "_probe_devices", lambda: ["00008030-001234567890ABCD"])
    namespace = cli._build_parser().parse_args(["inspect", "--device", "1"])
    assert cli._resolve_device_argument(namespace) is None
    assert namespace.device == "00008030-001234567890ABCD"


def test_out_of_range_device_number_is_rejected(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_probe_devices", lambda: ["00008030-001234567890ABCD"])
    namespace = cli._build_parser().parse_args(["inspect", "--device", "9"])
    assert cli._resolve_device_argument(namespace) == cli_v4.EXIT_CONFIG
    err = capsys.readouterr().err
    assert "not a device number in range" in err
    assert "00008030" not in err, "the raw UDID must be redacted even in an error"


def test_non_udid_device_value_is_rejected(monkeypatch, capsys):
    cli._probe_devices = lambda: ["00008030-001234567890ABCD"]
    namespace = cli._build_parser().parse_args(["inspect", "--device", "banana"])
    assert cli._resolve_device_argument(namespace) == cli_v4.EXIT_CONFIG
    assert "not a UDID" in capsys.readouterr().err


def test_bad_device_never_starts_a_run(monkeypatch):
    """A bad --device must cost nothing and write no report."""
    monkeypatch.setattr(cli, "_probe_devices", lambda: ["00008030-001234567890ABCD"])
    monkeypatch.setattr(
        cli,
        "cmd_inspect",
        lambda args: (_ for _ in ()).throw(AssertionError("a rejected --device must not inspect")),
    )
    assert cli.main(["inspect", "--device", "banana"]) == cli_v4.EXIT_CONFIG


# ------------------------------------------------------------- consent plumbing


def test_consent_flag_works_before_or_after_the_subcommand():
    """`--yes-sensitive inspect` used to be silently ignored."""
    parser = cli._build_parser()
    before = parser.parse_args(["--yes-sensitive", "inspect"])
    after = parser.parse_args(["inspect", "--yes-sensitive"])
    assert before.yes_sensitive is True
    assert after.yes_sensitive is True
    assert parser.parse_args(["--no-sensitive", "inspect"]).no_sensitive is True


def test_offline_inspect_never_prompts(monkeypatch, capsys):
    """An offline run touches no device and must not prompt at all."""

    def explode(prompt=""):
        raise AssertionError("the offline path must not prompt")

    monkeypatch.setattr(builtins, "input", explode)
    monkeypatch.setattr(
        cli, "_probe_devices", lambda: (_ for _ in ()).throw(AssertionError("must not probe"))
    )
    monkeypatch.setattr(cli, "cmd_inspect", lambda args: 0)
    assert cli.main(["inspect", "--backup-dir", "/tmp/backup"]) == 0


def test_both_compare_forms_reach_the_engine(tmp_path, monkeypatch):
    """End-to-end through dispatch, not just parsing."""
    previous = tmp_path / "a.json"
    current = tmp_path / "b.json"
    for path in (previous, current):
        path.write_text('{"device": {"ProductType": "iPhone15,4"}}', encoding="utf-8")

    seen: list[tuple] = []
    monkeypatch.setattr(cli, "cmd_compare", lambda ns: seen.append((ns.previous, ns.current)) or 0)
    assert cli.main(["compare", str(previous), "--current", str(current)]) == 0
    assert cli.main(["compare", "--previous", str(previous), "--current", str(current)]) == 0
    assert len(seen) == 2, "one of the two compare forms did not dispatch"
    for got_previous, got_current in seen:
        assert got_previous == str(previous)
        assert got_current == str(current)


# ------------------------------------------- interactive selection widgets


def _fake_tty(keys):
    """A stdin stand-in that yields *keys* and reports itself as a terminal."""
    stream = io.StringIO("".join(keys))
    stream.isatty = lambda: True  # type: ignore[method-assign]
    return stream


@pytest.fixture
def no_raw_mode(monkeypatch):
    """Skip the real termios switch: these tests drive a fake stream."""
    import contextlib

    from iphone_forensics import interactive

    monkeypatch.setattr(interactive, "_raw_mode", lambda stream: contextlib.nullcontext())


SCOPE = (
    ("Installed-app inventory", "--app-list"),
    ("Running-process inventory", "--pmd-processes"),
    ("Live system-log capture", "--syslog-seconds"),
)


def test_device_selector_moves_and_selects(no_raw_mode, monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty([interactive.KEY_DOWN, "\r"]))
    assert interactive.choose_device(["UDID-AAAA", "UDID-BBBB", "UDID-CCCC"]) == "UDID-BBBB"


def test_device_selector_wraps_around(no_raw_mode, monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty([interactive.KEY_UP, "\r"]))
    assert interactive.choose_device(["UDID-AAAA", "UDID-BBBB"]) == "UDID-BBBB"


def test_device_selector_quit_returns_none(no_raw_mode, monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty(["q"]))
    assert interactive.choose_device(["UDID-AAAA"]) is None


def test_device_selector_is_non_interactive_safe(monkeypatch, capsys):
    """No TTY must never block; it falls back to the first device."""
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert interactive.choose_device(["UDID-AAAA", "UDID-BBBB"]) == "UDID-AAAA"
    assert "UDID-AAAA" in capsys.readouterr().out


def test_sensitive_selector_space_toggles_and_enter_confirms(no_raw_mode, monkeypatch, capsys):
    """Space ticks one box, Enter confirms — not an all-or-nothing prompt."""
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty([" ", "\r"]))
    assert interactive.choose_sensitive(SCOPE) == {"Installed-app inventory"}
    assert "Sensitive collection enabled for:" in capsys.readouterr().out


def test_sensitive_selector_can_select_several(no_raw_mode, monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty([" ", interactive.KEY_DOWN, " ", "\r"]))
    assert interactive.choose_sensitive(SCOPE) == {
        "Installed-app inventory",
        "Running-process inventory",
    }


def test_sensitive_selector_starts_empty(no_raw_mode, monkeypatch, capsys):
    """Sensitive collection stays off unless deliberately chosen."""
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty(["\r"]))
    assert interactive.choose_sensitive(SCOPE) == set()
    assert "off for this run" in capsys.readouterr().out


def test_sensitive_selector_select_all_and_clear(no_raw_mode, monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty(["a", "\r"]))
    assert interactive.choose_sensitive(SCOPE) == {label for label, _ in SCOPE}
    monkeypatch.setattr(sys, "stdin", _fake_tty(["a", "n", "\r"]))
    assert interactive.choose_sensitive(SCOPE) == set()


def test_sensitive_selector_quit_enables_nothing(no_raw_mode, monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty(["a", "q"]))
    assert interactive.choose_sensitive(SCOPE) == set()


def test_sensitive_selector_is_non_interactive_safe(monkeypatch):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert interactive.choose_sensitive(SCOPE) == set()


def test_selector_shows_the_flags_for_each_item(no_raw_mode, monkeypatch, capsys):
    from iphone_forensics import interactive

    monkeypatch.setattr(sys, "stdin", _fake_tty(["\r"]))
    interactive.choose_sensitive(SCOPE)
    assert "--app-list" in capsys.readouterr().out


def test_partial_selection_enables_only_what_was_ticked():
    """Ticking the app list must not silently enable logs and backup."""
    from iphone_forensics import cli

    namespace = cli._build_parser().parse_args(["inspect"])
    engine = cli._engine_args(
        namespace,
        output=".",
        device="UDID",
        sensitive=True,
        explicit=cli._selected_dests({"Installed-app inventory"}),
    )
    assert engine.app_list is True
    assert engine.pmd_processes is False
    assert engine.crash_reports is False
    assert engine.provisioning is False


def test_scope_entries_all_declare_their_dests():
    """The menu and the flags must not drift apart."""
    from iphone_forensics import cli

    for _label, _flags, dests in cli.SENSITIVE_SCOPE:
        assert dests, "every scope entry must declare the dests it enables"
        for dest in dests:
            assert dest in cli.SENSITIVE_DESTS, f"{dest} is not a sensitive dest"


def test_needs_value_items_are_named_when_selected(monkeypatch, capsys):
    """Consent must not invent a capture window or a backup destination."""
    from iphone_forensics import cli, interactive

    monkeypatch.setattr(interactive, "choose_sensitive", lambda scope: {"Live system-log capture"})
    cli._resolve_sensitive(cli._build_parser().parse_args(["inspect"]))
    out = capsys.readouterr().out
    assert "still needs its argument" in out
    assert "--syslog-seconds" in out


def test_full_udid_is_printed_by_devices_command(monkeypatch, capsys):
    """The operator needs the whole id to target a device on the next command."""
    from iphone_forensics import cli_v4 as engine

    udid = "00008110-000609881432401E"
    monkeypatch.setattr(engine, "discover_devices", lambda raw, coll: [udid])
    assert engine.cmd_devices(argparse.Namespace(output=".")) == 0
    assert udid in capsys.readouterr().out, "the full UDID must be printed"
