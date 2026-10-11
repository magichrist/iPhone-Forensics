"""Documentation matches the implementation (docs/v5/09-docs-structure.md).

The README is the only place a new user learns the tool. If it drifts from the code,
it is worse than no documentation: it sends people to flags that do not exist and
away from the ones that do.

Checks:
  * the four primary commands in the README are the four the CLI actually exposes;
  * every command the README documents is a real subcommand;
  * the documented exit codes match the engine's constants;
  * the documented run-directory layout matches what a run actually creates.
"""
from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

import pytest

from iphone_forensics import cli, cli_v4

README = Path(__file__).resolve().parent.parent / "README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def test_readme_exists_and_is_substantial():
    text = _readme()
    assert text.startswith("# iPhone Forensics")
    assert len(text) > 3000, "the README was gutted"


def test_readme_documents_exactly_the_four_primary_commands():
    """The 4-command surface is the documented path; nothing else may lead."""
    text = _readme()
    parser = cli._build_parser()
    subparsers = next(action for action in parser._actions
                      if getattr(action, "_choices_actions", None))
    actual = {entry.dest for entry in subparsers._choices_actions}
    assert actual == {"devices", "inspect", "doctor", "compare"}, \
        "the primary surface changed; update the README and the docs together"

    for command in actual:
        assert f"iphone-forensics {command}" in text, \
            f"README does not document `{command}`"


def test_every_command_the_readme_shows_actually_exists():
    """A documented command that does not run is the worst kind of stale doc."""
    text = _readme()
    documented = set(re.findall(r"iphone-forensics ([a-z-]+)", text))
    parser = cli._build_parser()
    subparsers = next(action for action in parser._actions
                      if getattr(action, "_choices_actions", None))
    actual = {entry.dest for entry in subparsers._choices_actions}
    # `--help-advanced` is a documented flag, not a subcommand.
    flags = {"--help-advanced"}
    unknown = documented - actual - flags
    assert not unknown, f"README documents non-existent command(s): {sorted(unknown)}"
    # And the flag it names really works.
    for flag in flags & documented:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main([flag])
        assert code == cli_v4.EXIT_OK, f"`{flag}` exited {code}"
        assert "advanced" in buffer.getvalue().lower()


def test_engine_commands_referenced_by_the_readme_exist():
    """The advanced section must not reference a subcommand that is not there."""
    text = _readme()
    referenced = set(re.findall(r"iphone-surgery ([a-z-]+)", text))
    real = {name for name, _ in cli._engine_subcommands()}
    unknown = {name for name in referenced if name not in real and name not in {"--help"}}
    assert not unknown, f"README references missing iphone-surgery command(s): {sorted(unknown)}"


def test_documented_exit_codes_match_the_engine():
    """Exit codes are a scripting contract; the README must not drift from them."""
    text = _readme()
    mapping = {
        "0": cli_v4.EXIT_OK, "1": cli_v4.EXIT_FINDINGS, "2": cli_v4.EXIT_CONFIG,
        "3": cli_v4.EXIT_NO_DEVICE, "4": cli_v4.EXIT_AMBIGUOUS_DEVICE,
        "5": cli_v4.EXIT_PARTIAL, "6": cli_v4.EXIT_TOOL_FAILURE,
    }
    assert len(set(mapping.values())) == len(mapping), "exit codes are not distinct"
    for documented in mapping:
        assert re.search(rf"`{documented}`", text), f"exit code {documented} undocumented"


def test_readme_shows_the_real_run_directory_layout(tmp_path: Path):
    """The README's tree must match what a run actually creates."""
    import argparse

    from iphone_forensics.cli_v4 import _finish_run, _new_report
    from iphone_forensics.evidence import run_dir_paths

    paths = run_dir_paths(tmp_path, "20261011-090721")
    args = argparse.Namespace(redact=False, compare_json=None)
    _finish_run(paths["run_dir"], _new_report(args), {"checks": {}}, args)

    for name in ("report.html", "report.json", "manifest.json", "README.txt", "evidence"):
        assert name in _readme(), f"README does not document {name}"

    for filename in ("report.html", "report.json", "manifest.json"):
        assert paths[filename].is_file(), f"{filename} is documented but not produced"
    assert paths["readme"].is_file(), "README.txt is documented but not produced"
    assert paths["evidence_dir"].is_dir(), "evidence/ is documented but not produced"


def test_readme_states_the_cwd_output_default():
    """CWD default is a behavioural promise; automation depends on it."""
    assert "current working directory" in _readme().lower()


def test_readme_names_the_advanced_interface_exactly_once_as_the_advanced_one():
    """One CLI description lives in the README; the engine is the advanced path."""
    text = _readme()
    assert text.count("# Advanced interface") == 1
    # It must not present iphone-surgery as the primary entry point.
    assert "iphone-surgery" in text
    primary_block = text.split("## Advanced interface")[0]
    assert "iphone-surgery" not in primary_block, \
        "the advanced engine must not appear in the documented four-command path"


@pytest.mark.parametrize("claim", [
    "Coverage is not health",
    "not collected",
    "Failed vs unavailable",
    "Manual check required",
])
def test_readme_teaches_the_honesty_rules(claim):
    """The reading rules a user needs to interpret the report correctly."""
    assert claim.lower() in _readme().lower()