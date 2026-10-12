"""Phase 1 CLI reliability tests (docs/v4/phase-1-cli-reliability.md, task 5).

Covers the four no-device/offline guarantees that must hold before any other
v4 work lands:

* ``inspect --backup-dir`` works entirely offline and still writes a complete,
  manifest-backed run.
* A missing toolchain is reported as a BLOCKER instead of crashing, and the run
  is still persisted for later triage.
* ``config`` writes and validates a v4-schema config file.
* The no-subcommand welcome path exits 0 and stays non-interactive.

These are subprocess tests on purpose: they exercise the real entry point
(``python -m iphone_forensics.cli_v4``), argument parsing, exit codes, and the
files actually written to disk.  Nothing here touches a connected iPhone.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from iphone_forensics import __version__
from iphone_forensics.cli_v4 import EXIT_CONFIG, EXIT_FINDINGS, EXIT_OK

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

# Deterministic, tool-free PATH.  Offline tests must never invoke libimobiledevice,
# pymobiledevice3, or mvt-ios, and must not depend on what happens to be installed
# on the host running the suite.
OFFLINE_PATH = "/usr/bin:/bin"

# Generous: a cold interpreter start plus a handful of file copies.
CLI_TIMEOUT_SECONDS = 120


def _run_cli(
    *argv: str, cwd: Path | None = None, home: Path | None = None, path: str = OFFLINE_PATH
) -> subprocess.CompletedProcess:
    """Run the CLI in a subprocess with a hermetic environment.

    Targets `iphone_forensics.cli` — the single documented binary. This used to
    invoke `cli_v4` directly, back when that was a second console script; it now
    forwards to `cli.main`, so testing the real entry point is both simpler and
    more honest about what users actually run.

    ``stdin`` is closed so that an accidental ``input()`` surfaces as EOFError
    instead of hanging the suite — Phase 1 requires the welcome/config paths to be
    non-interactive safe.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR)
    env["PATH"] = path
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-m", "iphone_forensics.cli", *argv],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd or REPO_ROOT),
        stdin=subprocess.DEVNULL,
        timeout=CLI_TIMEOUT_SECONDS,
    )


def _home_sandbox(tmp_path: Path) -> Path:
    """Redirect ``Path.home()`` so the default ``~/Desktop/iphone-forensics``
    output root can never pollute the developer's real home directory."""
    home = tmp_path / "fake-home"
    home.mkdir(parents=True, exist_ok=True)
    return home


def _only_run_dir(output_root: Path) -> Path:
    runs = sorted(p for p in output_root.glob("iphone-forensics-*") if p.is_dir())
    assert len(runs) == 1, f"expected exactly one run directory, got {runs}"
    return runs[0]


def _make_backup_dir(tmp_path: Path, count: int = 2) -> Path:
    """A stand-in for an authorized backup / panic-dump directory."""
    backup = tmp_path / "backup-source"
    backup.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (backup / f"panic-full-{index}.ips").write_text(
            json.dumps(
                {"bug_type": "210", "procName": "kernel", "timestamp": "2026-01-01T10:00:00Z"}
            ),
            encoding="utf-8",
        )
    return backup


# ------------------------------------------------- inspect --backup-dir (offline)


def test_inspect_backup_dir_offline(tmp_path: Path):
    """Offline inspection of a supplied directory: exit 0/1 plus full evidence output."""
    home = _home_sandbox(tmp_path)
    backup = _make_backup_dir(tmp_path, count=2)
    output = tmp_path / "runs"

    result = _run_cli(
        "inspect",
        "--backup-dir",
        str(backup),
        "--output",
        str(output),
        "--no-fail-on-findings",
        home=home,
    )

    # Phase 1 task 4 documents --no-fail-on-findings as forcing EXIT_OK; the spec for
    # this test only requires a non-error exit, so both documented codes are accepted.
    assert result.returncode in (EXIT_OK, EXIT_FINDINGS), (
        f"unexpected exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "Traceback (most recent call last)" not in result.stderr, result.stderr

    run_dir = _only_run_dir(output)
    report_path = run_dir / "report.json"
    assert report_path.exists(), (
        f"report.json missing; run contains {sorted(p.name for p in run_dir.iterdir())}"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["schema_version"] == "5.0.0"
    assert report["version"] == __version__
    assert report["finished_at"], "finished_at must be set by finalize()"

    triage = report["crash_triage"]
    assert triage["files_scanned"] >= 2, (
        f"both supplied .ips artifacts must be scanned, got {triage['files_scanned']}"
    )

    assert (run_dir / "manifest.json").exists(), "manifest.json is the chain-of-custody record"

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "5.0.0"
    hashed = {entry["path"] for entry in manifest["artifacts"]}
    assert any(path.startswith("evidence/offline-evidence/") for path in hashed), (
        f"supplied artifacts must be copied into evidence, manifest holds {sorted(hashed)}"
    )


# ------------------------------------------- no toolkit / no device (offline)


def test_inspect_no_toolkit_no_device(tmp_path: Path):
    """Without any supported toolkit the run must BLOCKER, persist, and fail loudly."""
    home = _home_sandbox(tmp_path)
    output = tmp_path / "runs"

    result = _run_cli("inspect", "--output", str(output), home=home)

    assert result.returncode != EXIT_OK, (
        f"a BLOCKER run must not exit 0 (got {result.returncode})\n{result.stdout}"
    )
    assert result.returncode != EXIT_CONFIG, (
        "no-toolkit is a runtime condition, not a configuration error"
    )

    run_dir = _only_run_dir(output)
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))

    blockers = [f for f in report["findings"] if f["severity"] == "BLOCKER"]
    assert blockers, f"expected a BLOCKER finding, got {report['findings']}"
    titles = " | ".join(f["title"].lower() for f in blockers)
    assert "toolkit" in titles or "device" in titles, (
        f"BLOCKER must name the missing toolkit or missing device, got {titles}"
    )

    assert (run_dir / "manifest.json").exists(), "report must still be written and hashed"


# ------------------------------------------------------------------- config


def test_config_auto_load_or_template(tmp_path: Path):
    """`config --out` writes a valid v4 template; `config --check` accepts it."""
    home = _home_sandbox(tmp_path)
    config_path = tmp_path / "c.json"

    written = _run_cli("config", "--out", str(config_path), home=home)
    assert written.returncode == EXIT_OK, written.stderr
    assert config_path.exists()

    checked = _run_cli("config", "--check", str(config_path), home=home)
    assert checked.returncode == EXIT_OK, checked.stderr

    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["schema_version"] == "4.0.0"
    assert config.get("output_root")


def test_config_cwd_autoload_honors_output_root(tmp_path: Path):
    """`./iphone-surgery.json` redirects `output_root` (Phase 1 task 2).

    The config filename is retained from when this was the engine's own CLI; the
    binary is now `iphone-forensics`, but renaming the file would silently ignore
    every existing user's configuration.
    """
    home = _home_sandbox(tmp_path)
    cwd = tmp_path / "project"
    cwd.mkdir()
    backup = _make_backup_dir(tmp_path, count=1)
    configured_root = tmp_path / "configured-output"

    (cwd / "iphone-surgery.json").write_text(
        json.dumps(
            {
                "schema_version": "4.0.0",
                "output_root": str(configured_root),
                "safe_name_max_length": 100,
                "subprocess_timeout_seconds_default": 45,
                "syslog_max_seconds": 120,
                "offline_evidence_max_file_mb": 64,
                "offline_evidence_max_files": 2000,
                "redact_identifiers_in_console": True,
            }
        ),
        encoding="utf-8",
    )

    # No --output: the config file (or the documented default) decides the location.
    result = _run_cli("inspect", "--backup-dir", str(backup), cwd=cwd, home=home)

    assert result.returncode in (EXIT_OK, EXIT_FINDINGS), result.stderr
    runs = (
        [p for p in configured_root.glob("iphone-forensics-*") if p.is_dir()]
        if configured_root.exists()
        else []
    )
    # No fallback skip: `--config` and CWD auto-load both exist (cli_v4.load_config),
    # so a missing run directory is a real failure and must fail the test. The old
    # skip here claimed the feature was unimplemented, so the test could never fail.
    assert runs, (
        f"config output_root was ignored; run landed in "
        f"{sorted(p.name for p in cwd.iterdir())}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    run_dir = runs[0]
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "5.0.0"
    assert (run_dir / "manifest.json").exists()


# ------------------------------------------------------------------ welcome


def test_welcome_no_args(tmp_path: Path):
    """No subcommand => friendly welcome/doctor screen, exit 0, no input() required."""
    home = _home_sandbox(tmp_path)

    result = _run_cli(home=home)

    assert result.returncode == EXIT_OK, (
        f"welcome must exit 0, got {result.returncode}\n{result.stderr}"
    )
    assert "Traceback (most recent call last)" not in result.stderr, result.stderr

    assert __version__ in result.stdout, f"version missing from welcome screen:\n{result.stdout}"
    # The unified CLI's own name. `iphone-surgery` was merged into it and must
    # not be advertised as a separate tool.
    assert "iphone-forensics" in result.stdout
    assert "iphone-surgery" not in result.stdout, (
        f"welcome screen still advertises the retired name:\n{result.stdout}"
    )
    assert any(
        marker in result.stdout
        for marker in (
            "Operational mode",
            "Device discovery",
            "doctor",
            "inspect --backup-dir",
        )
    ), f"welcome must state toolchain/device state or a next action:\n{result.stdout}"
