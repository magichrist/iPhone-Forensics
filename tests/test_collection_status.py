"""Spec tests for the v5 collection-status emission layer (util + collectors).

Covers docs/v5/05-evidence-analysis-model.md:
  * every emitted status is one of the 11 COLLECTION_STATUSES values
  * missing binary -> tool_missing, timeout -> collection_error (timed_out kept),
    bounded-log expected stream end -> collected (non-failure), rc0 -> collected,
    nonzero -> collection_error
  * skip=True records skipped_by_user and never spawns a subprocess
  * pairing denial markers -> permission_denied (conservative: errored runs only)
  * discovery with no tool installed records a tool_missing entry
  * legacy reader aliases exported from util agree with models.normalize_status
  * nothing in the status layer raises on odd input
"""

import sys
from pathlib import Path

import pytest

from iphone_forensics.collectors import (
    PAIRING_DENIAL_MARKERS,
    discover_devices,
    save_result,
)
from iphone_forensics.models import (
    COLLECTION_STATUSES,
    HEALTH_STATUSES,
    STATUS_TO_HEALTH,
    normalize_status,
)
from iphone_forensics.util import (
    STATUS_ALIASES_FOR_READERS,
    capture_stream,
    run_command,
    write_command_result,
)

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX subprocess semantics")


# ------------------------------------------------------------- returncode 0 -> collected


# `save_result` refuses any command that is not provably read-only, so a test that
# drives it with a host binary (`python -c ...`) must declare that it is not issuing
# a device command. `HOST` is that declaration. Real collectors never pass it, and
# tests/test_readonly_guard.py pins that the guard cannot be bypassed silently.
HOST = {"enforce_read_only_check": False}


def test_success_exit_maps_to_collected(tmp_path: Path):
    collection: list[dict] = []
    save_result(tmp_path, collection, "echo-ok", [sys.executable, "-c", "print('ok')"], 15, **HOST)
    entry = collection[0]
    assert entry["status"] == "collected"
    assert entry["status_detail"] == "exit code 0"
    assert entry["returncode"] == 0
    assert (tmp_path / entry["stdout_file"]).exists()
    assert (tmp_path / entry["stderr_file"]).exists()


# ----------------------------------------------------------- nonzero exit -> collection_error


def test_nonzero_exit_maps_to_collection_error(tmp_path: Path):
    collection: list[dict] = []
    save_result(
        tmp_path,
        collection,
        "always-fails",
        [sys.executable, "-c", "raise SystemExit(3)"],
        15,
        **HOST,
    )
    entry = collection[0]
    assert entry["status"] == "collection_error"
    assert entry["returncode"] == 3
    assert "exit code 3" in entry["status_detail"]
    assert entry["timed_out"] is False


# -------------------------------------------------------------- missing binary -> tool_missing


def test_missing_binary_maps_to_tool_missing(tmp_path: Path, monkeypatch):
    # Simulate ENOENT for a real allowlisted shape. An invented binary name would be
    # refused by the read-only guard before ENOERT could ever happen, which would
    # make this test assert the wrong thing; the guard has its own suite in
    # tests/test_readonly_guard.py.
    def fake_run(command, timeout=45, **_kw):
        return {
            "command": command,
            "returncode": None,
            "stdout": b"",
            "stderr": b"",
            "duration_seconds": 0.0,
            "timed_out": False,
            "missing_binary": True,
            "os_error_type": "FileNotFoundError",
        }

    monkeypatch.setattr("iphone_forensics.collectors.run_command", fake_run)
    collection: list[dict] = []
    save_result(tmp_path, collection, "bogus-tool", ["idevice_id", "-l"], 5)
    entry = collection[0]
    assert entry["status"] == "tool_missing"
    assert entry["returncode"] is None
    assert entry["timed_out"] is False
    assert entry["status_detail"]


def test_missing_binary_via_write_command_result_directly(tmp_path: Path):
    meta = write_command_result(
        tmp_path, "direct-missing", run_command(["definitely-not-a-real-binary-xyz"], timeout=3)
    )
    assert meta["status"] == "tool_missing"


# --------------------------------------------------------------------- timeout -> collection_error


@POSIX_ONLY
def test_timeout_maps_to_collection_error_and_keeps_timed_out(tmp_path: Path):
    collection: list[dict] = []
    save_result(
        tmp_path,
        collection,
        "slow-command",
        [sys.executable, "-c", "import time; time.sleep(5)"],
        1,
        **HOST,
    )
    entry = collection[0]
    assert entry["status"] == "collection_error"
    assert entry["timed_out"] is True
    assert "timeout" in entry["status_detail"]
    assert entry["duration_seconds"] < 4


# --------------------------------------- bounded-log expected stream end stays collected (non-failure)


@POSIX_ONLY
def test_bounded_stream_end_is_collected_with_note(tmp_path: Path):
    out = tmp_path / "stream.bin"
    result = capture_stream(
        [
            sys.executable,
            "-c",
            "import sys, time; sys.stdout.write('line\\n'); sys.stdout.flush(); time.sleep(30)",
        ],
        1,
        out,
    )
    assert result["timed_out"] is True
    assert result["expected_stream_end"] is True
    meta = write_command_result(tmp_path, "stream", result)
    assert meta["status"] == "collected"
    assert "expected_stream_end" in meta["status_detail"]
    assert meta["timed_out"] is True  # evidence preserved alongside the healthy status


# --------------------------------------------------------------------------- skip flag


def test_skip_records_skipped_by_user_and_never_runs(tmp_path: Path):
    sentinel = tmp_path / "was-executed"
    collection: list[dict] = []
    result = save_result(
        tmp_path,
        collection,
        "declined-op",
        [sys.executable, "-c", f"open({str(sentinel)!r}, 'w').close()"],
        15,
        skip=True,
    )
    assert collection[0]["status"] == "skipped_by_user"
    assert collection[0]["returncode"] is None
    assert not sentinel.exists()  # nothing was spawned
    assert result["returncode"] is None


# ------------------------------------------------- permission_denied (conservative marker match)


def test_denial_marker_on_errored_run_maps_to_permission_denied(tmp_path: Path, monkeypatch):
    def fake_run(command, timeout=45, **_kw):
        return {
            "command": command,
            "returncode": 255,
            "stdout": b"",
            "stderr": b"ERROR: Pairing dialog or PIN was denied by the user",
            "duration_seconds": 0.1,
            "timed_out": False,
        }

    monkeypatch.setattr("iphone_forensics.collectors.run_command", fake_run)
    collection: list[dict] = []
    save_result(
        tmp_path,
        collection,
        "pairing-validation",
        ["idevicepair", "validate"],
        20,
        denial_markers=PAIRING_DENIAL_MARKERS,
    )
    assert collection[0]["status"] == "permission_denied"
    assert collection[0]["status_detail"]


def test_denial_marker_on_healthy_run_stays_collected(tmp_path: Path, monkeypatch):
    """Conservative guard: a successful run that merely mentions 'denied' is not a denial."""

    def fake_run(command, timeout=45, **_kw):
        return {
            "command": command,
            "returncode": 0,
            "stdout": b"SUCCESS: pairing validated (no access denied)",
            "stderr": b"",
            "duration_seconds": 0.1,
            "timed_out": False,
        }

    monkeypatch.setattr("iphone_forensics.collectors.run_command", fake_run)
    collection: list[dict] = []
    save_result(
        tmp_path,
        collection,
        "pairing-validation",
        ["idevicepair", "validate"],
        20,
        denial_markers=PAIRING_DENIAL_MARKERS,
    )
    assert collection[0]["status"] == "collected"


def test_denial_markers_are_lowercase_and_conservative():
    assert set(PAIRING_DENIAL_MARKERS) == {"denied", "refused"}


# ------------------------------------------------------ discovery without any tool records tool_missing


def test_discover_devices_without_tools_records_tool_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("iphone_forensics.collectors.shutil.which", lambda name: None)
    collection: list[dict] = []
    devices = discover_devices(tmp_path, collection)
    assert devices == []
    assert len(collection) == 1
    assert collection[0]["status"] == "tool_missing"
    assert (tmp_path / "connected-devices.txt").exists()


# --------------------------------------------------------------- vocabulary + roll-up guarantees


def test_all_emitted_statuses_are_in_collection_statuses(tmp_path: Path):
    """Round-trip: whatever the layer emits is a valid, idempotent status."""
    collection: list[dict] = []
    save_result(tmp_path, collection, "ok", [sys.executable, "-c", "pass"], 15, **HOST)
    save_result(
        tmp_path, collection, "bad", [sys.executable, "-c", "raise SystemExit(1)"], 15, **HOST
    )
    save_result(tmp_path, collection, "missing", ["definitely-not-a-real-binary-xyz"], 5, **HOST)
    save_result(
        tmp_path, collection, "skipped", [sys.executable, "-c", "pass"], 15, skip=True, **HOST
    )
    statuses = [entry["status"] for entry in collection]
    assert statuses == ["collected", "collection_error", "tool_missing", "skipped_by_user"]
    for status in statuses:
        assert status in COLLECTION_STATUSES
        assert normalize_status(status) == status  # pass-through, no aliasing


def test_status_to_health_rollup_for_emitted_statuses():
    """Summary roll-up: emitted statuses map onto declared health statuses."""
    emitted = (
        "collected",
        "collection_error",
        "tool_missing",
        "permission_denied",
        "skipped_by_user",
    )
    for status in emitted:
        assert status in STATUS_TO_HEALTH, status
        assert STATUS_TO_HEALTH[status] in HEALTH_STATUSES
    assert STATUS_TO_HEALTH["collected"] == "pass"
    for status in ("collection_error", "tool_missing", "permission_denied", "skipped_by_user"):
        assert STATUS_TO_HEALTH[status] == "not_tested", status


def test_status_aliases_for_readers_match_models():
    """util.STATUS_ALIASES_FOR_READERS must stay in lockstep with models.normalize_status."""
    assert STATUS_ALIASES_FOR_READERS == {
        "success": "collected",
        "expected_end": "collected",
        "failed_or_partial": "collection_error",
    }
    for legacy, expected in STATUS_ALIASES_FOR_READERS.items():
        assert normalize_status(legacy) == expected


def test_legacy_strings_are_never_emitted(tmp_path: Path):
    """The v4 strings may be *read* (normalized), never *written*."""
    collection: list[dict] = []
    save_result(tmp_path, collection, "ok", [sys.executable, "-c", "pass"], 15, **HOST)
    save_result(
        tmp_path, collection, "bad", [sys.executable, "-c", "raise SystemExit(2)"], 15, **HOST
    )
    save_result(tmp_path, collection, "missing", ["definitely-not-a-real-binary-xyz"], 5, **HOST)
    save_result(tmp_path, collection, "skip", [sys.executable, "-c", "pass"], 15, skip=True, **HOST)
    for entry in collection:
        assert entry["status"] not in {"success", "expected_end", "failed_or_partial"}


# ------------------------------------------------------------------------ never-raise guarantees


def test_write_command_result_never_raises_on_odd_results(tmp_path: Path):
    odd_results = [
        {},  # entirely empty
        {"stdout": b"x", "stderr": b"y"},  # no returncode, no flags
        {"returncode": 0, "timed_out": True},  # contradictory flags
        {"returncode": -9, "timed_out": False, "expected_stream_end": False},
    ]
    for result in odd_results:
        meta = write_command_result(tmp_path, "odd", result)
        assert meta["status"] in COLLECTION_STATUSES
        assert isinstance(meta["status_detail"], str) and meta["status_detail"]


def test_write_command_result_override_paths(tmp_path: Path):
    meta = write_command_result(
        tmp_path,
        "override",
        {"returncode": 1},
        status_override="skipped_by_user",
        status_detail_override="operator declined",
    )
    assert meta["status"] == "skipped_by_user"
    assert meta["status_detail"] == "operator declined"


def test_save_result_never_raises_on_bogus_input(tmp_path: Path):
    collection: list[dict] = []
    save_result(tmp_path, collection, "nope", ["definitely-not-a-real-binary-xyz"], 1, **HOST)
    save_result(tmp_path, collection, "nope-skip", ["whatever"], 1, skip=True)
    assert len(collection) == 2
    for entry in collection:
        assert entry["status"] in COLLECTION_STATUSES


def test_skip_keeps_existing_result_keys(tmp_path: Path):
    """New statuses are additive: old manifest keys survive on every path."""
    collection: list[dict] = []
    save_result(tmp_path, collection, "skipped-op", ["whatever"], 1, skip=True)
    entry = collection[0]
    for key in (
        "name",
        "command",
        "returncode",
        "duration_seconds",
        "timed_out",
        "expected_stream_end",
        "stdout_file",
        "stderr_file",
        "stdout_bytes",
        "stderr_bytes",
        "status",
    ):
        assert key in entry
    assert "status_detail" in entry
