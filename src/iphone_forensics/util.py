from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .models import normalize_status

REDACTED = "••••"


def redact(value: Any) -> str:
    """Mask an identifier, keeping only its last four characters.

    The single redaction helper for the whole toolchain (docs/v5/07). Console
    output, HTML, JSON and evidence all go through here, so a masked value looks
    the same everywhere.

    An absent value stays absent: ``None``, ``""`` and ``0``-length values render
    as ``""``, never as a mask. Rendering "••••" for a missing identifier would
    claim a value was hidden when none was ever collected.
    """
    text = str(value if value is not None else "")
    if not text:
        return ""
    if len(text) <= 4:
        return REDACTED
    return "•" * max(4, len(text) - 4) + text[-4:]


# v5 readers written against the v4 vocabulary (analysis.py, reporting.py) compare
# status strings for equality.  They must migrate to `normalize_status()` (or consult
# this map) before they can consume v5 statuses; exported here so the follow-up is a
# one-line change rather than a re-derivation.  Values mirror models._LEGACY_STATUS_ALIASES.
STATUS_ALIASES_FOR_READERS: dict[str, str] = {
    "success": "collected",
    "expected_end": "collected",
    "failed_or_partial": "collection_error",
}


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def safe_name(value: str) -> str:
    # Neutralize traversal sequences: collapse any repeated dots and keep the
    # result from starting with dots, so "../.." can never survive sanitization.
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "unknown")
    cleaned = re.sub(r"\.{2,}", ".", cleaned)
    if cleaned.startswith("."):
        cleaned = "_" + cleaned
    return cleaned[:100]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_in_browser(path: Path) -> bool:
    """Open a local file in the user's default browser. Never raises.

    Returns True when the hand-off was handed to the OS. `webbrowser` shells out to
    the platform opener, which may itself fail on a headless box or a stripped-down
    container; that is an environment condition, not a report defect, so it is
    swallowed rather than raised. The report is already on disk either way and the
    path has been printed, so a failed open costs the reader nothing.

    The path is passed through `Path.as_uri()` rather than interpolated into a URL,
    so spaces and other characters in a run directory name cannot break the URL or
    smuggle a fragment into it.
    """
    try:
        if not path.is_file():
            return False
        import webbrowser

        return bool(webbrowser.open(path.resolve().as_uri()))
    except Exception:  # noqa: BLE001 - opening a viewer must never break a run
        return False


def run_command(command: list[str], timeout: int = 45) -> dict[str, Any]:
    """Run a bounded, non-interactive command and preserve byte output."""
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_seconds": round(time.monotonic() - started, 3),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": exc.stdout or b"",
            "stderr": exc.stderr or b"",
            "duration_seconds": round(time.monotonic() - started, 3),
            "timed_out": True,
        }
    except OSError as exc:
        # ENOENT/EACCES surface here.  Record which, so write_command_result can
        # distinguish "tool not installed" (tool_missing) from other OS errors.
        missing = isinstance(exc, FileNotFoundError)
        return {
            "command": command,
            "returncode": None,
            "stdout": b"",
            "stderr": str(exc).encode(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "timed_out": False,
            "missing_binary": missing,
            "os_error_type": type(exc).__name__,
        }


def capture_stream(command: list[str], seconds: int, output_path: Path) -> dict[str, Any]:
    """Capture a live stream until a monotonic deadline; always terminate the child."""
    import tempfile

    started = time.monotonic()
    timed_out = False
    returncode: int | None = None
    missing_binary = False
    try:
        with output_path.open("wb") as output, tempfile.TemporaryFile() as errors:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=max(1, seconds))
            except subprocess.TimeoutExpired:
                timed_out = True  # Expected for a healthy continuous stream.
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            returncode = proc.returncode
            errors.seek(0)
            stderr_data = errors.read(1024 * 1024)
    except OSError as exc:
        stderr_data = str(exc).encode()
        missing_binary = isinstance(exc, FileNotFoundError)
    return {
        "command": command,
        "returncode": returncode,
        "stdout": output_path.read_bytes() if output_path.exists() else b"",
        "stderr": stderr_data,
        "duration_seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out,
        "expected_stream_end": timed_out,
        "stream_output_path": str(output_path),
        "missing_binary": missing_binary,
    }


def write_command_result(
    raw_dir: Path,
    name: str,
    result: dict[str, Any],
    *,
    status_override: str | None = None,
    status_detail_override: str | None = None,
) -> dict[str, Any]:
    """Persist one command outcome and label it with a v5 collection status.

    Precedence: explicit overrides (used by callers with context this layer
    cannot see, e.g. skip flags or pairing-denial parsing) > cause inference
    (missing binary / bounded stream end / timeout / exit code).  The emitted
    status is always normalized through models.normalize_status, so it stays
    inside COLLECTION_STATUSES and old readers keep working on read.
    """
    stdout_file = f"{safe_name(name)}.stdout.txt"
    stderr_file = f"{safe_name(name)}.stderr.txt"
    (raw_dir / stdout_file).write_bytes(result.get("stdout", b""))
    (raw_dir / stderr_file).write_bytes(result.get("stderr", b""))

    status: str
    detail: str
    if result.get("missing_binary"):
        status, detail = "tool_missing", "executable not found on PATH"
    elif result.get("expected_stream_end"):
        # A bounded log capture ends by hitting its deadline; that is the design,
        # not a failure.  timed_out stays True so readers can see what happened.
        status, detail = "collected", "expected_stream_end (bounded log capture)"
    elif result.get("timed_out"):
        status, detail = "collection_error", "command exceeded its timeout"
    elif result.get("returncode") == 0:
        status, detail = "collected", "exit code 0"
    else:
        status, detail = "collection_error", f"exit code {result.get('returncode')}"

    if status_override:
        status = normalize_status(status_override)
        if status_detail_override:
            detail = status_detail_override
    elif status_detail_override:
        detail = status_detail_override
    status = normalize_status(status)

    return {
        "name": name,
        "command": result.get("command", []),
        "returncode": result.get("returncode"),
        "duration_seconds": result.get("duration_seconds", 0),
        "timed_out": result.get("timed_out", False),
        "expected_stream_end": result.get("expected_stream_end", False),
        "stdout_file": stdout_file,
        "stderr_file": stderr_file,
        "stdout_bytes": len(result.get("stdout", b"")),
        "stderr_bytes": len(result.get("stderr", b"")),
        "status": status,
        "status_detail": detail,
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8"
    )


def secure_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
