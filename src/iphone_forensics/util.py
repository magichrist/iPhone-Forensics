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


def run_command(command: list[str], timeout: int = 45) -> dict[str, Any]:
    """Run a bounded, non-interactive command and preserve byte output."""
    started = time.monotonic()
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
        return {"command": command, "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr,
                "duration_seconds": round(time.monotonic() - started, 3), "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "returncode": None, "stdout": exc.stdout or b"",
                "stderr": exc.stderr or b"", "duration_seconds": round(time.monotonic() - started, 3),
                "timed_out": True}
    except OSError as exc:
        return {"command": command, "returncode": None, "stdout": b"",
                "stderr": str(exc).encode(), "duration_seconds": round(time.monotonic() - started, 3),
                "timed_out": False}


def capture_stream(command: list[str], seconds: int, output_path: Path) -> dict[str, Any]:
    """Capture a live stream until a monotonic deadline; always terminate the child."""
    import tempfile

    started = time.monotonic()
    timed_out = False
    returncode: int | None = None
    try:
        with output_path.open("wb") as output, tempfile.TemporaryFile() as errors:
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=errors, start_new_session=True)
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
    return {"command": command, "returncode": returncode,
            "stdout": output_path.read_bytes() if output_path.exists() else b"",
            "stderr": stderr_data, "duration_seconds": round(time.monotonic() - started, 3),
            "timed_out": timed_out, "expected_stream_end": timed_out,
            "stream_output_path": str(output_path)}


def write_command_result(raw_dir: Path, name: str, result: dict[str, Any]) -> dict[str, Any]:
    stdout_file = f"{safe_name(name)}.stdout.txt"
    stderr_file = f"{safe_name(name)}.stderr.txt"
    (raw_dir / stdout_file).write_bytes(result.get("stdout", b""))
    (raw_dir / stderr_file).write_bytes(result.get("stderr", b""))
    return {
        "name": name, "command": result.get("command", []),
        "returncode": result.get("returncode"),
        "duration_seconds": result.get("duration_seconds", 0),
        "timed_out": result.get("timed_out", False),
        "expected_stream_end": result.get("expected_stream_end", False),
        "stdout_file": stdout_file, "stderr_file": stderr_file,
        "stdout_bytes": len(result.get("stdout", b"")),
        "stderr_bytes": len(result.get("stderr", b"")),
        "status": ("success" if result.get("returncode") == 0 and not result.get("timed_out")
                   else "expected_end" if result.get("expected_stream_end")
                   else "failed_or_partial"),
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def secure_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
