"""Evidence manifest creation and later verification.

SHA-256 here proves *unchanged since hashing*, never authenticity of the
device-originated content. That distinction is surfaced in every output that
mentions the manifest.

This module is also the single writer of ``manifest.json`` (v5 output
layout, docs/v5/03-output-layout.md) and owns the run-directory layout
helpers (:func:`run_dir_paths`, :func:`write_readme_txt`).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import secure_mkdir, sha256_file, utc_now, write_json

SCHEMA_VERSION = "5.0.0"

# Name of the subdirectory that holds every collected artifact. v5 replaced the
# v4 `raw/` name with `evidence/` (docs/v5/03-output-layout.md); the content is
# unchanged, only the directory name. Every layer reads this constant so the
# writers (collectors), the readers (crash triage, manifest) and the report copy
# cannot drift apart again.
EVIDENCE_DIR_NAME = "evidence"

# v4 run directories still on disk used `raw/`. Triage reads both so an older
# run stays analyzable.
LEGACY_EVIDENCE_DIR_NAME = "raw"

def build_manifest(run_dir: Path) -> dict[str, Any]:
    """Hash every collected artifact (excluding reports/manifests themselves).

    Emits ``{"schema_version": ..., "artifacts": [{path, size_bytes, sha256}]}``
    and writes it to ``<run_dir>/manifest.json``. Only files that exist on
    disk are hashed, so a collector that produced no output leaves no
    manifest entry (no phantom artifacts).
    """
    excluded = {"manifest.json", "report.json", "report.html",
                "report-redacted.json", "report-redacted.html", "buyer-checklist.json"}
    entries: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        entries.append({
            "path": str(path.relative_to(run_dir)),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    manifest = {"schema_version": SCHEMA_VERSION, "artifacts": entries}
    write_json(run_dir / "manifest.json", manifest)
    return manifest


def verify_manifest(run_dir_or_manifest: Path) -> dict[str, Any]:
    """Verify that artifacts still match a previously written manifest.

    Accepts either a run directory containing manifest.json or a path directly
    to any manifest JSON file.
    """
    manifest_path = (run_dir_or_manifest / "manifest.json") if run_dir_or_manifest.is_dir() \
        else run_dir_or_manifest
    try:
        import json
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"verified": False, "error": f"cannot read manifest: {exc}",
                "matched": 0, "changed": 0, "missing": 0, "added": []}

    # v4 manifests are {"schema_version": ..., "artifacts": [...]}; v3 manifests
    # were a bare list of entries. Accept both so older runs remain verifiable.
    if isinstance(manifest, list):
        artifacts = manifest
    elif isinstance(manifest, dict):
        artifacts = manifest.get("artifacts", [])
    else:
        return {"verified": False, "error": "manifest must be a list or an object with 'artifacts'",
                "matched": 0, "changed": 0, "missing": 0, "added": []}

    base = manifest_path.parent
    matched = changed = missing = 0
    added: list[str] = []
    known_paths = set()
    problems: list[dict[str, str]] = []
    for entry in artifacts:
        path = base / entry["path"]
        known_paths.add(entry["path"])
        if not path.exists():
            missing += 1
            problems.append({"path": entry["path"], "problem": "missing"})
            continue
        import hashlib
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != entry["sha256"]:
            changed += 1
            problems.append({"path": entry["path"], "problem": "content changed since hashing"})
        else:
            matched += 1
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(base))
        if rel in known_paths or rel in {"manifest.json", "report.json", "report.html",
                                         "report-redacted.json", "report-redacted.html",
                                         "buyer-checklist.json"}:
            continue
        added.append(rel)
    return {
        "verified": changed == 0 and missing == 0,
        "matched": matched, "changed": changed, "missing": missing, "added": added,
        "problems": problems,
        "note": "Matching hashes prove files have not changed since hashing. They do not prove the original data was authentic.",
    }


def run_dir_paths(root: Path, stamp: str) -> dict[str, Path]:
    """Resolve (and create) a unique run-directory layout under *root*.

    The run directory is named ``iphone-forensics-<stamp>``; when that name
    already exists a ``-1``/``-2``… suffix is appended, so a previous run
    is never overwritten or cleaned. Both the run directory and its
    ``evidence/`` subdirectory are created with mode 0700.

    Returns a mapping with keys ``run_dir``, ``report.html``,
    ``report.json``, ``manifest.json``, ``readme`` and ``evidence_dir``.
    """
    run_dir = root / f"iphone-forensics-{stamp}"
    suffix = 0
    while run_dir.exists():
        suffix += 1
        run_dir = root / f"iphone-forensics-{stamp}-{suffix}"
    secure_mkdir(run_dir)
    evidence_dir = run_dir / EVIDENCE_DIR_NAME
    evidence_dir.mkdir(mode=0o700)
    return {
        "run_dir": run_dir,
        "report.html": run_dir / "report.html",
        "report.json": run_dir / "report.json",
        "manifest.json": run_dir / "manifest.json",
        "readme": run_dir / "README.txt",
        "evidence_dir": evidence_dir,
    }


def write_readme_txt(run_dir: Path, info: dict[str, Any]) -> Path:
    """Write the ``README.txt`` (~20 lines) explaining a run directory.

    *info* may carry ``version`` (tool version), ``generated``/``started``/
    ``finished`` (timestamps), ``device`` (string or mapping) and ``command``;
    missing keys fall back to honest defaults.
    """
    version = info.get("version") or "unknown"
    generated = info.get("generated") or info.get("started") or utc_now()
    finished = info.get("finished")
    device = info.get("device")
    if isinstance(device, dict):
        details = ", ".join(f"{key}: {value}" for key, value in device.items() if value)
        device = details or "unknown device"
    command = info.get("command")

    lines = [
        "iPhone Forensics - inspection run",
        "",
        "This directory holds the complete output of one iPhone Forensics",
        "inspection run: the human-readable report, the machine-readable data",
        "behind it, a tamper-evident manifest, and the collected evidence.",
        "",
        "Open report.html first - it is the primary report.",
        "",
        "Contents:",
        "  report.html     primary human-readable report (open this first)",
        "  report.json     machine-readable data backing report.html",
        "  manifest.json   SHA-256 digest and size of every evidence artifact",
        "  README.txt      this file",
        "  evidence/       collected artifacts, one file per collector",
        "",
        "Privacy warning: this directory contains data read from a real",
        "device and may include personal information. Keep it private and",
        "local - do not upload, share, or transmit it without removing",
        "sensitive information first.",
        "",
        f"Tool version: {version}",
        f"Generated (UTC): {generated}",
    ]
    if finished:
        lines.append(f"Finished (UTC): {finished}")
    if device:
        lines.append(f"Device: {device}")
    if command:
        lines.append(f"Command: {command}")
    path = run_dir / "README.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
