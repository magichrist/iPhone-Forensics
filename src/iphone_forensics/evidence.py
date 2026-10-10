"""Evidence manifest creation and later verification.

SHA-256 here proves *unchanged since hashing*, never authenticity of the
device-originated content. That distinction is surfaced in every output that
mentions the manifest.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import sha256_file, write_json

SCHEMA_VERSION = "4.0.0"


def build_manifest(run_dir: Path) -> dict[str, Any]:
    """Hash every collected artifact (excluding reports/manifests themselves)."""
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
            "schema_version": SCHEMA_VERSION,
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
