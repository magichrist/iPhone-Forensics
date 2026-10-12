"""P2 output-layout tests (docs/v5/03-output-layout.md).

Covers the unique run-dir guarantee (never overwrite), manifest <-> files
agreement, no phantom artifacts for collectors that produced no output, and
README.txt content.
"""

import json
from pathlib import Path

from iphone_forensics.evidence import (
    build_manifest,
    run_dir_paths,
    verify_manifest,
    write_readme_txt,
)

STAMP = "20261010-201500"


def test_run_dir_paths_applies_dedupe_suffix_without_overwriting(tmp_path: Path):
    root = tmp_path / "runs"
    root.mkdir()
    first = root / f"iphone-forensics-{STAMP}"
    first.mkdir()
    sentinel = first / "report.json"
    sentinel.write_text('{"previous": true}', encoding="utf-8")

    paths = run_dir_paths(root, STAMP)

    assert paths["run_dir"] == root / f"iphone-forensics-{STAMP}-1"
    assert paths["run_dir"].is_dir()
    # The pre-existing run is untouched: no overwrite, nothing added.
    assert sentinel.read_text(encoding="utf-8") == '{"previous": true}'
    assert sorted(p.name for p in first.iterdir()) == ["report.json"]
    # Every layout key points inside the new run directory.
    assert paths["report.html"] == paths["run_dir"] / "report.html"
    assert paths["report.json"] == paths["run_dir"] / "report.json"
    assert paths["manifest.json"] == paths["run_dir"] / "manifest.json"
    assert paths["readme"] == paths["run_dir"] / "README.txt"
    assert paths["evidence_dir"] == paths["run_dir"] / "evidence"
    assert paths["evidence_dir"].is_dir()


def test_run_dir_paths_second_collision_gets_suffix_two(tmp_path: Path):
    root = tmp_path / "runs"
    root.mkdir()
    (root / f"iphone-forensics-{STAMP}").mkdir()
    (root / f"iphone-forensics-{STAMP}-1").mkdir()

    paths = run_dir_paths(root, STAMP)

    assert paths["run_dir"] == root / f"iphone-forensics-{STAMP}-2"
    assert paths["run_dir"].is_dir()


def test_manifest_agrees_with_files_on_disk(tmp_path: Path):
    run_dir = tmp_path / "run"
    evidence = run_dir / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "device-info.json").write_text(
        json.dumps({"model": "iPhone15,4"}), encoding="utf-8"
    )
    (evidence / "hardware.json").write_text(json.dumps({"battery": "ok"}), encoding="utf-8")
    (run_dir / "report.json").write_text(json.dumps({"schema_version": "4.0.0"}), encoding="utf-8")
    (run_dir / "report.html").write_text("<html></html>", encoding="utf-8")

    manifest = build_manifest(run_dir)

    assert manifest["schema_version"] == "5.0.0"
    assert len(manifest["artifacts"]) == 2
    verdict = verify_manifest(run_dir)
    assert verdict["verified"] is True
    assert verdict["matched"] == 2
    assert verdict["changed"] == 0
    assert verdict["missing"] == 0
    assert verdict["added"] == []


def test_no_phantom_artifacts_for_missing_collectors(tmp_path: Path):
    # Simulate a run where only two collectors produced output: the manifest
    # must describe exactly those two files and nothing else.
    run_dir = tmp_path / "run"
    evidence = run_dir / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "device-info.json").write_text("{}", encoding="utf-8")
    (evidence / "hardware.json").write_text("{}", encoding="utf-8")

    manifest = build_manifest(run_dir)

    paths = sorted(entry["path"] for entry in manifest["artifacts"])
    assert paths == ["evidence/device-info.json", "evidence/hardware.json"]
    # A collector that produced no file leaves no manifest entry.
    assert not (evidence / "battery.json").exists()
    assert all("battery" not in entry["path"] for entry in manifest["artifacts"])
    # Each artifact carries exactly the documented fields.
    for entry in manifest["artifacts"]:
        assert set(entry) == {"path", "size_bytes", "sha256"}


def test_readme_txt_content(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    info = {
        "version": "4.0.0",
        "generated": "2026-10-10T20:15:00+00:00",
        "device": {"ProductType": "iPhone15,4"},
    }

    path = write_readme_txt(run_dir, info)

    assert path == run_dir / "README.txt"
    text = path.read_text(encoding="utf-8")
    assert "report.html" in text
    assert "privacy" in text.lower()
    assert "4.0.0" in text
    # ~20 lines: title, orientation, contents, privacy warning, versions,
    # timestamps.
    assert 15 <= len(text.strip().splitlines()) <= 30
