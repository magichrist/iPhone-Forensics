import json
from pathlib import Path

from iphone_forensics.evidence import build_manifest, verify_manifest


def test_manifest_roundtrip(tmp_path: Path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "note.txt").write_text("hello")
    manifest = build_manifest(tmp_path)
    assert len(manifest["artifacts"]) == 1
    assert manifest["artifacts"][0]["path"] == "raw/note.txt"
    verdict = verify_manifest(tmp_path)
    assert verdict["verified"] is True
    assert verdict["matched"] == 1


def test_verify_detects_changed_file(tmp_path: Path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "note.txt").write_text("hello")
    build_manifest(tmp_path)
    (tmp_path / "raw" / "note.txt").write_text("tampered")
    verdict = verify_manifest(tmp_path)
    assert verdict["verified"] is False
    assert verdict["changed"] == 1


def test_verify_detects_missing_file(tmp_path: Path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "note.txt").write_text("hello")
    build_manifest(tmp_path)
    (tmp_path / "raw" / "note.txt").unlink()
    verdict = verify_manifest(tmp_path)
    assert verdict["verified"] is False
    assert verdict["missing"] == 1


def test_verify_accepts_v3_list_manifest(tmp_path: Path):
    import hashlib
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "note.txt").write_text("hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    v3_manifest = [{"path": "raw/note.txt", "size_bytes": 5, "sha256": digest}]
    (tmp_path / "manifest.json").write_text(json.dumps(v3_manifest))
    verdict = verify_manifest(tmp_path)
    assert verdict["verified"] is True
    assert verdict["matched"] == 1


def test_verify_blank_report_files_are_not_flagged(tmp_path: Path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "note.txt").write_text("x")
    build_manifest(tmp_path)
    (tmp_path / "report.json").write_text(json.dumps({}))
    verdict = verify_manifest(tmp_path)
    assert verdict["verified"] is True
