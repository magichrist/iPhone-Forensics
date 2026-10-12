from pathlib import Path

from iphone_forensics.buyer import template
from iphone_forensics.reporting import build_html


def test_html_report_escapes_untrusted_fields(tmp_path: Path):
    report = {
        "version": "3.0.0",
        "started_at": "now",
        "finished_at": "later",
        "host": {"platform": "test", "macOS": "", "python": "3", "architecture": "arm64"},
        "device": {"DeviceName": "<script>alert(1)</script>"},
        "findings": [
            {
                "severity": "INFO",
                "title": "<img src=x>",
                "detail": "<script>bad</script>",
                "evidence": [],
            }
        ],
        "collection": [],
        "tools": {},
        "limitations": [],
        "assessment": {},
        "buyer_data": template(),
    }
    build_html(tmp_path, report)
    output = (tmp_path / "report.html").read_text()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "<script>alert(1)</script>" not in output


def test_redaction_masks_serial_and_udid(tmp_path: Path):
    from iphone_forensics.reporting import finalize

    report = {
        "version": "3.0.0",
        "started_at": "now",
        "finished_at": "later",
        "host": {"platform": "test", "macOS": "", "python": "3", "architecture": "arm64"},
        "target_udid": "12345678-1234-1234-1234-123456789abc",
        "connected_devices": ["12345678-1234-1234-1234-123456789abc"],
        "device": {"SerialNumber": "SERIAL-SECRET-1234", "ProductType": "iPhone15,4"},
        "findings": [],
        "collection": [],
        "tools": {},
        "limitations": [],
        "assessment": {},
        "buyer_data": template(),
    }
    finalize(tmp_path, report, redact_identifiers=True)
    redacted_json = (tmp_path / "report-redacted.json").read_text()
    redacted_html = (tmp_path / "report-redacted.html").read_text()
    assert "SERIAL-SECRET-1234" not in redacted_json
    assert "12345678-1234-1234-1234-123456789abc" not in redacted_json
    assert "SERIAL-SECRET-1234" not in redacted_html


def test_html_has_storage_normalization_and_comparison_section(tmp_path: Path):
    report = {
        "version": "3.0.0",
        "started_at": "now",
        "finished_at": "later",
        "host": {"platform": "test", "macOS": "", "python": "3", "architecture": "arm64"},
        "device": {"TotalDiskCapacity": 128000000000},
        "findings": [],
        "collection": [],
        "tools": {},
        "limitations": [],
        "assessment": {},
        "buyer_data": template(),
        "comparison": {
            "changes": [
                {"field": "ProductVersion", "previous": "17", "current": "18", "status": "changed"}
            ]
        },
    }
    build_html(tmp_path, report)
    output = (tmp_path / "report.html").read_text()
    assert "128.00 GB" in output
    assert "Change since the previous inspection" in output
    assert "ProductVersion" in output
