import argparse

from iphone_forensics.collectors import parse_key_values, parse_plist


def test_parse_key_values():
    assert parse_key_values("ProductType: iPhone15,4\nProductVersion: 18.0\n") == {
        "ProductType": "iPhone15,4",
        "ProductVersion": "18.0",
    }


def test_invalid_plist_returns_none():
    assert parse_plist(b"not a plist") is None


def test_diagnostic_candidates_only_returns_matching_keys():
    import plistlib

    from iphone_forensics.collectors import diagnostic_candidates

    payload = plistlib.dumps({"CycleCount": 215, "DeviceName": "Test", "BatteryTemperature": 3100})
    found = diagnostic_candidates(payload, "GasGauge")
    keys = {item["key"] for item in found}
    assert "CycleCount" in keys
    assert "BatteryTemperature" in keys
    assert "DeviceName" not in keys


# ------------------------------------------- pymobiledevice3 --udid compatibility


def test_udid_flag_is_only_passed_when_the_installed_build_accepts_it(monkeypatch):
    """pymobiledevice3 11.x removed the global `--udid`.

    Passing it anyway exits 2 with "No such option: --udid" before doing any
    work, so every pymobiledevice3 collector failed with a collection_error that
    looked like a device fault.
    """
    from iphone_forensics import collectors

    calls = []

    def fake_run(command, timeout=None, **_kw):
        calls.append(command)
        if command[-1] == "--help":
            return {
                "stdout": b"Usage: pymobiledevice3 [OPTIONS] COMMAND\n"
                b"--udid <str>  select device\n",
                "stderr": b"",
            }
        return {"stdout": b"{}", "stderr": b""}

    monkeypatch.setattr(collectors, "run_command", fake_run)
    monkeypatch.setattr(collectors, "_PMD_UDID_FLAG_CACHE", {})

    # A build that still accepts --udid keeps receiving it.
    collectors._PMD_UDID_FLAG_CACHE.clear()
    prefix = collectors._pmd_prefix("pmd", "UDID-1", {"findings": []})
    assert prefix == ["pmd", "--udid", "UDID-1"]

    # A build that dropped it must not receive it, and must say so.
    def no_udid(command, timeout=None):
        if command[-1] == "--help":
            return {
                "stdout": b"Usage: pymobiledevice3 [OPTIONS] COMMAND\n"
                b"--tunnel <str>\n--rsd HOST PORT\n",
                "stderr": b"",
            }
        return {"stdout": b"", "stderr": b""}

    monkeypatch.setattr(collectors, "run_command", no_udid)
    collectors._PMD_UDID_FLAG_CACHE.clear()
    report = {"findings": []}
    prefix = collectors._pmd_prefix("pmd", "UDID-1", report)
    assert prefix == ["pmd"], "must not pass an option this build rejects"
    assert any("does not accept --udid" in f["title"] for f in report["findings"]), (
        "the compatibility gap must be recorded, not silent"
    )


def test_udid_flag_probe_result_is_cached(monkeypatch):
    """The probe costs a subprocess; it must not run once per collector."""
    from iphone_forensics import collectors

    monkeypatch.setattr(collectors, "_PMD_UDID_FLAG_CACHE", {})
    probes = []

    def counting(command, timeout=None):
        if command[-1] == "--help":
            probes.append(command)
            return {"stdout": b"Usage: pymobiledevice3\n", "stderr": b""}
        return {"stdout": b"", "stderr": b""}

    monkeypatch.setattr(collectors, "run_command", counting)
    for _ in range(5):
        collectors._pmd_supports_udid_flag("pmd")
    assert len(probes) == 1, f"expected one probe, ran {len(probes)}"


def test_unprobeable_pmd_tool_does_not_raise(monkeypatch):
    """A tool that cannot be probed must degrade, never abort collection."""
    from iphone_forensics import collectors

    monkeypatch.setattr(collectors, "_PMD_UDID_FLAG_CACHE", {})

    def exploding(command, timeout=None):
        raise OSError("cannot execute")

    monkeypatch.setattr(collectors, "run_command", exploding)
    assert collectors._pmd_supports_udid_flag("pmd") is False


# ------------------------------------------------- storage capacity collection


def test_disk_usage_domain_is_queried_for_storage_capacity(monkeypatch, tmp_path):
    """TotalDiskCapacity lives in com.apple.disk_usage, not the default domain.

    `ideviceinfo -x` dumps only the default domain, which on current iOS has no
    capacity keys — so storage silently read as "not collected" on every modern
    device while being one flag away.
    """
    from iphone_forensics import collectors

    def fake_run(command, timeout=None, **_kw):
        if "-q" in command and "com.apple.disk_usage" in command:
            return {
                "stdout": b"TotalDiskCapacity: 128000000000\nTotalDataCapacity: 115484557312\n",
                "stderr": b"",
                "returncode": 0,
                "duration_seconds": 0.1,
                "timed_out": False,
            }
        if "-x" in command:
            return {
                "stdout": b"<plist><dict><key>ProductType</key>"
                b"<string>iPhone14,5</string></dict></plist>",
                "stderr": b"",
                "returncode": 0,
                "duration_seconds": 0.1,
                "timed_out": False,
            }
        return {
            "stdout": b"",
            "stderr": b"",
            "returncode": 1,
            "duration_seconds": 0.1,
            "timed_out": False,
        }

    monkeypatch.setattr(collectors, "run_command", fake_run)
    monkeypatch.setattr(
        collectors.shutil, "which", lambda name: f"/usr/bin/{name}" if name else None
    )

    report = {"collection": [], "findings": []}
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    args = argparse.Namespace(
        crash_reports=False,
        app_list=False,
        provisioning=False,
        syslog_seconds=0,
        pmd_syslog_seconds=0,
        backup="none",
        pmd_app_list=False,
        pmd_processes=False,
        pmd_crash_reports=False,
    )
    collectors.collect_device(args, tmp_path, evidence, report, "UDID")

    assert any(c["name"] == "device-info-disk-usage" for c in report["collection"]), (
        "the disk_usage domain was never queried"
    )
    assert report["device"].get("TotalDiskCapacity") == "128000000000"
    assert report["device"].get("TotalDataCapacity") == "115484557312"
    assert report["device"].get("ProductType") == "iPhone14,5", "existing keys must survive"


def test_unavailable_diagnostics_relay_is_unsupported_not_an_error(monkeypatch, tmp_path):
    """`diagnostics All` is refused on devices that expose only named domains.

    The per-domain queries still succeed, so recording this as a collection_error
    made a healthy device look broken.
    """
    from iphone_forensics import collectors

    monkeypatch.setattr(
        collectors,
        "run_command",
        lambda command, timeout=None, **_kw: {
            "stdout": b"",
            "stderr": b"ERROR: Could not connect to diagnostics_relay!",
            "returncode": 1,
            "duration_seconds": 0.1,
            "timed_out": False,
        },
    )

    collection: list = []
    collectors.save_result(
        tmp_path,
        collection,
        "diagnostics-All",
        ["idevicediagnostics", "diagnostics", "All"],
        10,
        unsupported_markers=collectors.DIAGNOSTICS_UNSUPPORTED_MARKERS,
    )
    assert collection[0]["status"] == "unsupported", collection[0]["status"]
    assert collection[0]["status_detail"]
