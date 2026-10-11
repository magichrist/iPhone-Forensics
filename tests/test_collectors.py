from iphone_forensics.collectors import parse_key_values, parse_plist


def test_parse_key_values():
    assert parse_key_values("ProductType: iPhone15,4\nProductVersion: 18.0\n") == {
        "ProductType": "iPhone15,4", "ProductVersion": "18.0"
    }


def test_invalid_plist_returns_none():
    assert parse_plist(b"not a plist") is None


def test_diagnostic_candidates_only_returns_matching_keys():
    from iphone_forensics.collectors import diagnostic_candidates
    import plistlib
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

    def fake_run(command, timeout=None):
        calls.append(command)
        if command[-1] == "--help":
            return {"stdout": b"Usage: pymobiledevice3 [OPTIONS] COMMAND\n"
                             b"--udid <str>  select device\n", "stderr": b""}
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
            return {"stdout": b"Usage: pymobiledevice3 [OPTIONS] COMMAND\n"
                             b"--tunnel <str>\n--rsd HOST PORT\n", "stderr": b""}
        return {"stdout": b"", "stderr": b""}

    monkeypatch.setattr(collectors, "run_command", no_udid)
    collectors._PMD_UDID_FLAG_CACHE.clear()
    report = {"findings": []}
    prefix = collectors._pmd_prefix("pmd", "UDID-1", report)
    assert prefix == ["pmd"], "must not pass an option this build rejects"
    assert any("does not accept --udid" in f["title"] for f in report["findings"]), \
        "the compatibility gap must be recorded, not silent"


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
