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
