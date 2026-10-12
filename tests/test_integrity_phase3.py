"""Phase 3 — integrity engine: schema normalization, continuity guard, all 9 classes.

How each of the nine INTEGRITY_CLASSES is reached (and by what it may *not* be
reached). The engine infers only four classes from a metadata diff; the rest are
constructed through `classify_assertion()`, which enforces the evidence rules:

| class                 | constructor path                                                        |
|-----------------------|-------------------------------------------------------------------------|
| verified              | classify_assertion("verified", narrow claim, evidence=[...])             |
| consistent            | assess_integrity: every compared field agrees                           |
| change_detected       | classify_change: benign OS/build, wear telemetry, diagnostic candidate  |
| replacement_indicated | classify_assertion(..., source=<supported diagnostic>) ONLY             |
| suspicious            | classify_change: identity mismatch / unexplained difference             |
| inconclusive          | assess_integrity: field present in one snapshot only (not comparable)   |
| not_detectable        | assess_integrity continuity guard finding                               |
| not_tested            | assess_integrity(None, ...)                                             |
| unsupported           | classify_assertion("unsupported", stated reason)                        |

Hard rule under test: a metadata difference can never yield `replacement_indicated`
(docs/v4/tampering-indicators.md).
"""

import pytest

from iphone_forensics.integrity import (
    assess_integrity,
    classify_assertion,
    classify_change,
    normalize_device,
)
from iphone_forensics.models import INTEGRITY_CLASSES

V3_REPORT = {
    "version": "3.0.0",  # no schema_version → treated as v3
    "device": {
        "Product Type": "iPhone15,4",
        "Serial Number": "F2LX9",
        "TotalDiskCapacity": "128000000000",
    },
}
V4_REPORT = {
    "schema_version": "4.0.0",
    "device": {
        "ProductType": "iPhone15,4",
        "SerialNumber": "F2LX9",
        "TotalDiskCapacity": 128000000000,
    },
}


# ------------------------------------------------------- schema normalization


def test_normalize_resolves_v3_space_key_to_v4():
    device = normalize_device(V3_REPORT)
    assert device["ProductType"] == "iPhone15,4"
    assert device["SerialNumber"] == "F2LX9"
    assert "Product Type" not in device  # legacy spelling is resolved, not kept


def test_normalize_keeps_v4_canonical_key():
    device = normalize_device(V4_REPORT)
    assert device["ProductType"] == "iPhone15,4"
    assert device["SerialNumber"] == "F2LX9"


def test_normalize_canonical_key_wins_over_legacy_alias():
    device = normalize_device(
        {"device": {"Product Type": "iPhone9,9", "ProductType": "iPhone15,4"}}
    )
    assert device["ProductType"] == "iPhone15,4"
    assert "Product Type" not in device


def test_normalize_missing_schema_version_is_treated_as_v3():
    # No schema_version: legacy keys and string capacities must still resolve.
    device = normalize_device(
        {"device": {"Product Type": "iPhone15,4", "TotalDiskCapacity": "128000000000"}}
    )
    assert device["ProductType"] == "iPhone15,4"
    assert device["TotalDiskCapacity"] == 128000000000
    assert isinstance(device["TotalDiskCapacity"], int)


def test_normalize_capacity_gb_tier_scaled_to_bytes():
    device = normalize_device(
        {
            "schema_version": "4.0.0",
            "device": {"TotalDiskCapacity": 128, "TotalDataCapacity": "119 GB"},
        }
    )
    assert device["TotalDiskCapacity"] == 128_000_000_000
    assert device["TotalDataCapacity"] == 119_000_000_000


def test_normalize_capacity_unparseable_passes_through():
    device = normalize_device({"device": {"TotalDiskCapacity": "unknown"}})
    assert device["TotalDiskCapacity"] == "unknown"  # stay visible, never invented


def test_normalize_does_not_mutate_input():
    report = {"device": {"Product Type": "iPhone15,4", "TotalDiskCapacity": 128}}
    normalize_device(report)
    assert report["device"] == {"Product Type": "iPhone15,4", "TotalDiskCapacity": 128}


def test_normalize_never_mistakes_report_keys_for_device_data():
    assert normalize_device({"version": "3.0.0", "findings": [], "collection": []}) == {}
    assert normalize_device({"device": "not-a-dict"}) == {}
    assert normalize_device(None) == {}


def test_normalize_accepts_bare_device_dict():
    assert normalize_device({"Product Type": "iPhone15,4"})["ProductType"] == "iPhone15,4"


def test_cross_schema_comparison_v3_previous_v4_current_is_consistent():
    result = assess_integrity(V3_REPORT, V4_REPORT)
    assert result["classifications"]["ProductType"] == "consistent"
    assert result["classifications"]["SerialNumber"] == "consistent"
    assert result["changes"] == []
    assert result["overall"] == "consistent"


def test_cross_schema_comparison_v4_previous_v3_current_is_consistent():
    result = assess_integrity(V4_REPORT, V3_REPORT)
    assert result["classifications"]["ProductType"] == "consistent"
    assert result["changes"] == []
    assert result["overall"] == "consistent"


def test_int_vs_string_and_gb_vs_bytes_capacity_is_not_a_change():
    prev = {"device": {"ProductType": "iPhone15,4", "TotalDiskCapacity": "128000000000"}}
    curr = {"device": {"ProductType": "iPhone15,4", "TotalDiskCapacity": 128}}  # GB tier
    result = assess_integrity(prev, curr)
    assert result["classifications"]["TotalDiskCapacity"] == "consistent"
    assert result["overall"] == "consistent"


# ------------------------------------------------------------- continuity guard


def test_continuity_established_when_hard_identifier_shared():
    prev = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "F2LX9"}}
    curr = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "F2LX9"}}
    result = assess_integrity(prev, curr)
    assert result["continuity"] == "established"
    assert not [f for f in result["findings"] if "continuity" in f["title"].lower()]
    assert result["overall"] == "consistent"


def test_continuity_not_tested_without_previous_snapshot():
    result = assess_integrity(None, V4_REPORT)
    assert result["continuity"] == "not_tested"
    assert result["overall"] == "not_tested"


def test_continuity_not_detectable_when_no_identifier_recorded():
    """Neither snapshot recorded UDID/serial/IMEI: continuity is reported as
    not_detectable with an INFO finding, but the field-level verdict is *not*
    silently downgraded — there is nothing that contradicts it, and the
    documented v3 compatibility contract keeps such a comparison `consistent`.
    The continuity key and finding carry the gap."""
    prev = {"device": {"ProductType": "iPhone15,4"}}
    curr = {"schema_version": "4.0.0", "device": {"ProductType": "iPhone15,4"}}
    result = assess_integrity(prev, curr)
    assert result["continuity"] == "not_detectable"
    finding = next(
        f for f in result["findings"] if f["title"] == "Device continuity cannot be established"
    )
    assert finding["severity"] == "INFO"
    assert finding["classification"] == "not_detectable"
    assert result["overall"] == "consistent"  # documented: no identifier was recorded


def test_continuity_cap_when_identity_recorded_but_unlinkable():
    """The serial exists on one side only: the data needed to link the snapshots
    existed and does not link them, so an affirmative verdict is capped."""
    prev = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "F2LX9"}}
    curr = {"schema_version": "4.0.0", "device": {"ProductType": "iPhone15,4"}}
    result = assess_integrity(prev, curr)
    assert result["continuity"] == "not_detectable"
    assert result["classifications"]["SerialNumber"] == "inconclusive"
    assert result["overall"] == "inconclusive"  # capped, not "consistent"
    finding = next(
        f for f in result["findings"] if f["title"] == "Device continuity cannot be established"
    )
    assert finding["severity"] == "INFO"


def test_continuity_cap_never_downgrades_suspicious_identity_rule():
    prev = {"device": {"ProductType": "iPhone15,4", "SerialNumber": "S-one"}}
    curr = {
        "schema_version": "4.0.0",
        "device": {"ProductType": "iPhone15,4", "SerialNumber": "S-two"},
    }
    result = assess_integrity(prev, curr)
    assert result["continuity"] == "not_detectable"
    assert result["overall"] == "suspicious"  # serial-change BLOCKER survives


# --------------------------------------------------- all nine integrity classes


def test_class_verified_from_narrow_claim_with_evidence():
    classification, finding = classify_assertion(
        "verified",
        "Both snapshots report serial F2LX9, matching Settings → General → About",
        evidence=["raw/device-info.plist", "photo://settings-about.jpg"],
    )
    assert classification == "verified"
    assert finding.classification == "verified"
    assert finding.confidence != "none"
    assert finding.evidence


def test_class_verified_refuses_claim_without_evidence():
    with pytest.raises(ValueError):
        classify_assertion("verified", "device looks genuine")
    with pytest.raises(ValueError):
        classify_assertion("verified", "", evidence=["raw/device-info.plist"])


def test_class_consistent_from_matching_snapshots():
    result = assess_integrity(
        {"device": {"ProductType": "iPhone15,4"}},
        {"schema_version": "4.0.0", "device": {"ProductType": "iPhone15,4"}},
    )
    assert result["classifications"]["ProductType"] == "consistent"
    assert result["overall"] == "consistent"


def test_class_change_detected_from_os_build_change():
    classification, _ = classify_change("BuildVersion", "21A329", "21B101")
    assert classification == "change_detected"


def test_class_replacement_indicated_only_from_diagnostic_assertion():
    classification, finding = classify_assertion(
        "replacement_indicated",
        "Display listed as replaced with a non-genuine part",
        source="parts_and_service_history",
        evidence=["photo://settings-parts-service-history.jpg"],
        next_test="Confirm at an authorized service provider before purchase.",
    )
    assert classification == "replacement_indicated"
    assert finding.severity in {"WARNING", "BLOCKER", "REVIEW"}
    assert finding.evidence


@pytest.mark.parametrize(
    "bad_source", ["metadata_diff", "snapshot_diff", "product_type_changed", ""]
)
def test_class_replacement_indicated_refuses_non_diagnostic_sources(bad_source):
    with pytest.raises(ValueError):
        classify_assertion(
            "replacement_indicated",
            "serial changed",
            source=bad_source,
            evidence=["report.json (previous)"],
        )


def test_class_replacement_indicated_requires_evidence_artifact():
    with pytest.raises(ValueError):
        classify_assertion(
            "replacement_indicated", "battery replaced", source="diagnostic_service", evidence=[]
        )


def test_metadata_diff_never_yields_replacement_indicated():
    prev = {
        "device": {
            "Product Type": "iPhone13,2",
            "ModelNumber": "MXCT3",
            "BuildVersion": "20A362",
            "TotalDiskCapacity": "64000000000",
            "SerialNumber": "AAAAA",
        }
    }
    curr = {
        "schema_version": "4.0.0",
        "device": {
            "ProductType": "iPhone15,4",
            "ModelNumber": "MTP13",
            "BuildVersion": "22B100",
            "TotalDiskCapacity": 256_000_000_000,
            "SerialNumber": "BBBBB",
        },
    }
    buyer = {
        "buyer": {"advertised_model": "iPhone 15"},
        "observations": {"reported_storage_gb": 256},
    }
    result = assess_integrity(prev, curr, buyer_data=buyer)
    assert result["overall"] != "replacement_indicated"
    assert all(c != "replacement_indicated" for c in result["classifications"].values())
    assert all(f["classification"] != "replacement_indicated" for f in result["findings"])


def test_class_suspicious_from_identity_mismatch():
    classification, finding = classify_change("SerialNumber", "A", "B")
    assert classification == "suspicious"
    assert finding.severity == "BLOCKER"


def test_class_inconclusive_from_not_comparable_field():
    result = assess_integrity({"device": {}}, {"device": {"ProductType": "iPhone15,4"}})
    assert result["classifications"]["ProductType"] == "inconclusive"
    assert result["changes"][0]["status"] == "not_comparable"


def test_class_not_detectable_from_continuity_guard():
    result = assess_integrity(
        {"device": {"ProductType": "iPhone15,4"}}, {"device": {"ProductType": "iPhone15,4"}}
    )
    assert any(f["classification"] == "not_detectable" for f in result["findings"])
    assert result["continuity"] == "not_detectable"


def test_class_not_tested_without_previous_snapshot():
    result = assess_integrity(None, V4_REPORT)
    assert result["overall"] == "not_tested"


def test_class_unsupported_from_stated_reason():
    classification, finding = classify_assertion(
        "unsupported",
        "Apple exposes pairing state only to Apple tooling; this tool cannot answer it.",
        evidence=["docs/v4/tampering-indicators.md"],
        confidence="high",
    )
    assert classification == "unsupported"
    assert finding.classification == "unsupported"
    with pytest.raises(ValueError):
        classify_assertion("unsupported", "")


def test_all_nine_integrity_classes_are_reachable():
    """One place asserting every class has a real constructor path."""
    reached = set()
    reached.add(
        classify_assertion(
            "verified", "same serial in both snapshots", evidence=["raw/device-info.plist"]
        )[0]
    )
    reached.add(
        assess_integrity({"device": {"SerialNumber": "S"}}, {"device": {"SerialNumber": "S"}})[
            "overall"
        ]
    )  # consistent
    reached.add(classify_change("BuildVersion", "21A329", "21B101")[0])  # change_detected
    reached.add(
        classify_assertion(
            "replacement_indicated",
            "display replaced",
            source="parts_and_service_history",
            evidence=["photo://parts.jpg"],
        )[0]
    )
    reached.add(classify_change("SerialNumber", "A", "B")[0])  # suspicious
    reached.add(
        assess_integrity({"device": {}}, {"device": {"ProductType": "iPhone15,4"}})[
            "classifications"
        ]["ProductType"]
    )  # inconclusive
    reached.add(
        assess_integrity(
            {"device": {"ProductType": "iPhone15,4"}}, {"device": {"ProductType": "iPhone15,4"}}
        )["findings"][0]["classification"]
    )  # not_detectable
    reached.add(assess_integrity(None, V4_REPORT)["overall"])  # not_tested
    reached.add(
        classify_assertion(
            "unsupported", "tool chain cannot answer this", evidence=["docs/v4/x.md"]
        )[0]
    )

    assert reached == set(INTEGRITY_CLASSES)
    assert len(INTEGRITY_CLASSES) == 9


# ----------------------------------------------------------------- output shape


def test_output_shape_unchanged_plus_continuity_key():
    result = assess_integrity(V3_REPORT, V4_REPORT, buyer_data={"buyer": {}, "observations": {}})
    assert set(result) == {
        "overall",
        "continuity",
        "classifications",
        "changes",
        "findings",
        "disclaimer",
    }
    assert isinstance(result["classifications"], dict)
    assert isinstance(result["changes"], list)
    assert isinstance(result["findings"], list)
    assert result["continuity"] in {"established", "not_detectable", "not_tested"}
    # Every change row keeps previous/current/classification for the report layer.
    for row in result["changes"]:
        assert {"field", "previous", "current"} <= set(row)
