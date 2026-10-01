from __future__ import annotations

import base64
import copy
import json

import pytest

from agent_trace_canary import Status, assert_no_canary_leak, check_document
from agent_trace_canary.fixture import SCENARIOS, build_demo_document, synthetic_canary


def test_clean_fixture_passes_with_full_coverage() -> None:
    report = check_document(build_demo_document())
    assert report.status is Status.PASS
    assert report.exercised_scenarios == list(SCENARIOS)
    assert report.findings == []
    assert report.locations_checked > 0


def test_leaky_fixture_fails_at_exact_path_without_echoing_value() -> None:
    document = build_demo_document(leaky=True)
    report = check_document(document)
    assert report.status is Status.LEAK
    assert [(x.scenario_id, x.location) for x in report.findings] == [
        ("tool_exception", "/capture/events/4/payload")
    ]
    assert synthetic_canary("tool_exception") not in json.dumps(report.to_dict())


@pytest.mark.parametrize("encoding", ["base64", "base64url", "hex", "url"])
def test_declared_reversible_encoding_is_detected(encoding: str) -> None:
    document = build_demo_document()
    canary = synthetic_canary("prompt")
    values = {
        "base64": base64.b64encode(canary.encode()).decode(),
        "base64url": base64.urlsafe_b64encode(canary.encode()).decode().rstrip("="),
        "hex": canary.encode().hex(),
        "url": "".join(f"%{byte:02X}" for byte in canary.encode()),
    }
    document["capture"]["events"][0]["payload"] = values[encoding]
    report = check_document(document)
    assert report.status is Status.LEAK
    if encoding == "base64url":
        assert report.findings[0].encoding in {"base64", "base64url"}
    else:
        assert report.findings[0].encoding == encoding


def test_nested_json_string_is_scanned_with_safe_pointer() -> None:
    document = build_demo_document()
    canary = synthetic_canary("tool_result")
    document["capture"]["events"][3]["payload"] = json.dumps({"event": {"exception": canary}})
    report = check_document(document)
    assert report.status is Status.LEAK
    assert any(f.location == "/capture/events/3/payload" for f in report.findings)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda d: d.update(capture={}), "capture is missing or empty"),
        (lambda d: d["metadata"].update(flush_ok=False), "capture flush was not confirmed"),
        (lambda d: d["metadata"].update(script_complete=False), "scripted steps were not confirmed complete"),
        (lambda d: d["scenarios"][0].update(exercised=False), "scenario not exercised: prompt"),
            (
                lambda d: d["scenarios"][0]["controls"].update(content_enabled_pointer="/controls/missing"),
                "invalid control boundary pointers: prompt",
        ),
        (
            lambda d: d["controls"]["content_enabled"]["events"][0].update(payload="[not observed]"),
            "positive-control canary not observed: prompt",
        ),
            (
                lambda d: d["scenarios"][0]["controls"].update(privacy_enabled_pointer="/capture/missing"),
                "invalid control boundary pointers: prompt",
        ),
    ],
)
def test_inconclusive_conditions(mutate, reason: str) -> None:
    document = build_demo_document()
    mutate(document)
    report = check_document(document)
    assert report.status is Status.INCONCLUSIVE
    assert reason in report.reasons


def test_pytest_helper() -> None:
    assert_no_canary_leak(build_demo_document())
    with pytest.raises(AssertionError) as exc:
        assert_no_canary_leak(build_demo_document(leaky=True))
    assert synthetic_canary("tool_exception") not in str(exc.value)


def test_document_is_not_mutated() -> None:
    document = build_demo_document()
    before = copy.deepcopy(document)
    check_document(document)
    assert document == before


def test_lowercase_partial_url_encoding_is_detected() -> None:
    document = build_demo_document()
    scenario = document["scenarios"][0]
    scenario["encodings"] = ["url"]
    encoded = scenario["canary"].replace("_", "%5f", 1)
    document["controls"]["content_enabled"]["events"][0]["payload"] = encoded
    document["capture"]["events"][0]["payload"] = encoded
    report = check_document(document)
    assert report.status is Status.LEAK
    assert report.findings[0].encoding == "url"


def test_uppercase_hex_encoding_is_detected() -> None:
    document = build_demo_document()
    scenario = document["scenarios"][0]
    scenario["encodings"] = ["hex"]
    encoded = scenario["canary"].encode().hex().upper()
    document["controls"]["content_enabled"]["events"][0]["payload"] = encoded
    document["capture"]["events"][0]["payload"] = encoded
    report = check_document(document)
    assert report.status is Status.LEAK
    assert report.findings[0].encoding == "hex"


def test_malformed_percent_text_does_not_crash_decoder() -> None:
    document = build_demo_document()
    scenario = document["scenarios"][0]
    scenario["encodings"] = ["url"]
    document["capture"]["events"][0]["payload"] = "%ZZ%2 ordinary text"
    report = check_document(document)
    assert report.status is Status.PASS


def test_canary_in_mapping_key_is_detected_without_echoing_key() -> None:
    document = build_demo_document()
    canary = synthetic_canary("prompt")
    document["capture"] = {canary: "ordinary value"}
    report = check_document(document)
    assert report.status is Status.LEAK
    assert report.findings[0].location == "/capture/~keys/0"
    assert canary not in json.dumps(report.to_dict())


def test_control_pointers_cannot_escape_declared_boundaries() -> None:
    document = build_demo_document()
    document.pop("controls")
    document["capture"] = {"events": []}
    document["scenarios"][0]["controls"] = {
        "content_enabled_pointer": "/scenarios/0/canary",
        "privacy_enabled_pointer": "/metadata/flush_ok",
    }
    report = check_document(document)
    assert report.status is Status.INCONCLUSIVE
    assert "capture contains no observable fields" in report.reasons
    assert "invalid control boundary pointers: prompt" in report.reasons
    assert report.locations_checked == 0


def test_report_sanitizes_canaries_from_untrusted_metadata() -> None:
    document = build_demo_document(leaky=True)
    canary = synthetic_canary("tool_exception")
    document["metadata"]["dependencies"]["polluted"] = canary
    report = check_document(document)
    assert report.status is Status.LEAK
    assert canary not in json.dumps(report.to_dict())
    with pytest.raises(AssertionError) as exc:
        assert_no_canary_leak(document)
    assert canary not in str(exc.value)


def test_non_string_encoding_is_inconclusive_not_exception() -> None:
    document = build_demo_document()
    document["scenarios"][0]["encodings"] = [{}]
    report = check_document(document)
    assert report.status is Status.INCONCLUSIVE
    assert "unsupported encoding declaration: prompt" in report.reasons


def test_missing_declared_required_scenario_is_inconclusive() -> None:
    document = build_demo_document()
    document["metadata"]["required_scenarios"] = ["prompt", "tool_exception"]
    document["scenarios"] = [item for item in document["scenarios"] if item["scenario_id"] != "tool_exception"]
    report = check_document(document)
    assert report.status is Status.INCONCLUSIVE
    assert "required scenario missing: tool_exception" in report.reasons
