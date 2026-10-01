from __future__ import annotations

from typing import Any

SCENARIOS = (
    "prompt",
    "output",
    "tool_args",
    "tool_result",
    "tool_exception",
    "output_validation_retry",
)


def synthetic_canary(scenario_id: str) -> str:
    if scenario_id not in SCENARIOS:
        raise ValueError("unknown scenario id")
    return f"TEST_ONLY_AGENT_TRACE_CANARY_{scenario_id.upper()}_9F2D7A"


def build_demo_document(*, leaky: bool = False) -> dict[str, Any]:
    """Return an independently-authored deterministic capture for local demos/tests."""
    capture_events: list[dict[str, Any]] = []
    positive_events: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []
    for index, scenario_id in enumerate(SCENARIOS):
        canary = synthetic_canary(scenario_id)
        capture_value = canary if leaky and scenario_id == "tool_exception" else "[content excluded]"
        capture_events.append({"scenario_id": scenario_id, "status": "ok", "payload": capture_value})
        positive_events.append({"scenario_id": scenario_id, "status": "ok", "payload": canary})
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "canary_id": f"canary-{index + 1:02d}",
                "canary": canary,
                "exercised": True,
                "encodings": ["raw", "base64", "base64url", "hex", "url"],
                "controls": {
                    "content_enabled_pointer": f"/controls/content_enabled/events/{index}/payload",
                    "privacy_enabled_pointer": f"/capture/events/{index}/payload",
                },
            }
        )
    return {
        "schema_version": 1,
        "metadata": {"flush_ok": True, "script_complete": True, "dependencies": {"python": "stdlib-demo"}},
        "scenarios": scenarios,
        "controls": {"content_enabled": {"events": positive_events}},
        "capture": {"events": capture_events},
    }
