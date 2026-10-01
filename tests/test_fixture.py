from agent_trace_canary.fixture import SCENARIOS, build_demo_document


def test_fixture_is_deterministic_and_synthetic() -> None:
    assert build_demo_document() == build_demo_document()
    document = build_demo_document()
    assert [item["scenario_id"] for item in document["scenarios"]] == list(SCENARIOS)
    assert all(item["canary"].startswith("TEST_ONLY_") for item in document["scenarios"])

