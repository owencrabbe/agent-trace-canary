from __future__ import annotations

import json
import subprocess
import sys

import pytest


@pytest.mark.integration
@pytest.mark.parametrize(
    "script",
    ["examples/openai_agents_offline.py", "examples/pydantic_ai_offline.py"],
)
def test_sdk_example_isolated_offline(script: str) -> None:
    completed = subprocess.run(
        [sys.executable, "tests/network_guard_runner.py", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "PASS"
    assert report["dependency_versions"]
