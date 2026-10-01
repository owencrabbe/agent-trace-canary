from __future__ import annotations

import json

from agent_trace_canary.cli import main
from agent_trace_canary.fixture import build_demo_document


def test_cli_pass(tmp_path, capsys) -> None:
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(build_demo_document()), encoding="utf-8")
    assert main([str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "PASS"


def test_cli_leak(tmp_path, capsys) -> None:
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(build_demo_document(leaky=True)), encoding="utf-8")
    assert main([str(path)]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "LEAK"
    assert output["findings"][0]["location"] == "/capture/events/4/payload"


def test_cli_malformed_is_inconclusive(tmp_path, capsys) -> None:
    path = tmp_path / "capture.json"
    path.write_text("{nope", encoding="utf-8")
    assert main([str(path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "INCONCLUSIVE"
    assert "malformed JSON" in output["reasons"][0]
    assert "{nope" not in output["reasons"][0]


def test_cli_empty_is_inconclusive(tmp_path, capsys) -> None:
    path = tmp_path / "capture.json"
    path.write_text("", encoding="utf-8")
    assert main([str(path)]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "INCONCLUSIVE"


def test_cli_separate_jsonl_capture_and_manifest(tmp_path, capsys) -> None:
    document = build_demo_document()
    capture_path = tmp_path / "capture.jsonl"
    capture_path.write_text(
        "\n".join(json.dumps(row) for row in document["capture"]["events"]),
        encoding="utf-8",
    )
    manifest = {key: value for key, value in document.items() if key != "capture"}
    manifest["controls"]["content_enabled"] = manifest["controls"]["content_enabled"]["events"]
    for index, scenario in enumerate(manifest["scenarios"]):
        scenario["controls"]["content_enabled_pointer"] = f"/controls/content_enabled/{index}/payload"
        scenario["controls"]["privacy_enabled_pointer"] = f"/capture/{index}/payload"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert main([str(capture_path), "--manifest", str(manifest_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
