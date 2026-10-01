#!/usr/bin/env python3
"""Offline OpenAI Agents SDK privacy-control probe using only ScriptedModel."""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import socket
from typing import Any

from agents import Agent, RunConfig, Runner, function_tool, trace
from agents.testing import ScriptedModel, assistant_message, function_call
from agents.tracing import set_trace_processors
from agents.tracing.processor_interface import TracingProcessor

from agent_trace_canary import check_document
from agent_trace_canary.fixture import synthetic_canary


def _block_network() -> None:
    def denied(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("network disabled in offline integration example")

    socket.create_connection = denied  # type: ignore[assignment]
    socket.socket.connect = denied  # type: ignore[assignment]


class LocalProcessor(TracingProcessor):
    def __init__(self) -> None:
        self.spans: list[dict[str, Any]] = []
        self.flush_ok = False

    def on_trace_start(self, _trace: Any) -> None:
        pass

    def on_trace_end(self, _trace: Any) -> None:
        pass

    def on_span_start(self, _span: Any) -> None:
        pass

    def on_span_end(self, span: Any) -> None:
        exported = span.export()
        if exported is not None:
            self.spans.append(exported)

    def shutdown(self) -> None:
        pass

    def force_flush(self) -> None:
        self.flush_ok = True


async def _capture(include_content: bool) -> tuple[LocalProcessor, bool]:
    tool_args = synthetic_canary("tool_args")

    @function_tool
    def local_echo(value: str) -> str:
        """Return a deterministic local result."""
        return synthetic_canary("tool_result") + value[:0]

    model = ScriptedModel(
        [
            [function_call("local_echo", {"value": tool_args}, call_id="call_1")],
            [assistant_message("offline run complete")],
        ],
        emit_traces=True,
    )
    processor = LocalProcessor()
    set_trace_processors([processor])
    agent = Agent(name="offline-canary", model=model, tools=[local_echo])
    with trace("offline-canary-control"):
        await Runner.run(
            agent,
            "exercise the local tool",
            run_config=RunConfig(trace_include_sensitive_data=include_content),
        )
    model.assert_complete()
    processor.force_flush()
    return processor, model.remaining_steps == 0


def _scenario(scenario_id: str, canary_id: str, index: int, field: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "canary_id": canary_id,
        "canary": synthetic_canary(scenario_id),
        "exercised": True,
        "encodings": ["raw", "base64", "base64url", "hex", "url"],
        "controls": {
            "content_enabled_pointer": f"/controls/content_enabled/spans/{index}/span_data/{field}",
            "privacy_enabled_pointer": f"/capture/spans/{index}/span_data/{field}",
        },
    }


async def make_document() -> dict[str, Any]:
    _block_network()
    positive, positive_complete = await _capture(True)
    private, private_complete = await _capture(False)
    return {
        "schema_version": 1,
        "metadata": {
            "flush_ok": positive.flush_ok and private.flush_ok,
            "script_complete": positive_complete and private_complete,
            "dependencies": {"openai-agents": importlib.metadata.version("openai-agents")},
        },
        "scenarios": [
            _scenario("tool_args", "openai-01", 1, "input"),
            _scenario("tool_result", "openai-02", 1, "output"),
        ],
        "controls": {"content_enabled": {"spans": positive.spans}},
        "capture": {"spans": private.spans},
    }


def main() -> int:
    report = check_document(asyncio.run(make_document()))
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
