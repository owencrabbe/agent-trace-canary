#!/usr/bin/env python3
"""Offline OpenAI Agents SDK privacy-control probe using only ScriptedModel."""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import socket
from typing import Any

from agents import Agent, RunConfig, Runner, UserError, function_tool, trace
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
    socket.socket.connect_ex = denied  # type: ignore[assignment]
    socket.socket.sendto = denied  # type: ignore[assignment]
    if hasattr(socket.socket, "sendmsg"):
        socket.socket.sendmsg = denied  # type: ignore[assignment]
    socket.getaddrinfo = denied  # type: ignore[assignment]
    socket.gethostbyname = denied  # type: ignore[assignment]
    socket.gethostbyaddr = denied  # type: ignore[assignment]


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


async def _capture(include_content: bool) -> tuple[LocalProcessor, bool, dict[str, Any]]:
    tool_args = synthetic_canary("tool_args")

    @function_tool
    def local_echo(value: str) -> str:
        """Return a deterministic local result."""
        return synthetic_canary("tool_result") + value[:0]

    success_model = ScriptedModel(
        [
            [function_call("local_echo", {"value": tool_args}, call_id="call_1")],
            [assistant_message("offline run complete")],
        ],
        emit_traces=True,
    )
    processor = LocalProcessor()
    set_trace_processors([processor])
    agent = Agent(name="offline-canary", model=success_model, tools=[local_echo])
    with trace("offline-canary-control"):
        await Runner.run(
            agent,
            "exercise the local tool",
            run_config=RunConfig(trace_include_sensitive_data=include_content),
        )
    success_model.assert_complete()

    async def raise_synthetic(value: str) -> str:
        raise ValueError(value)

    local_fail = function_tool(
        raise_synthetic,
        name_override="local_fail",
        failure_error_function=None,
    )
    failure_model = ScriptedModel(
        [[function_call("local_fail", {"value": synthetic_canary("tool_exception")}, call_id="call_2")]],
        emit_traces=True,
    )
    failure_agent = Agent(name="offline-failure-canary", model=failure_model, tools=[local_fail])
    failure_observed = False
    try:
        with trace("offline-canary-failure-control"):
            await Runner.run(
                failure_agent,
                "exercise the failing local tool",
                run_config=RunConfig(trace_include_sensitive_data=include_content),
            )
    except UserError:
        failure_observed = True
    failure_model.assert_complete()
    processor.force_flush()
    function_spans = {
        span["span_data"]["name"]: span
        for span in processor.spans
        if span.get("span_data", {}).get("type") == "function"
    }
    boundaries = {
        "tool_args": function_spans["local_echo"]["span_data"]["input"],
        "tool_result": function_spans["local_echo"]["span_data"]["output"],
        "tool_exception": function_spans["local_fail"]["error"]["data"]["error"],
    }
    complete = success_model.remaining_steps == 0 and failure_model.remaining_steps == 0 and failure_observed
    return processor, complete, boundaries


def _scenario(scenario_id: str, canary_id: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "canary_id": canary_id,
        "canary": synthetic_canary(scenario_id),
        "exercised": True,
        "encodings": ["raw", "base64", "base64url", "hex", "url"],
        "controls": {
            "content_enabled_pointer": f"/controls/content_enabled/boundaries/{scenario_id}",
            "privacy_enabled_pointer": f"/capture/boundaries/{scenario_id}",
        },
    }


async def make_document() -> dict[str, Any]:
    _block_network()
    positive, positive_complete, positive_boundaries = await _capture(True)
    private, private_complete, private_boundaries = await _capture(False)
    return {
        "schema_version": 1,
        "metadata": {
            "flush_ok": positive.flush_ok and private.flush_ok,
            "script_complete": positive_complete and private_complete,
            "required_scenarios": ["tool_args", "tool_result", "tool_exception"],
            "dependencies": {"openai-agents": importlib.metadata.version("openai-agents")},
        },
        "scenarios": [
            _scenario("tool_args", "openai-01"),
            _scenario("tool_result", "openai-02"),
            _scenario("tool_exception", "openai-03"),
        ],
        "controls": {
            "content_enabled": {"boundaries": positive_boundaries, "spans": positive.spans}
        },
        "capture": {"boundaries": private_boundaries, "spans": private.spans},
    }


def main() -> int:
    report = check_document(asyncio.run(make_document()))
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
