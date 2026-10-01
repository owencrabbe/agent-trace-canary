#!/usr/bin/env python3
"""Offline PydanticAI privacy-control probe using FunctionModel and local OTEL."""

from __future__ import annotations

import importlib.metadata
import json
import socket
from typing import Any

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import (
    Agent,
    InstrumentationSettings,
    ModelResponse,
    ModelRetry,
    TextPart,
    ToolCallPart,
    models,
)
from pydantic_ai.capabilities import Instrumentation
from pydantic_ai.models.function import FunctionModel

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


def _capture(include_content: bool) -> tuple[list[dict[str, Any]], bool, bool]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    call_count = 0

    def scripted_model(_messages: Any, _info: Any) -> ModelResponse:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return ModelResponse(parts=[ToolCallPart("local_echo", {"value": synthetic_canary("tool_args")})])
        if call_count == 2:
            return ModelResponse(parts=[TextPart("first-output-triggers-retry")])
        return ModelResponse(parts=[TextPart(synthetic_canary("output"))])

    agent = Agent(
        FunctionModel(scripted_model),
        capabilities=[
            Instrumentation(
                settings=InstrumentationSettings(
                    tracer_provider=provider,
                    include_content=include_content,
                )
            )
        ],
    )

    @agent.tool_plain
    def local_echo(value: str) -> str:
        """Return a deterministic local result."""
        return synthetic_canary("tool_result") + value[:0]

    validation_count = 0

    @agent.output_validator
    def require_retry(value: str) -> str:
        nonlocal validation_count
        validation_count += 1
        if validation_count == 1:
            raise ModelRetry(synthetic_canary("output_validation_retry"))
        return value

    agent.run_sync(synthetic_canary("prompt"))
    flush_ok = provider.force_flush()
    spans = [
        {"name": span.name, "attributes": dict(span.attributes or {})}
        for span in exporter.get_finished_spans()
    ]
    return spans, flush_ok, call_count == 3


def _scenario(scenario_id: str, canary_id: str, index: int, attribute: str) -> dict[str, Any]:
    escaped = attribute.replace("~", "~0").replace("/", "~1")
    return {
        "scenario_id": scenario_id,
        "canary_id": canary_id,
        "canary": synthetic_canary(scenario_id),
        "exercised": True,
        "encodings": ["raw", "base64", "base64url", "hex", "url"],
        "controls": {
            "content_enabled_pointer": f"/controls/content_enabled/spans/{index}/attributes/{escaped}",
            "privacy_enabled_pointer": f"/capture/spans/{index}/attributes/{escaped}",
        },
    }


def make_document() -> dict[str, Any]:
    _block_network()
    models.ALLOW_MODEL_REQUESTS = False
    positive, positive_flush, positive_complete = _capture(True)
    private, private_flush, private_complete = _capture(False)
    return {
        "schema_version": 1,
        "metadata": {
            "flush_ok": positive_flush and private_flush,
            "script_complete": positive_complete and private_complete,
            "required_scenarios": [
                "prompt",
                "tool_args",
                "tool_result",
                "output_validation_retry",
                "output",
            ],
            "dependencies": {
                "pydantic-ai-slim": importlib.metadata.version("pydantic-ai-slim"),
                "opentelemetry-sdk": importlib.metadata.version("opentelemetry-sdk"),
            },
        },
        "scenarios": [
            _scenario("prompt", "pydantic-01", 0, "gen_ai.input.messages"),
            _scenario("tool_args", "pydantic-02", 0, "gen_ai.output.messages"),
            _scenario("tool_result", "pydantic-03", 2, "gen_ai.input.messages"),
            _scenario("output_validation_retry", "pydantic-04", 3, "gen_ai.input.messages"),
            _scenario("output", "pydantic-05", 3, "gen_ai.output.messages"),
        ],
        "controls": {"content_enabled": {"spans": positive}},
        "capture": {"spans": private},
    }


def main() -> int:
    report = check_document(make_document())
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
