# agent-trace-canary

Offline regression tests for a narrow but important question: **did synthetic test-only content cross an agent telemetry boundary that was meant to exclude it?**

`agent-trace-canary` plants deterministic `TEST_ONLY_...` values in six agent workflow scenarios, captures telemetry locally, and scans nested JSON/JSONL without sending data anywhere. Reports contain only canary/scenario IDs, encodings, and JSON Pointer locations—never the matched value or surrounding capture content.

> This is a regression-test kit, not a privacy or compliance guarantee. A pass covers only the exercised scenarios, capture boundary, SDK version, and encodings declared in that run.

## Why this exists

Telemetry privacy behavior can regress on unusual paths. Two fixed historical examples motivated this project:

- OpenAI Agents SDK [issue #3110](https://github.com/openai/openai-agents-python/issues/3110) reported function-tool exceptions bypassing `trace_include_sensitive_data=False`; [PR #3111](https://github.com/openai/openai-agents-python/pull/3111) fixed the affected paths and merged May 5, 2026.
- PydanticAI [issue #7356](https://github.com/pydantic/pydantic-ai/issues/7356) reported native-output retry feedback appearing with `include_content=False`; [PR #7357](https://github.com/pydantic/pydantic-ai/pull/7357) fixed it and merged August 10, 2026.
- Langfuse [issue #14576](https://github.com/langfuse/langfuse/issues/14576) documented a masking limitation in a legacy ingestion path and is closed. This repository does not claim that current Langfuse versions leak.

These are historical bugs, not allegations about current releases. The optional integrations are pinned and tested against released APIs.

## Quick start

Python 3.10+ is required. The core checker has no runtime dependencies.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python examples/stdlib_demo.py
agent-trace-canary fixtures/clean.json --pretty
agent-trace-canary fixtures/leaky.json --pretty; test $? -eq 1
```

For a raw JSONL export, keep the scenario/control document separately and run `agent-trace-canary capture.jsonl --manifest manifest.json`. The JSONL rows become the top-level capture array, so control pointers should begin with `/capture/0`, `/capture/1`, and so on.

Exit codes are stable: `0` PASS, `1` LEAK, and `2` INCONCLUSIVE.

Use the pytest helper in a local capture test:

```python
from agent_trace_canary import assert_no_canary_leak

assert_no_canary_leak(canary_document)
```

## What a valid test proves

Each scenario declares two paths at the same logical capture boundary:

1. A content-enabled positive control must contain the synthetic sentinel.
2. A privacy-enabled control must capture the same expected event/path without the sentinel.

The checker refuses to pass when the capture is missing/empty, flush was not confirmed, scripted steps were not consumed, a scenario was not exercised, input is malformed, or either control cannot be observed. Covered scenarios are:

- prompt
- output
- tool arguments
- tool result
- tool exception
- output-validation retry feedback

Scanning descends through mappings, arrays, JSON embedded in strings, statuses, events, and exception-shaped records. A scenario may declare reversible `raw`, `base64`, `base64url`, `hex`, and URL-percent encodings.

## Optional SDK integrations

Install released versions used in CI:

```bash
python -m pip install -e '.[integrations,test]'
pytest -m integration
```

- `examples/openai_agents_offline.py` uses OpenAI Agents `0.22.3`, `ScriptedModel`, `function_call`, `assistant_message`, and `set_trace_processors` with a local processor. See the official [testing](https://openai.github.io/openai-agents-python/testing/) and [tracing](https://openai.github.io/openai-agents-python/tracing/) guides.
- `examples/pydantic_ai_offline.py` uses the released PydanticAI slim distribution `2.52.0`, `FunctionModel`, `ALLOW_MODEL_REQUESTS=False`, and OpenTelemetry SDK `1.44.0` with a local `TracerProvider`, `SimpleSpanProcessor`, and `InMemorySpanExporter`. See the official [testing](https://pydantic.dev/docs/ai/guides/testing/) and [instrumentation](https://pydantic.dev/docs/ai/integrations/logfire/) guides.

Examples run in isolated processes in the test suite so global tracing configuration cannot spill into another test or application. Tests also replace socket connection entry points, making an accidental network attempt fail immediately.

## Document format

The top-level JSON object contains:

- `schema_version: 1`
- `metadata.flush_ok`, `metadata.script_complete`, and dependency versions
- `scenarios` with IDs, synthetic values, exercised state, encodings, and positive/privacy JSON Pointers
- `controls.content_enabled`, retained only in a test fixture
- `capture`, the privacy-enabled local export being checked

Canary values necessarily exist in the test manifest and positive control. Do not reuse real credentials, production prompts, customer traces, or copied private datasets. Keep fixture files synthetic.

## Architecture

```text
offline scripted agent run
        │
        ├── content enabled ──> local positive-control capture
        └── privacy enabled ──> local candidate capture
                                      │
manifest + both captures ──> recursive scanner ──> PASS / LEAK / INCONCLUSIVE
```

The scanner is deliberately separate from SDK adapters. Framework-specific examples only serialize local captures into the small document format; the core package stays standard-library-only.

## Threat model and limitations

The kit is designed to catch accidental cleartext or declared reversible-encoding disclosure at a selected local export boundary. It does not prove absence of secrets, validate regulatory compliance, inspect encrypted/proprietary encodings, protect against a malicious exporter, cover data outside declared scenarios, or guarantee behavior of untested dependency versions. Hashes are not searched because they are not reversible and substring matching them would overstate what was observed. A compromised process can evade an in-process test.

Run this in CI alongside normal privacy reviews and end-to-end controls. Never point fixtures at production telemetry. The project performs no uploads and configures no remote exporter.

## Development

```bash
python -m pip install -e '.[test,integrations]'
pytest
python -m build
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Original code is licensed under Apache-2.0; dependency licenses remain their own.
