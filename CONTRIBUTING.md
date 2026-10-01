# Contributing

Thanks for helping make agent telemetry tests more trustworthy.

1. Open an issue describing the capture boundary or framework behavior.
2. Use only deterministic `TEST_ONLY_...` data. Never submit real secrets, customer traces, production prompts, or private code.
3. Add a positive control, a privacy-enabled control, and an inconclusive case for any new scenario or adapter.
4. Block network access in integration tests and keep all exporters local.
5. Run `pytest` and `python -m build` before opening a pull request.

Reports must not include matched values, surrounding capture content, exception messages derived from captures, or tracebacks containing canaries. New encodings must be reversible and explicitly declared.

By contributing, you agree that your contribution is licensed under Apache-2.0.

