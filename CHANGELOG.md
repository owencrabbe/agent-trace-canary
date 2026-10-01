# Changelog

## 0.1.2 — 2026-10-01

- Apply a final fail-closed scrub to every serialized report field against raw and reversible encoded forms of every valid synthetic canary.
- Redact encoded canaries smuggled into scenario IDs, canary IDs, paths, metadata, coverage lists, or diagnostic messages.

## 0.1.1 — 2026-10-01

- Detect synthetic canaries in mapping keys.
- Normalize mixed-case, partial URL-percent encodings and case-insensitive hexadecimal encodings.
- Enforce matching content-enabled/privacy capture boundaries and observable capture fields.
- Add explicit required-scenario coverage contracts.
- Sanitize dependency metadata before it can reach reports or pytest failures.
- Treat structurally invalid encoding declarations as INCONCLUSIVE.
- Exercise the fixed historical OpenAI function-tool exception path with a real offline SDK run.
- Install broader socket/DNS test tripwires before SDK imports and document their limits.

## 0.1.0 — 2026-10-01

- Initial offline checker, fixtures, CLI, pytest helper, and optional SDK examples.
