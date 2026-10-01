#!/usr/bin/env python3
"""Run both controls with the Python standard library plus this package."""

import json

from agent_trace_canary import check_document
from agent_trace_canary.fixture import build_demo_document


def main() -> int:
    clean = check_document(build_demo_document())
    leaky = check_document(build_demo_document(leaky=True))
    print(json.dumps({"clean": clean.to_dict(), "leaky": leaky.to_dict()}, indent=2, sort_keys=True))
    return 0 if clean.status.value == "PASS" and leaky.status.value == "LEAK" else 1


if __name__ == "__main__":
    raise SystemExit(main())

