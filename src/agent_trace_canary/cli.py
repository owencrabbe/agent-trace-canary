from __future__ import annotations

import argparse
import json
import sys

from .checker import check_document
from .io import load_capture
from .models import CanaryReport, Status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-trace-canary", description="Check local agent telemetry for synthetic canaries")
    parser.add_argument("capture", help="JSON/JSONL canary document, or - for stdin")
    parser.add_argument("--manifest", help="JSON manifest/control document when capture is a separate JSON/JSONL file")
    parser.add_argument("--pretty", action="store_true", help="pretty-print the safe JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = load_capture(args.capture)
        if args.manifest:
            manifest = load_capture(args.manifest)
            if not isinstance(manifest, dict):
                raise ValueError("manifest must be a JSON object")
            capture = document
            document = dict(manifest)
            document["capture"] = capture
        report = check_document(document)
    except ValueError as exc:
        report = CanaryReport(Status.INCONCLUSIVE, reasons=[str(exc)])
    print(json.dumps(report.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
