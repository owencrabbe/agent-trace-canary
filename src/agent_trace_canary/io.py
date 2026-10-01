from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_capture(path: str) -> Any:
    if path == "-":
        import sys

        text = sys.stdin.read()
        source = "stdin"
    else:
        source = path
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"unable to read {source}") from exc
    if not text.strip():
        raise ValueError(f"{source} is empty")
    suffix = Path(path).suffix.lower() if path != "-" else ""
    try:
        if suffix == ".jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            if len(rows) == 1 and isinstance(rows[0], dict) and "schema_version" in rows[0]:
                return rows[0]
            return rows
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {source} at line {exc.lineno}, column {exc.colno}") from None
