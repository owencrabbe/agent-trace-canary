from __future__ import annotations

from typing import Any

from .checker import check_document
from .models import Status


def assert_no_canary_leak(document: Any) -> None:
    """Assert a document passes, emitting only IDs, locations, and safe reasons."""
    report = check_document(document)
    if report.status is Status.PASS:
        return
    safe = report.to_dict()
    raise AssertionError(f"agent telemetry canary check did not pass: {safe}")

