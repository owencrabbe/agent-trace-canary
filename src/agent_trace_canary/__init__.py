"""Offline synthetic-canary checks for agent telemetry captures."""

from .checker import check_document
from .models import CanaryReport, Finding, Status
from .pytest import assert_no_canary_leak

__all__ = [
    "CanaryReport",
    "Finding",
    "Status",
    "assert_no_canary_leak",
    "check_document",
]
__version__ = "0.1.1"
