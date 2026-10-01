from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    LEAK = "LEAK"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class Finding:
    canary_id: str
    scenario_id: str
    location: str
    encoding: str


@dataclass
class CanaryReport:
    status: Status
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    dependency_versions: dict[str, str] = field(default_factory=dict)
    exercised_scenarios: list[str] = field(default_factory=list)
    checked_scenarios: list[str] = field(default_factory=list)
    locations_checked: int = 0

    @property
    def exit_code(self) -> int:
        return {Status.PASS: 0, Status.LEAK: 1, Status.INCONCLUSIVE: 2}[self.status]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

