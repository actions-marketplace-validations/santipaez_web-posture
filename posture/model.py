"""Posture findings and scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_PENALTY = {
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    remediation: str = ""


@dataclass(frozen=True)
class Report:
    target: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity is severity]

    def score(self) -> int:
        """Starts at 100 and subtracts a fixed penalty per finding. It is a
        coarse signal for tracking a domain over time, not a compliance rating."""
        score = 100
        for finding in self.findings:
            score -= _PENALTY[finding.severity]
        return max(0, score)
